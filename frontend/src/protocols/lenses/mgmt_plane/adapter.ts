import { literal } from "../../../data/evidence";
import type { SearchClient } from "../../../data/searchClient";
import {
  ALLOWED_SYSLOG_SOURCETYPES,
  EXCLUDED_AUTH_CATEGORIES,
  type AllowedSyslogSourcetype,
} from "../../shared/adapters/nxosSyslog";
import {
  MAX_INPUT_ROWS,
  type LensProfileValidator,
  type ProtocolConfiguration,
  type ProtocolDistributionMetric,
  type ProtocolFilter,
  type ProtocolKpi,
  type ProtocolLensId,
  type ProtocolLensSummary,
  type ProtocolMatrixCell,
  type ProtocolRequest,
  type ProtocolSourceOutcome,
  type ProtocolStatus,
  type ProtocolTimelineEvent,
} from "../../shared/contract";
import { buildAllowedFieldsClause } from "../../shared/fields";
import { buildFlowEndpointPredicates } from "../../shared/filterSpl";
import { formatBytes, formatCount } from "../../shared/format";
import {
  ProtocolConfigurationChangedError,
  runBoundedProtocolSearch,
  selectActiveProfiles,
  withProtocolConfigRecheck,
  type ProtocolRow,
} from "../../shared/runner";
import {
  checkStreamEstimateMode,
  type StreamReadinessEntry,
} from "../../shared/streamReadiness";
import {
  DEFAULT_MGMT_PLANE_THRESHOLDS,
  resolveMgmtPlaneThresholds,
  validateMgmtPlaneExtra,
  type MgmtPlaneExtraConfig,
  type MgmtPlaneSourceKind,
  type ResolvedMgmtPlaneThresholds,
} from "./validate";

export {
  DEFAULT_MGMT_PLANE_THRESHOLDS,
  resolveMgmtPlaneThresholds,
  validateMgmtPlaneExtra,
  type MgmtPlaneExtraConfig,
  type MgmtPlaneSourceKind,
  type ResolvedMgmtPlaneThresholds,
};

export type MgmtPlaneSourcetype =
  "stream:snmp" | "stream:ftp" | "stream:netflow" | AllowedSyslogSourcetype;

export type MgmtPlaneCategory =
  | "snmp_v1_v2c"
  | "snmp_set"
  | "cleartext"
  | "receipt_gap"
  | "snmp_v3"
  | "netflow_snmp"
  | "syslog_ok"
  | "syslog_baseline";

export const SNMP_PROJECTED_FIELDS = [
  "_time",
  "host",
  "sourcetype",
  "src_ip",
  "dest_ip",
  "src_port",
  "dest_port",
  "snmp_version",
  "version",
  "pdu_type",
  "method",
  "status",
  "bytes_in",
  "bytes_out",
  "time_taken",
] as const;

export const FTP_PROJECTED_FIELDS = [
  "_time",
  "host",
  "sourcetype",
  "src_ip",
  "dest_ip",
  "src_port",
  "dest_port",
  "command",
  "method",
  "status",
  "reply_code",
  "bytes_in",
  "bytes_out",
  "time_taken",
] as const;

export const NETFLOW_MGMT_PROJECTED_FIELDS = [
  "_time",
  "host",
  "sourcetype",
  "exporter_ip",
  "src_ip",
  "dest_ip",
  "src_port",
  "dest_port",
  "transport",
  "protocol",
  "bytes",
  "packets",
  "bytes_in",
  "bytes_out",
] as const;

export const SYSLOG_RECEIPT_PROJECTED_FIELDS = [
  "host",
  "sourcetype",
  "last_seen",
  "count",
] as const;

const EXCLUDED_AUTH_SET = new Set<string>(EXCLUDED_AUTH_CATEGORIES);
const AUTH_FTP_VERBS = new Set<string>(["USER", "PASS", "ACCT"]);

/**
 * Shortens DNS hostnames to their short label while preserving IPv4 and IPv6
 * literals completely intact.
 */
export function shortenDeviceLabel(device: string): string {
  const trimmed = device.trim();
  if (!trimmed) return "unknown";
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(trimmed) || trimmed.includes(":")) {
    return trimmed;
  }
  return trimmed.split(".")[0] || trimmed;
}

function sanitizeIdPart(raw: string): string {
  const cleaned = raw
    .trim()
    .replace(/[^A-Za-z0-9._:/-]/g, "_")
    .replace(/^[^A-Za-z0-9]+/, "");
  return cleaned || "item";
}

function shortFnvHash(input: string): string {
  let hash = 0x811c9dc5;
  for (let i = 0; i < input.length; i += 1) {
    hash ^= input.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193);
  }
  return (hash >>> 0).toString(36).padStart(7, "0").slice(0, 7);
}

/**
 * Generates a deterministic row/item ID matching `^[A-Za-z0-9._:/-]{1,128}$`
 * using `__` separators (never `->`).
 */
export function makeMgmtPlaneRowId(
  kind: string,
  sourceManager: string,
  targetDevice: string,
  extra?: string,
): string {
  const parts = [
    sanitizeIdPart(kind),
    sanitizeIdPart(sourceManager),
    sanitizeIdPart(targetDevice),
    ...(extra ? [sanitizeIdPart(extra)] : []),
  ];
  const full = parts.join("__");
  if (full.length <= 128) return full;
  const suffix = `__${shortFnvHash(full)}`;
  return `${full.slice(0, 128 - suffix.length)}${suffix}`;
}

/**
 * Builds a bounded, allowlisted SPL query for `stream:snmp`.
 * NEVER selects or references `community`, `value_raw`, `varbind_list`, `payload`, or `_raw`.
 * Emits `| head <maxRows + 1>` BEFORE `| table ...`.
 */
export function buildMgmtSnmpSearch(options: {
  index: string;
  filter?: ProtocolFilter;
  mgmtIps?: readonly string[];
  maxRows: number;
}): string {
  const index = literal(options.index, 80);
  const predicates: string[] = [`index=${index}`, `sourcetype="stream:snmp"`];
  predicates.push(
    ...buildFlowEndpointPredicates({
      filter: options.filter,
      srcFields: ["src_ip"],
      dstFields: ["dest_ip"],
      portFields: ["dest_port", "src_port"],
    }),
  );
  if (options.filter?.device) {
    const dev = literal(options.filter.device, 128);
    predicates.push(`(dest_ip="${dev}" OR host="${dev}" OR device="${dev}")`);
  } else if (options.mgmtIps?.length) {
    const quoted = options.mgmtIps.map((ip) => `"${literal(ip, 128)}"`);
    predicates.push(`(dest_ip IN (${quoted.join(", ")}))`);
  }
  const headLimit = Math.max(1, Math.trunc(options.maxRows)) + 1;
  const tableClause = buildAllowedFieldsClause(
    "mgmt_plane",
    SNMP_PROJECTED_FIELDS,
  );
  return `search ${predicates.join(" ")} | head ${headLimit} ${tableClause}`;
}

/**
 * Builds a bounded, allowlisted SPL query for `stream:ftp`.
 * Strips FTP `command`/`method` down to the verb inside Splunk BEFORE `| table`
 * and redacts `USER`/`PASS`/`ACCT` to `AUTH_CMD` so credential arguments never
 * cross the wire. NEVER references `login`, `password`, `passwd`, `authorization`, or `_raw`.
 */
export function buildMgmtFtpSearch(options: {
  index: string;
  filter?: ProtocolFilter;
  mgmtIps?: readonly string[];
  maxRows: number;
}): string {
  const index = literal(options.index, 80);
  const predicates: string[] = [`index=${index}`, `sourcetype="stream:ftp"`];
  predicates.push(
    ...buildFlowEndpointPredicates({
      filter: options.filter,
      srcFields: ["src_ip"],
      dstFields: ["dest_ip"],
      portFields: ["dest_port", "src_port"],
    }),
  );
  if (options.filter?.device) {
    const dev = literal(options.filter.device, 128);
    predicates.push(`(dest_ip="${dev}" OR host="${dev}" OR device="${dev}")`);
  } else if (options.mgmtIps?.length) {
    const quoted = options.mgmtIps.map((ip) => `"${literal(ip, 128)}"`);
    predicates.push(`(dest_ip IN (${quoted.join(", ")}))`);
  }
  const headLimit = Math.max(1, Math.trunc(options.maxRows)) + 1;
  const tableClause = buildAllowedFieldsClause(
    "mgmt_plane",
    FTP_PROJECTED_FIELDS,
  );
  return (
    `search ${predicates.join(" ")} ` +
    `| head ${headLimit} ` +
    `| eval command=upper(mvindex(split(trim(coalesce(command, method)), " "), 0)) ` +
    `| eval command=if(in(command, "USER", "PASS", "ACCT"), "AUTH_CMD", command) ` +
    `| eval method=command ` +
    tableClause
  );
}

/**
 * Builds a bounded, allowlisted SPL query for `stream:netflow` filtered BEFORE
 * `| head` on cleartext management destination ports:
 * FTP (21), Telnet (23), TFTP (69), SNMP (161/162), and optional cleartext HTTP (80).
 */
export function buildMgmtNetflowSearch(options: {
  index: string;
  filter?: ProtocolFilter;
  mgmtIps?: readonly string[];
  flagHttpPort80?: boolean;
  maxRows: number;
}): string {
  const index = literal(options.index, 80);
  const includeHttp = options.flagHttpPort80 !== false;
  const portClause = includeHttp
    ? "(dest_port=21 OR dest_port=23 OR dest_port=69 OR dest_port=161 OR dest_port=162 OR dest_port=80)"
    : "(dest_port=21 OR dest_port=23 OR dest_port=69 OR dest_port=161 OR dest_port=162)";
  const predicates: string[] = [
    `index=${index}`,
    `sourcetype="stream:netflow"`,
    portClause,
  ];
  predicates.push(
    ...buildFlowEndpointPredicates({
      filter: options.filter,
      srcFields: ["src_ip"],
      dstFields: ["dest_ip"],
      portFields: ["dest_port", "src_port"],
    }),
  );
  if (options.filter?.device) {
    const dev = literal(options.filter.device, 128);
    predicates.push(
      `(dest_ip="${dev}" OR host="${dev}" OR exporter_ip="${dev}" OR device="${dev}")`,
    );
  } else if (options.mgmtIps?.length) {
    const quoted = options.mgmtIps.map((ip) => `"${literal(ip, 128)}"`);
    predicates.push(`(dest_ip IN (${quoted.join(", ")}))`);
  }
  const headLimit = Math.max(1, Math.trunc(options.maxRows)) + 1;
  const tableClause = buildAllowedFieldsClause(
    "mgmt_plane",
    NETFLOW_MGMT_PROJECTED_FIELDS,
  );
  return `search ${predicates.join(" ")} | head ${headLimit} ${tableClause}`;
}

/**
 * Builds a bounded, allowlisted SPL query for SC4S (`cisco:ios`, `cisco:aci`)
 * and Cisco DC Networking TA (`cisco:dc:nexus9k:syslog`, `cisco:dc:aci:syslog`)
 * syslog receipt timestamps. Excludes AAA/auth categories and aggregates
 * `max(_time) AS last_seen count BY host sourcetype` BEFORE `| head` so chatty
 * devices cannot crowd quiet devices out of the 256-row cap.
 */
export function buildMgmtSyslogSearch(options: {
  index: string;
  sourcetypes?: readonly AllowedSyslogSourcetype[];
  filter?: ProtocolFilter;
  maxRows: number;
}): string {
  const index = literal(options.index, 80);
  const requested = options.sourcetypes?.length
    ? options.sourcetypes
    : ALLOWED_SYSLOG_SOURCETYPES;
  for (const st of requested) {
    if (!ALLOWED_SYSLOG_SOURCETYPES.includes(st)) {
      throw new Error(`Unsupported syslog sourcetype "${st}".`);
    }
  }
  const stClause =
    requested.length === 1
      ? `sourcetype="${requested[0]}"`
      : `(${requested.map((st) => `sourcetype="${st}"`).join(" OR ")})`;
  const predicates: string[] = [`index=${index}`, stClause];
  if (options.filter?.device) {
    predicates.push(`host="${literal(options.filter.device, 128)}"`);
  }
  const excludedCategories = EXCLUDED_AUTH_CATEGORIES.map((c) => `"${c}"`).join(
    ", ",
  );
  const headLimit = Math.max(1, Math.trunc(options.maxRows)) + 1;
  const tableClause = buildAllowedFieldsClause(
    "mgmt_plane",
    SYSLOG_RECEIPT_PROJECTED_FIELDS,
  );
  return (
    `search ${predicates.join(" ")} ` +
    `| eval category=coalesce(category, facility) ` +
    `| where (isnull(category) OR NOT (category IN (${excludedCategories}))) AND (isnull(facility) OR NOT (facility IN (${excludedCategories}))) ` +
    `| stats max(_time) AS last_seen count BY host sourcetype ` +
    `| head ${headLimit} ` +
    tableClause
  );
}

/**
 * Builds a `literal()`-quoted Splunk Search URL for raw events of a selected finding row.
 */
export function buildMgmtPlaneRawEventsUrl(options: {
  index: string;
  sourcetypes: readonly MgmtPlaneSourcetype[];
  sourceManager: string;
  targetDevice: string;
  destPort?: number;
  isSyslog?: boolean;
  earliest: number;
  latest: number;
}): string {
  const index = literal(options.index, 80);
  const sts = options.sourcetypes.length
    ? options.sourcetypes
    : (["stream:snmp", "stream:ftp", "stream:netflow"] as const);
  const stClause =
    sts.length === 1
      ? `sourcetype="${literal(sts[0], 64)}"`
      : `(${sts.map((s) => `sourcetype="${literal(s, 64)}"`).join(" OR ")})`;
  const target = literal(options.targetDevice, 128);
  let targetClause: string;
  if (options.isSyslog) {
    targetClause = `host="${target}"`;
  } else {
    const src =
      options.sourceManager && options.sourceManager !== "Syslog peer baseline"
        ? literal(options.sourceManager, 128)
        : undefined;
    const portClause =
      options.destPort !== undefined
        ? ` dest_port=${Math.trunc(options.destPort)}`
        : "";
    targetClause = src
      ? `src_ip="${src}" dest_ip="${target}"${portClause}`
      : `dest_ip="${target}"${portClause}`;
  }
  let q: string;
  if (options.isSyslog) {
    const excludedCategories = EXCLUDED_AUTH_CATEGORIES.map(
      (c) => `"${c}"`,
    ).join(", ");
    q = `search index=${index} ${stClause} ${targetClause} | rex "%(?<sc4s_cat>[A-Za-z0-9_]+)(?:-[A-Za-z0-9_]+)?-[0-7]-" | eval _cat=upper(coalesce(category, facility, sc4s_cat)) | where isnull(_cat) OR NOT (_cat IN (${excludedCategories}))`;
  } else {
    const hasSensitiveWire = sts.some(
      (s) => s === "stream:snmp" || s === "stream:ftp",
    );
    const redactClause = hasSensitiveWire
      ? ` | eval command=upper(mvindex(split(trim(coalesce(command, method)), " "), 0)) | eval command=if(in(command, "USER", "PASS", "ACCT"), "AUTH_CMD", command) | eval method=command | fields - _raw community varbind_list value_raw password passwd login authorization`
      : "";
    q = `search index=${index} ${stClause} ${targetClause}${redactClause}`;
  }
  const params = new URLSearchParams({
    q,
    earliest: String(Math.trunc(options.earliest)),
    latest: String(Math.trunc(options.latest)),
  });
  return `/app/splunk_adm/search?${params.toString()}`;
}

export type NormalizedSnmpVersion = "v1" | "v2c" | "v3" | "unknown";

export function classifySnmpVersion(
  rawVersion: unknown,
): NormalizedSnmpVersion {
  const v = asString(rawVersion).toLowerCase();
  if (!v) return "unknown";
  if (v === "1" || v === "v1" || v === "snmpv1") return "v1";
  if (
    v === "2" ||
    v === "2c" ||
    v === "v2" ||
    v === "v2c" ||
    v === "snmpv2" ||
    v === "snmpv2c"
  ) {
    return "v2c";
  }
  if (v === "3" || v === "v3" || v === "snmpv3") return "v3";
  return "unknown";
}

export function isSnmpSetOperation(rawPduOrMethod: unknown): boolean {
  const op = asString(rawPduOrMethod).toLowerCase();
  if (!op) return false;
  return (
    op === "set" ||
    op === "setrequest" ||
    op === "set-request" ||
    op === "set_request" ||
    op === "snmp-set" ||
    /\bset(?:-?request)?\b/.test(op)
  );
}

export function classifyCleartextPort(destPort: number): {
  protocol: "Telnet" | "TFTP" | "HTTP" | "FTP" | "SNMP" | "Management";
  isCleartextByPort: boolean;
} {
  switch (destPort) {
    case 23:
      return { protocol: "Telnet", isCleartextByPort: true };
    case 69:
      return { protocol: "TFTP", isCleartextByPort: true };
    case 80:
      return { protocol: "HTTP", isCleartextByPort: true };
    case 21:
      return { protocol: "FTP", isCleartextByPort: true };
    case 161:
    case 162:
      return { protocol: "SNMP", isCleartextByPort: false };
    default:
      return { protocol: "Management", isCleartextByPort: false };
  }
}

export interface NormalizedSnmpEvent {
  sourceType: "stream:snmp";
  timestamp: number | undefined;
  host: string;
  srcIp: string;
  destIp: string;
  destPort: number;
  snmpVersion: NormalizedSnmpVersion;
  pduType: string;
  isSet: boolean;
  status: string;
  bytes: number;
}

export interface NormalizedFtpEvent {
  sourceType: "stream:ftp";
  timestamp: number | undefined;
  host: string;
  srcIp: string;
  destIp: string;
  destPort: number;
  command: string;
  replyCode?: number;
  bytes: number;
}

export interface NormalizedNetflowMgmtEvent {
  sourceType: "stream:netflow";
  timestamp: number | undefined;
  host: string;
  exporterIp: string;
  srcIp: string;
  destIp: string;
  destPort: number;
  transport: string;
  protocol: "Telnet" | "TFTP" | "HTTP" | "FTP" | "SNMP" | "Management";
  bytes: number;
  packets: number;
}

export interface NormalizedSyslogReceiptEvent {
  sourceType: AllowedSyslogSourcetype;
  timestamp: number;
  count: number;
  rawHost: string;
  device: string;
  category: string;
}

export type NormalizedMgmtPlaneEvent =
  | NormalizedSnmpEvent
  | NormalizedFtpEvent
  | NormalizedNetflowMgmtEvent
  | NormalizedSyslogReceiptEvent;

function asString(value: unknown): string {
  if (typeof value === "string") return value.trim();
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  return "";
}

function asFiniteNumber(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim()) {
    const num = Number(value.trim());
    if (Number.isFinite(num)) return num;
  }
  return undefined;
}

function asEpochSeconds(value: unknown): number | undefined {
  const num = asFiniteNumber(value);
  if (num !== undefined && num > 0) return num;
  if (typeof value === "string" && value.trim()) {
    const parsed = Date.parse(value.trim());
    if (Number.isFinite(parsed) && parsed > 0) {
      return Math.floor(parsed / 1000);
    }
  }
  return undefined;
}

function sanitizeFtpVerb(raw: unknown): string {
  const token = asString(raw).toUpperCase().split(/\s+/)[0] ?? "";
  if (!/^[A-Z_]{2,12}$/.test(token)) return "FTP";
  if (AUTH_FTP_VERBS.has(token)) return "AUTH_CMD";
  return token;
}

function isSyslogSourcetype(st: string): st is AllowedSyslogSourcetype {
  return (ALLOWED_SYSLOG_SOURCETYPES as readonly string[]).includes(st);
}

/**
 * Normalizes a single allowlist-projected `stream:snmp`, `stream:ftp`,
 * `stream:netflow`, or syslog receipt row.
 */
export function normalizeMgmtPlaneRow(
  row: ProtocolRow,
  defaultSourcetype: MgmtPlaneSourcetype,
): NormalizedMgmtPlaneEvent | undefined {
  const stRaw = asString(row.sourcetype).toLowerCase();
  const sourceType: MgmtPlaneSourcetype =
    stRaw === "stream:snmp"
      ? "stream:snmp"
      : stRaw === "stream:ftp"
        ? "stream:ftp"
        : stRaw === "stream:netflow"
          ? "stream:netflow"
          : isSyslogSourcetype(stRaw)
            ? stRaw
            : defaultSourcetype;

  const host = asString(row.host) || "unknown";

  if (isSyslogSourcetype(sourceType)) {
    const timestamp = asEpochSeconds(row.last_seen ?? row._time);
    const rawHost = asString(row.host);
    if (!timestamp || !rawHost) return undefined;
    const category = asString(row.category || row.facility).toUpperCase();
    const facility = asString(row.facility).toUpperCase();
    if (
      (category && EXCLUDED_AUTH_SET.has(category)) ||
      (facility && EXCLUDED_AUTH_SET.has(facility))
    ) {
      return undefined;
    }
    const rawCount = asFiniteNumber(row.count);
    const count =
      rawCount !== undefined && rawCount >= 1 ? Math.trunc(rawCount) : 1;
    return {
      sourceType,
      timestamp,
      count,
      rawHost,
      device: shortenDeviceLabel(rawHost),
      category: category || "SYSLOG",
    };
  }

  const timestamp = asEpochSeconds(row._time);

  if (sourceType === "stream:snmp") {
    const srcIp = asString(row.src_ip);
    const destIp = asString(row.dest_ip);
    if (!srcIp || !destIp) return undefined;
    const rawPort = asFiniteNumber(row.dest_port);
    const destPort =
      rawPort !== undefined && rawPort >= 0 ? Math.trunc(rawPort) : 161;
    const snmpVersion = classifySnmpVersion(row.snmp_version ?? row.version);
    const pduRaw = asString(row.pdu_type ?? row.method) || "Unknown";
    const isSet = isSnmpSetOperation(pduRaw);
    const bytes = Math.max(
      0,
      (asFiniteNumber(row.bytes_in) ?? 0) +
        (asFiniteNumber(row.bytes_out) ?? 0),
    );
    return {
      sourceType: "stream:snmp",
      timestamp,
      host,
      srcIp,
      destIp,
      destPort,
      snmpVersion,
      pduType: pduRaw,
      isSet,
      status: asString(row.status) || "noError",
      bytes,
    };
  }

  if (sourceType === "stream:ftp") {
    const srcIp = asString(row.src_ip);
    const destIp = asString(row.dest_ip);
    if (!srcIp || !destIp) return undefined;
    const rawPort = asFiniteNumber(row.dest_port);
    const destPort =
      rawPort !== undefined && rawPort >= 0 ? Math.trunc(rawPort) : 21;
    const command = sanitizeFtpVerb(row.command ?? row.method);
    const rawReply = asFiniteNumber(row.reply_code);
    const statusText = asString(row.status);
    const parsedReplyMatch = /^(\d{3})\b/.exec(statusText);
    const replyCode =
      rawReply !== undefined
        ? Math.trunc(rawReply)
        : parsedReplyMatch
          ? Number(parsedReplyMatch[1])
          : undefined;
    const bytes = Math.max(
      0,
      (asFiniteNumber(row.bytes_in) ?? 0) +
        (asFiniteNumber(row.bytes_out) ?? 0),
    );
    return {
      sourceType: "stream:ftp",
      timestamp,
      host,
      srcIp,
      destIp,
      destPort,
      command,
      ...(replyCode !== undefined ? { replyCode } : {}),
      bytes,
    };
  }

  // stream:netflow
  const srcIp = asString(row.src_ip);
  const destIp = asString(row.dest_ip);
  const rawPort = asFiniteNumber(row.dest_port);
  if (!srcIp || !destIp || rawPort === undefined) return undefined;
  const destPort = Math.trunc(rawPort);
  if (destPort < 0 || destPort > 65535) return undefined;
  const { protocol } = classifyCleartextPort(destPort);
  const transportRaw = asString(row.transport ?? row.protocol).toUpperCase();
  const transport =
    transportRaw ||
    (destPort === 69 || destPort === 161 || destPort === 162 ? "UDP" : "TCP");
  const exporterIp = asString(row.exporter_ip) || host;
  const bytes = Math.max(
    0,
    asFiniteNumber(row.bytes) ??
      (asFiniteNumber(row.bytes_in) ?? 0) +
        (asFiniteNumber(row.bytes_out) ?? 0),
  );
  const packets = Math.max(0, asFiniteNumber(row.packets) ?? 0);

  return {
    sourceType: "stream:netflow",
    timestamp,
    host,
    exporterIp,
    srcIp,
    destIp,
    destPort,
    transport,
    protocol,
    bytes,
    packets,
  };
}

export interface MgmtPlaneFindingRow {
  /** URL-safe ID matching `^[A-Za-z0-9._:/-]{1,128}$` using `__`. */
  id: string;
  attention: boolean;
  category: MgmtPlaneCategory;
  findingLabel: string;
  sourceManager: string;
  targetDevice: string;
  rawTargetHost?: string;
  destPort?: number;
  countOrGapLabel: string;
  eventCount: number;
  gapMinutes?: number;
  totalBytes: number;
  detail: string;
  status: ProtocolStatus;
  reasons: string[];
  remediationNote: string;
  isSyslog: boolean;
  indexName: string;
  sourcetypes: MgmtPlaneSourcetype[];
  firstSeen?: number;
  lastSeen?: number;
}

export interface MgmtPlaneInvestigationResult {
  verdict: string;
  verdictStatus: ProtocolStatus;
  coverageStatus: ProtocolStatus;
  coverageLabel: string;
  hasActiveSnmp: boolean;
  hasActiveFtp: boolean;
  hasActiveNetflow: boolean;
  hasSyslogBaseline: boolean;
  kpis: ProtocolKpi[];
  distribution: ProtocolDistributionMetric[];
  rows: MgmtPlaneFindingRow[];
  matrixRows: string[];
  matrixCols: string[];
  matrixCells: ProtocolMatrixCell[];
  timelineEvents: ProtocolTimelineEvent[];
  timelineRowByEventId: Record<string, string>;
  outcomes: ProtocolSourceOutcome[];
  capped: boolean;
  streamReadiness?: StreamReadinessEntry[];
  bannerState?:
    | "empty"
    | "partial"
    | "blocked"
    | "unavailable"
    | "stale_config"
    | "estimate_only";
  bannerReason?: string;
  checkedAt: number;
}

function percentile(values: readonly number[], pct: number): number {
  if (!values.length) return 0;
  const sorted = [...values].sort((a, b) => a - b);
  const rank = Math.ceil((pct / 100) * sorted.length) - 1;
  const idx = Math.max(0, Math.min(sorted.length - 1, rank));
  return sorted[idx];
}

function buildSparklineBuckets(
  items: readonly { timestamp?: number; value: number }[],
  earliest: number,
  latest: number,
): number[] {
  const buckets = 6;
  const span = Math.max(1, latest - earliest);
  const grouped: number[][] = Array.from({ length: buckets }, () => []);
  for (const item of items) {
    const ts = item.timestamp ?? earliest;
    const idx = Math.min(
      buckets - 1,
      Math.max(0, Math.floor(((ts - earliest) / span) * buckets)),
    );
    grouped[idx].push(item.value);
  }
  const points = grouped.map((bucket) =>
    bucket.length ? bucket.reduce((a, b) => a + b, 0) : undefined,
  );
  const present = points.filter((p): p is number => p !== undefined);
  return present.length >= 4 ? present : [];
}

function statusPriority(status: ProtocolStatus): number {
  switch (status) {
    case "attention":
      return 4;
    case "unknown":
      return 3;
    case "not_covered":
      return 2;
    case "ok":
      return 1;
    case "none_observed":
      return 0;
  }
}

/**
 * Pure aggregation of normalized `stream:snmp`, `stream:ftp`, `stream:netflow`,
 * and syslog receipt events into Overview rows, KPI tiles, `DistributionBar`,
 * Manager × Target `HeatMatrix`, `SwimlaneTimeline`, and a single-sentence verdict.
 */
export function buildMgmtPlaneAnalysis(options: {
  events: readonly { event: NormalizedMgmtPlaneEvent; indexName: string }[];
  thresholds: ResolvedMgmtPlaneThresholds;
  earliest: number;
  latest: number;
  outcomes: ProtocolSourceOutcome[];
  capped: boolean;
  unparsedRowCount?: number;
  snmpConfigured?: boolean;
  ftpConfigured?: boolean;
  netflowConfigured?: boolean;
  syslogConfigured?: boolean;
  snmpOutcomes?: readonly ProtocolSourceOutcome[];
  ftpOutcomes?: readonly ProtocolSourceOutcome[];
  netflowOutcomes?: readonly ProtocolSourceOutcome[];
  syslogOutcomes?: readonly ProtocolSourceOutcome[];
  streamReadiness?: StreamReadinessEntry[];
}): MgmtPlaneInvestigationResult {
  const {
    events,
    thresholds,
    earliest,
    latest,
    outcomes,
    capped,
    unparsedRowCount = 0,
    snmpConfigured = false,
    ftpConfigured = false,
    netflowConfigured = false,
    syslogConfigured = false,
    snmpOutcomes,
    ftpOutcomes,
    netflowOutcomes,
    syslogOutcomes,
    streamReadiness,
  } = options;
  const nowSec = Math.floor(Date.now() / 1000);

  const anyBlocked = outcomes.some((o) => o.state === "blocked");
  const anyUnavailable = outcomes.some((o) => o.state === "unavailable");
  const anyPartialOutcome = outcomes.some(
    (o) => o.state === "partial" || Boolean(o.capped),
  );
  const anyDegraded =
    anyBlocked || anyUnavailable || capped || anyPartialOutcome;

  const snmpEvents = events.filter(
    (e): e is { event: NormalizedSnmpEvent; indexName: string } =>
      e.event.sourceType === "stream:snmp",
  );
  const ftpEvents = events.filter(
    (e): e is { event: NormalizedFtpEvent; indexName: string } =>
      e.event.sourceType === "stream:ftp",
  );
  const netflowEvents = events.filter(
    (e): e is { event: NormalizedNetflowMgmtEvent; indexName: string } =>
      e.event.sourceType === "stream:netflow",
  );
  const syslogEvents = events.filter(
    (e): e is { event: NormalizedSyslogReceiptEvent; indexName: string } =>
      isSyslogSourcetype(e.event.sourceType),
  );

  const isSourceDegraded = (
    configured: boolean,
    srcOutcomes: readonly ProtocolSourceOutcome[] | undefined,
    streamId?: "snmp" | "ftp",
  ): boolean => {
    if (streamId) {
      const readiness = streamReadiness?.find((r) => r.streamId === streamId);
      if (readiness?.state === "estimate_only") return true;
    }
    const list = srcOutcomes ?? (configured ? outcomes : []);
    return (
      list.some(
        (o) =>
          o.state === "blocked" ||
          o.state === "unavailable" ||
          o.state === "partial" ||
          Boolean(o.capped),
      ) ||
      (configured && srcOutcomes === undefined && capped)
    );
  };

  const isSourceHealthyComplete = (
    configured: boolean,
    srcOutcomes: readonly ProtocolSourceOutcome[] | undefined,
    streamId?: "snmp" | "ftp",
  ): boolean => {
    if (isSourceDegraded(configured, srcOutcomes, streamId)) return false;
    const list = srcOutcomes ?? (configured ? outcomes : []);
    if (!configured || !list.length) return false;
    return list.every((o) => o.state === "complete" && !o.capped);
  };

  const snmpDegraded = isSourceDegraded(snmpConfigured, snmpOutcomes, "snmp");
  const ftpDegraded = isSourceDegraded(ftpConfigured, ftpOutcomes, "ftp");
  const netflowDegraded = isSourceDegraded(netflowConfigured, netflowOutcomes);
  const syslogDegraded = isSourceDegraded(syslogConfigured, syslogOutcomes);

  const hasActiveSnmp =
    (snmpEvents.length > 0 && !snmpDegraded) ||
    isSourceHealthyComplete(snmpConfigured, snmpOutcomes, "snmp");
  const hasActiveFtp =
    (ftpEvents.length > 0 && !ftpDegraded) ||
    isSourceHealthyComplete(ftpConfigured, ftpOutcomes, "ftp");
  const hasActiveNetflow =
    (netflowEvents.length > 0 && !netflowDegraded) ||
    isSourceHealthyComplete(netflowConfigured, netflowOutcomes);

  const estimateEntries = (streamReadiness ?? []).filter(
    (e) => e.state === "estimate_only",
  );
  const anyEstimate = estimateEntries.length > 0;
  const estimateLabel = estimateEntries.map((e) => e.streamId).join(", ");

  if (!events.length) {
    if (anyEstimate) {
      return {
        verdict: `Stream ${estimateLabel} is in Estimate mode (statsOnly=true); no event rows are indexed.`,
        verdictStatus: "unknown",
        coverageStatus: "unknown",
        coverageLabel: "Estimate mode",
        hasActiveSnmp: false,
        hasActiveFtp: false,
        hasActiveNetflow,
        hasSyslogBaseline: false,
        kpis: [],
        distribution: [],
        rows: [],
        matrixRows: [],
        matrixCols: [],
        matrixCells: [],
        timelineEvents: [],
        timelineRowByEventId: {},
        outcomes,
        capped,
        streamReadiness,
        bannerState: "estimate_only",
        bannerReason: estimateEntries[0].detail,
        checkedAt: nowSec,
      };
    }
    if (anyBlocked) {
      return {
        verdict: "Source evidence could not be read for this role.",
        verdictStatus: "unknown",
        coverageStatus: "unknown",
        coverageLabel: "Blocked",
        hasActiveSnmp,
        hasActiveFtp,
        hasActiveNetflow,
        hasSyslogBaseline: false,
        kpis: [],
        distribution: [],
        rows: [],
        matrixRows: [],
        matrixCols: [],
        matrixCells: [],
        timelineEvents: [],
        timelineRowByEventId: {},
        outcomes,
        capped,
        streamReadiness,
        bannerState: "blocked",
        bannerReason:
          outcomes.find((o) => o.state === "blocked")?.detail ??
          "Access denied for one or more source indexes.",
        checkedAt: nowSec,
      };
    }
    if (anyUnavailable) {
      return {
        verdict: "One or more configured sources failed in this UTC window.",
        verdictStatus: "unknown",
        coverageStatus: "unknown",
        coverageLabel: "Unavailable",
        hasActiveSnmp,
        hasActiveFtp,
        hasActiveNetflow,
        hasSyslogBaseline: false,
        kpis: [],
        distribution: [],
        rows: [],
        matrixRows: [],
        matrixCols: [],
        matrixCells: [],
        timelineEvents: [],
        timelineRowByEventId: {},
        outcomes,
        capped,
        streamReadiness,
        bannerState: "unavailable",
        bannerReason:
          outcomes.find((o) => o.state === "unavailable")?.detail ??
          "Configured source failed to complete.",
        checkedAt: nowSec,
      };
    }
    if (anyDegraded) {
      return {
        verdict:
          "Search hit row cap before matching management-plane events were found — narrow the UTC window or filter.",
        verdictStatus: "unknown",
        coverageStatus: "unknown",
        coverageLabel: "Capped",
        hasActiveSnmp,
        hasActiveFtp,
        hasActiveNetflow,
        hasSyslogBaseline: false,
        kpis: [],
        distribution: [],
        rows: [],
        matrixRows: [],
        matrixCols: [],
        matrixCells: [],
        timelineEvents: [],
        timelineRowByEventId: {},
        outcomes,
        capped,
        streamReadiness,
        bannerState: "partial",
        bannerReason:
          "Search hit row cap before matching management-plane events were found — narrow the UTC window or filter.",
        checkedAt: nowSec,
      };
    }
    if (unparsedRowCount > 0) {
      const reason = `${unparsedRowCount} ${unparsedRowCount === 1 ? "row" : "rows"} returned but could not be normalized.`;
      return {
        verdict: reason,
        verdictStatus: "unknown",
        coverageStatus: "unknown",
        coverageLabel: "Unparsed rows",
        hasActiveSnmp: false,
        hasActiveFtp: false,
        hasActiveNetflow: false,
        hasSyslogBaseline: false,
        kpis: [],
        distribution: [],
        rows: [],
        matrixRows: [],
        matrixCols: [],
        matrixCells: [],
        timelineEvents: [],
        timelineRowByEventId: {},
        outcomes,
        capped,
        streamReadiness,
        bannerState: "unavailable",
        bannerReason: reason,
        checkedAt: nowSec,
      };
    }
    return {
      verdict:
        "No cleartext management traffic, legacy SNMP, or syslog receipt gaps observed in this UTC window.",
      verdictStatus: "none_observed",
      coverageStatus: "none_observed",
      coverageLabel: "None observed",
      hasActiveSnmp,
      hasActiveFtp,
      hasActiveNetflow,
      hasSyslogBaseline: false,
      kpis: [],
      distribution: [],
      rows: [],
      matrixRows: [],
      matrixCols: [],
      matrixCells: [],
      timelineEvents: [],
      timelineRowByEventId: {},
      outcomes,
      capped,
      streamReadiness,
      bannerState: "empty",
      bannerReason: "No matching management-plane events in this UTC window.",
      checkedAt: nowSec,
    };
  }

  const rows: MgmtPlaneFindingRow[] = [];
  const timelineEntries: { event: ProtocolTimelineEvent; rowId: string }[] = [];

  // Track SNMPv1/v2c, SNMP SET, Cleartext, Receipt Gap distributions
  const snmpLegacyPerTarget: number[] = [];
  const snmpSetPerTarget: number[] = [];
  const cleartextPerTarget: number[] = [];
  const receiptGapDevices: string[] = [];

  let snmpLegacyOrSetEventCount = 0;
  let cleartextSessionCount = 0;

  // 1. Aggregate SNMP (stream:snmp, correlated with port 161/162 NetFlow if present)
  const snmpPairs = new Set<string>();
  const snmpGroups = new Map<
    string,
    {
      srcIp: string;
      destIp: string;
      indexName: string;
      events: NormalizedSnmpEvent[];
    }
  >();

  for (const entry of snmpEvents) {
    const key = `${entry.event.srcIp}\0${entry.event.destIp}`;
    snmpPairs.add(key);
    const existing = snmpGroups.get(key) ?? {
      srcIp: entry.event.srcIp,
      destIp: entry.event.destIp,
      indexName: entry.indexName,
      events: [],
    };
    existing.events.push(entry.event);
    snmpGroups.set(key, existing);
  }

  for (const group of snmpGroups.values()) {
    const rowId = makeMgmtPlaneRowId("snmp", group.srcIp, group.destIp);
    const versions = new Set(group.events.map((e) => e.snmpVersion));
    const hasV1 = versions.has("v1");
    const hasV2c = versions.has("v2c");
    const hasV3 = versions.has("v3");
    const hasUnknownVer = versions.has("unknown");
    const legacyV1V2cEvents = group.events.filter(
      (e) =>
        e.snmpVersion === "v1" ||
        (e.snmpVersion === "v2c" && thresholds.flagSnmpV2c),
    );
    const setEvents = group.events.filter((e) => e.isSet);
    const flagLegacy = legacyV1V2cEvents.length > 0;
    const flagSet = setEvents.length > 0;
    const attention = flagLegacy || flagSet;

    if (flagLegacy) snmpLegacyPerTarget.push(legacyV1V2cEvents.length);
    if (flagSet) snmpSetPerTarget.push(setEvents.length);

    const flaggedEventSet = new Set<NormalizedSnmpEvent>([
      ...legacyV1V2cEvents,
      ...setEvents,
    ]);
    snmpLegacyOrSetEventCount += flaggedEventSet.size;

    const pduList = [...new Set(group.events.map((e) => e.pduType))];
    const totalBytes = group.events.reduce((s, e) => s + e.bytes, 0);
    const timestamps = group.events
      .map((e) => e.timestamp)
      .filter((t): t is number => t !== undefined);

    const reasons: string[] = [];
    if (hasV1) {
      const v1Count = group.events.filter((e) => e.snmpVersion === "v1").length;
      reasons.push(
        `SNMPv1 cleartext community protocol (${v1Count} ${v1Count === 1 ? "event" : "events"})`,
      );
    }
    if (hasV2c && thresholds.flagSnmpV2c) {
      const v2Count = group.events.filter(
        (e) => e.snmpVersion === "v2c",
      ).length;
      reasons.push(
        `SNMPv2c cleartext community protocol (${v2Count} ${v2Count === 1 ? "event" : "events"})`,
      );
    }
    if (flagSet) {
      reasons.push(
        `SNMP SET write operation (${setEvents.length} ${setEvents.length === 1 ? "event" : "events"})`,
      );
    }

    const verLabel =
      hasV1 && hasV2c
        ? "SNMPv1/v2c"
        : hasV1
          ? "SNMPv1"
          : hasV2c
            ? "SNMPv2c"
            : hasV3
              ? "SNMPv3"
              : "SNMP";
    const findingLabel =
      flagLegacy && flagSet
        ? `${verLabel} · SET`
        : flagLegacy
          ? verLabel
          : flagSet
            ? `${verLabel} SET`
            : verLabel;

    const category: MgmtPlaneCategory = flagSet
      ? "snmp_set"
      : flagLegacy
        ? "snmp_v1_v2c"
        : "snmp_v3";

    const status: ProtocolStatus = attention
      ? "attention"
      : hasV3 && !hasUnknownVer
        ? "ok"
        : "unknown";

    const detail = attention
      ? `${verLabel} ${pduList.join(", ")}`
      : hasV3 && !hasUnknownVer
        ? `SNMPv3 ${pduList.join(", ")} (encrypted)`
        : `${pduList.join(", ")} (SNMP version unknown)`;

    rows.push({
      id: rowId,
      attention,
      category,
      findingLabel,
      sourceManager: group.srcIp,
      targetDevice: group.destIp,
      destPort: 161,
      countOrGapLabel: `${formatCount(group.events.length)} ${group.events.length === 1 ? "event" : "events"}`,
      eventCount: group.events.length,
      totalBytes,
      detail,
      status,
      reasons:
        reasons.length > 0
          ? reasons
          : status === "unknown"
            ? ["SNMP version was not reported in stream:snmp."]
            : [],
      remediationNote:
        "Migrate SNMPv1/v2c polling and traps to SNMPv3 (authPriv), restrict write access, and audit any SNMP SET operations.",
      isSyslog: false,
      indexName: group.indexName,
      sourcetypes: ["stream:snmp"],
      ...(timestamps.length ? { firstSeen: Math.min(...timestamps) } : {}),
      ...(timestamps.length ? { lastSeen: Math.max(...timestamps) } : {}),
    });

    const lane = shortenDeviceLabel(group.destIp);
    for (let i = 0; i < group.events.length; i += 1) {
      const ev = group.events[i];
      if (ev.timestamp === undefined) continue;
      const evFlagged =
        ev.isSet ||
        ev.snmpVersion === "v1" ||
        (ev.snmpVersion === "v2c" && thresholds.flagSnmpV2c);
      const evId = `snmp_${rowId}_${i}_${ev.timestamp}`;
      const evVer =
        ev.snmpVersion === "unknown" ? "SNMP" : `SNMP${ev.snmpVersion}`;
      timelineEntries.push({
        event: {
          id: evId,
          lane,
          timestamp: ev.timestamp,
          kind: evFlagged ? "attention" : "ok",
          label: ev.isSet ? `SNMP SET (${evVer})` : `${evVer} ${ev.pduType}`,
          detail: `${ev.srcIp} → ${ev.destIp} (${evVer} ${ev.pduType})`,
        },
        rowId,
      });
    }
  }

  // 2. Aggregate FTP (stream:ftp) — always cleartext attention
  const ftpGroups = new Map<
    string,
    {
      srcIp: string;
      destIp: string;
      indexName: string;
      events: NormalizedFtpEvent[];
    }
  >();
  for (const entry of ftpEvents) {
    const key = `${entry.event.srcIp}\0${entry.event.destIp}`;
    const existing = ftpGroups.get(key) ?? {
      srcIp: entry.event.srcIp,
      destIp: entry.event.destIp,
      indexName: entry.indexName,
      events: [],
    };
    existing.events.push(entry.event);
    ftpGroups.set(key, existing);
  }

  for (const group of ftpGroups.values()) {
    const rowId = makeMgmtPlaneRowId("ftp", group.srcIp, group.destIp);
    const commands = [...new Set(group.events.map((e) => e.command))];
    const replyCodes = [
      ...new Set(
        group.events
          .map((e) => e.replyCode)
          .filter((c): c is number => c !== undefined),
      ),
    ];
    const totalBytes = group.events.reduce((s, e) => s + e.bytes, 0);
    const timestamps = group.events
      .map((e) => e.timestamp)
      .filter((t): t is number => t !== undefined);

    cleartextSessionCount += group.events.length;
    cleartextPerTarget.push(group.events.length);

    const codeNote = replyCodes.length ? ` (${replyCodes.join(", ")})` : "";
    rows.push({
      id: rowId,
      attention: true,
      category: "cleartext",
      findingLabel: "Cleartext FTP",
      sourceManager: group.srcIp,
      targetDevice: group.destIp,
      destPort: 21,
      countOrGapLabel: `${formatCount(group.events.length)} ${group.events.length === 1 ? "session" : "sessions"}`,
      eventCount: group.events.length,
      totalBytes,
      detail: `FTP ${commands.join(", ")}${codeNote}`,
      status: "attention",
      reasons: [
        `Cleartext FTP management session (${group.events.length} ${group.events.length === 1 ? "session" : "sessions"}; ${commands.join(", ")})`,
      ],
      remediationNote:
        "Replace cleartext FTP with SFTP (SSH), SCP, or FTPS (TLS) to protect management transfers and credentials in transit.",
      isSyslog: false,
      indexName: group.indexName,
      sourcetypes: ["stream:ftp"],
      ...(timestamps.length ? { firstSeen: Math.min(...timestamps) } : {}),
      ...(timestamps.length ? { lastSeen: Math.max(...timestamps) } : {}),
    });

    const lane = shortenDeviceLabel(group.destIp);
    for (let i = 0; i < group.events.length; i += 1) {
      const ev = group.events[i];
      if (ev.timestamp === undefined) continue;
      const evId = `ftp_${rowId}_${i}_${ev.timestamp}`;
      timelineEntries.push({
        event: {
          id: evId,
          lane,
          timestamp: ev.timestamp,
          kind: "attention",
          label: `Cleartext FTP (${ev.command})`,
          detail: `${ev.srcIp} → ${ev.destIp} (TCP/${ev.destPort} ${ev.command})`,
        },
        rowId,
      });
    }
  }

  // 3. Aggregate NetFlow cleartext management ports (21, 23, 69, 80, and uncorrelated 161/162)
  const netflowGroups = new Map<
    string,
    {
      srcIp: string;
      destIp: string;
      destPort: number;
      protocol: NormalizedNetflowMgmtEvent["protocol"];
      indexName: string;
      events: NormalizedNetflowMgmtEvent[];
    }
  >();

  for (const entry of netflowEvents) {
    const ev = entry.event;
    if (ev.destPort === 80 && !thresholds.flagHttpPort80) continue;
    if (
      (ev.destPort === 161 || ev.destPort === 162) &&
      snmpPairs.has(`${ev.srcIp}\0${ev.destIp}`)
    ) {
      // Already represented with authoritative SNMP version/PDU from stream:snmp
      continue;
    }
    const key = `${ev.srcIp}\0${ev.destIp}\0${ev.destPort}`;
    const existing = netflowGroups.get(key) ?? {
      srcIp: ev.srcIp,
      destIp: ev.destIp,
      destPort: ev.destPort,
      protocol: ev.protocol,
      indexName: entry.indexName,
      events: [],
    };
    existing.events.push(ev);
    netflowGroups.set(key, existing);
  }

  for (const group of netflowGroups.values()) {
    const isSnmpPort = group.destPort === 161 || group.destPort === 162;
    const isCleartext = classifyCleartextPort(group.destPort).isCleartextByPort;
    const rowId = makeMgmtPlaneRowId(
      "nf",
      group.srcIp,
      group.destIp,
      String(group.destPort),
    );
    const totalBytes = group.events.reduce((s, e) => s + e.bytes, 0);
    const timestamps = group.events
      .map((e) => e.timestamp)
      .filter((t): t is number => t !== undefined);
    const transport = group.events[0]?.transport ?? "TCP";

    if (isCleartext) {
      cleartextSessionCount += group.events.length;
      cleartextPerTarget.push(group.events.length);
    }

    const findingLabel = isSnmpPort
      ? "SNMP (NetFlow)"
      : `Cleartext ${group.protocol}`;
    const status: ProtocolStatus = isCleartext
      ? "attention"
      : isSnmpPort
        ? "not_covered"
        : "unknown";
    const detail = isSnmpPort
      ? `${transport}/${group.destPort} (${formatBytes(totalBytes)}; version not covered)`
      : `${transport}/${group.destPort} (${formatBytes(totalBytes)})`;

    rows.push({
      id: rowId,
      attention: isCleartext,
      category: isCleartext ? "cleartext" : "netflow_snmp",
      findingLabel,
      sourceManager: group.srcIp,
      targetDevice: group.destIp,
      destPort: group.destPort,
      countOrGapLabel: isCleartext
        ? `${formatCount(group.events.length)} ${group.events.length === 1 ? "session" : "sessions"}`
        : `${formatCount(group.events.length)} ${group.events.length === 1 ? "flow" : "flows"}`,
      eventCount: group.events.length,
      totalBytes,
      detail,
      status,
      reasons: isCleartext
        ? [
            `Cleartext ${group.protocol} traffic on ${transport}/${group.destPort} (${group.events.length} ${group.events.length === 1 ? "session" : "sessions"}, ${formatBytes(totalBytes)})`,
          ]
        : [
            `NetFlow observed ${transport}/${group.destPort} SNMP traffic (${formatBytes(totalBytes)}), but SNMP version and SET writes are not covered without stream:snmp.`,
          ],
      remediationNote: isSnmpPort
        ? "Enable stream:snmp to verify SNMPv3 vs SNMPv1/v2c and detect SNMP SET operations; NetFlow only confirms port 161/162 traffic."
        : group.protocol === "HTTP"
          ? "Migrate cleartext HTTP management (TCP/80) to HTTPS (TLS 1.2+) and disable HTTP server listeners on management interfaces."
          : group.protocol === "Telnet"
            ? "Disable Telnet (TCP/23) and enforce SSHv2 with key/TACACS+ authentication."
            : group.protocol === "FTP"
              ? "Disable FTP (TCP/21) and migrate file transfers to SFTP, SCP, or FTPS."
              : "Disable TFTP (UDP/69) and migrate image/config transfers to SCP, SFTP, or HTTPS.",
      isSyslog: false,
      indexName: group.indexName,
      sourcetypes: ["stream:netflow"],
      ...(timestamps.length ? { firstSeen: Math.min(...timestamps) } : {}),
      ...(timestamps.length ? { lastSeen: Math.max(...timestamps) } : {}),
    });

    if (isCleartext) {
      const lane = shortenDeviceLabel(group.destIp);
      for (let i = 0; i < group.events.length; i += 1) {
        const ev = group.events[i];
        if (ev.timestamp === undefined) continue;
        const evId = `nf_${rowId}_${i}_${ev.timestamp}`;
        timelineEntries.push({
          event: {
            id: evId,
            lane,
            timestamp: ev.timestamp,
            kind: "attention",
            label: `Cleartext ${group.protocol} (${transport}/${group.destPort})`,
            detail: `${ev.srcIp} → ${ev.destIp} (${transport}/${group.destPort}, ${formatBytes(ev.bytes)})`,
          },
          rowId,
        });
      }
    }
  }

  // 4. Syslog receipt gap detection (peer comparison requires >= 2 devices)
  const syslogByDevice = new Map<
    string,
    {
      device: string;
      rawHost: string;
      indexName: string;
      sourcetypes: Set<AllowedSyslogSourcetype>;
      categories: Set<string>;
      firstSeen: number;
      lastSeen: number;
      count: number;
    }
  >();

  for (const entry of syslogEvents) {
    const ev = entry.event;
    const existing = syslogByDevice.get(ev.device);
    if (existing) {
      existing.count += ev.count;
      existing.firstSeen = Math.min(existing.firstSeen, ev.timestamp);
      existing.lastSeen = Math.max(existing.lastSeen, ev.timestamp);
      existing.sourcetypes.add(ev.sourceType);
      existing.categories.add(ev.category);
    } else {
      syslogByDevice.set(ev.device, {
        device: ev.device,
        rawHost: ev.rawHost,
        indexName: entry.indexName,
        sourcetypes: new Set([ev.sourceType]),
        categories: new Set([ev.category]),
        firstSeen: ev.timestamp,
        lastSeen: ev.timestamp,
        count: ev.count,
      });
    }
  }

  const syslogDeviceList = [...syslogByDevice.values()];
  const hasSyslogBaseline = syslogDeviceList.length >= 2;

  if (syslogDeviceList.length === 1) {
    const only = syslogDeviceList[0];
    const rowId = makeMgmtPlaneRowId("syslog", "peer-baseline", only.device);
    rows.push({
      id: rowId,
      attention: false,
      category: "syslog_baseline",
      findingLabel: "Syslog baseline",
      sourceManager: "Syslog peer baseline",
      targetDevice: only.device,
      rawTargetHost: only.rawHost,
      countOrGapLabel: `${formatCount(only.count)} ${only.count === 1 ? "event" : "events"}`,
      eventCount: only.count,
      totalBytes: 0,
      detail: "Only 1 device reported; ≥ 2 peers required",
      status: syslogDegraded ? "unknown" : "not_covered",
      reasons: [
        syslogDegraded
          ? "Syslog source was degraded or capped; peer baseline could not be confirmed."
          : "Only 1 device reported syslog in this UTC window; receipt-gap comparison requires at least 2 peer devices and cannot establish a baseline.",
      ],
      remediationNote:
        "Verify syslog forwarding on peer devices; single-device windows cannot distinguish quiet periods from collector receipt gaps.",
      isSyslog: true,
      indexName: only.indexName,
      sourcetypes: [...only.sourcetypes],
      firstSeen: only.firstSeen,
      lastSeen: only.lastSeen,
    });
  } else if (syslogDeviceList.length >= 2) {
    const gapThresholdSec = thresholds.receiptGapMinutes * 60;
    for (const dev of syslogDeviceList) {
      let maxPeerLastSeen = -Infinity;
      let latestPeerDevice = "";
      for (const peer of syslogDeviceList) {
        if (peer.device === dev.device) continue;
        if (peer.lastSeen > maxPeerLastSeen) {
          maxPeerLastSeen = peer.lastSeen;
          latestPeerDevice = peer.device;
        }
      }
      const gapSeconds = maxPeerLastSeen - dev.lastSeen;
      const gapMinutes = Math.round(gapSeconds / 60);
      const isGap = gapSeconds >= gapThresholdSec;
      const rowId = makeMgmtPlaneRowId("syslog", "peer-baseline", dev.device);

      if (isGap) {
        receiptGapDevices.push(dev.device);
      }

      rows.push({
        id: rowId,
        attention: isGap,
        category: isGap ? "receipt_gap" : "syslog_ok",
        findingLabel: isGap ? "Receipt gap" : "Syslog reporting",
        sourceManager: "Syslog peer baseline",
        targetDevice: dev.device,
        rawTargetHost: dev.rawHost,
        countOrGapLabel: isGap
          ? `${gapMinutes} min gap`
          : `${formatCount(dev.count)} ${dev.count === 1 ? "event" : "events"}`,
        eventCount: dev.count,
        ...(isGap ? { gapMinutes } : {}),
        totalBytes: 0,
        detail: isGap
          ? `Stopped ${gapMinutes} min before ${latestPeerDevice}`
          : `Reporting within ${thresholds.receiptGapMinutes} min of peers`,
        status: isGap ? "attention" : syslogDegraded ? "unknown" : "ok",
        reasons: isGap
          ? [
              `Receipt gap: syslog stopped arriving ${gapMinutes} min before latest peer event (${latestPeerDevice}). Syslog stopped arriving while peers continued reporting; does not prove device down.`,
            ]
          : syslogDegraded
            ? [
                "Syslog source was degraded or capped; peer completeness is unknown.",
              ]
            : [],
        remediationNote: isGap
          ? "Check SC4S / syslog collector path, forwarder queues, management interface ACLs, and device logging configuration. Syslog stopped arriving while peers continued reporting; does not prove device down."
          : "Syslog events arrived consistently relative to peer devices in this window.",
        isSyslog: true,
        indexName: dev.indexName,
        sourcetypes: [...dev.sourcetypes],
        firstSeen: dev.firstSeen,
        lastSeen: dev.lastSeen,
      });

      if (isGap) {
        timelineEntries.push({
          event: {
            id: `gap_${rowId}_${dev.lastSeen}`,
            lane: dev.device,
            timestamp: dev.lastSeen,
            kind: "attention",
            label: `Receipt gap (${gapMinutes}m before ${latestPeerDevice})`,
            detail:
              "Syslog stopped arriving while peers continued reporting; does not prove device down.",
          },
          rowId,
        });
      }
    }
  }

  // Flagged-first sorting
  rows.sort((a, b) => {
    if (a.attention !== b.attention) return a.attention ? -1 : 1;
    const pDiff = statusPriority(b.status) - statusPriority(a.status);
    if (pDiff !== 0) return pDiff;
    if ((b.gapMinutes ?? 0) !== (a.gapMinutes ?? 0)) {
      return (b.gapMinutes ?? 0) - (a.gapMinutes ?? 0);
    }
    if (b.eventCount !== a.eventCount) return b.eventCount - a.eventCount;
    return a.id.localeCompare(b.id);
  });

  // 4 single-metric KPI tiles — never claim "ok" when contributing source(s) are degraded
  const flaggedRows = rows.filter((r) => r.attention);
  const hasCleartextCoverage = hasActiveFtp || hasActiveNetflow;
  const cleartextDegraded = ftpDegraded || netflowDegraded;

  const findingSpark = buildSparklineBuckets(
    [
      ...snmpEvents
        .filter(
          (e) =>
            e.event.isSet ||
            e.event.snmpVersion === "v1" ||
            (e.event.snmpVersion === "v2c" && thresholds.flagSnmpV2c),
        )
        .map((e) => ({ timestamp: e.event.timestamp, value: 1 })),
      ...ftpEvents.map((e) => ({ timestamp: e.event.timestamp, value: 1 })),
      ...netflowEvents
        .filter(
          (e) =>
            classifyCleartextPort(e.event.destPort).isCleartextByPort &&
            (e.event.destPort !== 80 || thresholds.flagHttpPort80),
        )
        .map((e) => ({ timestamp: e.event.timestamp, value: 1 })),
    ],
    earliest,
    latest,
  );

  const snmpSpark = buildSparklineBuckets(
    snmpEvents.map((e) => ({
      timestamp: e.event.timestamp,
      value:
        e.event.isSet ||
        e.event.snmpVersion === "v1" ||
        (e.event.snmpVersion === "v2c" && thresholds.flagSnmpV2c)
          ? 1
          : 0,
    })),
    earliest,
    latest,
  );

  const cleartextSpark = buildSparklineBuckets(
    [
      ...ftpEvents.map((e) => ({ timestamp: e.event.timestamp, value: 1 })),
      ...netflowEvents
        .filter(
          (e) =>
            classifyCleartextPort(e.event.destPort).isCleartextByPort &&
            (e.event.destPort !== 80 || thresholds.flagHttpPort80),
        )
        .map((e) => ({ timestamp: e.event.timestamp, value: 1 })),
    ],
    earliest,
    latest,
  );

  const gapSpark = buildSparklineBuckets(
    syslogEvents.map((e) => ({
      timestamp: e.event.timestamp,
      value: e.event.count,
    })),
    earliest,
    latest,
  );

  const allNotCovered = rows.every((r) => r.status === "not_covered");

  const kpis: ProtocolKpi[] = [
    {
      id: "findings",
      label: "Hygiene Findings",
      value:
        flaggedRows.length > 0
          ? formatCount(flaggedRows.length)
          : anyDegraded
            ? "Unknown"
            : allNotCovered
              ? "Not covered"
              : "0",
      ...(flaggedRows.length > 0 || (!anyDegraded && !allNotCovered)
        ? { unit: flaggedRows.length === 1 ? "finding" : "findings" }
        : {}),
      status:
        flaggedRows.length > 0
          ? "attention"
          : anyDegraded
            ? "unknown"
            : allNotCovered
              ? "not_covered"
              : "ok",
      ...(findingSpark.length ? { sparkline: findingSpark } : {}),
    },
    {
      id: "snmp-legacy",
      label: "SNMPv1/v2c & SET",
      value:
        snmpLegacyOrSetEventCount > 0
          ? formatCount(snmpLegacyOrSetEventCount)
          : snmpDegraded
            ? "Unknown"
            : hasActiveSnmp
              ? "0"
              : "Not covered",
      ...(snmpLegacyOrSetEventCount > 0 || (hasActiveSnmp && !snmpDegraded)
        ? { unit: snmpLegacyOrSetEventCount === 1 ? "event" : "events" }
        : {}),
      status:
        snmpLegacyOrSetEventCount > 0
          ? "attention"
          : snmpDegraded
            ? "unknown"
            : hasActiveSnmp
              ? "ok"
              : "not_covered",
      ...(snmpSpark.length ? { sparkline: snmpSpark } : {}),
    },
    {
      id: "cleartext",
      label: "Cleartext Sessions",
      value:
        cleartextSessionCount > 0
          ? formatCount(cleartextSessionCount)
          : cleartextDegraded
            ? "Unknown"
            : hasCleartextCoverage
              ? "0"
              : "Not covered",
      ...(cleartextSessionCount > 0 ||
      (hasCleartextCoverage && !cleartextDegraded)
        ? { unit: cleartextSessionCount === 1 ? "session" : "sessions" }
        : {}),
      status:
        cleartextSessionCount > 0
          ? "attention"
          : cleartextDegraded
            ? "unknown"
            : hasCleartextCoverage
              ? "ok"
              : "not_covered",
      ...(cleartextSpark.length ? { sparkline: cleartextSpark } : {}),
    },
    {
      id: "receipt-gaps",
      label: "Receipt Gaps",
      value:
        receiptGapDevices.length > 0
          ? formatCount(receiptGapDevices.length)
          : syslogDegraded
            ? "Unknown"
            : hasSyslogBaseline
              ? "0"
              : "Not covered",
      ...(receiptGapDevices.length > 0 || (hasSyslogBaseline && !syslogDegraded)
        ? { unit: receiptGapDevices.length === 1 ? "device" : "devices" }
        : {}),
      status:
        receiptGapDevices.length > 0
          ? "attention"
          : syslogDegraded
            ? "unknown"
            : hasSyslogBaseline
              ? "ok"
              : "not_covered",
      ...(gapSpark.length ? { sparkline: gapSpark } : {}),
    },
  ];

  // DistributionBar by hygiene finding category (true category totals in `count`)
  const distribution: ProtocolDistributionMetric[] = [];
  if (snmpLegacyPerTarget.length > 0) {
    const totalSnmpLegacy = snmpLegacyPerTarget.reduce((sum, v) => sum + v, 0);
    distribution.push({
      id: "snmp_v1_v2c",
      label: "SNMPv1/v2c",
      p50: Math.round(percentile(snmpLegacyPerTarget, 50)),
      p95: Math.round(percentile(snmpLegacyPerTarget, 95)),
      count: totalSnmpLegacy,
      unit: "events",
      status: "attention",
    });
  }
  if (snmpSetPerTarget.length > 0) {
    const totalSnmpSet = snmpSetPerTarget.reduce((sum, v) => sum + v, 0);
    distribution.push({
      id: "snmp_set",
      label: "SNMP SET",
      p50: Math.round(percentile(snmpSetPerTarget, 50)),
      p95: Math.round(percentile(snmpSetPerTarget, 95)),
      count: totalSnmpSet,
      unit: "events",
      status: "attention",
    });
  }
  if (cleartextPerTarget.length > 0) {
    const totalCleartext = cleartextPerTarget.reduce((sum, v) => sum + v, 0);
    distribution.push({
      id: "cleartext",
      label: "Cleartext protocols",
      p50: Math.round(percentile(cleartextPerTarget, 50)),
      p95: Math.round(percentile(cleartextPerTarget, 95)),
      count: totalCleartext,
      unit: "sessions",
      status: "attention",
    });
  }
  if (receiptGapDevices.length > 0) {
    distribution.push({
      id: "receipt_gap",
      label: "Receipt Gap",
      p50: receiptGapDevices.length,
      p95: receiptGapDevices.length,
      count: receiptGapDevices.length,
      unit: "devices",
      status: "attention",
    });
  }

  // Matrix: Manager/Source × Target/Device
  interface MatrixBucket {
    manager: string;
    target: string;
    rows: MgmtPlaneFindingRow[];
  }
  const matrixBuckets = new Map<string, MatrixBucket>();
  for (const row of rows) {
    const manager =
      row.sourceManager === "Syslog peer baseline"
        ? "Syslog peer baseline"
        : shortenDeviceLabel(row.sourceManager);
    const target = shortenDeviceLabel(row.targetDevice);
    const key = `${manager}\0${target}`;
    const bucket = matrixBuckets.get(key) ?? { manager, target, rows: [] };
    bucket.rows.push(row);
    matrixBuckets.set(key, bucket);
  }

  const flaggedManagers = new Set<string>();
  const flaggedTargets = new Set<string>();
  const matrixCells: ProtocolMatrixCell[] = [];
  for (const bucket of matrixBuckets.values()) {
    const sorted = [...bucket.rows].sort(
      (a, b) => statusPriority(b.status) - statusPriority(a.status),
    );
    const top = sorted[0];
    if (top.attention) {
      flaggedManagers.add(bucket.manager);
      flaggedTargets.add(bucket.target);
    }
    const labels = [...new Set(sorted.map((r) => r.findingLabel))];
    const value =
      top.category === "receipt_gap" && top.gapMinutes !== undefined
        ? `Gap ${top.gapMinutes}m`
        : labels.slice(0, 2).join(" · ");
    const details = sorted
      .flatMap((r) => (r.reasons.length ? r.reasons : [r.detail]))
      .slice(0, 3);
    matrixCells.push({
      row: bucket.manager,
      col: bucket.target,
      status: top.status,
      value,
      count: sorted.reduce((s, r) => s + r.eventCount, 0),
      detail: details.join("; "),
      itemId: top.id,
    });
  }

  const matrixRows = [...new Set(matrixCells.map((c) => c.row))].sort(
    (a, b) => {
      const af = flaggedManagers.has(a);
      const bf = flaggedManagers.has(b);
      if (af !== bf) return af ? -1 : 1;
      return a.localeCompare(b);
    },
  );
  const matrixCols = [...new Set(matrixCells.map((c) => c.col))].sort(
    (a, b) => {
      const af = flaggedTargets.has(a);
      const bf = flaggedTargets.has(b);
      if (af !== bf) return af ? -1 : 1;
      return a.localeCompare(b);
    },
  );

  // SwimlaneTimeline
  timelineEntries.sort((a, b) => a.event.timestamp - b.event.timestamp);
  const boundedTimeline = timelineEntries.slice(0, 128);
  const timelineEvents = boundedTimeline.map((e) => e.event);
  const timelineRowByEventId: Record<string, string> = {};
  for (const item of boundedTimeline) {
    timelineRowByEventId[item.event.id] = item.rowId;
  }

  // Plain-language single-sentence verdict above the fold — scoped strictly to covered sources
  let verdict: string;
  let verdictStatus: ProtocolStatus;

  if (flaggedRows.length > 0) {
    const lead = flaggedRows[0];
    verdict = `${flaggedRows.length} of ${rows.length} management ${rows.length === 1 ? "item needs" : "items need"} attention: ${lead.findingLabel} on ${lead.targetDevice}.`;
    verdictStatus = "attention";
  } else if (allNotCovered) {
    verdict = `${rows.length} observed management ${rows.length === 1 ? "item lacks" : "items lack"} SNMP version or syslog peer baseline coverage.`;
    verdictStatus = "not_covered";
  } else if (anyDegraded) {
    verdict = `${rows.length} observed management ${rows.length === 1 ? "item" : "items"} had no flagged findings, but one or more sources were capped or degraded.`;
    verdictStatus = "unknown";
  } else {
    const snmpRows = rows.filter(
      (r) =>
        r.category === "snmp_v3" ||
        r.category === "snmp_v1_v2c" ||
        r.category === "snmp_set" ||
        r.category === "netflow_snmp",
    );
    const hasUnknownRows = rows.some((r) => r.status === "unknown");
    const allSnmpOk =
      snmpRows.length > 0 && snmpRows.every((r) => r.status === "ok");
    const coveredScopeParts: string[] = [];
    if (allSnmpOk) coveredScopeParts.push("SNMPv3 only");
    if (hasCleartextCoverage) coveredScopeParts.push("no cleartext sessions");
    if (hasSyslogBaseline) coveredScopeParts.push("continuous syslog receipt");
    const suffix = coveredScopeParts.length
      ? ` (${coveredScopeParts.join(", ")})`
      : "";
    if (hasUnknownRows) {
      verdict = `${rows.length} observed management ${rows.length === 1 ? "item" : "items"} had no flagged findings, but one or more items had unknown version or status.`;
      verdictStatus = "unknown";
    } else {
      verdict = `${rows.length} of ${rows.length} management ${rows.length === 1 ? "item" : "items"} healthy across covered sources${suffix}.`;
      verdictStatus = "ok";
    }
  }

  const coverageStatus: ProtocolStatus = anyDegraded
    ? "attention"
    : verdictStatus === "not_covered"
      ? "not_covered"
      : "ok";
  const activeCount = outcomes.filter(
    (o) => o.state === "complete" || o.state === "partial",
  ).length;
  const coverageLabel =
    anyEstimate && activeCount === 0
      ? "Estimate mode"
      : `${activeCount} ${activeCount === 1 ? "source" : "sources"}`;

  const blockedDetail = outcomes.find((o) => o.state === "blocked")?.detail;
  const unavailableDetail = outcomes.find(
    (o) => o.state === "unavailable",
  )?.detail;

  let bannerState: MgmtPlaneInvestigationResult["bannerState"];
  let bannerReason: string | undefined;

  if (anyDegraded) {
    bannerState = "partial";
    bannerReason = anyBlocked
      ? `One or more sources denied access (${blockedDetail ?? "access denied"}); results are incomplete.`
      : anyUnavailable
        ? `One or more sources failed (${unavailableDetail ?? "search unavailable"}); results are incomplete.`
        : "Sample capped at 256 rows — narrow the UTC window or filter.";
  } else if (unparsedRowCount > 0) {
    bannerState = "partial";
    bannerReason = `${unparsedRowCount} ${unparsedRowCount === 1 ? "row" : "rows"} returned but could not be normalized.`;
  } else if (anyEstimate) {
    bannerState = "estimate_only";
    bannerReason = estimateEntries[0].detail;
  }

  return {
    verdict,
    verdictStatus,
    coverageStatus,
    coverageLabel,
    hasActiveSnmp,
    hasActiveFtp,
    hasActiveNetflow,
    hasSyslogBaseline,
    kpis,
    distribution,
    rows,
    matrixRows,
    matrixCols,
    matrixCells,
    timelineEvents,
    timelineRowByEventId,
    outcomes,
    capped,
    streamReadiness,
    ...(bannerState ? { bannerState, bannerReason } : {}),
    checkedAt: nowSec,
  };
}

export interface InvestigateMgmtPlaneOptions {
  skipEstimateCheck?: boolean;
  skipConfigRecheck?: boolean;
  profileValidators?: Partial<Record<ProtocolLensId, LensProfileValidator>>;
}

/**
 * Executes the on-demand Management-Plane Hygiene investigation across configured
 * `mgmt_plane` profiles (`stream:snmp`, `stream:ftp`, `stream:netflow`, and syslog),
 * verifying `adm_protocol_profiles` fingerprint before committing results.
 */
export async function investigateMgmtPlane(
  client: SearchClient,
  request: ProtocolRequest,
  configuration: ProtocolConfiguration,
  signal: AbortSignal,
  options: InvestigateMgmtPlaneOptions = {},
): Promise<MgmtPlaneInvestigationResult> {
  const scoped = selectActiveProfiles(
    configuration.profiles,
    "mgmt_plane",
    request.scope,
    request.earliest,
    request.latest,
  );
  if (!scoped.length) {
    return {
      verdict: "No active source profile covers this scope.",
      verdictStatus: "not_covered",
      coverageStatus: "not_covered",
      coverageLabel: "Not covered",
      hasActiveSnmp: false,
      hasActiveFtp: false,
      hasActiveNetflow: false,
      hasSyslogBaseline: false,
      kpis: [],
      distribution: [],
      rows: [],
      matrixRows: [],
      matrixCols: [],
      matrixCells: [],
      timelineEvents: [],
      timelineRowByEventId: {},
      outcomes: [],
      capped: false,
      bannerState: "unavailable",
      bannerReason: `No mgmt_plane profile configured for scope "${request.scope}".`,
      checkedAt: Math.floor(Date.now() / 1000),
    };
  }

  const snmpProfiles = scoped.filter((p) => {
    const sk = resolveMgmtPlaneThresholds(p).sourceKind;
    return sk === "stream_snmp" || sk === "auto";
  });
  const ftpProfiles = scoped.filter((p) => {
    const sk = resolveMgmtPlaneThresholds(p).sourceKind;
    return sk === "stream_ftp" || sk === "auto";
  });
  const netflowProfiles = scoped.filter((p) => {
    const sk = resolveMgmtPlaneThresholds(p).sourceKind;
    return sk === "netflow" || sk === "auto";
  });
  const syslogProfiles = scoped.filter((p) => {
    const sk = resolveMgmtPlaneThresholds(p).sourceKind;
    return sk === "syslog" || sk === "auto";
  });

  const runProfiles = async () => {
    const outcomes: ProtocolSourceOutcome[] = [];
    const snmpOutcomes: ProtocolSourceOutcome[] = [];
    const ftpOutcomes: ProtocolSourceOutcome[] = [];
    const netflowOutcomes: ProtocolSourceOutcome[] = [];
    const syslogOutcomes: ProtocolSourceOutcome[] = [];
    const collected: { event: NormalizedMgmtPlaneEvent; indexName: string }[] =
      [];
    let capped = false;
    let unparsedRowCount = 0;
    const chosenThresholds = resolveMgmtPlaneThresholds(scoped[0]);

    for (const profile of snmpProfiles) {
      signal.throwIfAborted();
      const t = resolveMgmtPlaneThresholds(profile);
      const spl = buildMgmtSnmpSearch({
        index: profile.index,
        filter: request.filter,
        mgmtIps: t.mgmtIps,
        maxRows: MAX_INPUT_ROWS,
      });
      const res = await runBoundedProtocolSearch(client, {
        lens: "mgmt_plane",
        profile,
        spl,
        earliest: request.earliest,
        latest: request.latest,
        signal,
        keySuffix: "snmp",
      });
      outcomes.push(res.outcome);
      snmpOutcomes.push(res.outcome);
      if (res.capped) capped = true;
      for (const row of res.rows) {
        const norm = normalizeMgmtPlaneRow(row, "stream:snmp");
        if (norm) collected.push({ event: norm, indexName: profile.index });
        else unparsedRowCount += 1;
      }
    }

    for (const profile of ftpProfiles) {
      signal.throwIfAborted();
      const t = resolveMgmtPlaneThresholds(profile);
      const spl = buildMgmtFtpSearch({
        index: profile.index,
        filter: request.filter,
        mgmtIps: t.mgmtIps,
        maxRows: MAX_INPUT_ROWS,
      });
      const res = await runBoundedProtocolSearch(client, {
        lens: "mgmt_plane",
        profile,
        spl,
        earliest: request.earliest,
        latest: request.latest,
        signal,
        keySuffix: "ftp",
      });
      outcomes.push(res.outcome);
      ftpOutcomes.push(res.outcome);
      if (res.capped) capped = true;
      for (const row of res.rows) {
        const norm = normalizeMgmtPlaneRow(row, "stream:ftp");
        if (norm) collected.push({ event: norm, indexName: profile.index });
        else unparsedRowCount += 1;
      }
    }

    for (const profile of netflowProfiles) {
      signal.throwIfAborted();
      const t = resolveMgmtPlaneThresholds(profile);
      const spl = buildMgmtNetflowSearch({
        index: profile.index,
        filter: request.filter,
        mgmtIps: t.mgmtIps,
        flagHttpPort80: t.flagHttpPort80,
        maxRows: MAX_INPUT_ROWS,
      });
      const res = await runBoundedProtocolSearch(client, {
        lens: "mgmt_plane",
        profile,
        spl,
        earliest: request.earliest,
        latest: request.latest,
        signal,
        keySuffix: "netflow",
      });
      outcomes.push(res.outcome);
      netflowOutcomes.push(res.outcome);
      if (res.capped) capped = true;
      for (const row of res.rows) {
        const norm = normalizeMgmtPlaneRow(row, "stream:netflow");
        if (norm) collected.push({ event: norm, indexName: profile.index });
        else unparsedRowCount += 1;
      }
    }

    for (const profile of syslogProfiles) {
      signal.throwIfAborted();
      const spl = buildMgmtSyslogSearch({
        index: profile.index,
        filter: request.filter,
        maxRows: MAX_INPUT_ROWS,
      });
      const res = await runBoundedProtocolSearch(client, {
        lens: "mgmt_plane",
        profile,
        spl,
        earliest: request.earliest,
        latest: request.latest,
        signal,
        keySuffix: "syslog",
      });
      outcomes.push(res.outcome);
      syslogOutcomes.push(res.outcome);
      if (res.capped) capped = true;
      for (const row of res.rows) {
        const norm = normalizeMgmtPlaneRow(row, "cisco:ios");
        if (norm) collected.push({ event: norm, indexName: profile.index });
        else unparsedRowCount += 1;
      }
    }

    // Explicit Stream Estimate-mode check ONLY on explicit investigation when
    // stream:snmp or stream:ftp completed with 0 rows.
    const emptyStreamIds: ("snmp" | "ftp")[] = [];
    const snmpCompletedEmpty =
      snmpProfiles.length > 0 &&
      collected.every((c) => c.event.sourceType !== "stream:snmp") &&
      snmpOutcomes.some((o) => o.state === "complete");
    if (snmpCompletedEmpty) emptyStreamIds.push("snmp");

    const ftpCompletedEmpty =
      ftpProfiles.length > 0 &&
      collected.every((c) => c.event.sourceType !== "stream:ftp") &&
      ftpOutcomes.some((o) => o.state === "complete");
    if (ftpCompletedEmpty) emptyStreamIds.push("ftp");

    let streamReadiness: StreamReadinessEntry[] | undefined;
    if (emptyStreamIds.length > 0 && !options.skipEstimateCheck) {
      streamReadiness = await checkStreamEstimateMode(
        client,
        emptyStreamIds,
        signal,
      );
      for (const entry of streamReadiness) {
        if (entry.state === "estimate_only") {
          outcomes.push({
            source: "protocol_stream_readiness",
            state: "estimate_only",
            detail: entry.detail,
          });
        }
      }
    }

    return buildMgmtPlaneAnalysis({
      events: collected,
      thresholds: chosenThresholds,
      earliest: request.earliest,
      latest: request.latest,
      outcomes,
      capped,
      unparsedRowCount,
      snmpConfigured: snmpProfiles.length > 0,
      ftpConfigured: ftpProfiles.length > 0,
      netflowConfigured: netflowProfiles.length > 0,
      syslogConfigured: syslogProfiles.length > 0,
      snmpOutcomes,
      ftpOutcomes,
      netflowOutcomes,
      syslogOutcomes,
      streamReadiness,
    });
  };

  if (options.skipConfigRecheck || !configuration.fingerprint) {
    return runProfiles();
  }

  const validators: Partial<Record<ProtocolLensId, LensProfileValidator>> = {
    ...options.profileValidators,
    mgmt_plane: validateMgmtPlaneExtra,
  };

  try {
    return await withProtocolConfigRecheck(
      configuration.fingerprint,
      validators,
      runProfiles,
      signal,
    );
  } catch (error) {
    if (error instanceof ProtocolConfigurationChangedError) {
      return {
        verdict: error.message,
        verdictStatus: "attention",
        coverageStatus: "unknown",
        coverageLabel: "Stale config",
        hasActiveSnmp: false,
        hasActiveFtp: false,
        hasActiveNetflow: false,
        hasSyslogBaseline: false,
        kpis: [],
        distribution: [],
        rows: [],
        matrixRows: [],
        matrixCols: [],
        matrixCells: [],
        timelineEvents: [],
        timelineRowByEventId: {},
        outcomes: [],
        capped: false,
        bannerState: "stale_config",
        bannerReason: error.message,
        checkedAt: Math.floor(Date.now() / 1000),
      };
    }
    throw error;
  }
}

/**
 * Hub "Check all" summary runner for `mgmt_plane`.
 */
export async function summarizeMgmtPlane(
  client: SearchClient,
  request: ProtocolRequest,
  configuration: ProtocolConfiguration,
  signal: AbortSignal,
  options?: InvestigateMgmtPlaneOptions,
): Promise<ProtocolLensSummary> {
  const result = await investigateMgmtPlane(
    client,
    request,
    configuration,
    signal,
    options,
  );
  const degraded =
    result.capped ||
    result.outcomes.some(
      (o) =>
        o.state === "blocked" ||
        o.state === "unavailable" ||
        o.state === "partial",
    );
  const status: ProtocolStatus =
    degraded && result.verdictStatus === "ok"
      ? "attention"
      : degraded && result.verdictStatus === "none_observed"
        ? "unknown"
        : result.verdictStatus;
  return {
    lens: "mgmt_plane",
    status,
    verdict: result.verdict,
    checkedAt: result.checkedAt,
    capped: result.capped,
    outcomes: result.outcomes,
  };
}
