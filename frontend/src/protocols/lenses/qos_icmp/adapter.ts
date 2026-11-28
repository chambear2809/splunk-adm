import { literal } from "../../../data/evidence";
import type { SearchClient } from "../../../data/searchClient";
import type {
  BaseProtocolProfile,
  LensProfileValidator,
  ProtocolConfiguration,
  ProtocolFilter,
  ProtocolKpi,
  ProtocolLensId,
  ProtocolLensSummary,
  ProtocolMatrixCell,
  ProtocolRequest,
  ProtocolSourceOutcome,
  ProtocolStatus,
  ProtocolTimelineEvent,
} from "../../shared/contract";
import { buildAllowedFieldsClause } from "../../shared/fields";
import { buildFlowEndpointPredicates } from "../../shared/filterSpl";
import { formatCount } from "../../shared/format";
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
  DEFAULT_QOS_ICMP_THRESHOLDS,
  validateQosIcmpExtra,
  type QosIcmpExtraConfig,
  type QosIcmpSourceKind,
  type ResolvedQosIcmpThresholds,
} from "./validate";

export {
  DEFAULT_QOS_ICMP_THRESHOLDS,
  validateQosIcmpExtra,
  type QosIcmpExtraConfig,
  type QosIcmpSourceKind,
  type ResolvedQosIcmpThresholds,
};

export type QosIcmpSourcetype =
  "stream:netflow" | "stream:icmp" | "cisco:dc:nd:flows";

export function resolveQosIcmpThresholds(
  profile?: BaseProtocolProfile,
): ResolvedQosIcmpThresholds {
  const extra = profile?.extra as QosIcmpExtraConfig | undefined;
  return {
    sourceKind:
      extra?.sourceKind === "stream_netflow" ||
      extra?.sourceKind === "stream_icmp" ||
      extra?.sourceKind === "nd_flows" ||
      extra?.sourceKind === "auto"
        ? extra.sourceKind
        : DEFAULT_QOS_ICMP_THRESHOLDS.sourceKind,
    icmpUnreachableWarnCount:
      typeof extra?.icmpUnreachableWarnCount === "number"
        ? extra.icmpUnreachableWarnCount
        : DEFAULT_QOS_ICMP_THRESHOLDS.icmpUnreachableWarnCount,
    icmpTtlExceededWarnCount:
      typeof extra?.icmpTtlExceededWarnCount === "number"
        ? extra.icmpTtlExceededWarnCount
        : DEFAULT_QOS_ICMP_THRESHOLDS.icmpTtlExceededWarnCount,
    dropPktWarnCount:
      typeof extra?.dropPktWarnCount === "number"
        ? extra.dropPktWarnCount
        : DEFAULT_QOS_ICMP_THRESHOLDS.dropPktWarnCount,
    unexpectedDscpValues: Array.isArray(extra?.unexpectedDscpValues)
      ? [...extra.unexpectedDscpValues]
      : DEFAULT_QOS_ICMP_THRESHOLDS.unexpectedDscpValues,
  };
}

export const NETFLOW_QOS_PROJECTED_FIELDS = [
  "_time",
  "host",
  "sourcetype",
  "exporter_ip",
  "src_ip",
  "dest_ip",
  "src_port",
  "dest_port",
  "protoid",
  "transport",
  "tos",
  "dscp",
  "ip_dscp",
  "ecn",
  "min_ttl",
  "bytes",
  "packets",
] as const;

export const ICMP_STREAM_PROJECTED_FIELDS = [
  "_time",
  "host",
  "sourcetype",
  "src_ip",
  "dest_ip",
  "icmp_type",
  "icmp_code",
  "type",
  "code",
  "bytes",
  "bytes_in",
  "bytes_out",
  "packets",
  "packets_in",
  "packets_out",
  "time_taken",
] as const;

export const ND_FLOWS_PROJECTED_FIELDS = [
  "_time",
  "host",
  "sourcetype",
  "srcIp",
  "dstIp",
  "srcPort",
  "dstPort",
  "protocolName",
  "dropPktCount",
  "dropReasons",
  "fabricName",
  "nd_host",
  "nodeName",
] as const;

/**
 * Builds a bounded, allowlisted SPL query for `stream:netflow`, `stream:icmp`,
 * or `cisco:dc:nd:flows`.
 * Always emits `| head <maxRows + 1>` BEFORE `buildAllowedFieldsClause` (`| table ...`)
 * so indexers cap rows and drop `_raw` server-side. Nested JSON fields in
 * `cisco:dc:nd:flows` (`stats[].dropPktCount`, `stats[].dropReasons`,
 * `stats[].nodeNames`) are projected via `| spath` after `| head` and never
 * queried with dotted field paths inside quotes in base `search`.
 */
export function buildQosIcmpSearch(options: {
  index: string;
  sourcetype: QosIcmpSourcetype;
  filter?: ProtocolFilter;
  maxRows: number;
}): string {
  const index = literal(options.index, 80);
  const headLimit = Math.max(1, Math.trunc(options.maxRows)) + 1;

  if (options.sourcetype === "cisco:dc:nd:flows") {
    const predicates: string[] = [
      `index=${index}`,
      `sourcetype="cisco:dc:nd:flows"`,
    ];
    predicates.push(
      ...buildFlowEndpointPredicates({
        filter: options.filter,
        srcFields: ["srcIp", "src_ip"],
        dstFields: ["dstIp", "dest_ip"],
        portFields: ["dstPort", "srcPort", "dest_port", "src_port"],
      }),
    );
    if (options.filter?.device) {
      const dev = literal(options.filter.device, 128);
      predicates.push(
        `(host="${dev}" OR nd_host="${dev}" OR nodeName="${dev}")`,
      );
    }
    const tableClause = buildAllowedFieldsClause(
      "qos_icmp",
      ND_FLOWS_PROJECTED_FIELDS,
    );
    return (
      `search ${predicates.join(" ")} ` +
      `| head ${headLimit} ` +
      `| spath path=stats{}.dropPktCount output=_nd_drop_pkts ` +
      `| spath path=stats{}.dropReasons{} output=_nd_drop_reasons ` +
      `| spath path=stats{}.nodeNames{} output=_nd_node_names ` +
      `| eval dropPktCount=coalesce(dropPktCount, _nd_drop_pkts), ` +
      `dropReasons=coalesce(dropReasons, _nd_drop_reasons), ` +
      `nodeName=coalesce(nodeName, _nd_node_names) ` +
      tableClause
    );
  }

  if (options.sourcetype === "stream:icmp") {
    const predicates: string[] = [`index=${index}`, `sourcetype="stream:icmp"`];
    predicates.push(
      ...buildFlowEndpointPredicates({
        filter: options.filter,
        srcFields: ["src_ip"],
        dstFields: ["dest_ip"],
      }),
    );
    if (options.filter?.device) {
      predicates.push(`host="${literal(options.filter.device, 128)}"`);
    }
    const tableClause = buildAllowedFieldsClause(
      "qos_icmp",
      ICMP_STREAM_PROJECTED_FIELDS,
    );
    return `search ${predicates.join(" ")} | head ${headLimit} ${tableClause}`;
  }

  const predicates: string[] = [
    `index=${index}`,
    `sourcetype="stream:netflow"`,
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
    predicates.push(`(host="${dev}" OR exporter_ip="${dev}")`);
  }
  const tableClause = buildAllowedFieldsClause(
    "qos_icmp",
    NETFLOW_QOS_PROJECTED_FIELDS,
  );
  return `search ${predicates.join(" ")} | head ${headLimit} ${tableClause}`;
}

/**
 * Builds a `literal()`-quoted Splunk Search URL for raw events of a selected flow.
 */
export function buildQosIcmpRawEventsUrl(options: {
  index: string;
  srcIp: string;
  dstIp: string;
  sourcetypes: readonly QosIcmpSourcetype[];
  earliest: number;
  latest: number;
}): string {
  const index = literal(options.index, 80);
  const src = literal(options.srcIp, 128);
  const dst = literal(options.dstIp, 128);
  const sts = options.sourcetypes.length
    ? options.sourcetypes
    : (["stream:netflow", "stream:icmp", "cisco:dc:nd:flows"] as const);
  const stClause =
    sts.length === 1
      ? `sourcetype="${sts[0]}"`
      : `(${sts.map((s) => `sourcetype="${s}"`).join(" OR ")})`;
  const q = `search index=${index} ${stClause} ((src_ip="${src}" dest_ip="${dst}") OR (srcIp="${src}" dstIp="${dst}"))`;
  const params = new URLSearchParams({
    q,
    earliest: String(Math.trunc(options.earliest)),
    latest: String(Math.trunc(options.latest)),
  });
  return `/app/splunk_adm/search?${params.toString()}`;
}

const DSCP_NAMES: Record<number, string> = {
  0: "DF",
  8: "CS1",
  10: "AF11",
  12: "AF12",
  14: "AF13",
  16: "CS2",
  18: "AF21",
  20: "AF22",
  22: "AF23",
  24: "CS3",
  26: "AF31",
  28: "AF32",
  30: "AF33",
  32: "CS4",
  34: "AF41",
  36: "AF42",
  38: "AF43",
  40: "CS5",
  46: "EF",
  48: "CS6",
  56: "CS7",
};

const ECN_LABELS: Record<number, string> = {
  0: "Not-ECT",
  1: "ECT(1)",
  2: "ECT(0)",
  3: "CE",
};

export function isStandardDscp(dscp: number): boolean {
  return Object.prototype.hasOwnProperty.call(DSCP_NAMES, dscp);
}

export function isUnexpectedDscp(
  dscp: number,
  configuredUnexpected: readonly number[] = [],
): boolean {
  return !isStandardDscp(dscp) || configuredUnexpected.includes(dscp);
}

export function formatDscpLabel(dscp: number): string {
  const name = DSCP_NAMES[dscp];
  return name ? `${name} (${dscp})` : `DSCP ${dscp}`;
}

export function formatEcnLabel(ecn: number): string {
  return ECN_LABELS[ecn] ?? `ECN ${ecn}`;
}

/**
 * Extracts DSCP (upper 6 bits) and ECN (lower 2 bits) from an IP ToS byte (`0..255`).
 */
export function extractDscpAndEcnFromTos(rawTos: unknown): {
  dscp?: number;
  ecn?: number;
} {
  const tosNum = asFiniteNumber(rawTos);
  if (tosNum === undefined) return {};
  const intTos = Math.trunc(tosNum);
  if (intTos < 0 || intTos > 255 || intTos !== tosNum) return {};
  return {
    dscp: (intTos >> 2) & 0x3f,
    ecn: intTos & 3,
  };
}

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

export function normalizeProtocolName(
  rawProto: unknown,
  rawTransport?: unknown,
): string {
  const transport = asString(rawTransport).toUpperCase();
  const proto = asString(rawProto).toUpperCase();
  const val = transport || proto;
  if (!val) return "IP";
  if (val === "6" || val === "TCP") return "TCP";
  if (val === "17" || val === "UDP") return "UDP";
  if (val === "1" || val === "ICMP") return "ICMP";
  if (val === "58" || val === "ICMPV6" || val === "IPV6-ICMP") return "ICMPv6";
  if (val === "47" || val === "GRE") return "GRE";
  if (val === "50" || val === "ESP") return "ESP";
  return val;
}

function isPureIpv6Address(ip: string): boolean {
  return ip.includes(":") && !/^(?:0+:){5}ffff:/i.test(ip);
}

/**
 * Converts RFC 4291 IPv4-mapped IPv6 literals (`0:0:0:0:0:FFFF:0A2A:0014`) to
 * dotted IPv4 so Nexus Dashboard flows correlate with NetFlow and ICMP.
 */
export function normalizeIpLiteral(raw: string): string {
  const trimmed = raw.trim();
  const match = /^(?:0{1,4}:){5}ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i.exec(
    trimmed,
  );
  if (!match) return trimmed;
  const hi = parseInt(match[1], 16);
  const lo = parseInt(match[2], 16);
  return `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
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
export function makeQosFlowRowId(
  srcIp: string,
  dstIp: string,
  proto: string,
  srcPort?: number,
  dstPort?: number,
): string {
  const portPart =
    srcPort !== undefined || dstPort !== undefined
      ? `__${srcPort ?? 0}_${dstPort ?? 0}`
      : "";
  const full = `${sanitizeIdPart(srcIp)}__${sanitizeIdPart(dstIp)}__${sanitizeIdPart(proto)}${portPart}`;
  if (full.length <= 128) return full;
  const suffix = `__${shortFnvHash(full)}`;
  const budget = 128 - suffix.length;
  return `${full.slice(0, budget)}${suffix}`;
}

export type IcmpEventCategory =
  "pmtud_candidate" | "unreachable" | "ttl_exceeded" | "echo" | "other";

export interface NormalizedNetflowQosEvent {
  sourceType: "stream:netflow";
  timestamp: number | undefined;
  host: string;
  exporterIp: string;
  srcIp: string;
  dstIp: string;
  srcPort?: number;
  dstPort?: number;
  proto: string;
  dscp?: number;
  ecn?: number;
  minTtl?: number;
  bytes: number;
  packets: number;
}

export interface NormalizedIcmpEvent {
  sourceType: "stream:icmp";
  timestamp: number | undefined;
  host: string;
  srcIp: string;
  dstIp: string;
  proto: "ICMP" | "ICMPv6";
  isIpv6: boolean;
  icmpType: number;
  icmpCode: number;
  category: IcmpEventCategory;
  bytes: number;
  packets: number;
  latencyMs?: number;
}

export interface NormalizedNdDropEvent {
  sourceType: "cisco:dc:nd:flows";
  timestamp: number | undefined;
  host: string;
  ndHost?: string;
  fabricName?: string;
  nodeNames: string[];
  srcIp: string;
  dstIp: string;
  srcPort?: number;
  dstPort?: number;
  proto: string;
  dropPktCount: number;
  dropReasons: string[];
  hasDrop: boolean;
}

export type NormalizedQosIcmpEvent =
  NormalizedNetflowQosEvent | NormalizedIcmpEvent | NormalizedNdDropEvent;

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

function asStringList(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value.flatMap((v) => asStringList(v));
  }
  const s = asString(value);
  if (!s) return [];
  return s
    .split(/[\n,|]+/)
    .map((part) => part.trim())
    .filter(Boolean);
}

function asNumberSum(value: unknown): number | undefined {
  if (Array.isArray(value)) {
    let total = 0;
    let found = false;
    for (const item of value) {
      const n = asFiniteNumber(item);
      if (n !== undefined) {
        total += Math.max(0, n);
        found = true;
      }
    }
    return found ? total : undefined;
  }
  const n = asFiniteNumber(value);
  return n !== undefined ? Math.max(0, n) : undefined;
}

export function classifyIcmpEvent(
  icmpType: number,
  icmpCode: number,
  isIpv6: boolean,
): IcmpEventCategory {
  if (isIpv6) {
    if (icmpType === 2) return "pmtud_candidate";
    if (icmpType === 1) return "unreachable";
    if (icmpType === 3) return "ttl_exceeded";
    if (icmpType === 128 || icmpType === 129) return "echo";
    return "other";
  }
  if (icmpType === 3 && icmpCode === 4) return "pmtud_candidate";
  if (icmpType === 3) return "unreachable";
  if (icmpType === 11) return "ttl_exceeded";
  if (icmpType === 8 || icmpType === 0) return "echo";
  return "other";
}

/**
 * Normalizes a single allowlist-projected `stream:netflow`, `stream:icmp`, or
 * `cisco:dc:nd:flows` row.
 */
export function normalizeQosIcmpRow(
  row: ProtocolRow,
  defaultSourcetype: QosIcmpSourcetype,
): NormalizedQosIcmpEvent | undefined {
  const stRaw = asString(row.sourcetype).toLowerCase();
  const sourceType: QosIcmpSourcetype =
    stRaw === "stream:icmp"
      ? "stream:icmp"
      : stRaw === "cisco:dc:nd:flows"
        ? "cisco:dc:nd:flows"
        : stRaw === "stream:netflow"
          ? "stream:netflow"
          : defaultSourcetype;

  const timestamp = asEpochSeconds(row._time);
  const host = asString(row.host) || "unknown";

  if (sourceType === "cisco:dc:nd:flows") {
    const rawSrc = asString(row.srcIp ?? row.src_ip);
    const rawDst = asString(row.dstIp ?? row.dest_ip);
    if (!rawSrc || !rawDst) return undefined;
    const srcIp = normalizeIpLiteral(rawSrc);
    const dstIp = normalizeIpLiteral(rawDst);
    const srcPortNum = asFiniteNumber(row.srcPort ?? row.src_port);
    const dstPortNum = asFiniteNumber(row.dstPort ?? row.dest_port);
    const srcPort =
      srcPortNum !== undefined && srcPortNum >= 0
        ? Math.trunc(srcPortNum)
        : undefined;
    const dstPort =
      dstPortNum !== undefined && dstPortNum >= 0
        ? Math.trunc(dstPortNum)
        : undefined;
    const proto = normalizeProtocolName(row.protocolName ?? row.transport);

    const dropPktCount =
      asNumberSum(row.dropPktCount) ?? asNumberSum(row.drop_packets) ?? 0;
    const dropReasons = asStringList(row.dropReasons ?? row.drop_reason).filter(
      (r) => !/^(?:0|none|null|n\/a|-)$/i.test(r),
    );
    const nodeNames = [
      ...new Set(
        asStringList(row.nodeName).filter(
          (n) => !/^(?:none|null|n\/a|-)$/i.test(n),
        ),
      ),
    ];
    const ndHost = asString(row.nd_host) || undefined;
    const fabricName = asString(row.fabricName) || undefined;
    const hasDrop = dropPktCount > 0 || dropReasons.length > 0;

    return {
      sourceType: "cisco:dc:nd:flows",
      timestamp,
      host,
      ...(ndHost ? { ndHost } : {}),
      ...(fabricName ? { fabricName } : {}),
      nodeNames,
      srcIp,
      dstIp,
      ...(srcPort !== undefined ? { srcPort } : {}),
      ...(dstPort !== undefined ? { dstPort } : {}),
      proto,
      dropPktCount,
      dropReasons,
      hasDrop,
    };
  }

  if (sourceType === "stream:icmp") {
    const rawSrc = asString(row.src_ip);
    const rawDst = asString(row.dest_ip);
    if (!rawSrc || !rawDst) return undefined;
    const srcIp = normalizeIpLiteral(rawSrc);
    const dstIp = normalizeIpLiteral(rawDst);

    const rawType = asFiniteNumber(row.icmp_type ?? row.type);
    if (rawType === undefined) return undefined;
    const icmpType = Math.trunc(rawType);
    const rawCode = asFiniteNumber(row.icmp_code ?? row.code);
    const icmpCode = rawCode !== undefined ? Math.trunc(rawCode) : 0;

    const isIpv6 = isPureIpv6Address(srcIp) || isPureIpv6Address(dstIp);
    const category = classifyIcmpEvent(icmpType, icmpCode, isIpv6);

    const bytes =
      asFiniteNumber(row.bytes) ??
      (asFiniteNumber(row.bytes_in) ?? 0) +
        (asFiniteNumber(row.bytes_out) ?? 0);
    const packets =
      asFiniteNumber(row.packets) ??
      (asFiniteNumber(row.packets_in) ?? 0) +
        (asFiniteNumber(row.packets_out) ?? 0);
    const rawTimeTaken = asFiniteNumber(row.time_taken);
    const latencyMs =
      rawTimeTaken !== undefined && rawTimeTaken >= 0
        ? rawTimeTaken / 1000
        : undefined;

    return {
      sourceType: "stream:icmp",
      timestamp,
      host,
      srcIp,
      dstIp,
      proto: isIpv6 ? "ICMPv6" : "ICMP",
      isIpv6,
      icmpType,
      icmpCode,
      category,
      bytes: Math.max(0, bytes),
      packets: Math.max(0, packets),
      ...(latencyMs !== undefined ? { latencyMs } : {}),
    };
  }

  const rawSrc = asString(row.src_ip);
  const rawDst = asString(row.dest_ip);
  if (!rawSrc || !rawDst) return undefined;
  const srcIp = normalizeIpLiteral(rawSrc);
  const dstIp = normalizeIpLiteral(rawDst);

  const exporterIp = asString(row.exporter_ip) || host;
  const srcPortNum = asFiniteNumber(row.src_port);
  const dstPortNum = asFiniteNumber(row.dest_port);
  const srcPort =
    srcPortNum !== undefined && srcPortNum >= 0
      ? Math.trunc(srcPortNum)
      : undefined;
  const dstPort =
    dstPortNum !== undefined && dstPortNum >= 0
      ? Math.trunc(dstPortNum)
      : undefined;
  const proto = normalizeProtocolName(row.protoid, row.transport);

  const fromTos = extractDscpAndEcnFromTos(row.tos);
  const explicitDscpNum = asFiniteNumber(row.dscp ?? row.ip_dscp);
  const explicitDscp =
    explicitDscpNum !== undefined &&
    Number.isInteger(explicitDscpNum) &&
    explicitDscpNum >= 0 &&
    explicitDscpNum <= 63
      ? explicitDscpNum
      : undefined;
  const explicitEcnNum = asFiniteNumber(row.ecn);
  const explicitEcn =
    explicitEcnNum !== undefined &&
    Number.isInteger(explicitEcnNum) &&
    explicitEcnNum >= 0 &&
    explicitEcnNum <= 3
      ? explicitEcnNum
      : undefined;

  const dscp = fromTos.dscp ?? explicitDscp;
  const ecn = fromTos.ecn ?? explicitEcn;

  const rawMinTtl = asFiniteNumber(row.min_ttl);
  const minTtl =
    rawMinTtl !== undefined && rawMinTtl >= 0 && rawMinTtl <= 255
      ? Math.trunc(rawMinTtl)
      : undefined;

  const bytes = Math.max(0, asFiniteNumber(row.bytes) ?? 0);
  const packets = Math.max(0, asFiniteNumber(row.packets) ?? 0);

  return {
    sourceType: "stream:netflow",
    timestamp,
    host,
    exporterIp,
    srcIp,
    dstIp,
    ...(srcPort !== undefined ? { srcPort } : {}),
    ...(dstPort !== undefined ? { dstPort } : {}),
    proto,
    ...(dscp !== undefined ? { dscp } : {}),
    ...(ecn !== undefined ? { ecn } : {}),
    ...(minTtl !== undefined ? { minTtl } : {}),
    bytes,
    packets,
  };
}

export interface ExporterDscpObservation {
  exporterIp: string;
  dscps: number[];
  ecns: number[];
  minTtl?: number;
  flowCount: number;
  firstSeen?: number;
  lastSeen?: number;
}

export interface QosIcmpFlowRow {
  /** URL-safe ID matching `^[A-Za-z0-9._:/-]{1,128}$` using `__`. */
  id: string;
  attention: boolean;
  srcIp: string;
  dstIp: string;
  srcPort?: number;
  dstPort?: number;
  proto: string;
  flowLabel: string;
  hasNetflowData: boolean;
  hasIcmpData: boolean;
  hasNdData: boolean;
  dscpValues: number[];
  ecnValues: number[];
  dscpSummary: string;
  dscpRemarked: boolean;
  remarkingDiff?: string;
  unexpectedDscp: boolean;
  minTtl?: number;
  exporterObservations: ExporterDscpObservation[];
  pmtudCount: number;
  ttlExceededCount: number;
  unreachableCount: number;
  echoCount: number;
  icmpSummary: string;
  pmtudExplanation?: string;
  dropPktCount: number;
  dropReasons: string[];
  ndNodes: string[];
  fabricName?: string;
  ndHost?: string;
  totalBytes: number;
  totalPackets: number;
  status: ProtocolStatus;
  reasons: string[];
  findings: string[];
  indexName: string;
  sourcetypes: QosIcmpSourcetype[];
  firstSeen?: number;
  lastSeen?: number;
}

export interface QosIcmpInvestigationResult {
  verdict: string;
  verdictStatus: ProtocolStatus;
  coverageStatus: ProtocolStatus;
  coverageLabel: string;
  hasActiveNetflow: boolean;
  netflowDegraded: boolean;
  netflowDegradedReason?: string;
  hasActiveIcmp: boolean;
  hasActiveNd: boolean;
  kpis: ProtocolKpi[];
  rows: QosIcmpFlowRow[];
  matrixRows: string[];
  matrixCols: string[];
  matrixCells: ProtocolMatrixCell[];
  timelineEvents: ProtocolTimelineEvent[];
  timelineRowByEventId: Record<string, string>;
  outcomes: ProtocolSourceOutcome[];
  capped: boolean;
  sourceMode: "mixed" | "netflow_only" | "icmp_only" | "nd_only" | "none";
  streamReadiness?: StreamReadinessEntry;
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

/**
 * Pure aggregation of normalized `stream:netflow`, `stream:icmp`, and
 * `cisco:dc:nd:flows` events into Overview rows, KPI tiles, Exporter × DSCP
 * `HeatMatrix`, `SwimlaneTimeline`, and a single-sentence verdict.
 */
export function buildQosIcmpAnalysis(options: {
  events: readonly { event: NormalizedQosIcmpEvent; indexName: string }[];
  thresholds: ResolvedQosIcmpThresholds;
  earliest: number;
  latest: number;
  outcomes: ProtocolSourceOutcome[];
  netflowOutcomes?: readonly ProtocolSourceOutcome[];
  capped: boolean;
  netflowConfigured?: boolean;
  icmpConfigured?: boolean;
  ndConfigured?: boolean;
  streamReadiness?: StreamReadinessEntry;
}): QosIcmpInvestigationResult {
  const {
    events,
    thresholds,
    earliest,
    latest,
    outcomes,
    netflowOutcomes,
    capped,
    netflowConfigured = false,
    icmpConfigured = false,
    ndConfigured = false,
    streamReadiness,
  } = options;
  const nowSec = Math.floor(Date.now() / 1000);

  const anyBlocked = outcomes.some((o) => o.state === "blocked");
  const anyUnavailable = outcomes.some((o) => o.state === "unavailable");
  const anyDegraded = anyBlocked || anyUnavailable;
  const anyPartial =
    outcomes.some((o) => o.state === "partial") || capped || anyDegraded;

  const netflowEvents = events.filter(
    (e): e is { event: NormalizedNetflowQosEvent; indexName: string } =>
      e.event.sourceType === "stream:netflow",
  );
  const icmpEvents = events.filter(
    (e): e is { event: NormalizedIcmpEvent; indexName: string } =>
      e.event.sourceType === "stream:icmp",
  );
  const ndEvents = events.filter(
    (e): e is { event: NormalizedNdDropEvent; indexName: string } =>
      e.event.sourceType === "cisco:dc:nd:flows",
  );

  const relevantNetflowOutcomes =
    netflowOutcomes !== undefined
      ? netflowOutcomes
      : netflowConfigured || netflowEvents.length > 0
        ? outcomes
        : [];
  const netflowCapped =
    relevantNetflowOutcomes.some((o) => o.capped || o.state === "partial") ||
    (netflowOutcomes === undefined &&
      (netflowConfigured || netflowEvents.length > 0) &&
      capped);
  const netflowBlocked = relevantNetflowOutcomes.some(
    (o) => o.state === "blocked",
  );
  const netflowUnavailable = relevantNetflowOutcomes.some(
    (o) => o.state === "unavailable",
  );
  const netflowDegraded = netflowCapped || netflowBlocked || netflowUnavailable;
  const netflowDegradedReason = netflowCapped
    ? "NetFlow sample capped"
    : netflowBlocked
      ? "NetFlow source blocked"
      : netflowUnavailable
        ? "NetFlow source unavailable"
        : undefined;

  const hasActiveNetflow =
    netflowEvents.length > 0 ||
    (netflowConfigured &&
      !netflowDegraded &&
      relevantNetflowOutcomes.length > 0 &&
      relevantNetflowOutcomes.every(
        (o) => o.state === "complete" && !o.capped,
      ));
  const hasActiveIcmp =
    icmpEvents.length > 0 ||
    (icmpConfigured && streamReadiness?.state === "enabled");
  const hasActiveNd =
    ndEvents.length > 0 ||
    (ndConfigured &&
      !anyDegraded &&
      outcomes.some((o) => o.state === "complete"));

  if (!events.length) {
    if (
      streamReadiness?.state === "estimate_only" &&
      !netflowEvents.length &&
      !ndEvents.length
    ) {
      return {
        verdict:
          "Stream icmp is in Estimate mode (statsOnly=true); no ICMP event rows are indexed.",
        verdictStatus: "unknown",
        coverageStatus: "unknown",
        coverageLabel: "Estimate mode",
        hasActiveNetflow,
        netflowDegraded,
        ...(netflowDegradedReason ? { netflowDegradedReason } : {}),
        hasActiveIcmp: false,
        hasActiveNd,
        kpis: [],
        rows: [],
        matrixRows: [],
        matrixCols: [],
        matrixCells: [],
        timelineEvents: [],
        timelineRowByEventId: {},
        outcomes,
        capped,
        sourceMode: "none",
        streamReadiness,
        bannerState: "estimate_only",
        bannerReason: streamReadiness.detail,
        checkedAt: nowSec,
      };
    }
    if (anyBlocked) {
      return {
        verdict: "Source evidence could not be read for this role.",
        verdictStatus: "unknown",
        coverageStatus: "unknown",
        coverageLabel: "Blocked",
        hasActiveNetflow,
        netflowDegraded,
        ...(netflowDegradedReason ? { netflowDegradedReason } : {}),
        hasActiveIcmp,
        hasActiveNd,
        kpis: [],
        rows: [],
        matrixRows: [],
        matrixCols: [],
        matrixCells: [],
        timelineEvents: [],
        timelineRowByEventId: {},
        outcomes,
        capped,
        sourceMode: "none",
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
        hasActiveNetflow,
        netflowDegraded,
        ...(netflowDegradedReason ? { netflowDegradedReason } : {}),
        hasActiveIcmp,
        hasActiveNd,
        kpis: [],
        rows: [],
        matrixRows: [],
        matrixCols: [],
        matrixCells: [],
        timelineEvents: [],
        timelineRowByEventId: {},
        outcomes,
        capped,
        sourceMode: "none",
        streamReadiness,
        bannerState: "unavailable",
        bannerReason:
          outcomes.find((o) => o.state === "unavailable")?.detail ??
          "Configured source failed to complete.",
        checkedAt: nowSec,
      };
    }
    if (anyPartial) {
      return {
        verdict:
          "Search hit row cap before matching QoS or ICMP events were found — narrow the UTC window or filter.",
        verdictStatus: "unknown",
        coverageStatus: "unknown",
        coverageLabel: "Capped",
        hasActiveNetflow,
        netflowDegraded,
        ...(netflowDegradedReason ? { netflowDegradedReason } : {}),
        hasActiveIcmp,
        hasActiveNd,
        kpis: [],
        rows: [],
        matrixRows: [],
        matrixCols: [],
        matrixCells: [],
        timelineEvents: [],
        timelineRowByEventId: {},
        outcomes,
        capped,
        sourceMode: "none",
        streamReadiness,
        bannerState: "partial",
        bannerReason:
          "Search hit row cap before matching QoS or ICMP events were found — narrow the UTC window or filter.",
        checkedAt: nowSec,
      };
    }
    return {
      verdict:
        "No matching QoS, ICMP, or fabric drop events observed in this UTC window.",
      verdictStatus: "none_observed",
      coverageStatus: "none_observed",
      coverageLabel: "None observed",
      hasActiveNetflow,
      netflowDegraded,
      ...(netflowDegradedReason ? { netflowDegradedReason } : {}),
      hasActiveIcmp,
      hasActiveNd,
      kpis: [],
      rows: [],
      matrixRows: [],
      matrixCols: [],
      matrixCells: [],
      timelineEvents: [],
      timelineRowByEventId: {},
      outcomes,
      capped,
      sourceMode: "none",
      streamReadiness,
      bannerState: "empty",
      bannerReason:
        streamReadiness?.state === "enabled"
          ? "Stream icmp is Enabled (statsOnly=false), but no matching QoS or ICMP events were observed in this UTC window."
          : "No matching events in this UTC window.",
      checkedAt: nowSec,
    };
  }

  interface FlowGroup {
    id: string;
    srcIp: string;
    dstIp: string;
    srcPort?: number;
    dstPort?: number;
    proto: string;
    netflow: NormalizedNetflowQosEvent[];
    icmp: NormalizedIcmpEvent[];
    nd: NormalizedNdDropEvent[];
    indexName: string;
  }

  const groups = new Map<string, FlowGroup>();

  const getOrCreateGroup = (
    srcIp: string,
    dstIp: string,
    proto: string,
    srcPort: number | undefined,
    dstPort: number | undefined,
    indexName: string,
  ): FlowGroup => {
    const key = `${srcIp}\0${dstIp}\0${proto}\0${srcPort ?? ""}\0${dstPort ?? ""}`;
    const existing = groups.get(key);
    if (existing) return existing;
    const group: FlowGroup = {
      id: makeQosFlowRowId(srcIp, dstIp, proto, srcPort, dstPort),
      srcIp,
      dstIp,
      ...(srcPort !== undefined ? { srcPort } : {}),
      ...(dstPort !== undefined ? { dstPort } : {}),
      proto,
      netflow: [],
      icmp: [],
      nd: [],
      indexName,
    };
    groups.set(key, group);
    return group;
  };

  for (const entry of netflowEvents) {
    const g = getOrCreateGroup(
      entry.event.srcIp,
      entry.event.dstIp,
      entry.event.proto,
      entry.event.srcPort,
      entry.event.dstPort,
      entry.indexName,
    );
    g.netflow.push(entry.event);
    g.indexName = entry.indexName;
  }

  for (const entry of icmpEvents) {
    const g = getOrCreateGroup(
      entry.event.srcIp,
      entry.event.dstIp,
      entry.event.proto,
      undefined,
      undefined,
      entry.indexName,
    );
    g.icmp.push(entry.event);
    if (!g.netflow.length) g.indexName = entry.indexName;
  }

  for (const entry of ndEvents) {
    const g = getOrCreateGroup(
      entry.event.srcIp,
      entry.event.dstIp,
      entry.event.proto,
      entry.event.srcPort,
      entry.event.dstPort,
      entry.indexName,
    );
    g.nd.push(entry.event);
    if (!g.netflow.length && !g.icmp.length) g.indexName = entry.indexName;
  }

  const activeSources = [
    netflowEvents.length > 0 ? "netflow" : null,
    icmpEvents.length > 0 ? "icmp" : null,
    ndEvents.length > 0 ? "nd" : null,
  ].filter(Boolean);
  const sourceMode: QosIcmpInvestigationResult["sourceMode"] =
    activeSources.length > 1
      ? "mixed"
      : activeSources[0] === "netflow"
        ? "netflow_only"
        : activeSources[0] === "icmp"
          ? "icmp_only"
          : activeSources[0] === "nd"
            ? "nd_only"
            : "none";

  const rows: QosIcmpFlowRow[] = [];

  for (const group of groups.values()) {
    const hasNetflowData = group.netflow.length > 0;
    const hasIcmpData = group.icmp.length > 0;
    const hasNdData = group.nd.length > 0;

    // Exporter DSCP aggregation
    const exporterMap = new Map<
      string,
      {
        dscps: Set<number>;
        ecns: Set<number>;
        minTtl?: number;
        flowCount: number;
        firstSeen?: number;
        lastSeen?: number;
      }
    >();
    const allDscps = new Set<number>();
    const allEcns = new Set<number>();
    let overallMinTtl: number | undefined;

    for (const ev of group.netflow) {
      const exp = exporterMap.get(ev.exporterIp) ?? {
        dscps: new Set<number>(),
        ecns: new Set<number>(),
        flowCount: 0,
      };
      exp.flowCount += 1;
      if (ev.dscp !== undefined) {
        exp.dscps.add(ev.dscp);
        allDscps.add(ev.dscp);
      }
      if (ev.ecn !== undefined) {
        exp.ecns.add(ev.ecn);
        allEcns.add(ev.ecn);
      }
      if (ev.minTtl !== undefined) {
        exp.minTtl =
          exp.minTtl === undefined
            ? ev.minTtl
            : Math.min(exp.minTtl, ev.minTtl);
        overallMinTtl =
          overallMinTtl === undefined
            ? ev.minTtl
            : Math.min(overallMinTtl, ev.minTtl);
      }
      if (ev.timestamp !== undefined) {
        exp.firstSeen =
          exp.firstSeen === undefined
            ? ev.timestamp
            : Math.min(exp.firstSeen, ev.timestamp);
        exp.lastSeen =
          exp.lastSeen === undefined
            ? ev.timestamp
            : Math.max(exp.lastSeen, ev.timestamp);
      }
      exporterMap.set(ev.exporterIp, exp);
    }

    const exporterObservations: ExporterDscpObservation[] = [
      ...exporterMap.entries(),
    ]
      .map(([exporterIp, info]) => ({
        exporterIp,
        dscps: [...info.dscps].sort((a, b) => a - b),
        ecns: [...info.ecns].sort((a, b) => a - b),
        ...(info.minTtl !== undefined ? { minTtl: info.minTtl } : {}),
        flowCount: info.flowCount,
        ...(info.firstSeen !== undefined ? { firstSeen: info.firstSeen } : {}),
        ...(info.lastSeen !== undefined ? { lastSeen: info.lastSeen } : {}),
      }))
      .sort(
        (a, b) =>
          (a.firstSeen ?? 0) - (b.firstSeen ?? 0) ||
          a.exporterIp.localeCompare(b.exporterIp),
      );

    const exportersWithDscp = exporterObservations.filter(
      (e) => e.dscps.length > 0,
    );
    const dscpValues = [...allDscps].sort((a, b) => a - b);
    const ecnValues = [...allEcns].sort((a, b) => a - b);

    // Remarking requires >= 2 exporters observing the same 5-tuple with different DSCP values.
    const dscpRemarked =
      exportersWithDscp.length >= 2 && dscpValues.length >= 2;
    const remarkingDiff = dscpRemarked
      ? exportersWithDscp
          .map(
            (e) =>
              `${e.exporterIp}: ${e.dscps.map((d) => formatDscpLabel(d)).join("/")}`,
          )
          .join(" → ")
      : undefined;

    const unexpectedDscps = dscpValues.filter((d) =>
      isUnexpectedDscp(d, thresholds.unexpectedDscpValues),
    );
    const unexpectedDscp = unexpectedDscps.length > 0;

    let dscpSummary = "Not covered";
    if (dscpValues.length > 0) {
      if (dscpRemarked) {
        const orderedDscps: number[] = [];
        for (const obs of exportersWithDscp) {
          for (const d of obs.dscps) {
            if (!orderedDscps.includes(d)) orderedDscps.push(d);
          }
        }
        dscpSummary = orderedDscps.map((d) => formatDscpLabel(d)).join(" → ");
      } else {
        const ecnStr = ecnValues.length
          ? ` · ${ecnValues.map((e) => formatEcnLabel(e)).join("/")}`
          : "";
        dscpSummary = `${dscpValues.map((d) => formatDscpLabel(d)).join(", ")}${ecnStr}`;
      }
    } else if (hasNetflowData) {
      dscpSummary = "Unmarked";
    }

    // ICMP aggregation
    const pmtudEvents = group.icmp.filter(
      (e) => e.category === "pmtud_candidate",
    );
    const ttlEvents = group.icmp.filter((e) => e.category === "ttl_exceeded");
    const unreachEvents = group.icmp.filter(
      (e) => e.category === "unreachable",
    );
    const echoEvents = group.icmp.filter((e) => e.category === "echo");

    const pmtudCount = pmtudEvents.length;
    const ttlExceededCount = ttlEvents.length;
    const unreachableCount = unreachEvents.length;
    const echoCount = echoEvents.length;

    let icmpSummary = "0";
    if (pmtudCount > 0) {
      icmpSummary =
        pmtudCount === 1
          ? "PMTUD candidate (T3/C4)"
          : `PMTUD candidate × ${pmtudCount}`;
    } else if (ttlExceededCount > 0) {
      icmpSummary = `TTL Exceeded × ${ttlExceededCount}`;
    } else if (unreachableCount > 0) {
      icmpSummary = `Unreachable × ${unreachableCount}`;
    } else if (echoCount > 0) {
      icmpSummary = `Echo × ${echoCount}`;
    }

    const pmtudExplanation =
      pmtudCount > 0
        ? pmtudEvents.some((e) => e.isIpv6)
          ? "PMTUD candidate (ICMPv6 Type 2 — Packet Too Big): an upstream hop reported an MTU smaller than the packet size. Inspect path MTU and DF/MSS clamping; does not confirm an MTU blackhole."
          : "PMTUD candidate (ICMP Type 3 Code 4 — Fragmentation Needed): an upstream hop could not fragment a DF-marked packet. Inspect path MTU and TCP MSS; does not confirm an MTU blackhole."
        : undefined;

    // ND drop aggregation
    const dropPktCount = group.nd.reduce((sum, e) => sum + e.dropPktCount, 0);
    const dropReasons = [...new Set(group.nd.flatMap((e) => e.dropReasons))];
    const ndNodes = [...new Set(group.nd.flatMap((e) => e.nodeNames))];
    const fabricName = group.nd.find((e) => e.fabricName)?.fabricName;
    const ndHost = group.nd.find((e) => e.ndHost)?.ndHost;
    const ndDropFlagged =
      dropPktCount >= thresholds.dropPktWarnCount || dropReasons.length > 0;

    // Reasons & findings
    const reasons: string[] = [];
    const findings: string[] = [];

    if (dscpRemarked && remarkingDiff) {
      reasons.push(`DSCP remarked across exporters (${remarkingDiff})`);
      findings.push(
        `DSCP remarking detected across ${exportersWithDscp.length} exporters: ${remarkingDiff}`,
      );
    }
    if (unexpectedDscp) {
      const labels = unexpectedDscps.map((d) => formatDscpLabel(d)).join(", ");
      reasons.push(`Unexpected DSCP class: ${labels}`);
      findings.push(`Unexpected DSCP class observed: ${labels}`);
    }
    if (pmtudCount > 0) {
      reasons.push(
        pmtudEvents.some((e) => e.isIpv6)
          ? `PMTUD candidate (ICMPv6 Packet Too Big × ${pmtudCount})`
          : `PMTUD candidate (Fragmentation Needed × ${pmtudCount})`,
      );
      if (pmtudExplanation) findings.push(pmtudExplanation);
    }
    if (ttlExceededCount >= thresholds.icmpTtlExceededWarnCount) {
      reasons.push(
        `${ttlExceededCount} ICMP TTL exceeded events (≥ ${thresholds.icmpTtlExceededWarnCount})`,
      );
      findings.push(
        `ICMP Type 11 TTL Exceeded spike: ${ttlExceededCount} events in window`,
      );
    }
    if (unreachableCount >= thresholds.icmpUnreachableWarnCount) {
      reasons.push(
        `${unreachableCount} ICMP Destination Unreachable events (≥ ${thresholds.icmpUnreachableWarnCount})`,
      );
      findings.push(
        `ICMP Destination Unreachable spike: ${unreachableCount} events in window`,
      );
    }
    if (ndDropFlagged) {
      const reasonText = dropReasons.length
        ? ` (${dropReasons.join(", ")})`
        : "";
      reasons.push(
        `ND fabric drop: ${formatCount(dropPktCount)} ${dropPktCount === 1 ? "pkt" : "pkts"}${reasonText}`,
      );
      findings.push(
        `Nexus Dashboard fabric drop on ${ndNodes.length ? ndNodes.join(", ") : (ndHost ?? "fabric")}: ${dropPktCount} pkts${reasonText}`,
      );
    }
    if (ecnValues.includes(3)) {
      findings.push("ECN Congestion Experienced (CE = 3) bit observed in ToS");
    }

    const attention = reasons.length > 0;
    const status: ProtocolStatus = attention
      ? "attention"
      : !hasNetflowData && !hasIcmpData && hasNdData
        ? "not_covered"
        : "ok";
    const rowReasons =
      !attention && !hasNetflowData && !hasIcmpData && hasNdData
        ? [
            "Nexus Dashboard flow only — DSCP marking and ICMP errors are not covered.",
          ]
        : reasons;

    const totalBytes =
      group.netflow.reduce((s, e) => s + e.bytes, 0) +
      group.icmp.reduce((s, e) => s + e.bytes, 0);
    const totalPackets =
      group.netflow.reduce((s, e) => s + e.packets, 0) +
      group.icmp.reduce((s, e) => s + e.packets, 0);

    const timestamps = [
      ...group.netflow.map((e) => e.timestamp),
      ...group.icmp.map((e) => e.timestamp),
      ...group.nd.map((e) => e.timestamp),
    ].filter((t): t is number => t !== undefined);

    const sourcetypes = [
      ...(hasNetflowData ? (["stream:netflow"] as const) : []),
      ...(hasIcmpData ? (["stream:icmp"] as const) : []),
      ...(hasNdData ? (["cisco:dc:nd:flows"] as const) : []),
    ];

    const flowLabel =
      group.srcPort !== undefined || group.dstPort !== undefined
        ? `${group.proto} ${group.srcPort ?? "*"} → ${group.dstPort ?? "*"}`
        : group.proto;

    rows.push({
      id: group.id,
      attention,
      srcIp: group.srcIp,
      dstIp: group.dstIp,
      ...(group.srcPort !== undefined ? { srcPort: group.srcPort } : {}),
      ...(group.dstPort !== undefined ? { dstPort: group.dstPort } : {}),
      proto: group.proto,
      flowLabel,
      hasNetflowData,
      hasIcmpData,
      hasNdData,
      dscpValues,
      ecnValues,
      dscpSummary,
      dscpRemarked,
      ...(remarkingDiff ? { remarkingDiff } : {}),
      unexpectedDscp,
      ...(overallMinTtl !== undefined ? { minTtl: overallMinTtl } : {}),
      exporterObservations,
      pmtudCount,
      ttlExceededCount,
      unreachableCount,
      echoCount,
      icmpSummary,
      ...(pmtudExplanation ? { pmtudExplanation } : {}),
      dropPktCount,
      dropReasons,
      ndNodes,
      ...(fabricName ? { fabricName } : {}),
      ...(ndHost ? { ndHost } : {}),
      totalBytes,
      totalPackets,
      status,
      reasons: rowReasons,
      findings,
      indexName: group.indexName,
      sourcetypes,
      ...(timestamps.length ? { firstSeen: Math.min(...timestamps) } : {}),
      ...(timestamps.length ? { lastSeen: Math.max(...timestamps) } : {}),
    });
  }

  rows.sort((a, b) => {
    if (a.attention !== b.attention) return a.attention ? -1 : 1;
    if (a.dscpRemarked !== b.dscpRemarked) return a.dscpRemarked ? -1 : 1;
    if (b.pmtudCount > 0 !== a.pmtudCount > 0) {
      return b.pmtudCount > 0 ? 1 : -1;
    }
    if (b.dropPktCount !== a.dropPktCount)
      return b.dropPktCount - a.dropPktCount;
    const bIcmpErr = b.ttlExceededCount + b.unreachableCount;
    const aIcmpErr = a.ttlExceededCount + a.unreachableCount;
    if (bIcmpErr !== aIcmpErr) return bIcmpErr - aIcmpErr;
    if (a.unexpectedDscp !== b.unexpectedDscp) {
      return a.unexpectedDscp ? -1 : 1;
    }
    if (b.totalBytes !== a.totalBytes) return b.totalBytes - a.totalBytes;
    return a.id.localeCompare(b.id);
  });

  // 4 single-metric KPI tiles
  const remarkedFlows = rows.filter((r) => r.dscpRemarked);
  const unexpectedDscpFlows = rows.filter((r) => r.unexpectedDscp);
  const totalPmtud = rows.reduce((sum, r) => sum + r.pmtudCount, 0);
  const totalIcmpErrors = rows.reduce(
    (sum, r) => sum + r.ttlExceededCount + r.unreachableCount,
    0,
  );
  const anyIcmpSpike = rows.some(
    (r) =>
      r.ttlExceededCount >= thresholds.icmpTtlExceededWarnCount ||
      r.unreachableCount >= thresholds.icmpUnreachableWarnCount,
  );
  const totalDropPkts = rows.reduce((sum, r) => sum + r.dropPktCount, 0);
  const anyNdDrop = rows.some(
    (r) =>
      r.dropPktCount >= thresholds.dropPktWarnCount || r.dropReasons.length > 0,
  );

  const remarkSpark = buildSparklineBuckets(
    netflowEvents.map((e) => ({
      timestamp: e.event.timestamp,
      value:
        e.event.dscp !== undefined &&
        isUnexpectedDscp(e.event.dscp, thresholds.unexpectedDscpValues)
          ? 1
          : 0,
    })),
    earliest,
    latest,
  );
  const pmtudSpark = buildSparklineBuckets(
    icmpEvents.map((e) => ({
      timestamp: e.event.timestamp,
      value: e.event.category === "pmtud_candidate" ? 1 : 0,
    })),
    earliest,
    latest,
  );
  const icmpErrSpark = buildSparklineBuckets(
    icmpEvents.map((e) => ({
      timestamp: e.event.timestamp,
      value:
        e.event.category === "ttl_exceeded" ||
        e.event.category === "unreachable"
          ? 1
          : 0,
    })),
    earliest,
    latest,
  );
  const ndDropSpark = buildSparklineBuckets(
    ndEvents.map((e) => ({
      timestamp: e.event.timestamp,
      value: e.event.dropPktCount,
    })),
    earliest,
    latest,
  );

  const kpis: ProtocolKpi[] = [
    {
      id: "dscp-remarks",
      label: "DSCP Remarks",
      value: hasActiveNetflow
        ? formatCount(remarkedFlows.length)
        : "Not covered",
      ...(hasActiveNetflow
        ? { unit: remarkedFlows.length === 1 ? "flow" : "flows" }
        : {}),
      status: !hasActiveNetflow
        ? "not_covered"
        : remarkedFlows.length > 0 || unexpectedDscpFlows.length > 0
          ? "attention"
          : "ok",
      ...(remarkSpark.length ? { sparkline: remarkSpark } : {}),
    },
    {
      id: "pmtud-candidates",
      label: "PMTUD Candidates",
      value: hasActiveIcmp ? formatCount(totalPmtud) : "Not covered",
      ...(hasActiveIcmp ? { unit: totalPmtud === 1 ? "event" : "events" } : {}),
      status: !hasActiveIcmp
        ? "not_covered"
        : totalPmtud > 0
          ? "attention"
          : "ok",
      ...(pmtudSpark.length ? { sparkline: pmtudSpark } : {}),
    },
    {
      id: "icmp-errors",
      label: "ICMP Errors",
      value: hasActiveIcmp ? formatCount(totalIcmpErrors) : "Not covered",
      ...(hasActiveIcmp
        ? { unit: totalIcmpErrors === 1 ? "event" : "events" }
        : {}),
      status: !hasActiveIcmp
        ? "not_covered"
        : anyIcmpSpike
          ? "attention"
          : "ok",
      ...(icmpErrSpark.length ? { sparkline: icmpErrSpark } : {}),
    },
    {
      id: "fabric-drops",
      label: "Fabric Drops",
      value: hasActiveNd ? formatCount(totalDropPkts) : "Not covered",
      ...(hasActiveNd ? { unit: totalDropPkts === 1 ? "pkt" : "pkts" } : {}),
      status: !hasActiveNd ? "not_covered" : anyNdDrop ? "attention" : "ok",
      ...(ndDropSpark.length ? { sparkline: ndDropSpark } : {}),
    },
  ];

  // Exporter × DSCP HeatMatrix
  interface MatrixBucket {
    exporter: string;
    dscpCol: string;
    flows: QosIcmpFlowRow[];
    remarkedCount: number;
    unexpectedCount: number;
    dropPkts: number;
    hasDrop: boolean;
  }
  const matrixBuckets = new Map<string, MatrixBucket>();
  const dscpNumByCol = new Map<string, number>();

  for (const row of rows) {
    if (row.exporterObservations.length > 0) {
      for (const exp of row.exporterObservations) {
        const dscps = exp.dscps.length ? exp.dscps : [-1];
        for (const dscp of dscps) {
          const dscpCol = dscp >= 0 ? formatDscpLabel(dscp) : "Unmarked";
          if (dscp >= 0) dscpNumByCol.set(dscpCol, dscp);
          else dscpNumByCol.set(dscpCol, 999);
          const key = `${exp.exporterIp}\0${dscpCol}`;
          const bucket = matrixBuckets.get(key) ?? {
            exporter: exp.exporterIp,
            dscpCol,
            flows: [],
            remarkedCount: 0,
            unexpectedCount: 0,
            dropPkts: 0,
            hasDrop: false,
          };
          if (!bucket.flows.some((f) => f.id === row.id)) {
            bucket.flows.push(row);
            if (row.dscpRemarked) bucket.remarkedCount += 1;
            if (
              dscp >= 0 &&
              isUnexpectedDscp(dscp, thresholds.unexpectedDscpValues)
            ) {
              bucket.unexpectedCount += 1;
            }
            if (
              row.dropPktCount >= thresholds.dropPktWarnCount ||
              row.dropReasons.length > 0
            ) {
              bucket.hasDrop = true;
              bucket.dropPkts += row.dropPktCount;
            }
          }
          matrixBuckets.set(key, bucket);
        }
      }
    } else if (row.hasNdData) {
      const exporter = shortenDeviceLabel(
        row.ndNodes[0] ?? row.ndHost ?? "nd-fabric",
      );
      const dscpCol = "ND Drops";
      dscpNumByCol.set(dscpCol, 1000);
      const key = `${exporter}\0${dscpCol}`;
      const bucket = matrixBuckets.get(key) ?? {
        exporter,
        dscpCol,
        flows: [],
        remarkedCount: 0,
        unexpectedCount: 0,
        dropPkts: 0,
        hasDrop: false,
      };
      bucket.flows.push(row);
      if (
        row.dropPktCount >= thresholds.dropPktWarnCount ||
        row.dropReasons.length > 0
      ) {
        bucket.hasDrop = true;
        bucket.dropPkts += row.dropPktCount;
      }
      matrixBuckets.set(key, bucket);
    }
  }

  const flaggedExporters = new Set<string>();
  const matrixCells: ProtocolMatrixCell[] = [];
  for (const bucket of matrixBuckets.values()) {
    const isFlagged =
      bucket.remarkedCount > 0 || bucket.unexpectedCount > 0 || bucket.hasDrop;
    if (isFlagged) flaggedExporters.add(bucket.exporter);

    const status: ProtocolStatus = isFlagged
      ? "attention"
      : bucket.dscpCol === "ND Drops"
        ? "not_covered"
        : "ok";

    let value = `${bucket.flows.length} ${bucket.flows.length === 1 ? "flow" : "flows"}`;
    if (bucket.remarkedCount > 0 && bucket.hasDrop) {
      value = "Remark · Drop";
    } else if (bucket.remarkedCount > 0) {
      value = `Remarked (${bucket.remarkedCount})`;
    } else if (bucket.hasDrop) {
      value = `Drop (${formatCount(bucket.dropPkts)})`;
    } else if (bucket.unexpectedCount > 0) {
      value = `Unexpected (${bucket.unexpectedCount})`;
    }

    const sortedCellFlows = [...bucket.flows].sort((a, b) =>
      a.attention === b.attention ? 0 : a.attention ? -1 : 1,
    );
    const details = sortedCellFlows
      .flatMap((f) => f.reasons)
      .filter(Boolean)
      .slice(0, 3);

    matrixCells.push({
      row: bucket.exporter,
      col: bucket.dscpCol,
      status,
      value,
      count: bucket.flows.length,
      detail: details.length
        ? details.join("; ")
        : `${bucket.flows.length} ${bucket.flows.length === 1 ? "flow" : "flows"} with consistent ${bucket.dscpCol}`,
      itemId: sortedCellFlows[0]?.id,
    });
  }

  const matrixRows = [...new Set(matrixCells.map((c) => c.row))].sort(
    (a, b) => {
      const aFlag = flaggedExporters.has(a);
      const bFlag = flaggedExporters.has(b);
      if (aFlag !== bFlag) return aFlag ? -1 : 1;
      return a.localeCompare(b);
    },
  );

  const matrixCols = [...new Set(matrixCells.map((c) => c.col))].sort(
    (a, b) => (dscpNumByCol.get(a) ?? 999) - (dscpNumByCol.get(b) ?? 999),
  );

  // SwimlaneTimeline of ICMP events and ND fabric drops
  const timelineEntries: {
    event: ProtocolTimelineEvent;
    rowId: string;
  }[] = [];

  for (let i = 0; i < icmpEvents.length; i += 1) {
    const ev = icmpEvents[i].event;
    if (ev.timestamp === undefined) continue;
    const rowId = makeQosFlowRowId(ev.srcIp, ev.dstIp, ev.proto);
    const lane = `${shortenDeviceLabel(ev.srcIp)} → ${shortenDeviceLabel(ev.dstIp)}`;
    let label: string;
    let kind: ProtocolTimelineEvent["kind"];
    if (ev.category === "pmtud_candidate") {
      label = ev.isIpv6
        ? "PMTUD candidate: Packet Too Big (Type 2)"
        : "PMTUD candidate: Fragmentation Needed (Type 3 Code 4)";
      kind = "attention";
    } else if (ev.category === "unreachable") {
      label = `Destination Unreachable (Type ${ev.icmpType} Code ${ev.icmpCode})`;
      kind = "attention";
    } else if (ev.category === "ttl_exceeded") {
      label = `TTL Exceeded (Type ${ev.icmpType} Code ${ev.icmpCode})`;
      kind = "attention";
    } else if (ev.category === "echo") {
      label = `ICMP Echo (Type ${ev.icmpType})`;
      kind = "ok";
    } else {
      label = `ICMP Type ${ev.icmpType} Code ${ev.icmpCode}`;
      kind = "info";
    }
    timelineEntries.push({
      event: {
        id: `icmp_${i}_${ev.timestamp}`,
        lane,
        timestamp: ev.timestamp,
        kind,
        label,
        detail: `${ev.srcIp} → ${ev.dstIp} (${label})`,
      },
      rowId,
    });
  }

  for (let i = 0; i < ndEvents.length; i += 1) {
    const ev = ndEvents[i].event;
    if (ev.timestamp === undefined || !ev.hasDrop) continue;
    const rowId = makeQosFlowRowId(
      ev.srcIp,
      ev.dstIp,
      ev.proto,
      ev.srcPort,
      ev.dstPort,
    );
    const nodeLabel = shortenDeviceLabel(
      ev.nodeNames[0] ?? ev.ndHost ?? ev.host,
    );
    const lane = `ND drop · ${nodeLabel}`;
    const reasonSuffix = ev.dropReasons.length
      ? ` (${ev.dropReasons.join(", ")})`
      : "";
    timelineEntries.push({
      event: {
        id: `nd_drop_${i}_${ev.timestamp}`,
        lane,
        timestamp: ev.timestamp,
        kind: "attention",
        label: `Fabric drop: ${formatCount(ev.dropPktCount)} ${ev.dropPktCount === 1 ? "pkt" : "pkts"}${reasonSuffix}`,
        detail: `${ev.fabricName ? `${ev.fabricName} · ` : ""}${ev.srcIp} → ${ev.dstIp}`,
      },
      rowId,
    });
  }

  timelineEntries.sort((a, b) => a.event.timestamp - b.event.timestamp);
  const boundedTimeline = timelineEntries.slice(0, 128);
  const timelineEvents = boundedTimeline.map((e) => e.event);
  const timelineRowByEventId: Record<string, string> = {};
  for (const item of boundedTimeline) {
    timelineRowByEventId[item.event.id] = item.rowId;
  }

  // Plain-language verdict above the fold
  const flaggedRows = rows.filter((r) => r.attention);
  let verdict: string;
  let verdictStatus: ProtocolStatus;

  if (flaggedRows.length > 0) {
    const lead = flaggedRows[0];
    const leadDetail = lead.dscpRemarked
      ? `DSCP remarked (${lead.dscpSummary})`
      : lead.pmtudCount > 0
        ? `PMTUD candidate (${lead.icmpSummary})`
        : lead.dropPktCount >= thresholds.dropPktWarnCount ||
            lead.dropReasons.length > 0
          ? `${formatCount(lead.dropPktCount)} fabric drops`
          : lead.ttlExceededCount >= thresholds.icmpTtlExceededWarnCount
            ? `${lead.ttlExceededCount} ICMP TTL exceeded`
            : lead.unreachableCount >= thresholds.icmpUnreachableWarnCount
              ? `${lead.unreachableCount} ICMP unreachable`
              : (lead.reasons[0] ?? "QoS/ICMP exception");
    verdict = `${flaggedRows.length} of ${rows.length} ${rows.length === 1 ? "flow needs" : "flows need"} attention: ${leadDetail} on ${lead.srcIp} → ${lead.dstIp}.`;
    verdictStatus = "attention";
  } else if (!hasActiveNetflow && !hasActiveIcmp && hasActiveNd) {
    const capPrefix = capped ? `First ${rows.length} ` : "";
    verdict = `Nexus Dashboard flows only (${capPrefix}${rows.length} ${rows.length === 1 ? "flow" : "flows"} observed${capped ? ", capped" : ""}, 0 drops) — DSCP and ICMP are not covered.`;
    verdictStatus = "not_covered";
  } else {
    const coveredChecks: string[] = [];
    const missingDims: string[] = [];
    if (hasActiveNetflow) coveredChecks.push("consistent DSCP markings");
    else missingDims.push("DSCP");
    if (hasActiveIcmp) coveredChecks.push("no ICMP errors");
    else missingDims.push("ICMP");
    if (hasActiveNd) coveredChecks.push("no fabric drops");
    else missingDims.push("fabric drops");
    const scopePrefix = capped
      ? `First ${rows.length} ${rows.length === 1 ? "flow" : "flows"} (capped)`
      : `${rows.length} of ${rows.length} ${rows.length === 1 ? "flow" : "flows"}`;
    const missingNote = missingDims.length
      ? ` — ${missingDims.join(" and ")} not covered`
      : "";
    verdict = `${scopePrefix} healthy with ${coveredChecks.join(", ")}${missingNote}.`;
    verdictStatus = "ok";
  }

  const coverageStatus: ProtocolStatus = anyPartial
    ? "attention"
    : !hasActiveNetflow && !hasActiveIcmp && hasActiveNd
      ? "not_covered"
      : "ok";
  const activeCount = outcomes.filter(
    (o) => o.state === "complete" || o.state === "partial",
  ).length;
  const coverageLabel =
    streamReadiness?.state === "estimate_only" &&
    !hasActiveNetflow &&
    !hasActiveNd
      ? "Estimate mode"
      : `${activeCount} ${activeCount === 1 ? "source" : "sources"}`;

  const blockedDetail = outcomes.find((o) => o.state === "blocked")?.detail;
  const unavailableDetail = outcomes.find(
    (o) => o.state === "unavailable",
  )?.detail;

  let bannerState: QosIcmpInvestigationResult["bannerState"];
  let bannerReason: string | undefined;

  if (anyPartial) {
    bannerState = "partial";
    bannerReason = anyBlocked
      ? `One or more sources denied access (${blockedDetail ?? "access denied"}); results are incomplete.`
      : anyUnavailable
        ? `One or more sources failed (${unavailableDetail ?? "search unavailable"}); results are incomplete.`
        : "Sample capped at 256 rows — narrow the UTC window or filter.";
  } else if (streamReadiness?.state === "estimate_only") {
    bannerState = "estimate_only";
    bannerReason = streamReadiness.detail;
  }

  return {
    verdict,
    verdictStatus,
    coverageStatus,
    coverageLabel,
    hasActiveNetflow,
    netflowDegraded,
    ...(netflowDegradedReason ? { netflowDegradedReason } : {}),
    hasActiveIcmp,
    hasActiveNd,
    kpis,
    rows,
    matrixRows,
    matrixCols,
    matrixCells,
    timelineEvents,
    timelineRowByEventId,
    outcomes,
    capped,
    sourceMode,
    streamReadiness,
    ...(bannerState ? { bannerState, bannerReason } : {}),
    checkedAt: nowSec,
  };
}

export interface InvestigateQosIcmpOptions {
  skipEstimateCheck?: boolean;
  skipConfigRecheck?: boolean;
  profileValidators?: Partial<Record<ProtocolLensId, LensProfileValidator>>;
}

/**
 * Executes the on-demand QoS/DSCP & ICMP investigation across configured
 * `qos_icmp` profiles (`stream:netflow`, `stream:icmp`, `cisco:dc:nd:flows`),
 * verifying `adm_protocol_profiles` fingerprint before committing results.
 */
export async function investigateQosIcmp(
  client: SearchClient,
  request: ProtocolRequest,
  configuration: ProtocolConfiguration,
  signal: AbortSignal,
  options: InvestigateQosIcmpOptions = {},
): Promise<QosIcmpInvestigationResult> {
  const scoped = selectActiveProfiles(
    configuration.profiles,
    "qos_icmp",
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
      hasActiveNetflow: false,
      netflowDegraded: false,
      hasActiveIcmp: false,
      hasActiveNd: false,
      kpis: [],
      rows: [],
      matrixRows: [],
      matrixCols: [],
      matrixCells: [],
      timelineEvents: [],
      timelineRowByEventId: {},
      outcomes: [],
      capped: false,
      sourceMode: "none",
      bannerState: "unavailable",
      bannerReason: `No qos_icmp profile configured for scope "${request.scope}".`,
      checkedAt: Math.floor(Date.now() / 1000),
    };
  }

  const netflowProfiles = scoped.filter((p) => {
    const sk = resolveQosIcmpThresholds(p).sourceKind;
    return sk === "stream_netflow" || sk === "auto";
  });
  const icmpProfiles = scoped.filter((p) => {
    const sk = resolveQosIcmpThresholds(p).sourceKind;
    return sk === "stream_icmp" || sk === "auto";
  });
  const ndProfiles = scoped.filter((p) => {
    const sk = resolveQosIcmpThresholds(p).sourceKind;
    return sk === "nd_flows" || sk === "auto";
  });

  const runProfiles = async () => {
    const outcomes: ProtocolSourceOutcome[] = [];
    const netflowOutcomes: ProtocolSourceOutcome[] = [];
    const collected: { event: NormalizedQosIcmpEvent; indexName: string }[] =
      [];
    let capped = false;
    const chosenThresholds = resolveQosIcmpThresholds(scoped[0]);

    for (const profile of netflowProfiles) {
      signal.throwIfAborted();
      const spl = buildQosIcmpSearch({
        index: profile.index,
        sourcetype: "stream:netflow",
        filter: request.filter,
        maxRows: 256,
      });
      const res = await runBoundedProtocolSearch(client, {
        lens: "qos_icmp",
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
        const norm = normalizeQosIcmpRow(row, "stream:netflow");
        if (norm) collected.push({ event: norm, indexName: profile.index });
      }
    }

    for (const profile of icmpProfiles) {
      signal.throwIfAborted();
      const spl = buildQosIcmpSearch({
        index: profile.index,
        sourcetype: "stream:icmp",
        filter: request.filter,
        maxRows: 256,
      });
      const res = await runBoundedProtocolSearch(client, {
        lens: "qos_icmp",
        profile,
        spl,
        earliest: request.earliest,
        latest: request.latest,
        signal,
        keySuffix: "icmp",
      });
      outcomes.push(res.outcome);
      if (res.capped) capped = true;
      for (const row of res.rows) {
        const norm = normalizeQosIcmpRow(row, "stream:icmp");
        if (norm) collected.push({ event: norm, indexName: profile.index });
      }
    }

    for (const profile of ndProfiles) {
      signal.throwIfAborted();
      const spl = buildQosIcmpSearch({
        index: profile.index,
        sourcetype: "cisco:dc:nd:flows",
        filter: request.filter,
        maxRows: 256,
      });
      const res = await runBoundedProtocolSearch(client, {
        lens: "qos_icmp",
        profile,
        spl,
        earliest: request.earliest,
        latest: request.latest,
        signal,
        keySuffix: "nd",
      });
      outcomes.push(res.outcome);
      if (res.capped) capped = true;
      for (const row of res.rows) {
        const norm = normalizeQosIcmpRow(row, "cisco:dc:nd:flows");
        if (norm) collected.push({ event: norm, indexName: profile.index });
      }
    }

    // Explicit Stream Estimate-mode check ONLY on explicit investigation when
    // stream:icmp completed with 0 rows.
    let streamReadiness: StreamReadinessEntry | undefined;
    const icmpCompletedEmpty =
      icmpProfiles.length > 0 &&
      collected.every((c) => c.event.sourceType !== "stream:icmp") &&
      outcomes.some(
        (o) =>
          icmpProfiles.some((ip) => ip.id === o.profile) &&
          o.state === "complete",
      );
    if (icmpCompletedEmpty && !options.skipEstimateCheck) {
      const entries = await checkStreamEstimateMode(client, ["icmp"], signal);
      streamReadiness = entries[0];
      if (streamReadiness?.state === "estimate_only") {
        outcomes.push({
          source: "protocol_stream_readiness",
          state: "estimate_only",
          detail: streamReadiness.detail,
        });
      }
    }

    const explicitNetflowConfigured = scoped.some(
      (p) => resolveQosIcmpThresholds(p).sourceKind === "stream_netflow",
    );
    const explicitNdConfigured = scoped.some(
      (p) => resolveQosIcmpThresholds(p).sourceKind === "nd_flows",
    );

    return buildQosIcmpAnalysis({
      events: collected,
      thresholds: chosenThresholds,
      earliest: request.earliest,
      latest: request.latest,
      outcomes,
      netflowOutcomes,
      capped,
      netflowConfigured:
        explicitNetflowConfigured ||
        collected.some((c) => c.event.sourceType === "stream:netflow"),
      icmpConfigured: icmpProfiles.length > 0,
      ndConfigured:
        explicitNdConfigured ||
        collected.some((c) => c.event.sourceType === "cisco:dc:nd:flows"),
      streamReadiness,
    });
  };

  if (options.skipConfigRecheck || !configuration.fingerprint) {
    return runProfiles();
  }

  const validators: Partial<Record<ProtocolLensId, LensProfileValidator>> = {
    ...options.profileValidators,
    qos_icmp: validateQosIcmpExtra,
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
        hasActiveNetflow: false,
        netflowDegraded: false,
        hasActiveIcmp: false,
        hasActiveNd: false,
        kpis: [],
        rows: [],
        matrixRows: [],
        matrixCols: [],
        matrixCells: [],
        timelineEvents: [],
        timelineRowByEventId: {},
        outcomes: [],
        capped: false,
        sourceMode: "none",
        bannerState: "stale_config",
        bannerReason: error.message,
        checkedAt: Math.floor(Date.now() / 1000),
      };
    }
    throw error;
  }
}

/**
 * Hub "Check all" summary runner for `qos_icmp`.
 */
export async function summarizeQosIcmp(
  client: SearchClient,
  request: ProtocolRequest,
  configuration: ProtocolConfiguration,
  signal: AbortSignal,
  options?: InvestigateQosIcmpOptions,
): Promise<ProtocolLensSummary> {
  const result = await investigateQosIcmp(
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
    lens: "qos_icmp",
    status,
    verdict: result.verdict,
    checkedAt: result.checkedAt,
    capped: result.capped,
    outcomes: result.outcomes,
  };
}
