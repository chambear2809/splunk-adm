import { literal } from "../../../data/evidence";
import type { SearchClient } from "../../../data/searchClient";
import type {
  BaseProtocolProfile,
  LensProfileValidator,
  ProtocolConfiguration,
  ProtocolDistributionMetric,
  ProtocolFilter,
  ProtocolKpi,
  ProtocolLensId,
  ProtocolLensSummary,
  ProtocolMatrixCell,
  ProtocolRequest,
  ProtocolSourceOutcome,
  ProtocolStatus,
} from "../../shared/contract";
import { buildAllowedFieldsClause } from "../../shared/fields";
import {
  buildFlowEndpointPredicates,
  matchesFlowEndpoints,
} from "../../shared/filterSpl";
import { formatCount, formatDurationMs } from "../../shared/format";
import {
  ProtocolConfigurationChangedError,
  runBoundedProtocolSearch,
  withProtocolConfigRecheck,
  type ProtocolRow,
} from "../../shared/runner";
import {
  checkStreamEstimateMode,
  type StreamReadinessEntry,
} from "../../shared/streamReadiness";
import {
  DEFAULT_ENTERPRISE_L7_THRESHOLDS,
  ENTERPRISE_L7_SOURCETYPES,
  ENTERPRISE_L7_STREAM_IDS,
  validateEnterpriseL7Extra,
  type EnterpriseL7ExtraConfig,
  type EnterpriseL7Sourcetype,
  type EnterpriseL7StreamId,
  type ResolvedEnterpriseL7Thresholds,
} from "./validate";

export {
  DEFAULT_ENTERPRISE_L7_THRESHOLDS,
  ENTERPRISE_L7_SOURCETYPES,
  ENTERPRISE_L7_STREAM_IDS,
  validateEnterpriseL7Extra,
  type EnterpriseL7ExtraConfig,
  type EnterpriseL7Sourcetype,
  type EnterpriseL7StreamId,
  type ResolvedEnterpriseL7Thresholds,
};

export const ENTERPRISE_L7_PROTOCOL_ORDER = [
  "SMB",
  "NFS",
  "LDAP",
  "RADIUS",
  "VoIP",
] as const;

export type EnterpriseL7Protocol =
  (typeof ENTERPRISE_L7_PROTOCOL_ORDER)[number];

export function protocolForSourcetype(
  sourcetype: EnterpriseL7Sourcetype,
): EnterpriseL7Protocol {
  switch (sourcetype) {
    case "stream:smb":
      return "SMB";
    case "stream:nfs":
      return "NFS";
    case "stream:ldap":
      return "LDAP";
    case "stream:radius":
      return "RADIUS";
    case "stream:sip":
    case "stream:rtp":
    case "stream:rtcp":
      return "VoIP";
  }
}

export function streamIdForSourcetype(
  sourcetype: EnterpriseL7Sourcetype,
): EnterpriseL7StreamId {
  return sourcetype.replace(/^stream:/, "") as EnterpriseL7StreamId;
}

export function resolveEnterpriseL7Thresholds(
  profile?: BaseProtocolProfile,
): ResolvedEnterpriseL7Thresholds {
  const extra = profile?.extra as EnterpriseL7ExtraConfig | undefined;
  const sourcetypes: EnterpriseL7Sourcetype[] = extra?.sourcetype
    ? [extra.sourcetype]
    : extra?.sourcetypes?.length
      ? [...extra.sourcetypes]
      : [...DEFAULT_ENTERPRISE_L7_THRESHOLDS.sourcetypes];
  return {
    sourcetypes,
    smbErrorWarnPct:
      typeof extra?.smbErrorWarnPct === "number"
        ? extra.smbErrorWarnPct
        : DEFAULT_ENTERPRISE_L7_THRESHOLDS.smbErrorWarnPct,
    nfsLatencyWarnMs:
      typeof extra?.nfsLatencyWarnMs === "number"
        ? extra.nfsLatencyWarnMs
        : DEFAULT_ENTERPRISE_L7_THRESHOLDS.nfsLatencyWarnMs,
    nfsErrorWarnPct:
      typeof extra?.nfsErrorWarnPct === "number"
        ? extra.nfsErrorWarnPct
        : DEFAULT_ENTERPRISE_L7_THRESHOLDS.nfsErrorWarnPct,
    ldapErrorWarnPct:
      typeof extra?.ldapErrorWarnPct === "number"
        ? extra.ldapErrorWarnPct
        : DEFAULT_ENTERPRISE_L7_THRESHOLDS.ldapErrorWarnPct,
    radiusRejectWarnCount:
      typeof extra?.radiusRejectWarnCount === "number"
        ? extra.radiusRejectWarnCount
        : DEFAULT_ENTERPRISE_L7_THRESHOLDS.radiusRejectWarnCount,
    voipMosWarnMin:
      typeof extra?.voipMosWarnMin === "number"
        ? extra.voipMosWarnMin
        : DEFAULT_ENTERPRISE_L7_THRESHOLDS.voipMosWarnMin,
    voipJitterWarnMs:
      typeof extra?.voipJitterWarnMs === "number"
        ? extra.voipJitterWarnMs
        : DEFAULT_ENTERPRISE_L7_THRESHOLDS.voipJitterWarnMs,
    voipLossWarnPct:
      typeof extra?.voipLossWarnPct === "number"
        ? extra.voipLossWarnPct
        : DEFAULT_ENTERPRISE_L7_THRESHOLDS.voipLossWarnPct,
  };
}

/**
 * Strictly allowlisted fields for Overview & Matrix searches.
 * NEVER includes `login`, `password`, `passwd`, `content`, `src_content`,
 * `dest_content`, `cookie`, `form_data`, `uri_query`, `payload`, `_raw`,
 * or row-expansion-only fields (`user_id`, `calling_station_id`).
 */
export const ENTERPRISE_L7_PROJECTED_FIELDS = [
  "_time",
  "host",
  "sourcetype",
  "src_ip",
  "dest_ip",
  "src_port",
  "dest_port",
  "protocol",
  "status",
  "status_code",
  "nt_status",
  "result_code",
  "response_code",
  "code",
  "message_type",
  "acct_status_type",
  "time_taken",
  "response_time",
  "command",
  "operation",
  "procedure",
  "method",
  "sip_method",
  "dialect",
  "smb_version",
  "nfs_version",
  "auth_type",
  "bind_type",
  "sasl_mechanism",
  "call_id",
  "mos",
  "jitter",
  "packet_loss",
  "packets_lost",
  "packet_loss_pct",
  "packets_in",
  "packets_out",
  "rtp_jitter",
  "rtcp_jitter",
  "codec",
  "nas_ip_address",
  "bytes_in",
  "bytes_out",
] as const;

/**
 * Row-expansion-only field lists used exclusively when an operator explicitly
 * inspects session identities inside a single SMB or RADIUS Detail Drawer.
 */
export const SMB_ROW_EXPANSION_FIELDS = [
  "_time",
  "host",
  "sourcetype",
  "src_ip",
  "dest_ip",
  "command",
  "dialect",
  "nt_status",
  "user_id",
] as const;

export const RADIUS_ROW_EXPANSION_FIELDS = [
  "_time",
  "host",
  "sourcetype",
  "src_ip",
  "dest_ip",
  "code",
  "status",
  "nas_ip_address",
  "calling_station_id",
] as const;

function buildSourcetypePredicate(
  sourcetypes: readonly EnterpriseL7Sourcetype[],
): string {
  const unique = [...new Set(sourcetypes)];
  if (unique.length === 1) {
    return `sourcetype="${unique[0]}"`;
  }
  return `(${unique.map((st) => `sourcetype="${st}"`).join(" OR ")})`;
}

function buildStreamAliasEval(
  sourcetypes: readonly EnterpriseL7Sourcetype[],
): string {
  const set = new Set<EnterpriseL7Sourcetype>(sourcetypes);
  const exprs: string[] = [];
  if (set.has("stream:nfs")) {
    exprs.push(
      `nfs_version=coalesce(nfs_version, if(sourcetype=="stream:nfs", version, null()))`,
    );
  }
  if (set.has("stream:ldap")) {
    exprs.push(
      `auth_type=coalesce(auth_type, if(sourcetype=="stream:ldap" AND lower(tostring(contains_sasl))=="true", "sasl", if(sourcetype=="stream:ldap" AND lower(tostring(contains_sasl))=="false", "simple", null())))`,
    );
  }
  if (set.has("stream:radius")) {
    exprs.push(
      `nas_ip_address=coalesce(nas_ip_address, if(sourcetype=="stream:radius", nas_ip, null()))`,
    );
  }
  if (set.has("stream:sip")) {
    exprs.push(
      `response_code=coalesce(response_code, if(sourcetype=="stream:sip", reply_code, null()))`,
    );
  }
  if (set.has("stream:rtp")) {
    exprs.push(
      `mos=coalesce(mos, if(sourcetype=="stream:rtp", mos_session, null()))`,
      `codec=coalesce(codec, if(sourcetype=="stream:rtp", codec_name, null()))`,
    );
  }
  if (set.has("stream:rtp") || set.has("stream:rtcp")) {
    const lostParts: string[] = [];
    if (set.has("stream:rtp")) {
      lostParts.push(`if(sourcetype=="stream:rtp", lost, null())`);
    }
    if (set.has("stream:rtcp")) {
      lostParts.push(
        `if(sourcetype=="stream:rtcp", coalesce(rr_cumlost, sr_cumlost), null())`,
      );
    }
    exprs.push(`packets_lost=coalesce(packets_lost, ${lostParts.join(", ")})`);
  }
  if (set.has("stream:rtcp")) {
    exprs.push(
      `rtcp_jitter=coalesce(rtcp_jitter, if(sourcetype=="stream:rtcp", coalesce(rr_jitter, sr_jitter), null()))`,
      `packet_loss=coalesce(packet_loss, if(sourcetype=="stream:rtcp", coalesce(rr_fcnlost, sr_fcnlost), null()))`,
    );
  }
  return exprs.length ? `| eval ${exprs.join(", ")} ` : "";
}

/**
 * Builds a bounded, allowlisted SPL query for Overview/Matrix `enterprise_l7`
 * searches. Emits `| head <maxRows + 1>` BEFORE `| table <allowlisted fields>`
 * so indexers cap rows and drop `_raw` server-side.
 *
 * Never selects `login`, `password`, `content`, `user_id`, or `calling_station_id`.
 */
export function buildEnterpriseL7Search(options: {
  index: string;
  sourcetypes?: readonly EnterpriseL7Sourcetype[];
  filter?: ProtocolFilter;
  maxRows: number;
}): string {
  const index = literal(options.index, 80);
  const sourcetypes = options.sourcetypes?.length
    ? options.sourcetypes
    : ENTERPRISE_L7_SOURCETYPES;
  const predicates: string[] = [
    `index=${index}`,
    buildSourcetypePredicate(sourcetypes),
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
      `(host="${dev}" OR nas_ip="${dev}" OR nas_ip_address="${dev}")`,
    );
  }
  const headLimit = Math.max(1, Math.trunc(options.maxRows)) + 1;
  const evalClause = buildStreamAliasEval(sourcetypes);
  const tableClause = buildAllowedFieldsClause(
    "enterprise_l7",
    ENTERPRISE_L7_PROJECTED_FIELDS,
  );
  return `search ${predicates.join(" ")} | head ${headLimit} ${evalClause}${tableClause}`;
}

/**
 * Builds an explicit single-row drawer expansion query for `user_id` (`stream:smb`)
 * or `calling_station_id` (`stream:radius`) with `includeRowExpansion: true`.
 * Never called during Overview/Matrix loading.
 */
export function buildEnterpriseL7RowExpansionSearch(options: {
  index: string;
  protocol: "SMB" | "RADIUS";
  server: string;
  maxRows?: number;
}): string {
  const index = literal(options.index, 80);
  const server = literal(options.server, 128);
  const headLimit = Math.max(1, Math.trunc(options.maxRows ?? 32)) + 1;
  if (options.protocol === "SMB") {
    const tableClause = buildAllowedFieldsClause(
      "enterprise_l7",
      SMB_ROW_EXPANSION_FIELDS,
      { includeRowExpansion: true },
    );
    return `search index=${index} sourcetype="stream:smb" dest_ip="${server}" | head ${headLimit} ${tableClause}`;
  }
  const tableClause = buildAllowedFieldsClause(
    "enterprise_l7",
    RADIUS_ROW_EXPANSION_FIELDS,
    { includeRowExpansion: true },
  );
  return (
    `search index=${index} sourcetype="stream:radius" dest_ip="${server}" ` +
    `| head ${headLimit} ` +
    `| eval nas_ip_address=coalesce(nas_ip_address, nas_ip) ` +
    tableClause
  );
}

/**
 * Builds a safe Splunk Search URL for raw events of a selected `(protocol, server)` row.
 */
export function buildEnterpriseL7RawEventsUrl(options: {
  index: string;
  sourcetypes: readonly EnterpriseL7Sourcetype[];
  server: string;
  earliest: number;
  latest: number;
}): string {
  const index = literal(options.index, 80);
  const dst = literal(options.server, 128);
  const sourcetypes = options.sourcetypes.length
    ? options.sourcetypes
    : ENTERPRISE_L7_SOURCETYPES;
  const stClause = buildSourcetypePredicate(sourcetypes);
  const q = `search index=${index} ${stClause} dest_ip="${dst}"`;
  const params = new URLSearchParams({
    q,
    earliest: String(Math.trunc(options.earliest)),
    latest: String(Math.trunc(options.latest)),
  });
  return `/app/splunk_adm/search?${params.toString()}`;
}

export interface NormalizedEnterpriseL7Event {
  sourcetype: EnterpriseL7Sourcetype;
  protocol: EnterpriseL7Protocol;
  timestamp: number | undefined;
  host: string;
  srcIp?: string;
  server: string;
  destPort?: number;
  latencyMs?: number;
  bytesIn?: number;
  bytesOut?: number;
  // SMB
  smbDialect?: string;
  isSmbV1?: boolean;
  smbNtStatus?: string;
  // NFS
  nfsVersion?: string;
  nfsStatus?: string;
  // LDAP
  ldapBindKind?: "simple_cleartext" | "simple_tls" | "sasl";
  ldapResultCode?: string;
  // RADIUS
  radiusDecision?: "accept" | "reject" | "other";
  nasIp?: string;
  hasExplicitNasIp?: boolean;
  // VoIP (SIP / RTP / RTCP)
  sipMethod?: string;
  sipStatusCode?: number;
  callId?: string;
  mos?: number;
  jitterMs?: number;
  packetLossPct?: number;
  codec?: string;
  // Shared status indicator
  hasStatusSample: boolean;
  isError: boolean;
}

export interface NasRejectSummary {
  nasIp: string;
  rejectCount: number;
  totalCount: number;
}

export interface EnterpriseL7ServiceRow {
  /** URL-safe `ITEM_ID` matching `^[A-Za-z0-9][A-Za-z0-9._:/@[\]-]{0,191}$` (`protocol__server`). */
  id: string;
  attention: boolean;
  protocol: EnterpriseL7Protocol;
  server: string;
  sourcetypes: EnterpriseL7Sourcetype[];
  eventCount: number;
  errorCount: number;
  statusSampleCount: number;
  errorPct?: number;
  latencyP50Ms?: number;
  latencyP95Ms?: number;
  totalBytes: number;
  // Protocol-specific findings
  smbDialects: string[];
  smbV1Count: number;
  topNtStatuses: { status: string; count: number }[];
  nfsVersions: string[];
  topNfsErrors: { status: string; count: number }[];
  ldapSimpleCleartextCount: number;
  ldapSaslCount: number;
  ldapSimpleTlsCount: number;
  radiusRejectCount: number;
  radiusAcceptCount: number;
  nasRejects: NasRejectSummary[];
  sipErrorCount: number;
  voipMinMos?: number;
  voipMaxJitterMs?: number;
  voipMaxPacketLossPct?: number;
  voipCodecs: string[];
  voipAlertCount: number;
  authOrQualitySummary: string;
  authOrQualityCovered: boolean;
  errorOrRejectSummary: string;
  errorOrRejectCovered: boolean;
  status: ProtocolStatus;
  reasons: string[];
  indexName: string;
  firstSeen?: number;
  lastSeen?: number;
}

export interface EnterpriseL7InvestigationResult {
  verdict: string;
  verdictStatus: ProtocolStatus;
  coverageStatus: ProtocolStatus;
  coverageLabel: string;
  kpis: ProtocolKpi[];
  rows: EnterpriseL7ServiceRow[];
  matrixRows: string[];
  matrixCols: string[];
  matrixCells: ProtocolMatrixCell[];
  distribution: ProtocolDistributionMetric[];
  outcomes: ProtocolSourceOutcome[];
  capped: boolean;
  configuredProtocols: EnterpriseL7Protocol[];
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

export interface EnterpriseL7RowExpansionResult {
  fieldName: "user_id" | "calling_station_id";
  values: string[];
  capped: boolean;
  outcome: ProtocolSourceOutcome;
}

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

const VALID_ST_SET = new Set<string>(ENTERPRISE_L7_SOURCETYPES);

function resolveSourcetype(
  row: ProtocolRow,
): EnterpriseL7Sourcetype | undefined {
  const st = asString(row.sourcetype).toLowerCase();
  if (VALID_ST_SET.has(st)) return st as EnterpriseL7Sourcetype;
  const proto = asString(row.protocol).toLowerCase();
  if (proto === "smb") return "stream:smb";
  if (proto === "nfs") return "stream:nfs";
  if (proto === "ldap" || proto === "ldaps") return "stream:ldap";
  if (proto === "radius") return "stream:radius";
  if (proto === "sip") return "stream:sip";
  if (proto === "rtp") return "stream:rtp";
  if (proto === "rtcp") return "stream:rtcp";
  return undefined;
}

const SMB_V1_RE =
  /^(?:smb\s*v?1(?:\.0)?|1(?:\.0)?|nt\s*lm\s*0\.12|pc\s*network\s*program\s*1\.0|lanman[\d.]*|lm1\.2x002)$/i;

export function isSmbV1Dialect(dialect: string): boolean {
  const trimmed = dialect.trim();
  if (!trimmed) return false;
  if (SMB_V1_RE.test(trimmed)) return true;
  const lower = trimmed.toLowerCase();
  return lower.includes("nt lm 0.12") || /\bsmb\s*v?1(?:\.0)?\b/.test(lower);
}

export function isSmbNtError(status: string): boolean {
  const norm = status.trim().toUpperCase();
  if (!norm) return false;
  if (
    norm === "STATUS_SUCCESS" ||
    norm === "SUCCESS" ||
    norm === "OK" ||
    norm === "NT_STATUS_OK" ||
    norm === "STATUS_MORE_PROCESSING_REQUIRED" ||
    norm === "0" ||
    norm === "0X0" ||
    norm === "0X00000000" ||
    norm === "0XC0000016"
  ) {
    return false;
  }
  return true;
}

export function isNfsError(status: string): boolean {
  const norm = status.trim().toUpperCase();
  if (!norm) return false;
  if (
    norm === "NFS3_OK" ||
    norm === "NFS4_OK" ||
    norm === "NFS_OK" ||
    norm === "OK" ||
    norm === "SUCCESS" ||
    norm === "0" ||
    norm === "0X0"
  ) {
    return false;
  }
  if (/^NFS\d*ERR_/.test(norm) || norm.startsWith("ERR_")) return true;
  const num = Number(norm);
  if (Number.isFinite(num)) return num !== 0;
  return true;
}

export function isLdapError(resultCode: string): boolean {
  const norm = resultCode.trim().toLowerCase();
  if (!norm) return false;
  if (
    norm === "0" ||
    norm === "success" ||
    norm === "ok" ||
    norm === "saslbindinprogress" ||
    norm === "14"
  ) {
    return false;
  }
  return true;
}

export function classifyRadiusDecision(
  rawCode: string,
): "accept" | "reject" | "other" {
  const norm = rawCode
    .trim()
    .toLowerCase()
    .replace(/[\s_]+/g, "-");
  if (norm === "access-reject" || norm === "reject" || norm === "3") {
    return "reject";
  }
  if (norm === "access-accept" || norm === "accept" || norm === "2") {
    return "accept";
  }
  return "other";
}

/**
 * Normalizes a single allowlist-projected Enterprise L7 row across
 * `stream:smb`, `stream:nfs`, `stream:ldap`, `stream:radius`,
 * `stream:sip`, `stream:rtp`, and `stream:rtcp`.
 */
export function normalizeEnterpriseL7Row(
  row: ProtocolRow,
): NormalizedEnterpriseL7Event | undefined {
  const sourcetype = resolveSourcetype(row);
  if (!sourcetype) return undefined;
  const server = asString(row.dest_ip);
  if (!server) return undefined;
  const srcIp = asString(row.src_ip) || undefined;
  const destPort = asFiniteNumber(row.dest_port);
  const timestamp = asEpochSeconds(row._time);
  const host = asString(row.host) || "unknown";
  const protocol = protocolForSourcetype(sourcetype);

  // Stream reports response_time and time_taken in microseconds.
  const rawLatency =
    asFiniteNumber(row.response_time) ?? asFiniteNumber(row.time_taken);
  const latencyMs =
    rawLatency !== undefined && rawLatency > 0 ? rawLatency / 1000 : undefined;

  const bytesIn = asFiniteNumber(row.bytes_in);
  const bytesOut = asFiniteNumber(row.bytes_out);

  const base: NormalizedEnterpriseL7Event = {
    sourcetype,
    protocol,
    timestamp,
    host,
    ...(srcIp ? { srcIp } : {}),
    server,
    ...(destPort !== undefined ? { destPort } : {}),
    ...(latencyMs !== undefined ? { latencyMs } : {}),
    ...(bytesIn !== undefined && bytesIn >= 0 ? { bytesIn } : {}),
    ...(bytesOut !== undefined && bytesOut >= 0 ? { bytesOut } : {}),
    hasStatusSample: false,
    isError: false,
  };

  if (sourcetype === "stream:smb") {
    const smbDialect =
      asString(row.dialect) || asString(row.smb_version) || undefined;
    const smbNtStatus =
      asString(row.nt_status) ||
      asString(row.status) ||
      asString(row.status_code) ||
      undefined;
    return {
      ...base,
      ...(smbDialect
        ? { smbDialect, isSmbV1: isSmbV1Dialect(smbDialect) }
        : {}),
      ...(smbNtStatus
        ? {
            smbNtStatus,
            hasStatusSample: true,
            isError: isSmbNtError(smbNtStatus),
          }
        : {}),
    };
  }

  if (sourcetype === "stream:nfs") {
    const nfsVersion = asString(row.nfs_version) || undefined;
    const nfsStatus =
      asString(row.status) || asString(row.status_code) || undefined;
    return {
      ...base,
      ...(nfsVersion ? { nfsVersion } : {}),
      ...(nfsStatus
        ? {
            nfsStatus,
            hasStatusSample: true,
            isError: isNfsError(nfsStatus),
          }
        : {}),
    };
  }

  if (sourcetype === "stream:ldap") {
    const authType = asString(row.auth_type).toLowerCase();
    const bindType = asString(row.bind_type).toLowerCase();
    const saslMechanism = asString(row.sasl_mechanism);
    const messageType = asString(row.message_type);
    const protoTag = asString(row.protocol).toLowerCase();
    const hasTls = destPort === 636 || protoTag === "ldaps";
    const isSasl =
      authType === "sasl" ||
      bindType === "sasl" ||
      (Boolean(saslMechanism) && saslMechanism.toLowerCase() !== "none");
    const isSimpleExplicit =
      authType === "simple" ||
      bindType === "simple" ||
      authType === "cleartext" ||
      bindType === "cleartext";
    const isBindMsg =
      Boolean(messageType) &&
      /bind/i.test(messageType) &&
      !/unbind/i.test(messageType);

    let ldapBindKind: NormalizedEnterpriseL7Event["ldapBindKind"];
    if (isSasl) {
      ldapBindKind = "sasl";
    } else if (
      isSimpleExplicit ||
      (isBindMsg && (authType !== "" || bindType !== "" || destPort === 389))
    ) {
      ldapBindKind = hasTls ? "simple_tls" : "simple_cleartext";
    }

    const ldapResultCode =
      asString(row.result_code) ||
      asString(row.status_code) ||
      asString(row.response_code) ||
      asString(row.status) ||
      undefined;

    return {
      ...base,
      ...(ldapBindKind ? { ldapBindKind } : {}),
      ...(ldapResultCode
        ? {
            ldapResultCode,
            hasStatusSample: true,
            isError: isLdapError(ldapResultCode),
          }
        : {}),
    };
  }

  if (sourcetype === "stream:radius") {
    const rawCode =
      asString(row.code) ||
      asString(row.status) ||
      asString(row.acct_status_type);
    const radiusDecision = rawCode
      ? classifyRadiusDecision(rawCode)
      : undefined;
    const explicitNas = asString(row.nas_ip_address);
    const nasIp = explicitNas || srcIp;
    return {
      ...base,
      ...(radiusDecision ? { radiusDecision, hasStatusSample: true } : {}),
      ...(nasIp ? { nasIp } : {}),
      hasExplicitNasIp: Boolean(explicitNas),
      isError: radiusDecision === "reject",
    };
  }

  if (sourcetype === "stream:sip") {
    const sipMethod =
      asString(row.sip_method) || asString(row.method) || undefined;
    const sipStatusCode =
      asFiniteNumber(row.response_code) ??
      asFiniteNumber(row.status_code) ??
      asFiniteNumber(row.status);
    const callId = asString(row.call_id) || undefined;
    const isSipError =
      sipStatusCode !== undefined &&
      sipStatusCode >= 400 &&
      sipStatusCode !== 401 &&
      sipStatusCode !== 407;
    return {
      ...base,
      ...(sipMethod ? { sipMethod } : {}),
      ...(sipStatusCode !== undefined
        ? {
            sipStatusCode,
            hasStatusSample: true,
            isError: isSipError,
          }
        : {}),
      ...(callId ? { callId } : {}),
    };
  }

  // stream:rtp / stream:rtcp
  const rawMos = asFiniteNumber(row.mos);
  const mos =
    rawMos !== undefined && rawMos >= 1 && rawMos <= 5 ? rawMos : undefined;
  const rawJitter =
    asFiniteNumber(row.jitter) ??
    asFiniteNumber(row.rtp_jitter) ??
    asFiniteNumber(row.rtcp_jitter);
  const jitterMs =
    rawJitter !== undefined && rawJitter >= 0 ? rawJitter : undefined;

  let packetLossPct =
    asFiniteNumber(row.packet_loss_pct) ?? asFiniteNumber(row.packet_loss);
  if (packetLossPct !== undefined && packetLossPct < 0) {
    packetLossPct = undefined;
  }
  if (packetLossPct === undefined) {
    const lost = asFiniteNumber(row.packets_lost);
    const pktsIn = asFiniteNumber(row.packets_in) ?? 0;
    const pktsOut = asFiniteNumber(row.packets_out) ?? 0;
    const total = pktsIn + pktsOut + (lost ?? 0);
    if (lost !== undefined && lost >= 0 && total > 0) {
      packetLossPct = (lost / total) * 100;
    }
  }
  const codec = asString(row.codec) || undefined;
  const callId = asString(row.call_id) || undefined;

  return {
    ...base,
    ...(mos !== undefined ? { mos } : {}),
    ...(jitterMs !== undefined ? { jitterMs } : {}),
    ...(packetLossPct !== undefined ? { packetLossPct } : {}),
    ...(codec ? { codec } : {}),
    ...(callId ? { callId } : {}),
  };
}

export function percentile(
  values: readonly number[],
  pct: number,
): number | undefined {
  if (!values.length) return undefined;
  const sorted = [...values].sort((a, b) => a - b);
  const idx = Math.min(
    sorted.length - 1,
    Math.max(0, Math.ceil((pct / 100) * sorted.length) - 1),
  );
  return sorted[idx];
}

function roundMetric(val: number): number {
  return val < 10 ? Math.round(val * 10) / 10 : Math.round(val);
}

function buildSparklineBuckets(
  events: readonly NormalizedEnterpriseL7Event[],
  earliest: number,
  latest: number,
  extract: (ev: NormalizedEnterpriseL7Event) => number | undefined,
  mode: "sum" | "rate",
): number[] {
  const buckets = 6;
  const span = Math.max(1, latest - earliest);
  const grouped: number[][] = Array.from({ length: buckets }, () => []);
  for (const ev of events) {
    const val = extract(ev);
    if (val === undefined) continue;
    const ts = ev.timestamp ?? earliest;
    const idx = Math.min(
      buckets - 1,
      Math.max(0, Math.floor(((ts - earliest) / span) * buckets)),
    );
    grouped[idx].push(val);
  }
  const points = grouped.map((bucket) => {
    if (!bucket.length) return undefined;
    if (mode === "sum") return bucket.reduce((a, b) => a + b, 0);
    return (bucket.reduce((a, b) => a + b, 0) / bucket.length) * 100;
  });
  const present = points.filter((p): p is number => p !== undefined);
  return present.length >= 4 ? present : [];
}

function isVoipAlertEvent(
  ev: NormalizedEnterpriseL7Event,
  thresholds: ResolvedEnterpriseL7Thresholds,
): boolean {
  if (ev.mos !== undefined && ev.mos < thresholds.voipMosWarnMin) return true;
  if (ev.jitterMs !== undefined && ev.jitterMs >= thresholds.voipJitterWarnMs) {
    return true;
  }
  if (
    ev.packetLossPct !== undefined &&
    ev.packetLossPct >= thresholds.voipLossWarnPct
  ) {
    return true;
  }
  return false;
}

function buildMatrixCellLabel(
  row: EnterpriseL7ServiceRow,
  thresholds: ResolvedEnterpriseL7Thresholds,
): string {
  if (row.attention) {
    if (row.smbV1Count > 0) return "SMBv1";
    if (row.ldapSimpleCleartextCount > 0) return "Simple bind";
    if (
      row.protocol === "RADIUS" &&
      row.nasRejects.some(
        (n) => n.rejectCount >= thresholds.radiusRejectWarnCount,
      )
    ) {
      const top = row.nasRejects[0];
      return `${top.rejectCount} rejects`;
    }
    if (
      row.voipMinMos !== undefined &&
      row.voipMinMos < thresholds.voipMosWarnMin
    ) {
      return `MOS ${row.voipMinMos.toFixed(1)}`;
    }
    if (
      row.voipMaxJitterMs !== undefined &&
      row.voipMaxJitterMs >= thresholds.voipJitterWarnMs
    ) {
      return `${Math.round(row.voipMaxJitterMs)} ms jitter`;
    }
    if (
      row.voipMaxPacketLossPct !== undefined &&
      row.voipMaxPacketLossPct >= thresholds.voipLossWarnPct
    ) {
      return `${row.voipMaxPacketLossPct.toFixed(1)}% loss`;
    }
    if (row.errorPct !== undefined && row.errorCount > 0) {
      return `${row.errorPct.toFixed(1)}% err`;
    }
    if (
      row.protocol === "NFS" &&
      row.latencyP95Ms !== undefined &&
      row.latencyP95Ms >= thresholds.nfsLatencyWarnMs
    ) {
      return formatDurationMs(row.latencyP95Ms);
    }
    return "Attention";
  }
  if (row.status === "not_covered") return "Not covered";
  return row.latencyP95Ms !== undefined
    ? formatDurationMs(row.latencyP95Ms)
    : "OK";
}

/**
 * Pure aggregation of normalized Enterprise L7 events into Overview rows,
 * KPI tiles, Protocol × Server HeatMatrix cells, latency distribution bars,
 * and a plain-language verdict.
 */
export function buildEnterpriseL7Analysis(options: {
  events: readonly {
    event: NormalizedEnterpriseL7Event;
    indexName: string;
  }[];
  thresholds: ResolvedEnterpriseL7Thresholds;
  configuredProtocols?: readonly EnterpriseL7Protocol[];
  earliest: number;
  latest: number;
  outcomes: ProtocolSourceOutcome[];
  capped: boolean;
  streamReadiness?: StreamReadinessEntry[];
}): EnterpriseL7InvestigationResult {
  const {
    events,
    thresholds,
    earliest,
    latest,
    outcomes,
    capped,
    streamReadiness,
  } = options;
  const nowSec = Math.floor(Date.now() / 1000);
  const configuredProtocols: EnterpriseL7Protocol[] = options
    .configuredProtocols?.length
    ? [...new Set(options.configuredProtocols)]
    : [
        ...new Set(
          thresholds.sourcetypes.map((st) => protocolForSourcetype(st)),
        ),
      ];

  const anyBlocked = outcomes.some((o) => o.state === "blocked");
  const anyUnavailable = outcomes.some((o) => o.state === "unavailable");
  const anyDegraded = anyBlocked || anyUnavailable;
  const anyPartial =
    outcomes.some((o) => o.state === "partial") || capped || anyDegraded;
  const allEstimateOnly =
    Boolean(streamReadiness?.length) &&
    streamReadiness!.every((s) => s.state === "estimate_only");
  const anyEstimateOnly = Boolean(
    streamReadiness?.some((s) => s.state === "estimate_only"),
  );

  if (!events.length) {
    if (anyEstimateOnly) {
      const estNames = streamReadiness!
        .filter((s) => s.state === "estimate_only")
        .map((s) => s.streamId)
        .join(", ");
      return {
        verdict: `Stream ${estNames} ${allEstimateOnly ? "are" : "is"} in Estimate mode (statsOnly=true); no event rows are indexed.`,
        verdictStatus: "unknown",
        coverageStatus: "unknown",
        coverageLabel: "Estimate mode",
        kpis: [],
        rows: [],
        matrixRows: [],
        matrixCols: [],
        matrixCells: [],
        distribution: [],
        outcomes,
        capped,
        configuredProtocols,
        streamReadiness,
        bannerState: "estimate_only",
        bannerReason:
          streamReadiness?.find((s) => s.state === "estimate_only")?.detail ??
          "One or more Enterprise L7 streams are in Estimate mode (statsOnly=true).",
        checkedAt: nowSec,
      };
    }
    if (anyBlocked) {
      return {
        verdict: "Source evidence could not be read for this role.",
        verdictStatus: "unknown",
        coverageStatus: "unknown",
        coverageLabel: "Blocked",
        kpis: [],
        rows: [],
        matrixRows: [],
        matrixCols: [],
        matrixCells: [],
        distribution: [],
        outcomes,
        capped,
        configuredProtocols,
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
        kpis: [],
        rows: [],
        matrixRows: [],
        matrixCols: [],
        matrixCells: [],
        distribution: [],
        outcomes,
        capped,
        configuredProtocols,
        streamReadiness,
        bannerState: "unavailable",
        bannerReason:
          outcomes.find((o) => o.state === "unavailable")?.detail ??
          "Configured source failed to complete.",
        checkedAt: nowSec,
      };
    }
    if (capped) {
      return {
        verdict:
          "Search hit the row cap before any Enterprise L7 rows could be analyzed.",
        verdictStatus: "unknown",
        coverageStatus: "unknown",
        coverageLabel: "Partial (capped)",
        kpis: [],
        rows: [],
        matrixRows: [],
        matrixCols: [],
        matrixCells: [],
        distribution: [],
        outcomes,
        capped: true,
        configuredProtocols,
        streamReadiness,
        bannerState: "partial",
        bannerReason:
          "Search hit row cap with zero matching Enterprise L7 rows — narrow the UTC window or filter.",
        checkedAt: nowSec,
      };
    }
    const anyEnabled = streamReadiness?.some((s) => s.state === "enabled");
    return {
      verdict: "No matching Enterprise L7 events observed in this UTC window.",
      verdictStatus: "none_observed",
      coverageStatus: "none_observed",
      coverageLabel: "None observed",
      kpis: [],
      rows: [],
      matrixRows: [],
      matrixCols: [],
      matrixCells: [],
      distribution: [],
      outcomes,
      capped,
      configuredProtocols,
      streamReadiness,
      bannerState: "empty",
      bannerReason: anyEnabled
        ? "Configured Enterprise L7 streams are Enabled (statsOnly=false), but no matching events were observed in this UTC window."
        : "No matching Enterprise L7 events in this UTC window.",
      checkedAt: nowSec,
    };
  }

  const groupMap = new Map<
    string,
    {
      protocol: EnterpriseL7Protocol;
      server: string;
      events: NormalizedEnterpriseL7Event[];
      indexName: string;
    }
  >();

  for (const entry of events) {
    const key = `${entry.event.protocol}__${entry.event.server}`;
    const existing = groupMap.get(key);
    if (existing) {
      existing.events.push(entry.event);
    } else {
      groupMap.set(key, {
        protocol: entry.event.protocol,
        server: entry.event.server,
        events: [entry.event],
        indexName: entry.indexName,
      });
    }
  }

  const rows: EnterpriseL7ServiceRow[] = [];
  for (const [id, group] of groupMap.entries()) {
    const { protocol, server, events: evs, indexName } = group;
    const sourcetypes = [...new Set(evs.map((e) => e.sourcetype))].sort();
    const eventCount = evs.length;
    const statusSamples = evs.filter((e) => e.hasStatusSample);
    const statusSampleCount = statusSamples.length;
    const errorCount = evs.filter((e) => e.isError).length;
    const errorPct =
      statusSampleCount > 0
        ? (errorCount / statusSampleCount) * 100
        : undefined;

    const latencies = evs
      .map((e) => e.latencyMs)
      .filter((v): v is number => v !== undefined);
    const latencyP50Ms = percentile(latencies, 50);
    const latencyP95Ms = percentile(latencies, 95);
    const totalBytes = evs.reduce(
      (sum, e) => sum + (e.bytesIn ?? 0) + (e.bytesOut ?? 0),
      0,
    );

    const smbDialects = [
      ...new Set(
        evs.map((e) => e.smbDialect).filter((d): d is string => Boolean(d)),
      ),
    ];
    const smbV1Count = evs.filter((e) => e.isSmbV1).length;
    const ntStatusCounts = new Map<string, number>();
    for (const e of evs) {
      if (e.smbNtStatus && e.isError) {
        ntStatusCounts.set(
          e.smbNtStatus,
          (ntStatusCounts.get(e.smbNtStatus) ?? 0) + 1,
        );
      }
    }
    const topNtStatuses = [...ntStatusCounts.entries()]
      .map(([status, count]) => ({ status, count }))
      .sort((a, b) => b.count - a.count || a.status.localeCompare(b.status))
      .slice(0, 5);

    const nfsVersions = [
      ...new Set(
        evs.map((e) => e.nfsVersion).filter((v): v is string => Boolean(v)),
      ),
    ];
    const nfsErrCounts = new Map<string, number>();
    for (const e of evs) {
      if (e.nfsStatus && e.isError) {
        nfsErrCounts.set(e.nfsStatus, (nfsErrCounts.get(e.nfsStatus) ?? 0) + 1);
      }
    }
    const topNfsErrors = [...nfsErrCounts.entries()]
      .map(([status, count]) => ({ status, count }))
      .sort((a, b) => b.count - a.count || a.status.localeCompare(b.status))
      .slice(0, 5);

    const ldapSimpleCleartextCount = evs.filter(
      (e) => e.ldapBindKind === "simple_cleartext",
    ).length;
    const ldapSaslCount = evs.filter((e) => e.ldapBindKind === "sasl").length;
    const ldapSimpleTlsCount = evs.filter(
      (e) => e.ldapBindKind === "simple_tls",
    ).length;

    const radiusRejectCount = evs.filter(
      (e) => e.radiusDecision === "reject",
    ).length;
    const radiusAcceptCount = evs.filter(
      (e) => e.radiusDecision === "accept",
    ).length;
    const nasMap = new Map<
      string,
      { rejectCount: number; totalCount: number }
    >();
    for (const e of evs) {
      if (e.protocol !== "RADIUS" || !e.nasIp) continue;
      const cur = nasMap.get(e.nasIp) ?? { rejectCount: 0, totalCount: 0 };
      cur.totalCount += 1;
      if (e.radiusDecision === "reject") cur.rejectCount += 1;
      nasMap.set(e.nasIp, cur);
    }
    const nasRejects: NasRejectSummary[] = [...nasMap.entries()]
      .map(([nasIp, counts]) => ({ nasIp, ...counts }))
      .filter((n) => n.rejectCount > 0)
      .sort(
        (a, b) =>
          b.rejectCount - a.rejectCount || a.nasIp.localeCompare(b.nasIp),
      );

    const sipErrorCount = evs.filter(
      (e) => e.sourcetype === "stream:sip" && e.isError,
    ).length;
    const mosValues = evs
      .map((e) => e.mos)
      .filter((v): v is number => v !== undefined);
    const jitterValues = evs
      .map((e) => e.jitterMs)
      .filter((v): v is number => v !== undefined);
    const lossValues = evs
      .map((e) => e.packetLossPct)
      .filter((v): v is number => v !== undefined);
    const voipMinMos = mosValues.length ? Math.min(...mosValues) : undefined;
    const voipMaxJitterMs = jitterValues.length
      ? Math.max(...jitterValues)
      : undefined;
    const voipMaxPacketLossPct = lossValues.length
      ? Math.max(...lossValues)
      : undefined;
    const voipCodecs = [
      ...new Set(
        evs.map((e) => e.codec).filter((c): c is string => Boolean(c)),
      ),
    ];
    const voipAlertCount = evs.filter((e) =>
      isVoipAlertEvent(e, thresholds),
    ).length;

    const reasons: string[] = [];
    let authOrQualitySummary = "Not covered";
    let authOrQualityCovered = false;
    let errorOrRejectSummary = "Not covered";
    let errorOrRejectCovered = false;

    if (protocol === "SMB") {
      if (smbV1Count > 0) {
        reasons.push(
          `SMBv1 dialect observed (${smbV1Count} ${smbV1Count === 1 ? "event" : "events"})`,
        );
      }
      if (
        errorPct !== undefined &&
        errorPct >= thresholds.smbErrorWarnPct &&
        errorCount > 0
      ) {
        reasons.push(
          `${errorPct.toFixed(1)}% SMB NT error rate (≥ ${thresholds.smbErrorWarnPct}%)`,
        );
      }
      if (smbDialects.length > 0) {
        authOrQualityCovered = true;
        authOrQualitySummary =
          smbV1Count > 0
            ? `SMBv1 (${smbDialects.find((d) => isSmbV1Dialect(d)) ?? smbDialects[0]})`
            : smbDialects[0];
      }
      if (errorPct !== undefined) {
        errorOrRejectCovered = true;
        errorOrRejectSummary = `${errorPct.toFixed(1)}% NT err`;
      }
    } else if (protocol === "NFS") {
      if (
        errorPct !== undefined &&
        errorPct >= thresholds.nfsErrorWarnPct &&
        errorCount > 0
      ) {
        reasons.push(
          `${errorPct.toFixed(1)}% NFS error rate (≥ ${thresholds.nfsErrorWarnPct}%)`,
        );
      }
      if (
        latencyP95Ms !== undefined &&
        latencyP95Ms >= thresholds.nfsLatencyWarnMs
      ) {
        reasons.push(
          `NFS latency p95 ${formatDurationMs(latencyP95Ms)} (≥ ${thresholds.nfsLatencyWarnMs} ms)`,
        );
      }
      if (nfsVersions.length > 0) {
        authOrQualityCovered = true;
        authOrQualitySummary = `NFSv${nfsVersions.join(", v")}`;
      }
      if (errorPct !== undefined) {
        errorOrRejectCovered = true;
        errorOrRejectSummary = `${errorPct.toFixed(1)}% err`;
      }
    } else if (protocol === "LDAP") {
      if (ldapSimpleCleartextCount > 0) {
        reasons.push(
          `Cleartext simple bind without SASL/TLS (${ldapSimpleCleartextCount} ${ldapSimpleCleartextCount === 1 ? "bind" : "binds"})`,
        );
      }
      if (
        errorPct !== undefined &&
        errorPct >= thresholds.ldapErrorWarnPct &&
        errorCount > 0
      ) {
        reasons.push(
          `${errorPct.toFixed(1)}% LDAP result_code errors (≥ ${thresholds.ldapErrorWarnPct}%)`,
        );
      }
      if (
        ldapSimpleCleartextCount > 0 ||
        ldapSaslCount > 0 ||
        ldapSimpleTlsCount > 0
      ) {
        authOrQualityCovered = true;
        authOrQualitySummary =
          ldapSimpleCleartextCount > 0
            ? "Simple bind (no SASL)"
            : ldapSaslCount > 0
              ? "SASL"
              : "LDAPS";
      }
      if (errorPct !== undefined) {
        errorOrRejectCovered = true;
        errorOrRejectSummary = `${errorPct.toFixed(1)}% err`;
      }
    } else if (protocol === "RADIUS") {
      const spikingNas = nasRejects.filter(
        (n) => n.rejectCount >= thresholds.radiusRejectWarnCount,
      );
      for (const nas of spikingNas) {
        reasons.push(
          `RADIUS Access-Reject spike on NAS ${nas.nasIp} (${nas.rejectCount} rejects ≥ ${thresholds.radiusRejectWarnCount})`,
        );
      }
      if (nasMap.size > 0) {
        authOrQualityCovered = true;
        authOrQualitySummary = spikingNas.length
          ? `${spikingNas[0].nasIp} (${spikingNas[0].rejectCount} rej)`
          : `${nasMap.size} ${nasMap.size === 1 ? "NAS" : "NASes"}`;
      }
      if (statusSampleCount > 0) {
        errorOrRejectCovered = true;
        errorOrRejectSummary = `${radiusRejectCount} ${radiusRejectCount === 1 ? "reject" : "rejects"}`;
      }
    } else if (protocol === "VoIP") {
      if (voipMinMos !== undefined && voipMinMos < thresholds.voipMosWarnMin) {
        reasons.push(
          `Low MOS ${voipMinMos.toFixed(1)} (< ${thresholds.voipMosWarnMin})`,
        );
      }
      if (
        voipMaxJitterMs !== undefined &&
        voipMaxJitterMs >= thresholds.voipJitterWarnMs
      ) {
        reasons.push(
          `High jitter ${Math.round(voipMaxJitterMs)} ms (≥ ${thresholds.voipJitterWarnMs} ms)`,
        );
      }
      if (
        voipMaxPacketLossPct !== undefined &&
        voipMaxPacketLossPct >= thresholds.voipLossWarnPct
      ) {
        reasons.push(
          `High packet loss ${voipMaxPacketLossPct.toFixed(1)}% (≥ ${thresholds.voipLossWarnPct}%)`,
        );
      }
      if (
        voipMinMos !== undefined ||
        voipMaxJitterMs !== undefined ||
        voipMaxPacketLossPct !== undefined
      ) {
        authOrQualityCovered = true;
        const parts: string[] = [];
        if (voipMinMos !== undefined)
          parts.push(`MOS ${voipMinMos.toFixed(1)}`);
        if (voipMaxJitterMs !== undefined)
          parts.push(`${Math.round(voipMaxJitterMs)} ms jitter`);
        authOrQualitySummary = parts.join(" · ");
      }
      if (voipMaxPacketLossPct !== undefined) {
        errorOrRejectCovered = true;
        errorOrRejectSummary = `${voipMaxPacketLossPct.toFixed(1)}% loss`;
      } else if (errorPct !== undefined) {
        errorOrRejectCovered = true;
        errorOrRejectSummary = `${errorPct.toFixed(1)}% SIP err`;
      }
    }

    const attention = reasons.length > 0;
    const hasAnyHealthSignal =
      authOrQualityCovered ||
      errorOrRejectCovered ||
      (protocol === "NFS" && latencyP95Ms !== undefined);
    const status: ProtocolStatus = attention
      ? "attention"
      : hasAnyHealthSignal
        ? "ok"
        : "not_covered";

    const rowReasons =
      !attention && !hasAnyHealthSignal
        ? [
            `Health posture fields for ${protocol} were not present in this feed.`,
          ]
        : reasons;

    const timestamps = evs
      .map((e) => e.timestamp)
      .filter((t): t is number => t !== undefined);

    rows.push({
      id,
      attention,
      protocol,
      server,
      sourcetypes,
      eventCount,
      errorCount,
      statusSampleCount,
      ...(errorPct !== undefined ? { errorPct } : {}),
      ...(latencyP50Ms !== undefined ? { latencyP50Ms } : {}),
      ...(latencyP95Ms !== undefined ? { latencyP95Ms } : {}),
      totalBytes,
      smbDialects,
      smbV1Count,
      topNtStatuses,
      nfsVersions,
      topNfsErrors,
      ldapSimpleCleartextCount,
      ldapSaslCount,
      ldapSimpleTlsCount,
      radiusRejectCount,
      radiusAcceptCount,
      nasRejects,
      sipErrorCount,
      ...(voipMinMos !== undefined ? { voipMinMos } : {}),
      ...(voipMaxJitterMs !== undefined ? { voipMaxJitterMs } : {}),
      ...(voipMaxPacketLossPct !== undefined ? { voipMaxPacketLossPct } : {}),
      voipCodecs,
      voipAlertCount,
      authOrQualitySummary,
      authOrQualityCovered,
      errorOrRejectSummary,
      errorOrRejectCovered,
      status,
      reasons: rowReasons,
      indexName,
      ...(timestamps.length ? { firstSeen: Math.min(...timestamps) } : {}),
      ...(timestamps.length ? { lastSeen: Math.max(...timestamps) } : {}),
    });
  }

  rows.sort((a, b) => {
    if (a.attention !== b.attention) return a.attention ? -1 : 1;
    if (a.status !== b.status) {
      if (a.status === "ok") return -1;
      if (b.status === "ok") return 1;
    }
    const aErr = a.errorPct ?? -1;
    const bErr = b.errorPct ?? -1;
    if (aErr !== bErr) return bErr - aErr;
    const aLat = a.latencyP95Ms ?? -1;
    const bLat = b.latencyP95Ms ?? -1;
    if (aLat !== bLat) return bLat - aLat;
    return b.eventCount - a.eventCount || a.id.localeCompare(b.id);
  });

  // KPI strip (<= 4 single-metric tiles, clean units, sparkline buckets)
  const allEvents = events.map((e) => e.event);

  const authCoverageEvents = allEvents.filter(
    (e) => e.smbDialect !== undefined || e.ldapBindKind !== undefined,
  );
  const legacyInsecureAuthCount = allEvents.filter(
    (e) => e.isSmbV1 || e.ldapBindKind === "simple_cleartext",
  ).length;
  const legacyAuthSpark = buildSparklineBuckets(
    allEvents,
    earliest,
    latest,
    (e) => (e.isSmbV1 || e.ldapBindKind === "simple_cleartext" ? 1 : 0),
    "sum",
  );

  const l7ErrorSamples = allEvents.filter(
    (e) => e.protocol !== "RADIUS" && e.hasStatusSample,
  );
  const l7ErrorCount = l7ErrorSamples.filter((e) => e.isError).length;
  const l7ErrorPct =
    l7ErrorSamples.length > 0
      ? (l7ErrorCount / l7ErrorSamples.length) * 100
      : undefined;
  const l7ErrorSpark = buildSparklineBuckets(
    l7ErrorSamples,
    earliest,
    latest,
    (e) => (e.isError ? 1 : 0),
    "rate",
  );
  const anyL7ErrorFlag = rows.some(
    (r) =>
      r.attention &&
      r.protocol !== "RADIUS" &&
      r.errorPct !== undefined &&
      ((r.protocol === "SMB" && r.errorPct >= thresholds.smbErrorWarnPct) ||
        (r.protocol === "NFS" && r.errorPct >= thresholds.nfsErrorWarnPct) ||
        (r.protocol === "LDAP" && r.errorPct >= thresholds.ldapErrorWarnPct) ||
        (r.protocol === "VoIP" && r.sipErrorCount > 0)),
  );

  const radiusEvents = allEvents.filter(
    (e) => e.protocol === "RADIUS" && e.hasStatusSample,
  );
  const totalRadiusRejects = radiusEvents.filter(
    (e) => e.radiusDecision === "reject",
  ).length;
  const anyRadiusSpike = rows.some(
    (r) =>
      r.protocol === "RADIUS" &&
      r.nasRejects.some(
        (n) => n.rejectCount >= thresholds.radiusRejectWarnCount,
      ),
  );
  const radiusRejectSpark = buildSparklineBuckets(
    allEvents.filter((e) => e.protocol === "RADIUS"),
    earliest,
    latest,
    (e) => (e.radiusDecision === "reject" ? 1 : 0),
    "sum",
  );

  const voipQualitySamples = allEvents.filter(
    (e) =>
      e.mos !== undefined ||
      e.jitterMs !== undefined ||
      e.packetLossPct !== undefined,
  );
  const voipQualityAlerts = voipQualitySamples.filter((e) =>
    isVoipAlertEvent(e, thresholds),
  ).length;
  const voipSpark = buildSparklineBuckets(
    voipQualitySamples,
    earliest,
    latest,
    (e) => (isVoipAlertEvent(e, thresholds) ? 1 : 0),
    "sum",
  );

  const kpis: ProtocolKpi[] = [
    {
      id: "legacy-insecure-auth",
      label: "Legacy / Insecure Auth",
      value: authCoverageEvents.length
        ? formatCount(legacyInsecureAuthCount)
        : "Not covered",
      ...(authCoverageEvents.length
        ? { unit: legacyInsecureAuthCount === 1 ? "event" : "events" }
        : {}),
      status: !authCoverageEvents.length
        ? "not_covered"
        : legacyInsecureAuthCount > 0
          ? "attention"
          : "ok",
      ...(legacyAuthSpark.length ? { sparkline: legacyAuthSpark } : {}),
    },
    {
      id: "l7-error-rate",
      label: "L7 Error Rate",
      value:
        l7ErrorPct !== undefined ? `${l7ErrorPct.toFixed(1)}%` : "Not covered",
      status:
        l7ErrorPct === undefined
          ? "not_covered"
          : anyL7ErrorFlag
            ? "attention"
            : "ok",
      ...(l7ErrorSpark.length ? { sparkline: l7ErrorSpark } : {}),
    },
    {
      id: "radius-rejects",
      label: "RADIUS Rejects",
      value: radiusEvents.length
        ? formatCount(totalRadiusRejects)
        : "Not covered",
      ...(radiusEvents.length
        ? { unit: totalRadiusRejects === 1 ? "reject" : "rejects" }
        : {}),
      status: !radiusEvents.length
        ? "not_covered"
        : anyRadiusSpike
          ? "attention"
          : "ok",
      ...(radiusRejectSpark.length ? { sparkline: radiusRejectSpark } : {}),
    },
    {
      id: "voip-quality-alerts",
      label: "VoIP Quality Alerts",
      value: voipQualitySamples.length
        ? formatCount(voipQualityAlerts)
        : "Not covered",
      ...(voipQualitySamples.length
        ? { unit: voipQualityAlerts === 1 ? "alert" : "alerts" }
        : {}),
      status: !voipQualitySamples.length
        ? "not_covered"
        : voipQualityAlerts > 0
          ? "attention"
          : "ok",
      ...(voipSpark.length ? { sparkline: voipSpark } : {}),
    },
  ];

  // Protocol × Server HeatMatrix (rows sorted flagged-first, uncollected protocols marked not_covered)
  const configuredSet = new Set<EnterpriseL7Protocol>(configuredProtocols);
  const observedProtocols = new Set<EnterpriseL7Protocol>(
    rows.map((r) => r.protocol),
  );
  const flaggedProtocols = new Set<EnterpriseL7Protocol>(
    rows.filter((r) => r.attention).map((r) => r.protocol),
  );
  const allMatrixProtocols = [
    ...new Set<EnterpriseL7Protocol>([
      ...ENTERPRISE_L7_PROTOCOL_ORDER,
      ...observedProtocols,
    ]),
  ];
  const matrixRows = [...allMatrixProtocols].sort((a, b) => {
    const aFlag = flaggedProtocols.has(a);
    const bFlag = flaggedProtocols.has(b);
    if (aFlag !== bFlag) return aFlag ? -1 : 1;
    const aObs = observedProtocols.has(a);
    const bObs = observedProtocols.has(b);
    if (aObs !== bObs) return aObs ? -1 : 1;
    const aConf = configuredSet.has(a);
    const bConf = configuredSet.has(b);
    if (aConf !== bConf) return aConf ? -1 : 1;
    return (
      ENTERPRISE_L7_PROTOCOL_ORDER.indexOf(a) -
      ENTERPRISE_L7_PROTOCOL_ORDER.indexOf(b)
    );
  });

  const serverAttentionSet = new Set<string>(
    rows.filter((r) => r.attention).map((r) => r.server),
  );
  const matrixCols = [...new Set(rows.map((r) => r.server))].sort((a, b) => {
    const aFlag = serverAttentionSet.has(a);
    const bFlag = serverAttentionSet.has(b);
    if (aFlag !== bFlag) return aFlag ? -1 : 1;
    return a.localeCompare(b);
  });

  const matrixCells: ProtocolMatrixCell[] = rows.map((row) => ({
    row: row.protocol,
    col: row.server,
    status: row.status,
    value: buildMatrixCellLabel(row, thresholds),
    count: row.eventCount,
    detail: row.reasons.length
      ? row.reasons.join("; ")
      : `${row.protocol} on ${row.server} within bounds`,
    itemId: row.id,
  }));

  // Emit explicit `not_covered` cells for protocols not configured/collected in this scope.
  for (const proto of matrixRows) {
    if (configuredSet.has(proto) || observedProtocols.has(proto)) continue;
    for (const server of matrixCols) {
      matrixCells.push({
        row: proto,
        col: server,
        status: "not_covered",
        value: "Not covered",
        detail: `${proto} stream is not configured for this scope.`,
      });
    }
  }

  // DistributionBar: L7 response latency (p50/p95 ms) across observed services
  const distribution: ProtocolDistributionMetric[] = rows
    .filter((r) => r.latencyP50Ms !== undefined && r.latencyP95Ms !== undefined)
    .map((r) => {
      const p50 = roundMetric(r.latencyP50Ms!);
      const p95 = roundMetric(r.latencyP95Ms!);
      const latencyAttention =
        r.protocol === "NFS" && p95 >= thresholds.nfsLatencyWarnMs;
      return {
        id: r.id,
        label: `${r.protocol} ${r.server}`,
        p50,
        p95,
        unit: "ms",
        status: (latencyAttention ? "attention" : "ok") as ProtocolStatus,
      };
    })
    .sort((a, b) => b.p95 - a.p95)
    .slice(0, 6);

  // Plain-language verdict above the fold
  const flaggedRows = rows.filter((r) => r.attention);
  let verdict: string;
  let verdictStatus: ProtocolStatus;

  if (flaggedRows.length > 0) {
    const lead = flaggedRows[0];
    verdict = `${flaggedRows.length} of ${rows.length} ${rows.length === 1 ? "service needs" : "services need"} attention: ${lead.protocol} ${lead.server} (${lead.reasons[0]}).`;
    verdictStatus = "attention";
  } else if (rows.every((r) => r.status === "not_covered")) {
    verdict = `${rows.length} Enterprise L7 ${rows.length === 1 ? "service" : "services"} observed, but health posture fields were not covered.`;
    verdictStatus = "not_covered";
  } else {
    verdict = `${rows.length} of ${rows.length} Enterprise L7 ${rows.length === 1 ? "service" : "services"} within auth, error, and VoIP quality bounds.`;
    verdictStatus = "ok";
  }

  const coverageStatus: ProtocolStatus = anyPartial
    ? "attention"
    : verdictStatus === "not_covered"
      ? "not_covered"
      : "ok";
  const activeCount = outcomes.filter(
    (o) => o.state === "complete" || o.state === "partial",
  ).length;
  const coverageLabel = `${activeCount} ${activeCount === 1 ? "source" : "sources"}`;

  const blockedDetail = outcomes.find((o) => o.state === "blocked")?.detail;
  const unavailableDetail = outcomes.find(
    (o) => o.state === "unavailable",
  )?.detail;
  const partialReason = anyBlocked
    ? `One or more sources denied access (${blockedDetail ?? "access denied"}); results are incomplete.`
    : anyUnavailable
      ? `One or more sources failed (${unavailableDetail ?? "search unavailable"}); results are incomplete.`
      : "Search hit row cap or partial source — narrow the UTC window or filter.";

  return {
    verdict,
    verdictStatus,
    coverageStatus,
    coverageLabel,
    kpis,
    rows,
    matrixRows,
    matrixCols,
    matrixCells,
    distribution,
    outcomes,
    capped,
    configuredProtocols,
    streamReadiness,
    ...(anyPartial
      ? {
          bannerState: "partial" as const,
          bannerReason: partialReason,
        }
      : {}),
    checkedAt: nowSec,
  };
}

export interface InvestigateEnterpriseL7Options {
  skipEstimateCheck?: boolean;
  skipConfigRecheck?: boolean;
  profileValidators?: Partial<Record<ProtocolLensId, LensProfileValidator>>;
}

/**
 * Executes an on-demand Enterprise L7 investigation across configured
 * `enterprise_l7` profiles (`stream:smb`, `stream:nfs`, `stream:ldap`,
 * `stream:radius`, `stream:sip`, `stream:rtp`, `stream:rtcp`).
 */
export async function investigateEnterpriseL7(
  client: SearchClient,
  request: ProtocolRequest,
  configuration: ProtocolConfiguration,
  signal: AbortSignal,
  options: InvestigateEnterpriseL7Options = {},
): Promise<EnterpriseL7InvestigationResult> {
  const scoped = configuration.profiles.filter(
    (p) => p.lens === "enterprise_l7" && p.scope === request.scope,
  );
  if (!scoped.length) {
    return {
      verdict: "No active source profile covers this scope.",
      verdictStatus: "not_covered",
      coverageStatus: "not_covered",
      coverageLabel: "Not covered",
      kpis: [],
      rows: [],
      matrixRows: [],
      matrixCols: [],
      matrixCells: [],
      distribution: [],
      outcomes: [],
      capped: false,
      configuredProtocols: [],
      bannerState: "unavailable",
      bannerReason: `No enterprise_l7 profile configured for scope "${request.scope}".`,
      checkedAt: Math.floor(Date.now() / 1000),
    };
  }

  const runProfiles = async () => {
    const outcomes: ProtocolSourceOutcome[] = [];
    const collected: {
      event: NormalizedEnterpriseL7Event;
      indexName: string;
    }[] = [];
    let capped = false;
    const configuredSourcetypes = new Set<EnterpriseL7Sourcetype>();
    const chosenThresholds = resolveEnterpriseL7Thresholds(scoped[0]);

    for (const profile of scoped) {
      signal.throwIfAborted();
      const profileThresholds = resolveEnterpriseL7Thresholds(profile);
      for (const st of profileThresholds.sourcetypes) {
        configuredSourcetypes.add(st);
      }
      const spl = buildEnterpriseL7Search({
        index: profile.index,
        sourcetypes: profileThresholds.sourcetypes,
        filter: request.filter,
        maxRows: 256,
      });
      const res = await runBoundedProtocolSearch(client, {
        lens: "enterprise_l7",
        profile,
        spl,
        earliest: request.earliest,
        latest: request.latest,
        signal,
      });
      outcomes.push(res.outcome);
      if (res.capped) capped = true;
      for (const row of res.rows) {
        const norm = normalizeEnterpriseL7Row(row);
        if (!norm) continue;
        if (!matchesFlowEndpoints(request.filter, norm.srcIp, norm.server)) {
          continue;
        }
        collected.push({ event: norm, indexName: profile.index });
      }
    }

    const configuredProtocols = [
      ...new Set(
        [...configuredSourcetypes].map((st) => protocolForSourcetype(st)),
      ),
    ];

    // Explicit Stream Estimate-mode check ONLY when configured streams completed with 0 rows.
    let streamReadiness: StreamReadinessEntry[] | undefined;
    const completedEmpty =
      collected.length === 0 &&
      !capped &&
      outcomes.some((o) => o.state === "complete");
    if (completedEmpty && !options.skipEstimateCheck) {
      const streamIds = [...configuredSourcetypes].map((st) =>
        streamIdForSourcetype(st),
      );
      const idsToCheck =
        streamIds.length === ENTERPRISE_L7_STREAM_IDS.length
          ? ENTERPRISE_L7_STREAM_IDS
          : [...new Set(streamIds)];
      streamReadiness = await checkStreamEstimateMode(
        client,
        idsToCheck,
        signal,
      );
      for (const entry of streamReadiness) {
        if (entry.state === "estimate_only") {
          outcomes.push({
            source: "protocol_stream_readiness",
            state: "estimate_only",
            detail: `${entry.streamId}: ${entry.detail}`,
          });
        }
      }
    }

    return buildEnterpriseL7Analysis({
      events: collected,
      thresholds: chosenThresholds,
      configuredProtocols,
      earliest: request.earliest,
      latest: request.latest,
      outcomes,
      capped,
      streamReadiness,
    });
  };

  if (options.skipConfigRecheck || !configuration.fingerprint) {
    return runProfiles();
  }

  const validators: Partial<Record<ProtocolLensId, LensProfileValidator>> = {
    ...options.profileValidators,
    enterprise_l7: validateEnterpriseL7Extra,
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
        kpis: [],
        rows: [],
        matrixRows: [],
        matrixCols: [],
        matrixCells: [],
        distribution: [],
        outcomes: [],
        capped: false,
        configuredProtocols: [],
        bannerState: "stale_config",
        bannerReason: error.message,
        checkedAt: Math.floor(Date.now() / 1000),
      };
    }
    throw error;
  }
}

/**
 * Explicit single-row Detail Drawer drilldown for `ROW_EXPANSION_ONLY_FIELDS`
 * (`user_id` on SMB, `calling_station_id` on RADIUS). Never called on mount,
 * Overview, or Matrix.
 */
export async function fetchEnterpriseL7RowExpansion(
  client: SearchClient,
  options: {
    profile: BaseProtocolProfile;
    protocol: "SMB" | "RADIUS";
    server: string;
    earliest: number;
    latest: number;
    signal: AbortSignal;
  },
): Promise<EnterpriseL7RowExpansionResult> {
  const fieldName =
    options.protocol === "SMB" ? "user_id" : "calling_station_id";
  const spl = buildEnterpriseL7RowExpansionSearch({
    index: options.profile.index,
    protocol: options.protocol,
    server: options.server,
    maxRows: 32,
  });
  const res = await runBoundedProtocolSearch(client, {
    lens: "enterprise_l7",
    profile: options.profile,
    spl,
    earliest: options.earliest,
    latest: options.latest,
    maxRows: 32,
    includeRowExpansion: true,
    signal: options.signal,
    keySuffix: `rowexp:${options.protocol}:${options.server}`,
  });
  const values = [
    ...new Set(
      res.rows.map((r) => asString(r[fieldName])).filter((v) => v.length > 0),
    ),
  ].slice(0, 16);
  return {
    fieldName,
    values,
    capped: res.capped,
    outcome: res.outcome,
  };
}

/**
 * Hub "Check all" summary runner for `enterprise_l7`.
 * Downgrades degraded/capped summaries: `ok` -> `attention`, `none_observed` -> `unknown`.
 */
export async function summarizeEnterpriseL7(
  client: SearchClient,
  request: ProtocolRequest,
  configuration: ProtocolConfiguration,
  signal: AbortSignal,
  options?: InvestigateEnterpriseL7Options,
): Promise<ProtocolLensSummary> {
  const result = await investigateEnterpriseL7(
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
    lens: "enterprise_l7",
    status,
    verdict: result.verdict,
    checkedAt: result.checkedAt,
    capped: result.capped,
    outcomes: result.outcomes,
  };
}
