import { literal } from "../../../data/evidence";
import type { SearchClient } from "../../../data/searchClient";
import {
  MAX_INPUT_ROWS,
  type BaseProtocolProfile,
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
import { formatCount, formatDurationMs } from "../../shared/format";
import {
  ProtocolConfigurationChangedError,
  runBoundedProtocolSearch,
  selectActiveProfiles,
  withProtocolConfigRecheck,
  type ProtocolRow,
} from "../../shared/runner";
import {
  DEFAULT_LB_HEALTH_THRESHOLDS,
  validateLbHealthExtra,
  type LbHealthExtraConfig,
  type LbHealthSourceKind,
  type ResolvedLbHealthThresholds,
} from "./validate";

export {
  DEFAULT_LB_HEALTH_THRESHOLDS,
  validateLbHealthExtra,
  type LbHealthExtraConfig,
  type LbHealthSourceKind,
  type ResolvedLbHealthThresholds,
};

/**
 * Sourcetypes and error semantics mirror `frontend/src/ecosystem/loadBalancerEvidence.ts`
 * (`F5_LTM_HTTP` and `AWS_ELB_ACCESS`) without importing it at runtime so the
 * per-lens IIFE bundle stays compact.
 */
export const F5_LTM_SOURCETYPES = [
  "f5:bigip:ltm:http:irule",
  "f5:bigip:ltm:lb:failed:irule",
  "f5:bigip:ltm:failed:irule",
] as const;

export const AWS_ALB_SOURCETYPES = [
  "aws:elb:accesslogs",
  "aws:alb:accesslogs",
] as const;

export const AWS_NLB_SOURCETYPES = [
  "aws:elb:accesslogs",
  "aws:nlb:accesslogs",
] as const;

export const AWS_ELB_ALL_SOURCETYPES = [
  "aws:elb:accesslogs",
  "aws:alb:accesslogs",
  "aws:nlb:accesslogs",
] as const;

export type LbHealthSourcetype =
  | (typeof F5_LTM_SOURCETYPES)[number]
  | (typeof AWS_ALB_SOURCETYPES)[number]
  | (typeof AWS_NLB_SOURCETYPES)[number];

export type LbHealthFamily = "f5_ltm" | "aws_alb" | "aws_nlb";
export type LbHealthSearchTarget = "f5_ltm" | "aws_alb" | "aws_nlb" | "aws_elb";

export const F5_LTM_PROJECTED_FIELDS = [
  "_time",
  "host",
  "sourcetype",
  "f5_irule",
  "vip",
  "virtual_server",
  "pool",
  "pool_name",
  "member_ip",
  "member_port",
  "node",
  "node_port",
  "src_ip",
  "dest_ip",
  "http_method",
  "http_status",
  "status",
  "req_elapsed_time",
  "time_taken",
  "response_time",
  "bytes_in",
  "bytes_out",
] as const;

export const AWS_ALB_PROJECTED_FIELDS = [
  "_time",
  "host",
  "sourcetype",
  "elb",
  "vip",
  "target_group",
  "pool",
  "target_ip",
  "target_port",
  "member_ip",
  "member_port",
  "src_ip",
  "dest_ip",
  "elb_status_code",
  "target_status_code",
  "error_reason",
  "actions_executed",
  "request_processing_time",
  "target_processing_time",
  "response_processing_time",
  "bytes_in",
  "bytes_out",
  "ssl_protocol",
  "tls_version",
] as const;

export const AWS_NLB_PROJECTED_FIELDS = [
  "_time",
  "host",
  "sourcetype",
  "elb",
  "listener",
  "src_ip",
  "dest_ip",
  "target_ip",
  "target_port",
  "connection_time_ms",
  "handshake_time_ms",
  "bytes_in",
  "bytes_out",
  "ssl_protocol",
  "tls_version",
  "tls_alert",
  "verify_status",
] as const;

export const AWS_ELB_COMBINED_PROJECTED_FIELDS = [
  ...new Set([...AWS_ALB_PROJECTED_FIELDS, ...AWS_NLB_PROJECTED_FIELDS]),
] as const;

export function resolveLbHealthThresholds(
  profile?: BaseProtocolProfile,
): ResolvedLbHealthThresholds {
  const extra = profile?.extra as LbHealthExtraConfig | undefined;
  return {
    sourceKind:
      extra?.sourceKind === "f5_ltm" ||
      extra?.sourceKind === "aws_alb" ||
      extra?.sourceKind === "aws_nlb" ||
      extra?.sourceKind === "auto"
        ? extra.sourceKind
        : DEFAULT_LB_HEALTH_THRESHOLDS.sourceKind,
    errorRateWarnPct:
      typeof extra?.errorRateWarnPct === "number" &&
      Number.isFinite(extra.errorRateWarnPct)
        ? extra.errorRateWarnPct
        : DEFAULT_LB_HEALTH_THRESHOLDS.errorRateWarnPct,
    latencyWarnMs:
      typeof extra?.latencyWarnMs === "number" &&
      Number.isFinite(extra.latencyWarnMs)
        ? extra.latencyWarnMs
        : DEFAULT_LB_HEALTH_THRESHOLDS.latencyWarnMs,
    lbFailedWarnCount:
      typeof extra?.lbFailedWarnCount === "number" &&
      Number.isInteger(extra.lbFailedWarnCount)
        ? extra.lbFailedWarnCount
        : DEFAULT_LB_HEALTH_THRESHOLDS.lbFailedWarnCount,
  };
}

/**
 * Anchored regex for Splunk-iRule-HTTP / Splunk-iRule-LB_FAILED HSL messages.
 * Uses Splunk's default rex target field without naming forbidden fields so
 * unquoted `http_uri` / `http_url` delimiter injection cannot forge `node` or
 * `http_status` values.
 */
const F5_SAFE_REX_PATTERN =
  '^(?:<\\d{1,3}>)?(?:[^,"]{0,128},)?' +
  "f5_irule=(?<f5_rx_irule>Splunk-iRule-(?:HTTP|LB_FAILED))" +
  ",src_ip=(?<f5_rx_src_ip>[0-9A-Fa-f:.]{2,45})(?:%\\d{1,5})?" +
  ",vip=(?<f5_rx_vip>[0-9A-Fa-f:.]{2,45})(?:%\\d{1,5})?" +
  ",http_method=(?<f5_rx_method>[A-Z]{0,16})" +
  ',http_host=[^,"]{0,300}?:\\d{1,5}' +
  ',http_uri=[^,"]{0,8192},http_url=[^,"]{0,8192}' +
  ",http_version=[0-9.]{0,8}" +
  ',http_user_agent="[^"]{0,8192}",http_content_type=[^,"]{0,256},http_referrer="[^"]{0,8192}"' +
  ",req_start_time=[0-9/: ]{19}" +
  ',[^,"]{1,32}="[^"]{0,8192}",[^,"]{1,32}=[^,"]{0,256}' +
  ',virtual_server="(?<f5_rx_pool>[^" ]{0,255})(?: [^"]{0,128})?"' +
  ",bytes_in=(?<f5_rx_bytes_in>\\d{0,19})" +
  "(?:,res_start_time=[0-9/: ]{19}" +
  ",node=(?<f5_rx_node>[0-9A-Fa-f:.]{2,45})(?:%\\d{1,5})?" +
  ",node_port=(?<f5_rx_node_port>\\d{1,5}),http_status=(?<f5_rx_status>\\d{3})" +
  ",req_elapsed_time=(?<f5_rx_elapsed_ms>\\d{1,19}),bytes_out=(?<f5_rx_bytes_out>\\d{0,19}))?" +
  "\\s*$";

/**
 * Builds a bounded, allowlisted SPL query for F5 BIG-IP LTM iRule HSL or AWS ALB/NLB access logs.
 * Always emits `| head <maxRows + 1>` BEFORE `buildAllowedFieldsClause("lb_health", ...)`
 * and never appends a post-`| head` `| where` filter that would mask row capping.
 */
export function buildLbHealthSearch(options: {
  index: string;
  target: LbHealthSearchTarget;
  filter?: ProtocolFilter;
  maxRows: number;
}): string {
  const index = literal(options.index, 80);
  const headLimit = Math.max(1, Math.trunc(options.maxRows)) + 1;

  if (options.target === "f5_ltm") {
    const predicates: string[] = [
      `index=${index}`,
      `(${F5_LTM_SOURCETYPES.map((st) => `sourcetype="${st}"`).join(" OR ")})`,
    ];
    predicates.push(
      ...buildFlowEndpointPredicates({
        filter: options.filter,
        srcFields: ["src_ip"],
        dstFields: ["vip", "dest_ip", "node", "member_ip"],
        portFields: ["node_port", "dest_port", "src_port"],
      }),
    );
    if (options.filter?.device) {
      const dev = literal(options.filter.device, 128);
      predicates.push(
        `(host="${dev}" OR vip="${dev}" OR virtual_server="${dev}" OR pool="${dev}" OR pool_name="${dev}" OR node="${dev}" OR member_ip="${dev}")`,
      );
    }
    const rexClause = `| rex "${F5_SAFE_REX_PATTERN.replace(/"/g, '\\"')}"`;
    const evalClause =
      "| eval f5_irule=coalesce(f5_rx_irule,f5_irule)," +
      " src_ip=coalesce(f5_rx_src_ip,src_ip)," +
      " vip=coalesce(f5_rx_vip,vip)," +
      " http_method=coalesce(f5_rx_method,http_method)," +
      " pool=coalesce(f5_rx_pool,pool)," +
      " bytes_in=coalesce(f5_rx_bytes_in,bytes_in)," +
      ' node=if(isnotnull(f5_rx_irule),if(f5_rx_irule="Splunk-iRule-LB_FAILED",null(),f5_rx_node),node),' +
      ' node_port=if(isnotnull(f5_rx_irule),if(f5_rx_irule="Splunk-iRule-LB_FAILED",null(),f5_rx_node_port),node_port),' +
      ' http_status=if(isnotnull(f5_rx_irule),if(f5_rx_irule="Splunk-iRule-LB_FAILED",null(),f5_rx_status),http_status),' +
      ' req_elapsed_time=if(isnotnull(f5_rx_irule),if(f5_rx_irule="Splunk-iRule-LB_FAILED",null(),f5_rx_elapsed_ms),req_elapsed_time),' +
      ' bytes_out=if(isnotnull(f5_rx_irule),if(f5_rx_irule="Splunk-iRule-LB_FAILED",null(),f5_rx_bytes_out),bytes_out)';
    const tableClause = buildAllowedFieldsClause(
      "lb_health",
      F5_LTM_PROJECTED_FIELDS,
    );
    return `search ${predicates.join(" ")} ${rexClause} ${evalClause} | head ${headLimit} ${tableClause}`;
  }

  const sourcetypes =
    options.target === "aws_alb"
      ? AWS_ALB_SOURCETYPES
      : options.target === "aws_nlb"
        ? AWS_NLB_SOURCETYPES
        : AWS_ELB_ALL_SOURCETYPES;
  const projectedFields =
    options.target === "aws_alb"
      ? AWS_ALB_PROJECTED_FIELDS
      : options.target === "aws_nlb"
        ? AWS_NLB_PROJECTED_FIELDS
        : AWS_ELB_COMBINED_PROJECTED_FIELDS;

  const predicates: string[] = [
    `index=${index}`,
    `(${sourcetypes.map((st) => `sourcetype="${st}"`).join(" OR ")})`,
  ];
  const dstFields =
    options.target === "aws_nlb"
      ? ["dest_ip", "target_ip", "elb", "listener"]
      : options.target === "aws_alb"
        ? ["dest_ip", "vip", "target_ip", "member_ip", "elb"]
        : ["dest_ip", "vip", "target_ip", "member_ip", "elb", "listener"];
  predicates.push(
    ...buildFlowEndpointPredicates({
      filter: options.filter,
      srcFields: ["src_ip"],
      dstFields,
      portFields: ["dest_port", "src_port", "target_port", "listener_port"],
    }),
  );
  if (options.filter?.device) {
    const dev = literal(options.filter.device, 128);
    predicates.push(
      `(host="${dev}" OR elb="${dev}" OR target_group="${dev}" OR listener="${dev}" OR vip="${dev}" OR target_ip="${dev}" OR member_ip="${dev}")`,
    );
  }
  const tableClause = buildAllowedFieldsClause("lb_health", projectedFields);
  return `search ${predicates.join(" ")} | head ${headLimit} ${tableClause}`;
}

/**
 * Builds a `literal()`-quoted Splunk Search URL for raw events of a selected VIP/member row.
 */
export function buildLbHealthRawEventsUrl(options: {
  index: string;
  sourcetypes: readonly LbHealthSourcetype[];
  vip: string;
  memberIp?: string;
  earliest: number;
  latest: number;
}): string {
  const index = literal(options.index, 80);
  const sts = options.sourcetypes.length
    ? options.sourcetypes
    : [...F5_LTM_SOURCETYPES, ...AWS_ELB_ALL_SOURCETYPES];
  const stClause =
    sts.length === 1
      ? `sourcetype="${literal(sts[0], 80)}"`
      : `(${sts.map((s) => `sourcetype="${literal(s, 80)}"`).join(" OR ")})`;

  const selectorClauses: string[] = [];
  if (options.vip && /^[A-Za-z0-9][A-Za-z0-9._:/@-]*$/.test(options.vip)) {
    const safeVip = literal(options.vip, 128);
    selectorClauses.push(
      `(vip="${safeVip}" OR elb="${safeVip}" OR dest_ip="${safeVip}")`,
    );
  }
  if (
    options.memberIp &&
    /^[A-Za-z0-9][A-Za-z0-9._:/@-]*$/.test(options.memberIp)
  ) {
    const safeMember = literal(options.memberIp, 128);
    selectorClauses.push(
      `(node="${safeMember}" OR member_ip="${safeMember}" OR target_ip="${safeMember}")`,
    );
  }

  const q = [`search index=${index}`, stClause, ...selectorClauses].join(" ");
  const params = new URLSearchParams({
    q,
    earliest: String(Math.trunc(options.earliest)),
    latest: String(Math.trunc(options.latest)),
  });
  return `/app/splunk_adm/search?${params.toString()}`;
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

function isAbsentToken(value: string): boolean {
  return (
    !value || value === "-" || /^none$/i.test(value) || /^null$/i.test(value)
  );
}

export function isIpLiteral(value: string): boolean {
  const trimmed = value.trim();
  if (!trimmed) return false;
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(trimmed)) return true;
  if (/^[0-9A-Fa-f:]+$/.test(trimmed) && trimmed.includes(":")) return true;
  return false;
}

/**
 * Strips F5 route domain suffixes (`%<id>`) and normalizes RFC 4291 IPv4-mapped
 * IPv6 literals to dotted IPv4.
 */
export function normalizeLbIp(raw: string): string {
  const trimmed = raw.trim().replace(/^\[|\]$/g, "");
  const withoutRd = trimmed.replace(/%\d{1,5}$/, "");
  const mapped = /^(?:0{1,4}:){5}ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i.exec(
    withoutRd,
  );
  if (!mapped) return withoutRd;
  const hi = parseInt(mapped[1], 16);
  const lo = parseInt(mapped[2], 16);
  return `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
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

export function shortenBalancerLabel(vip: string): string {
  const trimmed = vip.trim();
  if (!trimmed) return "unknown";
  if (isIpLiteral(trimmed)) return trimmed;
  const elbMatch = /^(app|net)\/([^/]+)\/[a-f0-9]+$/i.exec(trimmed);
  if (elbMatch) {
    return `${elbMatch[1]}/${elbMatch[2]}`;
  }
  return shortenDeviceLabel(trimmed);
}

export function shortenPoolLabel(pool: string): string {
  const trimmed = pool.trim();
  if (!trimmed) return "default";
  const tgMatch = /targetgroup\/([^/]+)\/[a-f0-9]+$/i.exec(trimmed);
  if (tgMatch) return tgMatch[1];
  return trimmed;
}

function extractF5Pool(row: ProtocolRow): string {
  const explicit = asString(row.pool ?? row.pool_name);
  if (!isAbsentToken(explicit)) return explicit;
  const vs = asString(row.virtual_server);
  if (!isAbsentToken(vs)) {
    return vs.split(/\s+/)[0] || vs;
  }
  return "default-pool";
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
export function makeLbHealthRowId(
  family: LbHealthFamily,
  vip: string,
  pool: string,
  memberKey: string,
): string {
  const full = `${sanitizeIdPart(family)}__${sanitizeIdPart(vip)}__${sanitizeIdPart(pool)}__${sanitizeIdPart(memberKey)}`;
  if (full.length <= 128) return full;
  const suffix = `__${shortFnvHash(full)}`;
  const budget = 128 - suffix.length;
  return `${full.slice(0, budget)}${suffix}`;
}

export type LbErrorSide = "none" | "balancer" | "target";

export interface NormalizedLbHealthEvent {
  family: LbHealthFamily;
  sourcetype: LbHealthSourcetype;
  timestamp: number | undefined;
  host: string;
  vip: string;
  vipIp?: string;
  pool: string;
  memberIp?: string;
  memberPort?: number;
  srcIp?: string;
  httpMethod?: string;
  balancerStatusCode?: number;
  targetStatusCode?: number;
  errorSide: LbErrorSide;
  isLbFailed: boolean;
  isNlbTlsFailure: boolean;
  failureCategory?: string;
  errorReason?: string;
  actionsExecuted?: string;
  latencyMs?: number;
  connectionTimeMs?: number;
  handshakeTimeMs?: number;
  bytesIn: number;
  bytesOut: number;
  tlsProtocol?: string;
  tlsAlert?: string;
  verifyStatus?: string;
}

function parsePort(value: unknown): number | undefined {
  const n = asFiniteNumber(value);
  if (n === undefined || !Number.isInteger(n) || n < 0 || n > 65535) {
    return undefined;
  }
  return n;
}

function parseHttpStatus(value: unknown): number | undefined {
  const s = asString(value);
  if (isAbsentToken(s)) return undefined;
  const n = asFiniteNumber(s);
  if (n === undefined || !Number.isInteger(n) || n < 100 || n > 599) {
    return undefined;
  }
  return n;
}

function formatTlsSummary(
  tlsVersion: string,
  sslProtocol: string,
): string | undefined {
  const ver = isAbsentToken(tlsVersion) ? "" : tlsVersion;
  const cipher = isAbsentToken(sslProtocol) ? "" : sslProtocol;
  if (ver && cipher) return `${ver} · ${cipher}`;
  return ver || cipher || undefined;
}

const F5_CRITICAL_FIELDS = [
  "f5_irule",
  "vip",
  "virtual_server",
  "pool",
  "pool_name",
  "node",
  "member_ip",
  "node_port",
  "member_port",
  "http_status",
  "status",
  "req_elapsed_time",
] as const;

const EMBEDDED_KV_DELIMITER_RE = /,[a-zA-Z_][a-zA-Z0-9_]*=/;

function hasF5InjectionOrMultivalue(row: ProtocolRow): boolean {
  for (const field of F5_CRITICAL_FIELDS) {
    const val = row[field];
    if (Array.isArray(val)) return true;
    if (typeof val === "string" && EMBEDDED_KV_DELIMITER_RE.test(val)) {
      return true;
    }
  }
  return false;
}

/**
 * Normalizes a single allowlist-projected F5 LTM iRule, AWS ALB, or AWS NLB row.
 */
export function normalizeLbHealthRow(
  row: ProtocolRow,
  defaultFamily?: LbHealthFamily,
): NormalizedLbHealthEvent | undefined {
  const stRaw = asString(row.sourcetype).toLowerCase();
  const f5Irule = asString(row.f5_irule);
  const elb = asString(row.elb);

  let family: LbHealthFamily | undefined;
  if (
    stRaw.startsWith("f5:bigip:ltm:") ||
    f5Irule.startsWith("Splunk-iRule-") ||
    Array.isArray(row.f5_irule)
  ) {
    family = "f5_ltm";
  } else if (
    stRaw === "aws:nlb:accesslogs" ||
    elb.startsWith("net/") ||
    (!isAbsentToken(asString(row.listener)) &&
      isAbsentToken(asString(row.elb_status_code)) &&
      isAbsentToken(asString(row.target_group))) ||
    !isAbsentToken(asString(row.verify_status)) ||
    !isAbsentToken(asString(row.tls_alert)) ||
    asFiniteNumber(row.handshake_time_ms) !== undefined ||
    asFiniteNumber(row.connection_time_ms) !== undefined
  ) {
    family = "aws_nlb";
  } else if (
    stRaw === "aws:alb:accesslogs" ||
    elb.startsWith("app/") ||
    !isAbsentToken(asString(row.target_group)) ||
    asFiniteNumber(row.elb_status_code) !== undefined ||
    asFiniteNumber(row.target_status_code) !== undefined ||
    asFiniteNumber(row.request_processing_time) !== undefined
  ) {
    family = "aws_alb";
  } else if (stRaw !== "aws:elb:accesslogs") {
    family = defaultFamily;
  }

  if (!family) return undefined;

  const timestamp = asEpochSeconds(row._time);
  const host = asString(row.host) || "unknown";
  const rawSrc = asString(row.src_ip);
  const srcIp = !isAbsentToken(rawSrc) ? normalizeLbIp(rawSrc) : undefined;
  const bytesIn = Math.max(0, asFiniteNumber(row.bytes_in) ?? 0);
  const bytesOut = Math.max(0, asFiniteNumber(row.bytes_out) ?? 0);

  if (family === "f5_ltm") {
    if (hasF5InjectionOrMultivalue(row)) {
      return undefined;
    }

    const isFailedSourcetype =
      stRaw === "f5:bigip:ltm:lb:failed:irule" ||
      stRaw === "f5:bigip:ltm:failed:irule" ||
      stRaw.endsWith("failed:irule");
    const isLbFailed =
      f5Irule === "Splunk-iRule-LB_FAILED" || isFailedSourcetype;

    const sourcetype: LbHealthSourcetype =
      stRaw === "f5:bigip:ltm:lb:failed:irule"
        ? "f5:bigip:ltm:lb:failed:irule"
        : stRaw === "f5:bigip:ltm:failed:irule"
          ? "f5:bigip:ltm:failed:irule"
          : isLbFailed
            ? "f5:bigip:ltm:lb:failed:irule"
            : "f5:bigip:ltm:http:irule";

    const rawVip = asString(row.vip ?? row.dest_ip);
    const vip = !isAbsentToken(rawVip)
      ? normalizeLbIp(rawVip)
      : shortenDeviceLabel(host);
    const vipIp = isIpLiteral(vip) ? vip : undefined;
    const pool = extractF5Pool(row);

    // Authentic LB_FAILED events have no backend response leg; never trust
    // auto-extracted node/member_ip/http_status/latency on LB_FAILED rows.
    const rawMember = isLbFailed ? "" : asString(row.node ?? row.member_ip);
    const memberIp = !isAbsentToken(rawMember)
      ? normalizeLbIp(rawMember)
      : undefined;
    const memberPort = isLbFailed
      ? undefined
      : parsePort(row.node_port ?? row.member_port);

    const httpMethod = asString(row.http_method) || undefined;
    const statusCode = isLbFailed
      ? undefined
      : parseHttpStatus(row.http_status ?? row.status);
    const rawLatency = isLbFailed
      ? undefined
      : asFiniteNumber(
          row.req_elapsed_time ?? row.response_time ?? row.time_taken,
        );
    const latencyMs =
      rawLatency !== undefined && rawLatency >= 0 ? rawLatency : undefined;
    const f5BytesOut = isLbFailed ? 0 : bytesOut;

    let errorSide: LbErrorSide = "none";
    let failureCategory: string | undefined;
    if (isLbFailed) {
      errorSide = "balancer";
      failureCategory = "LB_FAILED";
    } else if (statusCode !== undefined && statusCode >= 500) {
      if (memberIp) {
        errorSide = "target";
        failureCategory = `Target HTTP ${statusCode}`;
      } else {
        errorSide = "balancer";
        failureCategory = `Balancer HTTP ${statusCode}`;
      }
    }

    return {
      family: "f5_ltm",
      sourcetype,
      timestamp,
      host,
      vip,
      ...(vipIp ? { vipIp } : {}),
      pool,
      ...(memberIp ? { memberIp } : {}),
      ...(memberPort !== undefined ? { memberPort } : {}),
      ...(srcIp ? { srcIp } : {}),
      ...(httpMethod ? { httpMethod } : {}),
      ...(errorSide === "balancer" && statusCode !== undefined
        ? { balancerStatusCode: statusCode }
        : {}),
      ...(errorSide === "target" && statusCode !== undefined
        ? { targetStatusCode: statusCode }
        : {}),
      errorSide,
      isLbFailed,
      isNlbTlsFailure: false,
      ...(failureCategory ? { failureCategory } : {}),
      ...(isLbFailed
        ? { errorReason: "LB_FAILED (pool selection or connect failed)" }
        : {}),
      ...(latencyMs !== undefined ? { latencyMs } : {}),
      bytesIn,
      bytesOut: f5BytesOut,
    };
  }

  if (family === "aws_alb") {
    const sourcetype: LbHealthSourcetype =
      stRaw === "aws:alb:accesslogs"
        ? "aws:alb:accesslogs"
        : "aws:elb:accesslogs";

    const rawDest = asString(row.vip ?? row.dest_ip);
    const destIp = !isAbsentToken(rawDest) ? normalizeLbIp(rawDest) : undefined;
    const vip = !isAbsentToken(elb)
      ? elb
      : (destIp ?? shortenDeviceLabel(host));
    const vipIp = destIp && isIpLiteral(destIp) ? destIp : undefined;

    const rawPool = asString(row.target_group ?? row.pool);
    const pool = !isAbsentToken(rawPool) ? rawPool : "default-target-group";

    const rawTarget = asString(row.target_ip ?? row.member_ip);
    const memberIp = !isAbsentToken(rawTarget)
      ? normalizeLbIp(rawTarget)
      : undefined;
    const memberPort = parsePort(row.target_port ?? row.member_port);

    const elbStatusCode = parseHttpStatus(row.elb_status_code);
    const targetStatusCode = parseHttpStatus(row.target_status_code);
    const rawErrorReason = asString(row.error_reason);
    const errorReason = !isAbsentToken(rawErrorReason)
      ? rawErrorReason
      : undefined;
    const rawActions = asString(row.actions_executed);
    const actionsExecuted = !isAbsentToken(rawActions) ? rawActions : undefined;

    const reqSec = asFiniteNumber(row.request_processing_time);
    const tgtSec = asFiniteNumber(row.target_processing_time);
    const respSec = asFiniteNumber(row.response_processing_time);
    const validSecs = [reqSec, tgtSec, respSec].filter(
      (v): v is number => v !== undefined && v >= 0,
    );
    const latencyMs =
      validSecs.length > 0
        ? validSecs.reduce((sum, s) => sum + s, 0) * 1000
        : undefined;

    // Explicit ALB balancer-vs-target error split:
    // - Balancer error: elb_status_code >= 500 when target_status_code is absent/`-`
    //   OR differs from elb_status_code with an ALB error_reason (or target < 500).
    // - Target error: target_status_code >= 500 (including backend 5xx propagated through ALB).
    const isBalancerError =
      elbStatusCode !== undefined &&
      elbStatusCode >= 500 &&
      (targetStatusCode === undefined ||
        (targetStatusCode !== elbStatusCode && Boolean(errorReason)) ||
        targetStatusCode < 500);
    const isTargetError =
      !isBalancerError &&
      targetStatusCode !== undefined &&
      targetStatusCode >= 500;

    let errorSide: LbErrorSide = "none";
    let failureCategory: string | undefined;
    if (isBalancerError) {
      errorSide = "balancer";
      failureCategory = errorReason
        ? `ALB ${elbStatusCode} (${errorReason})`
        : `ALB ${elbStatusCode}`;
    } else if (isTargetError) {
      errorSide = "target";
      failureCategory = `Target HTTP ${targetStatusCode}`;
    }

    const tlsProtocol = formatTlsSummary(
      asString(row.tls_version),
      asString(row.ssl_protocol),
    );

    return {
      family: "aws_alb",
      sourcetype,
      timestamp,
      host,
      vip,
      ...(vipIp ? { vipIp } : {}),
      pool,
      ...(memberIp ? { memberIp } : {}),
      ...(memberPort !== undefined ? { memberPort } : {}),
      ...(srcIp ? { srcIp } : {}),
      ...(elbStatusCode !== undefined
        ? { balancerStatusCode: elbStatusCode }
        : {}),
      ...(targetStatusCode !== undefined ? { targetStatusCode } : {}),
      errorSide,
      isLbFailed: false,
      isNlbTlsFailure: false,
      ...(failureCategory ? { failureCategory } : {}),
      ...(errorReason ? { errorReason } : {}),
      ...(actionsExecuted ? { actionsExecuted } : {}),
      ...(latencyMs !== undefined ? { latencyMs } : {}),
      bytesIn,
      bytesOut,
      ...(tlsProtocol ? { tlsProtocol } : {}),
    };
  }

  // aws_nlb
  const sourcetype: LbHealthSourcetype =
    stRaw === "aws:nlb:accesslogs"
      ? "aws:nlb:accesslogs"
      : "aws:elb:accesslogs";

  const rawDest = asString(row.dest_ip);
  const destIp = !isAbsentToken(rawDest) ? normalizeLbIp(rawDest) : undefined;
  const vip = !isAbsentToken(elb) ? elb : (destIp ?? shortenDeviceLabel(host));
  const vipIp = destIp && isIpLiteral(destIp) ? destIp : undefined;

  const rawListener = asString(row.listener);
  const pool = !isAbsentToken(rawListener) ? rawListener : "tls-listener";

  // NLB TLS access logs normally omit target_ip/target_port; keep optional support if enriched.
  const rawTarget = asString(row.target_ip);
  const memberIp = !isAbsentToken(rawTarget)
    ? normalizeLbIp(rawTarget)
    : undefined;
  const memberPort = parsePort(row.target_port);

  const rawConnMs = asFiniteNumber(row.connection_time_ms);
  const connectionTimeMs =
    rawConnMs !== undefined && rawConnMs >= 0 ? rawConnMs : undefined;
  const rawHandshakeMs = asFiniteNumber(row.handshake_time_ms);
  const handshakeTimeMs =
    rawHandshakeMs !== undefined && rawHandshakeMs >= 0
      ? rawHandshakeMs
      : undefined;
  // Use TLS handshake latency (not total idle session lifetime) for request latency SLA checks.
  const latencyMs = handshakeTimeMs;

  const rawTlsAlert = asString(row.tls_alert);
  const tlsAlert = !isAbsentToken(rawTlsAlert) ? rawTlsAlert : undefined;
  const rawVerify = asString(row.verify_status);
  const verifyStatus = !isAbsentToken(rawVerify) ? rawVerify : undefined;

  const hasTlsAlert = Boolean(tlsAlert);
  const hasFailedVerify = Boolean(
    verifyStatus && /^failed/i.test(verifyStatus),
  );
  const isNlbTlsFailure = hasTlsAlert || hasFailedVerify;
  const errorSide: LbErrorSide = isNlbTlsFailure ? "balancer" : "none";

  let failureCategory: string | undefined;
  if (isNlbTlsFailure) {
    const parts = [
      ...(tlsAlert ? [`alert:${tlsAlert}`] : []),
      ...(hasFailedVerify && verifyStatus ? [verifyStatus] : []),
    ];
    failureCategory = `NLB TLS failure (${parts.join(", ")})`;
  }

  const tlsProtocol = formatTlsSummary(
    asString(row.tls_version),
    asString(row.ssl_protocol),
  );

  return {
    family: "aws_nlb",
    sourcetype,
    timestamp,
    host,
    vip,
    ...(vipIp ? { vipIp } : {}),
    pool,
    ...(memberIp ? { memberIp } : {}),
    ...(memberPort !== undefined ? { memberPort } : {}),
    ...(srcIp ? { srcIp } : {}),
    errorSide,
    isLbFailed: false,
    isNlbTlsFailure,
    ...(failureCategory ? { failureCategory } : {}),
    ...(latencyMs !== undefined ? { latencyMs } : {}),
    ...(connectionTimeMs !== undefined ? { connectionTimeMs } : {}),
    ...(handshakeTimeMs !== undefined ? { handshakeTimeMs } : {}),
    bytesIn,
    bytesOut,
    ...(tlsProtocol ? { tlsProtocol } : {}),
    ...(tlsAlert ? { tlsAlert } : {}),
    ...(verifyStatus ? { verifyStatus } : {}),
  };
}

export interface LbHealthPoolMemberRow {
  /** URL-safe ID matching `^[A-Za-z0-9._:/-]{1,128}$` using `__`. */
  id: string;
  attention: boolean;
  family: LbHealthFamily;
  sourceLabel: string;
  vip: string;
  vipDisplay: string;
  vipIp?: string;
  pool: string;
  poolDisplay: string;
  memberIp?: string;
  memberPort?: number;
  memberLabel: string;
  requestCount: number;
  balancerErrorCount: number;
  targetErrorCount: number;
  healthyCount: number;
  lbFailedCount: number;
  nlbTlsFailureCount: number;
  balancerErrorPct: number;
  targetErrorPct: number;
  targetErrorsCovered: boolean;
  p50LatencyMs?: number;
  p95LatencyMs?: number;
  avgConnectionTimeMs?: number;
  bytesIn: number;
  bytesOut: number;
  errorReasons: string[];
  tlsAlerts: string[];
  verifyStatuses: string[];
  tlsProtocols: string[];
  status: ProtocolStatus;
  reasons: string[];
  findings: string[];
  indexName: string;
  sourcetypes: LbHealthSourcetype[];
  firstSeen?: number;
  lastSeen?: number;
}

export interface LbHealthInvestigationResult {
  verdict: string;
  verdictStatus: ProtocolStatus;
  coverageStatus: ProtocolStatus;
  coverageLabel: string;
  hasTargetTelemetry: boolean;
  kpis: ProtocolKpi[];
  distribution: ProtocolDistributionMetric[];
  rows: LbHealthPoolMemberRow[];
  matrixRows: string[];
  matrixCols: string[];
  matrixCells: ProtocolMatrixCell[];
  timelineEvents: ProtocolTimelineEvent[];
  timelineRowByEventId: Record<string, string>;
  outcomes: ProtocolSourceOutcome[];
  capped: boolean;
  bannerState?:
    "empty" | "partial" | "blocked" | "unavailable" | "stale_config";
  bannerReason?: string;
  checkedAt: number;
}

function percentile(
  values: readonly number[],
  pct: number,
): number | undefined {
  if (!values.length) return undefined;
  const sorted = [...values].sort((a, b) => a - b);
  const rank = Math.ceil((pct / 100) * sorted.length) - 1;
  const idx = Math.max(0, Math.min(sorted.length - 1, rank));
  return sorted[idx];
}

function roundMs(value: number): number {
  return value < 10 ? Math.round(value * 10) / 10 : Math.round(value);
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

function familyLabel(family: LbHealthFamily): string {
  if (family === "f5_ltm") return "F5 BIG-IP LTM iRule";
  if (family === "aws_alb") return "AWS ALB Access Logs";
  return "AWS NLB TLS Access Logs";
}

function formatPct(pct: number): string {
  return `${pct > 0 && pct < 1 ? pct.toFixed(1) : Math.round(pct)}%`;
}

/**
 * Pure aggregation of normalized F5 BIG-IP LTM, AWS ALB, and AWS NLB events into
 * KPIs, balancer-vs-target DistributionBar, VIP/Pool/Member rows, VIP × Pool Member
 * HeatMatrix, SwimlaneTimeline, and single-sentence verdict.
 */
export function buildLbHealthAnalysis(options: {
  events: readonly { event: NormalizedLbHealthEvent; indexName: string }[];
  thresholds: ResolvedLbHealthThresholds;
  earliest: number;
  latest: number;
  outcomes: ProtocolSourceOutcome[];
  capped: boolean;
  unparsedRowCount?: number;
}): LbHealthInvestigationResult {
  const {
    events,
    thresholds,
    earliest,
    latest,
    outcomes,
    capped,
    unparsedRowCount = 0,
  } = options;
  const nowSec = Math.floor(Date.now() / 1000);

  const anyBlocked = outcomes.some((o) => o.state === "blocked");
  const anyUnavailable = outcomes.some((o) => o.state === "unavailable");
  const anyDegraded = anyBlocked || anyUnavailable;
  const anyPartial =
    outcomes.some((o) => o.state === "partial") || capped || anyDegraded;

  if (!events.length) {
    if (anyBlocked) {
      return {
        verdict: "Source evidence could not be read for this role.",
        verdictStatus: "unknown",
        coverageStatus: "unknown",
        coverageLabel: "Blocked",
        hasTargetTelemetry: false,
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
        bannerState: "blocked",
        bannerReason:
          outcomes.find((o) => o.state === "blocked")?.detail ??
          "Access denied for one or more load balancer indexes.",
        checkedAt: nowSec,
      };
    }
    if (anyUnavailable) {
      return {
        verdict: "One or more configured sources failed in this UTC window.",
        verdictStatus: "unknown",
        coverageStatus: "unknown",
        coverageLabel: "Unavailable",
        hasTargetTelemetry: false,
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
          "Search hit row cap before matching load balancer events were found — narrow the UTC window or filter.",
        verdictStatus: "unknown",
        coverageStatus: "unknown",
        coverageLabel: "Capped",
        hasTargetTelemetry: false,
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
        bannerState: "partial",
        bannerReason:
          "Search hit row cap before matching load balancer events were found — narrow the UTC window or filter.",
        checkedAt: nowSec,
      };
    }
    if (unparsedRowCount > 0) {
      const unparsedReason = `${unparsedRowCount} ${unparsedRowCount === 1 ? "row" : "rows"} returned but could not be normalized`;
      return {
        verdict: `${unparsedReason}.`,
        verdictStatus: "unknown",
        coverageStatus: "unknown",
        coverageLabel: "Unparsed",
        hasTargetTelemetry: false,
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
        bannerState: "unavailable",
        bannerReason: unparsedReason,
        checkedAt: nowSec,
      };
    }
    return {
      verdict:
        "No matching F5, ALB, or NLB load balancer events observed in this UTC window.",
      verdictStatus: "none_observed",
      coverageStatus: "none_observed",
      coverageLabel: "None observed",
      hasTargetTelemetry: false,
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
      bannerState: "empty",
      bannerReason: "No matching load balancer events in this UTC window.",
      checkedAt: nowSec,
    };
  }

  interface MemberGroup {
    id: string;
    family: LbHealthFamily;
    vip: string;
    vipIp?: string;
    pool: string;
    memberIp?: string;
    memberPort?: number;
    memberLabel: string;
    events: NormalizedLbHealthEvent[];
    sourcetypes: Set<LbHealthSourcetype>;
    indexName: string;
  }

  const groups = new Map<string, MemberGroup>();

  for (const entry of events) {
    const ev = entry.event;
    const memberKey = ev.memberIp
      ? `${ev.memberIp}${ev.memberPort !== undefined ? `:${ev.memberPort}` : ""}`
      : ev.isLbFailed
        ? "no_member_lb_failed"
        : ev.family === "aws_nlb"
          ? "tls_listener"
          : "no_target";
    const memberLabel = ev.memberIp
      ? `${ev.memberIp}${ev.memberPort !== undefined ? `:${ev.memberPort}` : ""}`
      : ev.isLbFailed
        ? "No member (LB_FAILED)"
        : ev.family === "aws_nlb"
          ? "(TLS listener)"
          : "(no target)";
    const key = `${ev.family}\0${ev.vip}\0${ev.pool}\0${memberKey}`;
    let group = groups.get(key);
    if (!group) {
      group = {
        id: makeLbHealthRowId(ev.family, ev.vip, ev.pool, memberKey),
        family: ev.family,
        vip: ev.vip,
        ...(ev.vipIp ? { vipIp: ev.vipIp } : {}),
        pool: ev.pool,
        ...(ev.memberIp ? { memberIp: ev.memberIp } : {}),
        ...(ev.memberPort !== undefined ? { memberPort: ev.memberPort } : {}),
        memberLabel,
        events: [],
        sourcetypes: new Set<LbHealthSourcetype>(),
        indexName: entry.indexName,
      };
      groups.set(key, group);
    } else if (!group.vipIp && ev.vipIp) {
      group.vipIp = ev.vipIp;
    }
    group.events.push(ev);
    group.sourcetypes.add(ev.sourcetype);
  }

  const rows: LbHealthPoolMemberRow[] = [];

  for (const group of groups.values()) {
    const requestCount = group.events.length;
    const balancerErrorCount = group.events.filter(
      (e) => e.errorSide === "balancer",
    ).length;
    const targetErrorCount = group.events.filter(
      (e) => e.errorSide === "target",
    ).length;
    const healthyCount = requestCount - balancerErrorCount - targetErrorCount;
    const lbFailedCount = group.events.filter((e) => e.isLbFailed).length;
    const nlbTlsFailureCount = group.events.filter(
      (e) => e.isNlbTlsFailure,
    ).length;
    const balancerHttpErrCount =
      balancerErrorCount - lbFailedCount - nlbTlsFailureCount;

    const balancerErrorPct = (balancerErrorCount / requestCount) * 100;
    const targetErrorPct = (targetErrorCount / requestCount) * 100;
    const totalErrorPct =
      ((balancerErrorCount + targetErrorCount) / requestCount) * 100;

    const targetErrorsCovered = group.family !== "aws_nlb";

    const latencies = group.events
      .map((e) => e.latencyMs)
      .filter((v): v is number => v !== undefined);
    const p50Raw = percentile(latencies, 50);
    const p95Raw = percentile(latencies, 95);
    const p50LatencyMs = p50Raw !== undefined ? roundMs(p50Raw) : undefined;
    const p95LatencyMs = p95Raw !== undefined ? roundMs(p95Raw) : undefined;

    const connTimes = group.events
      .map((e) => e.connectionTimeMs)
      .filter((v): v is number => v !== undefined);
    const avgConnectionTimeMs = connTimes.length
      ? roundMs(connTimes.reduce((a, b) => a + b, 0) / connTimes.length)
      : undefined;

    const bytesIn = group.events.reduce((sum, e) => sum + e.bytesIn, 0);
    const bytesOut = group.events.reduce((sum, e) => sum + e.bytesOut, 0);

    const reasonCounts = new Map<string, number>();
    const alertCounts = new Map<string, number>();
    const verifyCounts = new Map<string, number>();
    const tlsProtocols = new Set<string>();

    for (const ev of group.events) {
      if (ev.errorReason) {
        reasonCounts.set(
          ev.errorReason,
          (reasonCounts.get(ev.errorReason) ?? 0) + 1,
        );
      }
      if (ev.tlsAlert) {
        alertCounts.set(ev.tlsAlert, (alertCounts.get(ev.tlsAlert) ?? 0) + 1);
      }
      if (ev.verifyStatus) {
        verifyCounts.set(
          ev.verifyStatus,
          (verifyCounts.get(ev.verifyStatus) ?? 0) + 1,
        );
      }
      if (ev.tlsProtocol) {
        tlsProtocols.add(ev.tlsProtocol);
      }
    }

    const sortTop = (m: Map<string, number>) =>
      [...m.entries()]
        .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
        .slice(0, 5)
        .map(([k, count]) => (count > 1 ? `${k} (${count})` : k));

    const errorReasons = sortTop(reasonCounts);
    const tlsAlerts = sortTop(alertCounts);
    const verifyStatuses = sortTop(verifyCounts);

    const reasons: string[] = [];
    const findings: string[] = [];

    if (lbFailedCount >= thresholds.lbFailedWarnCount) {
      reasons.push(
        `F5 LB_FAILED × ${lbFailedCount} (≥ ${thresholds.lbFailedWarnCount})`,
      );
      findings.push(
        `Balancer failure: ${lbFailedCount} Splunk-iRule-LB_FAILED ${lbFailedCount === 1 ? "event" : "events"} (pool selection or member connect failed)`,
      );
    }

    if (nlbTlsFailureCount > 0) {
      const detail = [...tlsAlerts, ...verifyStatuses]
        .filter((s) => !/^Success\b/i.test(s))
        .slice(0, 2)
        .join(", ");
      reasons.push(
        `NLB TLS failure × ${nlbTlsFailureCount}${detail ? ` (${detail})` : ""}`,
      );
      findings.push(
        `NLB TLS listener failure: ${nlbTlsFailureCount} failed TLS ${nlbTlsFailureCount === 1 ? "connection" : "connections"}${detail ? ` (${detail})` : ""}`,
      );
    }

    if (
      balancerHttpErrCount > 0 &&
      balancerErrorPct >= thresholds.errorRateWarnPct
    ) {
      const topReason = errorReasons[0];
      reasons.push(
        `Balancer errors ${formatPct(balancerErrorPct)} (${balancerHttpErrCount}/${requestCount})${topReason ? ` · ${topReason}` : ""}`,
      );
      findings.push(
        `Balancer-side 5xx: ${balancerHttpErrCount} of ${requestCount} requests (${formatPct(balancerErrorPct)})${topReason ? ` — top reason: ${topReason}` : ""}`,
      );
    }

    if (targetErrorCount > 0 && targetErrorPct >= thresholds.errorRateWarnPct) {
      reasons.push(
        `Target 5xx ${formatPct(targetErrorPct)} (${targetErrorCount}/${requestCount})`,
      );
      findings.push(
        `Backend target 5xx: ${targetErrorCount} of ${requestCount} requests (${formatPct(targetErrorPct)})`,
      );
    }

    if (
      reasons.length === 0 &&
      balancerErrorCount + targetErrorCount > 0 &&
      totalErrorPct >= thresholds.errorRateWarnPct
    ) {
      reasons.push(
        `Combined error rate ${formatPct(totalErrorPct)} (${balancerErrorCount} balancer, ${targetErrorCount} target)`,
      );
      findings.push(
        `Combined error rate ${formatPct(totalErrorPct)}: ${balancerErrorCount} balancer and ${targetErrorCount} target errors across ${requestCount} requests`,
      );
    }

    if (
      p95LatencyMs !== undefined &&
      p95LatencyMs >= thresholds.latencyWarnMs
    ) {
      reasons.push(
        `p95 latency ${p95LatencyMs} ms (≥ ${thresholds.latencyWarnMs} ms)`,
      );
      findings.push(
        `High latency: p95 ${p95LatencyMs} ms (p50 ${p50LatencyMs ?? p95LatencyMs} ms)`,
      );
    }

    const attention = reasons.length > 0;
    const status: ProtocolStatus = attention ? "attention" : "ok";

    const timestamps = group.events
      .map((e) => e.timestamp)
      .filter((t): t is number => t !== undefined);

    rows.push({
      id: group.id,
      attention,
      family: group.family,
      sourceLabel: familyLabel(group.family),
      vip: group.vip,
      vipDisplay: shortenBalancerLabel(group.vip),
      ...(group.vipIp ? { vipIp: group.vipIp } : {}),
      pool: group.pool,
      poolDisplay: shortenPoolLabel(group.pool),
      ...(group.memberIp ? { memberIp: group.memberIp } : {}),
      ...(group.memberPort !== undefined
        ? { memberPort: group.memberPort }
        : {}),
      memberLabel: group.memberLabel,
      requestCount,
      balancerErrorCount,
      targetErrorCount,
      healthyCount,
      lbFailedCount,
      nlbTlsFailureCount,
      balancerErrorPct,
      targetErrorPct,
      targetErrorsCovered,
      ...(p50LatencyMs !== undefined ? { p50LatencyMs } : {}),
      ...(p95LatencyMs !== undefined ? { p95LatencyMs } : {}),
      ...(avgConnectionTimeMs !== undefined ? { avgConnectionTimeMs } : {}),
      bytesIn,
      bytesOut,
      errorReasons,
      tlsAlerts,
      verifyStatuses,
      tlsProtocols: [...tlsProtocols],
      status,
      reasons,
      findings,
      indexName: group.indexName,
      sourcetypes: [...group.sourcetypes],
      ...(timestamps.length ? { firstSeen: Math.min(...timestamps) } : {}),
      ...(timestamps.length ? { lastSeen: Math.max(...timestamps) } : {}),
    });
  }

  rows.sort((a, b) => {
    if (a.attention !== b.attention) return a.attention ? -1 : 1;
    const aHard = a.lbFailedCount + a.nlbTlsFailureCount;
    const bHard = b.lbFailedCount + b.nlbTlsFailureCount;
    if (bHard !== aHard) return bHard - aHard;
    const aErr = a.balancerErrorCount + a.targetErrorCount;
    const bErr = b.balancerErrorCount + b.targetErrorCount;
    if (bErr !== aErr) return bErr - aErr;
    if ((b.p95LatencyMs ?? 0) !== (a.p95LatencyMs ?? 0)) {
      return (b.p95LatencyMs ?? 0) - (a.p95LatencyMs ?? 0);
    }
    if (b.requestCount !== a.requestCount)
      return b.requestCount - a.requestCount;
    return a.id.localeCompare(b.id);
  });

  // 4 single-metric KPI tiles
  const totalRequests = rows.reduce((sum, r) => sum + r.requestCount, 0);
  const totalBalancerErrors = rows.reduce(
    (sum, r) => sum + r.balancerErrorCount,
    0,
  );
  const targetCoveredRows = rows.filter((r) => r.targetErrorsCovered);
  const totalTargetErrors = targetCoveredRows.reduce(
    (sum, r) => sum + r.targetErrorCount,
    0,
  );
  const totalHealthy = rows.reduce((sum, r) => sum + r.healthyCount, 0);
  const hasTargetTelemetry = targetCoveredRows.length > 0;

  const allLatencies = events
    .map((e) => e.event.latencyMs)
    .filter((v): v is number => v !== undefined);
  const overallP95Raw = percentile(allLatencies, 95);
  const overallP95Ms =
    overallP95Raw !== undefined ? roundMs(overallP95Raw) : undefined;

  const reqSpark = buildSparklineBuckets(
    events.map((e) => ({ timestamp: e.event.timestamp, value: 1 })),
    earliest,
    latest,
  );
  const balSpark = buildSparklineBuckets(
    events.map((e) => ({
      timestamp: e.event.timestamp,
      value: e.event.errorSide === "balancer" ? 1 : 0,
    })),
    earliest,
    latest,
  );
  const tgtSpark = buildSparklineBuckets(
    events
      .filter((e) => e.event.family !== "aws_nlb")
      .map((e) => ({
        timestamp: e.event.timestamp,
        value: e.event.errorSide === "target" ? 1 : 0,
      })),
    earliest,
    latest,
  );
  const latencySpark = buildSparklineBuckets(
    events
      .filter((e) => e.event.latencyMs !== undefined)
      .map((e) => ({
        timestamp: e.event.timestamp,
        value: e.event.latencyMs ?? 0,
      })),
    earliest,
    latest,
  );

  const latencyStatus: ProtocolStatus =
    overallP95Ms !== undefined
      ? overallP95Ms >= thresholds.latencyWarnMs
        ? "attention"
        : "ok"
      : anyPartial || capped
        ? "unknown"
        : "not_covered";

  const latencyValue =
    overallP95Ms !== undefined
      ? formatDurationMs(overallP95Ms)
      : anyPartial || capped
        ? "Unknown"
        : "Not covered";

  const kpis: ProtocolKpi[] = [
    {
      id: "requests",
      label: "Requests",
      value: formatCount(totalRequests),
      unit: totalRequests === 1 ? "req" : "reqs",
      status: totalRequests > 0 ? "ok" : "none_observed",
      ...(reqSpark.length ? { sparkline: reqSpark } : {}),
    },
    {
      id: "balancer-errors",
      label: "Balancer Errors",
      value: formatCount(totalBalancerErrors),
      unit: totalBalancerErrors === 1 ? "balancer err" : "balancer errs",
      status: totalBalancerErrors > 0 ? "attention" : "ok",
      ...(balSpark.length ? { sparkline: balSpark } : {}),
    },
    {
      id: "target-errors",
      label: "Target Errors",
      value: hasTargetTelemetry
        ? formatCount(totalTargetErrors)
        : "Not covered",
      ...(hasTargetTelemetry
        ? { unit: totalTargetErrors === 1 ? "target err" : "target errs" }
        : {}),
      status: !hasTargetTelemetry
        ? "not_covered"
        : totalTargetErrors > 0
          ? "attention"
          : "ok",
      ...(hasTargetTelemetry && tgtSpark.length ? { sparkline: tgtSpark } : {}),
    },
    {
      id: "latency-p95",
      label: "Latency p95",
      value: latencyValue,
      status: latencyStatus,
      ...(latencySpark.length ? { sparkline: latencySpark } : {}),
    },
  ];

  // DistributionBar: Balancer Errors vs Target Errors vs Healthy
  const maxSplit = Math.max(totalRequests, 1);
  const distribution: ProtocolDistributionMetric[] = [
    {
      id: "balancer-errors",
      label: "Balancer Errors",
      p50: totalBalancerErrors,
      p95: totalBalancerErrors,
      max: maxSplit,
      unit: "reqs",
      status: totalBalancerErrors > 0 ? "attention" : "ok",
    },
    {
      id: "target-errors",
      label: "Target Errors",
      p50: totalTargetErrors,
      p95: totalTargetErrors,
      max: maxSplit,
      unit: "reqs",
      status: !hasTargetTelemetry
        ? "not_covered"
        : totalTargetErrors > 0
          ? "attention"
          : "ok",
    },
    {
      id: "healthy",
      label: "Healthy",
      p50: totalHealthy,
      p95: totalHealthy,
      max: maxSplit,
      unit: "reqs",
      status: "ok",
    },
  ];

  // HeatMatrix: VIP / Balancer × Pool Member
  interface MatrixBucket {
    vipCol: string;
    memberCol: string;
    rows: LbHealthPoolMemberRow[];
    requests: number;
    balancerErrors: number;
    targetErrors: number;
    lbFailed: number;
    nlbTlsFailures: number;
    maxP95LatencyMs: number;
  }

  const matrixBuckets = new Map<string, MatrixBucket>();
  const flaggedVips = new Set<string>();
  const flaggedMembers = new Set<string>();

  for (const row of rows) {
    const vipLabel = shortenDeviceLabel(row.vipDisplay);
    const memberCol = row.memberIp
      ? row.memberLabel
      : `${row.poolDisplay} · ${row.memberLabel}`;
    const key = `${vipLabel}\0${memberCol}`;
    const bucket = matrixBuckets.get(key) ?? {
      vipCol: vipLabel,
      memberCol,
      rows: [],
      requests: 0,
      balancerErrors: 0,
      targetErrors: 0,
      lbFailed: 0,
      nlbTlsFailures: 0,
      maxP95LatencyMs: 0,
    };
    bucket.rows.push(row);
    bucket.requests += row.requestCount;
    bucket.balancerErrors += row.balancerErrorCount;
    bucket.targetErrors += row.targetErrorCount;
    bucket.lbFailed += row.lbFailedCount;
    bucket.nlbTlsFailures += row.nlbTlsFailureCount;
    bucket.maxP95LatencyMs = Math.max(
      bucket.maxP95LatencyMs,
      row.p95LatencyMs ?? 0,
    );
    matrixBuckets.set(key, bucket);
    if (row.attention) {
      flaggedVips.add(vipLabel);
      flaggedMembers.add(memberCol);
    }
  }

  const matrixCells: ProtocolMatrixCell[] = [];
  for (const bucket of matrixBuckets.values()) {
    const anyAttention = bucket.rows.some((r) => r.attention);
    const status: ProtocolStatus = anyAttention ? "attention" : "ok";
    let value = `${formatCount(bucket.requests)} ${bucket.requests === 1 ? "req" : "reqs"}`;
    if (bucket.lbFailed > 0 && bucket.targetErrors > 0) {
      value = `LB_FAILED (${bucket.lbFailed}) · Target (${bucket.targetErrors})`;
    } else if (bucket.lbFailed > 0) {
      value = `LB_FAILED (${bucket.lbFailed})`;
    } else if (bucket.nlbTlsFailures > 0) {
      value = `TLS fail (${bucket.nlbTlsFailures})`;
    } else if (bucket.balancerErrors > 0 && bucket.targetErrors > 0) {
      value = `Bal ${bucket.balancerErrors} · Target ${bucket.targetErrors}`;
    } else if (bucket.balancerErrors > 0) {
      value = `Bal err (${bucket.balancerErrors})`;
    } else if (bucket.targetErrors > 0) {
      value = `Target 5xx (${bucket.targetErrors})`;
    } else if (
      anyAttention &&
      bucket.maxP95LatencyMs >= thresholds.latencyWarnMs
    ) {
      value = `p95 ${formatDurationMs(bucket.maxP95LatencyMs)}`;
    }

    const sortedRows = [...bucket.rows].sort((a, b) =>
      a.attention === b.attention ? 0 : a.attention ? -1 : 1,
    );
    const topDetails = sortedRows
      .flatMap((r) => r.reasons)
      .filter(Boolean)
      .slice(0, 3);

    matrixCells.push({
      row: bucket.vipCol,
      col: bucket.memberCol,
      status,
      value,
      count: bucket.requests,
      detail: topDetails.length
        ? topDetails.join("; ")
        : `${bucket.requests} requests, 0 balancer/target errors`,
      itemId: sortedRows[0]?.id,
    });
  }

  const matrixRows = [...new Set(matrixCells.map((c) => c.row))].sort(
    (a, b) => {
      const aFlag = flaggedVips.has(a);
      const bFlag = flaggedVips.has(b);
      if (aFlag !== bFlag) return aFlag ? -1 : 1;
      return a.localeCompare(b);
    },
  );
  const matrixCols = [...new Set(matrixCells.map((c) => c.col))].sort(
    (a, b) => {
      const aFlag = flaggedMembers.has(a);
      const bFlag = flaggedMembers.has(b);
      if (aFlag !== bFlag) return aFlag ? -1 : 1;
      return a.localeCompare(b);
    },
  );

  // SwimlaneTimeline of failures (F5 LB_FAILED, backend 5xx, ALB 5xx, NLB TLS alerts/verify failures)
  const timelineEntries: {
    event: ProtocolTimelineEvent;
    rowId: string;
  }[] = [];

  for (let i = 0; i < events.length; i += 1) {
    const ev = events[i].event;
    if (ev.timestamp === undefined || ev.errorSide === "none") continue;
    const memberKey = ev.memberIp
      ? `${ev.memberIp}${ev.memberPort !== undefined ? `:${ev.memberPort}` : ""}`
      : ev.isLbFailed
        ? "no_member_lb_failed"
        : ev.family === "aws_nlb"
          ? "tls_listener"
          : "no_target";
    const rowId = makeLbHealthRowId(ev.family, ev.vip, ev.pool, memberKey);
    const lane = `${shortenDeviceLabel(shortenBalancerLabel(ev.vip))} · ${shortenPoolLabel(ev.pool)}`;
    const memberSuffix = ev.memberIp
      ? ` on ${ev.memberIp}${ev.memberPort !== undefined ? `:${ev.memberPort}` : ""}`
      : "";
    const label = `${ev.failureCategory ?? "Load balancer error"}${memberSuffix}`;

    timelineEntries.push({
      event: {
        id: `lb_${i}_${ev.timestamp}`,
        lane,
        timestamp: ev.timestamp,
        kind: "attention",
        label,
        detail: `${ev.vip} · ${ev.pool} — ${label}`,
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

  // Single-sentence plain-language verdict above the fold
  const flaggedRows = rows.filter((r) => r.attention);
  const totalLbFailed = rows.reduce((sum, r) => sum + r.lbFailedCount, 0);
  const totalNlbTlsFailures = rows.reduce(
    (sum, r) => sum + r.nlbTlsFailureCount,
    0,
  );

  let verdict: string;
  let verdictStatus: ProtocolStatus;

  if (flaggedRows.length > 0) {
    const highlights: string[] = [];
    if (totalLbFailed > 0) {
      highlights.push(`${totalLbFailed} F5 LB_FAILED`);
    }
    if (totalNlbTlsFailures > 0) {
      highlights.push(`${totalNlbTlsFailures} NLB TLS`);
    }
    const lead = flaggedRows[0];
    if (!highlights.length && lead.reasons.length) {
      highlights.push(lead.reasons[0]);
    }
    const highlightText = highlights.length
      ? ` (${highlights.join(", ")})`
      : "";
    if (!hasTargetTelemetry) {
      verdict = `${flaggedRows.length} of ${rows.length} ${rows.length === 1 ? "listener needs" : "listeners need"} attention: ${totalBalancerErrors} balancer/TLS ${totalBalancerErrors === 1 ? "failure" : "failures"}${highlightText}.`;
    } else {
      verdict = `${flaggedRows.length} of ${rows.length} ${rows.length === 1 ? "member needs" : "members need"} attention: ${totalBalancerErrors} balancer vs ${totalTargetErrors} target ${totalBalancerErrors + totalTargetErrors === 1 ? "error" : "errors"}${highlightText}.`;
    }
    verdictStatus = "attention";
  } else if (!hasTargetTelemetry) {
    verdict = `${rows.length} of ${rows.length} ${rows.length === 1 ? "listener" : "listeners"} healthy across ${formatCount(totalRequests)} TLS connections with 0 TLS alerts or verification failures.`;
    verdictStatus = "ok";
  } else {
    verdict = `${rows.length} of ${rows.length} ${rows.length === 1 ? "member" : "members"} healthy across ${formatCount(totalRequests)} requests with 0 balancer or target errors.`;
    verdictStatus = "ok";
  }

  const coverageStatus: ProtocolStatus =
    anyPartial || unparsedRowCount > 0
      ? "attention"
      : !hasTargetTelemetry
        ? "ok"
        : "ok";
  const activeCount = outcomes.filter(
    (o) => o.state === "complete" || o.state === "partial",
  ).length;
  const coverageLabel = `${activeCount} ${activeCount === 1 ? "source" : "sources"}`;

  const blockedDetail = outcomes.find((o) => o.state === "blocked")?.detail;
  const unavailableDetail = outcomes.find(
    (o) => o.state === "unavailable",
  )?.detail;

  let bannerState: LbHealthInvestigationResult["bannerState"];
  let bannerReason: string | undefined;

  if (anyPartial || unparsedRowCount > 0) {
    bannerState = "partial";
    bannerReason = anyBlocked
      ? `One or more sources denied access (${blockedDetail ?? "access denied"}); results are incomplete.`
      : anyUnavailable
        ? `One or more sources failed (${unavailableDetail ?? "search unavailable"}); results are incomplete.`
        : unparsedRowCount > 0 && !capped
          ? `${unparsedRowCount} ${unparsedRowCount === 1 ? "row" : "rows"} returned could not be normalized; results may be incomplete.`
          : "Sample capped at 256 rows — narrow the UTC window or filter.";
  }

  return {
    verdict,
    verdictStatus,
    coverageStatus,
    coverageLabel,
    hasTargetTelemetry,
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
    ...(bannerState ? { bannerState, bannerReason } : {}),
    checkedAt: nowSec,
  };
}

export interface InvestigateLbHealthOptions {
  skipConfigRecheck?: boolean;
  profileValidators?: Partial<Record<ProtocolLensId, LensProfileValidator>>;
}

function targetAllowedFamily(
  target: LbHealthSearchTarget,
): LbHealthFamily | undefined {
  if (target === "f5_ltm") return "f5_ltm";
  if (target === "aws_alb") return "aws_alb";
  if (target === "aws_nlb") return "aws_nlb";
  return undefined;
}

/**
 * Executes the on-demand Load Balancer Pool Health investigation across configured
 * `lb_health` profiles (F5 BIG-IP LTM iRule HSL, AWS ALB, AWS NLB TLS),
 * verifying the `adm_protocol_profiles` fingerprint before committing results.
 */
export async function investigateLbHealth(
  client: SearchClient,
  request: ProtocolRequest,
  configuration: ProtocolConfiguration,
  signal: AbortSignal,
  options: InvestigateLbHealthOptions = {},
): Promise<LbHealthInvestigationResult> {
  const scoped = selectActiveProfiles(
    configuration.profiles,
    "lb_health",
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
      hasTargetTelemetry: false,
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
      bannerReason: `No lb_health profile configured for scope "${request.scope}".`,
      checkedAt: Math.floor(Date.now() / 1000),
    };
  }

  const runProfiles = async () => {
    const outcomes: ProtocolSourceOutcome[] = [];
    const collected: {
      event: NormalizedLbHealthEvent;
      indexName: string;
    }[] = [];
    let capped = false;
    let unparsedRowCount = 0;
    const chosenThresholds = resolveLbHealthThresholds(scoped[0]);

    for (const profile of scoped) {
      const sk = resolveLbHealthThresholds(profile).sourceKind;
      const targets: LbHealthSearchTarget[] =
        sk === "auto" ? ["f5_ltm", "aws_elb"] : [sk];

      for (const target of targets) {
        signal.throwIfAborted();
        const spl = buildLbHealthSearch({
          index: profile.index,
          target,
          filter: request.filter,
          maxRows: MAX_INPUT_ROWS,
        });
        const res = await runBoundedProtocolSearch(client, {
          lens: "lb_health",
          profile,
          spl,
          earliest: request.earliest,
          latest: request.latest,
          signal,
          keySuffix: target,
        });
        outcomes.push(res.outcome);
        if (res.capped) capped = true;
        const expectedFamily = targetAllowedFamily(target);
        for (const row of res.rows) {
          const norm = normalizeLbHealthRow(row, expectedFamily);
          if (!norm) {
            unparsedRowCount += 1;
            continue;
          }
          if (expectedFamily && norm.family !== expectedFamily) continue;
          collected.push({ event: norm, indexName: profile.index });
        }
      }
    }

    return buildLbHealthAnalysis({
      events: collected,
      thresholds: chosenThresholds,
      earliest: request.earliest,
      latest: request.latest,
      outcomes,
      capped,
      unparsedRowCount,
    });
  };

  if (options.skipConfigRecheck || !configuration.fingerprint) {
    return runProfiles();
  }

  const validators: Partial<Record<ProtocolLensId, LensProfileValidator>> = {
    ...options.profileValidators,
    lb_health: validateLbHealthExtra,
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
        hasTargetTelemetry: false,
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
 * Hub "Check all" summary runner for `lb_health`.
 */
export async function summarizeLbHealth(
  client: SearchClient,
  request: ProtocolRequest,
  configuration: ProtocolConfiguration,
  signal: AbortSignal,
  options?: InvestigateLbHealthOptions,
): Promise<ProtocolLensSummary> {
  const result = await investigateLbHealth(
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
    lens: "lb_health",
    status,
    verdict: result.verdict,
    checkedAt: result.checkedAt,
    capped: result.capped,
    outcomes: result.outcomes,
  };
}
