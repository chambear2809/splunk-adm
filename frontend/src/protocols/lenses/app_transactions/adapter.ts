import { literal } from "../../../data/evidence";
import type { SearchClient } from "../../../data/searchClient";
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
  APP_TRANSACTIONS_DB_SOURCETYPES,
  APP_TRANSACTIONS_HTTP_SOURCETYPE,
  APP_TRANSACTIONS_SOURCETYPES,
  APP_TRANSACTIONS_STREAM_IDS,
  DEFAULT_APP_TRANSACTIONS_THRESHOLDS,
  resolveAppTransactionsThresholds,
  validateAppTransactionsExtra,
  type AppTransactionsExtraConfig,
  type AppTransactionsSourceKind,
  type AppTransactionsSourcetype,
  type AppTransactionsStreamId,
  type ResolvedAppTransactionsThresholds,
} from "./validate";

export {
  APP_TRANSACTIONS_DB_SOURCETYPES,
  APP_TRANSACTIONS_HTTP_SOURCETYPE,
  APP_TRANSACTIONS_SOURCETYPES,
  APP_TRANSACTIONS_STREAM_IDS,
  DEFAULT_APP_TRANSACTIONS_THRESHOLDS,
  resolveAppTransactionsThresholds,
  validateAppTransactionsExtra,
  type AppTransactionsExtraConfig,
  type AppTransactionsSourceKind,
  type AppTransactionsSourcetype,
  type AppTransactionsStreamId,
  type ResolvedAppTransactionsThresholds,
};

export type AppTransactionsKind = "http" | "db";

/**
 * Strictly allowlisted fields for `stream:http`.
 * NEVER includes `cookie`, `form_data`, `uri_query`, `authorization`, `content`,
 * `payload`, `src_content`, `dest_content`, or `_raw`.
 */
export const HTTP_PROJECTED_FIELDS = [
  "_time",
  "host",
  "sourcetype",
  "src_ip",
  "dest_ip",
  "src_port",
  "dest_port",
  "protocol",
  "app",
  "http_method",
  "method",
  "status",
  "status_code",
  "uri_path",
  "site",
  "time_taken",
  "response_time",
  "bytes_in",
  "bytes_out",
] as const;

/**
 * Strictly allowlisted fields for `stream:mysql`, `stream:postgres`, `stream:tds`,
 * and `stream:tns`.
 * NEVER includes `query`, `sql_statement`, `bind_variable_value`, `error`,
 * `login`, `password`, `passwd`, `content`, `payload`, or `_raw`.
 */
export const DB_PROJECTED_FIELDS = [
  "_time",
  "host",
  "sourcetype",
  "src_ip",
  "dest_ip",
  "src_port",
  "dest_port",
  "protocol",
  "app",
  "db_type",
  "database",
  "dbname",
  "status",
  "error_code",
  "sql_error_code",
  "time_taken",
  "response_time",
  "rows_returned",
  "result_row_count",
  "bytes_in",
  "bytes_out",
] as const;

const DB_SOURCETYPE_SET = new Set<string>(APP_TRANSACTIONS_DB_SOURCETYPES);
const ALL_SOURCETYPE_SET = new Set<string>(APP_TRANSACTIONS_SOURCETYPES);

function buildDbSourcetypePredicate(): string {
  return `(${APP_TRANSACTIONS_DB_SOURCETYPES.map((st) => `sourcetype="${st}"`).join(" OR ")})`;
}

/**
 * Builds a bounded, allowlisted SPL query for HTTP (`stream:http`) or SQL DB
 * (`stream:mysql`, `stream:postgres`, `stream:tds`, `stream:tns`).
 *
 * Always emits `| head <maxRows + 1>` BEFORE `buildAllowedFieldsClause` (`| table ...`)
 * so indexers cap rows and drop `_raw` server-side. Never includes SQL `query`,
 * `sql_statement`, `bind_variable_value`, `uri_query`, `form_data`, or `cookie`.
 */
export function buildAppTransactionsSearch(options: {
  index: string;
  kind: AppTransactionsKind;
  filter?: ProtocolFilter;
  maxRows: number;
}): string {
  const index = literal(options.index, 80);
  const headLimit = Math.max(1, Math.trunc(options.maxRows)) + 1;

  if (options.kind === "http") {
    const predicates: string[] = [
      `index=${index}`,
      `sourcetype="${APP_TRANSACTIONS_HTTP_SOURCETYPE}"`,
    ];
    if (options.filter?.src) {
      predicates.push(`src_ip="${literal(options.filter.src, 128)}"`);
    }
    if (options.filter?.dst) {
      predicates.push(`dest_ip="${literal(options.filter.dst, 128)}"`);
    }
    if (options.filter?.device) {
      const dev = literal(options.filter.device, 128);
      predicates.push(`(host="${dev}" OR dest_ip="${dev}" OR site="${dev}")`);
    }
    const tableClause = buildAllowedFieldsClause(
      "app_transactions",
      HTTP_PROJECTED_FIELDS,
    );
    return `search ${predicates.join(" ")} | head ${headLimit} ${tableClause}`;
  }

  const predicates: string[] = [`index=${index}`, buildDbSourcetypePredicate()];
  if (options.filter?.src) {
    predicates.push(`src_ip="${literal(options.filter.src, 128)}"`);
  }
  if (options.filter?.dst) {
    predicates.push(`dest_ip="${literal(options.filter.dst, 128)}"`);
  }
  if (options.filter?.device) {
    const dev = literal(options.filter.device, 128);
    predicates.push(`(host="${dev}" OR dest_ip="${dev}")`);
  }
  const tableClause = buildAllowedFieldsClause(
    "app_transactions",
    DB_PROJECTED_FIELDS,
  );
  return (
    `search ${predicates.join(" ")} ` +
    `| head ${headLimit} ` +
    `| eval sql_error_code=coalesce(if(isnotnull(sql_error_code) AND sql_error_code!="" AND sql_error_code!="0" AND sql_error_code!="00000", sql_error_code, null()), if(sourcetype=="stream:tds", sql_result_codes, null()), error_code, if(isnotnull(error) AND error!="", "SQL_ERROR", null()), sql_error_code) ` +
    `| eval sql_error_code=if(isnull(sql_error_code) OR sql_error_code=="", null(), if(match(sql_error_code, "^[A-Za-z0-9_.:-]{1,32}$"), sql_error_code, "SQL_ERROR")) ` +
    `| eval error_code=if(isnull(error_code) OR error_code=="", null(), if(match(error_code, "^[A-Za-z0-9_.:-]{1,32}$"), error_code, "SQL_ERROR")) ` +
    tableClause
  );
}

/**
 * Builds a `literal()`-quoted Splunk Search URL for raw events of a selected server.
 */
export function buildAppTransactionsRawEventsUrl(options: {
  index: string;
  serverIp: string;
  destPort?: number;
  sourcetypes: readonly AppTransactionsSourcetype[];
  earliest: number;
  latest: number;
}): string {
  const index = literal(options.index, 80);
  const dst = literal(options.serverIp, 128);
  const validSts = options.sourcetypes.filter((st) =>
    ALL_SOURCETYPE_SET.has(st),
  );
  const sts = validSts.length ? validSts : APP_TRANSACTIONS_SOURCETYPES;
  const stClause =
    sts.length === 1
      ? `sourcetype="${sts[0]}"`
      : `(${sts.map((s) => `sourcetype="${s}"`).join(" OR ")})`;
  const portClause =
    options.destPort !== undefined &&
    Number.isInteger(options.destPort) &&
    options.destPort >= 0 &&
    options.destPort <= 65535
      ? ` dest_port=${options.destPort}`
      : "";
  const q = `search index=${index} ${stClause} dest_ip="${dst}"${portClause}`;
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

function asStringList(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value.flatMap((v) => asStringList(v));
  }
  const s = asString(value);
  return s ? [s] : [];
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

/**
 * Defensively strips any `?…` query string or `#…` fragment from `uri_path`
 * client-side before aggregation or rendering.
 */
export function sanitizeUriPath(raw: unknown): string | undefined {
  const str = asString(raw);
  if (!str) return undefined;
  const cleaned = str.split(/[?#]/, 1)[0].trim();
  return cleaned || undefined;
}

function sanitizeIdPart(raw: string): string {
  const cleaned = raw
    .trim()
    .replace(/[^A-Za-z0-9._:/-]+/g, "_")
    .replace(/^[^A-Za-z0-9]+/, "")
    .replace(/_+$/, "");
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
export function makeAppTransactionRowId(
  protocolLabel: string,
  serverIp: string,
  destPort?: number,
): string {
  const portPart = destPort !== undefined ? `__${destPort}` : "";
  const full = `${sanitizeIdPart(protocolLabel)}__${sanitizeIdPart(serverIp)}${portPart}`;
  if (full.length <= 128) return full;
  const suffix = `__${shortFnvHash(full)}`;
  const budget = 128 - suffix.length;
  return `${full.slice(0, budget)}${suffix}`;
}

export function protocolLabelForSource(
  sourcetype: AppTransactionsSourcetype,
): string {
  switch (sourcetype) {
    case "stream:http":
      return "HTTP";
    case "stream:mysql":
      return "MySQL";
    case "stream:postgres":
      return "PostgreSQL";
    case "stream:tds":
      return "TDS / SQL Server";
    case "stream:tns":
      return "TNS / Oracle";
  }
}

function resolveSourcetype(
  row: ProtocolRow,
  defaultKind?: AppTransactionsKind,
): AppTransactionsSourcetype | undefined {
  const st = asString(row.sourcetype).toLowerCase();
  if (ALL_SOURCETYPE_SET.has(st)) {
    return st as AppTransactionsSourcetype;
  }
  const hint = (
    asString(row.db_type) ||
    asString(row.protocol) ||
    asString(row.app)
  ).toLowerCase();
  if (hint === "http" || hint === "https") return "stream:http";
  if (hint.includes("mysql") || hint.includes("maria")) return "stream:mysql";
  if (hint.includes("postgres") || hint === "pg") return "stream:postgres";
  if (
    hint.includes("tds") ||
    hint.includes("mssql") ||
    hint.includes("sqlserver")
  ) {
    return "stream:tds";
  }
  if (hint.includes("tns") || hint.includes("oracle")) return "stream:tns";
  if (defaultKind === "http") return "stream:http";
  if (defaultKind === "db") return "stream:mysql";
  return undefined;
}

const BENIGN_DB_STATUS_TOKENS = new Set<string>([
  "",
  "0",
  "00000",
  "ok",
  "success",
  "none",
  "null",
  "false",
  "n/a",
  "-",
]);

const STRICT_ERROR_CODE_RE = /^[A-Za-z0-9_.:-]{1,32}$/;

function isErrorToken(raw: string): boolean {
  return !BENIGN_DB_STATUS_TOKENS.has(raw.trim().toLowerCase());
}

function sanitizeSqlErrorCode(raw: string): string {
  const trimmed = raw.trim();
  return STRICT_ERROR_CODE_RE.test(trimmed) ? trimmed : "SQL_ERROR";
}

export interface NormalizedAppTransactionEvent {
  sourcetype: AppTransactionsSourcetype;
  kind: AppTransactionsKind;
  protocolLabel: string;
  timestamp: number | undefined;
  host: string;
  srcIp?: string;
  serverIp: string;
  srcPort?: number;
  destPort?: number;
  latencyMs?: number;
  bytesIn?: number;
  bytesOut?: number;
  httpMethod?: string;
  httpStatus?: number;
  uriPath?: string;
  site?: string;
  dbName?: string;
  sqlErrorCode?: string;
  rowsReturned?: number;
  hasStatusSample: boolean;
  isError: boolean;
  errorKind?: "http_5xx" | "http_4xx" | "sql_error";
  errorLabel?: string;
}

/**
 * Normalizes a single allowlist-projected `stream:http`, `stream:mysql`,
 * `stream:postgres`, `stream:tds`, or `stream:tns` row.
 *
 * Splunk Stream 8.1.6 reports `time_taken` (`flow.time-taken`) and
 * `response_time` (`flow.sc-send-time`) in microseconds (`µs`), so both are
 * converted to milliseconds via `/ 1000`.
 */
export function normalizeAppTransactionRow(
  row: ProtocolRow,
  defaultKind?: AppTransactionsKind,
): NormalizedAppTransactionEvent | undefined {
  const sourcetype = resolveSourcetype(row, defaultKind);
  if (!sourcetype) return undefined;
  const serverIp = asString(row.dest_ip);
  if (!serverIp) return undefined;

  const srcIp = asString(row.src_ip) || undefined;
  const rawSrcPort = asFiniteNumber(row.src_port);
  const rawDestPort = asFiniteNumber(row.dest_port);
  const srcPort =
    rawSrcPort !== undefined && rawSrcPort >= 0 && rawSrcPort <= 65535
      ? Math.trunc(rawSrcPort)
      : undefined;
  const destPort =
    rawDestPort !== undefined && rawDestPort >= 0 && rawDestPort <= 65535
      ? Math.trunc(rawDestPort)
      : undefined;

  const timestamp = asEpochSeconds(row._time);
  const host = asString(row.host) || "unknown";
  const kind: AppTransactionsKind =
    sourcetype === "stream:http" ? "http" : "db";
  const protocolLabel = protocolLabelForSource(sourcetype);

  const timeTakenUs = asFiniteNumber(row.time_taken);
  const responseTimeUs = asFiniteNumber(row.response_time);
  const rawLatencyUs =
    timeTakenUs !== undefined && timeTakenUs > 0
      ? timeTakenUs
      : (responseTimeUs ?? timeTakenUs);
  const latencyMs =
    rawLatencyUs !== undefined && rawLatencyUs >= 0
      ? rawLatencyUs / 1000
      : undefined;

  const bytesIn = asFiniteNumber(row.bytes_in);
  const bytesOut = asFiniteNumber(row.bytes_out);

  if (kind === "http") {
    const httpMethod =
      asString(row.http_method ?? row.method).toUpperCase() || undefined;
    const rawStatus = asFiniteNumber(row.status ?? row.status_code);
    const httpStatus =
      rawStatus !== undefined &&
      Number.isInteger(rawStatus) &&
      rawStatus >= 100 &&
      rawStatus <= 599
        ? rawStatus
        : undefined;
    const uriPath = sanitizeUriPath(row.uri_path);
    const site = asString(row.site) || undefined;
    const hasStatusSample = httpStatus !== undefined;
    const isError = httpStatus !== undefined && httpStatus >= 400;
    const errorKind =
      httpStatus !== undefined
        ? httpStatus >= 500
          ? "http_5xx"
          : httpStatus >= 400
            ? "http_4xx"
            : undefined
        : undefined;
    const errorLabel = isError ? String(httpStatus) : undefined;

    return {
      sourcetype,
      kind,
      protocolLabel,
      timestamp,
      host,
      ...(srcIp ? { srcIp } : {}),
      serverIp,
      ...(srcPort !== undefined ? { srcPort } : {}),
      ...(destPort !== undefined ? { destPort } : {}),
      ...(latencyMs !== undefined ? { latencyMs } : {}),
      ...(bytesIn !== undefined && bytesIn >= 0 ? { bytesIn } : {}),
      ...(bytesOut !== undefined && bytesOut >= 0 ? { bytesOut } : {}),
      ...(httpMethod ? { httpMethod } : {}),
      ...(httpStatus !== undefined ? { httpStatus } : {}),
      ...(uriPath ? { uriPath } : {}),
      ...(site ? { site } : {}),
      hasStatusSample,
      isError,
      ...(errorKind ? { errorKind } : {}),
      ...(errorLabel ? { errorLabel } : {}),
    };
  }

  const dbName = asString(row.dbname ?? row.database) || undefined;
  const rowsNum = asFiniteNumber(row.result_row_count ?? row.rows_returned);
  const rowsReturned =
    rowsNum !== undefined && rowsNum >= 0 ? Math.trunc(rowsNum) : undefined;

  const sqlCodes = [
    ...asStringList(row.sql_error_code),
    ...asStringList(row.error_code),
  ]
    .filter(isErrorToken)
    .map(sanitizeSqlErrorCode);
  const rawErr = asString(row.error);
  const hasRawErr = Boolean(rawErr && isErrorToken(rawErr));
  const rawDbStatus = asString(row.status);
  const statusIsError =
    Boolean(rawDbStatus) && isErrorToken(rawDbStatus) && rawDbStatus !== "200";

  const sqlErrorCode =
    sqlCodes[0] ??
    (hasRawErr ? "SQL_ERROR" : undefined) ??
    (statusIsError ? sanitizeSqlErrorCode(rawDbStatus) : undefined);

  const isError = Boolean(sqlErrorCode);
  const hasStatusSample =
    DB_SOURCETYPE_SET.has(sourcetype) || isError || Boolean(rawDbStatus);
  const errorLabel = sqlErrorCode;

  return {
    sourcetype,
    kind,
    protocolLabel,
    timestamp,
    host,
    ...(srcIp ? { srcIp } : {}),
    serverIp,
    ...(srcPort !== undefined ? { srcPort } : {}),
    ...(destPort !== undefined ? { destPort } : {}),
    ...(latencyMs !== undefined ? { latencyMs } : {}),
    ...(bytesIn !== undefined && bytesIn >= 0 ? { bytesIn } : {}),
    ...(bytesOut !== undefined && bytesOut >= 0 ? { bytesOut } : {}),
    ...(dbName ? { dbName } : {}),
    ...(sqlErrorCode ? { sqlErrorCode } : {}),
    ...(rowsReturned !== undefined ? { rowsReturned } : {}),
    hasStatusSample,
    isError,
    ...(isError ? { errorKind: "sql_error" as const } : {}),
    ...(errorLabel ? { errorLabel } : {}),
  };
}

export interface AppTransactionEndpointBreakdown {
  label: string;
  count: number;
  errorCount: number;
}

export interface AppTransactionClientBreakdown {
  clientIp: string;
  count: number;
  errorCount: number;
}

export interface AppTransactionErrorBreakdown {
  code: string;
  count: number;
}

export interface AppTransactionsServiceRow {
  /** URL-safe ID matching `^[A-Za-z0-9._:/-]{1,128}$` using `__`. */
  id: string;
  attention: boolean;
  kind: AppTransactionsKind;
  protocolLabel: string;
  protocolDisplay: string;
  serverIp: string;
  destPort?: number;
  serverMatrixLabel: string;
  serviceName?: string;
  sourcetypes: AppTransactionsSourcetype[];
  txnCount: number;
  statusSampleCount: number;
  errorCount: number;
  http5xxCount: number;
  http4xxCount: number;
  sqlErrorCount: number;
  errorPct?: number;
  latencyP50Ms?: number;
  latencyP95Ms?: number;
  latencyMaxMs?: number;
  totalBytesIn: number;
  totalBytesOut: number;
  totalRowsReturned?: number;
  topPathsOrDatabases: AppTransactionEndpointBreakdown[];
  topErrors: AppTransactionErrorBreakdown[];
  topClients: AppTransactionClientBreakdown[];
  status: ProtocolStatus;
  reasons: string[];
  indexName: string;
  firstSeen?: number;
  lastSeen?: number;
}

export interface AppTransactionsInvestigationResult {
  verdict: string;
  verdictStatus: ProtocolStatus;
  coverageStatus: ProtocolStatus;
  coverageLabel: string;
  hasActiveHttp: boolean;
  hasActiveDb: boolean;
  kpis: ProtocolKpi[];
  rows: AppTransactionsServiceRow[];
  matrixRows: string[];
  matrixCols: string[];
  matrixCells: ProtocolMatrixCell[];
  distribution: ProtocolDistributionMetric[];
  timelineEvents: ProtocolTimelineEvent[];
  timelineRowByEventId: Record<string, string>;
  outcomes: ProtocolSourceOutcome[];
  capped: boolean;
  sourceMode: "mixed" | "http_only" | "db_only" | "none";
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

function splitDurationParts(ms: number): { value: string; unit: string } {
  if (ms < 1) return { value: String(Math.round(ms * 1000)), unit: "µs" };
  if (ms < 1000) {
    return {
      value: ms < 10 ? ms.toFixed(1) : String(Math.round(ms)),
      unit: "ms",
    };
  }
  return { value: (ms / 1000).toFixed(2), unit: "s" };
}

function buildSparklineBuckets(
  items: readonly { timestamp?: number; value: number }[],
  earliest: number,
  latest: number,
  mode: "sum" | "rate" | "p95",
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
  const points = grouped.map((bucket) => {
    if (!bucket.length) return undefined;
    if (mode === "sum") return bucket.reduce((a, b) => a + b, 0);
    if (mode === "rate") {
      return (bucket.reduce((a, b) => a + b, 0) / bucket.length) * 100;
    }
    return percentile(bucket, 95);
  });
  const present = points.filter((p): p is number => p !== undefined);
  return present.length >= 4 ? present : [];
}

/**
 * Pure aggregation of normalized HTTP and SQL DB transaction events into
 * server golden-signals rows, KPI tiles, `DistributionBar`, `HeatMatrix`,
 * `SwimlaneTimeline`, and a single-sentence verdict.
 */
export function buildAppTransactionsAnalysis(options: {
  events: readonly {
    event: NormalizedAppTransactionEvent;
    indexName: string;
  }[];
  thresholds: ResolvedAppTransactionsThresholds;
  httpThresholds?: ResolvedAppTransactionsThresholds;
  dbThresholds?: ResolvedAppTransactionsThresholds;
  earliest: number;
  latest: number;
  outcomes: ProtocolSourceOutcome[];
  httpOutcomes?: readonly ProtocolSourceOutcome[];
  dbOutcomes?: readonly ProtocolSourceOutcome[];
  capped: boolean;
  unparsedRowCount?: number;
  httpConfigured?: boolean;
  dbConfigured?: boolean;
  streamReadiness?: StreamReadinessEntry[];
}): AppTransactionsInvestigationResult {
  const {
    events,
    thresholds,
    httpThresholds = thresholds,
    dbThresholds = thresholds,
    earliest,
    latest,
    outcomes,
    httpOutcomes,
    dbOutcomes,
    capped,
    unparsedRowCount = 0,
    httpConfigured = false,
    dbConfigured = false,
    streamReadiness,
  } = options;
  const nowSec = Math.floor(Date.now() / 1000);

  const anyBlocked = outcomes.some((o) => o.state === "blocked");
  const anyUnavailable = outcomes.some((o) => o.state === "unavailable");
  const anyDegraded = anyBlocked || anyUnavailable;
  const anyPartial =
    outcomes.some((o) => o.state === "partial") || capped || anyDegraded;

  const httpEvents = events.filter((e) => e.event.kind === "http");
  const dbEvents = events.filter((e) => e.event.kind === "db");

  const relHttpOutcomes = httpOutcomes ?? (httpConfigured ? outcomes : []);
  const relDbOutcomes = dbOutcomes ?? (dbConfigured ? outcomes : []);

  const hasActiveHttp =
    httpEvents.length > 0 ||
    (httpConfigured &&
      relHttpOutcomes.length > 0 &&
      relHttpOutcomes.every((o) => o.state === "complete" && !o.capped));
  const hasActiveDb =
    dbEvents.length > 0 ||
    (dbConfigured &&
      relDbOutcomes.length > 0 &&
      relDbOutcomes.every((o) => o.state === "complete" && !o.capped));

  const estimateStreams =
    streamReadiness?.filter((s) => s.state === "estimate_only") ?? [];

  if (!events.length) {
    if (
      estimateStreams.length > 0 &&
      !anyBlocked &&
      !anyUnavailable &&
      !anyPartial
    ) {
      const names = estimateStreams.map((s) => s.streamId).join(", ");
      const detail =
        estimateStreams.length === 1
          ? estimateStreams[0].detail
          : `Splunk Stream ${names} ${estimateStreams.length === 1 ? "is" : "are"} in Estimate mode (statsOnly=true); no transaction events are indexed.`;
      return {
        verdict: `Stream ${names} in Estimate mode (statsOnly=true); no transaction events are indexed.`,
        verdictStatus: "unknown",
        coverageStatus: "unknown",
        coverageLabel: "Estimate mode",
        hasActiveHttp: false,
        hasActiveDb: false,
        kpis: [],
        rows: [],
        matrixRows: [],
        matrixCols: [],
        matrixCells: [],
        distribution: [],
        timelineEvents: [],
        timelineRowByEventId: {},
        outcomes,
        capped,
        sourceMode: "none",
        streamReadiness,
        bannerState: "estimate_only",
        bannerReason: detail,
        checkedAt: nowSec,
      };
    }
    if (anyBlocked) {
      return {
        verdict: "Source evidence could not be read for this role.",
        verdictStatus: "unknown",
        coverageStatus: "unknown",
        coverageLabel: "Blocked",
        hasActiveHttp,
        hasActiveDb,
        kpis: [],
        rows: [],
        matrixRows: [],
        matrixCols: [],
        matrixCells: [],
        distribution: [],
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
        hasActiveHttp,
        hasActiveDb,
        kpis: [],
        rows: [],
        matrixRows: [],
        matrixCols: [],
        matrixCells: [],
        distribution: [],
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
          "Search hit row cap before matching transactions were found — narrow the UTC window or filter.",
        verdictStatus: "unknown",
        coverageStatus: "unknown",
        coverageLabel: "Capped",
        hasActiveHttp,
        hasActiveDb,
        kpis: [],
        rows: [],
        matrixRows: [],
        matrixCols: [],
        matrixCells: [],
        distribution: [],
        timelineEvents: [],
        timelineRowByEventId: {},
        outcomes,
        capped,
        sourceMode: "none",
        streamReadiness,
        bannerState: "partial",
        bannerReason:
          "Search hit row cap before matching transactions were found — narrow the UTC window or filter.",
        checkedAt: nowSec,
      };
    }
    if (unparsedRowCount > 0) {
      const noun = unparsedRowCount === 1 ? "row" : "rows";
      return {
        verdict: `${unparsedRowCount} ${noun} returned but could not be normalized — check sourcetype and field mappings.`,
        verdictStatus: "unknown",
        coverageStatus: "unknown",
        coverageLabel: "Unparsed rows",
        hasActiveHttp: false,
        hasActiveDb: false,
        kpis: [],
        rows: [],
        matrixRows: [],
        matrixCols: [],
        matrixCells: [],
        distribution: [],
        timelineEvents: [],
        timelineRowByEventId: {},
        outcomes,
        capped,
        sourceMode: "none",
        streamReadiness,
        bannerState: "unavailable",
        bannerReason: `${unparsedRowCount} ${noun} returned but could not be normalized.`,
        checkedAt: nowSec,
      };
    }
    const enabledCheck = streamReadiness?.some((s) => s.state === "enabled");
    return {
      verdict:
        "No HTTP or SQL database transactions observed in this UTC window.",
      verdictStatus: "none_observed",
      coverageStatus: "none_observed",
      coverageLabel: "None observed",
      hasActiveHttp,
      hasActiveDb,
      kpis: [],
      rows: [],
      matrixRows: [],
      matrixCols: [],
      matrixCells: [],
      distribution: [],
      timelineEvents: [],
      timelineRowByEventId: {},
      outcomes,
      capped,
      sourceMode: "none",
      streamReadiness,
      bannerState: "empty",
      bannerReason: enabledCheck
        ? "Splunk Stream is Enabled (statsOnly=false), but no matching transactions were observed in this UTC window."
        : "No matching HTTP or SQL database transactions in this UTC window.",
      checkedAt: nowSec,
    };
  }

  interface ServiceGroup {
    id: string;
    kind: AppTransactionsKind;
    protocolLabel: string;
    serverIp: string;
    destPort?: number;
    items: { event: NormalizedAppTransactionEvent; indexName: string }[];
  }

  const groups = new Map<string, ServiceGroup>();
  for (const entry of events) {
    const ev = entry.event;
    const key = `${ev.protocolLabel}\0${ev.serverIp}\0${ev.destPort ?? ""}`;
    let group = groups.get(key);
    if (!group) {
      group = {
        id: makeAppTransactionRowId(ev.protocolLabel, ev.serverIp, ev.destPort),
        kind: ev.kind,
        protocolLabel: ev.protocolLabel,
        serverIp: ev.serverIp,
        ...(ev.destPort !== undefined ? { destPort: ev.destPort } : {}),
        items: [],
      };
      groups.set(key, group);
    }
    group.items.push(entry);
  }

  const sourceMode: AppTransactionsInvestigationResult["sourceMode"] =
    httpEvents.length > 0 && dbEvents.length > 0
      ? "mixed"
      : httpEvents.length > 0
        ? "http_only"
        : dbEvents.length > 0
          ? "db_only"
          : "none";

  const rows: AppTransactionsServiceRow[] = [];
  const timelineCandidates: {
    event: ProtocolTimelineEvent;
    rowId: string;
  }[] = [];

  for (const group of groups.values()) {
    const rowThresholds = group.kind === "http" ? httpThresholds : dbThresholds;
    const sourcetypes = [
      ...new Set(group.items.map((i) => i.event.sourcetype)),
    ];
    const txnCount = group.items.length;
    const latencies: number[] = [];
    let statusSampleCount = 0;
    let errorCount = 0;
    let http5xxCount = 0;
    let http4xxCount = 0;
    let sqlErrorCount = 0;
    let totalBytesIn = 0;
    let totalBytesOut = 0;
    let totalRowsReturned = 0;
    let hasRowsReturned = false;
    let firstSeen: number | undefined;
    let lastSeen: number | undefined;

    const pathStats = new Map<string, { count: number; errorCount: number }>();
    const dbStats = new Map<string, { count: number; errorCount: number }>();
    const siteCounts = new Map<string, number>();
    const errorCodeCounts = new Map<string, number>();
    const clientStats = new Map<
      string,
      { count: number; errorCount: number }
    >();

    const serverMatrixLabel =
      group.destPort !== undefined
        ? `${group.serverIp}:${group.destPort}`
        : group.serverIp;

    for (let idx = 0; idx < group.items.length; idx += 1) {
      const ev = group.items[idx].event;
      if (ev.latencyMs !== undefined) latencies.push(ev.latencyMs);
      if (ev.hasStatusSample) statusSampleCount += 1;
      if (ev.isError) errorCount += 1;
      if (ev.errorKind === "http_5xx") http5xxCount += 1;
      else if (ev.errorKind === "http_4xx") http4xxCount += 1;
      else if (ev.errorKind === "sql_error") sqlErrorCount += 1;

      if (ev.errorLabel) {
        errorCodeCounts.set(
          ev.errorLabel,
          (errorCodeCounts.get(ev.errorLabel) ?? 0) + 1,
        );
      }

      if (ev.bytesIn !== undefined) totalBytesIn += ev.bytesIn;
      if (ev.bytesOut !== undefined) totalBytesOut += ev.bytesOut;
      if (ev.rowsReturned !== undefined) {
        hasRowsReturned = true;
        totalRowsReturned += ev.rowsReturned;
      }

      if (ev.timestamp !== undefined) {
        firstSeen =
          firstSeen === undefined
            ? ev.timestamp
            : Math.min(firstSeen, ev.timestamp);
        lastSeen =
          lastSeen === undefined
            ? ev.timestamp
            : Math.max(lastSeen, ev.timestamp);
      }

      if (ev.site) {
        siteCounts.set(ev.site, (siteCounts.get(ev.site) ?? 0) + 1);
      }
      if (ev.uriPath) {
        const cur = pathStats.get(ev.uriPath) ?? { count: 0, errorCount: 0 };
        cur.count += 1;
        if (ev.isError) cur.errorCount += 1;
        pathStats.set(ev.uriPath, cur);
      }
      if (ev.dbName) {
        const cur = dbStats.get(ev.dbName) ?? { count: 0, errorCount: 0 };
        cur.count += 1;
        if (ev.isError) cur.errorCount += 1;
        dbStats.set(ev.dbName, cur);
      }
      if (ev.srcIp) {
        const cur = clientStats.get(ev.srcIp) ?? { count: 0, errorCount: 0 };
        cur.count += 1;
        if (ev.isError) cur.errorCount += 1;
        clientStats.set(ev.srcIp, cur);
      }

      if (ev.timestamp !== undefined) {
        const slow =
          ev.latencyMs !== undefined &&
          ev.latencyMs >= rowThresholds.latencyWarnMs;
        if (ev.isError || slow) {
          let label: string;
          if (ev.errorKind === "http_5xx" && ev.httpStatus !== undefined) {
            label = `HTTP ${ev.httpStatus}`;
          } else if (
            ev.errorKind === "http_4xx" &&
            ev.httpStatus !== undefined
          ) {
            label = `HTTP ${ev.httpStatus}`;
          } else if (ev.errorKind === "sql_error") {
            label = ev.sqlErrorCode
              ? `SQL error ${ev.sqlErrorCode}`
              : `SQL error (${ev.errorLabel ?? "failed"})`;
          } else {
            label = `Slow txn (${formatDurationMs(ev.latencyMs)})`;
          }
          const targetPart = ev.uriPath
            ? ` ${ev.httpMethod ? `${ev.httpMethod} ` : ""}${ev.uriPath}`
            : ev.dbName
              ? ` db=${ev.dbName}`
              : "";
          const latencyPart =
            ev.latencyMs !== undefined
              ? ` (${formatDurationMs(ev.latencyMs)})`
              : "";
          timelineCandidates.push({
            event: {
              id: `${group.id}_${idx}_${ev.timestamp}`,
              lane: serverMatrixLabel,
              timestamp: ev.timestamp,
              kind: "attention",
              label,
              detail: `${ev.srcIp ?? "client"} → ${serverMatrixLabel}${targetPart} · ${label}${latencyPart}`,
            },
            rowId: group.id,
          });
        }
      }
    }

    const errorPct =
      statusSampleCount > 0
        ? (errorCount / statusSampleCount) * 100
        : undefined;
    const latencyP50Ms = percentile(latencies, 50);
    const latencyP95Ms = percentile(latencies, 95);
    const latencyMaxMs = latencies.length ? Math.max(...latencies) : undefined;

    const reasons: string[] = [];
    if (errorPct !== undefined && errorPct >= rowThresholds.errorRateWarnPct) {
      if (group.kind === "http") {
        if (http5xxCount > 0 && http4xxCount > 0) {
          reasons.push(
            `${errorPct.toFixed(1)}% HTTP errors (${http5xxCount} 5xx, ${http4xxCount} 4xx)`,
          );
        } else if (http5xxCount > 0) {
          reasons.push(`${errorPct.toFixed(1)}% HTTP 5xx errors`);
        } else {
          reasons.push(`${errorPct.toFixed(1)}% HTTP 4xx errors`);
        }
      } else {
        reasons.push(`${errorPct.toFixed(1)}% SQL errors (${sqlErrorCount})`);
      }
    }
    if (
      latencyP95Ms !== undefined &&
      latencyP95Ms >= rowThresholds.latencyWarnMs
    ) {
      reasons.push(`p95 latency ${formatDurationMs(latencyP95Ms)}`);
    }

    const attention = reasons.length > 0;
    const status: ProtocolStatus = attention ? "attention" : "ok";

    const topSite = [...siteCounts.entries()].sort(
      (a, b) => b[1] - a[1],
    )[0]?.[0];
    const topDb = [...dbStats.entries()].sort(
      (a, b) => b[1].count - a[1].count,
    )[0]?.[0];
    const serviceName = topSite ?? topDb;

    const topPathsOrDatabases: AppTransactionEndpointBreakdown[] = [
      ...(group.kind === "http" ? pathStats.entries() : dbStats.entries()),
    ]
      .map(([label, stats]) => ({
        label,
        count: stats.count,
        errorCount: stats.errorCount,
      }))
      .sort(
        (a, b) =>
          b.errorCount - a.errorCount ||
          b.count - a.count ||
          a.label.localeCompare(b.label),
      )
      .slice(0, 5);

    const topErrors: AppTransactionErrorBreakdown[] = [
      ...errorCodeCounts.entries(),
    ]
      .map(([code, count]) => ({ code, count }))
      .sort((a, b) => b.count - a.count || a.code.localeCompare(b.code))
      .slice(0, 5);

    const topClients: AppTransactionClientBreakdown[] = [
      ...clientStats.entries(),
    ]
      .map(([clientIp, stats]) => ({
        clientIp,
        count: stats.count,
        errorCount: stats.errorCount,
      }))
      .sort(
        (a, b) =>
          b.errorCount - a.errorCount ||
          b.count - a.count ||
          a.clientIp.localeCompare(b.clientIp),
      )
      .slice(0, 5);

    const protocolDisplay =
      group.destPort !== undefined
        ? `${group.protocolLabel} · ${group.destPort}`
        : group.protocolLabel;

    rows.push({
      id: group.id,
      attention,
      kind: group.kind,
      protocolLabel: group.protocolLabel,
      protocolDisplay,
      serverIp: group.serverIp,
      ...(group.destPort !== undefined ? { destPort: group.destPort } : {}),
      serverMatrixLabel,
      ...(serviceName ? { serviceName } : {}),
      sourcetypes,
      txnCount,
      statusSampleCount,
      errorCount,
      http5xxCount,
      http4xxCount,
      sqlErrorCount,
      ...(errorPct !== undefined ? { errorPct } : {}),
      ...(latencyP50Ms !== undefined ? { latencyP50Ms } : {}),
      ...(latencyP95Ms !== undefined ? { latencyP95Ms } : {}),
      ...(latencyMaxMs !== undefined ? { latencyMaxMs } : {}),
      totalBytesIn,
      totalBytesOut,
      ...(hasRowsReturned ? { totalRowsReturned } : {}),
      topPathsOrDatabases,
      topErrors,
      topClients,
      status,
      reasons,
      indexName: group.items[0].indexName,
      ...(firstSeen !== undefined ? { firstSeen } : {}),
      ...(lastSeen !== undefined ? { lastSeen } : {}),
    });
  }

  rows.sort((a, b) => {
    if (a.attention !== b.attention) return a.attention ? -1 : 1;
    if ((b.errorPct ?? -1) !== (a.errorPct ?? -1)) {
      return (b.errorPct ?? -1) - (a.errorPct ?? -1);
    }
    if ((b.latencyP95Ms ?? -1) !== (a.latencyP95Ms ?? -1)) {
      return (b.latencyP95Ms ?? -1) - (a.latencyP95Ms ?? -1);
    }
    if (b.txnCount !== a.txnCount) return b.txnCount - a.txnCount;
    return a.id.localeCompare(b.id);
  });

  // 4 single-metric KPI tiles with explicit units
  const totalTxns = rows.reduce((sum, r) => sum + r.txnCount, 0);
  const totalSamples = rows.reduce((sum, r) => sum + r.statusSampleCount, 0);
  const totalErrors = rows.reduce((sum, r) => sum + r.errorCount, 0);
  const overallErrorPct =
    totalSamples > 0 ? (totalErrors / totalSamples) * 100 : undefined;

  const allLatencies = events
    .map((e) => e.event.latencyMs)
    .filter((v): v is number => v !== undefined);
  const overallP95Ms = percentile(allLatencies, 95);
  const flaggedRows = rows.filter((r) => r.attention);

  const txnSpark = buildSparklineBuckets(
    events.map((e) => ({ timestamp: e.event.timestamp, value: 1 })),
    earliest,
    latest,
    "sum",
  );
  const errSpark = buildSparklineBuckets(
    events
      .filter((e) => e.event.hasStatusSample)
      .map((e) => ({
        timestamp: e.event.timestamp,
        value: e.event.isError ? 1 : 0,
      })),
    earliest,
    latest,
    "rate",
  );
  const latSpark = buildSparklineBuckets(
    events
      .filter((e) => e.event.latencyMs !== undefined)
      .map((e) => ({
        timestamp: e.event.timestamp,
        value: e.event.latencyMs!,
      })),
    earliest,
    latest,
    "p95",
  );

  const latencyParts =
    overallP95Ms !== undefined ? splitDurationParts(overallP95Ms) : undefined;

  const kpis: ProtocolKpi[] = [
    {
      id: "transactions",
      label: "Transactions",
      value: formatCount(totalTxns),
      unit: totalTxns === 1 ? "txn" : "txns",
      status: "ok",
      ...(txnSpark.length ? { sparkline: txnSpark } : {}),
    },
    {
      id: "error-rate",
      label: "Error Rate",
      value:
        overallErrorPct !== undefined
          ? overallErrorPct.toFixed(1)
          : "Not covered",
      ...(overallErrorPct !== undefined ? { unit: "%" } : {}),
      status:
        overallErrorPct === undefined
          ? "not_covered"
          : overallErrorPct >= thresholds.errorRateWarnPct
            ? "attention"
            : "ok",
      ...(errSpark.length ? { sparkline: errSpark } : {}),
    },
    {
      id: "p95-latency",
      label: "p95 Latency",
      value: latencyParts ? latencyParts.value : "Not covered",
      ...(latencyParts ? { unit: latencyParts.unit } : {}),
      status:
        overallP95Ms === undefined
          ? "not_covered"
          : overallP95Ms >= thresholds.latencyWarnMs
            ? "attention"
            : "ok",
      ...(latSpark.length ? { sparkline: latSpark } : {}),
    },
    {
      id: "flagged-services",
      label: "Flagged Services",
      value: formatCount(flaggedRows.length),
      unit: flaggedRows.length === 1 ? "service" : "services",
      status: flaggedRows.length > 0 ? "attention" : "ok",
    },
  ];

  // p50 / p95 DistributionBar
  const distribution: ProtocolDistributionMetric[] = rows
    .filter((r) => r.latencyP50Ms !== undefined && r.latencyP95Ms !== undefined)
    .slice(0, 6)
    .map((r) => {
      const rowWarnMs =
        r.kind === "http"
          ? httpThresholds.latencyWarnMs
          : dbThresholds.latencyWarnMs;
      return {
        id: r.id,
        label: r.serviceName ?? r.serverMatrixLabel,
        p50: roundMetric(r.latencyP50Ms!),
        p95: roundMetric(r.latencyP95Ms!),
        ...(r.latencyMaxMs !== undefined
          ? { max: roundMetric(r.latencyMaxMs) }
          : {}),
        unit: "ms",
        status:
          r.latencyP95Ms! >= rowWarnMs || r.attention ? "attention" : "ok",
      };
    });

  // Client x Server HeatMatrix
  interface PairBucket {
    client: string;
    server: string;
    row: AppTransactionsServiceRow;
    count: number;
    sampleCount: number;
    errorCount: number;
    latencies: number[];
  }
  const rowByServerKey = new Map<string, AppTransactionsServiceRow>();
  for (const r of rows) {
    rowByServerKey.set(
      `${r.protocolLabel}\0${r.serverIp}\0${r.destPort ?? ""}`,
      r,
    );
  }

  const pairBuckets = new Map<string, PairBucket>();
  for (const entry of events) {
    const ev = entry.event;
    if (!ev.srcIp) continue;
    const rowKey = `${ev.protocolLabel}\0${ev.serverIp}\0${ev.destPort ?? ""}`;
    const serviceRow = rowByServerKey.get(rowKey);
    if (!serviceRow) continue;
    const col = serviceRow.serverMatrixLabel;
    const bucketKey = `${ev.srcIp}\0${col}`;
    let bucket = pairBuckets.get(bucketKey);
    if (!bucket) {
      bucket = {
        client: ev.srcIp,
        server: col,
        row: serviceRow,
        count: 0,
        sampleCount: 0,
        errorCount: 0,
        latencies: [],
      };
      pairBuckets.set(bucketKey, bucket);
    }
    bucket.count += 1;
    if (ev.hasStatusSample) bucket.sampleCount += 1;
    if (ev.isError) bucket.errorCount += 1;
    if (ev.latencyMs !== undefined) bucket.latencies.push(ev.latencyMs);
  }

  const flaggedClients = new Set<string>();
  const flaggedServers = new Set<string>();
  const matrixCells: ProtocolMatrixCell[] = [];

  for (const bucket of pairBuckets.values()) {
    const rowThresholds =
      bucket.row.kind === "http" ? httpThresholds : dbThresholds;
    const pairErrPct =
      bucket.sampleCount > 0
        ? (bucket.errorCount / bucket.sampleCount) * 100
        : undefined;
    const pairP95 = percentile(bucket.latencies, 95);
    const errBreach =
      pairErrPct !== undefined && pairErrPct >= rowThresholds.errorRateWarnPct;
    const latBreach =
      pairP95 !== undefined && pairP95 >= rowThresholds.latencyWarnMs;
    const isFlagged = errBreach || latBreach;

    if (isFlagged) {
      flaggedClients.add(bucket.client);
      flaggedServers.add(bucket.server);
    }

    let value = `${formatCount(bucket.count)} ${bucket.count === 1 ? "txn" : "txns"}`;
    if (errBreach && pairErrPct !== undefined) {
      value = `${pairErrPct.toFixed(1)}% err`;
    } else if (latBreach && pairP95 !== undefined) {
      value = `${formatDurationMs(pairP95)} p95`;
    }

    const detailParts = [
      `${bucket.count} ${bucket.count === 1 ? "txn" : "txns"}`,
      ...(pairErrPct !== undefined
        ? [
            `${pairErrPct.toFixed(1)}% errors (${bucket.errorCount}/${bucket.sampleCount})`,
          ]
        : []),
      ...(pairP95 !== undefined ? [`p95 ${formatDurationMs(pairP95)}`] : []),
    ];

    matrixCells.push({
      row: bucket.client,
      col: bucket.server,
      status: isFlagged ? "attention" : "ok",
      value,
      count: bucket.count,
      detail: detailParts.join(" · "),
      itemId: bucket.row.id,
    });
  }

  const matrixRows = [...new Set(matrixCells.map((c) => c.row))].sort(
    (a, b) => {
      const aFlag = flaggedClients.has(a);
      const bFlag = flaggedClients.has(b);
      if (aFlag !== bFlag) return aFlag ? -1 : 1;
      return a.localeCompare(b);
    },
  );
  const matrixCols = [...new Set(matrixCells.map((c) => c.col))].sort(
    (a, b) => {
      const aFlag = flaggedServers.has(a);
      const bFlag = flaggedServers.has(b);
      if (aFlag !== bFlag) return aFlag ? -1 : 1;
      return a.localeCompare(b);
    },
  );

  // SwimlaneTimeline sorted chronologically, bounded to 128 events
  timelineCandidates.sort((a, b) => a.event.timestamp - b.event.timestamp);
  const boundedTimeline = timelineCandidates.slice(0, 128);
  const timelineEvents = boundedTimeline.map((e) => e.event);
  const timelineRowByEventId: Record<string, string> = {};
  for (const item of boundedTimeline) {
    timelineRowByEventId[item.event.id] = item.rowId;
  }

  // Single-sentence plain-language verdict above the fold
  let verdict: string;
  let verdictStatus: ProtocolStatus;
  if (flaggedRows.length > 0) {
    const lead = flaggedRows[0];
    const leadReason = lead.reasons[0] ?? "threshold exceeded";
    verdict = `${flaggedRows.length} of ${rows.length} ${rows.length === 1 ? "service needs" : "services need"} attention: ${leadReason} on ${lead.protocolLabel} ${lead.serverMatrixLabel}.`;
    verdictStatus = "attention";
  } else {
    verdict = `${rows.length} of ${rows.length} ${rows.length === 1 ? "service" : "services"} healthy across ${formatCount(totalTxns)} transactions.`;
    verdictStatus = "ok";
  }

  const coverageStatus: ProtocolStatus = anyPartial
    ? "attention"
    : estimateStreams.length > 0
      ? "unknown"
      : "ok";
  const activeCount = outcomes.filter(
    (o) => o.state === "complete" || o.state === "partial",
  ).length;
  const coverageLabel =
    estimateStreams.length > 0 && !anyPartial
      ? "Estimate mode"
      : `${activeCount} ${activeCount === 1 ? "source" : "sources"}`;

  const blockedDetail = outcomes.find((o) => o.state === "blocked")?.detail;
  const unavailableDetail = outcomes.find(
    (o) => o.state === "unavailable",
  )?.detail;

  let bannerState: AppTransactionsInvestigationResult["bannerState"];
  let bannerReason: string | undefined;

  if (anyPartial) {
    bannerState = "partial";
    bannerReason = anyBlocked
      ? `One or more sources denied access (${blockedDetail ?? "access denied"}); results are incomplete.`
      : anyUnavailable
        ? `One or more sources failed (${unavailableDetail ?? "search unavailable"}); results are incomplete.`
        : "Search hit row cap or partial source — narrow the UTC window or filter.";
  } else if (estimateStreams.length > 0) {
    bannerState = "estimate_only";
    const names = estimateStreams.map((s) => s.streamId).join(", ");
    bannerReason =
      estimateStreams.length === 1
        ? estimateStreams[0].detail
        : `Stream ${names} in Estimate mode (statsOnly=true); switch to Enabled to index events.`;
  }

  return {
    verdict,
    verdictStatus,
    coverageStatus,
    coverageLabel,
    hasActiveHttp,
    hasActiveDb,
    kpis,
    rows,
    matrixRows,
    matrixCols,
    matrixCells,
    distribution,
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

export interface InvestigateAppTransactionsOptions {
  skipEstimateCheck?: boolean;
  skipConfigRecheck?: boolean;
  profileValidators?: Partial<Record<ProtocolLensId, LensProfileValidator>>;
}

/**
 * Executes the on-demand HTTP & DB Transactions investigation across configured
 * `app_transactions` profiles (`stream:http`, `stream:mysql`, `stream:postgres`,
 * `stream:tds`, `stream:tns`), verifying `adm_protocol_profiles` fingerprint
 * before committing results.
 */
export async function investigateAppTransactions(
  client: SearchClient,
  request: ProtocolRequest,
  configuration: ProtocolConfiguration,
  signal: AbortSignal,
  options: InvestigateAppTransactionsOptions = {},
): Promise<AppTransactionsInvestigationResult> {
  const scoped = configuration.profiles.filter(
    (p) => p.lens === "app_transactions" && p.scope === request.scope,
  );
  if (!scoped.length) {
    return {
      verdict: "No active source profile covers this scope.",
      verdictStatus: "not_covered",
      coverageStatus: "not_covered",
      coverageLabel: "Not covered",
      hasActiveHttp: false,
      hasActiveDb: false,
      kpis: [],
      rows: [],
      matrixRows: [],
      matrixCols: [],
      matrixCells: [],
      distribution: [],
      timelineEvents: [],
      timelineRowByEventId: {},
      outcomes: [],
      capped: false,
      sourceMode: "none",
      bannerState: "unavailable",
      bannerReason: `No app_transactions profile configured for scope "${request.scope}".`,
      checkedAt: Math.floor(Date.now() / 1000),
    };
  }

  const httpProfiles = scoped.filter((p) => {
    const sk = resolveAppTransactionsThresholds(p).sourceKind;
    return sk === "http" || sk === "auto";
  });
  const dbProfiles = scoped.filter((p) => {
    const sk = resolveAppTransactionsThresholds(p).sourceKind;
    return sk === "db" || sk === "auto";
  });

  const runProfiles = async () => {
    const outcomes: ProtocolSourceOutcome[] = [];
    const httpOutcomes: ProtocolSourceOutcome[] = [];
    const dbOutcomes: ProtocolSourceOutcome[] = [];
    const collected: {
      event: NormalizedAppTransactionEvent;
      indexName: string;
    }[] = [];
    let rawRowCount = 0;
    let httpRawCount = 0;
    let dbRawCount = 0;
    let capped = false;

    const chosenThresholds = resolveAppTransactionsThresholds(scoped[0]);
    const httpThresholds = resolveAppTransactionsThresholds(
      httpProfiles[0] ?? scoped[0],
    );
    const dbThresholds = resolveAppTransactionsThresholds(
      dbProfiles[0] ?? scoped[0],
    );

    for (const profile of httpProfiles) {
      signal.throwIfAborted();
      const spl = buildAppTransactionsSearch({
        index: profile.index,
        kind: "http",
        filter: request.filter,
        maxRows: MAX_INPUT_ROWS,
      });
      const res = await runBoundedProtocolSearch(client, {
        lens: "app_transactions",
        profile,
        spl,
        earliest: request.earliest,
        latest: request.latest,
        maxRows: MAX_INPUT_ROWS,
        signal,
        keySuffix: "http",
      });
      outcomes.push(res.outcome);
      httpOutcomes.push(res.outcome);
      if (res.capped) capped = true;
      rawRowCount += res.rows.length;
      httpRawCount += res.rows.length;
      for (const row of res.rows) {
        const norm = normalizeAppTransactionRow(row, "http");
        if (norm) collected.push({ event: norm, indexName: profile.index });
      }
    }

    for (const profile of dbProfiles) {
      signal.throwIfAborted();
      const spl = buildAppTransactionsSearch({
        index: profile.index,
        kind: "db",
        filter: request.filter,
        maxRows: MAX_INPUT_ROWS,
      });
      const res = await runBoundedProtocolSearch(client, {
        lens: "app_transactions",
        profile,
        spl,
        earliest: request.earliest,
        latest: request.latest,
        maxRows: MAX_INPUT_ROWS,
        signal,
        keySuffix: "db",
      });
      outcomes.push(res.outcome);
      dbOutcomes.push(res.outcome);
      if (res.capped) capped = true;
      rawRowCount += res.rows.length;
      dbRawCount += res.rows.length;
      for (const row of res.rows) {
        const norm = normalizeAppTransactionRow(row, "db");
        if (norm) collected.push({ event: norm, indexName: profile.index });
      }
    }

    // Explicit Stream Estimate-mode check ONLY during investigation when a
    // queried Stream group completed with 0 rows.
    const httpCompletedEmpty =
      httpProfiles.length > 0 &&
      httpRawCount === 0 &&
      httpOutcomes.some((o) => o.state === "complete");
    const dbCompletedEmpty =
      dbProfiles.length > 0 &&
      dbRawCount === 0 &&
      dbOutcomes.some((o) => o.state === "complete");

    const streamIdsToCheck: AppTransactionsStreamId[] = [
      ...(httpCompletedEmpty ? (["http"] as const) : []),
      ...(dbCompletedEmpty
        ? (["mysql", "postgres", "tds", "tns"] as const)
        : []),
    ];

    let streamReadiness: StreamReadinessEntry[] | undefined;
    if (streamIdsToCheck.length > 0 && !options.skipEstimateCheck) {
      streamReadiness = await checkStreamEstimateMode(
        client,
        streamIdsToCheck,
        signal,
      );
      const estimateEntries = streamReadiness.filter(
        (e) => e.state === "estimate_only",
      );
      if (estimateEntries.length > 0) {
        outcomes.push({
          source: "protocol_stream_readiness",
          state: "estimate_only",
          detail: estimateEntries
            .map((e) => `${e.streamId}: ${e.detail}`)
            .join("; "),
        });
      }
    }

    const unparsedRowCount = Math.max(0, rawRowCount - collected.length);

    return buildAppTransactionsAnalysis({
      events: collected,
      thresholds: chosenThresholds,
      httpThresholds,
      dbThresholds,
      earliest: request.earliest,
      latest: request.latest,
      outcomes,
      httpOutcomes,
      dbOutcomes,
      capped,
      unparsedRowCount,
      httpConfigured: httpProfiles.length > 0,
      dbConfigured: dbProfiles.length > 0,
      streamReadiness,
    });
  };

  if (options.skipConfigRecheck || !configuration.fingerprint) {
    return runProfiles();
  }

  const validators: Partial<Record<ProtocolLensId, LensProfileValidator>> = {
    ...options.profileValidators,
    app_transactions: validateAppTransactionsExtra,
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
        hasActiveHttp: false,
        hasActiveDb: false,
        kpis: [],
        rows: [],
        matrixRows: [],
        matrixCols: [],
        matrixCells: [],
        distribution: [],
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
 * Hub "Check all" summary runner for `app_transactions`.
 */
export async function summarizeAppTransactions(
  client: SearchClient,
  request: ProtocolRequest,
  configuration: ProtocolConfiguration,
  signal: AbortSignal,
  options?: InvestigateAppTransactionsOptions,
): Promise<ProtocolLensSummary> {
  const result = await investigateAppTransactions(
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
    lens: "app_transactions",
    status,
    verdict: result.verdict,
    checkedAt: result.checkedAt,
    capped: result.capped,
    outcomes: result.outcomes,
  };
}
