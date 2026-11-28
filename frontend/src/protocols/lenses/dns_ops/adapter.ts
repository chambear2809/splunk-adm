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
  DEFAULT_DNS_OPS_THRESHOLDS,
  validateDnsOpsExtra,
  type DnsOpsExtraConfig,
  type DnsOpsSourcetype,
  type ResolvedDnsOpsThresholds,
} from "./validate";

export {
  DEFAULT_DNS_OPS_THRESHOLDS,
  validateDnsOpsExtra,
  type DnsOpsExtraConfig,
  type DnsOpsSourcetype,
  type ResolvedDnsOpsThresholds,
};

export function resolveDnsOpsThresholds(
  profile?: BaseProtocolProfile,
): ResolvedDnsOpsThresholds {
  const extra = profile?.extra as DnsOpsExtraConfig | undefined;
  return {
    sourcetype:
      extra?.sourcetype === "cilium:hubble:flow"
        ? "cilium:hubble:flow"
        : DEFAULT_DNS_OPS_THRESHOLDS.sourcetype,
    latencyWarnMs:
      typeof extra?.latencyWarnMs === "number"
        ? extra.latencyWarnMs
        : DEFAULT_DNS_OPS_THRESHOLDS.latencyWarnMs,
    nxdomainWarnPct:
      typeof extra?.nxdomainWarnPct === "number"
        ? extra.nxdomainWarnPct
        : DEFAULT_DNS_OPS_THRESHOLDS.nxdomainWarnPct,
    servfailWarnPct:
      typeof extra?.servfailWarnPct === "number"
        ? extra.servfailWarnPct
        : DEFAULT_DNS_OPS_THRESHOLDS.servfailWarnPct,
  };
}

export const DNS_STREAM_PROJECTED_FIELDS = [
  "_time",
  "host",
  "sourcetype",
  "src_ip",
  "dest_ip",
  "query",
  "query_type",
  "reply_code",
  "reply_code_id",
  "message_type",
  "response_time",
  "time_taken",
  "ttl",
  "answer",
  "answers",
  "host_addr",
  "transaction_id",
] as const;

export const HUBBLE_DNS_PROJECTED_FIELDS = [
  "_time",
  "host",
  "sourcetype",
  "src_ip",
  "dest_ip",
  "message_type",
  "query",
  "query_type",
  "reply_code_id",
  "answer",
  "flow.l7.dns.query",
  "flow.l7.dns.rcode",
  "flow.l7.dns.ips",
  "flow.l7.dns.qtypes",
  "flow.l7.dns.ttl",
] as const;

/**
 * Builds a bounded, allowlisted SPL query for `stream:dns` or `cilium:hubble:flow`.
 * Emits `| head <maxRows + 1>` before `| table <allowlisted fields>` so indexers
 * cap rows and drop `_raw` server-side without sorting the full index.
 */
export function buildDnsOpsSearch(options: {
  index: string;
  sourcetype: DnsOpsSourcetype;
  filter?: ProtocolFilter;
  maxRows: number;
}): string {
  const index = literal(options.index, 80);
  const headLimit = Math.max(1, Math.trunc(options.maxRows)) + 1;

  if (options.sourcetype === "cilium:hubble:flow") {
    const predicates: string[] = [
      `index=${index}`,
      `sourcetype="cilium:hubble:flow"`,
      `(flow.l7.dns.query=* OR query=*)`,
    ];
    predicates.push(
      ...buildFlowEndpointPredicates({
        filter: options.filter,
        srcFields: ["src_ip", "flow.IP.source", "flow.IP.destination"],
        dstFields: ["dest_ip", "flow.IP.destination", "flow.IP.source"],
        portFields: [
          "dest_port",
          "src_port",
          "flow.l4.UDP.destination_port",
          "flow.l4.UDP.source_port",
          "flow.l4.TCP.destination_port",
          "flow.l4.TCP.source_port",
        ],
      }),
    );
    if (options.filter?.device) {
      const dev = literal(options.filter.device, 128);
      predicates.push(
        `(host="${dev}" OR node_name="${dev}" OR flow.node_name="${dev}")`,
      );
    }
    const tableClause = buildAllowedFieldsClause(
      "dns_ops",
      HUBBLE_DNS_PROJECTED_FIELDS,
    );
    return (
      `search ${predicates.join(" ")} ` +
      `| head ${headLimit} ` +
      `| spath path=flow.l7.dns.query output=hubble_query ` +
      `| spath path=flow.l7.dns.qtypes{} output=hubble_qtype ` +
      `| spath path=flow.l7.dns.rcode output=hubble_rcode ` +
      `| spath path=flow.l7.dns.ips{} output=hubble_ips ` +
      `| spath path=flow.IP.source output=hubble_src ` +
      `| spath path=flow.IP.destination output=hubble_dst ` +
      `| spath path=flow.l7.type output=hubble_l7_type ` +
      `| spath path=flow.is_reply output=hubble_is_reply ` +
      `| eval query=coalesce(query, hubble_query, 'flow.l7.dns.query'), ` +
      `query_type=coalesce(query_type, hubble_qtype, 'flow.l7.dns.qtypes{}'), ` +
      `reply_code_id=coalesce(reply_code_id, hubble_rcode, 'flow.l7.dns.rcode'), ` +
      `answer=coalesce(answer, hubble_ips, 'flow.l7.dns.ips{}', 'flow.l7.dns.ips'), ` +
      `message_type=coalesce(message_type, hubble_l7_type, 'flow.l7.type'), ` +
      `src_ip=coalesce(src_ip, if(upper(message_type)=="RESPONSE" OR lower(coalesce(hubble_is_reply, 'flow.is_reply'))=="true", coalesce(hubble_dst, 'flow.IP.destination'), coalesce(hubble_src, 'flow.IP.source'))), ` +
      `dest_ip=coalesce(dest_ip, if(upper(message_type)=="RESPONSE" OR lower(coalesce(hubble_is_reply, 'flow.is_reply'))=="true", coalesce(hubble_src, 'flow.IP.source'), coalesce(hubble_dst, 'flow.IP.destination'))) ` +
      tableClause
    );
  }

  const predicates: string[] = [`index=${index}`, `sourcetype="stream:dns"`];
  predicates.push(
    ...buildFlowEndpointPredicates({
      filter: options.filter,
      srcFields: ["src_ip"],
      dstFields: ["dest_ip"],
      portFields: ["dest_port", "src_port"],
    }),
  );
  if (options.filter?.device) {
    predicates.push(`host="${literal(options.filter.device, 128)}"`);
  }
  const tableClause = buildAllowedFieldsClause(
    "dns_ops",
    DNS_STREAM_PROJECTED_FIELDS,
  );
  return `search ${predicates.join(" ")} | head ${headLimit} ${tableClause}`;
}

/**
 * Builds a safe Splunk Search URL for raw events of a selected client→resolver pair.
 */
export function buildDnsOpsRawEventsUrl(options: {
  index: string;
  sourcetype: DnsOpsSourcetype;
  client: string;
  resolver: string;
  earliest: number;
  latest: number;
}): string {
  const index = literal(options.index, 80);
  const src = literal(options.client, 128);
  const dst = literal(options.resolver, 128);
  const q =
    options.sourcetype === "cilium:hubble:flow"
      ? `search index=${index} sourcetype="cilium:hubble:flow" (flow.l7.dns.query=* OR query=*) (src_ip="${src}" OR flow.IP.source="${src}" OR flow.IP.destination="${src}") (dest_ip="${dst}" OR flow.IP.destination="${dst}" OR flow.IP.source="${dst}")`
      : `search index=${index} sourcetype="stream:dns" src_ip="${src}" dest_ip="${dst}"`;
  const params = new URLSearchParams({
    q,
    earliest: String(Math.trunc(options.earliest)),
    latest: String(Math.trunc(options.latest)),
  });
  return `/app/splunk_adm/search?${params.toString()}`;
}

export type CanonicalRcode =
  "NOERROR" | "NXDOMAIN" | "SERVFAIL" | "REFUSED" | "OTHER";

export interface NormalizedDnsOpsEvent {
  sourceType: DnsOpsSourcetype;
  timestamp: number | undefined;
  host: string;
  client: string;
  resolver: string;
  query?: string;
  queryTypes: string[];
  messageTypes: string[];
  rcode?: CanonicalRcode;
  latencyMs?: number;
  answers: string[];
  ttlSeconds?: number;
}

export interface FailingDomainSummary {
  query: string;
  rcode: CanonicalRcode;
  count: number;
}

export interface AnswerChurnDomainSummary {
  query: string;
  distinctAnswers: string[];
}

export interface DnsOpsPairRow {
  /** URL-safe `ITEM_ID` matching `^[A-Za-z0-9][A-Za-z0-9._:/@[\]-]{0,191}$` (`client__resolver`). */
  id: string;
  attention: boolean;
  client: string;
  resolver: string;
  sourceKind: "stream_dns" | "hubble_only";
  queryCount: number;
  responseCount: number;
  nxdomainCount: number;
  servfailCount: number;
  refusedCount: number;
  nxdomainPct?: number;
  servfailPct?: number;
  refusedPct?: number;
  latencyP50Ms?: number;
  latencyP95Ms?: number;
  answerChurnCount: number;
  answerChurnSummary: string;
  answerChurnDomains: AnswerChurnDomainSummary[];
  topFailingDomains: FailingDomainSummary[];
  searchSuffixHint?: string;
  searchSuffixDomains: string[];
  status: ProtocolStatus;
  reasons: string[];
  indexName: string;
  firstSeen?: number;
  lastSeen?: number;
}

export interface DnsOpsInvestigationResult {
  verdict: string;
  verdictStatus: ProtocolStatus;
  coverageStatus: ProtocolStatus;
  coverageLabel: string;
  kpis: ProtocolKpi[];
  rows: DnsOpsPairRow[];
  matrixRows: string[];
  matrixCols: string[];
  matrixCells: ProtocolMatrixCell[];
  distribution: ProtocolDistributionMetric[];
  outcomes: ProtocolSourceOutcome[];
  capped: boolean;
  sourceMode: "stream_dns" | "hubble_only" | "mixed" | "none";
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

function asString(value: unknown): string {
  if (typeof value === "string") return value.trim();
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  return "";
}

function asStringArray(value: unknown): string[] {
  if (Array.isArray(value)) {
    return value.flatMap((v) => asStringArray(v));
  }
  if (typeof value === "string") {
    const trimmed = value.trim();
    return trimmed ? [trimmed] : [];
  }
  if (typeof value === "number" && Number.isFinite(value)) {
    return [String(value)];
  }
  return [];
}

function asFiniteNumber(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim()) {
    const num = Number(value);
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

function asObject(value: unknown): Record<string, unknown> | undefined {
  if (value && typeof value === "object" && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  return undefined;
}

function normalizeQueryName(value: unknown): string | undefined {
  const first = asStringArray(value)[0];
  if (!first) return undefined;
  const cleaned = first.replace(/\.+$/, "").toLowerCase();
  return cleaned || undefined;
}

export function normalizeDnsRcode(
  rawCode: unknown,
  options?: { isHubbleResponse?: boolean; isRequestOnly?: boolean },
): CanonicalRcode | undefined {
  const str = asString(rawCode);
  if (!str) {
    if (options?.isHubbleResponse && !options?.isRequestOnly) {
      // Hubble proto3 omits rcode=0 (NOERROR) on RESPONSE messages.
      return "NOERROR";
    }
    return undefined;
  }
  if (/^\d+$/.test(str)) {
    const num = Number(str);
    if (num === 0) return "NOERROR";
    if (num === 2) return "SERVFAIL";
    if (num === 3) return "NXDOMAIN";
    if (num === 5) return "REFUSED";
    return "OTHER";
  }
  const upper = str.toUpperCase().replace(/[\s_-]+/g, "");
  if (upper === "NOERROR") return "NOERROR";
  if (upper === "NXDOMAIN" || upper === "NONEXISTENTDOMAIN") return "NXDOMAIN";
  if (upper === "SERVFAIL" || upper === "SERVERFAILURE") return "SERVFAIL";
  if (upper === "REFUSED" || upper === "QUERYREFUSED") return "REFUSED";
  return "OTHER";
}

function extractAnswers(values: unknown[]): string[] {
  const out = new Set<string>();
  for (const val of values) {
    if (val === undefined || val === null) continue;
    if (Array.isArray(val)) {
      for (const item of val) {
        for (const extracted of extractAnswers([item])) {
          out.add(extracted);
        }
      }
      continue;
    }
    const obj = asObject(val);
    if (obj) {
      const candidate = asString(
        obj.address ?? obj.answer ?? obj.ip ?? obj.target ?? obj.value,
      );
      if (candidate) out.add(candidate.replace(/\.+$/, "").toLowerCase());
      continue;
    }
    const str = asString(val);
    if (str) {
      for (const part of str.split(/[,\s]+/)) {
        const cleaned = part.trim().replace(/\.+$/, "").toLowerCase();
        if (cleaned) out.add(cleaned);
      }
    }
  }
  return [...out];
}

function firstTtl(value: unknown): number | undefined {
  const list = Array.isArray(value) ? value : [value];
  for (const item of list) {
    const num = asFiniteNumber(item);
    if (num !== undefined && num >= 0) return num;
  }
  return undefined;
}

/**
 * Normalizes a single allowlist-projected `stream:dns` or `cilium:hubble:flow` row.
 */
export function normalizeDnsOpsRow(
  row: ProtocolRow,
  defaultSourcetype: DnsOpsSourcetype,
): NormalizedDnsOpsEvent | undefined {
  const stRaw = asString(row.sourcetype).toLowerCase();
  const sourceType: DnsOpsSourcetype =
    stRaw === "cilium:hubble:flow" ||
    (defaultSourcetype === "cilium:hubble:flow" && stRaw !== "stream:dns")
      ? "cilium:hubble:flow"
      : "stream:dns";

  const timestamp = asEpochSeconds(row._time);
  const host = asString(row.host) || "unknown";

  if (sourceType === "cilium:hubble:flow") {
    const flow = asObject(row.flow);
    const ipObj = asObject(flow?.IP);
    const l7 = asObject(flow?.l7);
    const dns = asObject(l7?.dns);

    const messageTypes = asStringArray(row.message_type ?? l7?.type).map((m) =>
      m.toUpperCase(),
    );
    const isResponse =
      messageTypes.includes("RESPONSE") ||
      flow?.is_reply === true ||
      flow?.is_reply === "true";
    const isRequestOnly =
      messageTypes.length > 0 &&
      messageTypes.every((m) => m === "REQUEST" || m === "QUERY") &&
      !isResponse;

    const explicitSrc = asString(row.src_ip);
    const explicitDst = asString(row.dest_ip);
    const rawSrc = asString(ipObj?.source);
    const rawDst = asString(ipObj?.destination);

    const client = explicitSrc || (isResponse ? rawDst : rawSrc);
    const resolver = explicitDst || (isResponse ? rawSrc : rawDst);
    if (!client || !resolver) return undefined;

    const query = normalizeQueryName(
      row["flow.l7.dns.query"] ?? dns?.query ?? row.query,
    );
    const queryTypes = asStringArray(
      row["flow.l7.dns.qtypes"] ?? dns?.qtypes ?? row.query_type,
    ).map((q) => q.toUpperCase());
    const rcode = normalizeDnsRcode(
      row["flow.l7.dns.rcode"] ??
        dns?.rcode ??
        row.reply_code ??
        row.reply_code_id,
      { isHubbleResponse: isResponse, isRequestOnly },
    );
    const answers = extractAnswers([
      row["flow.l7.dns.ips"],
      dns?.ips,
      row.host_addr,
      row.answers,
      row.answer,
    ]);
    const ttlSeconds = firstTtl(row["flow.l7.dns.ttl"] ?? dns?.ttl ?? row.ttl);

    return {
      sourceType,
      timestamp,
      host,
      client,
      resolver,
      ...(query ? { query } : {}),
      queryTypes,
      messageTypes,
      ...(rcode ? { rcode } : {}),
      answers,
      ...(ttlSeconds !== undefined ? { ttlSeconds } : {}),
    };
  }

  const client = asString(row.src_ip);
  const resolver = asString(row.dest_ip);
  if (!client || !resolver) return undefined;

  const messageTypes = asStringArray(row.message_type).map((m) =>
    m.toUpperCase(),
  );
  const isRequestOnly =
    messageTypes.length > 0 &&
    messageTypes.every((m) => m === "QUERY" || m === "REQUEST") &&
    row.reply_code === undefined &&
    row.reply_code_id === undefined;

  const query = normalizeQueryName(row.query);
  const queryTypes = asStringArray(row.query_type).map((q) => q.toUpperCase());
  const rcode = normalizeDnsRcode(row.reply_code ?? row.reply_code_id, {
    isRequestOnly,
  });

  // Splunk Stream streams/dns reports response_time and time_taken in microseconds.
  const rawLatency =
    asFiniteNumber(row.response_time) ?? asFiniteNumber(row.time_taken);
  const latencyMs =
    !isRequestOnly && rawLatency !== undefined && rawLatency > 0
      ? rawLatency / 1000
      : undefined;

  const answers = extractAnswers([row.host_addr, row.answers, row.answer]);
  const ttlSeconds = firstTtl(row.ttl);

  return {
    sourceType,
    timestamp,
    host,
    client,
    resolver,
    ...(query ? { query } : {}),
    queryTypes,
    messageTypes,
    ...(rcode ? { rcode } : {}),
    ...(latencyMs !== undefined ? { latencyMs } : {}),
    answers,
    ...(ttlSeconds !== undefined ? { ttlSeconds } : {}),
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
  events: readonly NormalizedDnsOpsEvent[],
  earliest: number,
  latest: number,
  extract: (ev: NormalizedDnsOpsEvent) => number | undefined,
  mode: "p95" | "sum" | "rate",
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
    if (mode === "rate") {
      return (bucket.reduce((a, b) => a + b, 0) / bucket.length) * 100;
    }
    return percentile(bucket, 95);
  });
  const present = points.filter((p): p is number => p !== undefined);
  return present.length >= 4 ? present : [];
}

function detectSearchSuffixAmplification(
  events: readonly NormalizedDnsOpsEvent[],
): { hint?: string; domains: string[] } {
  const nxQueries = events
    .filter((ev) => ev.rcode === "NXDOMAIN" && ev.query)
    .map((ev) => ev.query!);
  if (nxQueries.length < 3) return { domains: [] };

  const multiLabel = nxQueries.filter((q) => q.split(".").length >= 4);
  if (multiLabel.length < 3) return { domains: [] };

  const suffixCounts = new Map<string, Set<string>>();
  const queryCounts = new Map<string, number>();
  const prefixCounts = new Map<string, Set<string>>();

  for (const q of multiLabel) {
    queryCounts.set(q, (queryCounts.get(q) ?? 0) + 1);
    const labels = q.split(".");
    if (labels.length >= 3) {
      const suffix2 = labels.slice(-2).join(".");
      const s2 = suffixCounts.get(suffix2) ?? new Set<string>();
      s2.add(q);
      suffixCounts.set(suffix2, s2);
    }
    if (labels.length >= 4) {
      const suffix3 = labels.slice(-3).join(".");
      const s3 = suffixCounts.get(suffix3) ?? new Set<string>();
      s3.add(q);
      suffixCounts.set(suffix3, s3);
    }
    const prefix = labels.slice(0, 2).join(".");
    const pSet = prefixCounts.get(prefix) ?? new Set<string>();
    pSet.add(q);
    prefixCounts.set(prefix, pSet);
  }

  let topSuffix: string | undefined;
  let topSuffixQueries = 0;
  for (const [suffix, set] of suffixCounts.entries()) {
    if (
      set.size >= 2 &&
      (set.size > topSuffixQueries ||
        (set.size === topSuffixQueries &&
          suffix.length > (topSuffix?.length ?? 0)))
    ) {
      topSuffix = suffix;
      topSuffixQueries = set.size;
    }
  }

  const repeatedMultiLabel = [...queryCounts.entries()].find(
    ([, cnt]) => cnt >= 3,
  );
  const walkedPrefix = [...prefixCounts.entries()].find(
    ([, set]) => set.size >= 2,
  );

  if (!topSuffix && !repeatedMultiLabel && !walkedPrefix) {
    return { domains: [] };
  }

  const uniqueDomains = [...new Set(multiLabel)].slice(0, 5);
  const hint = topSuffix
    ? `Possible search-suffix amplification: ${multiLabel.length} NXDOMAINs on *.${topSuffix}`
    : repeatedMultiLabel
      ? `Possible search-suffix amplification: ${repeatedMultiLabel[1]} repeated NXDOMAINs on ${repeatedMultiLabel[0]}`
      : `Possible search-suffix amplification: ${multiLabel.length} multi-label NXDOMAINs`;
  return { hint, domains: uniqueDomains };
}

function buildMatrixCellLabel(
  row: DnsOpsPairRow,
  thresholds: ResolvedDnsOpsThresholds,
): string {
  if (row.attention) {
    if (
      row.servfailPct !== undefined &&
      row.servfailPct >= thresholds.servfailWarnPct
    ) {
      return `${row.servfailPct.toFixed(1)}% SERVFAIL`;
    }
    if (
      row.latencyP95Ms !== undefined &&
      row.latencyP95Ms >= thresholds.latencyWarnMs
    ) {
      return formatDurationMs(row.latencyP95Ms);
    }
    if (
      row.nxdomainPct !== undefined &&
      row.nxdomainPct >= thresholds.nxdomainWarnPct
    ) {
      return `${row.nxdomainPct.toFixed(1)}% NXDOMAIN`;
    }
    if (row.refusedPct !== undefined && row.refusedPct > 0) {
      return `${row.refusedPct.toFixed(1)}% REFUSED`;
    }
    if (row.searchSuffixHint) {
      return "Suffix amp";
    }
  }
  if (row.status === "not_covered") return "Not covered";
  return row.latencyP95Ms !== undefined
    ? formatDurationMs(row.latencyP95Ms)
    : "OK";
}

/**
 * Pure aggregation of normalized `stream:dns` and `cilium:hubble:flow` events
 * into Overview rows, KPI tiles, Matrix cells, resolver latency distribution,
 * and a single-sentence verdict.
 */
export function buildDnsOpsAnalysis(options: {
  events: readonly { event: NormalizedDnsOpsEvent; indexName: string }[];
  thresholds: ResolvedDnsOpsThresholds;
  earliest: number;
  latest: number;
  outcomes: ProtocolSourceOutcome[];
  capped: boolean;
  streamReadiness?: StreamReadinessEntry;
}): DnsOpsInvestigationResult {
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

  const anyBlocked = outcomes.some((o) => o.state === "blocked");
  const anyUnavailable = outcomes.some((o) => o.state === "unavailable");
  const anyDegraded = anyBlocked || anyUnavailable;
  const anyPartial =
    outcomes.some((o) => o.state === "partial") || capped || anyDegraded;

  if (!events.length) {
    if (streamReadiness?.state === "estimate_only") {
      return {
        verdict:
          "Stream dns is in Estimate mode (statsOnly=true); no event rows are indexed.",
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
        kpis: [],
        rows: [],
        matrixRows: [],
        matrixCols: [],
        matrixCells: [],
        distribution: [],
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
        kpis: [],
        rows: [],
        matrixRows: [],
        matrixCols: [],
        matrixCells: [],
        distribution: [],
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
    return {
      verdict: "No matching DNS events observed in this UTC window.",
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
      sourceMode: "none",
      streamReadiness,
      bannerState: "empty",
      bannerReason:
        streamReadiness?.state === "enabled"
          ? "Stream dns is Enabled (statsOnly=false), but no matching DNS events were observed in this UTC window."
          : "No matching events in this UTC window.",
      checkedAt: nowSec,
    };
  }

  const pairMap = new Map<
    string,
    {
      client: string;
      resolver: string;
      events: NormalizedDnsOpsEvent[];
      indexName: string;
    }
  >();

  for (const entry of events) {
    const key = `${entry.event.client}__${entry.event.resolver}`;
    const existing = pairMap.get(key);
    if (existing) {
      existing.events.push(entry.event);
      if (entry.event.sourceType === "stream:dns") {
        existing.indexName = entry.indexName;
      }
    } else {
      pairMap.set(key, {
        client: entry.event.client,
        resolver: entry.event.resolver,
        events: [entry.event],
        indexName: entry.indexName,
      });
    }
  }

  const allStreamEvents = events
    .map((e) => e.event)
    .filter((e) => e.sourceType === "stream:dns");
  const allHubbleEvents = events
    .map((e) => e.event)
    .filter((e) => e.sourceType === "cilium:hubble:flow");
  const sourceMode: DnsOpsInvestigationResult["sourceMode"] =
    allStreamEvents.length > 0 && allHubbleEvents.length > 0
      ? "mixed"
      : allStreamEvents.length > 0
        ? "stream_dns"
        : "hubble_only";

  const rows: DnsOpsPairRow[] = [];
  for (const [id, group] of pairMap.entries()) {
    const hasStream = group.events.some((e) => e.sourceType === "stream:dns");
    const isHubbleOnly = !hasStream;
    const queryCount = group.events.length;
    const responses = group.events.filter((e) => e.rcode !== undefined);
    const responseCount = responses.length;

    const nxdomainCount = responses.filter(
      (e) => e.rcode === "NXDOMAIN",
    ).length;
    const servfailCount = responses.filter(
      (e) => e.rcode === "SERVFAIL",
    ).length;
    const refusedCount = responses.filter((e) => e.rcode === "REFUSED").length;

    const nxdomainPct =
      responseCount > 0 ? (nxdomainCount / responseCount) * 100 : undefined;
    const servfailPct =
      responseCount > 0 ? (servfailCount / responseCount) * 100 : undefined;
    const refusedPct =
      responseCount > 0 ? (refusedCount / responseCount) * 100 : undefined;

    const latencies = group.events
      .map((e) => e.latencyMs)
      .filter((v): v is number => v !== undefined);
    const latencyP50Ms = percentile(latencies, 50);
    const latencyP95Ms = percentile(latencies, 95);

    // Answer churn per queried domain
    const answersByQuery = new Map<
      string,
      { signatures: Set<string>; distinctIps: Set<string> }
    >();
    for (const ev of group.events) {
      if (!ev.query || !ev.answers.length) continue;
      const bucket = answersByQuery.get(ev.query) ?? {
        signatures: new Set<string>(),
        distinctIps: new Set<string>(),
      };
      bucket.signatures.add([...ev.answers].sort().join("|"));
      for (const ans of ev.answers) bucket.distinctIps.add(ans);
      answersByQuery.set(ev.query, bucket);
    }
    const answerChurnDomains: AnswerChurnDomainSummary[] = [
      ...answersByQuery.entries(),
    ]
      .filter(([, b]) => b.signatures.size > 1)
      .map(([query, b]) => ({
        query,
        distinctAnswers: [...b.distinctIps].sort().slice(0, 6),
      }))
      .sort((a, b) => b.distinctAnswers.length - a.distinctAnswers.length)
      .slice(0, 5);
    const answerChurnCount = [...answersByQuery.values()].filter(
      (b) => b.signatures.size > 1,
    ).length;
    const maxChurnAnswers = answerChurnDomains.reduce(
      (max, d) => Math.max(max, d.distinctAnswers.length),
      0,
    );
    const answerChurnSummary =
      answerChurnCount === 0
        ? "none"
        : answerChurnCount === 1
          ? `${answerChurnDomains[0].query} (${answerChurnDomains[0].distinctAnswers.length} answers)`
          : `up to ${maxChurnAnswers} distinct answers`;

    // Top failing query domains (capped at 5)
    const failingMap = new Map<string, FailingDomainSummary>();
    for (const ev of responses) {
      if (!ev.rcode || ev.rcode === "NOERROR" || !ev.query) continue;
      const fKey = `${ev.query}\0${ev.rcode}`;
      const existing = failingMap.get(fKey);
      if (existing) {
        existing.count += 1;
      } else {
        failingMap.set(fKey, { query: ev.query, rcode: ev.rcode, count: 1 });
      }
    }
    const topFailingDomains = [...failingMap.values()]
      .sort((a, b) => b.count - a.count || a.query.localeCompare(b.query))
      .slice(0, 5);

    const suffixAmp = detectSearchSuffixAmplification(group.events);

    const reasons: string[] = [];
    if (
      servfailPct !== undefined &&
      servfailPct >= thresholds.servfailWarnPct &&
      servfailCount > 0
    ) {
      reasons.push(
        `${servfailPct.toFixed(1)}% SERVFAIL (≥ ${thresholds.servfailWarnPct}%)`,
      );
    }
    if (
      latencyP95Ms !== undefined &&
      latencyP95Ms >= thresholds.latencyWarnMs
    ) {
      reasons.push(
        `Latency p95 ${formatDurationMs(latencyP95Ms)} (≥ ${thresholds.latencyWarnMs} ms)`,
      );
    }
    if (
      nxdomainPct !== undefined &&
      nxdomainPct >= thresholds.nxdomainWarnPct &&
      nxdomainCount > 0
    ) {
      reasons.push(
        `${nxdomainPct.toFixed(1)}% NXDOMAIN (≥ ${thresholds.nxdomainWarnPct}%)`,
      );
    }
    if (refusedPct !== undefined && refusedCount > 0) {
      reasons.push(
        `${refusedPct.toFixed(1)}% REFUSED (${refusedCount} ${refusedCount === 1 ? "query" : "queries"})`,
      );
    }
    if (suffixAmp.hint) {
      reasons.push(suffixAmp.hint);
    }

    const attention = reasons.length > 0;
    // Never mark a Hubble-only pair green `ok` when resolver latency was not collected.
    const status: ProtocolStatus = attention
      ? "attention"
      : isHubbleOnly || latencyP95Ms === undefined || responseCount === 0
        ? "not_covered"
        : "ok";
    const rowReasons =
      !attention && isHubbleOnly
        ? ["Hubble DNS L7 only — resolver latency is not covered."]
        : !attention && latencyP95Ms === undefined
          ? ["Resolver latency was not reported in this feed."]
          : reasons;

    const timestamps = group.events
      .map((e) => e.timestamp)
      .filter((t): t is number => t !== undefined);

    rows.push({
      id,
      attention,
      client: group.client,
      resolver: group.resolver,
      sourceKind: isHubbleOnly ? "hubble_only" : "stream_dns",
      queryCount,
      responseCount,
      nxdomainCount,
      servfailCount,
      refusedCount,
      ...(nxdomainPct !== undefined ? { nxdomainPct } : {}),
      ...(servfailPct !== undefined ? { servfailPct } : {}),
      ...(refusedPct !== undefined ? { refusedPct } : {}),
      ...(latencyP50Ms !== undefined ? { latencyP50Ms } : {}),
      ...(latencyP95Ms !== undefined ? { latencyP95Ms } : {}),
      answerChurnCount,
      answerChurnSummary,
      answerChurnDomains,
      topFailingDomains,
      ...(suffixAmp.hint ? { searchSuffixHint: suffixAmp.hint } : {}),
      searchSuffixDomains: suffixAmp.domains,
      status,
      reasons: rowReasons,
      indexName: group.indexName,
      ...(timestamps.length ? { firstSeen: Math.min(...timestamps) } : {}),
      ...(timestamps.length ? { lastSeen: Math.max(...timestamps) } : {}),
    });
  }

  rows.sort((a, b) => {
    if (a.attention !== b.attention) return a.attention ? -1 : 1;
    if (a.sourceKind !== b.sourceKind) {
      return a.sourceKind === "stream_dns" ? -1 : 1;
    }
    const aServfail = a.servfailPct ?? -1;
    const bServfail = b.servfailPct ?? -1;
    if (aServfail !== bServfail) return bServfail - aServfail;
    const aLat = a.latencyP95Ms ?? -1;
    const bLat = b.latencyP95Ms ?? -1;
    if (aLat !== bLat) return bLat - aLat;
    const aNx = a.nxdomainPct ?? -1;
    const bNx = b.nxdomainPct ?? -1;
    if (aNx !== bNx) return bNx - aNx;
    return b.queryCount - a.queryCount;
  });

  // KPI strip (<= 4 tiles, one metric per tile, readable units)
  const allEvents = events.map((e) => e.event);
  const allLatencies = allEvents
    .map((e) => e.latencyMs)
    .filter((v): v is number => v !== undefined);
  const overallLatencyP95 = percentile(allLatencies, 95);

  const allResponses = allEvents.filter((e) => e.rcode !== undefined);
  const totalResponses = allResponses.length;
  const totalServfail = allResponses.filter(
    (e) => e.rcode === "SERVFAIL",
  ).length;
  const totalNxdomain = allResponses.filter(
    (e) => e.rcode === "NXDOMAIN",
  ).length;
  const overallServfailPct =
    totalResponses > 0 ? (totalServfail / totalResponses) * 100 : undefined;
  const overallNxdomainPct =
    totalResponses > 0 ? (totalNxdomain / totalResponses) * 100 : undefined;
  const maxPairServfailPct = rows.reduce(
    (max, r) =>
      r.servfailPct !== undefined && r.servfailPct > max ? r.servfailPct : max,
    0,
  );
  const maxPairNxdomainPct = rows.reduce(
    (max, r) =>
      r.nxdomainPct !== undefined && r.nxdomainPct > max ? r.nxdomainPct : max,
    0,
  );
  const flaggedRows = rows.filter((r) => r.attention);

  const latencySpark = buildSparklineBuckets(
    allEvents,
    earliest,
    latest,
    (e) => e.latencyMs,
    "p95",
  );
  const servfailSpark = buildSparklineBuckets(
    allResponses,
    earliest,
    latest,
    (e) => (e.rcode === "SERVFAIL" ? 1 : 0),
    "rate",
  );
  const nxdomainSpark = buildSparklineBuckets(
    allResponses,
    earliest,
    latest,
    (e) => (e.rcode === "NXDOMAIN" ? 1 : 0),
    "rate",
  );
  const errorSpark = buildSparklineBuckets(
    allResponses,
    earliest,
    latest,
    (e) => (e.rcode && e.rcode !== "NOERROR" ? 1 : 0),
    "sum",
  );

  const kpis: ProtocolKpi[] = [
    {
      id: "resolver-latency-p95",
      label: "Resolver Latency p95",
      value:
        overallLatencyP95 !== undefined
          ? overallLatencyP95 < 10
            ? overallLatencyP95.toFixed(1)
            : String(Math.round(overallLatencyP95))
          : "Not covered",
      ...(overallLatencyP95 !== undefined ? { unit: "ms" } : {}),
      status:
        overallLatencyP95 === undefined
          ? "not_covered"
          : overallLatencyP95 >= thresholds.latencyWarnMs
            ? "attention"
            : "ok",
      ...(latencySpark.length ? { sparkline: latencySpark } : {}),
    },
    {
      id: "servfail-rate",
      label: "SERVFAIL Rate",
      value:
        overallServfailPct !== undefined
          ? `${overallServfailPct.toFixed(1)}%`
          : "Not covered",
      status:
        overallServfailPct === undefined
          ? "not_covered"
          : maxPairServfailPct >= thresholds.servfailWarnPct &&
              totalServfail > 0
            ? "attention"
            : "ok",
      ...(servfailSpark.length ? { sparkline: servfailSpark } : {}),
    },
    {
      id: "nxdomain-rate",
      label: "NXDOMAIN Rate",
      value:
        overallNxdomainPct !== undefined
          ? `${overallNxdomainPct.toFixed(1)}%`
          : "Not covered",
      status:
        overallNxdomainPct === undefined
          ? "not_covered"
          : maxPairNxdomainPct >= thresholds.nxdomainWarnPct &&
              totalNxdomain > 0
            ? "attention"
            : "ok",
      ...(nxdomainSpark.length ? { sparkline: nxdomainSpark } : {}),
    },
    {
      id: "flagged-pairs",
      label: "Flagged Pairs",
      value: formatCount(flaggedRows.length),
      unit: flaggedRows.length === 1 ? "pair" : "pairs",
      status:
        flaggedRows.length > 0
          ? "attention"
          : sourceMode === "hubble_only" || overallLatencyP95 === undefined
            ? "not_covered"
            : "ok",
      ...(errorSpark.length ? { sparkline: errorSpark } : {}),
    },
  ];

  // Matrix dimensions and cells
  const matrixRows = [...new Set(rows.map((r) => r.client))].sort((a, b) =>
    a.localeCompare(b),
  );
  const matrixCols = [...new Set(rows.map((r) => r.resolver))].sort((a, b) =>
    a.localeCompare(b),
  );
  const matrixCells: ProtocolMatrixCell[] = rows.map((row) => ({
    row: row.client,
    col: row.resolver,
    status: row.status,
    value: buildMatrixCellLabel(row, thresholds),
    count: row.queryCount,
    detail: row.reasons.length
      ? row.reasons.join("; ")
      : "DNS latency and error rates within bounds",
    itemId: row.id,
  }));

  // Top resolvers latency p50/p95 distribution bars
  const resolverGroups = new Map<string, number[]>();
  for (const ev of allEvents) {
    if (ev.latencyMs === undefined) continue;
    const list = resolverGroups.get(ev.resolver) ?? [];
    list.push(ev.latencyMs);
    resolverGroups.set(ev.resolver, list);
  }
  const distribution: ProtocolDistributionMetric[] = [
    ...resolverGroups.entries(),
  ]
    .map(([resolver, latenciesMs]) => {
      const p50 = roundMetric(percentile(latenciesMs, 50) ?? 0);
      const p95 = roundMetric(percentile(latenciesMs, 95) ?? 0);
      return {
        id: resolver,
        label: resolver,
        p50,
        p95,
        unit: "ms",
        status: (p95 >= thresholds.latencyWarnMs
          ? "attention"
          : "ok") as ProtocolStatus,
      };
    })
    .sort((a, b) => b.p95 - a.p95)
    .slice(0, 6);

  // Single-sentence plain-language verdict (thresholds stay in tooltips)
  let verdict: string;
  let verdictStatus: ProtocolStatus;

  if (flaggedRows.length > 0) {
    const lead = flaggedRows[0];
    const leadSummary =
      lead.servfailPct !== undefined &&
      lead.servfailPct >= thresholds.servfailWarnPct &&
      lead.servfailCount > 0
        ? `${lead.servfailPct.toFixed(1)}% SERVFAIL`
        : lead.latencyP95Ms !== undefined &&
            lead.latencyP95Ms >= thresholds.latencyWarnMs
          ? `high latency (${formatDurationMs(lead.latencyP95Ms)})`
          : lead.nxdomainPct !== undefined &&
              lead.nxdomainPct >= thresholds.nxdomainWarnPct &&
              lead.nxdomainCount > 0
            ? `${lead.nxdomainPct.toFixed(1)}% NXDOMAIN`
            : lead.refusedPct !== undefined && lead.refusedCount > 0
              ? `${lead.refusedPct.toFixed(1)}% REFUSED`
              : (lead.reasons[0] ?? "exception");
    const suffixNote =
      sourceMode === "hubble_only" ? " (Hubble L7; latency not covered)" : "";
    verdict = `${flaggedRows.length} of ${rows.length} ${rows.length === 1 ? "pair needs" : "pairs need"} attention: ${leadSummary} on ${lead.client} → ${lead.resolver}${suffixNote}.`;
    verdictStatus = "attention";
  } else if (sourceMode === "hubble_only" || overallLatencyP95 === undefined) {
    verdict = `Hubble DNS L7 fallback only (${rows.length} ${rows.length === 1 ? "pair" : "pairs"} observed) — resolver latency is not covered.`;
    verdictStatus = "not_covered";
  } else {
    verdict = `${rows.length} of ${rows.length} ${rows.length === 1 ? "pair" : "pairs"} within resolver latency and error bounds.`;
    verdictStatus = "ok";
  }

  const coverageStatus: ProtocolStatus = anyPartial
    ? "attention"
    : sourceMode === "hubble_only"
      ? "not_covered"
      : "ok";
  const activeCount = outcomes.filter(
    (o) => o.state === "complete" || o.state === "partial",
  ).length;
  const coverageLabel =
    sourceMode === "hubble_only"
      ? "Hubble only"
      : `${activeCount} ${activeCount === 1 ? "source" : "sources"}`;

  const blockedDetail = outcomes.find((o) => o.state === "blocked")?.detail;
  const unavailableDetail = outcomes.find(
    (o) => o.state === "unavailable",
  )?.detail;
  const partialReason =
    anyBlocked && sourceMode === "hubble_only"
      ? `Primary source blocked (${blockedDetail ?? "access denied"}); showing Hubble DNS L7 fallback only.`
      : anyBlocked
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
    sourceMode,
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

export interface InvestigateDnsOpsOptions {
  skipEstimateCheck?: boolean;
  skipConfigRecheck?: boolean;
  profileValidators?: Partial<Record<ProtocolLensId, LensProfileValidator>>;
}

/**
 * Executes the on-demand DNS Operations investigation across configured `dns_ops`
 * profiles (`stream:dns` primary, `cilium:hubble:flow` fallback), rechecking the
 * `adm_protocol_profiles` fingerprint to discard stale results.
 */
export async function investigateDnsOps(
  client: SearchClient,
  request: ProtocolRequest,
  configuration: ProtocolConfiguration,
  signal: AbortSignal,
  options: InvestigateDnsOpsOptions = {},
): Promise<DnsOpsInvestigationResult> {
  const scoped = configuration.profiles.filter(
    (p) => p.lens === "dns_ops" && p.scope === request.scope,
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
      sourceMode: "none",
      bannerState: "unavailable",
      bannerReason: `No dns_ops profile configured for scope "${request.scope}".`,
      checkedAt: Math.floor(Date.now() / 1000),
    };
  }

  const streamProfiles = scoped.filter(
    (p) => resolveDnsOpsThresholds(p).sourcetype === "stream:dns",
  );
  const hubbleProfiles = scoped.filter(
    (p) => resolveDnsOpsThresholds(p).sourcetype === "cilium:hubble:flow",
  );

  const matchesDirectionFilter = (ev: NormalizedDnsOpsEvent): boolean =>
    matchesFlowEndpoints(request.filter, ev.client, ev.resolver);

  const runProfiles = async () => {
    const outcomes: ProtocolSourceOutcome[] = [];
    const collected: { event: NormalizedDnsOpsEvent; indexName: string }[] = [];
    let capped = false;
    let chosenThresholds = resolveDnsOpsThresholds(
      streamProfiles[0] ?? hubbleProfiles[0],
    );

    for (const profile of streamProfiles) {
      signal.throwIfAborted();
      const thresholds = resolveDnsOpsThresholds(profile);
      chosenThresholds = thresholds;
      const spl = buildDnsOpsSearch({
        index: profile.index,
        sourcetype: "stream:dns",
        filter: request.filter,
        maxRows: 256,
      });
      const res = await runBoundedProtocolSearch(client, {
        lens: "dns_ops",
        profile,
        spl,
        earliest: request.earliest,
        latest: request.latest,
        signal,
      });
      outcomes.push(res.outcome);
      if (res.capped) capped = true;
      for (const row of res.rows) {
        const norm = normalizeDnsOpsRow(row, "stream:dns");
        if (norm && matchesDirectionFilter(norm)) {
          collected.push({ event: norm, indexName: profile.index });
        }
      }
    }

    // Fallback to cilium:hubble:flow only when stream:dns collected 0 events.
    if (collected.length === 0 && hubbleProfiles.length > 0) {
      for (const profile of hubbleProfiles) {
        signal.throwIfAborted();
        if (!streamProfiles.length) {
          chosenThresholds = resolveDnsOpsThresholds(profile);
        }
        const spl = buildDnsOpsSearch({
          index: profile.index,
          sourcetype: "cilium:hubble:flow",
          filter: request.filter,
          maxRows: 256,
        });
        const res = await runBoundedProtocolSearch(client, {
          lens: "dns_ops",
          profile,
          spl,
          earliest: request.earliest,
          latest: request.latest,
          signal,
        });
        outcomes.push(res.outcome);
        if (res.capped) capped = true;
        for (const row of res.rows) {
          const norm = normalizeDnsOpsRow(row, "cilium:hubble:flow");
          if (norm && matchesDirectionFilter(norm)) {
            collected.push({ event: norm, indexName: profile.index });
          }
        }
      }
    }

    // Check Stream Estimate mode ONLY when stream:dns returned 0 rows on explicit Investigate.
    let streamReadiness: StreamReadinessEntry | undefined;
    const dnsCompletedEmpty =
      streamProfiles.length > 0 &&
      collected.every((c) => c.event.sourceType !== "stream:dns") &&
      outcomes.some(
        (o) =>
          streamProfiles.some((sp) => sp.id === o.profile) &&
          o.state === "complete",
      );
    if (dnsCompletedEmpty && !options.skipEstimateCheck) {
      const entries = await checkStreamEstimateMode(client, ["dns"], signal);
      streamReadiness = entries[0];
      if (streamReadiness?.state === "estimate_only") {
        outcomes.push({
          source: "protocol_stream_readiness",
          state: "estimate_only",
          detail: streamReadiness.detail,
        });
      }
    }

    return buildDnsOpsAnalysis({
      events: collected,
      thresholds: chosenThresholds,
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
    dns_ops: validateDnsOpsExtra,
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
 * Hub "Check all" summary runner for `dns_ops`.
 */
export async function summarizeDnsOps(
  client: SearchClient,
  request: ProtocolRequest,
  configuration: ProtocolConfiguration,
  signal: AbortSignal,
  options?: InvestigateDnsOpsOptions,
): Promise<ProtocolLensSummary> {
  const result = await investigateDnsOps(
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
    lens: "dns_ops",
    status,
    verdict: result.verdict,
    checkedAt: result.checkedAt,
    capped: result.capped,
    outcomes: result.outcomes,
  };
}
