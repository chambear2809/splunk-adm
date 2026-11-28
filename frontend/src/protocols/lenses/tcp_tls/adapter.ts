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
import { buildFlowEndpointPredicates } from "../../shared/filterSpl";
import {
  formatBytes,
  formatCount,
  formatDurationMs,
} from "../../shared/format";
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
  DEFAULT_TCP_TLS_THRESHOLDS,
  validateTcpTlsExtra,
  type ResolvedTcpTlsThresholds,
  type TcpTlsExtraConfig,
  type TcpTlsSourcetype,
} from "./validate";

export {
  DEFAULT_TCP_TLS_THRESHOLDS,
  validateTcpTlsExtra,
  type ResolvedTcpTlsThresholds,
  type TcpTlsExtraConfig,
  type TcpTlsSourcetype,
};

export function resolveTcpTlsThresholds(
  profile?: BaseProtocolProfile,
): ResolvedTcpTlsThresholds {
  const extra = profile?.extra as TcpTlsExtraConfig | undefined;
  return {
    rttWarnMs:
      typeof extra?.rttWarnMs === "number"
        ? extra.rttWarnMs
        : DEFAULT_TCP_TLS_THRESHOLDS.rttWarnMs,
    retransmitWarnPct:
      typeof extra?.retransmitWarnPct === "number"
        ? extra.retransmitWarnPct
        : DEFAULT_TCP_TLS_THRESHOLDS.retransmitWarnPct,
    certExpiryWarnDays:
      typeof extra?.certExpiryWarnDays === "number"
        ? extra.certExpiryWarnDays
        : DEFAULT_TCP_TLS_THRESHOLDS.certExpiryWarnDays,
    sourcetype:
      extra?.sourcetype === "stream:netflow"
        ? "stream:netflow"
        : DEFAULT_TCP_TLS_THRESHOLDS.sourcetype,
  };
}

export const TCP_TLS_PROJECTED_FIELDS = [
  "_time",
  "host",
  "sourcetype",
  "src_ip",
  "dest_ip",
  "src_port",
  "dest_port",
  "client_rtt",
  "server_rtt",
  "client_rtt_packets",
  "server_rtt_packets",
  "bytes_in",
  "bytes_out",
  "packets_in",
  "packets_out",
  "duplicate_packets_in",
  "duplicate_packets_out",
  "missing_packets_in",
  "missing_packets_out",
  "canceled",
  "refused",
  "tcp_status",
  "time_taken",
  "tls_version",
  "ssl_version",
  "ssl_subject",
  "ssl_cert_subject",
  "ssl_validity_end",
  "ssl_cert_not_after",
  "ssl_cert_days_remaining",
  "ssl_cert_self_signed",
  "ssl_end_time",
  "ssl_issuer",
  "ssl_subject_common_name",
  "ssl_error",
  "ssl_cipher_name",
  "ssl_cipher",
  "cipher_suite",
  "sni",
  "vxlan_id",
  "total_bytes",
  "total_packets",
  "retransmits",
  "resets",
] as const;

export const NETFLOW_FALLBACK_FIELDS = [
  "_time",
  "host",
  "sourcetype",
  "exporter_ip",
  "src_ip",
  "dest_ip",
  "src_port",
  "dest_port",
  "total_bytes",
  "total_packets",
] as const;

/**
 * Builds a bounded, allowlisted SPL query for `stream:tcp` or `stream:netflow`.
 * Projects with `| table` before `| head` so `_raw` is dropped server-side
 * without sorting the full index.
 */
export function buildTcpTlsSearch(options: {
  index: string;
  sourcetype: TcpTlsSourcetype;
  filter?: ProtocolFilter;
  maxRows: number;
}): string {
  const index = literal(options.index, 80);
  const predicates: string[] = [
    `index=${index}`,
    `sourcetype="${options.sourcetype}"`,
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
  if (options.filter?.vni && options.sourcetype === "stream:tcp") {
    predicates.push(`vxlan_id="${literal(options.filter.vni, 16)}"`);
  }
  const headLimit = Math.max(1, Math.trunc(options.maxRows)) + 1;

  if (options.sourcetype === "stream:netflow") {
    const tableClause = buildAllowedFieldsClause(
      "tcp_tls",
      NETFLOW_FALLBACK_FIELDS,
    );
    return (
      `search ${predicates.join(" ")} ` +
      `| head ${headLimit} ` +
      `| eval total_bytes=coalesce(bytes_in + bytes_out, bytes_in, bytes_out, bytes, 0), total_packets=coalesce(packets_in + packets_out, packets_in, packets_out, packets, 0) ` +
      tableClause
    );
  }

  const tableClause = buildAllowedFieldsClause(
    "tcp_tls",
    TCP_TLS_PROJECTED_FIELDS,
  );
  return `search ${predicates.join(" ")} | head ${headLimit} ${tableClause}`;
}

/**
 * Builds a safe Splunk Search URL for raw events of a selected client→server pair.
 */
export function buildTcpTlsRawEventsUrl(options: {
  index: string;
  sourcetype: TcpTlsSourcetype;
  client: string;
  server: string;
  earliest: number;
  latest: number;
}): string {
  const index = literal(options.index, 80);
  const src = literal(options.client, 128);
  const dst = literal(options.server, 128);
  const st: TcpTlsSourcetype =
    options.sourcetype === "stream:netflow" ? "stream:netflow" : "stream:tcp";
  const q = `search index=${index} sourcetype="${st}" src_ip="${src}" dest_ip="${dst}"`;
  const params = new URLSearchParams({
    q,
    earliest: String(Math.trunc(options.earliest)),
    latest: String(Math.trunc(options.latest)),
  });
  return `/app/splunk_adm/search?${params.toString()}`;
}

export interface NormalizedTcpTlsEvent {
  sourceType: TcpTlsSourcetype;
  timestamp: number | undefined;
  host: string;
  exporterIp?: string;
  client: string;
  server: string;
  srcPort?: number;
  destPort?: number;
  clientRttMs?: number;
  serverRttMs?: number;
  totalBytes: number;
  totalPackets: number;
  retransmitCount: number;
  hasRetransmitFlag: boolean;
  resetCount: number;
  hasResetFlag: boolean;
  tlsVersion?: string;
  legacyTls: boolean;
  cipher?: string;
  certSubject?: string;
  certIssuer?: string;
  certNotAfter?: string;
  certDaysRemaining?: number;
  certSelfSigned: boolean;
  sslError?: string;
  sni?: string;
  hasTlsData: boolean;
}

export interface TcpTlsPairRow {
  /** URL-safe `ITEM_ID` matching `^[A-Za-z0-9._:/-]{1,128}$` (`client__server`). */
  id: string;
  attention: boolean;
  client: string;
  server: string;
  destPorts: number[];
  sourceKind: "stream_tcp" | "netflow_only";
  flowCount: number;
  serverRttP50Ms?: number;
  serverRttP95Ms?: number;
  clientRttP50Ms?: number;
  clientRttP95Ms?: number;
  retransmits: number;
  resets: number;
  retransmitPct?: number;
  retransmitBasis: "packets" | "flows" | "none";
  totalBytes: number;
  totalPackets: number;
  tlsVersion?: string;
  cipher?: string;
  certSubject?: string;
  certIssuer?: string;
  certNotAfter?: string;
  certDaysRemaining?: number;
  certSelfSigned: boolean;
  sni?: string;
  sslError?: string;
  hasTlsData: boolean;
  tlsStatus: ProtocolStatus;
  tlsPostureLabel: string;
  status: ProtocolStatus;
  reasons: string[];
  indexName: string;
  firstSeen?: number;
  lastSeen?: number;
}

export interface TcpTlsInvestigationResult {
  verdict: string;
  verdictStatus: ProtocolStatus;
  coverageStatus: ProtocolStatus;
  coverageLabel: string;
  kpis: ProtocolKpi[];
  rows: TcpTlsPairRow[];
  matrixRows: string[];
  matrixCols: string[];
  matrixCells: ProtocolMatrixCell[];
  distribution: ProtocolDistributionMetric[];
  outcomes: ProtocolSourceOutcome[];
  capped: boolean;
  sourceMode: "stream_tcp" | "netflow_only" | "mixed" | "none";
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

function parseTcpStatusFlags(tcpStatus: unknown): {
  retransmit: boolean;
  reset: boolean;
} {
  const raw = asString(tcpStatus);
  if (!raw) return { retransmit: false, reset: false };
  if (/^\d+$/.test(raw)) {
    const code = Number(raw);
    // Splunk Stream 8.1.6 streams/tcp: tcp_status 0=OK, 1=RESET, 2=IGNORED.
    return {
      reset: code === 1,
      retransmit: false,
    };
  }
  const upper = raw.toUpperCase();
  return {
    reset: /\bRST\b|RESET/.test(upper),
    retransmit: /RETRANS/.test(upper),
  };
}

function asTruthyFlag(value: unknown): boolean {
  if (value === true || value === 1) return true;
  const s = asString(value).toLowerCase();
  return s === "true" || s === "1" || s === "yes";
}

// Matches SSLv2/SSLv3/SSL 3.0, OpenSSL "TLSv1", TLS 1.0, TLS 1.1, 1.0, 1.1;
// never flags TLS 1.2 or TLS 1.3.
const LEGACY_TLS_RE =
  /^(?:SSL\s*v?[23](?:\.0)?|TLS\s*v?1(?:[._][01])?(?![._0-9])|1\.[01])$/i;

export function isLegacyTlsVersion(version: string | undefined): boolean {
  if (!version) return false;
  return LEGACY_TLS_RE.test(version.trim());
}

function parseCertDaysRemaining(
  row: ProtocolRow,
  referenceEpoch: number,
): number | undefined {
  const explicitDays = asFiniteNumber(row.ssl_cert_days_remaining);
  if (explicitDays !== undefined) return Math.floor(explicitDays);
  const notAfterEpoch = asEpochSeconds(
    row.ssl_validity_end ?? row.ssl_cert_not_after ?? row.ssl_end_time,
  );
  if (notAfterEpoch === undefined) return undefined;
  return Math.floor((notAfterEpoch - referenceEpoch) / 86400);
}

/**
 * Normalizes a single allowlist-projected `stream:tcp` or `stream:netflow` row.
 */
export function normalizeTcpTlsRow(
  row: ProtocolRow,
  defaultSourcetype: TcpTlsSourcetype,
  referenceEpoch: number,
): NormalizedTcpTlsEvent | undefined {
  const client = asString(row.src_ip);
  const server = asString(row.dest_ip);
  if (!client || !server) return undefined;

  const stRaw = asString(row.sourcetype).toLowerCase();
  const sourceType: TcpTlsSourcetype =
    stRaw === "stream:netflow" ||
    (defaultSourcetype === "stream:netflow" && stRaw !== "stream:tcp")
      ? "stream:netflow"
      : "stream:tcp";

  const timestamp = asEpochSeconds(row._time);
  const host = asString(row.host) || asString(row.exporter_ip) || "unknown";
  const exporterIp = asString(row.exporter_ip) || undefined;
  const srcPort = asFiniteNumber(row.src_port);
  const destPort = asFiniteNumber(row.dest_port);

  const totalBytesDerived = asFiniteNumber(row.total_bytes);
  const bytesIn = asFiniteNumber(row.bytes_in);
  const bytesOut = asFiniteNumber(row.bytes_out);
  const legacyBytes = asFiniteNumber(row.bytes);
  const totalBytes =
    totalBytesDerived ?? ((bytesIn ?? 0) + (bytesOut ?? 0) || legacyBytes || 0);

  const totalPacketsDerived = asFiniteNumber(row.total_packets);
  const packetsIn = asFiniteNumber(row.packets_in);
  const packetsOut = asFiniteNumber(row.packets_out);
  const legacyPackets = asFiniteNumber(row.packets);
  const totalPackets =
    totalPacketsDerived ??
    ((packetsIn ?? 0) + (packetsOut ?? 0) || legacyPackets || 0);

  if (sourceType === "stream:netflow") {
    return {
      sourceType,
      timestamp,
      host,
      exporterIp,
      client,
      server,
      ...(srcPort !== undefined ? { srcPort } : {}),
      ...(destPort !== undefined ? { destPort } : {}),
      totalBytes: Math.max(0, totalBytes),
      totalPackets: Math.max(0, totalPackets),
      retransmitCount: 0,
      hasRetransmitFlag: false,
      resetCount: 0,
      hasResetFlag: false,
      legacyTls: false,
      certSelfSigned: false,
      hasTlsData: false,
    };
  }

  // Splunk Stream reports client_rtt and server_rtt in microseconds.
  const rawClientRtt = asFiniteNumber(row.client_rtt);
  const clientRttPkts = asFiniteNumber(row.client_rtt_packets);
  const clientRttMs =
    rawClientRtt !== undefined &&
    rawClientRtt >= 0 &&
    !(rawClientRtt === 0 && clientRttPkts === 0)
      ? rawClientRtt / 1000
      : undefined;

  const rawServerRtt = asFiniteNumber(row.server_rtt);
  const serverRttPkts = asFiniteNumber(row.server_rtt_packets);
  const serverRttMs =
    rawServerRtt !== undefined &&
    rawServerRtt >= 0 &&
    !(rawServerRtt === 0 && serverRttPkts === 0)
      ? rawServerRtt / 1000
      : undefined;

  const statusFlags = parseTcpStatusFlags(row.tcp_status);
  const explicitRetrans = asFiniteNumber(row.retransmits);
  const dupPkts =
    (asFiniteNumber(row.duplicate_packets_in) ?? 0) +
    (asFiniteNumber(row.duplicate_packets_out) ?? 0);
  const missingPkts =
    (asFiniteNumber(row.missing_packets_in) ?? 0) +
    (asFiniteNumber(row.missing_packets_out) ?? 0);
  const streamRetrans = dupPkts + missingPkts;
  const explicitResets = asFiniteNumber(row.resets);
  const canceledOrRefused =
    asTruthyFlag(row.canceled) || asTruthyFlag(row.refused);
  const retransmitCount =
    explicitRetrans !== undefined
      ? Math.max(0, explicitRetrans)
      : streamRetrans > 0
        ? streamRetrans
        : statusFlags.retransmit
          ? 1
          : 0;
  const resetCount =
    explicitResets !== undefined
      ? Math.max(0, explicitResets)
      : statusFlags.reset || canceledOrRefused
        ? 1
        : 0;

  const parseOneTls = (raw: unknown): string | undefined => {
    const items = Array.isArray(raw) ? raw : [raw];
    for (const item of items) {
      const s = asString(item);
      if (!s || /^(?:0|0\.0|none|unknown|-)$/i.test(s)) continue;
      if (s === "3.0") return "SSL 3.0";
      if (s === "3.1") return "TLS 1.0";
      if (s === "3.2") return "TLS 1.1";
      if (s === "3.3") return "TLS 1.2";
      if (s === "3.4") return "TLS 1.3";
      return s;
    }
    return undefined;
  };
  const tlsVersion =
    parseOneTls(row.tls_version) ?? parseOneTls(row.ssl_version);
  const cipher =
    asString(row.ssl_cipher_name ?? row.ssl_cipher ?? row.cipher_suite) ||
    undefined;
  const certSubject =
    asString(
      row.ssl_subject ?? row.ssl_cert_subject ?? row.ssl_subject_common_name,
    ) || undefined;
  const certIssuer = asString(row.ssl_issuer) || undefined;
  const certNotAfter =
    asString(
      row.ssl_validity_end ?? row.ssl_cert_not_after ?? row.ssl_end_time,
    ) || undefined;
  const certDaysRemaining = parseCertDaysRemaining(row, referenceEpoch);
  const certSelfSigned = asTruthyFlag(row.ssl_cert_self_signed);
  const sni = asString(row.sni) || undefined;
  const rawSslError = asString(row.ssl_error);
  const sslError =
    rawSslError && !/^(?:none|ok|0|false|-)$/i.test(rawSslError)
      ? rawSslError
      : undefined;

  const hasTlsData = Boolean(
    tlsVersion ||
    cipher ||
    certSubject ||
    certIssuer ||
    certNotAfter ||
    certDaysRemaining !== undefined ||
    sni ||
    sslError,
  );

  return {
    sourceType,
    timestamp,
    host,
    exporterIp,
    client,
    server,
    ...(srcPort !== undefined ? { srcPort } : {}),
    ...(destPort !== undefined ? { destPort } : {}),
    ...(clientRttMs !== undefined ? { clientRttMs } : {}),
    ...(serverRttMs !== undefined ? { serverRttMs } : {}),
    totalBytes: Math.max(0, totalBytes),
    totalPackets: Math.max(0, totalPackets),
    retransmitCount,
    hasRetransmitFlag: statusFlags.retransmit || retransmitCount > 0,
    resetCount,
    hasResetFlag: statusFlags.reset || resetCount > 0,
    ...(tlsVersion ? { tlsVersion } : {}),
    legacyTls: isLegacyTlsVersion(tlsVersion),
    ...(cipher ? { cipher } : {}),
    ...(certSubject ? { certSubject } : {}),
    ...(certIssuer ? { certIssuer } : {}),
    ...(certNotAfter ? { certNotAfter } : {}),
    ...(certDaysRemaining !== undefined ? { certDaysRemaining } : {}),
    certSelfSigned,
    ...(sslError ? { sslError } : {}),
    ...(sni ? { sni } : {}),
    hasTlsData,
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
  events: readonly NormalizedTcpTlsEvent[],
  earliest: number,
  latest: number,
  extract: (ev: NormalizedTcpTlsEvent) => number | undefined,
  mode: "p95" | "sum",
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
    return percentile(bucket, 95);
  });
  const present = points.filter((p): p is number => p !== undefined);
  return present.length >= 4 ? present : [];
}

function buildMatrixCellLabel(
  row: TcpTlsPairRow,
  thresholds: ResolvedTcpTlsThresholds,
): string {
  if (row.sourceKind === "netflow_only") return "Not covered";
  if (row.attention) {
    if (
      row.serverRttP95Ms !== undefined &&
      row.serverRttP95Ms >= thresholds.rttWarnMs
    ) {
      return formatDurationMs(row.serverRttP95Ms);
    }
    if (
      row.retransmitPct !== undefined &&
      row.retransmitPct >= thresholds.retransmitWarnPct
    ) {
      return `${row.retransmitPct.toFixed(1)}% loss`;
    }
    if (row.resets > 0) {
      return `${row.resets} ${row.resets === 1 ? "reset" : "resets"}`;
    }
    if (row.tlsStatus === "attention") {
      if (row.sslError) return "TLS error";
      if (isLegacyTlsVersion(row.tlsVersion)) {
        return row.tlsVersion ?? "Legacy TLS";
      }
      if (row.certDaysRemaining !== undefined && row.certDaysRemaining <= 0) {
        return "Cert expired";
      }
      if (row.certDaysRemaining !== undefined) {
        return `Cert ${row.certDaysRemaining}d`;
      }
    }
  }
  return row.serverRttP95Ms !== undefined
    ? formatDurationMs(row.serverRttP95Ms)
    : row.retransmitPct !== undefined
      ? `${row.retransmitPct.toFixed(1)}%`
      : "OK";
}

/**
 * Pure aggregation of normalized TCP/TLS and NetFlow events into Overview rows,
 * KPI tiles, Matrix cells, RTT distribution bars, and a single-sentence verdict.
 */
export function buildTcpTlsAnalysis(options: {
  events: readonly { event: NormalizedTcpTlsEvent; indexName: string }[];
  thresholds: ResolvedTcpTlsThresholds;
  earliest: number;
  latest: number;
  outcomes: ProtocolSourceOutcome[];
  capped: boolean;
  streamReadiness?: StreamReadinessEntry;
}): TcpTlsInvestigationResult {
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
          "Stream tcp is in Estimate mode (statsOnly=true); no event rows are indexed.",
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
      verdict: "No matching TCP or NetFlow events observed in this UTC window.",
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
          ? "Stream tcp is Enabled (statsOnly=false), but no matching TCP events were observed in this UTC window."
          : "No matching events in this UTC window.",
      checkedAt: nowSec,
    };
  }

  const pairMap = new Map<
    string,
    {
      client: string;
      server: string;
      events: NormalizedTcpTlsEvent[];
      indexName: string;
    }
  >();

  for (const entry of events) {
    const key = `${entry.event.client}__${entry.event.server}`;
    const existing = pairMap.get(key);
    if (existing) {
      existing.events.push(entry.event);
      if (entry.event.sourceType === "stream:tcp") {
        existing.indexName = entry.indexName;
      }
    } else {
      pairMap.set(key, {
        client: entry.event.client,
        server: entry.event.server,
        events: [entry.event],
        indexName: entry.indexName,
      });
    }
  }

  const allTcpEvents = events
    .map((e) => e.event)
    .filter((e) => e.sourceType === "stream:tcp");
  const allNetflowEvents = events
    .map((e) => e.event)
    .filter((e) => e.sourceType === "stream:netflow");
  const sourceMode: TcpTlsInvestigationResult["sourceMode"] =
    allTcpEvents.length > 0 && allNetflowEvents.length > 0
      ? "mixed"
      : allTcpEvents.length > 0
        ? "stream_tcp"
        : "netflow_only";

  const rows: TcpTlsPairRow[] = [];
  for (const [id, group] of pairMap.entries()) {
    const tcpEvents = group.events.filter((e) => e.sourceType === "stream:tcp");
    const isNetflowOnly = tcpEvents.length === 0;
    const activeEvents = isNetflowOnly ? group.events : tcpEvents;

    const destPorts = [
      ...new Set(
        group.events
          .map((e) => e.destPort)
          .filter((p): p is number => p !== undefined && p > 0),
      ),
    ].sort((a, b) => a - b);

    const serverRtts = tcpEvents
      .map((e) => e.serverRttMs)
      .filter((v): v is number => v !== undefined);
    const clientRtts = tcpEvents
      .map((e) => e.clientRttMs)
      .filter((v): v is number => v !== undefined);

    const serverRttP50Ms = percentile(serverRtts, 50);
    const serverRttP95Ms = percentile(serverRtts, 95);
    const clientRttP50Ms = percentile(clientRtts, 50);
    const clientRttP95Ms = percentile(clientRtts, 95);

    const totalBytes = activeEvents.reduce((sum, e) => sum + e.totalBytes, 0);
    const totalPackets = activeEvents.reduce(
      (sum, e) => sum + e.totalPackets,
      0,
    );

    const retransmits = tcpEvents.reduce(
      (sum, e) => sum + e.retransmitCount,
      0,
    );
    const resets = tcpEvents.reduce((sum, e) => sum + e.resetCount, 0);
    const retransmitFlows = tcpEvents.filter((e) => e.hasRetransmitFlag).length;

    let retransmitPct: number | undefined;
    let retransmitBasis: TcpTlsPairRow["retransmitBasis"] = "none";
    if (!isNetflowOnly) {
      if (totalPackets > 0 && retransmits > 0) {
        retransmitPct = (retransmits / totalPackets) * 100;
        retransmitBasis = "packets";
      } else if (tcpEvents.length > 0) {
        retransmitPct = (retransmitFlows / tcpEvents.length) * 100;
        retransmitBasis = "flows";
      }
    }

    const tlsEvents = tcpEvents.filter((e) => e.hasTlsData);
    const hasTlsData = tlsEvents.length > 0;
    const legacyEvent = tlsEvents.find((e) => e.legacyTls);
    const errorEvent = tlsEvents.find((e) => e.sslError);
    const daysList = tlsEvents
      .map((e) => e.certDaysRemaining)
      .filter((d): d is number => d !== undefined);
    const minDaysRemaining = daysList.length
      ? Math.min(...daysList)
      : undefined;
    const representativeTls =
      errorEvent ??
      legacyEvent ??
      tlsEvents.find(
        (e) =>
          e.certDaysRemaining !== undefined &&
          e.certDaysRemaining === minDaysRemaining,
      ) ??
      tlsEvents[0];
    const certSelfSigned = tlsEvents.some((e) => e.certSelfSigned);

    const reasons: string[] = [];
    if (
      serverRttP95Ms !== undefined &&
      serverRttP95Ms >= thresholds.rttWarnMs
    ) {
      reasons.push(
        `Server RTT p95 ${formatDurationMs(serverRttP95Ms)} (≥ ${thresholds.rttWarnMs} ms)`,
      );
    }
    if (
      clientRttP95Ms !== undefined &&
      clientRttP95Ms >= thresholds.rttWarnMs
    ) {
      reasons.push(
        `Client RTT p95 ${formatDurationMs(clientRttP95Ms)} (≥ ${thresholds.rttWarnMs} ms)`,
      );
    }
    if (
      retransmitPct !== undefined &&
      retransmitPct >= thresholds.retransmitWarnPct
    ) {
      reasons.push(
        `${retransmitPct.toFixed(1)}% retransmits (≥ ${thresholds.retransmitWarnPct}%)`,
      );
    }
    if (resets > 0) {
      reasons.push(`${resets} TCP ${resets === 1 ? "reset" : "resets"}`);
    }

    let tlsStatus: ProtocolStatus =
      isNetflowOnly || !hasTlsData ? "not_covered" : "ok";
    let tlsPostureLabel = isNetflowOnly || !hasTlsData ? "Not covered" : "";

    if (hasTlsData && representativeTls) {
      if (errorEvent?.sslError) {
        tlsStatus = "attention";
        reasons.push(`SSL error: ${errorEvent.sslError}`);
      }
      if (legacyEvent?.tlsVersion) {
        tlsStatus = "attention";
        reasons.push(`Legacy ${legacyEvent.tlsVersion}`);
      }
      if (minDaysRemaining !== undefined && minDaysRemaining <= 0) {
        tlsStatus = "attention";
        reasons.push("Certificate expired");
      } else if (
        minDaysRemaining !== undefined &&
        minDaysRemaining <= thresholds.certExpiryWarnDays
      ) {
        tlsStatus = "attention";
        reasons.push(`Cert expires in ${minDaysRemaining}d`);
      }

      const ver = representativeTls.tlsVersion ?? "TLS";
      if (errorEvent?.sslError) {
        tlsPostureLabel = `${ver} · error`;
      } else if (minDaysRemaining !== undefined && minDaysRemaining <= 0) {
        tlsPostureLabel = `${ver} · expired`;
      } else if (minDaysRemaining !== undefined) {
        tlsPostureLabel = `${ver} · ${minDaysRemaining}d`;
      } else {
        tlsPostureLabel = ver;
      }
    }

    const attention = !isNetflowOnly && reasons.length > 0;
    // Never mark a NetFlow-only pair green `ok` — RTT & TLS health were not collected.
    const status: ProtocolStatus = isNetflowOnly
      ? "not_covered"
      : attention
        ? "attention"
        : "ok";
    const rowReasons = isNetflowOnly
      ? ["NetFlow fallback only — TCP RTT and TLS posture are not covered."]
      : reasons;
    const timestamps = group.events
      .map((e) => e.timestamp)
      .filter((t): t is number => t !== undefined);

    rows.push({
      id,
      attention,
      client: group.client,
      server: group.server,
      destPorts,
      sourceKind: isNetflowOnly ? "netflow_only" : "stream_tcp",
      flowCount: activeEvents.length,
      ...(serverRttP50Ms !== undefined ? { serverRttP50Ms } : {}),
      ...(serverRttP95Ms !== undefined ? { serverRttP95Ms } : {}),
      ...(clientRttP50Ms !== undefined ? { clientRttP50Ms } : {}),
      ...(clientRttP95Ms !== undefined ? { clientRttP95Ms } : {}),
      retransmits,
      resets,
      ...(retransmitPct !== undefined ? { retransmitPct } : {}),
      retransmitBasis,
      totalBytes,
      totalPackets,
      ...(representativeTls?.tlsVersion
        ? { tlsVersion: representativeTls.tlsVersion }
        : {}),
      ...(representativeTls?.cipher
        ? { cipher: representativeTls.cipher }
        : {}),
      ...(representativeTls?.certSubject
        ? { certSubject: representativeTls.certSubject }
        : {}),
      ...(representativeTls?.certIssuer
        ? { certIssuer: representativeTls.certIssuer }
        : {}),
      ...(representativeTls?.certNotAfter
        ? { certNotAfter: representativeTls.certNotAfter }
        : {}),
      ...(minDaysRemaining !== undefined
        ? { certDaysRemaining: minDaysRemaining }
        : {}),
      certSelfSigned,
      ...(representativeTls?.sni ? { sni: representativeTls.sni } : {}),
      ...(errorEvent?.sslError ? { sslError: errorEvent.sslError } : {}),
      hasTlsData,
      tlsStatus,
      tlsPostureLabel,
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
      return a.sourceKind === "stream_tcp" ? -1 : 1;
    }
    const aRetrans = a.retransmitPct ?? -1;
    const bRetrans = b.retransmitPct ?? -1;
    if (aRetrans !== bRetrans) return bRetrans - aRetrans;
    if ((b.serverRttP95Ms ?? -1) !== (a.serverRttP95Ms ?? -1)) {
      return (b.serverRttP95Ms ?? -1) - (a.serverRttP95Ms ?? -1);
    }
    return b.totalBytes - a.totalBytes;
  });

  // Overall KPI metrics — one clear metric per tile with readable units.
  let kpis: ProtocolKpi[];
  if (sourceMode === "netflow_only") {
    const totalBytesAll = rows.reduce((sum, r) => sum + r.totalBytes, 0);
    const totalFlowsAll = rows.reduce((sum, r) => sum + r.flowCount, 0);
    const capPrefix = capped ? "≥ " : "";
    kpis = [
      {
        id: "netflow-pairs",
        label: "Observed pairs",
        value: `${capPrefix}${formatCount(rows.length)}`,
        unit: rows.length === 1 ? "pair" : "pairs",
      },
      {
        id: "netflow-bytes",
        label: "NetFlow volume",
        value: `${capPrefix}${formatBytes(totalBytesAll)}`,
      },
      {
        id: "netflow-flows",
        label: "Flow records",
        value: `${capPrefix}${formatCount(totalFlowsAll)}`,
        unit: totalFlowsAll === 1 ? "flow" : "flows",
      },
      {
        id: "rtt-tls-coverage",
        label: "RTT & TLS",
        value: "Not covered",
        status: "not_covered",
      },
    ];
  } else {
    const allServerRtts = allTcpEvents
      .map((e) => e.serverRttMs)
      .filter((v): v is number => v !== undefined);
    const overallServerRttP95 = percentile(allServerRtts, 95);
    const maxPairRetransPct = rows.reduce(
      (max, r) =>
        r.retransmitPct !== undefined && r.retransmitPct > max
          ? r.retransmitPct
          : max,
      0,
    );
    const totalResets = rows.reduce((sum, r) => sum + r.resets, 0);
    const tlsIssueCount = rows.filter(
      (r) => r.tlsStatus === "attention",
    ).length;
    const anyTlsObserved = rows.some((r) => r.hasTlsData);

    const serverRttSpark = buildSparklineBuckets(
      allTcpEvents,
      earliest,
      latest,
      (e) => e.serverRttMs,
      "p95",
    );
    const retransSpark = buildSparklineBuckets(
      allTcpEvents,
      earliest,
      latest,
      (e) => e.retransmitCount,
      "sum",
    );
    const resetSpark = buildSparklineBuckets(
      allTcpEvents,
      earliest,
      latest,
      (e) => e.resetCount,
      "sum",
    );
    const tlsIssueSpark = buildSparklineBuckets(
      allTcpEvents,
      earliest,
      latest,
      (e) =>
        e.legacyTls ||
        Boolean(e.sslError) ||
        (e.certDaysRemaining !== undefined &&
          e.certDaysRemaining <= thresholds.certExpiryWarnDays)
          ? 1
          : 0,
      "sum",
    );

    kpis = [
      {
        id: "server-rtt-p95",
        label: "Server RTT p95",
        value:
          overallServerRttP95 !== undefined
            ? overallServerRttP95 < 10
              ? overallServerRttP95.toFixed(1)
              : String(Math.round(overallServerRttP95))
            : "Not covered",
        ...(overallServerRttP95 !== undefined ? { unit: "ms" } : {}),
        status:
          overallServerRttP95 === undefined
            ? "not_covered"
            : overallServerRttP95 >= thresholds.rttWarnMs
              ? "attention"
              : "ok",
        ...(serverRttSpark.length ? { sparkline: serverRttSpark } : {}),
      },
      {
        id: "max-retransmit",
        label: "Max Retransmit",
        value: `${maxPairRetransPct.toFixed(1)}%`,
        status:
          maxPairRetransPct >= thresholds.retransmitWarnPct
            ? "attention"
            : "ok",
        ...(retransSpark.length ? { sparkline: retransSpark } : {}),
      },
      {
        id: "tcp-resets",
        label: "TCP Resets",
        value: formatCount(totalResets),
        unit: totalResets === 1 ? "reset" : "resets",
        status: totalResets > 0 ? "attention" : "ok",
        ...(resetSpark.length ? { sparkline: resetSpark } : {}),
      },
      {
        id: "tls-posture",
        label: "TLS Issues",
        value: !anyTlsObserved ? "Not covered" : String(tlsIssueCount),
        ...(anyTlsObserved
          ? { unit: tlsIssueCount === 1 ? "pair" : "pairs" }
          : {}),
        status: !anyTlsObserved
          ? "not_covered"
          : tlsIssueCount > 0
            ? "attention"
            : "ok",
        ...(tlsIssueSpark.length ? { sparkline: tlsIssueSpark } : {}),
      },
    ];
  }

  // Matrix dimensions and cells
  const matrixRows = [...new Set(rows.map((r) => r.client))].sort((a, b) =>
    a.localeCompare(b),
  );
  const matrixCols = [...new Set(rows.map((r) => r.server))].sort((a, b) =>
    a.localeCompare(b),
  );
  const matrixCells: ProtocolMatrixCell[] = rows.map((row) => ({
    row: row.client,
    col: row.server,
    status: row.status,
    value: buildMatrixCellLabel(row, thresholds),
    count: row.flowCount,
    detail: row.reasons.length
      ? row.reasons.join("; ")
      : "RTT, retransmits, and TLS within bounds",
    itemId: row.id,
  }));

  // Top servers RTT p50/p95 distribution bars
  const serverGroups = new Map<string, number[]>();
  for (const ev of allTcpEvents) {
    if (ev.serverRttMs === undefined) continue;
    const list = serverGroups.get(ev.server) ?? [];
    list.push(ev.serverRttMs);
    serverGroups.set(ev.server, list);
  }
  const distribution: ProtocolDistributionMetric[] = [...serverGroups.entries()]
    .map(([server, rtts]) => {
      const p50 = roundMetric(percentile(rtts, 50) ?? 0);
      const p95 = roundMetric(percentile(rtts, 95) ?? 0);
      return {
        id: server,
        label: server,
        p50,
        p95,
        unit: "ms",
        status: (p95 >= thresholds.rttWarnMs
          ? "attention"
          : "ok") as ProtocolStatus,
      };
    })
    .sort((a, b) => b.p95 - a.p95)
    .slice(0, 6);

  // Single-sentence plain-language verdict (keep thresholds in tooltips, not the headline).
  const flaggedRows = rows.filter((r) => r.attention);
  let verdict: string;
  let verdictStatus: ProtocolStatus;

  if (sourceMode === "netflow_only") {
    verdict = `NetFlow fallback only (${capped ? "≥ " : ""}${rows.length} ${rows.length === 1 ? "pair" : "pairs"} observed) — TCP RTT and TLS posture are not covered.`;
    verdictStatus = "not_covered";
  } else if (flaggedRows.length > 0) {
    const lead = flaggedRows[0];
    const leadSummary =
      lead.serverRttP95Ms !== undefined &&
      lead.serverRttP95Ms >= thresholds.rttWarnMs
        ? `high RTT (${formatDurationMs(lead.serverRttP95Ms)})`
        : lead.retransmitPct !== undefined &&
            lead.retransmitPct >= thresholds.retransmitWarnPct
          ? `${lead.retransmitPct.toFixed(1)}% retransmits`
          : lead.resets > 0
            ? `${lead.resets} TCP ${lead.resets === 1 ? "reset" : "resets"}`
            : (lead.reasons[0] ?? "exception");
    const tlsIssues = rows.filter((r) => r.tlsStatus === "attention").length;
    const extras: string[] = [
      `${leadSummary} on ${lead.client} → ${lead.server}`,
    ];
    if (tlsIssues > 0) {
      extras.push(`${tlsIssues} TLS ${tlsIssues === 1 ? "issue" : "issues"}`);
    }
    verdict = `${flaggedRows.length} of ${rows.length} ${rows.length === 1 ? "pair needs" : "pairs need"} attention: ${extras.join("; ")}.`;
    verdictStatus = "attention";
  } else {
    verdict = `${rows.length} of ${rows.length} ${rows.length === 1 ? "pair" : "pairs"} within RTT, retransmit, and TLS bounds.`;
    verdictStatus = "ok";
  }

  const anySourceFailed = anyBlocked || anyUnavailable;
  const coverageStatus: ProtocolStatus =
    sourceMode === "netflow_only"
      ? "not_covered"
      : anySourceFailed
        ? "attention"
        : "ok";
  const activeCount = outcomes.filter(
    (o) => o.state === "complete" || o.state === "partial",
  ).length;
  const coverageLabel =
    sourceMode === "netflow_only"
      ? "NetFlow only"
      : `${activeCount} ${activeCount === 1 ? "source" : "sources"}`;

  const blockedDetail = outcomes.find((o) => o.state === "blocked")?.detail;
  const unavailableDetail = outcomes.find(
    (o) => o.state === "unavailable",
  )?.detail;
  const partialReason =
    anyBlocked && sourceMode === "netflow_only"
      ? `Primary source blocked (${blockedDetail ?? "access denied"}); showing NetFlow fallback only.`
      : anyBlocked
        ? `One or more sources denied access (${blockedDetail ?? "access denied"}); results are incomplete.`
        : anyUnavailable
          ? `One or more sources failed (${unavailableDetail ?? "search unavailable"}); results are incomplete.`
          : "Sample capped at row limit — narrow the UTC window or filter.";

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

export interface InvestigateTcpTlsOptions {
  skipEstimateCheck?: boolean;
  skipConfigRecheck?: boolean;
  profileValidators?: Partial<Record<ProtocolLensId, LensProfileValidator>>;
}

/**
 * Executes the on-demand TCP/TLS investigation across configured `tcp_tls`
 * profiles (`stream:tcp` primary, `stream:netflow` fallback), rechecking the
 * `adm_protocol_profiles` fingerprint to discard stale results.
 */
export async function investigateTcpTls(
  client: SearchClient,
  request: ProtocolRequest,
  configuration: ProtocolConfiguration,
  signal: AbortSignal,
  options: InvestigateTcpTlsOptions = {},
): Promise<TcpTlsInvestigationResult> {
  const scoped = selectActiveProfiles(
    configuration.profiles,
    "tcp_tls",
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
      bannerReason: `No tcp_tls profile configured for scope "${request.scope}".`,
      checkedAt: Math.floor(Date.now() / 1000),
    };
  }

  const tcpProfiles = scoped.filter(
    (p) => resolveTcpTlsThresholds(p).sourcetype === "stream:tcp",
  );
  const netflowProfiles = scoped.filter(
    (p) => resolveTcpTlsThresholds(p).sourcetype === "stream:netflow",
  );

  const runProfiles = async () => {
    const outcomes: ProtocolSourceOutcome[] = [];
    const collected: { event: NormalizedTcpTlsEvent; indexName: string }[] = [];
    let capped = false;
    let chosenThresholds = resolveTcpTlsThresholds(
      tcpProfiles[0] ?? netflowProfiles[0],
    );

    for (const profile of tcpProfiles) {
      signal.throwIfAborted();
      const thresholds = resolveTcpTlsThresholds(profile);
      chosenThresholds = thresholds;
      const spl = buildTcpTlsSearch({
        index: profile.index,
        sourcetype: "stream:tcp",
        filter: request.filter,
        maxRows: 256,
      });
      const res = await runBoundedProtocolSearch(client, {
        lens: "tcp_tls",
        profile,
        spl,
        earliest: request.earliest,
        latest: request.latest,
        signal,
      });
      outcomes.push(res.outcome);
      if (res.capped) capped = true;
      for (const row of res.rows) {
        const norm = normalizeTcpTlsRow(row, "stream:tcp", request.latest);
        if (norm) collected.push({ event: norm, indexName: profile.index });
      }
    }

    // Fallback to stream:netflow only when no stream:tcp events were found, no
    // VNI filter is active (NetFlow records do not carry vxlan_id), and either
    // no endpoint/port filter was applied or primary stream:tcp could not run.
    const hasEndpointFilter = Boolean(
      request.filter?.src ||
      request.filter?.dst ||
      request.filter?.port ||
      request.filter?.device,
    );
    const primarySucceeded = outcomes.some(
      (o) => o.state === "complete" || o.state === "partial",
    );
    const allowNetflowFallback =
      !tcpProfiles.length || !hasEndpointFilter || !primarySucceeded;
    if (
      collected.length === 0 &&
      netflowProfiles.length > 0 &&
      !request.filter?.vni &&
      allowNetflowFallback
    ) {
      for (const profile of netflowProfiles) {
        signal.throwIfAborted();
        if (!tcpProfiles.length) {
          chosenThresholds = resolveTcpTlsThresholds(profile);
        }
        const spl = buildTcpTlsSearch({
          index: profile.index,
          sourcetype: "stream:netflow",
          filter: request.filter,
          maxRows: 256,
        });
        const res = await runBoundedProtocolSearch(client, {
          lens: "tcp_tls",
          profile,
          spl,
          earliest: request.earliest,
          latest: request.latest,
          signal,
        });
        outcomes.push(res.outcome);
        if (res.capped) capped = true;
        for (const row of res.rows) {
          const norm = normalizeTcpTlsRow(
            row,
            "stream:netflow",
            request.latest,
          );
          if (norm) collected.push({ event: norm, indexName: profile.index });
        }
      }
    }

    // Check Stream Estimate mode ONLY when stream:tcp returned 0 rows and
    // an explicit investigation was requested.
    let streamReadiness: StreamReadinessEntry | undefined;
    const tcpCompletedEmpty =
      tcpProfiles.length > 0 &&
      collected.every((c) => c.event.sourceType !== "stream:tcp") &&
      outcomes.some(
        (o) =>
          tcpProfiles.some((tp) => tp.id === o.profile) &&
          o.state === "complete",
      );
    if (tcpCompletedEmpty && !options.skipEstimateCheck) {
      const entries = await checkStreamEstimateMode(client, ["tcp"], signal);
      streamReadiness = entries[0];
      if (streamReadiness?.state === "estimate_only") {
        outcomes.push({
          source: "protocol_stream_readiness",
          state: "estimate_only",
          detail: streamReadiness.detail,
        });
      }
    }

    return buildTcpTlsAnalysis({
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
    tcp_tls: validateTcpTlsExtra,
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
 * Hub "Check all" summary runner for `tcp_tls`.
 */
export async function summarizeTcpTls(
  client: SearchClient,
  request: ProtocolRequest,
  configuration: ProtocolConfiguration,
  signal: AbortSignal,
  options?: InvestigateTcpTlsOptions,
): Promise<ProtocolLensSummary> {
  const result = await investigateTcpTls(
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
    lens: "tcp_tls",
    status,
    verdict: result.verdict,
    checkedAt: result.checkedAt,
    capped: result.capped,
    outcomes: result.outcomes,
  };
}
