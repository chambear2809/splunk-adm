import { literal } from "../../data/evidence";
import { optionalJobs } from "../../data/optionalJobs";
import {
  requireNoSearchErrors,
  SearchAccessDeniedError,
  type SearchClient,
} from "../../data/searchClient";
import type { ProtocolConfiguration, ProtocolStatus } from "./contract";
import { formatBytes, formatCount } from "./format";

export interface ProtocolTrafficBucket {
  id: string;
  label: string;
  protoid?: number;
  port?: number;
  bytes: number;
  flows: number;
  sharePct: number;
}

export interface TrafficMixResult {
  status: ProtocolStatus;
  summary: string;
  totalBytes: number;
  totalFlows: number;
  ipv4Bytes: number;
  ipv6Bytes: number;
  ipv4Pct: number;
  ipv6Pct: number;
  topProtocols: ProtocolTrafficBucket[];
  capped: boolean;
  index?: string;
  checkedAt: number;
}

const MAX_MIX_ROWS = 64;

const PROTO_NAMES: Record<number, string> = {
  1: "ICMP",
  6: "TCP",
  17: "UDP",
  47: "GRE",
  50: "ESP",
  58: "ICMPv6",
  89: "OSPF",
  103: "PIM",
};

const PORT_LABELS: Record<number, string> = {
  22: "SSH (22)",
  23: "Telnet (23)",
  53: "DNS (53)",
  80: "HTTP (80)",
  123: "NTP (123)",
  161: "SNMP (161)",
  179: "BGP (179)",
  389: "LDAP (389)",
  443: "HTTPS/TLS (443)",
  445: "SMB (445)",
  636: "LDAPS (636)",
  1433: "MSSQL (1433)",
  1521: "Oracle (1521)",
  2049: "NFS (2049)",
  3306: "MySQL (3306)",
  4789: "VXLAN (4789)",
  5432: "Postgres (5432)",
  8080: "HTTP-Alt (8080)",
  8443: "HTTPS-Alt (8443)",
};

const NETFLOW_CAPABLE_LENSES = new Set([
  "qos_icmp",
  "tcp_tls",
  "mgmt_plane",
  "routing",
]);

/** Picks a configured NetFlow-capable index for the active scope, if any. */
export function selectTrafficMixIndex(
  configuration: ProtocolConfiguration,
  scope: string,
): string | undefined {
  const scoped = configuration.profiles.filter((p) => p.scope === scope);
  const explicit = scoped.find(
    (p) =>
      (p.extra?.sourcetype === "stream:netflow" ||
        p.extra?.sourceKind === "stream_netflow" ||
        p.extra?.sourceKind === "netflow") &&
      p.index,
  );
  if (explicit) return explicit.index;
  const fallback = scoped.find(
    (p) => NETFLOW_CAPABLE_LENSES.has(p.lens) && p.index,
  );
  return fallback?.index;
}

/**
 * Builds a bounded NetFlow protocol/port & IPv4/IPv6 mix search.
 * Aggregates strictly on `protoid`, `dest_port`, and IP family without `_raw`.
 */
export function buildTrafficMixSearch(options: {
  index: string;
  maxRows?: number;
}): string {
  const idx = literal(options.index, 80);
  const limit = Math.max(1, Math.min(options.maxRows ?? MAX_MIX_ROWS, 128));
  return [
    `search index="${idx}" sourcetype="stream:netflow"`,
    `| eval ip_family=if(like(src_ip,"%:%") OR like(dest_ip,"%:%"),"IPv6","IPv4")`,
    `| eval proto_num=tonumber(protoid)`,
    `| eval port_num=tonumber(dest_port)`,
    `| eval row_bytes=coalesce(tonumber(bytes), tonumber(bytes_in)+tonumber(bytes_out), 0)`,
    `| stats sum(row_bytes) AS total_bytes count AS flows BY proto_num port_num ip_family`,
    `| sort 0 -total_bytes -flows`,
    `| head ${limit + 1}`,
    `| table proto_num port_num ip_family total_bytes flows`,
  ].join(" ");
}

function asNum(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value)) return value;
  if (typeof value === "string" && value.trim()) {
    const n = Number(value);
    if (Number.isFinite(n)) return n;
  }
  return undefined;
}

function formatProtocolBucketLabel(protoid?: number, port?: number): string {
  if (port !== undefined && PORT_LABELS[port]) return PORT_LABELS[port];
  const protoName =
    protoid !== undefined
      ? (PROTO_NAMES[protoid] ?? `Proto ${protoid}`)
      : "Other";
  if (port !== undefined && port > 0 && (protoid === 6 || protoid === 17)) {
    return `${protoName}/${port}`;
  }
  return protoName;
}

export function summarizeTrafficMixRows(
  rows: readonly Record<string, unknown>[],
  options: { capped: boolean; index?: string; nowSec?: number },
): TrafficMixResult {
  const checkedAt = options.nowSec ?? Math.floor(Date.now() / 1000);
  if (!rows.length) {
    return {
      status: options.capped ? "unknown" : "none_observed",
      summary: options.capped
        ? "NetFlow traffic mix hit row cap before returning rows."
        : "No NetFlow traffic observed in this UTC window.",
      totalBytes: 0,
      totalFlows: 0,
      ipv4Bytes: 0,
      ipv6Bytes: 0,
      ipv4Pct: 0,
      ipv6Pct: 0,
      topProtocols: [],
      capped: options.capped,
      index: options.index,
      checkedAt,
    };
  }

  let totalBytes = 0;
  let totalFlows = 0;
  let ipv4Bytes = 0;
  let ipv6Bytes = 0;
  let ipv4Flows = 0;

  const byBucket = new Map<
    string,
    {
      label: string;
      protoid?: number;
      port?: number;
      bytes: number;
      flows: number;
    }
  >();

  for (const row of rows) {
    const protoid = asNum(row.proto_num ?? row.protoid);
    const port = asNum(row.port_num ?? row.dest_port);
    const bytes = Math.max(0, asNum(row.total_bytes ?? row.bytes) ?? 0);
    const flows = Math.max(0, Math.trunc(asNum(row.flows ?? row.count) ?? 0));
    const family =
      typeof row.ip_family === "string" &&
      row.ip_family.toUpperCase() === "IPV6"
        ? "IPv6"
        : "IPv4";

    totalBytes += bytes;
    totalFlows += flows;
    if (family === "IPv6") {
      ipv6Bytes += bytes;
    } else {
      ipv4Bytes += bytes;
      ipv4Flows += flows;
    }

    const label = formatProtocolBucketLabel(protoid, port);
    const key = label;
    const existing = byBucket.get(key);
    if (existing) {
      existing.bytes += bytes;
      existing.flows += flows;
    } else {
      byBucket.set(key, { label, protoid, port, bytes, flows });
    }
  }

  const denom = totalBytes > 0 ? totalBytes : Math.max(1, totalFlows);
  const ipv4Pct =
    totalBytes > 0
      ? Number(((ipv4Bytes / totalBytes) * 100).toFixed(1))
      : Number(((ipv4Flows / Math.max(1, totalFlows)) * 100).toFixed(1));
  const ipv6Pct = Number(Math.max(0, 100 - ipv4Pct).toFixed(1));

  const sorted = [...byBucket.values()]
    .sort((a, b) => b.bytes - a.bytes || b.flows - a.flows)
    .slice(0, 6)
    .map((entry) => ({
      id: entry.label,
      label: entry.label,
      protoid: entry.protoid,
      port: entry.port,
      bytes: entry.bytes,
      flows: entry.flows,
      sharePct: Number(
        (((totalBytes > 0 ? entry.bytes : entry.flows) / denom) * 100).toFixed(
          1,
        ),
      ),
    }));

  const lead = sorted[0];
  const summary = lead
    ? `${formatBytes(totalBytes)} across ${formatCount(totalFlows)} flows — led by ${lead.label} (${lead.sharePct}%) · IPv4 ${ipv4Pct}% / IPv6 ${ipv6Pct}%.`
    : `${formatBytes(totalBytes)} across ${formatCount(totalFlows)} flows.`;

  return {
    status: options.capped ? "unknown" : "ok",
    summary,
    totalBytes,
    totalFlows,
    ipv4Bytes,
    ipv6Bytes,
    ipv4Pct,
    ipv6Pct,
    topProtocols: sorted,
    capped: options.capped,
    index: options.index,
    checkedAt,
  };
}

/**
 * On-demand NetFlow traffic mix loader for the Protocols hub.
 * Never auto-runs on mount; invoked only by explicit user action.
 */
export async function loadProtocolTrafficMix(
  client: SearchClient,
  options: {
    configuration: ProtocolConfiguration;
    scope: string;
    earliest: number;
    latest: number;
    signal: AbortSignal;
  },
): Promise<TrafficMixResult> {
  const checkedAt = Math.floor(Date.now() / 1000);
  const index = selectTrafficMixIndex(options.configuration, options.scope);
  if (!index) {
    return {
      status: "not_covered",
      summary: "No NetFlow-capable protocol profile covers this scope.",
      totalBytes: 0,
      totalFlows: 0,
      ipv4Bytes: 0,
      ipv6Bytes: 0,
      ipv4Pct: 0,
      ipv6Pct: 0,
      topProtocols: [],
      capped: false,
      checkedAt,
    };
  }
  const spl = buildTrafficMixSearch({ index, maxRows: MAX_MIX_ROWS });
  const deadline = AbortSignal.timeout(25000);
  const searchSignal = AbortSignal.any([options.signal, deadline]);
  const key = `protocol_traffic_mix:${options.scope}:${index}:${options.earliest}:${options.latest}`;
  try {
    const result = await optionalJobs.run("protocol_traffic_mix", key, client, {
      search: spl,
      earliest: String(options.earliest),
      latest: String(options.latest),
      maxRows: MAX_MIX_ROWS,
      allowEmpty: true,
      overflow: "truncate",
      signal: searchSignal,
    });
    requireNoSearchErrors(result, "protocol_traffic_mix");
    const capped =
      Boolean(result.truncated) || result.rows.length > MAX_MIX_ROWS;
    const rows =
      result.rows.length > MAX_MIX_ROWS
        ? result.rows.slice(0, MAX_MIX_ROWS)
        : result.rows;
    return summarizeTrafficMixRows(rows, { capped, index, nowSec: checkedAt });
  } catch (error) {
    if (options.signal.aborted) throw error;
    const detail =
      error instanceof SearchAccessDeniedError
        ? "Caller lacks access to the NetFlow index."
        : error instanceof Error
          ? error.message
          : "Traffic mix search failed.";
    return {
      status: "unknown",
      summary: detail,
      totalBytes: 0,
      totalFlows: 0,
      ipv4Bytes: 0,
      ipv6Bytes: 0,
      ipv4Pct: 0,
      ipv6Pct: 0,
      topProtocols: [],
      capped: false,
      index,
      checkedAt,
    };
  }
}
