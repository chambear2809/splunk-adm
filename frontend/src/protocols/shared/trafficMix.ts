import { literal } from "../../data/evidence";
import { optionalJobs } from "../../data/optionalJobs";
import {
  requireNoSearchErrors,
  SearchAccessDeniedError,
  type SearchClient,
} from "../../data/searchClient";
import type { ProtocolConfiguration, ProtocolStatus } from "./contract";
import { assertNoForbiddenFieldsInSpl } from "./fields";
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
  /** Optional tooltip explaining capped/partial/error status. */
  statusReason?: string;
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
  67: "DHCP (67)",
  68: "DHCP (68)",
  69: "TFTP (69)",
  80: "HTTP (80)",
  123: "NTP (123)",
  161: "SNMP (161)",
  162: "SNMP Trap (162)",
  179: "BGP (179)",
  389: "LDAP (389)",
  443: "HTTPS/TLS (443)",
  445: "SMB (445)",
  514: "Syslog (514)",
  636: "LDAPS (636)",
  1433: "MSSQL (1433)",
  1521: "Oracle (1521)",
  1812: "RADIUS (1812)",
  1813: "RADIUS Acct (1813)",
  2049: "NFS (2049)",
  2379: "etcd (2379)",
  3306: "MySQL (3306)",
  4789: "VXLAN (4789)",
  5060: "SIP (5060)",
  5432: "Postgres (5432)",
  6379: "Redis (6379)",
  6443: "K8s API (6443)",
  8080: "HTTP-Alt (8080)",
  8443: "HTTPS-Alt (8443)",
};

const WELL_KNOWN_PORTS_SPL = Object.keys(PORT_LABELS).join(",");

/**
 * Picks a verified NetFlow index for the active scope, if any.
 * Only selects profiles explicitly configured for NetFlow (`stream:netflow`,
 * `stream_netflow`, `netflow`) or `qos_icmp` (`auto` defaults to NetFlow).
 * Avoids guessing NetFlow on DME or `stream:tcp` indexes.
 */
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
  const qosAuto = scoped.find(
    (p) =>
      p.lens === "qos_icmp" &&
      (p.extra?.sourceKind === undefined || p.extra?.sourceKind === "auto") &&
      p.index,
  );
  return qosAuto?.index;
}

/**
 * Builds a bounded NetFlow protocol/port & IPv4/IPv6 mix search.
 * Classifies each directional flow by service port (well-known port from
 * either src or dest, else privileged port <=1023, else -1 for ephemeral/other),
 * applies `fillnull` so portless protocols (ICMP, GRE, OSPF) survive `stats BY`,
 * and computes exact grand totals & IPv4/IPv6 splits via `eventstats` BEFORE `| head`.
 */
export function buildTrafficMixSearch(options: {
  index: string;
  maxRows?: number;
}): string {
  const idx = literal(options.index, 80);
  const limit = Math.max(1, Math.min(options.maxRows ?? MAX_MIX_ROWS, 128));
  const spl = [
    `search index="${idx}" sourcetype="stream:netflow"`,
    `| eval ip_family=if(like(src_ip,"%:%") OR like(dest_ip,"%:%"),"IPv6","IPv4")`,
    `| eval proto_num=coalesce(tonumber(protoid), -1)`,
    `| eval sp=tonumber(src_port), dp=tonumber(dest_port)`,
    `| eval min_p=if(isnotnull(sp) AND sp>0 AND isnotnull(dp) AND dp>0, min(sp, dp), coalesce(if(dp>0, dp, null()), if(sp>0, sp, null()), -1))`,
    `| eval service_port=case(dp IN (${WELL_KNOWN_PORTS_SPL}), dp, sp IN (${WELL_KNOWN_PORTS_SPL}), sp, min_p>0 AND min_p<=1023, min_p, 1=1, -1)`,
    `| eval row_bytes=coalesce(tonumber(bytes), if(isnotnull(bytes_in) OR isnotnull(bytes_out), coalesce(tonumber(bytes_in), 0)+coalesce(tonumber(bytes_out), 0), null()), 0)`,
    `| fillnull value=-1 proto_num service_port`,
    `| stats sum(row_bytes) AS total_bytes count AS flows BY proto_num service_port ip_family`,
    `| eventstats sum(total_bytes) AS grand_bytes sum(flows) AS grand_flows sum(eval(if(ip_family=="IPv6", total_bytes, 0))) AS grand_ipv6_bytes sum(eval(if(ip_family=="IPv6", flows, 0))) AS grand_ipv6_flows`,
    `| sort 0 -total_bytes -flows`,
    `| head ${limit + 1}`,
    `| table proto_num service_port ip_family total_bytes flows grand_bytes grand_flows grand_ipv6_bytes grand_ipv6_flows`,
  ].join(" ");
  assertNoForbiddenFieldsInSpl("qos_icmp", spl);
  return spl;
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
  if (port !== undefined && port > 0 && PORT_LABELS[port]) {
    return PORT_LABELS[port];
  }
  const protoName =
    protoid !== undefined && protoid >= 0
      ? (PROTO_NAMES[protoid] ?? `Proto ${protoid}`)
      : "Other";
  if (port !== undefined && port > 0 && (protoid === 6 || protoid === 17)) {
    return `${protoName}/${port}`;
  }
  if ((protoid === 6 || protoid === 17) && (port === undefined || port < 0)) {
    return `Other ${protoName}`;
  }
  return protoName;
}

export function summarizeTrafficMixRows(
  rows: readonly Record<string, unknown>[],
  options: { capped: boolean; index?: string; nowSec?: number; limit?: number },
): TrafficMixResult {
  const checkedAt = options.nowSec ?? Math.floor(Date.now() / 1000);
  const limit = options.limit ?? MAX_MIX_ROWS;
  if (!rows.length) {
    return {
      status: options.capped ? "unknown" : "none_observed",
      summary: options.capped
        ? "NetFlow traffic mix hit row cap before returning rows."
        : "No NetFlow traffic observed in this UTC window.",
      ...(options.capped
        ? {
            statusReason:
              "Search hit the row cap before returning aggregated buckets.",
          }
        : {}),
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

  let sumBytes = 0;
  let sumFlows = 0;
  let sumIpv4Bytes = 0;
  let sumIpv6Bytes = 0;
  let sumIpv4Flows = 0;

  let grandBytes: number | undefined;
  let grandFlows: number | undefined;
  let grandIpv6Bytes: number | undefined;
  let grandIpv6Flows: number | undefined;

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
    const rawProto = asNum(row.proto_num ?? row.protoid);
    const protoid =
      rawProto !== undefined && rawProto >= 0 ? rawProto : undefined;
    const rawPort = asNum(row.service_port ?? row.port_num ?? row.dest_port);
    const port = rawPort !== undefined && rawPort > 0 ? rawPort : undefined;
    const bytes = Math.max(0, asNum(row.total_bytes ?? row.bytes) ?? 0);
    const flows = Math.max(0, Math.trunc(asNum(row.flows ?? row.count) ?? 0));
    const family =
      typeof row.ip_family === "string" &&
      row.ip_family.toUpperCase() === "IPV6"
        ? "IPv6"
        : "IPv4";

    if (grandBytes === undefined) {
      const gb = asNum(row.grand_bytes);
      const gf = asNum(row.grand_flows);
      const g6b = asNum(row.grand_ipv6_bytes);
      const g6f = asNum(row.grand_ipv6_flows);
      if (gb !== undefined) grandBytes = Math.max(0, gb);
      if (gf !== undefined) grandFlows = Math.max(0, Math.trunc(gf));
      if (g6b !== undefined) grandIpv6Bytes = Math.max(0, g6b);
      if (g6f !== undefined) grandIpv6Flows = Math.max(0, Math.trunc(g6f));
    }

    sumBytes += bytes;
    sumFlows += flows;
    if (family === "IPv6") {
      sumIpv6Bytes += bytes;
    } else {
      sumIpv4Bytes += bytes;
      sumIpv4Flows += flows;
    }

    const label = formatProtocolBucketLabel(protoid, port);
    const existing = byBucket.get(label);
    if (existing) {
      existing.bytes += bytes;
      existing.flows += flows;
    } else {
      byBucket.set(label, { label, protoid, port, bytes, flows });
    }
  }

  const totalBytes =
    grandBytes !== undefined ? Math.max(grandBytes, sumBytes) : sumBytes;
  const totalFlows =
    grandFlows !== undefined ? Math.max(grandFlows, sumFlows) : sumFlows;
  const ipv6Bytes =
    grandIpv6Bytes !== undefined ? grandIpv6Bytes : sumIpv6Bytes;
  const ipv4Bytes =
    grandBytes !== undefined
      ? Math.max(0, totalBytes - ipv6Bytes)
      : sumIpv4Bytes;
  const ipv6Flows =
    grandIpv6Flows !== undefined
      ? grandIpv6Flows
      : Math.max(0, sumFlows - sumIpv4Flows);
  const ipv4Flows = Math.max(0, totalFlows - ipv6Flows);

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
  const capSuffix = options.capped ? ` (top ${limit} buckets shown)` : "";
  const summary = lead
    ? `${formatBytes(totalBytes)} across ${formatCount(totalFlows)} flows — led by ${lead.label}, ${lead.sharePct}%${capSuffix}.`
    : `${formatBytes(totalBytes)} across ${formatCount(totalFlows)} flows${capSuffix}.`;

  return {
    status: options.capped ? "unknown" : "ok",
    summary,
    ...(options.capped
      ? {
          statusReason: `More than ${limit} service-port buckets matched; totals reflect all flows via eventstats, and top ${limit} buckets are ranked.`,
        }
      : {}),
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
    return summarizeTrafficMixRows(rows, {
      capped,
      index,
      nowSec: checkedAt,
      limit: MAX_MIX_ROWS,
    });
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
      statusReason: detail,
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
