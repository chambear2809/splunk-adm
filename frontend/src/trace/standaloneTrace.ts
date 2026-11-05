import { pathTraceSearch } from "../data/deviceFlows";
import { requireNoSearchErrors, type SearchClient } from "../data/searchClient";
import type { EndpointKind, Graph, GraphNode } from "../graph";
import { loadTopology } from "../provider";
import { emptyTopology } from "../topology";
import { isSafeIdentifier } from "../app/urlState";

const IP = /^[0-9A-Fa-f:.]{2,45}$/;
export const isIpLiteral = (s: string) => IP.test(s) && /[.:]/.test(s);
const MAX_RESOLVE_ROWS = 64;
const MAX_TRACE_ROWS = 2000;

const first = (v: unknown): string | undefined => {
  const x = Array.isArray(v) ? v[0] : v;
  return typeof x === "string" && x.trim() ? x.trim() : undefined;
};
const all = (v: unknown): string[] =>
  (Array.isArray(v) ? v : [v])
    .filter((x): x is string => typeof x === "string" && x.trim() !== "")
    .map((x) => x.trim());

/** Server-side name → address lookup; the value must be a safe identifier. */
export function pathTraceResolveSearch(value: string): string {
  if (!isSafeIdentifier(value) || /[,"`$]/.test(value))
    throw new Error("Invalid endpoint name.");
  return `| \`adm_path_trace_resolve(${value})\``;
}

/** Distinct IP literals from adm_path_trace_resolve rows. */
export function resolvedAddresses(rows: readonly unknown[]): string[] {
  const out = new Set<string>();
  for (const r of rows)
    if (r && typeof r === "object")
      for (const ip of all((r as Record<string, unknown>).ip))
        if (isIpLiteral(ip)) out.add(ip);
  return [...out].sort();
}

const ENDPOINT_KINDS: EndpointKind[] = [
  "k8s_node",
  "vm",
  "external",
  "network_client",
  "k8s_service",
];
const IDENTITY_RANK: Record<string, number> = {
  vm: 0,
  k8s_node: 1,
  pod: 2,
  network_client: 3,
  other: 4,
};
const K8S_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$/;
const ATTRS = [
  "attach_device",
  "attach_interface",
  "epg",
  "tenant",
  "app_profile",
  "mac",
  "scope",
  "vm_name",
  "service",
] as const;

/**
 * A graph holding only the pair's endpoints, from adm_path_trace endpoint
 * rows (adm_ip_identity). An address without an identity row stays a bare
 * endpoint so the trace can still resolve it by IP. A pod becomes a workload
 * on its Kubernetes node; adm_path_pod_nodes rows (trace_role pod_node) add
 * that node so its own attachment (for example a VM vNIC) carries the pod.
 */
export function endpointGraph(
  rows: readonly unknown[],
  addresses: readonly string[],
): Graph {
  const nodes = new Map<string, GraphNode>();
  // vSphere-only VMs resolve through their virtual port, not a bare node.
  const virtual = new Set<string>();
  for (const raw of rows) {
    const r = raw as Record<string, unknown> | null;
    if (r?.row_type === "link" && r.link_kind === "virtual_port")
      all(r.ip).forEach((ip) => virtual.add(ip));
  }
  // An address can carry several identities (VM vNIC, Kubernetes node, host
  // network pod). The network path starts at the vNIC, so a VM identity wins,
  // then a node, then any other kind; a mapped scope wins over an unmapped one.
  const rank = (r: Record<string, unknown>) =>
    (IDENTITY_RANK[first(r.entity_kind) ?? ""] ?? IDENTITY_RANK.other) * 2 +
    (first(r.scope)?.startsWith("unmapped:") ? 1 : 0);
  const chosen = new Map<string, Record<string, unknown>>();
  const hosts = new Map<string, GraphNode>();
  for (const raw of rows) {
    if (!raw || typeof raw !== "object") continue;
    const r = raw as Record<string, unknown>;
    if (r.row_type !== "endpoint") continue;
    if (r.trace_role === "pod_node") {
      const name = first(r.entity_name),
        cluster = first(r.cluster),
        ip = first(r.ip);
      if (
        first(r.entity_kind) !== "k8s_node" ||
        !name ||
        !cluster ||
        !K8S_NAME.test(name) ||
        !K8S_NAME.test(cluster) ||
        !ip ||
        !isIpLiteral(ip)
      )
        continue;
      const id = `node:${cluster}/${name}`;
      const prior = hosts.get(id);
      // One node, one address: a node row naming another address is ambiguous.
      if (prior && prior.addresses?.[0] !== ip) {
        hosts.set(id, { ...prior, addresses: [] });
        continue;
      }
      const scope = first(r.scope);
      hosts.set(id, {
        id,
        label: name,
        kind: "endpoint",
        endpoint_kind: "k8s_node",
        cluster,
        addresses: prior?.addresses ?? [ip],
        attributes: {
          ...(prior?.attributes ?? {}),
          ...(scope && !scope.startsWith("unmapped:") ? { scope } : {}),
        },
      });
      continue;
    }
    const ip = first(r.ip);
    if (!ip || !isIpLiteral(ip)) continue;
    const prior = chosen.get(ip);
    if (!prior || rank(r) < rank(prior)) chosen.set(ip, r);
  }
  for (const [ip, r] of chosen) {
    const name = first(r.entity_name);
    const cluster = first(r.cluster);
    const node = first(r.node);
    if (
      first(r.entity_kind) === "pod" &&
      name &&
      cluster &&
      node &&
      K8S_NAME.test(node)
    ) {
      const namespace = first(r.namespace);
      const scope = first(r.scope);
      nodes.set(ip, {
        id: `pod:${cluster}/${namespace ?? ""}/${name}`,
        label: name,
        kind: "workload",
        cluster,
        ...(namespace ? { namespace } : {}),
        addresses: [ip],
        attributes: {
          node,
          ...(scope ? { scope } : {}),
          ...(first(r.owner_name) ? { owner_name: first(r.owner_name)! } : {}),
        },
      });
      continue;
    }
    const kind = first(r.entity_kind) as EndpointKind | undefined;
    const attributes: Record<string, string> = {};
    for (const key of ATTRS) {
      const v = first(r[key]);
      if (v) attributes[key] = v;
    }
    const scope = attributes.scope;
    nodes.set(ip, {
      id: `${kind ?? "endpoint"}:${scope ? `${scope}/` : ""}${ip}`,
      label: first(r.entity_name) ?? attributes.vm_name ?? ip,
      kind: "endpoint",
      endpoint_kind: kind && ENDPOINT_KINDS.includes(kind) ? kind : "external",
      addresses: [ip],
      attributes,
    });
  }
  for (const ip of addresses)
    if (!nodes.has(ip) && !virtual.has(ip))
      nodes.set(ip, {
        id: `ip:${ip}`,
        label: ip,
        kind: "endpoint",
        endpoint_kind: "external",
        addresses: [ip],
      });
  const instant = new Date(0).toISOString();
  return {
    schema_version: 1,
    snapshot_id: "path-trace",
    generated_at: instant,
    demo: false,
    window: { start: instant, end: instant },
    boundary: {
      id: "path-trace",
      service: "",
      environment: "",
      cluster: "",
      namespace: "",
      root_node_id: "",
    },
    nodes: [
      ...nodes.values(),
      ...[...hosts.values()].filter((h) => h.addresses?.length),
    ],
    edges: [],
    coverage: {
      spans: 0,
      conversations: 0,
      matched_conversations: 0,
      unresolved_conversations: 0,
      ambiguous_conversations: 0,
      warnings: [],
    },
  };
}

interface Window {
  earliest: string;
  latest?: string;
  timezone?: string;
  signal: AbortSignal;
}

/** One side: an IP literal as-is, otherwise exactly one resolved address. */
export async function resolveTraceAddress(
  client: SearchClient,
  query: string,
  side: "Source" | "Destination",
  w: Window,
): Promise<string> {
  if (isIpLiteral(query)) return query;
  const result = requireNoSearchErrors(
    await client.search({
      search: pathTraceResolveSearch(query),
      earliest: w.earliest,
      latest: w.latest,
      timezone: w.timezone,
      maxRows: MAX_RESOLVE_ROWS,
      allowEmpty: true,
      signal: w.signal,
    }),
    `${side} lookup`,
  );
  const ips = resolvedAddresses(result.rows);
  if (ips.length === 1) return ips[0];
  throw new Error(
    ips.length
      ? `${side} "${query}" matches ${ips.length} addresses; enter an IP.`
      : `${side} "${query}" not found.`,
  );
}

/**
 * Trace without a built map: names resolve server-side, then adm_path_trace
 * returns observations, identities and vSphere rows; fabric links come from
 * adm_topology in the same window.
 */
export async function loadStandaloneTrace(
  client: SearchClient,
  request: { src: string; dst: string },
  w: Window,
) {
  const [src, dst] = await Promise.all([
    resolveTraceAddress(client, request.src, "Source", w),
    resolveTraceAddress(client, request.dst, "Destination", w),
  ]);
  const [trace, topology] = await Promise.all([
    client.search({
      search: pathTraceSearch(src, dst),
      earliest: w.earliest,
      latest: w.latest,
      timezone: w.timezone,
      maxRows: MAX_TRACE_ROWS,
      allowEmpty: true,
      signal: w.signal,
    }),
    loadTopology(client, w.earliest, w.signal, w.latest, w.timezone).catch(() =>
      emptyTopology(),
    ),
  ]);
  const rows = requireNoSearchErrors(trace, "Path trace").rows;
  return {
    addresses: { src, dst },
    rows,
    graph: endpointGraph(rows, [src, dst]),
    topology,
  };
}
