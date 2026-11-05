import type { Graph, GraphEdge, GraphNode } from "../graph";

/**
 * Deterministic synthetic graphs for scale benchmarks and tests. Shapes follow
 * the adm_graph contract (service/workload/endpoint kinds, runs_on, calls and
 * communicates_with relationships with server ports and byte counters); the
 * values are synthetic and carry no customer data.
 */
export interface SyntheticOptions {
  nodes: number;
  edges: number;
  seed?: number;
  /** Fraction of conversations with an ACL drop (default 0.01). */
  blocked?: number;
}

function rng(seed: number) {
  let s = seed >>> 0 || 1;
  return () => {
    s ^= s << 13;
    s ^= s >>> 17;
    s ^= s << 5;
    return (s >>> 0) / 4294967296;
  };
}

const PORTS: [number, string][] = [
  [443, "tcp"],
  [8080, "tcp"],
  [5432, "tcp"],
  [6379, "tcp"],
  [53, "udp"],
  [9092, "tcp"],
  [50051, "tcp"],
];

export function syntheticGraph(options: SyntheticOptions): Graph {
  const random = rng(options.seed ?? 7);
  const blocked = options.blocked ?? 0.01;
  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];
  const total = Math.max(4, options.nodes);
  const serviceCount = Math.max(2, Math.round(total * 0.04));
  const podCount = Math.round(total * 0.5);
  const foreignCount = Math.round(total * 0.16);
  const hostCount = Math.max(2, Math.round(total * 0.02));
  const endpointCount =
    total - serviceCount - podCount - foreignCount - hostCount;
  const svc = (i: number) => `service:c1/shop/s${i}/prod`;
  for (let i = 0; i < serviceCount; i++)
    nodes.push({
      id: svc(i),
      label: `svc-${i}`,
      kind: "service",
      namespace: "shop",
      cluster: "c1",
    });
  const pods: string[] = [];
  for (let i = 0; i < podCount; i++) {
    const id = `pod:c1/shop/p${i}`;
    pods.push(id);
    nodes.push({
      id,
      label: `svc-${i % serviceCount}-7d9f-${i.toString(36)}`,
      kind: "workload",
      namespace: "shop",
      cluster: "c1",
      addresses: [`10.1.${(i >> 8) & 255}.${i & 255}`],
      attributes: { node: `node-${i % hostCount}`, owner: `owner-${i % 97}` },
    });
  }
  const peers: string[] = [];
  for (let i = 0; i < foreignCount; i++) {
    const id = `pod:c1/ns${i % 23}/f${i}`;
    peers.push(id);
    nodes.push({
      id,
      label: `ext-pod-${i}`,
      kind: "workload",
      namespace: `ns${i % 23}`,
      cluster: "c1",
      addresses: [`10.2.${(i >> 8) & 255}.${i & 255}`],
    });
  }
  for (let i = 0; i < hostCount; i++) {
    const id = `node:c1/node-${i}`;
    peers.push(id);
    nodes.push({
      id,
      label: `node-${i}`,
      kind: "endpoint",
      endpoint_kind: "k8s_node",
      cluster: "c1",
      addresses: [`192.168.0.${i & 255}`],
    });
  }
  for (let i = 0; i < endpointCount; i++) {
    const kind = i % 5;
    const ip = `198.51.${(i >> 8) & 255}.${i & 255}`;
    const id = `ip:${ip}`;
    peers.push(id);
    nodes.push(
      kind === 0
        ? {
            id,
            label: `vm-${i}`,
            kind: "endpoint",
            endpoint_kind: "vm",
            addresses: [ip],
            attributes: {
              tenant: `t${i % 3}`,
              app_profile: "core",
              epg: `epg-${i % 17}`,
            },
          }
        : {
            id,
            label: ip,
            kind: "endpoint",
            endpoint_kind: kind === 1 ? "unresolved" : "external",
            addresses: [ip],
          },
    );
  }
  let n = 0;
  const edge = (e: Omit<GraphEdge, "id" | "evidence">) =>
    edges.push({ ...e, id: `e${n++}`, evidence: [] });
  for (let i = 0; i < podCount; i++)
    edge({
      source: svc(i % serviceCount),
      target: pods[i],
      relationship: "runs_on",
      confidence: "correlated",
      count: 1,
    });
  for (let i = 1; i < serviceCount && edges.length < options.edges; i++)
    edge({
      source: svc(Math.floor((i - 1) / 3)),
      target: svc(i),
      relationship: "calls",
      confidence: "observed",
      count: 1 + Math.floor(random() * 500),
    });
  const seen = new Set<string>();
  const ends = [...pods, ...peers];
  let guard = 0;
  while (edges.length < options.edges && guard++ < options.edges * 8) {
    const a = pods[Math.floor(random() * random() * pods.length)];
    const b = ends[Math.floor(random() * ends.length)];
    if (a === b) continue;
    const [port, transport] = PORTS[Math.floor(random() * PORTS.length)];
    const key = `${a}|${b}|${port}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const bytes = Math.floor(10 ** (2 + random() * 8));
    edge({
      source: a,
      target: b,
      relationship: "communicates_with",
      confidence: "correlated",
      direction_basis: random() < 0.85 ? "initiator" : "unknown",
      server_port: port,
      transport,
      bytes,
      count: 1 + Math.floor(bytes / 20000),
      ...(random() < blocked ? { acl_action: "drop" as const } : {}),
    });
  }
  return {
    schema_version: 1,
    snapshot_id: `synthetic:${total}:${options.edges}`,
    generated_at: "2026-10-07T12:00:00.000Z",
    demo: true,
    window: {
      start: "2026-10-07T11:00:00.000Z",
      end: "2026-10-07T12:00:00.000Z",
    },
    boundary: {
      id: "c1/shop/svc-0/prod",
      service: "svc-0",
      environment: "prod",
      cluster: "c1",
      namespace: "shop",
      root_node_id: svc(0),
    },
    nodes,
    edges,
    coverage: {
      spans: 0,
      conversations: edges.length,
      matched_conversations: edges.length,
      unresolved_conversations: 0,
      ambiguous_conversations: 0,
      warnings: [],
    },
  };
}
