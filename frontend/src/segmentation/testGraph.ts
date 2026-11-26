import type { Graph, GraphEdge, GraphNode } from "../graph";

/** UNIT-TEST DATA ONLY: a small graph shaped like adm_graph output. */
export const T = {
  service: "service:c1/shop/checkout/prod",
  checkoutPod: "pod:c1/co-1",
  frontendPod: "pod:c1/fe-1",
  otherNsPod: "pod:c1/ops-1",
  db: "vm:prod/10.20.30.40",
  win: "vm:prod/10.30.40.25",
  svcFrontend: "k8s_service:c1/shop/checkout-api/10.50.0.20:8080",
  external: "ip:prod/203.0.113.40",
  unresolved: "ip:prod/10.99.0.5",
};

export function testGraph(overrides: Partial<Graph> = {}): Graph {
  const nodes: GraphNode[] = [
    {
      id: T.service,
      label: "checkout",
      kind: "service",
      namespace: "shop",
      cluster: "c1",
      attributes: { environment: "prod" },
    },
    {
      id: T.checkoutPod,
      label: "checkout-abc",
      kind: "workload",
      namespace: "shop",
      cluster: "c1",
      addresses: ["10.42.0.20"],
      attributes: { owner: "checkout", owner_kind: "Deployment" },
    },
    {
      id: T.frontendPod,
      label: "frontend-abc",
      kind: "workload",
      namespace: "shop",
      cluster: "c1",
      addresses: ["10.42.0.15"],
      attributes: { owner: "frontend", owner_kind: "Deployment" },
    },
    {
      id: T.otherNsPod,
      label: "ops-abc",
      kind: "workload",
      namespace: "ops",
      cluster: "c1",
      addresses: ["10.42.1.9"],
    },
    {
      id: T.db,
      label: "orders-db-01",
      kind: "endpoint",
      endpoint_kind: "vm",
      addresses: ["10.20.30.40"],
      attributes: {
        tenant: "shop",
        app_profile: "orders",
        epg: "db",
        scope: "prod",
      },
    },
    {
      id: T.win,
      label: "win-client-01",
      kind: "endpoint",
      endpoint_kind: "vm",
      addresses: ["10.30.40.25"],
      attributes: {
        tenant: "shop",
        app_profile: "clients",
        epg: "win-clients",
        scope: "prod",
      },
    },
    {
      id: T.svcFrontend,
      label: "checkout-api · 10.50.0.20:8080",
      kind: "endpoint",
      endpoint_kind: "k8s_service",
      namespace: "shop",
      cluster: "c1",
      addresses: ["10.50.0.20"],
    },
    {
      id: T.external,
      label: "203.0.113.40",
      kind: "endpoint",
      endpoint_kind: "external",
      addresses: ["203.0.113.40"],
    },
    {
      id: T.unresolved,
      label: "10.99.0.5",
      kind: "endpoint",
      endpoint_kind: "unresolved",
      addresses: ["10.99.0.5"],
    },
  ];
  const conv = (
    id: string,
    source: string,
    target: string,
    port: number | undefined,
    count: number,
    extra: Partial<GraphEdge> = {},
  ): GraphEdge => ({
    id,
    source,
    target,
    relationship: "communicates_with",
    evidence: ["netflow"],
    confidence: "observed",
    count,
    ...(port !== undefined ? { server_port: port, transport: "tcp" } : {}),
    ...extra,
  });
  const edges: GraphEdge[] = [
    {
      id: "runs",
      source: T.service,
      target: T.checkoutPod,
      relationship: "runs_on",
      evidence: ["otel"],
      confidence: "observed",
      count: 1,
    },
    conv("fe-co", T.frontendPod, T.checkoutPod, 8080, 40, {
      evidence: ["hubble"],
    }),
    conv("co-db", T.checkoutPod, T.db, 5432, 30, {
      contract_basis: "intent",
      contract: "k8s-to-db",
      contract_entry: "tcp 5432",
    }),
    conv("win-db", T.win, T.db, 5432, 7, {
      contract_basis: "none",
      acl_action: "drop",
    }),
    conv("win-svc", T.win, T.svcFrontend, 8080, 5, {
      contract_basis: "not_evaluated",
      contract_reason: "unclassified side",
    }),
    conv("co-ext", T.checkoutPod, T.external, 443, 3, { bytes: 900 }),
    conv("ops-co", T.otherNsPod, T.checkoutPod, 9090, 2, { bytes: 50 }),
    conv("unres-db", T.unresolved, T.db, 5432, 1, { confidence: "unresolved" }),
    conv("icmp", T.win, T.external, undefined, 4),
  ];
  return {
    schema_version: 1,
    snapshot_id: "test",
    generated_at: "2026-11-20T12:00:00Z",
    demo: false,
    window: { start: "2026-11-20T11:00:00Z", end: "2026-11-20T12:00:00Z" },
    boundary: {
      id: "c1/shop/checkout/prod",
      service: "checkout",
      environment: "prod",
      cluster: "c1",
      namespace: "shop",
      root_node_id: T.service,
    },
    nodes,
    edges,
    coverage: {
      spans: 0,
      conversations: 8,
      matched_conversations: 7,
      unresolved_conversations: 1,
      ambiguous_conversations: 0,
      warnings: [],
    },
    ...overrides,
  };
}
