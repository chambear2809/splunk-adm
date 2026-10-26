import { describe, expect, it } from "vitest";
import { filterGraph, focusHops, focusTrace } from "./filters";
import { indexGraph, type Graph } from "./graph";

const graph = {
  schema_version: 1,
  snapshot_id: "filters",
  generated_at: "2026-01-01T00:00:00Z",
  demo: false,
  window: { start: "2026-01-01T00:00:00Z", end: "2026-01-01T01:00:00Z" },
  boundary: {
    id: "svc-a",
    service: "a",
    environment: "prod",
    cluster: "c",
    namespace: "n",
    root_node_id: "svc-a",
  },
  coverage: {
    spans: 1,
    conversations: 3,
    matched_conversations: 1,
    unresolved_conversations: 1,
    ambiguous_conversations: 1,
    warnings: [],
  },
  nodes: [
    { id: "svc-a", label: "a", kind: "service" },
    {
      id: "pod-a",
      label: "a-1",
      kind: "workload",
      attributes: { owner: "svc-a" },
    },
    { id: "pod-b", label: "b-1", kind: "workload" },
    { id: "pod-c", label: "a-2", kind: "workload" },
    {
      id: "unknown",
      label: "10.0.0.1",
      kind: "endpoint",
      endpoint_kind: "unresolved",
    },
    {
      id: "ambiguous",
      label: "10.0.0.2",
      kind: "endpoint",
      endpoint_kind: "ambiguous",
    },
    {
      id: "external",
      label: "203.0.113.1",
      kind: "endpoint",
      endpoint_kind: "external",
    },
    { id: "node", label: "node", kind: "endpoint", endpoint_kind: "k8s_node" },
    {
      id: "owned-node",
      label: "owned-node",
      kind: "endpoint",
      endpoint_kind: "k8s_node",
    },
    {
      id: "isolated",
      label: "isolated",
      kind: "endpoint",
      endpoint_kind: "vm",
    },
  ],
  edges: [
    {
      id: "runs",
      source: "svc-a",
      target: "pod-a",
      relationship: "runs_on",
      evidence: [],
      confidence: "observed",
      count: 1,
    },
    {
      id: "unknown-edge",
      source: "pod-a",
      target: "unknown",
      relationship: "communicates_with",
      evidence: [],
      confidence: "unresolved",
      count: 1,
      server_port: 53,
      sources: ["hubble"],
    },
    {
      id: "runs-sibling",
      source: "svc-a",
      target: "pod-c",
      relationship: "runs_on",
      evidence: [],
      confidence: "observed",
      count: 1,
    },
    {
      id: "ambiguous-edge",
      source: "pod-a",
      target: "ambiguous",
      relationship: "communicates_with",
      evidence: [],
      confidence: "correlated",
      count: 1,
      server_port: 443,
      sources: ["netflow"],
      acl_action: "drop",
    },
    {
      id: "external-edge",
      source: "pod-a",
      target: "external",
      relationship: "communicates_with",
      evidence: [],
      confidence: "correlated",
      count: 1,
      server_port: 443,
      sources: ["hubble"],
    },
    {
      id: "tunnel",
      source: "pod-a",
      target: "node",
      relationship: "communicates_with",
      evidence: [],
      confidence: "observed",
      count: 1,
      transport: "ipip",
    },
    {
      id: "owned-tunnel",
      source: "pod-a",
      target: "owned-node",
      relationship: "communicates_with",
      evidence: [],
      confidence: "observed",
      count: 1,
      transport: "ipip",
    },
    {
      id: "owned-traffic",
      source: "pod-b",
      target: "owned-node",
      relationship: "communicates_with",
      evidence: [],
      confidence: "observed",
      count: 1,
      transport: "tcp",
    },
  ],
} as unknown as Graph;

describe("graph facets", () => {
  it("combines identity, port, source and blocked facets with AND", () => {
    const result = filterGraph(graph, {
      identity: "unknown",
      port: 53,
      source: "hubble",
      blocked: false,
    });
    expect(result.edges.map((edge) => edge.id)).toEqual([
      "unknown-edge",
      "runs",
    ]);
    expect(result.nodes.map((node) => node.id)).toEqual(
      expect.arrayContaining(["pod-a", "unknown", "svc-a"]),
    );
    expect(result.nodes.map((node) => node.id)).not.toContain("pod-c");
  });
  it("treats ambiguous identities as unknown and retains ownership context", () => {
    const result = filterGraph(graph, { identity: "unknown" });
    expect(result.edges.map((edge) => edge.id)).toEqual(
      expect.arrayContaining(["unknown-edge", "ambiguous-edge", "runs"]),
    );
    expect(result.edges).not.toContainEqual(
      expect.objectContaining({ id: "external-edge" }),
    );
  });
  it("hides tunnel-only Kubernetes nodes but keeps owned infrastructure", () => {
    const hidden = filterGraph(graph, { hideInfrastructure: true });
    expect(hidden.nodes.map((node) => node.id)).not.toContain("node");
    expect(hidden.nodes.map((node) => node.id)).toEqual(
      expect.arrayContaining(["isolated", "owned-node"]),
    );
    const result = filterGraph(graph, { port: 53, hideInfrastructure: true });
    expect(result.nodes.map((node) => node.id)).not.toContain("node");
  });
  it("returns the original graph for no active facets", () => {
    expect(filterGraph(graph, {})).toBe(graph);
  });
  it("returns an empty, well-formed graph when no edge matches", () => {
    const result = filterGraph(graph, { port: 65535 });
    expect(result.edges).toEqual([]);
    expect(result.nodes).toEqual([]);
    expect(graph.edges.length).toBeGreaterThan(0);
  });
  it("applies port and source facets to traffic observations", () => {
    const withObservation = {
      ...graph,
      edges: [
        ...graph.edges,
        {
          id: "observation",
          source: "pod-a",
          target: "external",
          relationship: "traffic_observation",
          evidence: [],
          confidence: "observed",
          count: 1,
          server_port: 8080,
          sources: ["meraki"],
        },
      ],
    } as unknown as Graph;
    const result = filterGraph(withObservation, {
      port: 8080,
      source: "meraki",
    });
    expect(result.edges.map((edge) => edge.id)).toContain("observation");
  });
  it("handles dense service and port sets without dangling endpoints", () => {
    const dense = {
      ...graph,
      nodes: [...graph.nodes],
      edges: [...graph.edges],
    };
    for (let i = 0; i < 32; i += 1) {
      dense.nodes.push({ id: `s${i}`, label: `s${i}`, kind: "service" });
      dense.nodes.push({ id: `w${i}`, label: `w${i}`, kind: "workload" });
      dense.edges.push({
        id: `r${i}`,
        source: `s${i}`,
        target: `w${i}`,
        relationship: "runs_on",
        evidence: [],
        confidence: "observed",
        count: 1,
      });
      dense.edges.push({
        id: `p${i}`,
        source: `w${i}`,
        target: "external",
        relationship: "communicates_with",
        evidence: [],
        confidence: "correlated",
        count: 1,
        server_port: 1000 + i,
        sources: ["hubble"],
      });
    }
    const result = filterGraph(dense, { port: 1017 });
    expect(result.edges.map((edge) => edge.id)).toEqual(
      expect.arrayContaining(["p17", "r17"]),
    );
    expect(
      result.edges.every(
        (edge) =>
          result.nodes.some((node) => node.id === edge.source) &&
          result.nodes.some((node) => node.id === edge.target),
      ),
    ).toBe(true);
  });
});

describe("focusHops", () => {
  const index = indexGraph(graph);
  it("walks undirected edges exactly to the requested depth", () => {
    expect([...focusHops(index, "unknown", 0)]).toEqual(["unknown"]);
    expect(focusHops(index, "unknown", 1)).toEqual(
      new Set(["unknown", "pod-a"]),
    );
    expect(focusHops(index, "unknown", 2)).toEqual(
      new Set([
        "unknown",
        "pod-a",
        "svc-a",
        "ambiguous",
        "external",
        "node",
        "owned-node",
      ]),
    );
  });
  it("rejects invalid bounds and unknown nodes without leaking the graph", () => {
    expect(focusHops(index, "missing", 2)).toEqual(new Set());
    expect(focusHops(index, "unknown", -1)).toEqual(new Set());
    expect(focusHops(index, "unknown", 1.5)).toEqual(new Set());
    expect(focusHops(index, "unknown", Number.POSITIVE_INFINITY)).toEqual(
      new Set(),
    );
  });
});

describe("focusHops direction", () => {
  const edge = (
    id: string,
    source: string,
    target: string,
    relationship: string,
    extra: Record<string, unknown> = {},
  ) => ({
    id,
    source,
    target,
    relationship,
    evidence: [],
    confidence: "observed",
    count: 1,
    ...extra,
  });
  const node = (id: string, kind: string) => ({ id, label: id, kind });
  // client -> vip -(forwards_to)-> web-pod -> api-pod -> db; svc-api owns api-pod.
  const directed = indexGraph({
    nodes: [
      node("client", "endpoint"),
      node("vip", "endpoint"),
      node("web-pod", "workload"),
      node("svc-api", "service"),
      node("api-pod", "workload"),
      node("db", "endpoint"),
      node("batch", "workload"),
      node("mystery", "endpoint"),
    ],
    edges: [
      edge("e1", "client", "vip", "communicates_with"),
      edge("e2", "vip", "web-pod", "forwards_to"),
      edge("e3", "web-pod", "api-pod", "communicates_with"),
      edge("e4", "api-pod", "db", "communicates_with"),
      edge("e5", "batch", "api-pod", "communicates_with"),
      edge("e6", "svc-api", "api-pod", "runs_on"),
      edge("e7", "mystery", "api-pod", "communicates_with", {
        direction_basis: "unknown",
      }),
      edge("e8", "web-pod", "db", "traffic_observation"),
    ],
  } as unknown as Graph);

  it("follows callers from server to client and treats forwards_to as free", () => {
    expect(focusHops(directed, "api-pod", 1, "callers")).toEqual(
      new Set(["api-pod", "svc-api", "web-pod", "vip", "batch", "mystery"]),
    );
    const two = focusHops(directed, "api-pod", 2, "callers");
    expect(two.has("client")).toBe(true);
    expect(two.has("db")).toBe(false);
  });
  it("follows dependencies from client to server and follows unknown direction both ways", () => {
    expect(focusHops(directed, "web-pod", 1, "dependencies")).toEqual(
      new Set(["web-pod", "api-pod", "svc-api"]),
    );
    const result = focusHops(directed, "web-pod", 2, "dependencies");
    expect(result.has("db")).toBe(true);
    expect(result.has("batch")).toBe(false);
    expect(result.has("client")).toBe(false);
    expect(result.has("mystery")).toBe(true);
  });
  it("treats a service as its pods and ignores traffic observations", () => {
    expect(focusHops(directed, "svc-api", 1, "dependencies")).toEqual(
      new Set(["svc-api", "api-pod", "db", "mystery"]),
    );
    expect(focusHops(directed, "svc-api", 0, "callers")).toEqual(
      new Set(["svc-api", "api-pod"]),
    );
    expect(focusHops(directed, "svc-api", 1)).toEqual(
      new Set(["svc-api", "api-pod", "web-pod", "db", "batch", "mystery"]),
    );
  });
  it("does not follow blocked conversations as dependencies", () => {
    const blocked = indexGraph({
      nodes: [node("a", "workload"), node("b", "workload")],
      edges: [
        edge("x", "a", "b", "communicates_with", {
          acl_action: "drop",
          acl_drops: 3,
        }),
      ],
    } as unknown as Graph);
    expect(focusHops(blocked, "b", 1, "callers")).toEqual(new Set(["b"]));
    expect(focusHops(blocked, "a", 1, "dependencies")).toEqual(new Set(["a"]));
    expect(focusHops(blocked, "a", 1)).toEqual(new Set(["a", "b"]));
  });
  it("stays bounded on cycles", () => {
    const cycle = indexGraph({
      nodes: [node("a", "workload"), node("b", "workload")],
      edges: [
        edge("x", "a", "b", "communicates_with"),
        edge("y", "b", "a", "communicates_with"),
      ],
    } as unknown as Graph);
    expect(focusHops(cycle, "a", 3, "callers")).toEqual(new Set(["a", "b"]));
  });
});

describe("focusTrace", () => {
  const edge = (
    id: string,
    source: string,
    target: string,
    extra: Record<string, unknown> = {},
  ) => ({
    id,
    source,
    target,
    relationship: "communicates_with",
    evidence: [],
    confidence: "observed",
    count: 1,
    ...extra,
  });
  const node = (id: string) => ({ id, label: id, kind: "workload" });
  const traced = indexGraph({
    nodes: ["a", "b", "c", "d", "e"].map(node),
    edges: [
      edge("ab", "a", "b", { direction_basis: "port_rule" }),
      edge("cb", "c", "b", { direction_basis: "unknown" }),
      edge("db", "d", "b", { acl_action: "drop" }),
      edge("ae", "a", "e"),
    ],
  } as unknown as Graph);
  it("reports only the conversations the walk followed", () => {
    const result = focusTrace(traced, "b", 1, "callers");
    expect(result.nodes).toEqual(new Set(["b", "a", "c"]));
    expect(result.followed).toEqual(new Set(["ab", "cb"]));
  });
  it("reports nothing followed when no dependency was observed", () => {
    const result = focusTrace(traced, "b", 2, "dependencies");
    expect(result.nodes).toEqual(new Set(["b", "c"]));
    expect(result.followed).toEqual(new Set(["cb"]));
    expect(focusTrace(traced, "e", 2, "dependencies").followed.size).toBe(0);
  });
});
