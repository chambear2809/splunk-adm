import { describe, expect, it } from "vitest";
import { filterGraph, focusHops } from "./filters";
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
