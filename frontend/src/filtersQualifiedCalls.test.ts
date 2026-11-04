import { describe, expect, it } from "vitest";
import { filterGraph } from "./filters";
import type { Graph } from "./graph";

const qualifiedCallsGraph: Graph = {
  schema_version: 1,
  snapshot_id: "qualified-calls",
  generated_at: "2026-01-01T00:00:00Z",
  demo: false,
  window: { start: "2026-01-01T00:00:00Z", end: "2026-01-01T01:00:00Z" },
  boundary: {
    id: "service-a",
    service: "a",
    environment: "prod",
    cluster: "cluster-a",
    namespace: "default",
    root_node_id: "service-a",
  },
  coverage: {
    spans: 1,
    conversations: 2,
    matched_conversations: 2,
    unresolved_conversations: 0,
    ambiguous_conversations: 0,
    warnings: [],
  },
  nodes: [
    { id: "service-a", label: "service-a", kind: "service" },
    { id: "service-b", label: "service-b", kind: "service" },
    { id: "service-c", label: "service-c", kind: "service" },
  ],
  edges: [
    {
      id: "otel-call-a",
      source: "service-a",
      target: "service-b",
      relationship: "calls",
      evidence: [],
      confidence: "observed",
      count: 1,
      sources: ["otel"],
    },
    {
      id: "otel-call-b",
      source: "service-b",
      target: "service-c",
      relationship: "calls",
      evidence: [],
      confidence: "observed",
      count: 1,
      sources: ["otel"],
    },
    {
      id: "other-call",
      source: "service-c",
      target: "service-a",
      relationship: "calls",
      evidence: [],
      confidence: "observed",
      count: 1,
      sources: ["netflow"],
    },
  ],
};

const mixedGraph: Graph = {
  ...qualifiedCallsGraph,
  nodes: [
    ...qualifiedCallsGraph.nodes,
    { id: "pod-a", label: "pod-a", kind: "workload" },
    { id: "pod-b", label: "pod-b", kind: "workload" },
    {
      id: "external",
      label: "external",
      kind: "endpoint",
      endpoint_kind: "external",
    },
  ],
  edges: [
    ...qualifiedCallsGraph.edges,
    {
      id: "otel-network",
      source: "pod-a",
      target: "external",
      relationship: "communicates_with",
      evidence: [],
      confidence: "observed",
      count: 1,
      server_port: 443,
      sources: ["otel"],
    },
    {
      id: "other-network",
      source: "pod-b",
      target: "external",
      relationship: "communicates_with",
      evidence: [],
      confidence: "observed",
      count: 1,
      server_port: 443,
      sources: ["netflow"],
    },
  ],
};

describe("qualified graph source filtering", () => {
  it("retains every matching call and endpoint in the qualified graph", () => {
    const result = filterGraph(qualifiedCallsGraph, { source: "otel" });
    expect(result.edges.map((edge) => edge.id)).toEqual([
      "otel-call-a",
      "otel-call-b",
    ]);
    expect(result.nodes.map((node) => node.id)).toEqual([
      "service-a",
      "service-b",
      "service-c",
    ]);
  });

  it("retains matching network and calls edges while excluding other sources", () => {
    const result = filterGraph(mixedGraph, { source: "otel" });
    expect(result.edges.map((edge) => edge.id)).toEqual([
      "otel-call-a",
      "otel-call-b",
      "otel-network",
    ]);
    expect(result.nodes.map((node) => node.id)).not.toContain("pod-b");
  });

  it.each([
    { identity: "identified" as const },
    { port: 443 },
    { blocked: true },
    { source: "otel", identity: "identified" as const },
    { source: "otel", blocked: true },
    { source: "otel", port: 443 },
  ])("does not treat calls as matching flow facet %#", (facet) => {
    const result = filterGraph(qualifiedCallsGraph, facet);
    expect(result.edges).toEqual([]);
    expect(result.nodes).toEqual([]);
  });
});
