import { describe, expect, it } from "vitest";
import { emphasisCounts, neighborhoodForSelection } from "../MapView";
import { indexGraph, type Graph } from "../graph";
import { computeLayout } from "../layout";
import { demoGraph } from "../provider";

const graph = demoGraph("nxos");
const index = indexGraph(graph);

describe("map emphasis counts", () => {
  it("includes every frontend member when a merged card is selected", () => {
    const merged: Graph = {
      schema_version: 1,
      snapshot_id: "merged-selection",
      generated_at: "2026-01-01T00:00:00Z",
      demo: true,
      window: {
        start: "2026-01-01T00:00:00Z",
        end: "2026-01-01T01:00:00Z",
      },
      boundary: {
        id: "service:c/shop/api/prod",
        service: "api",
        environment: "prod",
        cluster: "c",
        namespace: "shop",
        root_node_id: "service:c/shop/api/prod",
      },
      nodes: [
        {
          id: "service:c/shop/api/prod",
          label: "api",
          kind: "service",
          namespace: "shop",
          cluster: "c",
        },
        {
          id: "workload:c/client",
          label: "client",
          kind: "workload",
          namespace: "shop",
          cluster: "c",
          attributes: { owner: "client" },
        },
        {
          id: "k8s_service:c/shop/api/vip",
          label: "api · 10.0.0.1:443",
          kind: "endpoint",
          endpoint_kind: "k8s_service",
          namespace: "shop",
          cluster: "c",
          addresses: ["10.0.0.1"],
          attributes: {
            service: "api",
            frontend: "10.0.0.1:443",
            type: "LoadBalancer",
          },
        },
        {
          id: "k8s_service:c/shop/api/nodeport",
          label: "api · 10.0.0.2:30080",
          kind: "endpoint",
          endpoint_kind: "k8s_service",
          namespace: "shop",
          cluster: "c",
          addresses: ["10.0.0.2"],
          attributes: {
            service: "api",
            frontend: "10.0.0.2:30080",
            type: "NodePort",
          },
        },
      ],
      edges: [
        {
          id: "client>vip",
          source: "workload:c/client",
          target: "k8s_service:c/shop/api/vip",
          relationship: "communicates_with",
          evidence: [],
          confidence: "observed",
          count: 1,
        },
        {
          id: "client>nodeport",
          source: "workload:c/client",
          target: "k8s_service:c/shop/api/nodeport",
          relationship: "communicates_with",
          evidence: [],
          confidence: "observed",
          count: 1,
        },
      ],
      coverage: {
        spans: 0,
        conversations: 2,
        matched_conversations: 2,
        unresolved_conversations: 0,
        ambiguous_conversations: 0,
        warnings: [],
      },
    };
    const index = indexGraph(merged);
    const layout = computeLayout(merged, index, "network", {
      mergeFrontends: true,
    });
    const group = layout.groups.find(
      (item) => item.items[0]?.members?.length === 2,
    );
    expect(group).toBeDefined();
    const selected = group!.items[0].nodeId;
    const neighborhood = neighborhoodForSelection(
      { kind: "node", id: selected },
      index,
      layout,
    );
    expect(neighborhood.edges).toEqual(
      new Set(["client>vip", "client>nodeport"]),
    );
    const counts = emphasisCounts(layout, index, { neighborhood });
    expect(counts.connections).toBe(counts.totalConnections);
  });

  it("reports no dimmed cards or connections without emphasis", () => {
    const counts = emphasisCounts(
      computeLayout(graph, index, "network"),
      index,
      {},
    );
    expect(counts.cards).toBe(counts.totalCards);
    expect(counts.connections).toBe(counts.totalConnections);
  });

  it("counts partial node and edge emphasis from the rendered layout", () => {
    const layout = computeLayout(graph, index, "network");
    const first = graph.nodes[0].id;
    const counts = emphasisCounts(layout, index, {
      matchNodes: new Set([first]),
      matchEdges: new Set(),
    });
    expect(counts.cards).toBeLessThan(counts.totalCards);
    expect(counts.connections).toBeLessThanOrEqual(counts.totalConnections);
  });

  it("uses collapsed members when deciding card emphasis", () => {
    const layout = computeLayout(graph, index, "network", { collapse: true });
    const counts = emphasisCounts(layout, index, {
      matchNodes: new Set([graph.nodes[0].id]),
      matchEdges: new Set(),
    });
    expect(counts.totalCards).toBeGreaterThan(0);
    expect(counts.cards).toBeLessThanOrEqual(counts.totalCards);
  });

  it("keeps grouped routed connections emphasized when any member matches", () => {
    const layout = computeLayout(graph, index, "network");
    const routed = layout.edges[0];
    const counts = emphasisCounts(layout, index, {
      matchNodes: new Set(),
      matchEdges: new Set([routed.members[0]]),
    });
    expect(counts.connections).toBeGreaterThanOrEqual(1);
  });

  it("gives an active search precedence over a selected neighborhood", () => {
    const layout = computeLayout(graph, index, "network");
    const counts = emphasisCounts(layout, index, {
      matchNodes: new Set(),
      matchEdges: new Set(),
      neighborhood: {
        nodes: new Set(graph.nodes.map((node) => node.id)),
        edges: new Set(graph.edges.map((edge) => edge.id)),
      },
    });
    expect(counts.cards).toBe(0);
    expect(counts.connections).toBe(0);
  });

  it("keeps a frontend handoff connection emphasized when its matched member is grouped", () => {
    const layout = computeLayout(graph, index, "network");
    const [first, second] = layout.edges;
    const grouped = {
      ...layout,
      edges: [{ ...first, members: [first.members[0], second.members[0]] }],
    };
    const counts = emphasisCounts(layout, index, {
      matchNodes: new Set(),
      matchEdges: new Set([first.members[0]]),
    });
    expect(counts.connections).toBeGreaterThanOrEqual(1);
    expect(
      emphasisCounts(grouped, index, {
        matchNodes: new Set(),
        matchEdges: new Set([first.members[0]]),
      }).connections,
    ).toBe(1);
  });
});
