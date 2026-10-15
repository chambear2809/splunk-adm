import { describe, expect, it } from "vitest";
import { emphasisCounts } from "../MapView";
import { indexGraph } from "../graph";
import { computeLayout } from "../layout";
import { demoGraph } from "../provider";

const graph = demoGraph("nxos");
const index = indexGraph(graph);

describe("map emphasis counts", () => {
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
