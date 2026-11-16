import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { indexGraph } from "../graph";
import { computeLayout } from "../layout";
import { MapView } from "../MapView";
import { TableView } from "../map/TableView";
import { emptyTopology, indexTopology } from "../topology";
import { syntheticGraph } from "./generate";
import { truncateGraph } from "./truncate";

const map = (nodes: number, edges: number, options = {}) => {
  const graph = syntheticGraph({ nodes, edges });
  const index = indexGraph(graph);
  const layout = computeLayout(graph, index, "network", options);
  return {
    layout,
    html: renderToStaticMarkup(
      <MapView
        layout={layout}
        index={index}
        selection={null}
        onSelect={() => undefined}
        onExpand={() => undefined}
        deviceLabel={(raw) => raw}
        describeEdge={(e) => ({ title: e.id, lines: [] })}
        label="map"
      />,
    ),
  };
};

describe("map rendering at scale", () => {
  it("keeps small maps in SVG", () => {
    const { html } = map(120, 300);
    expect(html).toContain('class="edges"');
    expect(html).not.toContain("atlas-edge-canvas");
  });
  it("draws dense maps on a canvas with an accessible note and chips", () => {
    const { html, layout } = map(4000, 10000, { aggregate: false });
    expect(layout.edges.length).toBeGreaterThan(1000);
    expect(html).toContain("atlas-edge-canvas");
    expect(html).not.toContain('class="edges"');
    expect(html).toMatch(/aria-description="[\d,]+ connections are drawn/);
    expect(html).toMatch(/lines drawn direct/);
  });
  it("shows the summarized-groups and truncation chips", () => {
    const graph = syntheticGraph({ nodes: 5000, edges: 12000 });
    const cut = truncateGraph(
      graph.nodes,
      graph.edges,
      graph.boundary.root_node_id,
      { nodes: 5000, edges: 12000 },
    );
    const g = { ...graph, ...cut };
    const index = indexGraph(g);
    const layout = computeLayout(g, index, "network");
    const html = renderToStaticMarkup(
      <MapView
        layout={layout}
        index={index}
        selection={null}
        onSelect={() => undefined}
        onExpand={() => undefined}
        deviceLabel={(raw) => raw}
        describeEdge={(e) => ({ title: e.id, lines: [] })}
        label="map"
      />,
    );
    expect(html).toMatch(/Top [\d,]+ of 12,000 connections/);
    expect(html).toMatch(/[\d,]+ groups? summarized/);
  });
});

describe("table rendering at scale", () => {
  it("renders a window of a 100k-row table", () => {
    const graph = syntheticGraph({ nodes: 4000, edges: 100000 });
    const index = indexGraph(graph);
    const html = renderToStaticMarkup(
      <TableView
        graph={graph}
        label={(id) => index.node.get(id)?.label ?? id}
        onSelect={() => undefined}
        topo={indexTopology(emptyTopology())}
        index={index}
        node={(id) => index.node.get(id)}
      />,
    );
    const rows = html.match(/<tr /g)?.length ?? 0;
    expect(rows).toBeLessThan(120);
    expect(html).toMatch(/aria-rowcount="\d{5,}"/);
    expect(html).toContain('aria-sort="none"');
  });
});
