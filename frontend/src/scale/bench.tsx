import { createRoot, type Root } from "react-dom/client";
import { indexGraph, type Graph } from "../graph";
import { computeLayout } from "../layout";
import { MapView } from "../MapView";
import { TableView } from "../map/TableView";
import { emptyTopology, indexTopology } from "../topology";
import { syntheticGraph } from "./generate";
import "../styles.css";

/**
 * Browser benchmark harness (not shipped): renders the real MapView and
 * TableView over synthetic graphs and reports layout, first-render and
 * pan/zoom frame times. Driven by tests/browser/perf-scale.spec.ts.
 */
const host = document.getElementById("bench-root")!;
let root: Root | undefined;
const frame = () =>
  new Promise<void>((resolve) =>
    requestAnimationFrame(() => setTimeout(resolve, 0)),
  );
const percentile = (values: number[], p: number) => {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * p))];
};
const reset = () => {
  root?.unmount();
  host.innerHTML = "";
  root = createRoot(host);
  return root;
};

async function map(nodes: number, edges: number, options: object = {}) {
  const graph: Graph = syntheticGraph({ nodes, edges });
  const index = indexGraph(graph);
  const r = reset();
  const t0 = performance.now();
  const layout = computeLayout(graph, index, "network", options);
  const layoutMs = performance.now() - t0;
  r.render(
    <MapView
      layout={layout}
      index={index}
      selection={null}
      onSelect={() => undefined}
      onExpand={() => undefined}
      deviceLabel={(raw) => raw}
      describeEdge={(e) => ({ title: e.id, lines: [] })}
      label="benchmark map"
    />,
  );
  await frame();
  await frame();
  const initialMs = performance.now() - t0;
  const surface = host.querySelector(".map-canvas") as HTMLElement;
  const pans: number[] = [];
  for (let i = 0; i < 30; i++) {
    const s = performance.now();
    surface.dispatchEvent(
      new WheelEvent("wheel", {
        deltaX: 7,
        deltaY: 5,
        ctrlKey: i % 3 === 0,
        bubbles: true,
        cancelable: true,
      }),
    );
    await frame();
    pans.push(performance.now() - s);
  }
  return {
    nodes: graph.nodes.length,
    edges: graph.edges.length,
    routed: layout.edges.length,
    cards: layout.groups.reduce((n, g) => n + g.items.length, 0),
    canvas: !!host.querySelector("canvas.atlas-edge-canvas"),
    layoutMs: Math.round(layoutMs),
    initialMs: Math.round(initialMs),
    panP50: Math.round(percentile(pans, 0.5)),
    panP95: Math.round(percentile(pans, 0.95)),
  };
}

async function table(edges: number) {
  const graph = syntheticGraph({ nodes: 4000, edges });
  const index = indexGraph(graph);
  const topo = indexTopology(emptyTopology());
  const r = reset();
  const t0 = performance.now();
  r.render(
    <TableView
      graph={graph}
      label={(id) => index.node.get(id)?.label ?? id}
      onSelect={() => undefined}
      topo={topo}
      index={index}
      node={(id) => index.node.get(id)}
    />,
  );
  await frame();
  await frame();
  const initialMs = performance.now() - t0;
  const scroller = (host.querySelector("[data-scroll-region]") ??
    host.querySelector(".table-view")) as HTMLElement;
  const frames: number[] = [];
  let last = performance.now();
  for (let i = 0; i < 60; i++) {
    scroller.scrollTop += 900;
    await new Promise<void>((resolve) =>
      requestAnimationFrame(() => resolve()),
    );
    const now = performance.now();
    frames.push(now - last);
    last = now;
  }
  return {
    rows: graph.edges.length,
    domRows: host.querySelectorAll("tr").length,
    initialMs: Math.round(initialMs),
    scrollP50: Math.round(percentile(frames, 0.5)),
    scrollP95: Math.round(percentile(frames, 0.95)),
  };
}

declare global {
  interface Window {
    atlasBench: { map: typeof map; table: typeof table };
  }
}
window.atlasBench = { map, table };
document.body.dataset.ready = "1";
