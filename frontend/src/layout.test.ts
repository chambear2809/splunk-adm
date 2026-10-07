import { describe, expect, it } from "vitest";
import { indexGraph, parseGraph, type Graph } from "./graph";
import { computeLayout, type Layout } from "./layout";
import { demoGraph } from "./provider";

const graph = demoGraph();
const index = indexGraph(graph);
const network = computeLayout(graph, index, "network");
const idOf = (label: string) => graph.nodes.find((n) => n.label === label)!.id;
const laneOf = (layout: Layout, label: string) => {
  const it = layout.items.get(idOf(label))!;
  return layout.groups.find((g) => g.id === it.groupId)!.lane;
};
const length = (pts: [number, number][]) =>
  pts
    .slice(1)
    .reduce((s, p, i) => s + Math.hypot(p[0] - pts[i][0], p[1] - pts[i][1]), 0);
const numbers = (d: string) =>
  (d.match(/-?\d+(\.\d+)?(e-?\d+)?|NaN|Infinity/g) ?? []).map(Number);

function assertSound(layout: Layout) {
  for (const g of layout.groups)
    for (const v of [g.x, g.y, g.w, g.h]) expect(Number.isFinite(v)).toBe(true);
  for (const e of layout.edges)
    for (const v of numbers(e.d)) expect(Number.isFinite(v)).toBe(true);
  const byColumn = new Map<number, typeof layout.groups>();
  for (const g of layout.groups)
    byColumn.set(g.column, [...(byColumn.get(g.column) ?? []), g]);
  for (const col of byColumn.values()) {
    const sorted = [...col].sort((a, b) => a.y - b.y);
    for (let i = 1; i < sorted.length; i++)
      expect(sorted[i].y).toBeGreaterThanOrEqual(
        sorted[i - 1].y + sorted[i - 1].h,
      );
  }
}

describe("computeLayout (network)", () => {
  it("is deterministic", () => {
    const again = computeLayout(graph, index, "network");
    expect(again.edges.map((e) => e.d)).toEqual(network.edges.map((e) => e.d));
    expect([...again.items.values()]).toEqual([...network.items.values()]);
  });
  it("has finite coordinates and no overlapping groups", () =>
    assertSound(network));
  it("places every node exactly once", () => {
    expect(network.items.size).toBe(graph.nodes.length);
    expect(new Set(network.order).size).toBe(network.order.length);
  });
  it("assigns lanes by role", () => {
    expect(network.lanes.filter((l) => l.y === 30).map((l) => l.kind)).toEqual([
      "sources",
      "application",
      "dependencies",
    ]);
    expect(laneOf(network, "ingress-nginx-controller-6b9d7c8f5-q7m2z")).toBe(
      "sources",
    );
    expect(laneOf(network, "10.99.0.7")).toBe("sources");
    // node-d only opens connections into checkout, so it is a source.
    expect(laneOf(network, "node-d")).toBe("sources");
    expect(laneOf(network, "frontend")).toBe("application");
    expect(laneOf(network, "orders-db-01")).toBe("dependencies");
    expect(laneOf(network, "coredns-7c65d6cfc9-h2x4l")).toBe("dependencies");
    expect(laneOf(network, "203.0.113.40")).toBe("dependencies");
    // node-a and node-b appear only in tunnel traffic.
    expect(laneOf(network, "node-a")).toBe("infrastructure");
    expect(laneOf(network, "node-b")).toBe("infrastructure");
  });
  it("stacks Infrastructure below Dependencies with its own title", () => {
    const infra = network.groups.find((g) => g.lane === "infrastructure")!;
    const deps = network.groups.filter(
      (g) => g.lane === "dependencies" && g.column === infra.column,
    );
    expect(deps.length).toBeGreaterThan(0);
    for (const d of deps) expect(infra.y).toBeGreaterThan(d.y + d.h);
    const label = network.lanes.find((l) => l.kind === "infrastructure")!;
    expect(label.y).toBeLessThan(infra.y);
    expect(label.y).toBeGreaterThan(Math.max(...deps.map((d) => d.y + d.h)));
  });
  it("lists pods inside their service's group", () => {
    const pod = graph.nodes.find(
      (n) => n.label === "checkout-5f8b9c7d6-m4n7q",
    )!;
    const service = graph.nodes.find((n) => n.label === "checkout")!;
    expect(network.items.get(pod.id)!.groupId).toBe(
      network.items.get(service.id)!.groupId,
    );
  });
  it("orders services by call depth", () => {
    const x = (label: string) =>
      network.items.get(graph.nodes.find((n) => n.label === label)!.id)!.x;
    expect(x("frontend")).toBeLessThan(x("checkout"));
    expect(x("checkout")).toBeLessThan(x("catalog"));
    expect(x("catalog")).toBe(x("payment"));
  });
  it("routes every drawn relationship and omits runs_on lines", () => {
    const drawn = graph.edges.filter((e) => e.relationship !== "runs_on");
    expect(network.edges.map((e) => e.id).sort()).toEqual(
      drawn.map((e) => e.id).sort(),
    );
  });
  it("draws arrowheads only when direction is known", () => {
    for (const e of network.edges) {
      const known = !(
        e.edge.relationship === "communicates_with" &&
        e.edge.direction_basis === "unknown"
      );
      expect(e.directed).toBe(known);
      // Directed edges into a port pill get their arrowhead from the pill.
      expect(e.arrow === "end").toBe(known && !e.pill);
    }
  });
  it("labels each server port once per card and port", () => {
    const keys = network.pills.map((p) => `${p.itemId}|${p.label}`);
    expect(new Set(keys).size).toBe(keys.length);
    const checkout = network.pills.find(
      (p) =>
        p.itemId === idOf("checkout-5f8b9c7d6-m4n7q") && p.label === "8080/tcp",
    )!;
    // frontend, node-d and both reports pods connect to checkout on 8080.
    expect(checkout.edgeIds).toHaveLength(4);
    expect(network.pills.map((p) => p.label)).toEqual(
      expect.arrayContaining(["5432/tcp", "53/udp", "443/tcp", "50051/tcp"]),
    );
    for (const p of network.pills) {
      const it = network.items.get(p.itemId)!;
      expect(p.x + p.w <= it.x || p.x >= it.x + it.w).toBe(true);
    }
  });
  it("never shares an attachment point between edges", () => {
    const ends = network.edges.flatMap((e) => [e.points[0], e.points.at(-1)!]);
    const keys = ends.map(([x, y]) => `${x.toFixed(1)},${y.toFixed(1)}`);
    expect(new Set(keys).size).toBe(keys.length);
  });
  it("keeps cross-column paths short and above the map's bottom edge", () => {
    const bottom = Math.max(...network.groups.map((g) => g.y + g.h));
    for (const e of network.edges) {
      const [a, b] = [e.points[0], e.points.at(-1)!];
      const sameColumn =
        network.items.get(e.edge.source)!.column ===
        network.items.get(e.edge.target)!.column;
      if (sameColumn)
        expect(length(e.points) - Math.abs(a[1] - b[1])).toBeLessThan(80);
      else
        expect(
          length(e.points) / Math.hypot(b[0] - a[0], b[1] - a[1]),
        ).toBeLessThan(2);
      for (const [, y] of e.points) expect(y).toBeLessThanOrEqual(bottom + 12);
    }
  });
  it("uses one line style: orthogonal segments with rounded corners", () => {
    for (const e of network.edges) {
      expect(e.d).not.toMatch(/C/);
      for (let i = 1; i < e.points.length; i++) {
        const [x1, y1] = e.points[i - 1],
          [x2, y2] = e.points[i];
        expect(x1 === x2 || y1 === y2).toBe(true);
      }
    }
  });
  it("collapses pod lists into summaries and keeps expanded groups", () => {
    const collapsed = computeLayout(graph, index, "network", {
      collapse: true,
    });
    const reports = collapsed.groups.find((g) => g.title === "reports")!;
    expect(reports.collapsed).toBe(true);
    expect(reports.items).toHaveLength(1);
    expect(reports.items[0].members).toHaveLength(2);
    expect(collapsed.items.get(idOf("reports-7f6d5c4b3-aaaaa"))).toBe(
      reports.items[0],
    );
    assertSound(collapsed);
    const expanded = computeLayout(graph, index, "network", {
      collapse: true,
      expanded: new Set([reports.id]),
    });
    expect(
      expanded.groups.find((g) => g.id === reports.id)!.items,
    ).toHaveLength(2);
  });
  it("keeps long edges' horizontal segments clear of intermediate cards", () => {
    for (const e of network.edges) {
      const pts = [...e.d.matchAll(/[ML](-?[\d.]+),(-?[\d.]+)/g)].map((m) => [
        Number(m[1]),
        Number(m[2]),
      ]);
      for (let i = 1; i < pts.length; i++) {
        const [x1, y1] = pts[i - 1],
          [x2, y2] = pts[i];
        if (Math.abs(y1 - y2) > 0.5) continue;
        for (const g of network.groups) {
          const inside =
            y1 > g.y + 1 &&
            y1 < g.y + g.h - 1 &&
            Math.min(x1, x2) < g.x + 1 &&
            Math.max(x1, x2) > g.x + g.w - 1;
          expect(inside, `${e.id} crosses ${g.id}`).toBe(false);
        }
      }
    }
  });
});

describe("computeLayout (services)", () => {
  const services = computeLayout(graph, index, "services");
  it("shows only services and traced calls", () => {
    expect(
      [...services.items.keys()].every(
        (id) => index.node.get(id)!.kind === "service",
      ),
    ).toBe(true);
    expect(services.edges.every((e) => e.edge.relationship === "calls")).toBe(
      true,
    );
    assertSound(services);
  });
});

function largeGraph(): Graph {
  const nodes: Graph["nodes"] = [],
    edges: Graph["edges"] = [];
  const svc = (i: number) => `service:c/ns/s${i}/e`;
  for (let i = 0; i < 40; i++)
    nodes.push({
      id: svc(i),
      label: `s${i}`,
      kind: "service",
      namespace: "ns",
    });
  for (let i = 0; i < 300; i++)
    nodes.push({
      id: `pod:c/p${i}`,
      label: `pod-${i}`,
      kind: "workload",
      namespace: i % 5 ? "ns" : "other",
      attributes: { node: `n${i % 6}` },
    });
  for (let i = 0; i < 160; i++)
    nodes.push({
      id: `ip:x/10.0.${Math.floor(i / 250)}.${i % 250}`,
      label: `10.0.0.${i}`,
      kind: "endpoint",
      endpoint_kind: i % 2 ? "external" : "unresolved",
    });
  let n = 0;
  const edge = (e: Omit<Graph["edges"][0], "id" | "evidence" | "count">) =>
    edges.push({ ...e, id: `e${n++}`, evidence: [], count: 1 });
  for (let i = 1; i < 40; i++)
    edge({
      source: svc(Math.floor((i - 1) / 3)),
      target: svc(i),
      relationship: "calls",
      confidence: "observed",
    });
  for (let i = 0; i < 300; i++)
    if (i % 5)
      edge({
        source: svc(i % 40),
        target: `pod:c/p${i}`,
        relationship: "runs_on",
        confidence: "correlated",
      });
  let k = 0;
  while (edges.length < 2000) {
    const a = `pod:c/p${k % 300}`;
    const b = k % 3 ? `pod:c/p${(k * 7 + 3) % 300}` : nodes[340 + (k % 160)].id;
    if (a !== b)
      edge({
        source: a,
        target: b,
        relationship: "communicates_with",
        confidence: "correlated",
        direction_basis: k % 4 ? "initiator" : "unknown",
      });
    k++;
  }
  return parseGraph({
    schema_version: 1,
    snapshot_id: "large",
    generated_at: "2026-10-07T12:00:00Z",
    demo: true,
    window: { start: "2026-10-07T11:00:00Z", end: "2026-10-07T12:00:00Z" },
    boundary: {
      id: "b",
      service: "s0",
      environment: "e",
      cluster: "c",
      namespace: "ns",
      root_node_id: svc(0),
    },
    nodes,
    edges,
    coverage: {
      spans: 0,
      conversations: 0,
      matched_conversations: 0,
      unresolved_conversations: 0,
      ambiguous_conversations: 0,
      warnings: [],
    },
  });
}

describe("layout performance", () => {
  it("lays out 500 nodes and 2,000 edges in under 200 ms", () => {
    const big = largeGraph();
    const idx = indexGraph(big);
    computeLayout(big, idx, "network"); // warm up the JIT
    const start = performance.now();
    const layout = computeLayout(big, idx, "network");
    const ms = performance.now() - start;
    expect(big.nodes).toHaveLength(500);
    expect(big.edges).toHaveLength(2000);
    expect(layout.items.size).toBe(500);
    assertSound(layout);
    expect(ms).toBeLessThan(200);
  });
});
