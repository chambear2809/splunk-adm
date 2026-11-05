import { describe, expect, it } from "vitest";
import { parseGraph } from "../graph";
import type { SearchClient, SearchRequest } from "../data/searchClient";
import { syntheticGraph } from "./generate";
import { createHitIndex } from "./hitIndex";
import { GRAPH_BOUND_ROWS, boundedGraphClient } from "./graphSearch";
import { truncateGraph, truncationChip } from "./truncate";
import { sortRows, windowRange } from "./VirtualTable";
import { strokeWidth } from "./weight";

describe("truncateGraph", () => {
  const big = syntheticGraph({ nodes: 6000, edges: 15000 });
  const root = big.boundary.root_node_id;

  it("passes complete graphs within the limits through unchanged", () => {
    const small = syntheticGraph({ nodes: 200, edges: 600 });
    const r = truncateGraph(small.nodes, small.edges, root, {
      nodes: small.nodes.length,
      edges: small.edges.length,
    });
    expect(r.truncation).toBeUndefined();
    expect(r.edges).toHaveLength(small.edges.length);
  });

  it("keeps the heaviest relationships and only the nodes they need", () => {
    const r = truncateGraph(big.nodes, big.edges, root, {
      nodes: 6000,
      edges: 15000,
    });
    expect(r.truncation).toMatchObject({
      truncated: true,
      total: { nodes: 6000, edges: 15000 },
    });
    expect(r.nodes.length).toBeLessThanOrEqual(4000);
    expect(r.edges.length).toBeLessThanOrEqual(10000);
    const ids = new Set(r.nodes.map((n) => n.id));
    expect(ids.has(root)).toBe(true);
    for (const e of r.edges) {
      expect(ids.has(e.source)).toBe(true);
      expect(ids.has(e.target)).toBe(true);
    }
    // Structure first, then traffic by bytes: kept traffic is heavier.
    const kept = new Set(r.edges.map((e) => e.id));
    const median = (xs: number[]) =>
      xs.sort((a, b) => a - b)[Math.floor(xs.length / 2)];
    const traffic = big.edges.filter(
      (e) => e.relationship === "communicates_with",
    );
    expect(
      median(traffic.filter((e) => kept.has(e.id)).map((e) => e.bytes ?? 0)),
    ).toBeGreaterThan(
      median(traffic.filter((e) => !kept.has(e.id)).map((e) => e.bytes ?? 0)),
    );
    expect(r.edges.filter((e) => e.relationship === "runs_on").length).toBe(
      big.edges.filter((e) => e.relationship === "runs_on").length,
    );
    expect(() =>
      parseGraph({
        ...big,
        nodes: r.nodes,
        edges: r.edges,
        truncation: r.truncation,
      }),
    ).not.toThrow();
    expect(truncationChip(r.truncation!)).toMatch(/^Top [\d,]+ of 15,000/);
  });

  it("reports server-side truncation even when the rows fit", () => {
    const small = syntheticGraph({ nodes: 100, edges: 300 });
    const r = truncateGraph(small.nodes, small.edges, root, {
      nodes: 100,
      edges: 9000,
    });
    expect(r.truncation?.total.edges).toBe(9000);
    expect(r.truncation?.shown.edges).toBe(small.edges.length);
  });

  it("drops relationships whose endpoints the server did not return", () => {
    const small = syntheticGraph({ nodes: 100, edges: 300 });
    const nodes = small.nodes.slice(0, 60);
    const r = truncateGraph(nodes, small.edges, root, {
      nodes: 100,
      edges: 300,
    });
    const ids = new Set(r.nodes.map((n) => n.id));
    expect(r.edges.every((e) => ids.has(e.source) && ids.has(e.target))).toBe(
      true,
    );
  });
});

describe("boundedGraphClient", () => {
  const capture = () => {
    const seen: SearchRequest[] = [];
    const client: SearchClient = {
      search: (request) => {
        seen.push(request);
        return Promise.resolve({ rows: [], warnings: [], errors: [] });
      },
    };
    return { seen, client: boundedGraphClient(client) };
  };
  const base = {
    earliest: "-1h",
    maxRows: 10,
    signal: new AbortController().signal,
  };
  it("appends a top-N ranking to graph reads and allows truncation", async () => {
    const { seen, client } = capture();
    await client.search({
      ...base,
      search: '| `adm_application_graph_read("a","b","c","d")`',
    });
    expect(seen[0].search).toMatch(/\| sort 0 adm_rank_group -adm_rank_bytes/);
    expect(seen[0].search).toMatch(/adm_rank<=10000/);
    expect(seen[0].maxRows).toBe(GRAPH_BOUND_ROWS);
    expect(seen[0].overflow).toBe("truncate");
  });
  it("leaves other searches unchanged", async () => {
    const { seen, client } = capture();
    await client.search({ ...base, search: "`adm_topology`" });
    expect(seen[0]).toMatchObject({ search: "`adm_topology`", maxRows: 10 });
    expect(seen[0].overflow).toBeUndefined();
  });
});

describe("hit index", () => {
  it("finds the nearest polyline within tolerance", () => {
    const index = createHitIndex([
      {
        id: "a",
        points: [
          [0, 0],
          [1000, 0],
        ] as [number, number][],
      },
      {
        id: "b",
        points: [
          [0, 50],
          [0, 900],
          [800, 900],
        ] as [number, number][],
      },
    ]);
    expect(index.hit(500, 3, 6)?.id).toBe("a");
    expect(index.hit(400, 902, 6)?.id).toBe("b");
    expect(index.hit(400, 400, 6)).toBeUndefined();
  });
  it("indexes 100k lines quickly", () => {
    const lines = Array.from({ length: 100000 }, (_, i) => ({
      id: String(i),
      points: [
        [i % 2000, (i * 7) % 3000],
        [(i * 13) % 2000, (i * 3) % 3000],
      ] as [number, number][],
    }));
    const start = performance.now();
    const index = createHitIndex(lines);
    index.hit(1000, 1500, 6);
    expect(performance.now() - start).toBeLessThan(3000);
  });
});

describe("virtual table helpers", () => {
  it("windows rows with overscan", () => {
    expect(windowRange(0, 340, 34, 100000)).toEqual([0, 18]);
    expect(windowRange(34 * 5000, 340, 34, 100000)).toEqual([4992, 5018]);
    expect(windowRange(34 * 99990, 340, 34, 100000)).toEqual([99982, 100000]);
  });
  it("sorts stably by number or natural text", () => {
    const rows = ["b10", "a2", "b9", "a2"];
    expect(sortRows(rows, (r) => r, 1)).toEqual(["a2", "a2", "b9", "b10"]);
    expect(sortRows([3, 1, 2], (r) => r, -1)).toEqual([3, 2, 1]);
  });
});

describe("strokeWidth", () => {
  it("scales logarithmically within bounds", () => {
    expect(strokeWidth(0, 1e9)).toBe(1.25);
    expect(strokeWidth(1e9, 1e9)).toBe(7);
    const mid = strokeWidth(3e4, 1e9);
    expect(mid).toBeGreaterThan(1.25);
    expect(mid).toBeLessThan(7);
  });
});
