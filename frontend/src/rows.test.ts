import { describe, expect, it } from "vitest";
import demo from "../../fixtures/demo-rows.json";
import expected from "../../tests/splunk/expected/graph.json";
import { MAX_ROWS, rowsToGraph, type Row } from "./rows";

const args = demo.args;
const rows = (): Row[] => structuredClone(demo.rows) as Row[];
const graph = () => rowsToGraph(rows(), args, { demo: true });

describe("rowsToGraph on captured lab rows", () => {
  const g = graph();
  const nodes = new Map(g.nodes.map((n) => [n.id, n]));

  it("builds the boundary, window and coverage from the meta row", () => {
    expect(g.demo).toBe(true);
    expect(g.boundary.root_node_id).toBe(
      "service:demo-cluster/shop/frontend/demo",
    );
    expect(g.window).toEqual({
      start: "2026-10-07T11:45:00.000Z",
      end: "2026-10-07T12:00:00.000Z",
    });
    const m = expected.meta;
    expect(g.coverage.conversations).toBe(Number(m.conversations_in_scope));
    expect(g.coverage.matched_conversations).toBe(
      Number(m.matched_conversations),
    );
    expect(g.coverage.unresolved_conversations).toBe(
      Number(m.unresolved_conversations),
    );
    expect(g.coverage.ambiguous_conversations).toBe(
      Number(m.ambiguous_conversations),
    );
    expect(g.coverage.spans).toBe(11);
    expect(g.coverage.warnings).toEqual([]);
  });

  it("matches the hand-derived expected node set", () => {
    expect([...nodes.keys()].sort()).toEqual(
      Object.keys(expected.nodes).sort(),
    );
    for (const id of expected.absent_nodes) expect(nodes.has(id)).toBe(false);
    for (const [id, want] of Object.entries(expected.nodes)) {
      const n = nodes.get(id)!;
      const w = want as Record<string, unknown>;
      expect(n.kind).toBe(w.kind);
      if (w.label) expect(n.label).toBe(w.label);
      if (w.endpoint_kind) expect(n.endpoint_kind).toBe(w.endpoint_kind);
      if (w.namespace) expect(n.namespace).toBe(w.namespace);
      if (w.addresses) expect(n.addresses).toEqual(w.addresses);
      for (const [k, v] of Object.entries(w))
        if (k.startsWith("attr_")) expect(n.attributes?.[k.slice(5)]).toBe(v);
    }
  });

  it("matches the hand-derived expected edge set", () => {
    const key = (e: { relationship: string; source: string; target: string }) =>
      `${e.relationship} ${e.source} ${e.target}`;
    expect(g.edges.map(key).sort()).toEqual(expected.edges.map(key).sort());
    for (const want of expected.edges as Record<string, unknown>[]) {
      const e = g.edges.find((x) => key(x) === key(want as never))!;
      if (want.confidence) expect(e.confidence).toBe(want.confidence);
      if (want.server_port)
        expect(e.server_port).toBe(Number(want.server_port));
      if (want.transport) expect(e.transport).toBe(want.transport);
      if (want.direction_basis)
        expect(e.direction_basis).toBe(want.direction_basis);
      if (want.encapsulation) expect(e.encapsulation).toBe(want.encapsulation);
      if (want.bytes) expect(e.bytes).toBe(Number(want.bytes));
      if (want.sources) expect(e.sources).toEqual(want.sources);
      if (want.span_ids) expect(e.span_ids).toEqual(want.span_ids);
      for (const ev of (want.evidence_includes as string[]) ?? [])
        expect(e.evidence).toContain(ev);
    }
  });

  it("normalizes single values and multivalues to arrays", () => {
    const single = g.edges.find((e) => e.sources?.length === 1)!;
    expect(Array.isArray(single.observers)).toBe(true);
    const vm = nodes.get("vm:prod/10.20.30.40")!;
    expect(vm.addresses).toEqual(["10.20.30.40"]);
  });
});

describe("rowsToGraph validation", () => {
  const meta = () => rows().find((r) => r.row_type === "meta")!;

  it("keeps pipe characters inside a value instead of splitting", () => {
    const r = rows();
    const e = r.find((x) => x.relationship === "communicates_with")!;
    e.observers = "netflow:192.0.2.11:a|b>c";
    const g = rowsToGraph(r, args);
    expect(g.edges.find((x) => x.id === e.id)!.observers).toEqual([
      "netflow:192.0.2.11:a|b>c",
    ]);
  });

  it("accepts the empty graph a missing entry service produces", () => {
    const m = meta();
    m.root_present = "0";
    m.nodes = "0";
    m.edges = "0";
    m.warnings = "Entry service frontend has no spans; the graph is empty.";
    const g = rowsToGraph([m], args);
    expect(g.nodes).toEqual([]);
    expect(g.coverage.warnings[0]).toMatch(/no spans/);
  });

  it("surfaces the search's limit warning", () => {
    const m = meta();
    m.nodes = "501";
    m.warnings = [
      "Graph exceeds 500 nodes or 2,000 edges (501 nodes, 3 edges); narrow the window or the namespace.",
    ];
    expect(() => rowsToGraph([m], args)).toThrow(/Graph exceeds 500 nodes/);
  });

  it("rejects more rows than the limit allows", () => {
    expect(() =>
      rowsToGraph(new Array(MAX_ROWS + 1).fill(meta()), args),
    ).toThrow(/pilot limit/);
  });

  it.each([
    ["no meta row", (r: Row[]) => r.filter((x) => x.row_type !== "meta")],
    [
      "two meta rows",
      (r: Row[]) => [...r, r.find((x) => x.row_type === "meta")!],
    ],
    ["unknown row type", (r: Row[]) => [...r, { row_type: "trace" }]],
    ["non-object row", (r: Row[]) => [...r, "x" as unknown as Row]],
    [
      "node without id",
      (r: Row[]) => {
        delete r.find((x) => x.row_type === "node")!.id;
        return r;
      },
    ],
    [
      "unknown node kind",
      (r: Row[]) => {
        r.find((x) => x.row_type === "node")!.kind = "router";
        return r;
      },
    ],
    [
      "unknown endpoint kind",
      (r: Row[]) => {
        r.find((x) => x.endpoint_kind)!.endpoint_kind = "switch";
        return r;
      },
    ],
    [
      "non-numeric count",
      (r: Row[]) => {
        r.find((x) => x.row_type === "edge")!.count = "12abc";
        return r;
      },
    ],
    [
      "negative port",
      (r: Row[]) => {
        r.find((x) => x.server_port)!.server_port = "-1";
        return r;
      },
    ],
    [
      "port out of range",
      (r: Row[]) => {
        r.find((x) => x.server_port)!.server_port = "70000";
        return r;
      },
    ],
    [
      "unknown direction basis",
      (r: Row[]) => {
        r.find((x) => x.direction_basis)!.direction_basis = "guess";
        return r;
      },
    ],
    [
      "multivalue where a single value is required",
      (r: Row[]) => {
        r.find((x) => x.row_type === "edge")!.source = ["a", "b"];
        return r;
      },
    ],
    [
      "dangling edge target",
      (r: Row[]) => {
        r.find((x) => x.row_type === "edge")!.target = "pod:missing";
        return r;
      },
    ],
    [
      "duplicate node",
      (r: Row[]) => [...r, r.find((x) => x.row_type === "node")!],
    ],
    [
      "missing window",
      (r: Row[]) => {
        delete r.find((x) => x.row_type === "meta")!.window_start;
        return r;
      },
    ],
    [
      "object value",
      (r: Row[]) => {
        r.find((x) => x.row_type === "node")!.label = { a: 1 };
        return r;
      },
    ],
  ])("rejects %s", (_name, mutate) => {
    expect(() => rowsToGraph(mutate(rows()), args)).toThrow();
  });

  it("rejects a non-array result", () => {
    expect(() => rowsToGraph({ rows: [] }, args)).toThrow();
  });
});
