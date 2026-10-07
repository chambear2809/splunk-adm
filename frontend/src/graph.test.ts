import { describe, expect, it } from "vitest";
import { directionLabel } from "./glossary";
import { indexGraph, matchesQuery, parseGraph, type Graph } from "./graph";
import { demoGraph } from "./provider";

const demo = demoGraph();
const clone = (): Record<string, any> => structuredClone(demo);
const kindOf = (g: Record<string, any>, id: string) =>
  g.nodes.find((n: { id: string }) => n.id === id).kind;
const edgeOf = (g: Record<string, any>, relationship: string) =>
  g.edges.find(
    (e: { relationship: string }) => e.relationship === relationship,
  );

describe("parseGraph", () => {
  it("accepts the demo fixture", () => {
    const g = parseGraph(clone());
    expect(g.boundary.root_node_id).toBe(demo.boundary.root_node_id);
    expect(g.nodes.length).toBeGreaterThan(0);
  });

  it("accepts an optional evidence_truncated flag and rejects non-booleans", () => {
    const g = clone();
    g.edges[0].evidence_truncated = true;
    expect(() => parseGraph(g)).not.toThrow();
    g.edges[0].evidence_truncated = "yes";
    expect(() => parseGraph(g)).toThrow(/invalid relationships/);
  });

  it("accepts an empty graph whose root is absent", () => {
    const g = clone();
    g.nodes = [];
    g.edges = [];
    expect(() => parseGraph(g)).not.toThrow();
  });

  it.each([
    [
      "endpoint_kind on a workload",
      (g: any) => {
        g.nodes.find((n: any) => n.kind === "workload").endpoint_kind = "vm";
      },
    ],
    [
      "unknown endpoint_kind",
      (g: any) => {
        g.nodes.find((n: any) => n.kind === "endpoint").endpoint_kind =
          "router";
      },
    ],
    [
      "non-string attribute",
      (g: any) => {
        g.nodes.find((n: any) => n.attributes).attributes.epg = 5;
      },
    ],
    [
      "out-of-range server_port",
      (g: any) => {
        edgeOf(g, "communicates_with").server_port = 70000;
      },
    ],
    [
      "unknown direction_basis",
      (g: any) => {
        edgeOf(g, "communicates_with").direction_basis = "guess";
      },
    ],
    [
      "non-array sources",
      (g: any) => {
        edgeOf(g, "communicates_with").sources = "netflow";
      },
    ],
    [
      "old coverage shape",
      (g: any) => {
        g.coverage = {
          spans: 1,
          flows: 1,
          matched_flows: 1,
          unresolved_flows: 0,
          warnings: [],
        };
      },
    ],
  ])("rejects %s", (_name, mutate) => {
    const g = clone();
    mutate(g);
    expect(() => parseGraph(g)).toThrow();
  });

  it.each([
    ["empty snapshot id", (g: any) => (g.snapshot_id = "")],
    ["empty node id", (g: any) => (g.nodes[0].id = "")],
    ["empty edge id", (g: any) => (g.edges[0].id = "")],
    ["empty boundary id", (g: any) => (g.boundary.id = "")],
  ])("rejects %s", (_name, mutate) => {
    const g = clone();
    mutate(g);
    expect(() => parseGraph(g)).toThrow();
  });

  it("rejects a root that is not a service", () => {
    const g = clone();
    const workload = g.nodes.find(
      (n: { kind: string }) => n.kind === "workload",
    );
    g.boundary.root_node_id = workload.id;
    expect(() => parseGraph(g)).toThrow(/not a service/);
  });

  it("rejects a missing root", () => {
    const g = clone();
    g.boundary.root_node_id = "service:nope";
    expect(() => parseGraph(g)).toThrow(/root/);
  });

  it("rejects runs_on from a service to a service", () => {
    const g = clone();
    const e = edgeOf(g, "runs_on");
    const other = g.nodes.find(
      (n: { kind: string; id: string }) =>
        n.kind === "service" && n.id !== e.source,
    );
    e.target = other.id;
    expect(() => parseGraph(g)).toThrow(/incompatible node kinds/);
  });

  it("rejects calls into a workload", () => {
    const g = clone();
    const e = edgeOf(g, "calls");
    e.target = edgeOf(g, "runs_on").target;
    expect(kindOf(g, e.target)).toBe("workload");
    expect(() => parseGraph(g)).toThrow(/incompatible node kinds/);
  });

  it("rejects communicates_with involving a service", () => {
    const g = clone();
    const e = edgeOf(g, "communicates_with");
    e.source = g.boundary.root_node_id;
    expect(() => parseGraph(g)).toThrow(/incompatible node kinds/);
  });

  it.each([
    ["numeric-looking generated_at", (g: any) => (g.generated_at = "1")],
    [
      "timezone-less generated_at",
      (g: any) => (g.generated_at = "2026-10-07T12:00:00"),
    ],
    ["date-only window", (g: any) => (g.window.start = "2026-10-07")],
    [
      "reversed window",
      (g: any) => {
        [g.window.start, g.window.end] = [g.window.end, g.window.start];
      },
    ],
    ["zero-length window", (g: any) => (g.window.start = g.window.end)],
  ])("rejects %s", (_name, mutate) => {
    const g = clone();
    mutate(g);
    expect(() => parseGraph(g)).toThrow();
  });

  it("accepts offsets and fractional seconds", () => {
    const g = clone();
    g.generated_at = "2026-10-07T14:00:00.123456+02:00";
    expect(() => parseGraph(g)).not.toThrow();
  });

  it("rejects dangling edge references", () => {
    const g = clone();
    g.edges[0].target = "workload:missing";
    expect(() => parseGraph(g)).toThrow(/invalid relationships/);
  });
});

describe("graph helpers", () => {
  const g = parseGraph(clone()) as Graph;
  it("indexes incident and outgoing edges", () => {
    const index = indexGraph(g);
    const root = g.boundary.root_node_id;
    expect(index.node.get(root)?.kind).toBe("service");
    for (const e of index.outgoing.get(root) ?? []) expect(e.source).toBe(root);
    const incidentCount = g.edges.filter(
      (e) => e.source === root || e.target === root,
    ).length;
    expect(index.incident.get(root)?.length).toBe(incidentCount);
  });
  it("matches attributes such as VM name and EPG", () => {
    const vm = g.nodes.find((n) => n.endpoint_kind === "vm")!;
    expect(matchesQuery(vm, "orders-db")).toBe(true);
    expect(matchesQuery(vm, "EPG")).toBe(false);
    expect(matchesQuery(vm, "db")).toBe(true);
  });
  it("explains direction in plain words", () => {
    const edge = (basis: string, sources: string[]) =>
      ({ ...g.edges[0], direction_basis: basis, sources }) as Graph["edges"][0];
    expect(
      directionLabel(edge("initiator", ["netflow", "ftd", "isovalent"])),
    ).toBe("Initiator reported by Cisco FTD and Isovalent");
    expect(directionLabel(edge("port_rule", ["netflow"]))).toMatch(/ports/);
    expect(directionLabel(edge("unknown", []))).toBe("Direction unknown");
  });
  it("matches labels and addresses case-insensitively", () => {
    const withAddress = g.nodes.find((n) => n.addresses?.length)!;
    expect(matchesQuery(withAddress, withAddress.addresses![0])).toBe(true);
    expect(matchesQuery(withAddress, withAddress.label.toUpperCase())).toBe(
      true,
    );
    expect(matchesQuery(withAddress, "   ")).toBe(true);
    expect(matchesQuery(withAddress, "no-such-thing-zz")).toBe(false);
  });
});
