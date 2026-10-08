import { describe, expect, it } from "vitest";
import { csvCell, FLOW_COLUMNS, requiredFlowsCsv } from "./csv";
import { indexGraph, type Graph } from "./graph";
import {
  aclSummary,
  contractSummary,
  handoffExplanation,
  summarize,
} from "./glossary";
import { computeLayout } from "./layout";
import { rowsToGraph, type Row } from "./rows";
import {
  buildPath,
  deviceSummaries,
  fabricLayers,
  indexTopology,
  rowsToTopology,
  type Stage,
} from "./topology";
import { aciArgs, aciGraphRows, aciTopologyRows, ids } from "./testdata/aci";

const rows = () => structuredClone(aciGraphRows) as Row[];
const graph = (r: Row[] = rows()) => rowsToGraph(r, aciArgs);
const topo = () => indexTopology(rowsToTopology(aciTopologyRows));
const path = (edgeId: string, g: Graph = graph()) => {
  const index = indexGraph(g);
  return buildPath(index.edge.get(edgeId)!, g, index, topo());
};
const brief = (s: Stage) => `${s.kind}:${s.title}`;
const withEdge = (id: string, patch: Record<string, unknown>) =>
  rows().map((r) => (r.id === id ? { ...r, ...patch } : r));

describe("v2 graph contract", () => {
  it("accepts Service frontends, Envoy addresses and forwards_to edges", () => {
    const g = graph();
    const kinds = g.nodes.map((n) => n.endpoint_kind).filter(Boolean);
    expect(kinds.filter((k) => k === "k8s_service")).toHaveLength(6);
    expect(kinds.filter((k) => k === "k8s_node_proxy")).toHaveLength(2);
    const fwd = g.edges.filter((e) => e.relationship === "forwards_to");
    expect(fwd).toHaveLength(6);
    expect(fwd.find((e) => e.id === "fwd:catlb-a")).toMatchObject({
      confidence: "inferred",
      handoff_basis: "time_inferred",
      via_node: ["node-a"],
    });
    const gw = g.edges.find((e) => e.id === "conv:win-gw")!;
    expect(gw).toMatchObject({
      contract: "win-to-shop",
      contract_entry: "tcp 443",
      contract_basis: "intent",
      acl_action: "permit",
      acl_leaf: "pod-1/node-103",
      acl_permits: 6,
    });
  });

  it.each([
    ["forwards_to without handoff_basis", "fwd:gw-fe", { handoff_basis: "" }],
    [
      "the removed span_client_address basis",
      "fwd:gw-fe",
      { handoff_basis: "span_client_address" },
    ],
    ["service_only on an edge", "fwd:gw-fe", { handoff_basis: "service_only" }],
    ["a correlated hand-off", "fwd:gw-fe", { confidence: "correlated" }],
    ["a hand-off from a pod", "fwd:gw-fe", { source: ids.checkoutPod }],
    [
      "handoff_basis on a conversation",
      "conv:win-gw",
      { handoff_basis: "hubble_client_tuple" },
    ],
    ["an inferred conversation", "conv:win-gw", { confidence: "inferred" }],
    [
      "a contract on a hand-off",
      "fwd:gw-fe",
      { contract: "x", contract_basis: "intent" },
    ],
    [
      "a named contract that is neither intent nor deny",
      "conv:win-gw",
      { contract_basis: "not_evaluated" },
    ],
    [
      "intent without a contract",
      "conv:win-catlb",
      { contract_basis: "intent" },
    ],
    ["an unknown contract basis", "conv:win-gw", { contract_basis: "maybe" }],
    ["an unknown ACL action", "conv:win-gw", { acl_action: "deny" }],
    ["a non-numeric ACL count", "conv:win-gw", { acl_permits: "six" }],
  ])("rejects %s", (_, id, patch) => {
    expect(() => graph(withEdge(id, patch))).toThrow();
  });

  it("rejects an unknown endpoint kind", () => {
    expect(() =>
      graph(withEdge(ids.gateway, { endpoint_kind: "k8s_gateway" })),
    ).toThrow(/endpoint_kind/);
  });
});

describe("front-door layout", () => {
  const g = graph();
  const index = indexGraph(g);
  const layout = computeLayout(g, index, "network");
  const col = (id: string) => layout.items.get(id)!.column;

  it("puts Service frontends between sources and the application", () => {
    expect(layout.lanes.map((l) => l.title)).toContain("Entry points");
    expect(col(ids.win)).toBeLessThan(col(ids.gateway));
    expect(col(ids.gateway)).toBeLessThan(col(ids.fePod));
    expect(col(ids.envoyA)).toBe(col(ids.gateway));
    const np = layout.groups.find((gr) => gr.id.endsWith("shop/catalog-np"))!;
    expect(np.subtitle).toBe("NodePort 30081");
    expect(np.headerNodeId).toBe(ids.catalogNp);
    const gw = layout.groups.find((gr) => gr.id.endsWith("shop/shop-gateway"))!;
    expect(gw.subtitle).toBe("10.50.0.10:443");
  });

  it("routes hand-offs, labels inferred ones and flags blocked conversations", () => {
    const routed = new Map(layout.edges.map((r) => [r.id, r]));
    expect(routed.get("fwd:gw-fe")?.label).toBeUndefined();
    expect(routed.get("fwd:catlb-a")?.label).toBe("inferred");
    expect(routed.get("conv:win-db")?.blocked).toBe(true);
    expect(routed.get("conv:win-gw")?.blocked).toBeUndefined();
    for (const r of layout.edges)
      for (const [x, y] of r.points) expect(Number.isFinite(x + y)).toBe(true);
  });

  it("labels nodes without conversations as hosts, not tunnel peers", () => {
    const hosts = layout.groups.find(
      (gr) => gr.id === "group:infrastructure:hosts",
    )!;
    expect(hosts.subtitle).toBe("Hosting these pods");
    expect(hosts.items.map((i) => i.nodeId)).toEqual([
      ids.nodeA,
      ids.nodeB,
      ids.nodeC,
    ]);
  });

  it("keeps cards from overlapping", () => {
    const boxes = layout.groups;
    for (const a of boxes)
      for (const b of boxes)
        if (a !== b && a.column === b.column)
          expect(a.y + a.h <= b.y || b.y + b.h <= a.y).toBe(true);
  });
});

describe("candidate paths on one ACI fabric", () => {
  it("lists every equal-cost spine as one stage", () => {
    const layers = fabricLayers(topo(), "pod-1/node-103", "leaf-101")!;
    expect(layers.map((l) => l.ids)).toEqual([
      ["leaf-103"],
      ["spine-201", "spine-202"],
      ["leaf-101"],
    ]);
  });

  it("walks a Cilium Gateway conversation through Envoy to a remote backend", () => {
    const p = path("conv:win-gw");
    expect(p.stages.map(brief)).toEqual([
      "entity:win-client-01",
      "switch:leaf-103",
      "switch:One of 2 spines",
      "switch:leaf-101",
      "host:node-a",
      "handoff:Cilium Gateway",
      "switch:leaf-101",
      "switch:One of 2 spines",
      "switch:leaf-102",
      "host:node-b",
      "entity:frontend-6d8f9c7b5-q2w4e",
    ]);
    const [, leaf103, spines, , , handoff] = p.stages;
    expect(leaf103.observed).toBe(true);
    expect(leaf103.observedBy).toEqual(["Stream NetFlow", "ACI ACL log"]);
    expect(leaf103.ports).toEqual({ in: "Eth1/5", out: undefined });
    expect(spines.subtitle).toBe("spine-201, spine-202 · ECMP");
    expect(spines.alternatives).toEqual(["spine-201", "spine-202"]);
    expect(handoff.subtitle).toBe(
      "Envoy · VIP 10.50.0.10:443 · upstream from 10.42.0.200",
    );
    expect(handoff.handoff).toEqual({
      state: "observed",
      text: "Envoy forwarded with X-Forwarded-For 10.30.40.25",
    });
    expect(p.policy).toEqual([
      {
        text: "Permitted by contract win-to-shop · tcp 443 (intent)",
        tone: "intent",
      },
      { text: "ACL log: permit at leaf-103 (6 permits)", tone: "observed" },
    ]);
  });

  it("stops at the receiving node for NodePort Local", () => {
    const p = path("conv:win-fenp");
    expect(p.stages.slice(-3).map(brief)).toEqual([
      "host:node-b",
      "handoff:NodePort 30080",
      "entity:frontend-6d8f9c7b5-q2w4e",
    ]);
    expect(p.stages.at(-3)!.observed).toBe(true);
  });

  it("ends at the Service when no evidence chose a backend", () => {
    const p = path("conv:win-catnp");
    expect(p.stages.at(-1)!.handoff).toEqual({
      state: "undetermined",
      text: "Backend not determined (2 candidates)",
    });
    // Envoy only re-originates Gateway/Ingress traffic.
    expect(p.stages.at(-1)!.subtitle).toBe(
      "10.10.20.12:30081 · Cluster · SNAT",
    );
  });

  it("prefers the observed backend and attaches a floating-SVI node by LLDP", () => {
    const p = path("conv:win-catlb");
    const handoff = p.stages.find((s) => s.kind === "handoff")!;
    expect(handoff.handoff?.text).toBe(
      "Hubble recorded the SNAT translation on node-a",
    );
    const leaf = [...p.stages].reverse().find((s) => s.title === "leaf-103")!;
    expect(leaf.ports?.out).toBe("Eth1/13");
    expect(p.stages.at(-2)).toMatchObject({ kind: "host", title: "node-c" });
    expect(p.stages.at(-1)!.subtitle).toBe("Pod · shop · 1 of 2 backends");
  });

  it("keeps an intra-EPG conversation on its leaf with no contract", () => {
    const p = path("conv:win-win2");
    expect(p.stages.map(brief)).toEqual([
      "entity:win-client-01",
      "switch:leaf-103",
      "entity:win-client-02",
    ]);
    expect(p.stages[1].ports).toEqual({ in: "Eth1/5", out: "Eth1/6" });
    expect(p.policy).toEqual([
      { text: "Same EPG (intra-EPG)", tone: "intent" },
    ]);
  });

  it("shows a blocked conversation with the enforcing leaf", () => {
    const p = path("conv:win-db");
    expect(p.policy).toEqual([
      {
        text: "No permitting contract found in the collected policy",
        tone: "neutral",
      },
      {
        text: "ACL log: drop at leaf-103 (3 drops) · blocked by the fabric",
        tone: "blocked",
      },
    ]);
  });
});

describe("plain-language policy and hand-off copy", () => {
  it.each([
    [
      "hubble_client_tuple",
      "Hubble saw the same client address and port arrive at this pod",
    ],
    ["hubble_xlate", "Hubble recorded the SNAT translation on node-a"],
    [
      "time_inferred",
      "Inferred: the only connection from node-a to a catalog-api pod within 1 s",
    ],
    ["l7_forwarded_for", "Envoy forwarded with X-Forwarded-For 10.30.40.25"],
  ] as const)("explains %s", (basis, text) => {
    expect(
      handoffExplanation(basis, {
        service: "catalog-api",
        clients: ["10.30.40.25"],
        node: "node-a",
      }),
    ).toBe(text);
  });

  it("summarizes contract intent, unevaluated policy and ACL logs", () => {
    const g = graph();
    const edge = (id: string) => g.edges.find((e) => e.id === id)!;
    expect(contractSummary(edge("conv:win-catlb"))).toMatch(
      /^Policy not evaluated$/,
    );
    expect(contractSummary(edge("conv:envoy-fe"))).toBeUndefined();
    expect(aclSummary(edge("conv:co-db"))).toBeUndefined();
    const index = indexGraph(g);
    expect(
      summarize(g.nodes, g.edges, (id) => index.node.get(id)).blocked,
    ).toBe(1);
  });
});

describe("devices and required flows", () => {
  const g = graph();
  const index = indexGraph(g);
  it("credits the ACL-log leaf and lists idle spines", () => {
    const { devices, idle } = deviceSummaries(g.edges, topo());
    const leaf = devices.find((d) => d.label === "leaf-103")!;
    expect(leaf.sources).toEqual(["Stream NetFlow", "ACI ACL log"]);
    expect(leaf.edges.map((e) => e.id)).toContain("conv:win-db");
    expect(idle.map((d) => d.name)).toEqual(["spine-201", "spine-202"]);
  });

  it("adds contract, ACL, Service and backend columns", () => {
    const csv = requiredFlowsCsv(g, index, topo()).trimEnd().split("\r\n");
    expect(csv[0]).toBe(FLOW_COLUMNS.join(","));
    const col = (line: string, name: (typeof FLOW_COLUMNS)[number]) => {
      const cells = line.split(",");
      return cells[
        cells.length - FLOW_COLUMNS.length + FLOW_COLUMNS.indexOf(name)
      ];
    };
    const gw = csv.find((l) => l.includes("10.50.0.10"))!;
    expect(col(gw, "contract")).toBe("win-to-shop");
    expect(col(gw, "acl_action")).toBe("permit");
    expect(col(gw, "acl_leaf")).toBe("leaf-103 (node-103)");
    expect(col(gw, "service")).toBe("shop-gateway");
    expect(col(gw, "backend")).toBe("frontend-6d8f9c7b5-q2w4e");
    expect(col(gw, "handoff")).toBe("Envoy X-Forwarded-For");
    const np = csv.find(
      (l) => l.includes("10.10.20.12:30081") || l.includes(",30081,"),
    )!;
    expect(col(np, "backend")).toBe("not determined");
    const cat = csv.find((l) => l.includes(",catalog-api,"))!;
    expect(col(cat, "backend")).toBe(
      "catalog-6a1c2d3e4-p9r5t; catalog-6a1c2d3e4-x7k2m (inferred)",
    );
    const blocked = csv.find((l) => l.includes(",drop,"))!;
    expect(col(blocked, "contract_basis")).toBe("none");
  });

  it("neutralizes formula-like contract names", () => {
    const g2 = graph(withEdge("conv:win-gw", { contract: "=cmd|calc" }));
    const csv = requiredFlowsCsv(g2, indexGraph(g2), topo());
    expect(csv).toContain(csvCell("=cmd|calc"));
    expect(csv).not.toMatch(/,=cmd/);
  });
});
