import { describe, expect, it } from "vitest";
import aciRows from "../../fixtures/demo-rows-aci.json";
import aciTopology from "../../fixtures/demo-topology-aci.json";
import {
  contractCell,
  contractSummary,
  policyReason,
  receivedOn,
} from "./glossary";
import { indexGraph } from "./graph";
import { computeLayout } from "./layout";
import { FIT_MIN, itemText, NAME_PREFIX, rawFit } from "./MapView";
import { demoGraph, demoTopology } from "./provider";
import { rowsToGraph, type Row } from "./rows";
import {
  buildPath,
  deviceName,
  indexTopology,
  rowsToTopology,
  type Stage,
} from "./topology";

// The lab-exported ACI rows are the contract: these tests run on them as-is.
const graph = demoGraph();
const index = indexGraph(graph);
const topo = indexTopology(demoTopology());
const C = "demo-cluster";
const VM = "vm:prod/10.30.40.25";
const svc = (name: string, frontend: string) =>
  `k8s_service:${C}/shop/${name}/${frontend}`;
const conv = (source: string, target: string) =>
  graph.edges.find(
    (e) =>
      e.relationship === "communicates_with" &&
      e.source === source &&
      e.target === target,
  )!;
const nodeByLabel = (label: string) =>
  graph.nodes.find((n) => n.label === label)!.id;
const brief = (s: Stage) =>
  `${s.kind}:${s.title}${s.kind === "entity" || s.kind === "gap" || s.kind === "handoff" ? "" : s.observed ? " ✓" : " ·"}`;
const path = (source: string, target: string, backend?: string) =>
  buildPath(conv(source, target), graph, index, topo, { backend });

describe("real ACI demo rows", () => {
  it("assemble into a graph and topology without errors", () => {
    expect(() =>
      rowsToGraph(structuredClone(aciRows.rows) as Row[], aciRows.args),
    ).not.toThrow();
    expect(() =>
      rowsToTopology(structuredClone(aciTopology) as Row[]),
    ).not.toThrow();
    expect(graph.demo).toBe(true);
    expect(graph.nodes).toHaveLength(25);
    expect(graph.edges).toHaveLength(33);
    expect(topo.byKey.get("spine-201")?.role).toBe("spine");
    expect(topo.lldpHost.get("node-a")).toEqual({
      device: "leaf-101",
      port: "Ethernet1/11",
    });
  });

  it("VM → Gateway VIP → Envoy → remote frontend pod", () => {
    const p = path(VM, svc("cilium-gateway-shop", "10.50.0.10:443"));
    expect(p.stages.map(brief)).toEqual([
      "entity:win-client-01",
      "switch:leaf-103 ✓",
      "switch:One of 2 spines ·",
      "switch:leaf-101 ✓",
      "host:node-a ✓",
      "handoff:Cilium Gateway",
      "switch:leaf-101 ✓",
      "switch:One of 2 spines ·",
      "switch:leaf-102 ✓",
      "host:node-b ✓",
      "entity:frontend-7d9c6b5f4-q4m9z",
    ]);
    const handoff = p.stages[5];
    expect(handoff.subtitle).toBe(
      "Envoy · VIP 10.50.0.10:443 · upstream from 10.42.0.200",
    );
    expect(handoff.handoff?.text).toBe(
      "Envoy forwarded with X-Forwarded-For 10.30.40.25",
    );
    expect(p.backends.map((b) => b.label)).toEqual([
      "frontend-7d9c6b5f4-q4m9z",
      "frontend-7d9c6b5f4-x2k8p",
    ]);
    // Choosing the local backend ends at the receiving node.
    const local = path(
      VM,
      svc("cilium-gateway-shop", "10.50.0.10:443"),
      nodeByLabel("frontend-7d9c6b5f4-x2k8p"),
    );
    expect(local.stages.slice(-2).map(brief)).toEqual([
      "handoff:Cilium Gateway",
      "entity:frontend-7d9c6b5f4-x2k8p",
    ]);
  });

  it("Cluster SNAT catalog-api: SNAT translation plus an inferred connection", () => {
    const p = path(VM, svc("catalog-api", "10.50.0.30:8080"));
    const handoff = p.stages.find((s) => s.kind === "handoff")!;
    expect(handoff.handoff).toEqual({
      state: "observed",
      text: "Hubble recorded the SNAT translation on node-a; 1 more connection inferred from timing",
    });
    expect(p.backends).toEqual([
      {
        id: nodeByLabel("catalog-6a1c2d3e4-p9r5t"),
        label: "catalog-6a1c2d3e4-p9r5t",
        state: "observed",
      },
    ]);
    expect(p.stages.slice(-3).map(brief)).toEqual([
      "switch:leaf-103 ·",
      "host:node-c ·",
      "entity:catalog-6a1c2d3e4-p9r5t",
    ]);
  });

  it("draws catalog-api's two hand-offs as one labelled line", () => {
    const layout = computeLayout(graph, index, "network");
    const lines = layout.edges.filter(
      (r) =>
        r.edge.relationship === "forwards_to" &&
        r.edge.source === svc("catalog-api", "10.50.0.30:8080"),
    );
    expect(lines).toHaveLength(1);
    expect(lines[0].members).toHaveLength(2);
    expect(lines[0].edge.confidence).toBe("observed");
    expect(lines[0].label).toBe("+1 inferred");
    // The badge sits just before the target, not mid-route.
    const target = layout.items.get(lines[0].edge.target)!;
    expect(lines[0].mid.x).toBeGreaterThan(target.x - 120);
    expect(lines[0].mid.x).toBeLessThan(target.x);
  });

  it("DSR cart-api: received on node-b, IPIP to node-c, DSR note", () => {
    const p = path(VM, svc("cart-api", "10.50.0.40:8080"));
    expect(p.stages.map(brief)).toEqual([
      "entity:win-client-01",
      "switch:leaf-103 ✓",
      "switch:One of 2 spines ·",
      "switch:leaf-102 ✓",
      "host:node-b ·",
      "handoff:LoadBalancer VIP",
      "switch:leaf-102 ✓",
      "switch:One of 2 spines ·",
      "switch:leaf-103 ·",
      "host:node-c ✓",
      "entity:cart-4c2e5a7b9-w8v2c",
    ]);
    expect(p.stages[5].subtitle).toBe("VIP 10.50.0.40:8080 · Cluster · DSR");
    expect(p.notes[0]).toMatch(
      /^Cilium DSR: node-b forwards to node-c over IPIP/,
    );
    const ipip = conv(`node:${C}/node-b`, `node:${C}/node-c`);
    expect(ipip.transport).toBe("ipip");
    const layout = computeLayout(graph, index, "network");
    expect(layout.edges.find((r) => r.id === ipip.id)?.label).toBe(
      "IPIP (DSR)",
    );
  });

  it("NodePort Local payment-np stops at the receiving node", () => {
    const p = path(VM, svc("payment-np", "10.10.20.11:30080"));
    expect(p.stages.slice(-4).map(brief)).toEqual([
      "switch:leaf-101 ✓",
      "host:node-a ✓",
      "handoff:NodePort 30080",
      "entity:payment-2b4d6f8a1-k3j6h",
    ]);
    expect(p.stages.at(-2)!.handoff?.text).toBe(
      "Hubble saw the same client address and port arrive at this pod",
    );
  });

  it("direct pod IP crosses the fabric with no hand-off", () => {
    const p = path(VM, nodeByLabel("frontend-7d9c6b5f4-q4m9z"));
    expect(p.stages.map(brief)).toEqual([
      "entity:win-client-01",
      "switch:leaf-103 ✓",
      "switch:One of 2 spines ·",
      "switch:leaf-102 ✓",
      "host:node-b ✓",
      "entity:frontend-7d9c6b5f4-q4m9z",
    ]);
    expect(p.policy[0].text).toBe(
      "Permitted by contract win-to-pods · tcp 8080 (intent)",
    );
  });

  it("blocked VM → DB shows the ACI drop at leaf-103", () => {
    const p = path(VM, "vm:prod/10.20.30.40");
    expect(p.stages.map(brief)).toEqual([
      "entity:win-client-01",
      "switch:leaf-103 ✓",
      "switch:One of 2 spines ·",
      "switch:leaf-102 ·",
      "entity:orders-db-01",
    ]);
    expect(p.policy.map((x) => x.tone)).toEqual(["neutral", "blocked"]);
    expect(p.policy[1].text).toBe(
      "ACL log: drop at leaf-103 (1 drop) · blocked by the fabric",
    );
  });

  it("names a deny contract when one is reported", () => {
    const rows = (structuredClone(aciRows.rows) as Row[]).map((r) =>
      r.row_type === "edge" && r.acl_action === "drop"
        ? { ...r, contract: "deny-clients-to-db", contract_entry: "tcp 5432" }
        : r,
    );
    const g = rowsToGraph(rows, aciRows.args);
    const i = indexGraph(g);
    const e = g.edges.find((x) => x.acl_action === "drop")!;
    expect(buildPath(e, g, i, topo).policy[0].text).toBe(
      "Denied by contract deny-clients-to-db · tcp 5432",
    );
  });

  it("attaches Envoy through its node", () => {
    const p = path(
      `k8s_node_proxy:${C}/node-a`,
      nodeByLabel("frontend-7d9c6b5f4-q4m9z"),
    );
    expect(p.stages.map(brief)).toEqual([
      "entity:Envoy on node-a",
      "host:node-a ·",
      "switch:leaf-101 ✓",
      "switch:One of 2 spines ·",
      "switch:leaf-102 ✓",
      "host:node-b ✓",
      "entity:frontend-7d9c6b5f4-q4m9z",
    ]);
  });
});

describe("v2.1 contract changes on the real rows", () => {
  const patched = (patch: (r: Row) => Row) => {
    const g = rowsToGraph(
      (structuredClone(aciRows.rows) as Row[]).map(patch),
      aciRows.args,
    );
    return { g, i: indexGraph(g) };
  };
  const isGateway = (r: Row) =>
    r.row_type === "edge" &&
    r.relationship === "communicates_with" &&
    r.target === svc("cilium-gateway-shop", "10.50.0.10:443");

  it("shows intra-EPG and unevaluated policy without naming a contract", () => {
    const { g, i } = patched((r) =>
      isGateway(r)
        ? {
            ...r,
            contract_basis: "intra_epg",
            contract: undefined,
            contract_subject: undefined,
            contract_filter: undefined,
            contract_entry: undefined,
          }
        : r,
    );
    const e = g.edges.find((x) => x.target.includes("cilium-gateway"))!;
    expect(buildPath(e, g, i, topo).policy[0]).toEqual({
      text: "Same EPG (intra-EPG)",
      tone: "intent",
    });
    expect(() =>
      patched((r) =>
        isGateway(r) ? { ...r, contract_basis: "intra_epg" } : r,
      ),
    ).toThrow();
    const { g: g2 } = patched((r) =>
      isGateway(r)
        ? {
            ...r,
            contract_basis: "not_evaluated",
            contract: undefined,
            contract_reason: "vzAny relation in VRF shop:prod",
          }
        : r,
    );
    const e2 = g2.edges.find((x) => x.target.includes("cilium-gateway"))!;
    expect(contractSummary(e2)).toBe("Policy not evaluated");
    expect(policyReason(e2)).toBe("vzAny relation in VRF shop:prod");
    expect(contractCell(e2)).toBe("Not evaluated");
  });

  it("never presents one receiving node as fact when several received", () => {
    const { g, i } = patched((r) =>
      isGateway(r) ||
      (r.relationship === "forwards_to" &&
        r.source === svc("cilium-gateway-shop", "10.50.0.10:443"))
        ? { ...r, via_node: ["node-a", "node-b"] }
        : r,
    );
    const e = g.edges.find((x) => x.target.includes("cilium-gateway"))!;
    expect(e.via_node).toEqual(["node-a", "node-b"]);
    expect(receivedOn(e.via_node)).toBe("one of node-a, node-b");
    const p = buildPath(e, g, i, topo);
    const recv = p.stages.find((s) => s.alternatives?.includes("node-a"))!;
    expect(recv).toMatchObject({
      kind: "host",
      title: "One of 2 nodes",
      subtitle: "node-a, node-b · received the traffic",
    });
    // node-a and node-b sit on different leaves: no single leaf is claimed.
    expect(p.stages.some((s) => s.kind === "gap")).toBe(true);
    expect(p.stages.every((s) => s.title !== "host:node-a")).toBe(true);
  });

  it("reads integer window bounds and the new meta warnings", () => {
    expect(graph.window).toEqual({
      start: "2026-10-07T11:45:00.000Z",
      end: "2026-10-07T12:00:00.000Z",
    });
    const rows = (structuredClone(aciRows.rows) as Row[]).map((r) =>
      r.row_type === "meta"
        ? {
            ...r,
            warnings: [
              "3 summary rows listed only the first 50 connections; their hand-offs and connection counts are approximate.",
              "ACI policy read reached max_rows_per_query; contract annotations may be incomplete.",
            ],
          }
        : r,
    );
    expect(rowsToGraph(rows, aciRows.args).coverage.warnings).toHaveLength(2);
  });
});

describe("card names on the ACI demo at the 1440×900 fit", () => {
  // Map area at 1440×900: viewport minus header, toolbar and legend.
  const MAP_W = 1440,
    MAP_H = 900 - 54 - 50 - 37;
  const layout = computeLayout(graph, index, "network");
  const label = (raw: string) => deviceName(raw, topo).name;

  it("fits at 85% or more without collapsing pods", () => {
    expect(rawFit(layout, MAP_W, MAP_H)).toBeGreaterThanOrEqual(FIT_MIN);
    expect(layout.collapsed).toBe(false);
  });

  it("never truncates names of 16 characters or fewer, and keeps prefix and suffix otherwise", () => {
    const checked: string[] = [];
    for (const g of layout.groups)
      for (const it of g.items) {
        if (it.role === "summary") continue;
        const { text, fitted } = itemText(it, index.node.get(it.nodeId), label);
        checked.push(fitted.name);
        if (text.length <= 16) {
          expect(fitted.name, text).toBe(text);
          continue;
        }
        if (fitted.name === text) continue;
        const [head, tail] = fitted.name.split("…");
        expect(head.length, text).toBeGreaterThanOrEqual(NAME_PREFIX);
        expect(text.startsWith(head), text).toBe(true);
        const suffix = text.slice(text.lastIndexOf("-") + 1);
        if (suffix.length <= 8) expect(tail, text).toBe(suffix);
      }
    expect(checked).toEqual(
      expect.arrayContaining(["win-client-01", "orders-db-01", "checkout-api"]),
    );
    expect(
      checked.some(
        (n) =>
          /^frontend-7d9.*…q4m9z$/.test(n) || n === "frontend-7d9c6b5f4-q4m9z",
      ),
    ).toBe(true);
  });
});
