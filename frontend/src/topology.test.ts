import { describe, expect, it } from "vitest";
import topologyRows from "../../fixtures/demo-topology.json";
import { indexGraph, type GraphEdge } from "./graph";
import { demoGraph, demoTopology } from "./provider";
import {
  buildPath,
  emptyTopology,
  indexTopology,
  interfaceKey,
  interfaceLabel,
  observationsByDevice,
  parseObserver,
  rowsToTopology,
} from "./topology";

const graph = demoGraph();
const index = indexGraph(graph);
const topo = indexTopology(demoTopology());
const byLabel = (label: string) =>
  graph.nodes.find((n) => n.label === label)!.id;
const conv = (from: string, to: string): GraphEdge =>
  graph.edges.find(
    (e) =>
      e.relationship === "communicates_with" &&
      e.source === byLabel(from) &&
      e.target === byLabel(to),
  )!;
const titles = (edge: GraphEdge, t = topo) =>
  buildPath(edge, graph, index, t).stages.map((s) =>
    s.kind === "gap" ? "GAP" : s.title,
  );

describe("rowsToTopology", () => {
  it("parses the captured adm_topology rows", () => {
    const t = rowsToTopology(topologyRows);
    expect(t.devices.map((d) => d.id).sort()).toEqual([
      "border-1",
      "ftd-edge",
      "leaf-101",
      "leaf-102",
      "leaf-201",
    ]);
    expect(t.links).toHaveLength(2);
    expect(t.devices.find((d) => d.id === "ftd-edge")?.kind).toBe("firewall");
    expect(t.devices.find((d) => d.id === "leaf-201")?.aci_node).toBe(
      "pod-1/node-201",
    );
    expect(
      t.interfaces.find(
        (i) => i.device_id === "leaf-101" && i.interface === "Ethernet1/49",
      )?.ifindex,
    ).toBe(436232192);
    expect(t.warnings[0]).toMatch(/ifIndex/);
  });
  it.each([
    ["not an array", { rows: [] }],
    ["unknown row type", [{ row_type: "router" }]],
    ["device without id", [{ row_type: "device", name: "x" }]],
    [
      "unsupported device kind",
      [{ row_type: "device", device_id: "x", device_kind: "toaster" }],
    ],
    ["link missing an end", [{ row_type: "link", a_device: "x" }]],
    [
      "non-numeric ifindex",
      [
        {
          row_type: "interface",
          device_id: "x",
          interface: "Ethernet1/1",
          ifindex: "abc",
        },
      ],
    ],
    ["multivalue device id", [{ row_type: "device", device_id: ["a", "b"] }]],
  ])("rejects %s", (_name, rows) => {
    expect(() => rowsToTopology(rows)).toThrow();
  });
});

describe("interface names", () => {
  it("normalizes ethX/Y, EthX/Y and EthernetX/Y to one key", () => {
    expect(interfaceKey("eth1/11")).toBe(interfaceKey("Ethernet1/11"));
    expect(interfaceKey("Eth1/11")).toBe(interfaceKey("ethernet1/11"));
    expect(interfaceKey("Ethernet1/1/2")).toBe("ethernet1/1/2");
    expect(interfaceLabel("Ethernet1/49")).toBe("Eth1/49");
    expect(interfaceLabel("inside")).toBe("inside");
  });
});

describe("parseObserver", () => {
  it("names NetFlow exporters and resolves known ifIndex values", () => {
    const [p] = parseObserver(
      "netflow:192.0.2.11:ifIndex 436232192>ifIndex 999",
      topo,
    );
    expect(p).toMatchObject({
      key: "leaf-101",
      label: "leaf-101",
      in: "Eth1/49",
      out: "ifIndex 999",
    });
  });
  it("splits Nexus Dashboard ingress and egress leaves and skips unknowns", () => {
    const points = parseObserver(
      "nd:dc1-vxlan:leaf-101:eth1/11>leaf-102:eth1/12",
      topo,
    );
    expect(points.map((p) => [p.label, p.in ?? p.out])).toEqual([
      ["leaf-101", "Eth1/11"],
      ["leaf-102", "Eth1/12"],
    ]);
    expect(parseObserver("nd:dc1-vxlan:?>leaf-101:eth1/11", topo)).toHaveLength(
      1,
    );
  });
  it("maps Isovalent to the node and FTD to the firewall", () => {
    expect(parseObserver("isovalent:node-a", topo)[0]).toMatchObject({
      key: "node-a",
      role: "host",
    });
    expect(
      parseObserver("ftd:192.0.2.1:inside>outside", topo)[0],
    ).toMatchObject({
      label: "ftd-edge",
      role: "firewall",
      in: "inside",
      out: "outside",
    });
  });
  it("falls back to the raw address for unknown exporters", () => {
    expect(parseObserver("netflow:198.51.100.99:a>b", topo)[0].label).toBe(
      "Exporter 198.51.100.99",
    );
  });
  it("groups observations by device for Seen by lists", () => {
    const seen = observationsByDevice(
      conv("checkout-5f8b9c7d6-m4n7q", "catalog-6a1c2d3e4-p9r5t"),
      topo,
    );
    expect(seen.map((d) => d.label).sort()).toEqual([
      "leaf-101",
      "leaf-102",
      "node-a",
    ]);
  });
});

describe("buildPath", () => {
  it("walks pod → node → leaf → CDP path → leaf → node → pod", () => {
    const edge = conv("checkout-5f8b9c7d6-m4n7q", "catalog-6a1c2d3e4-p9r5t");
    const path = buildPath(edge, graph, index, topo);
    expect(titles(edge)).toEqual([
      "checkout-5f8b9c7d6-m4n7q",
      "node-a",
      "leaf-101",
      "border-1",
      "leaf-102",
      "node-b",
      "catalog-6a1c2d3e4-p9r5t",
    ]);
    const seen = Object.fromEntries(
      path.stages.map((s) => [s.title, s.observed]),
    );
    expect(seen["leaf-101"]).toBe(true);
    expect(seen["leaf-102"]).toBe(true);
    expect(seen["node-a"]).toBe(true);
    expect(seen["border-1"]).toBe(false);
    const leaf101 = path.stages.find((s) => s.title === "leaf-101")!;
    expect(leaf101.ports).toEqual({ in: "Eth1/11", out: "Eth1/49" });
  });
  it("keeps same-node pod traffic off the fabric", () => {
    const path = buildPath(
      conv("frontend-7d9c6b5f4-x2k8p", "checkout-5f8b9c7d6-m4n7q"),
      graph,
      index,
      topo,
    );
    expect(path.sameHost).toBe(true);
    expect(path.stages.map((s) => s.title)).toEqual([
      "frontend-7d9c6b5f4-x2k8p",
      "node-a",
      "checkout-5f8b9c7d6-m4n7q",
    ]);
  });
  it("shows a gap where no link joins the NX-OS fabric to ACI", () => {
    expect(titles(conv("checkout-5f8b9c7d6-m4n7q", "orders-db-01"))).toEqual([
      "checkout-5f8b9c7d6-m4n7q",
      "node-a",
      "leaf-101",
      "GAP",
      "leaf-201",
      "orders-db-01",
    ]);
  });
  it("places the firewall next to the external side with gaps", () => {
    const edge = conv("payment-2b4d6f8a1-k3j6h", "203.0.113.40");
    expect(titles(edge)).toEqual([
      "payment-2b4d6f8a1-k3j6h",
      "node-b",
      "leaf-102",
      "GAP",
      "ftd-edge",
      "203.0.113.40",
    ]);
    const fw = buildPath(edge, graph, index, topo).stages.find(
      (s) => s.title === "ftd-edge",
    )!;
    expect(fw).toMatchObject({ kind: "firewall", observed: true });
    expect(fw.seenInterfaces).toEqual(["inside → outside"]);
  });
  it("starts with a gap when the client is unknown", () => {
    expect(titles(conv("10.99.0.7", "cart-4c2e5a7b9-w8v2c"))).toEqual([
      "10.99.0.7",
      "GAP",
      "leaf-102",
      "node-b",
      "cart-4c2e5a7b9-w8v2c",
    ]);
  });
  it("routes tunnel traffic between nodes", () => {
    expect(titles(conv("node-a", "node-b"))).toEqual([
      "node-a",
      "leaf-101",
      "border-1",
      "leaf-102",
      "node-b",
    ]);
  });
  it("says so when no topology is loaded", () => {
    const empty = indexTopology(emptyTopology());
    const path = buildPath(
      conv("checkout-5f8b9c7d6-m4n7q", "catalog-6a1c2d3e4-p9r5t"),
      graph,
      index,
      empty,
    );
    expect(path.stages.find((s) => s.kind === "gap")?.title).toBe(
      "Topology not loaded",
    );
  });
});

describe("edgeMatches and deviceName", () => {
  it("finds every conversation a device saw", async () => {
    const { edgeMatches } = await import("./topology");
    const seenBy101 = graph.edges.filter((e) =>
      edgeMatches(e, "leaf-101", topo),
    );
    expect(seenBy101.length).toBeGreaterThanOrEqual(8);
    expect(
      graph.edges
        .filter((e) => edgeMatches(e, "ftd-edge", topo))
        .map((e) => e.target),
    ).toEqual([byLabel("203.0.113.40")]);
    expect(graph.edges.some((e) => edgeMatches(e, "ethernet1/12", topo))).toBe(
      true,
    );
    expect(
      graph.edges.filter((e) => edgeMatches(e, "5432", topo)),
    ).toHaveLength(1);
  });
  it("names ACI leaves by hostname with the node as secondary text", async () => {
    const { deviceName } = await import("./topology");
    expect(deviceName("pod-1/node-201", topo)).toEqual({
      name: "leaf-201",
      secondary: "node-201",
    });
    expect(deviceName("leaf-101", topo)).toEqual({ name: "leaf-101" });
    expect(deviceName("mystery", topo)).toEqual({ name: "mystery" });
  });
  it("summarizes devices and conversations missed by the fabric", async () => {
    const { deviceSummaries } = await import("./topology");
    const s = deviceSummaries(graph.edges, topo);
    expect(s.devices[0].label).toBe("ftd-edge");
    expect(s.devices.map((d) => d.label)).toEqual(
      expect.arrayContaining(["leaf-101", "leaf-102", "node-a", "node-b"]),
    );
    // ingress→frontend, frontend→checkout and checkout→coredns are Isovalent-only.
    expect(s.unseenByFabric).toHaveLength(3);
    expect(s.idle.map((d) => d.name)).toEqual(["border-1", "leaf-201"]);
  });
});
