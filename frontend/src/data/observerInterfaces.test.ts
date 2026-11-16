import { describe, expect, it } from "vitest";
import vdsFiVpc from "../../../fixtures/path-trace-vds-fi-vpc.json";
import l3outFixture from "../../../fixtures/path-trace-l3out.json";
import {
  indexGraph,
  type Graph,
  type GraphEdge,
  type GraphNode,
} from "../graph";
import { endpointGraph } from "../trace/standaloneTrace";
import { traceTopology } from "../trace/traceModel";
import { emptyTopology, indexTopology } from "../topology";
import { pathTraceObservers } from "./pathTrace";
import {
  mergeObserverRows,
  observerInterfaceRows,
  outLabel,
} from "./observerInterfaces";

/**
 * A map conversation carrying the observers of a live adm_path_trace shape:
 * VDS IPFIX on both ESXi hosts and ingress-only NetFlow on both vPC leaves.
 */
function conversation(rows: unknown[], src: string, dst: string) {
  const g = endpointGraph(rows, [src, dst]);
  const topo = indexTopology(traceTopology(emptyTopology(), rows));
  const ports = [...topo.virtualPorts.values()].flat();
  const node = (ip: string): GraphNode => {
    const p = ports.find((x) => x.ip === ip);
    const attributes: Record<string, string> = p?.mac ? { mac: p.mac } : {};
    return {
      id: p?.vm ?? `ip:${ip}`,
      label: p?.vm_name ?? ip,
      kind: "endpoint",
      endpoint_kind: p ? "vm" : "external",
      addresses: [ip],
      attributes,
    };
  };
  const edge: GraphEdge = {
    id: "conv",
    source: node(src).id,
    target: node(dst).id,
    relationship: "communicates_with",
    evidence: [],
    confidence: "observed",
    count: 12,
    direction_basis: "initiator",
    observers: pathTraceObservers(rows),
  };
  const graph: Graph = { ...g, nodes: [node(src), node(dst)], edges: [edge] };
  return { edge, index: indexGraph(graph), topo };
}
const view = (rows: ReturnType<typeof observerInterfaceRows>) =>
  rows.map((r) => [r.label, r.in ?? "", r.out ?? "", r.records ?? "-"]);

describe("observer interfaces for a conversation", () => {
  const { edge, index, topo } = conversation(
    vdsFiVpc.rows as unknown[],
    "192.0.2.3",
    "198.51.100.2",
  );
  it("names in and out per observer device and infers the leaf egress", () => {
    const rows = observerInterfaceRows(edge, index, topo);
    expect(view(rows)).toEqual([
      [
        "vmm-dc1 on 203.0.113.11",
        "vmnic7 (vmm-dc1 uplink)",
        "k8s-vm-01 vNIC (port 9)",
        "-",
      ],
      ["vmm-dc1 on 203.0.113.11", "k8s-vm-01 vNIC (port 9)", "", "-"],
      [
        "vmm-dc1 on 203.0.113.14",
        "vmnic7 (vmm-dc1 uplink)",
        "app-vm-02 vNIC (port 48)",
        "-",
      ],
      ["vmm-dc1 on 203.0.113.14", "app-vm-02 vNIC (port 48)", "", "-"],
      ["fab1-leaf101", "port-channel2", "vpc-1-22-FI (inferred)", "-"],
      ["fab1-leaf102", "port-channel1", "vpc-1-22-FI (inferred)", "-"],
    ]);
    expect(rows.filter((r) => r.inferredOut).map((r) => r.label)).toEqual([
      "fab1-leaf101",
      "fab1-leaf102",
    ]);
    expect(rows.every((r) => r.sources.includes("Stream NetFlow"))).toBe(true);
    expect(rows.flatMap((r) => [r.in, r.out]).join(" ")).not.toMatch(/ifIndex/);
  });

  it("does not infer an egress when the direction is unknown", () => {
    const rows = observerInterfaceRows(
      { ...edge, direction_basis: "unknown" },
      index,
      topo,
    );
    expect(rows.some((r) => r.inferredOut)).toBe(false);
  });

  it("attributes records only to the observer that exported them", () => {
    const single = { ...edge, observers: [edge.observers![0]], records: 953 };
    expect(observerInterfaceRows(single, index, topo)[0].records).toBe(953);
    const qualified = {
      ...edge,
      traffic_observations: [
        { exporter_ip: "192.0.2.253" },
        { exporter_ip: "192.0.2.253" },
        { exporter_ip: "203.0.113.11" },
      ],
    };
    const rows = observerInterfaceRows(qualified, index, topo);
    expect(rows.find((r) => r.label === "fab1-leaf102")?.records).toBe(2);
    expect(rows.find((r) => r.label === "fab1-leaf101")?.records).toBe(
      undefined,
    );
  });

  it("merges a card's conversations per device and interface pair", () => {
    const rows = observerInterfaceRows(
      { ...edge, observers: [edge.observers![0]], records: 5 },
      index,
      topo,
    );
    const merged = mergeObserverRows([rows, rows]);
    expect(merged).toHaveLength(1);
    expect(merged[0].records).toBe(10);
  });
});

describe("observer interfaces toward an address outside the fabric", () => {
  it("points an ingress-only leaf at the fabric only when the destination has an ACI attachment", () => {
    const { edge, index, topo } = conversation(
      l3outFixture.rows as unknown[],
      "192.0.2.3",
      "198.51.100.6",
    );
    const leaf = observerInterfaceRows(edge, index, topo).find(
      (r) => r.label === "fab1-leaf102",
    );
    // No fvCEp for the destination: the egress stays unknown on the map.
    expect([leaf?.in, leaf?.out, leaf?.inferredOut]).toEqual([
      "port-channel1",
      undefined,
      false,
    ]);
    expect(outLabel("fabric (inferred)")).toBe("→ fabric (inferred)");
    expect(outLabel("Eth1/5")).toBe("Eth1/5");
  });
});
