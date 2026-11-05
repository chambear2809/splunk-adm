import { describe, expect, it } from "vitest";
import aciTopologyRows from "../../../fixtures/demo-topology-aci.json";
import vsphereRows from "../../../fixtures/demo-topology-aci-vsphere.json";
import vdsFiVpc from "../../../fixtures/path-trace-vds-fi-vpc.json";
import { demoPathTraceRows } from "../data/demoClient";
import type { SearchClient, SearchRequest } from "../data/searchClient";
import {
  endpointGraph,
  loadStandaloneTrace,
  pathTraceResolveSearch,
  resolvedAddresses,
} from "./standaloneTrace";
import { emptyTopology } from "../topology";
import { assembleTrace } from "./usePathTrace";

/** adm_ip_identity rows the trace search appends for the demo pair. */
const endpointRows = [
  {
    row_type: "endpoint",
    ip: "10.30.40.25",
    scope: "prod",
    entity_kind: "vm",
    entity_name: "win-client-01",
    attach_device: "pod-1/node-103",
    attach_interface: "eth1/5",
    epg: "win-clients",
    tenant: "shop",
    mac: "00:50:56:AA:40:25",
  },
  {
    row_type: "endpoint",
    ip: "10.20.30.40",
    scope: "prod",
    entity_kind: "vm",
    entity_name: "orders-db-01",
    attach_device: "pod-1/node-102",
    attach_interface: "eth1/6",
    epg: "db",
    tenant: "shop",
  },
];

const fakeClient = (requests: SearchRequest[]): SearchClient => ({
  async search(request) {
    requests.push(request);
    if (request.search === "`adm_topology`")
      return { rows: aciTopologyRows, warnings: [], errors: [] };
    if (request.search.includes("adm_path_trace_resolve(win-client-01)"))
      return {
        rows: [{ entity_name: "win-client-01", ip: ["10.30.40.25"] }],
        warnings: [],
        errors: [],
      };
    if (request.search.includes("adm_path_trace_resolve(db)"))
      return {
        rows: [
          { entity_name: "orders-db-01", ip: "10.20.30.40" },
          { entity_name: "orders-db-02", ip: "10.20.30.41" },
        ],
        warnings: [],
        errors: [],
      };
    if (request.search.includes("adm_path_trace_resolve"))
      return { rows: [], warnings: [], errors: [] };
    if (request.search.includes("adm_path_trace("))
      return {
        rows: [...demoPathTraceRows(), ...endpointRows, ...vsphereRows],
        warnings: [],
        errors: [],
      };
    throw new Error(`Unexpected search ${request.search}`);
  },
});
const w = {
  earliest: "-1h",
  latest: "now",
  signal: new AbortController().signal,
};

describe("trace without a built map", () => {
  it("resolves a name server-side and assembles the full path", async () => {
    const requests: SearchRequest[] = [];
    const r = await loadStandaloneTrace(
      fakeClient(requests),
      { src: "win-client-01", dst: "10.20.30.40" },
      w,
    );
    expect(r.addresses).toEqual({ src: "10.30.40.25", dst: "10.20.30.40" });
    expect(requests.map((q) => q.search)).toContain(
      "| `adm_path_trace(10.30.40.25,10.20.30.40)`",
    );
    expect(requests.every((q) => q.earliest === "-1h")).toBe(true);
    const { trace } = assembleTrace(r.addresses, r.graph, r.topology, r.rows);
    expect(trace.status).toBe("traced");
    expect(trace.hops.map((h) => h.label)).toEqual([
      "win-client-01",
      "vmm-shop",
      "leaf-103",
      "One of 2 spines",
      "leaf-102",
      "vmm-shop",
      "orders-db-01",
    ]);
  });

  it("refuses ambiguous and unknown names", async () => {
    const client = fakeClient([]);
    await expect(
      loadStandaloneTrace(client, { src: "db", dst: "10.1.1.1" }, w),
    ).rejects.toThrow('Source "db" matches 2 addresses; enter an IP.');
    await expect(
      loadStandaloneTrace(client, { src: "10.1.1.1", dst: "ghost" }, w),
    ).rejects.toThrow('Destination "ghost" not found.');
  });

  it("builds endpoint nodes and keeps bare IPs traceable", () => {
    const g = endpointGraph(endpointRows, ["10.30.40.25", "203.0.113.9"]);
    expect(g.nodes.map((n) => n.id)).toEqual([
      "vm:prod/10.30.40.25",
      "vm:prod/10.20.30.40",
      "ip:203.0.113.9",
    ]);
    expect(g.nodes[0].attributes?.attach_device).toBe("pod-1/node-103");
    expect(
      resolvedAddresses([{ ip: ["10.0.0.1", "bad", "10.0.0.1"] }]),
    ).toEqual(["10.0.0.1"]);
    expect(() => pathTraceResolveSearch("a,b")).toThrow();
    expect(pathTraceResolveSearch("orders-db-01")).toBe(
      "| `adm_path_trace_resolve(orders-db-01)`",
    );
  });
});

describe("trace through a VDS, UCS fabric interconnects and a vPC leaf pair", () => {
  // Live adm_path_trace shape (see _provenance): the source address is both a
  // Kubernetes node and a VM; the destination is a VM; ACI topology rows are
  // absent from adm_topology.
  const rows = vdsFiVpc.rows as unknown[];
  const pair = { src: "192.0.2.3", dst: "198.51.100.2" };
  const trace = () =>
    assembleTrace(
      pair,
      endpointGraph(rows, [pair.src, pair.dst]),
      emptyTopology(),
      rows,
    ).trace;

  it("starts at the VM vNIC rather than the Kubernetes node identity", () => {
    const g = endpointGraph(rows, [pair.src, pair.dst]);
    expect(g.nodes.map((n) => [n.label, n.endpoint_kind])).toEqual([
      ["k8s-vm-01", "vm"],
      ["app-vm-02", "vm"],
    ]);
  });

  it("draws both VDS instances, the FI pair and the vPC leaves without a spine", () => {
    const t = trace();
    expect(t.status).toBe("traced");
    expect(t.hops.map((h) => [h.kind, h.label, h.evidence])).toEqual([
      ["endpoint", "k8s-vm-01", "observed"],
      ["virtual_switch", "vmm-dc1", "observed"],
      ["switch", "One of 2 switches", "inferred"],
      ["switch", "One of 2 leaves", "observed"],
      ["switch", "One of 2 switches", "inferred"],
      ["virtual_switch", "vmm-dc1", "observed"],
      ["endpoint", "app-vm-02", "observed"],
    ]);
    expect(t.hops[1].detail).toContain("on 203.0.113.11");
    expect(t.hops[5].detail).toContain("on 203.0.113.14");
    expect(t.hops[3].alternatives?.map((a) => a.label)).toEqual([
      "fab1-leaf101",
      "fab1-leaf102",
    ]);
  });

  it("names exporter ifIndex values from SNMP and VMware inventory", () => {
    const t = trace();
    expect(t.hops[3].seen).toEqual(["port-channel2", "port-channel1"]);
    expect(t.hops[1].seen).toContain(
      "vmnic7 (vmm-dc1 uplink) → k8s-vm-01 vNIC (port 9)",
    );
    expect(t.hops[5].seen).toContain(
      "vmnic7 (vmm-dc1 uplink) → app-vm-02 vNIC (port 48)",
    );
    expect(t.hops.flatMap((h) => h.seen).join(" ")).not.toMatch(/ifIndex/);
  });

  it("keeps the known vPC attachment when the other side is unknown", () => {
    const t = assembleTrace(
      { src: pair.src, dst: "203.0.113.99" },
      endpointGraph(rows, [pair.src, "203.0.113.99"]),
      emptyTopology(),
      rows,
    ).trace;
    expect(t.hops.map((h) => h.label)).toEqual([
      "k8s-vm-01",
      "vmm-dc1",
      "One of 2 switches",
      "One of 2 leaves",
      "Attachment of 203.0.113.99 unknown",
      "203.0.113.99",
    ]);
  });
});
