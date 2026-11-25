import { describe, expect, it } from "vitest";
import aciTopologyRows from "../../../fixtures/demo-topology-aci.json";
import vsphereRows from "../../../fixtures/demo-topology-aci-vsphere.json";
import vdsFiVpc from "../../../fixtures/path-trace-vds-fi-vpc.json";
import { demoPathTraceRows } from "../data/demoClient";
import {
  SearchAccessDeniedError,
  type SearchClient,
  type SearchRequest,
} from "../data/searchClient";
import {
  endpointGraph,
  loadStandaloneTrace,
  pathTraceResolveSearch,
  qualifiedEndpointRows,
  resolvedAddresses,
  traceWindow,
} from "./standaloneTrace";
import { emptyTopology } from "../topology";
import {
  assembleScopedTrace,
  assembleStandaloneResult,
  assembleTrace,
} from "./usePathTrace";

/** adm_ip_identity rows the trace search appends for the demo pair. */
const endpointRows = [
  {
    row_type: "endpoint",
    ip: "10.30.40.25",
    scope: "prod",
    scope_mapping_verified: 1,
    entity_id: "client",
    valid_from: 0,
    valid_end: 300,
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
    scope_mapping_verified: 1,
    entity_id: "database",
    valid_from: 0,
    valid_end: 300,
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
    if (request.search.includes("adm_path_trace_resolve(win-client-01,"))
      return {
        rows: [{ ...endpointRows[0], ip: ["10.30.40.25"] }],
        warnings: [],
        errors: [],
      };
    if (request.search.includes("adm_path_trace_resolve(db,"))
      return {
        rows: [
          { ...endpointRows[1], ip: "10.20.30.40" },
          { ...endpointRows[1], entity_id: "other-db", ip: "10.20.30.41" },
        ],
        warnings: [],
        errors: [],
      };
    if (request.search.includes("adm_path_trace_resolve"))
      return { rows: [], warnings: [], errors: [] };
    if (request.search.includes("adm_path_trace("))
      return {
        rows: [
          ...demoPathTraceRows(),
          ...endpointRows,
          ...vsphereRows,
          {
            row_type: "observation",
            scope: "prod",
            flow_source: "ftd",
            records: "2",
            drops: "1",
          },
          {
            row_type: "observation",
            scope: "other",
            flow_source: "ftd",
            records: "20",
          },
        ],
        warnings: [],
        errors: [],
      };
    if (request.search.includes("adm_path_evidence("))
      return { rows: [], warnings: [], errors: [] };
    throw new Error(`Unexpected search ${request.search}`);
  },
});
const w = {
  earliest: "100",
  latest: "200",
  scope: "prod",
  signal: new AbortController().signal,
};

describe("trace without a built map", () => {
  it("surfaces main-search warnings in the operator trace notes", async () => {
    const client = fakeClient([]);
    const warningClient: SearchClient = {
      search: async (request) => {
        const result = await client.search(request);
        return request.search.includes("adm_path_trace(")
          ? { ...result, warnings: ["search peer did not respond"] }
          : result;
      },
    };
    const result = await loadStandaloneTrace(
      warningClient,
      { src: "win-client-01", dst: "10.20.30.40" },
      w,
    );
    expect(result.warnings).toContain(
      "Path trace search was incomplete: search peer did not respond",
    );
    expect(result.graph.nodes.map((node) => node.label)).toEqual([
      "10.30.40.25",
      "10.20.30.40",
    ]);
    const trace = assembleStandaloneResult(
      { ...result.addresses, scope: "prod" },
      result,
    ).trace;
    expect(trace.notes).toContain(
      "Trace data quality: Path trace search was incomplete: search peer did not respond",
    );
  });

  it("distinguishes gNMI access denial from empty optional context", async () => {
    const base = fakeClient([]);
    const client: SearchClient = {
      search: async (request) => {
        if (request.search.includes("adm_path_trace_gnmi_context"))
          throw new SearchAccessDeniedError();
        return base.search(request);
      },
    };
    const result = await loadStandaloneTrace(
      client,
      { src: "win-client-01", dst: "10.20.30.40" },
      w,
    );
    expect(result.warnings).toContain(
      "gNMI interface context access denied; interface context is unavailable.",
    );
  });

  it("withholds supplemental evidence from incomplete searches", async () => {
    const base = fakeClient([]);
    const client: SearchClient = {
      async search(request) {
        if (request.search.includes("adm_path_evidence("))
          return {
            rows: [{ _raw: "unfinished" }],
            warnings: ["partial capture"],
            errors: [],
          };
        if (request.search.includes("adm_path_trace_gnmi_context"))
          return {
            rows: [{ row_type: "gnmi_context" }],
            warnings: ["partial context"],
            errors: [],
          };
        return base.search(request);
      },
    };
    const result = await loadStandaloneTrace(
      client,
      { src: "10.30.40.25", dst: "10.20.30.40" },
      w,
    );
    expect(result.evidence).toEqual([]);
    expect(
      result.rows.map((row) => (row as { row_type: string }).row_type),
    ).toEqual(["observation"]);
    expect(result.warnings).toEqual([
      "Path evidence search was incomplete: partial capture",
      "gNMI interface context search was incomplete: partial context",
    ]);
  });

  it("returns only scoped observations and qualified identity", async () => {
    const requests: SearchRequest[] = [];
    const result = await loadStandaloneTrace(
      fakeClient(requests),
      { src: "win-client-01", dst: "10.20.30.40" },
      w,
    );
    expect(requests.map((q) => q.search)).toContain(
      "| `adm_path_trace(10.30.40.25,10.20.30.40,prod)`",
    );
    expect(requests.every((q) => q.earliest === "100")).toBe(true);
    expect(result.graph.nodes.map((n) => n.label)).toEqual([
      "win-client-01",
      "orders-db-01",
    ]);
    expect(result.topology.devices).toEqual([]);
    expect(result.evidence).toEqual([]);
    expect(result.rows).toHaveLength(1);
    const trace = assembleScopedTrace(
      result.addresses,
      result.graph,
      result.rows,
    ).trace;
    expect(trace.status).toBe("partial");
    expect(trace.hops).toHaveLength(1);
    expect(trace.hops[0].kind).toBe("gap");
    expect(
      trace.notes.some((note) => note.includes("counts are not combined")),
    ).toBe(true);
    expect(
      trace.notes.some((note) =>
        note.includes("2 observed records, including 1 drop"),
      ),
    ).toBe(true);
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

  it.each([
    {
      warnings: ["Splunk truncated this search; results could be incomplete."],
    },
    { truncated: { shown: 1, total: 2 } },
  ])(
    "stops before tracing if a name lookup is incomplete (%j)",
    async (completion) => {
      const requests: SearchRequest[] = [];
      const client: SearchClient = {
        async search(request) {
          requests.push(request);
          return {
            rows: [endpointRows[0]],
            warnings: [],
            errors: [],
            ...completion,
          };
        },
      };
      await expect(
        loadStandaloneTrace(
          client,
          { src: "win-client-01", dst: "10.20.30.40" },
          w,
        ),
      ).rejects.toThrow("Source lookup was incomplete; retry or enter an IP.");
      expect(requests.map(({ search }) => search)).toEqual([
        "| `adm_path_trace_resolve(win-client-01,prod)`",
      ]);
    },
  );

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
    expect(pathTraceResolveSearch("orders-db-01", "prod")).toBe(
      "| `adm_path_trace_resolve(orders-db-01,prod)`",
    );
  });

  it("filters scope and validity and rejects competing identities", () => {
    const row = {
      row_type: "endpoint",
      ip: "10.1.1.1",
      scope: "prod",
      scope_mapping_verified: 1,
      entity_id: "vm-a",
      valid_from: 0,
      valid_end: 300,
    };
    expect(
      qualifiedEndpointRows(
        [
          row,
          { ...row, scope: "other", entity_id: "vm-b" },
          { ...row, entity_id: "old", valid_end: 100 },
        ],
        "prod",
        100,
        200,
      ),
    ).toEqual([row]);
    expect(() =>
      qualifiedEndpointRows(
        [row, { ...row, entity_id: "vm-b" }],
        "prod",
        100,
        200,
      ),
    ).toThrow(/Multiple identities/);
    expect(() =>
      qualifiedEndpointRows(
        [row, { ...row, entity_id: "vm-b", valid_from: 150 }],
        "prod",
        100,
        200,
      ),
    ).toThrow(/Multiple identities/);
    expect(
      qualifiedEndpointRows(
        [{ ...row, scope_mapping_verified: 0 }],
        "prod",
        100,
        200,
      ),
    ).toEqual([]);
    expect(() => traceWindow("-1h", "now")).toThrow(/absolute/);
    expect(() => pathTraceResolveSearch("db")).toThrow(/scope/);
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
