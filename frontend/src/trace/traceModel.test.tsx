import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import {
  DEMO_PATH_TRACE_PAIR,
  demoDeviceFlows,
  demoGraph,
  demoPathTraceRows,
  demoTopology,
  demoVsphereTopology,
} from "../data/demoClient";
import type { TraceHop } from "../data/pathTrace";
import { indexTopology } from "../topology";
import {
  blockedHops,
  collapseHops,
  epochLabel,
  findDevices,
  flowTokens,
  hopIcon,
  mergeDeviceFlows,
  portProtoLabel,
  traceHighlight,
  traceSummary,
  traceTopology,
} from "./traceModel";
import { assembleTrace, traceAddress } from "./usePathTrace";
import { TraceView } from "./TraceView";

const demoTrace = () =>
  assembleTrace(
    DEMO_PATH_TRACE_PAIR,
    demoGraph("aci"),
    demoVsphereTopology(),
    demoPathTraceRows(),
  );

describe("trace summary", () => {
  it("sums observation rows and keeps proto/port", () => {
    const s = traceSummary(demoPathTraceRows());
    expect(s.records).toBe(2);
    expect(s.bytes).toBe(60);
    expect(portProtoLabel(s.protocols, s.ports)).toBe("tcp/5432");
    expect(portProtoLabel([], [])).toBeUndefined();
    expect(portProtoLabel(["tcp"], ["443", "80"])).toBe("tcp/443 +1");
  });

  it("ignores malformed and non-observation rows", () => {
    const s = traceSummary([
      null,
      "x",
      { row_type: "endpoint", records: "9" },
      { row_type: "observation", records: "-3", bytes: "nan" },
      {
        row_type: "observation",
        records: "4",
        flow_source: "netflow",
        last_seen: "1791374220",
      },
    ]);
    expect(s.records).toBe(4);
    expect(s.bytes).toBeUndefined();
    expect(s.lastSeenBySource.get("Stream NetFlow")).toBe(1791374220);
  });
});

describe("demo trace presentation", () => {
  it("places icons, the ACL drop and the map highlight", () => {
    const { trace, topo } = demoTrace();
    expect(trace.hops.map((h) => hopIcon(h, topo).kind)).toEqual([
      "VM",
      "VDS",
      "Leaf",
      "Spine",
      "Leaf",
      "VDS",
      "VM",
    ]);
    const blocked = blockedHops(trace, topo);
    expect([...blocked.keys()]).toEqual([2]);
    expect(blocked.get(2)).toEqual({
      kind: "aci",
      services: ["tcp/5432"],
      reasons: [],
    });
    const lit = traceHighlight(trace);
    expect(lit.nodes.has("vm:prod/10.30.40.25")).toBe(true);
    expect(lit.nodes.has("spine-201")).toBe(true);
    expect(lit.edges.size).toBe(1);
  });

  it("renders labels, badges only for inferred and blocked hops", () => {
    const done = { status: "done" as const, ...demoTrace() };
    const html = renderToStaticMarkup(
      <TraceView request={DEMO_PATH_TRACE_PAIR} result={done} />,
    );
    expect(html).toContain("win-client-01 → orders-db-01");
    expect(html).toContain("tcp/5432");
    expect(html).toContain("2 records");
    expect(html).toContain("Traced");
    // IS-IS adjacency and COOP evidence narrow the ECMP spines (still inferred).
    expect(html).toContain("IS-IS adjacency up from leaf-103");
    expect(html).toContain("Eth1/5");
    expect(html.match(/atlas-hop-badge inferred/g)).toHaveLength(3);
    expect(html.match(/atlas-hop-badge blocked/g)).toHaveLength(1);
    expect(html).not.toContain("Observed");
  });

  it("resolves names to addresses for the live search", () => {
    const topo = indexTopology(demoVsphereTopology());
    expect(traceAddress("orders-db-01", demoGraph("aci"), topo)).toBe(
      "10.20.30.40",
    );
    expect(traceAddress("10.1.1.1", demoGraph("aci"), topo)).toBe("10.1.1.1");
    expect(traceAddress("nobody", demoGraph("aci"), topo)).toBeUndefined();
  });

  it("merges only the pair's vSphere rows into inventory", () => {
    const base = demoTopology("aci");
    expect(traceTopology(base, demoPathTraceRows())).toBe(base);
    const merged = traceTopology(base, [
      {
        row_type: "device",
        device_id: "leaf-103",
        name: "leaf-103",
        device_kind: "switch",
        sources: "aci",
      },
      {
        row_type: "device",
        device_id: "fi-a",
        name: "fi-a",
        device_kind: "network_device",
        sources: "ucs",
      },
    ]);
    expect(merged.devices.length).toBe(base.devices.length + 1);
  });
});

describe("collapseHops", () => {
  const hop = (label: string, evidence: TraceHop["evidence"] = "inferred") =>
    ({ kind: "switch", label, evidence, sources: [], seen: [] }) as TraceHop;
  it("keeps short paths whole", () => {
    const hops = "abcdefg".split("").map((l) => hop(l));
    expect(collapseHops(hops, false).every((i) => i.type === "hop")).toBe(true);
  });
  it("collapses long middles but never gaps", () => {
    const hops = "abcdefghij".split("").map((l) => hop(l));
    hops[5] = hop("gap", "gap");
    const items = collapseHops(hops, false);
    expect(
      items.map((i) => (i.type === "more" ? `+${i.hops.length}` : i.hop.label)),
    ).toEqual(["a", "b", "+3", "gap", "+2", "i", "j"]);
    expect(collapseHops(hops, true)).toHaveLength(10);
  });
});

describe("device lookup", () => {
  const topo = demoVsphereTopology();
  it("finds devices by name, IP, serial and DN", () => {
    expect(findDevices("leaf-103", topo).map((d) => d.id)).toEqual([
      "leaf-103",
    ]);
    expect(findDevices("192.0.2.103", topo)[0]?.id).toBe("leaf-103");
    expect(findDevices("FDO26410A03", topo)[0]?.id).toBe("leaf-103");
    expect(findDevices("topology/pod-1/node-103/sys", topo)[0]?.id).toBe(
      "leaf-103",
    );
    expect(findDevices("esx-03", topo)[0]?.mgmt_ip).toBe("192.0.2.73");
    expect(findDevices("192.0.2.73", topo).map((d) => d.name)).toEqual([
      "esx-03",
    ]);
    expect(findDevices("", topo)).toEqual([]);
  });
  it("maps devices to adm_device_flows tokens", () => {
    const [leaf] = findDevices("leaf-103", topo);
    expect(flowTokens(leaf)).toEqual(["pod-1/node-103", "192.0.2.103"]);
    const [vds] = findDevices("vmm-shop", topo);
    expect(flowTokens(vds)).toEqual(["192.0.2.71", "192.0.2.73"]);
  });
  it("merges flows across tokens without double counting", () => {
    const a = demoDeviceFlows("192.0.2.73");
    const merged = mergeDeviceFlows("vds", [a, a, demoDeviceFlows("none")]);
    expect(merged.conversations).toHaveLength(1);
    expect(merged.totals.conversations).toBe(1);
    expect(merged.totals.flows).toBe(2);
    expect(epochLabel(1791374220)).toBe("2026-10-07 11:57");
    expect(epochLabel(undefined)).toBeUndefined();
  });
});
