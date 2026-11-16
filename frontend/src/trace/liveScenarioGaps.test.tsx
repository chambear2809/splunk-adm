import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import vdsFiVpc from "../../../fixtures/path-trace-vds-fi-vpc.json";
import { pathTraceDrops } from "../data/pathTrace";
import { emptyTopology } from "../topology";
import { endpointGraph } from "./standaloneTrace";
import {
  blockedHops,
  blockedLabel,
  openServices,
  portProtoLabel,
  traceSummary,
} from "./traceModel";
import { TraceView } from "./TraceView";
import { assembleTrace } from "./usePathTrace";

/**
 * Regressions for the gaps found by the 2026-11-04 live lab scenarios
 * (docs/operators/LIVE_SCENARIOS.md), on the live-shaped adm_path_trace rows of
 * fixtures/path-trace-vds-fi-vpc.json: 192.0.2.3 (EPG1, VLAN 341, host .11)
 * to 198.51.100.2 (EPG2, VLAN 342, host .14) through UCS FIs to a vPC pair.
 */
type Row = Record<string, unknown>;
const base = vdsFiVpc.rows as Row[];
const pair = { src: "192.0.2.3", dst: "198.51.100.2" };
const LEAF101 = "192.0.2.252";

/** adm_path_trace now names the listener side of every record. */
const withServices = (rows: Row[]) =>
  rows.map((r) =>
    r.row_type === "observation" && r.flow_source === "netflow"
      ? {
          ...r,
          services: ["tcp/47001", "tcp/47003"],
          client_ports: ["47110", "47111", "47112", "47113"],
        }
      : r,
  );
const aclDrop = (node: string, drops: number): Row => ({
  row_type: "observation",
  observer: `aci_acllog:pod-1/${node}`,
  observer_device: `pod-1/${node}`,
  flow_source: "aci_acllog",
  direction: "forward",
  records: String(drops),
  drops: String(drops),
  permits: "0",
  protocols: "tcp",
  dest_ports: "47003",
  services: "tcp/47003",
  drop_services: "tcp/47003",
  client_ports: ["47110", "47111"],
  first_seen: "1793806188",
  last_seen: "1793806580",
});
const run = (rows: Row[], p: { src: string; dst: string } = pair) =>
  assembleTrace(p, endpointGraph(rows, [p.src, p.dst]), emptyTopology(), rows);

describe("gap 2: deep-linked traces show the enforcing leaf as Blocked", () => {
  // Scenario C: atlas-deny-47003 at node-102 only after leaf101 po2 is shut.
  const rows = [
    ...withServices(base).filter((r) => !String(r.observer).includes(LEAF101)),
    aclDrop("node-102", 14),
  ];

  it("reads drop rows into the standalone trace (no graph edges)", () => {
    expect(pathTraceDrops(rows)).toEqual([
      {
        source: "aci_acllog",
        device: "pod-1/node-102",
        services: ["tcp/47003"],
        reasons: [],
        records: 14,
      },
    ]);
    const { trace } = run(rows);
    expect(trace.conversations).toEqual([]);
    expect(trace.drops).toHaveLength(1);
  });

  it("badges the leaf with the per-port verdict while tcp/47001 forwards", () => {
    const { trace, topo, summary } = run(rows);
    const blocked = blockedHops(trace, topo);
    expect([...blocked.keys()]).toEqual([3]);
    expect(trace.hops[3].label).toBe("fab1-leaf102");
    const verdict = blocked.get(3)!;
    expect(verdict.kind).toBe("aci");
    expect(blockedLabel(verdict)).toBe("Blocked tcp/47003");
    expect(openServices(summary, blocked)).toEqual(["tcp/47001"]);
    const html = renderToStaticMarkup(
      <TraceView
        request={pair}
        result={{ status: "done", trace, topo, summary }}
      />,
    );
    expect(html).toContain("Blocked tcp/47003 (ACI contract)");
    expect(html).toContain("tcp/47001 not blocked");
    expect(html.match(/atlas-hop-badge blocked/g)).toHaveLength(1);
  });

  it("marks a still-ambiguous vPC hop blocked when the drop is on a member", () => {
    const { trace, topo } = run([
      ...withServices(base),
      aclDrop("node-102", 4),
    ]);
    expect(trace.hops[3].label).toBe("One of 2 leaves");
    expect([...blockedHops(trace, topo).keys()]).toEqual([3]);
  });

  it("finds no drop when none was logged", () => {
    const { trace, topo } = run(withServices(base));
    expect(blockedHops(trace, topo).size).toBe(0);
  });
});

describe("gap 3: the vPC hop narrows to the observing member", () => {
  it("shows leaf102 observed and leaf101 not seen (scenario B)", () => {
    const rows = base.filter((r) => !String(r.observer).includes(LEAF101));
    const hop = run(rows).trace.hops[3];
    expect(hop.label).toBe("fab1-leaf102");
    expect(hop.evidence).toBe("observed");
    expect(hop.alternatives).toBeUndefined();
    expect(hop.notSeen?.map((a) => a.label)).toEqual(["fab1-leaf101"]);
    expect(hop.in).toBe("port-channel1");
  });

  it("keeps One of 2 leaves when both members observed", () => {
    expect(run(base).trace.hops[3].label).toBe("One of 2 leaves");
  });
});

describe("gap 4: same host and VDS segment is VM → VDS → VM", () => {
  // A second VM on host .11 in the same portgroup and VLAN (scenario F2).
  const peer = "192.0.2.4";
  const rows: Row[] = [
    ...base.filter((r) => r.row_type !== "observation"),
    {
      ...base.find((r) => r.link_kind === "virtual_port" && r.ip === pair.src)!,
      b_device: "vm:00:50:56:00:00:04",
      b_device_name: "k8s-vm-02",
      mac: "00:50:56:00:00:04",
      ip: peer,
    },
    {
      row_type: "observation",
      observer: "netflow:203.0.113.11:ifIndex 9>ifIndex 10",
      observer_device: "203.0.113.11",
      flow_source: "netflow",
      direction: "forward",
      records: "12",
      protocols: "tcp",
      dest_ports: "4240",
      services: "tcp/4240",
    },
  ];
  const p = { src: pair.src, dst: peer };

  it("drops the inferred fabric interconnect hop", () => {
    const { trace } = run(rows, p);
    expect(trace.hops.map((h) => [h.kind, h.label])).toEqual([
      ["endpoint", "k8s-vm-01"],
      ["virtual_switch", "vmm-dc1"],
      ["endpoint", "k8s-vm-02"],
    ]);
    expect(trace.notes).toContain(
      "Both endpoints share one host and virtual switch segment.",
    );
  });

  it("goes through the fabric when a leaf observed the pair", () => {
    const routed = [
      ...rows,
      {
        row_type: "observation",
        observer: `netflow:${LEAF101}:ifIndex 369098753>?`,
        observer_device: LEAF101,
        flow_source: "netflow",
        direction: "forward",
        records: "3",
        protocols: "tcp",
        dest_ports: "4240",
      },
    ];
    const hops = run(routed, p).trace.hops;
    expect(hops.map((h) => h.label)).toContain("fab1-leaf101");
    expect(hops.find((h) => h.label === "fab1-leaf101")?.evidence).toBe(
      "observed",
    );
    expect(hops.some((h) => h.label === "One of 2 switches")).toBe(true);
  });
});

describe("gap 6: Kubernetes drops at the Cilium node", () => {
  // Pods on two Kubernetes nodes that are the two VMs of the fixture.
  const podA = "10.244.1.10",
    podB = "10.244.2.20";
  const pods: Row[] = [
    [podA, "web-1", "k8s-node-1"],
    [podB, "api-1", "k8s-node-2"],
  ].map(([ip, name, node]) => ({
    row_type: "endpoint",
    ip,
    entity_kind: "pod",
    entity_name: name,
    cluster: "lab",
    namespace: "shop",
    node,
    scope: "lab",
  }));
  const nodes: Row[] = [
    [pair.src, "k8s-node-1"],
    [pair.dst, "k8s-node-2"],
  ].map(([ip, name]) => ({
    row_type: "endpoint",
    trace_role: "pod_node",
    ip,
    entity_kind: "k8s_node",
    entity_name: name,
    node: name,
    cluster: "lab",
    scope: "lab",
  }));
  const hubble = (verdict: "drop" | "forward"): Row => ({
    row_type: "observation",
    observer: "hubble:k8s-node-2",
    observer_device: "k8s-node-2",
    flow_source: "hubble",
    direction: "forward",
    records: "5",
    drops: verdict === "drop" ? "5" : "0",
    protocols: "tcp",
    dest_ports: "8080",
    services: "tcp/8080",
    client_ports: ["41000", "41002"],
    ...(verdict === "drop"
      ? { drop_services: "tcp/8080", drop_reasons: "POLICY_DENIED" }
      : {}),
    src_pods: "shop/web-1",
    dst_pods: "shop/api-1",
  });
  const rows = (verdict: "drop" | "forward") => [
    ...base.filter(
      (r) => r.row_type !== "observation" && r.row_type !== "endpoint",
    ),
    ...pods,
    ...nodes,
    hubble(verdict),
  ];
  const p = { src: podA, dst: podB };

  it("places pods behind their nodes and the nodes on their VM vNICs", () => {
    const { trace } = run(rows("forward"), p);
    expect(trace.hops.map((h) => [h.kind, h.label])).toEqual([
      ["endpoint", "web-1"],
      ["host", "k8s-node-1"],
      ["virtual_switch", "vmm-dc1"],
      ["switch", "One of 2 switches"],
      ["switch", "One of 2 leaves"],
      ["switch", "One of 2 switches"],
      ["virtual_switch", "vmm-dc1"],
      ["host", "k8s-node-2"],
      ["endpoint", "api-1"],
    ]);
    expect(trace.hops[7].evidence).toBe("observed");
    expect(trace.hops[7].sources).toEqual(["Hubble"]);
  });

  it("renders Blocked (Kubernetes policy) at the node, not at a leaf", () => {
    const { trace, topo, summary } = run(rows("drop"), p);
    const blocked = blockedHops(trace, topo);
    expect([...blocked.keys()]).toEqual([7]);
    expect(blocked.get(7)).toEqual({
      kind: "k8s",
      services: ["tcp/8080"],
      reasons: ["POLICY_DENIED"],
    });
    const html = renderToStaticMarkup(
      <TraceView
        request={p}
        result={{ status: "done", trace, topo, summary }}
      />,
    );
    expect(html).toContain("Kubernetes policy");
    expect(html).not.toContain("ACI contract");
  });
});

describe("gap 8: trace ports are service ports", () => {
  it("summarizes listener ports and keeps client ports for the detail", () => {
    const s = traceSummary(withServices(base));
    expect(s.ports).toEqual(["47001", "47003"]);
    expect(s.services).toEqual(["tcp/47001", "tcp/47003"]);
    expect(s.clientPorts).toEqual(["47110", "47111", "47112", "47113"]);
    expect(portProtoLabel(s.protocols, s.ports)).toBe("tcp/47001 +1");
  });

  it("drops reverse-direction client ports from rows without services", () => {
    // The fixture rows predate the services field.
    const s = traceSummary(base);
    expect(s.ports).toEqual(["47001", "47003"]);
    expect(s.clientPorts).toEqual([]);
  });

  it("shows client ports only in the endpoint detail", () => {
    const { trace, topo, summary } = run(withServices(base));
    const html = renderToStaticMarkup(
      <TraceView
        request={pair}
        result={{ status: "done", trace, topo, summary }}
      />,
    );
    expect(html).toContain("tcp/47001 +1");
    expect(html).not.toContain("47110");
  });
});
