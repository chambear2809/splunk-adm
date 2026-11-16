import { describe, expect, it } from "vitest";
import type { Graph } from "../graph";
import { indexTopology, rowsToTopology } from "../topology";
import {
  DEMO_PATH_TRACE_PAIR,
  demoGraph,
  demoPathTraceRows,
  demoTopology,
  demoVsphereTopology,
} from "./demoClient";
import {
  hopEvidenceText,
  fabricEvidenceRows,
  pathTraceObservers,
  tracePath,
  type TraceHop,
} from "./pathTrace";

const brief = (h: TraceHop) =>
  `${h.kind}:${h.label}:${h.evidence}${h.alternatives ? `[${h.alternatives.map((a) => a.label).join("/")}]` : ""}`;

describe("tracePath on the ACI demo with vSphere rows", () => {
  const graph = demoGraph("aci");
  const topology = indexTopology(demoVsphereTopology());
  const observers = pathTraceObservers(demoPathTraceRows());
  const fabricEvidence = fabricEvidenceRows(demoPathTraceRows());

  it("traces VM → VDS → leaf → spines → leaf → VDS → VM from APIC VMM and hvsAdj rows", () => {
    const t = tracePath({
      ...DEMO_PATH_TRACE_PAIR,
      graph,
      topology,
      observers,
    });
    expect(t.status).toBe("traced");
    expect(t.hops.map(brief)).toEqual([
      "endpoint:win-client-01:observed",
      "virtual_switch:vmm-shop:observed",
      "switch:leaf-103:observed",
      "switch:One of 2 spines:inferred[spine-201/spine-202]",
      "switch:leaf-102:inferred",
      "virtual_switch:vmm-shop:inferred",
      "endpoint:orders-db-01:observed",
    ]);
    const vds = t.hops[1];
    expect(vds.detail).toBe(
      "VDS · on esx-03 · portgroup shop|clients|win-clients · VLAN 1030",
    );
    expect(vds.out).toBe("vmnic2");
    expect(vds.sources).toEqual(["Stream NetFlow"]);
    expect(vds.seen).toEqual(["port 18 → port 14"]);
    expect(t.hops[2].in).toBe("Eth1/5");
    expect(t.hops[4].out).toBe("Eth1/6");
    expect(t.hops[5].out).toBe("vmnic2");
    expect(t.gaps).toEqual([]);
    expect(t.notes).toContain(
      "ACL log: drop at leaf-103 (1 drop) · blocked by the fabric",
    );
    expect(hopEvidenceText(vds)).toBe("Observed by Stream NetFlow");
    expect(hopEvidenceText(t.hops[3])).toBe("Inferred from topology");
  });

  it("narrows the spine hop to IS-IS + COOP qualified spines without marking it observed", () => {
    expect(
      fabricEvidence.filter((e) => e.kind === "isis_adjacency"),
    ).toHaveLength(5);
    const t = tracePath({
      ...DEMO_PATH_TRACE_PAIR,
      graph,
      topology,
      observers,
      fabricEvidence,
    });
    const spine = t.hops[3];
    expect(brief(spine)).toBe("switch:spine-201:inferred");
    expect(spine.support).toEqual(["ACI IS-IS adjacency", "ACI COOP endpoint"]);
    expect(spine.sources).toEqual([]);
    expect(spine.detail).toBe(
      "IS-IS adjacency up from leaf-103; COOP knows 00:50:56:AA:10:40 · ECMP, forwarding spine not observed",
    );
    expect(hopEvidenceText(spine)).toBe(
      "Inferred; supported by ACI IS-IS adjacency, ACI COOP endpoint",
    );
    // Without a COOP record for the destination no spine qualifies.
    const noCoop = tracePath({
      ...DEMO_PATH_TRACE_PAIR,
      graph,
      topology,
      fabricEvidence: fabricEvidence.filter((e) => e.kind !== "coop_endpoint"),
    });
    expect(brief(noCoop.hops[3])).toBe(
      "switch:One of 2 spines:inferred[spine-201/spine-202]",
    );
    expect(noCoop.hops[3].support).toBeUndefined();
    expect(noCoop.notes).toContain(
      "No spine has both an up IS-IS adjacency from the source leaf and a COOP record for the destination; spine candidates are topology-only.",
    );
  });

  it("parses only well-formed fabric evidence rows", () => {
    expect(
      fabricEvidenceRows([
        {
          row_type: "fabric_evidence",
          evidence_kind: "isis_adjacency",
          node: "pod-1/node-1",
          peer_node: "pod-1/node-2",
        },
        {
          row_type: "fabric_evidence",
          evidence_kind: "isis_adjacency",
          node: "leaf-1",
        },
        {
          row_type: "fabric_evidence",
          evidence_kind: "other",
          node: "pod-1/node-1",
        },
        { row_type: "observation", observer: "x" },
        null,
      ]),
    ).toEqual([
      {
        kind: "isis_adjacency",
        node: "pod-1/node-1",
        peerNode: "pod-1/node-2",
      },
    ]);
  });

  it("resolves endpoints by name and refuses unknown or identical ones", () => {
    const byName = tracePath({
      src: "win-client-01",
      dst: "orders-db-01",
      graph,
      topology,
    });
    expect(byName.hops.length).toBe(7);
    expect(byName.hops[1].evidence).toBe("inferred");
    expect(
      tracePath({ src: "10.0.0.250", dst: "10.20.30.40", graph, topology }),
    ).toMatchObject({ status: "unresolved", hops: [] });
    expect(
      tracePath({ src: "10.20.30.40", dst: "orders-db-01", graph, topology })
        .reason,
    ).toBe("Source and destination are the same endpoint.");
  });

  it("keeps the base ACI demo unchanged when no vSphere rows exist", () => {
    const base = tracePath({
      ...DEMO_PATH_TRACE_PAIR,
      graph,
      topology: indexTopology(demoTopology("aci")),
    });
    expect(base.hops.some((h) => h.kind === "virtual_switch")).toBe(false);
  });
});

// Shape of the live finding: both VMs on one VDS, attached to the same leaf vPC pair.
const vpcRows = [
  ...["101", "102"].map((n) => ({
    row_type: "device",
    device_id: `leaf${n}`,
    name: `leaf${n}`,
    device_kind: "switch",
    role: "leaf",
    aci_node: `pod-1/node-${n}`,
    mgmt_ip: n === "101" ? "10.110.5.2" : "10.110.5.3",
    sources: "aci",
  })),
  ...["201", "202"].map((n) => ({
    row_type: "device",
    device_id: `spine${n}`,
    name: `spine${n}`,
    device_kind: "switch",
    role: "spine",
    aci_node: `pod-1/node-${n}`,
    sources: "aci",
  })),
  ...["101", "102"].flatMap((l) =>
    ["201", "202"].map((sp) => ({
      row_type: "link",
      a_device: `leaf${l}`,
      a_interface: `eth1/${sp === "201" ? 49 : 50}`,
      b_device: `spine${sp}`,
      b_interface: `eth1/${l === "101" ? 1 : 2}`,
      link_source: "aci",
    })),
  ),
  {
    row_type: "device",
    device_id: "vsphere:apic/vmm/VMware/dom/vc",
    name: "dom",
    device_kind: "virtual_switch",
    switch_type: "vds",
    ipfix_observers: ["10.110.253.11", "10.110.253.13"],
    sources: "aci_vmm",
  },
  ...[
    ["hv-11", "esx-11", "10.110.253.11"],
    ["hv-13", "esx-13", "10.110.253.13"],
  ].map(([id, name, ip]) => ({
    row_type: "device",
    device_id: `vsphere:apic/${id}`,
    name,
    device_kind: "hypervisor",
    mgmt_ip: ip,
    parent_device: "vsphere:apic/vmm/VMware/dom/vc",
    sources: "aci_vmm",
  })),
  ...[
    ["10.110.96.7", "00:50:56:00:00:07", "hv-13", "vpc-1-21"],
    ["10.110.96.3", "00:50:56:00:00:03", "hv-11", "vpc-1-22"],
  ].map(([ip, mac, hv, pathep]) => ({
    row_type: "link",
    link_kind: "virtual_port",
    link_source: "aci_vmm",
    a_device: "vsphere:apic/vmm/VMware/dom/vc",
    b_device: `vm:${mac}`,
    b_device_name: `vm-${ip}`,
    hypervisor: `vsphere:apic/${hv}`,
    mac,
    ip,
    vlan: "341",
    attach_nodes: ["pod-1/node-101", "pod-1/node-102"],
    attach_interface: pathep,
  })),
];
const vpcGraph: Graph = {
  service: "",
  nodes: ["10.110.96.7", "10.110.96.3"].map((ip) => ({
    id: `vm:${ip}`,
    label: ip,
    kind: "endpoint",
    endpoint_kind: "vm",
    addresses: [ip],
  })),
  edges: [
    {
      id: "e1",
      source: "vm:10.110.96.7",
      target: "vm:10.110.96.3",
      relationship: "communicates_with",
      evidence: ["netflow"],
      confidence: "observed",
      count: 4,
      observers: [
        "netflow:10.110.253.13:ifIndex 5>ifIndex 9",
        "netflow:10.110.5.2:ifIndex 436248576>?",
      ],
    },
  ],
} as unknown as Graph;

describe("tracePath across one vPC pair", () => {
  it("narrows the vPC to the one leaf that observed, no spine, VDS observed only on the exporting host", () => {
    const t = tracePath({
      src: "10.110.96.7",
      dst: "10.110.96.3",
      graph: vpcGraph,
      topology: indexTopology(rowsToTopology(vpcRows)),
    });
    expect(t.hops.map(brief)).toEqual([
      "endpoint:10.110.96.7:observed",
      "virtual_switch:dom:observed",
      "gap:Uplink from esx-13 to the fabric not collected:gap",
      "switch:leaf101:observed",
      "gap:Uplink from esx-11 to the fabric not collected:gap",
      "virtual_switch:dom:inferred",
      "endpoint:10.110.96.3:observed",
    ]);
    expect(t.hops[3].device).toBe("leaf101");
    expect(t.hops[3].detail).toBe("ACI leaf · vPC peer leaf102 not seen");
    expect(t.hops[3].notSeen).toEqual([
      { device: "leaf102", label: "leaf102" },
    ]);
    expect(t.hops.some((h) => /spine/i.test(h.label))).toBe(false);
  });

  it("keeps both vPC leaves when both observed the flow (scenario B before the shut)", () => {
    const graph = {
      ...vpcGraph,
      edges: [
        {
          ...vpcGraph.edges[0],
          observers: [
            ...vpcGraph.edges[0].observers!,
            "netflow:10.110.5.3:ifIndex 436248577>?",
          ],
        },
      ],
    };
    const t = tracePath({
      src: "10.110.96.7",
      dst: "10.110.96.3",
      graph,
      topology: indexTopology(rowsToTopology(vpcRows)),
    });
    expect(t.hops[3].label).toBe("One of 2 leaves");
    expect(t.hops[3].alternatives?.map((a) => a.label)).toEqual([
      "leaf101",
      "leaf102",
    ]);
    expect(t.hops[3].notSeen).toBeUndefined();
  });

  it("keeps both vPC leaves when neither observed the flow", () => {
    const graph = {
      ...vpcGraph,
      edges: [
        {
          ...vpcGraph.edges[0],
          observers: ["netflow:10.110.253.13:ifIndex 5>ifIndex 9"],
        },
      ],
    };
    const t = tracePath({
      src: "10.110.96.7",
      dst: "10.110.96.3",
      graph,
      topology: indexTopology(rowsToTopology(vpcRows)),
    });
    expect(t.hops[3].label).toBe("One of 2 leaves");
    expect(t.hops[3].evidence).toBe("inferred");
  });

  it("narrows to the other member after its peer's port is shut (scenario B)", () => {
    const graph = {
      ...vpcGraph,
      edges: [
        {
          ...vpcGraph.edges[0],
          observers: [
            "netflow:10.110.253.13:ifIndex 5>ifIndex 9",
            "netflow:10.110.5.3:ifIndex 436248577>?",
          ],
        },
      ],
    };
    const t = tracePath({
      src: "10.110.96.7",
      dst: "10.110.96.3",
      graph,
      topology: indexTopology(rowsToTopology(vpcRows)),
    });
    expect(t.hops[3].label).toBe("leaf102");
    expect(t.hops[3].evidence).toBe("observed");
    expect(t.hops[3].notSeen?.map((a) => a.label)).toEqual(["leaf101"]);
  });

  it("routes each host through its fabric interconnects (hvsAdj) to the leaf vPC", () => {
    const fi = (n: string) => `vsphere:apic/lldp/90:eb:50:a2:da:${n}`;
    const rows = [
      ...vpcRows,
      ...[
        ["8a", "FI-A", "10.110.2.251"],
        ["8b", "FI-B", "10.110.2.252"],
      ].map(([n, name, ip]) => ({
        row_type: "device",
        device_id: fi(n),
        name,
        device_kind: "network_device",
        mgmt_ip: ip,
        sources: "aci_hvsAdj",
      })),
      ...["hv-11", "hv-13"].flatMap((hv, h) =>
        ["8a", "8b"].map((n, i) => ({
          row_type: "link",
          link_kind: "uplink",
          link_source: "aci_hvsAdj",
          a_device: "vsphere:apic/vmm/VMware/dom/vc",
          hypervisor: `vsphere:apic/${hv}`,
          b_device: fi(n),
          b_interface: `Veth${800 + h * 10 + i}`,
          binding: "hvsAdj_lldp",
        })),
      ),
      ...[
        ["8a", "pod-1/node-101", "eth1/21"],
        ["8a", "pod-1/node-102", "eth1/21"],
        ["8b", "pod-1/node-101", "eth1/22"],
        ["8b", "pod-1/node-102", "eth1/22"],
      ].map(([n, leaf, port]) => ({
        row_type: "link",
        link_kind: "uplink",
        link_source: "aci_lldpAdjEp",
        a_device: fi(n),
        b_device: leaf,
        b_interface: port,
        binding: "lldp_chassis_mac",
      })),
    ];
    const topology = indexTopology(rowsToTopology(rows));
    const t = tracePath({
      src: "10.110.96.7",
      dst: "10.110.96.3",
      graph: vpcGraph,
      topology,
    });
    expect(t.hops.map(brief)).toEqual([
      "endpoint:10.110.96.7:observed",
      "virtual_switch:dom:observed",
      "switch:One of 2 switches:inferred[FI-A/FI-B]",
      "switch:leaf101:observed",
      "switch:One of 2 switches:inferred[FI-A/FI-B]",
      "virtual_switch:dom:inferred",
      "endpoint:10.110.96.3:observed",
    ]);
    expect(t.gaps).toEqual([]);
    expect(t.hops[2].detail).toBe("FI-A, FI-B · host uplinks");
    // Fabric interconnects are attachment hops, never transit between leaves.
    expect(topology.adjacency.get("leaf101")?.map((x) => x.to)).toEqual([
      "spine201",
      "spine202",
    ]);
  });

  it("finds an endpoint present only in virtual switch inventory", () => {
    const graph = { ...vpcGraph, nodes: [vpcGraph.nodes[0]], edges: [] };
    const t = tracePath({
      src: "10.110.96.7",
      dst: "vm-10.110.96.3",
      graph,
      topology: indexTopology(rowsToTopology(vpcRows)),
    });
    expect(t.dst.virtualPort?.hypervisor).toBe("vsphere:apic/hv-11");
    expect(t.hops.at(-1)?.label).toBe("vm-10.110.96.3");
    expect(t.notes).toContain(
      "No conversation between these endpoints was collected; every hop is inferred from topology.",
    );
  });
});
