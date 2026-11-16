import { describe, expect, it } from "vitest";
import { indexGraph, type Graph, type GraphEdge } from "../graph";
import { bundleSummary, computeLayout } from "../layout";
import { demoGraph } from "../provider";
import {
  indexTopology,
  resolveInventoryEndpoints,
  rowsToTopology,
} from "../topology";
import {
  inferLeafEgress,
  nameInterfacePair,
  type DeviceFlows,
} from "../data/deviceFlows";
import { inferLeafHopEgress } from "../data/pathTrace";

const graph = demoGraph("nxos");
const index = indexGraph(graph);
const declutter = { cardBundles: true, quiet: true } as const;

describe("card-pair bundling", () => {
  const rows = computeLayout(graph, index, "network");
  const cards = computeLayout(graph, index, "network", declutter);
  it("draws at most one line per card pair", () => {
    expect(cards.edges.length).toBeLessThan(rows.edges.length);
    const pairs = cards.edges.map((e) => {
      const a = cards.items.get(e.edge.source)!.groupId,
        b = cards.items.get(e.edge.target)!.groupId;
      return [a, b].sort().join("|");
    });
    expect(new Set(pairs).size).toBe(pairs.length);
    expect(cards.pills).toHaveLength(0);
  });
  it("keeps every drawn relationship as a member of some line", () => {
    const drawn = new Set(cards.edges.flatMap((e) => e.members));
    const routable = rows.edges
      .flatMap((e) => e.members)
      .filter((id) => {
        const e = index.edge.get(id)!;
        return (
          cards.items.get(e.source)!.groupId !==
          cards.items.get(e.target)!.groupId
        );
      });
    for (const id of routable) expect(drawn.has(id)).toBe(true);
  });
  it("hides inferred relationships only on request", () => {
    const inferred = graph.edges.filter((e) => e.confidence === "inferred");
    const hidden = computeLayout(graph, index, "network", {
      ...declutter,
      hideInferred: true,
    });
    const members = new Set(hidden.edges.flatMap((e) => e.members));
    for (const e of inferred) expect(members.has(e.id)).toBe(false);
    if (inferred.length) {
      const shown = new Set(cards.edges.flatMap((e) => e.members));
      expect(inferred.some((e) => shown.has(e.id))).toBe(true);
    }
  });
  it("marks all-inferred lines and badges mixed lines", () => {
    for (const r of cards.edges) {
      const conf = r.members.map((id) => index.edge.get(id)!.confidence);
      const n = conf.filter((c) => c === "inferred").length;
      expect(r.inferred === true).toBe(n === conf.length);
      expect(r.label).toBe(n && n < conf.length ? `+${n} inferred` : undefined);
    }
  });
  it("summarizes a bundle with link, record, and port counts", () => {
    const edge = (over: Partial<GraphEdge>): GraphEdge =>
      ({
        id: Math.random().toString(),
        source: "a",
        target: "b",
        relationship: "traffic_observation",
        confidence: "correlated",
        count: 1,
        ...over,
      }) as GraphEdge;
    expect(
      bundleSummary([
        edge({ records: 5, destination_port: 8080, transport: "tcp" }),
        edge({ records: 2, destination_port: 443, transport: "tcp" }),
        edge({ relationship: "calls", count: 3 }),
      ]),
    ).toEqual([
      "3 links · 3 traced spans · 7 records",
      "Ports 8080/tcp, 443/tcp",
    ]);
  });
});

describe("inventory endpoint resolution", () => {
  const base: Graph = {
    ...graph,
    nodes: [
      ...graph.nodes,
      {
        id: "network-endpoint:x",
        kind: "endpoint",
        endpoint_kind: "unresolved",
        label: "192.0.2.44",
        addresses: ["192.0.2.44"],
      },
    ],
  };
  const port = (mac: string, ip: string, vm = "node-vm-1") => ({
    row_type: "link",
    a_device: "vsphere:vc/vmm/VMware/dc1",
    b_device: `vm:${mac}`,
    b_device_name: vm,
    link_kind: "virtual_port",
    mac,
    ip,
    portgroup: "T1|AP1|EPG1",
  });
  const devices = [
    {
      row_type: "device",
      device_id: "vsphere:vc/vmm/VMware/dc1",
      name: "dc1",
      device_kind: "virtual_switch",
    },
  ];
  it("names an address bound to exactly one vNIC by IP and MAC", () => {
    const topo = indexTopology(
      rowsToTopology([...devices, port("00:50:56:00:00:01", "192.0.2.44")]),
    );
    const node = resolveInventoryEndpoints(base, topo).nodes.at(-1)!;
    expect(node).toMatchObject({
      id: "network-endpoint:x",
      label: "node-vm-1",
      endpoint_kind: "vm",
      attributes: { mac: "00:50:56:00:00:01", epg: "EPG1" },
    });
  });
  it("leaves an address claimed by two vNICs unresolved", () => {
    const topo = indexTopology(
      rowsToTopology([
        ...devices,
        port("00:50:56:00:00:01", "192.0.2.44"),
        port("00:50:56:00:00:02", "192.0.2.44", "other-vm"),
      ]),
    );
    expect(resolveInventoryEndpoints(base, topo)).toBe(base);
  });
  it("never resolves by name alone", () => {
    const topo = indexTopology(
      rowsToTopology([...devices, port("", "192.0.2.99", "192.0.2.44")]),
    );
    expect(resolveInventoryEndpoints(base, topo)).toBe(base);
  });
});

describe("device interface pairs", () => {
  const names = new Map([[9, "port-channel1"]]);
  it("omits an absent egress instead of showing ?", () => {
    expect(nameInterfacePair("ifIndex 9 > ?", names, false)).toBe(
      "port-channel1",
    );
    expect(nameInterfacePair("ifIndex 9 > ifIndex 0", names, false)).toBe(
      "port-channel1",
    );
    expect(nameInterfacePair("? > ifIndex 9", names, false)).toBe(
      "→ port-channel1",
    );
    expect(nameInterfacePair("? > ?", names, false)).toBe("");
  });
});

describe("leaf egress inference (ingress-only ACI NetFlow)", () => {
  // Field shapes as returned live by adm_device_inventory / adm_vsphere_topology(1).
  const topo = indexTopology(
    rowsToTopology([
      {
        row_type: "device",
        device_id: "vsphere:apic1/vmm/VMware/dc-vmm/vcenter",
        name: "vcenter",
        device_kind: "virtual_switch",
      },
      {
        row_type: "link",
        name: "00:50:56:95:88:B4",
        a_device: "vsphere:apic1/vmm/VMware/dc-vmm/vcenter",
        b_device: "vm:00:50:56:95:88:b4",
        b_device_name: "k8s-node-2",
        link_kind: "virtual_port",
        link_source: "aci_vmm",
        mac: "00:50:56:95:88:b4",
        ip: "192.0.2.4",
        vlan: "341",
        portgroup: "T|AP|EPG",
        attach_nodes: ["pod-1/node-101", "pod-1/node-102"],
        attach_interface: "vpc-1-22-UCS-FI",
      },
    ]),
  );
  const flows = (dst: string, interfaces: string[]): DeviceFlows => ({
    device: "leaf101",
    conversations: [
      {
        src: "192.0.2.3",
        dst,
        protocol: "tcp",
        flows: 1,
        interfaces,
        vlans: [],
        segments: [],
        sources: ["netflow"],
        blocked: false,
        drops: 0,
        permits: 0,
      },
    ],
    totals: { conversations: 1, flows: 1 },
    truncated: false,
    recordsCapped: false,
  });
  const leaf = (node: string) =>
    ({
      id: "fab1-leaf",
      name: "leaf",
      kind: "switch",
      aci_node: node,
    }) as never;
  it("labels the destination's attachment on this leaf as inferred", () => {
    const out = inferLeafEgress(
      flows("192.0.2.4", ["port-channel1"]),
      leaf("pod-1/node-101"),
      topo,
    );
    expect(out.conversations[0].interfaces).toEqual([
      "port-channel1 > vpc-1-22-UCS-FI (inferred)",
    ]);
  });
  it("points toward the fabric when the destination is on another leaf", () => {
    const out = inferLeafEgress(
      flows("192.0.2.4", ["port-channel1"]),
      leaf("pod-1/node-103"),
      topo,
    );
    expect(out.conversations[0].interfaces).toEqual([
      "port-channel1 > fabric (inferred)",
    ]);
  });
  it("keeps exported egress and unknown destinations unchanged", () => {
    for (const [dst, ifs] of [
      ["192.0.2.4", ["port-channel1 > Ethernet1/5"]],
      ["192.0.2.200", ["port-channel1"]],
    ] as const) {
      const input = flows(dst, [...ifs]);
      expect(
        inferLeafEgress(input, leaf("pod-1/node-101"), topo).conversations[0]
          .interfaces,
      ).toEqual(ifs);
    }
    const input = flows("192.0.2.4", ["port-channel1"]);
    expect(inferLeafEgress(input, undefined, topo)).toBe(input);
  });
});

describe("trace hop egress inference", () => {
  const topo = indexTopology(
    rowsToTopology([
      {
        row_type: "device",
        device_id: "fab1-leaf101",
        name: "leaf101",
        device_kind: "switch",
        aci_node: "pod-1/node-101",
      },
      {
        row_type: "device",
        device_id: "fab1-leaf103",
        name: "leaf103",
        device_kind: "switch",
        aci_node: "pod-1/node-103",
      },
    ]),
  );
  const port = {
    switch: "vds",
    vm: "vm:00:50:56:95:88:b4",
    mac: "00:50:56:95:88:b4",
    ip: "192.0.2.4",
    attach_nodes: ["pod-1/node-101", "pod-1/node-102"],
    attach_interface: "vpc-1-22-UCS-FI",
  };
  it("fills an ingress-only leaf hop from the destination attachment", () => {
    const hops = inferLeafHopEgress(
      [
        {
          kind: "switch",
          label: "leaf101",
          device: "fab1-leaf101",
          in: "port-channel1",
          evidence: "observed",
          sources: [],
          seen: [],
        },
        {
          kind: "switch",
          label: "leaf103",
          device: "fab1-leaf103",
          in: "port-channel3",
          evidence: "observed",
          sources: [],
          seen: [],
        },
        {
          kind: "switch",
          label: "leaf101",
          device: "fab1-leaf101",
          in: "a",
          out: "b",
          evidence: "observed",
          sources: [],
          seen: [],
        },
      ] as never,
      port,
      topo,
    );
    expect(hops.map((h) => h.out)).toEqual([
      "vpc-1-22-UCS-FI (inferred)",
      "fabric (inferred)",
      "b",
    ]);
  });
});
