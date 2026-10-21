import { describe, expect, it } from "vitest";
import topologyRows from "../../fixtures/demo-topology.json";
import {
  indexGraph,
  type Graph,
  type GraphEdge,
  type GraphNode,
} from "./graph";
import { demoGraph, demoTopology } from "./provider";
import {
  buildPath,
  choiceExplanation,
  deviceKindLabel,
  deviceSummaries,
  edgeDeviceContext,
  emptyTopology,
  indexTopology,
  interfaceKey,
  interfaceLabel,
  observationsByDevice,
  parseObserver,
  rowsToTopology,
  deviceName,
  nodeDeviceContext,
  resolveDevice,
} from "./topology";

const graph = demoGraph("nxos");
const index = indexGraph(graph);
const topo = indexTopology(demoTopology("nxos"));
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
    expect(t.warnings.some((w) => /ifIndex/.test(w))).toBe(true);
  });
  it("keeps cluster-qualified Kubernetes inventory hosts distinct from switches", () => {
    const t = rowsToTopology([
      {
        row_type: "device",
        device_id: "node:cilium-aci-east/worker-01",
        name: "worker-01",
        device_kind: "host",
        cluster: "cilium-aci-east",
        sources: ["kubelet"],
      },
    ]);
    expect(t.devices[0]).toMatchObject({
      kind: "host",
      cluster: "cilium-aci-east",
    });
    expect(deviceKindLabel(t.devices[0].kind, t.devices[0].cluster)).toBe(
      "Kubernetes host · cilium-aci-east",
    );
  });
  it("preserves network-client freshness and attachment evidence without making it a route", () => {
    const clientId = "network_client:client-a";
    const switchId = "switch:campus-a";
    const t = rowsToTopology([
      {
        row_type: "device",
        device_id: clientId,
        name: "02:61:00:00:00:20",
        device_kind: "network_client",
        device_authority: '["org-a","network-a"]',
        native_device_id: "02:61:00:00:00:20",
        source_time: "1780000000",
        source_time_status: "stale",
        history_coverage: "unconfirmed",
        received_time: "1780000005",
        latest_received_time: "1780000010",
        attachment_status: "observed_snapshot",
        attachment_basis: "catalyst_client_snapshot",
        mapping_status: "mapped",
        scope: "campus-a",
        sources: ["catalyst_client_snapshot"],
      },
      {
        row_type: "device",
        device_id: switchId,
        name: "access-1",
        device_kind: "switch",
      },
      {
        row_type: "link",
        a_device: clientId,
        b_device: switchId,
        link_kind: "physical",
        link_source: "catalyst_client_snapshot",
      },
      {
        row_type: "device",
        device_id: "sdwan_router:tloc-a",
        name: "SD-WAN TLOC 192.0.2.10 (public-internet)",
        device_kind: "router",
        evidence_kind: "observed_overlay_context",
        overlay_peer_system_ip: "192.0.2.11",
        overlay_peer_color: "mpls",
        overlay_protocol: "ipsec",
      },
    ]);
    expect(t.devices[0]).toMatchObject({
      kind: "network_client",
      mapping_status: "mapped",
      attachment_status: "observed_snapshot",
      attachment_basis: "catalyst_client_snapshot",
      source_time: "1780000000",
      source_time_status: "stale",
      history_coverage: "unconfirmed",
      received_time: "1780000005",
      latest_received_time: "1780000010",
    });
    expect(deviceKindLabel(t.devices[0].kind)).toBe("Network client");
    expect(t.devices[2]).toMatchObject({
      kind: "router",
      evidence_kind: "observed_overlay_context",
      overlay_peer_system_ip: "192.0.2.11",
      overlay_protocol: "ipsec",
    });
    expect(indexTopology(t).adjacency.size).toBe(0);
  });
  it.each([
    ["not an array", { rows: [] }],
    ["unknown row type", [{ row_type: "router" }]],
    [
      "unknown device kind",
      [{ row_type: "device", device_id: "unknown:1", device_kind: "edge" }],
    ],
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
  it("does not choose an arbitrary LLDP attachment or parallel link port", () => {
    const links = [
      {
        a_device: "leaf-a",
        a_interface: "Eth1/1",
        b_device: "worker-1",
        source: "lldp" as const,
      },
      {
        a_device: "leaf-b",
        a_interface: "Eth1/2",
        b_device: "worker-1",
        source: "lldp" as const,
      },
      {
        a_device: "leaf-a",
        a_interface: "Eth1/3",
        b_device: "leaf-b",
        b_interface: "Eth1/4",
        source: "cdp" as const,
      },
      {
        a_device: "leaf-a",
        a_interface: "Eth1/5",
        b_device: "leaf-b",
        b_interface: "Eth1/6",
        source: "cdp" as const,
      },
    ];
    for (const ordered of [links, [...links].reverse()]) {
      const result = indexTopology({ ...emptyTopology(), links: ordered });
      expect(result.lldpHost.has("worker-1")).toBe(false);
      // Endpoints without inventory identities are retained as gaps, never
      // inserted into physical adjacency under an unqualified alias.
      expect(result.adjacency.size).toBe(0);
    }
  });
  it("does not overwrite colliding device aliases and keeps typed nonphysical links out of paths", () => {
    const devices = [
      {
        id: "catalyst:org-a:leaf-a",
        name: "leaf-a",
        kind: "switch" as const,
        sources: [],
        aliases: ["shared-name"],
        mgmt_ip: "192.0.2.10",
      },
      {
        id: "meraki:org-b:leaf-b",
        name: "leaf-b",
        kind: "switch" as const,
        sources: [],
        aliases: ["shared-name"],
        mgmt_ip: "192.0.2.10",
      },
      {
        id: "catalyst:org-a:router-a",
        name: "router-a",
        kind: "router" as const,
        sources: [],
      },
      {
        id: "catalyst:org-a:ap-a",
        name: "AP-1",
        kind: "access_point" as const,
        sources: [],
      },
    ];
    const indexed = indexTopology({
      ...emptyTopology(),
      devices,
      links: [
        {
          a_device: devices[0].id,
          b_device: devices[1].id,
          source: "inventory",
          kind: "overlay_context",
        },
        {
          a_device: devices[0].id,
          b_device: devices[1].id,
          source: "inventory",
          kind: "traffic_observation",
        },
        {
          a_device: devices[0].id,
          b_device: devices[1].id,
          source: "cdp",
          kind: "physical",
        },
      ],
    });
    expect(indexed.byKey.has("shared-name")).toBe(false);
    expect(indexed.byIp.has("192.0.2.10")).toBe(false);
    expect(indexed.ambiguousKeys.has("shared-name")).toBe(true);
    expect(deviceName("shared-name", indexed)).toEqual({
      name: "shared-name",
      secondary: "Ambiguous alias",
    });
    expect(indexed.adjacency.get(devices[0].id.toLowerCase())).toEqual([
      { to: devices[1].id.toLowerCase(), out: undefined, in: undefined },
    ]);
    const withoutPhysical = indexTopology({
      ...emptyTopology(),
      devices,
      links: [
        {
          a_device: devices[0].id,
          b_device: devices[1].id,
          source: "inventory",
          kind: "overlay_context",
        },
      ],
    });
    expect(withoutPhysical.adjacency.size).toBe(0);
    expect(withoutPhysical.byKey.get("ap-1")?.kind).toBe("access_point");
    expect(withoutPhysical.byKey.get("router-a")?.kind).toBe("router");
  });
  it("counts connections within aggregated inferred evidence", () => {
    const base = conv("frontend-7d9c6b5f4-x2k8p", "checkout-5f8b9c7d6-m4n7q");
    const text = choiceExplanation(
      {
        id: base.target,
        label: "backend",
        state: "observed",
        edges: [
          {
            ...base,
            confidence: "observed",
            handoff_basis: "hubble_client_tuple",
            count: 2,
          },
          {
            ...base,
            confidence: "inferred",
            handoff_basis: "time_inferred",
            count: 37,
          },
        ],
      },
      { clients: [] },
    );
    expect(text).toContain("37 more connections inferred from timing");
  });
  it("normalizes ethX/Y, EthX/Y and EthernetX/Y to one key", () => {
    expect(interfaceKey("eth1/11")).toBe(interfaceKey("Ethernet1/11"));
    expect(interfaceKey("Eth1/11")).toBe(interfaceKey("ethernet1/11"));
    expect(interfaceKey("Ethernet1/1/2")).toBe("ethernet1/1/2");
    expect(interfaceLabel("Ethernet1/49")).toBe("Eth1/49");
    expect(interfaceLabel("inside")).toBe("inside");
  });
});

describe("source-qualified topology resolution", () => {
  const digest = (n: string) => n.repeat(64).slice(0, 64);
  const device = (
    id: string,
    name: string,
    scope: string,
    cluster: string,
    authority: string,
    sources: string[] = ["aci_topSystem"],
    extra: Record<string, unknown> = {},
  ) => ({
    id,
    name,
    kind: "switch" as const,
    sources,
    scope,
    cluster,
    mapping_status: "mapped",
    device_authority: authority,
    aliases: ["shared-leaf"],
    ...extra,
  });

  it("resolves duplicate aliases only with matching scope and optional cluster/authority", () => {
    const aci = device(
      `aci:${digest("a")}`,
      "leaf-1",
      "campus",
      "aci-east",
      "apic-a",
    );
    const nxos = device(
      `nxos:${digest("b")}`,
      "leaf-1",
      "campus",
      "nxos-west",
      "collector-b",
      ["nxos"],
    );
    const index = indexTopology({ ...emptyTopology(), devices: [aci, nxos] });
    expect(resolveDevice("shared-leaf", index)).toBeUndefined();
    expect(
      resolveDevice("shared-leaf", index, { cluster: "aci-east" }),
    ).toBeUndefined();
    expect(
      resolveDevice("shared-leaf", index, {
        scope: "campus",
        cluster: "aci-east",
        authority: "apic-a",
        families: ["aci_topSystem"],
      })?.id,
    ).toBe(aci.id);
    expect(
      resolveDevice("shared-leaf", index, {
        scope: "campus",
        cluster: "nxos-west",
        authority: "collector-b",
        families: ["nxos"],
      })?.id,
    ).toBe(nxos.id);
    expect(
      resolveDevice("shared-leaf", index, {
        scope: "other",
        cluster: "aci-east",
      }),
    ).toBeUndefined();
  });

  it("rejects duplicate aliases within the same scope and canonical IDs with conflicting context", () => {
    const a = device(
      `aci:${digest("c")}`,
      "leaf-a",
      "campus",
      "aci-east",
      "apic-a",
    );
    const b = device(
      `aci:${digest("d")}`,
      "leaf-b",
      "campus",
      "aci-east",
      "apic-a",
    );
    const index = indexTopology({ ...emptyTopology(), devices: [a, b] });
    expect(
      resolveDevice("shared-leaf", index, {
        scope: "campus",
        cluster: "aci-east",
      }),
    ).toBeUndefined();
    expect(
      resolveDevice(a.id, index, { scope: "campus", cluster: "aci-west" }),
    ).toBeUndefined();
    expect(
      resolveDevice(a.id, index, { scope: "campus", cluster: "aci-east" })?.id,
    ).toBe(a.id);
  });

  it("treats scope, cluster, and authority as exact case-sensitive context", () => {
    const a = device(
      `aci:${digest("8")}`,
      "leaf-a",
      "Campus",
      "Aci-East",
      "APIC-A",
    );
    const index = indexTopology({ ...emptyTopology(), devices: [a] });
    expect(
      resolveDevice("shared-leaf", index, {
        scope: "campus",
        cluster: "Aci-East",
        authority: "APIC-A",
      }),
    ).toBeUndefined();
    expect(
      resolveDevice("shared-leaf", index, {
        scope: "Campus",
        cluster: "Aci-East",
        authority: "apic-a",
      }),
    ).toBeUndefined();
    expect(
      resolveDevice("shared-leaf", index, {
        scope: "Campus",
        cluster: "Aci-East",
        authority: "APIC-A",
      })?.id,
    ).toBe(a.id);
  });

  it("resolves ND names across ACI and NX-OS only under the exact supplied scope", () => {
    const aci = device(
      `aci:${digest("9")}`,
      "leaf-101",
      "campus-aci",
      "aci-east",
      "apic-a",
      ["aci_topSystem"],
      { aliases: ["leaf-101"] },
    );
    const nxos = device(
      `nxos:${digest("a")}`,
      "leaf-101",
      "campus-nxos",
      "nxos-west",
      "collector-b",
      ["nxos"],
      { aliases: ["leaf-101"] },
    );
    const index = indexTopology({
      ...emptyTopology(),
      devices: [aci, nxos],
    });
    expect(
      parseObserver("nd:aci-1:leaf-101:eth1/1", index, {
        scope: "campus-aci",
      })[0],
    ).toMatchObject({ key: aci.id.toLowerCase(), label: "leaf-101" });
    expect(
      parseObserver("nd:aci-1:leaf-101:eth1/1", index, {
        scope: "CAMPUS-ACI",
      })[0].key,
    ).toBe("leaf-101");
  });

  it("keeps agreed scope when one endpoint lacks cluster and rejects context conflicts", () => {
    const source: GraphNode = {
      id: "vm:campus-aci/10.20.30.40",
      label: "database",
      kind: "endpoint",
      endpoint_kind: "vm",
      attributes: { scope: "campus-aci" },
    };
    const target: GraphNode = {
      id: "pod:cilium-aci-east/shop/backend",
      label: "backend",
      kind: "workload",
      cluster: "cilium-aci-east",
      attributes: { scope: "campus-aci" },
    };
    const edge: GraphEdge = {
      id: "context-edge",
      source: source.id,
      target: target.id,
      relationship: "communicates_with",
      evidence: [],
      confidence: "correlated",
      count: 1,
    };
    const graphIndex = indexGraph({
      nodes: [source, target],
      edges: [edge],
    } as unknown as Graph);
    expect(edgeDeviceContext(edge, graphIndex)).toEqual({
      scope: "campus-aci",
    });

    const conflicting = {
      ...target,
      attributes: { scope: "Campus-ACI" },
    };
    const conflictIndex = indexGraph({
      nodes: [source, conflicting],
      edges: [edge],
    } as unknown as Graph);
    const context = edgeDeviceContext(edge, conflictIndex);
    expect(context).toEqual({ conflict: true });
    expect(parseObserver("nd:aci-1:leaf-102:eth1/1", topo, context)).toEqual(
      [],
    );
    expect(
      nodeDeviceContext({
        ...source,
        cluster: undefined,
      }),
    ).toEqual({ scope: "campus-aci", cluster: undefined });
  });

  it("does not choose an IP alias across scopes or conflicting ifIndex records", () => {
    const a = device(
      `nxos:${digest("e")}`,
      "leaf-a",
      "campus-a",
      "nx-west",
      "collector",
      ["nxos"],
      { mgmt_ip: "192.0.2.50" },
    );
    const b = device(
      `nxos:${digest("f")}`,
      "leaf-b",
      "campus-b",
      "nx-west",
      "collector",
      ["nxos"],
      { mgmt_ip: "192.0.2.50" },
    );
    const index = indexTopology({
      ...emptyTopology(),
      devices: [a, b],
      interfaces: [
        { device_id: a.id, interface: "Ethernet1/1", ifindex: 7 },
        { device_id: a.id, interface: "Ethernet1/2", ifindex: 7 },
      ],
    });
    expect(resolveDevice("192.0.2.50", index)).toBeUndefined();
    expect(
      resolveDevice("192.0.2.50", index, {
        scope: "campus-b",
        cluster: "nx-west",
      })?.id,
    ).toBe(b.id);
    expect(
      parseObserver("netflow:192.0.2.50:ifIndex 7>ifIndex 7", index, {
        scope: "campus-a",
        cluster: "nx-west",
        authority: "collector",
        families: ["nxos"],
      })[0],
    ).toMatchObject({ key: a.id, in: "ifIndex 7", out: "ifIndex 7" });
  });

  it("keys LLDP host attachment by canonical host identity and suppresses unknown host aliases", () => {
    const leaf = device(
      `nxos:${digest("1")}`,
      "leaf-1",
      "campus",
      "nx-west",
      "collector",
      ["nxos"],
    );
    const host = {
      ...device(
        `host:${digest("2")}`,
        "worker-1",
        "campus",
        "nx-west",
        "kubernetes_node",
        ["kubernetes_node"],
      ),
      kind: "host" as const,
    };
    const link = {
      a_device: leaf.id,
      a_interface: "Ethernet1/3",
      b_device: host.id,
      source: "lldp",
      kind: "physical" as const,
      scope: "campus",
      cluster: "nx-west",
      mapping_status: "mapped",
    };
    const valid = indexTopology({
      ...emptyTopology(),
      devices: [leaf, host],
      links: [link],
    });
    const resolvedHost = resolveDevice("worker-1", valid, {
      scope: "campus",
      cluster: "nx-west",
      families: ["kubernetes_node"],
    });
    expect(resolvedHost?.id).toBe(host.id);
    expect(valid.lldpHost.get(host.id)).toEqual({
      device: leaf.id,
      port: "Ethernet1/3",
    });

    const unknown = indexTopology({
      ...emptyTopology(),
      devices: [leaf],
      links: [{ ...link, b_device: "worker-1" }],
    });
    expect(unknown.lldpHost.size).toBe(0);
    expect(unknown.adjacency.size).toBe(0);
  });

  it("preserves only explicit canonical physical endpoints in V2 adjacency", () => {
    const a = device(
      `aci:${digest("3")}`,
      "leaf-a",
      "campus",
      "aci-east",
      "apic-a",
    );
    const b = device(
      `nxos:${digest("4")}`,
      "leaf-b",
      "campus",
      "aci-east",
      "collector-b",
      ["nxos"],
    );
    const unresolved = indexTopology({
      ...emptyTopology(),
      devices: [a, b],
      links: [
        {
          a_device: a.id,
          b_device: "unknown-leaf",
          source: "cdp",
          kind: "physical",
          scope: "campus",
          cluster: "aci-east",
          mapping_status: "mapped",
        },
      ],
    });
    expect(unresolved.adjacency.size).toBe(0);
    const foreignAuthorityAllowed = indexTopology({
      ...emptyTopology(),
      devices: [a, b],
      links: [
        {
          a_device: a.id,
          b_device: b.id,
          source: "aci_fabricLink",
          kind: "physical",
          scope: "campus",
          cluster: "aci-east",
          mapping_status: "mapped",
        },
      ],
    });
    expect(foreignAuthorityAllowed.adjacency.size).toBe(2);
  });

  it("does not mark a path stage from an ambiguous V2 exporter IP", () => {
    const leafA = device(
      `nxos:${digest("5")}`,
      "leaf-a",
      "campus",
      "cluster-a",
      "collector-a",
      ["nxos"],
      { mgmt_ip: "192.0.2.44" },
    );
    const leafB = device(
      `nxos:${digest("6")}`,
      "leaf-b",
      "campus",
      "cluster-a",
      "collector-b",
      ["nxos"],
      { mgmt_ip: "192.0.2.44" },
    );
    const extra = device(
      `nxos:${digest("7")}`,
      "leaf-c",
      "campus",
      "cluster-a",
      "collector-c",
      ["nxos"],
      { mgmt_ip: "192.0.2.44" },
    );
    const nodes = [
      {
        id: "node:cluster-a/worker-a",
        label: "worker-a",
        kind: "endpoint" as const,
        endpoint_kind: "k8s_node" as const,
        cluster: "cluster-a",
        attributes: { scope: "campus", attach_device: leafA.id },
      },
      {
        id: "node:cluster-a/worker-b",
        label: "worker-b",
        kind: "endpoint" as const,
        endpoint_kind: "k8s_node" as const,
        cluster: "cluster-a",
        attributes: { scope: "campus", attach_device: leafB.id },
      },
    ];
    const edge: GraphEdge = {
      id: "edge-1",
      source: nodes[0].id,
      target: nodes[1].id,
      relationship: "communicates_with",
      evidence: ["flow"],
      confidence: "correlated",
      count: 1,
      observers: ["netflow:192.0.2.44:in>out"],
    };
    const graph = { nodes, edges: [edge] } as unknown as Graph;
    const topology = indexTopology({
      ...emptyTopology(),
      devices: [leafA, leafB, extra],
      links: [
        {
          a_device: leafA.id,
          b_device: leafB.id,
          source: "cdp",
          kind: "physical",
          scope: "campus",
          cluster: "cluster-a",
          mapping_status: "mapped",
        },
      ],
    });
    const path = buildPath(edge, graph, indexGraph(graph), topology);
    expect(
      path.stages
        .filter((s) => s.title.startsWith("leaf-"))
        .map((s) => [s.title, s.observed]),
    ).toEqual([
      ["leaf-a", false],
      ["leaf-b", false],
    ]);
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
  it("does not name a same-IP network client as the firewall for an ftd observer", () => {
    const rows = structuredClone(demoTopology("catalyst-aci"));
    const device = rows.devices.find((d) => d.kind === "network_client")!;
    device.mgmt_ip = "192.0.2.77";
    const point = parseObserver(
      "ftd:192.0.2.77:inside>outside",
      indexTopology(rows),
      { scope: device.scope, cluster: device.cluster },
    )[0];
    expect(point).toMatchObject({
      resolved: false,
      label: "Firewall 192.0.2.77",
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
  it("uses only complete client-edge handoffs for each client, port, and transport", () => {
    const g = structuredClone(demoGraph("catalyst-aci"));
    const service = g.nodes.find(
      (node) => node.endpoint_kind === "k8s_service",
    )!;
    const cluster = service.cluster ?? g.boundary.cluster;
    service.cluster = cluster;
    service.attributes = {
      ...service.attributes,
      handoff_coverage: "complete",
      handoff_connections: "20",
      handoff_determined: "20",
      handoff_unresolved: "0",
    };
    const pods = g.edges
      .filter(
        (candidate) =>
          candidate.relationship === "forwards_to" &&
          candidate.source === service.id,
      )
      .map((candidate) => candidate.target);
    if (pods.length < 2) {
      const extraPod = `pod:${cluster}/test/client-handoff-backend`;
      g.nodes.push({
        id: extraPod,
        label: "client-handoff-backend",
        kind: "workload",
        cluster,
      });
      g.edges.push({
        id: `aggregate-forward:${service.id}:${extraPod}`,
        source: service.id,
        target: extraPod,
        relationship: "forwards_to",
        evidence: ["test aggregate context"],
        confidence: "correlated",
        count: 1,
      });
      pods.push(extraPod);
    }
    const [podA, podB] = pods;
    const appendClient = (
      id: string,
      port: number,
      transport: string,
      target: string,
      records: NonNullable<GraphEdge["client_handoffs"]>,
    ) => {
      const client = `network_client:${id}`;
      g.nodes.push({
        id: client,
        label: id,
        kind: "client",
        endpoint_kind: "network_client",
        addresses: [`192.0.2.${id === "client-a" ? "41" : "42"}`],
        cluster,
      });
      const edge: GraphEdge = {
        id: `client-edge:${id}`,
        source: client,
        target: service.id,
        relationship: "communicates_with",
        evidence: ["catalyst"],
        confidence: "correlated",
        count: 1,
        server_port: port,
        transport,
        observers: ["hubble:unscoped-flow-observer"],
        via_node: ["aggregate-receiver"],
        client_handoff_coverage: "complete",
        client_handoff_connections: records.reduce(
          (sum, record) => sum + record.connections,
          0,
        ),
        client_handoff_determined: records.reduce(
          (sum, record) => sum + record.connections,
          0,
        ),
        client_handoff_unresolved: 0,
        client_handoffs: records,
      };
      g.edges.push(edge);
      return edge;
    };
    const clientA = appendClient("client-a", 443, "tcp", podA, [
      {
        target: podA,
        basis: "hubble_client_tuple",
        connections: 2,
        receiving_nodes: ["receiver-a"],
        observers: ["hubble:client-a-proof"],
      },
    ]);
    const clientB = appendClient("client-b", 8443, "udp", podB, [
      {
        target: podB,
        basis: "hubble_client_tuple",
        connections: 1,
        receiving_nodes: ["receiver-b1"],
        observers: ["hubble:client-b-proof"],
      },
      {
        target: podB,
        basis: "time_inferred",
        connections: 1,
        receiving_nodes: ["receiver-b2"],
        observers: ["hubble:client-b-inference"],
      },
    ]);
    g.edges
      .filter((candidate) => candidate.relationship === "forwards_to")
      .forEach((candidate) => {
        candidate.via_node = ["aggregate-receiver"];
        candidate.observers = ["nd:aggregate-observer:Eth1/1>Eth1/2"];
      });

    const graphIndex = indexGraph(g);
    const topology = indexTopology(demoTopology("catalyst-aci"));
    const pathA = buildPath(clientA, g, graphIndex, topology);
    const pathB = buildPath(clientB, g, graphIndex, topology);
    expect(pathA.backends.map((backend) => backend.id)).toEqual([podA]);
    expect(pathB.backends.map((backend) => backend.id)).toEqual([podB]);
    expect(pathA.backend).toBe(podA);
    expect(pathB.backend).toBe(podB);
    expect(
      pathA.stages.some((stage) => stage.title === "aggregate-receiver"),
    ).toBe(false);
    expect(pathB.stages.some((stage) => stage.title === "One of 2 nodes")).toBe(
      true,
    );
    expect(
      pathB.stages.find((stage) => stage.kind === "handoff")?.handoff,
    ).toMatchObject({
      state: "inferred",
      text: expect.stringContaining("Inferred from timing · 1 connection"),
    });
    expect(
      pathB.stages.find((stage) => stage.kind === "handoff")?.handoff?.text,
    ).toContain("Hubble: same client tuple · 1 connection");
    expect(pathB.stages.flatMap((stage) => stage.observedBy)).not.toContain(
      "nd:aggregate-observer:Eth1/1>Eth1/2",
    );
    expect([clientA.server_port, clientA.transport]).toEqual([443, "tcp"]);
    expect([clientB.server_port, clientB.transport]).toEqual([8443, "udp"]);
  });

  it("fails closed on missing or incomplete client handoff metadata", () => {
    const g = structuredClone(demoGraph("catalyst-aci"));
    const service = g.nodes.find(
      (node) => node.endpoint_kind === "k8s_service",
    )!;
    service.attributes = {
      ...service.attributes,
      handoff_coverage: "complete",
    };
    const client: GraphNode = {
      id: "network_client:missing-proof",
      label: "missing-proof",
      kind: "client",
      endpoint_kind: "network_client",
    };
    g.nodes.push(client);
    const edge: GraphEdge = {
      id: "client-edge:missing-proof",
      source: client.id,
      target: service.id,
      relationship: "communicates_with",
      evidence: [],
      confidence: "correlated",
      count: 1,
      via_node: ["aggregate-receiver"],
    };
    g.edges.push(edge);
    const path = buildPath(
      edge,
      g,
      indexGraph(g),
      indexTopology(demoTopology("catalyst-aci")),
    );
    expect(path.backends).toEqual([]);
    expect(
      path.stages.some((stage) => stage.title === "aggregate-receiver"),
    ).toBe(false);
    expect(
      path.stages.find((stage) => stage.kind === "handoff")?.handoff?.text,
    ).toMatch(/unavailable or invalid/);
  });

  it("does not borrow aggregate V2 handoff or receiving-node evidence for a client path", () => {
    const g = structuredClone(demoGraph("catalyst-aci"));
    const edge = g.edges.find(
      (candidate) =>
        candidate.relationship === "communicates_with" &&
        g.nodes.find((node) => node.id === candidate.target)?.endpoint_kind ===
          "k8s_service",
    )!;
    const service = g.nodes.find((node) => node.id === edge.target)!;
    service.attributes = {
      ...service.attributes,
      handoff_coverage: "partial",
      handoff_connections: "4",
      handoff_determined: "2",
      handoff_unresolved: "2",
    };
    const candidate = g.edges.find(
      (item) =>
        item.relationship === "forwards_to" && item.source === service.id,
    )!;
    Object.assign(edge, {
      client_handoff_coverage: "partial",
      client_handoff_connections: 4,
      client_handoff_determined: 2,
      client_handoff_unresolved: 2,
      client_handoffs: [
        {
          target: candidate.target,
          basis: "hubble_client_tuple",
          connections: 2,
          receiving_nodes: ["client-receiver"],
          observers: ["hubble:client-proof"],
        },
      ],
    });
    edge.observers = [];
    edge.via_node = undefined;
    const choices = g.edges.filter(
      (candidate) =>
        candidate.relationship === "forwards_to" &&
        candidate.source === service.id,
    );
    expect(choices.length).toBeGreaterThan(0);
    choices.forEach((candidate) => {
      candidate.via_node = ["shared-receiving-node"];
    });

    const path = buildPath(
      edge,
      g,
      indexGraph(g),
      indexTopology(demoTopology("catalyst-aci")),
    );
    expect(path.backends).toEqual([]);
    expect(
      path.stages.some((stage) => stage.title === "shared-receiving-node"),
    ).toBe(false);
    expect(path.stages.some((stage) => stage.kind === "gap")).toBe(true);
    expect(
      path.stages.find((stage) => stage.kind === "handoff")?.handoff,
    ).toMatchObject({
      state: "undetermined",
      text: expect.stringContaining("handoff coverage is partial"),
    });
  });

  it("resolves the captured ACI VM attachment and ND observer with graph scope", () => {
    const captured = demoGraph("catalyst-aci");
    const capturedIndex = indexGraph(captured);
    const capturedTopology = indexTopology(demoTopology("catalyst-aci"));
    const vm = captured.nodes.find(
      (node) => node.id === "vm:campus-aci/10.20.30.40",
    )!;
    const edge = captured.edges.find(
      (candidate) =>
        candidate.relationship === "communicates_with" &&
        (candidate.source === vm.id || candidate.target === vm.id),
    )!;
    const attached = resolveDevice(
      vm.attributes?.attach_device,
      capturedTopology,
      nodeDeviceContext(vm),
    );
    expect(attached).toMatchObject({
      id: "aci:ef405db29b9d1f604f20af39a492a8798198f746faa1004703a5b7f056b6a561",
      name: "leaf-102",
    });
    const path = buildPath(edge, captured, capturedIndex, capturedTopology);
    expect(path.stages.some((stage) => stage.nodeId === attached?.id)).toBe(
      true,
    );
    expect(
      observationsByDevice(
        edge,
        capturedTopology,
        [],
        edgeDeviceContext(edge, capturedIndex),
      ).some((observation) => observation.key === attached?.id.toLowerCase()),
    ).toBe(true);
    const summaries = deviceSummaries([edge], capturedTopology, capturedIndex);
    expect(
      summaries.devices.some((summary) => summary.key === attached?.id),
    ).toBe(true);
  });

  it("keeps the captured unresolved IP source identity while following its client handoff", () => {
    const captured = demoGraph("catalyst-aci");
    const capturedIndex = indexGraph(captured);
    const capturedTopology = indexTopology(demoTopology("catalyst-aci"));
    const sourceId = "ip:campus-aci/10.61.0.20";
    const edge = captured.edges.find(
      (candidate) =>
        candidate.relationship === "communicates_with" &&
        candidate.source === sourceId &&
        candidate.target ===
          "k8s_service:cilium-aci-east/shop/checkout-api/10.50.0.20:8080",
    )!;
    const source = captured.nodes.find((node) => node.id === sourceId)!;
    const path = buildPath(edge, captured, capturedIndex, capturedTopology);
    expect(source).toMatchObject({
      kind: "endpoint",
      endpoint_kind: "unresolved",
    });
    expect(path.backend).toBe(edge.client_handoffs?.[0].target);
    expect(path.stages[0]).toMatchObject({
      kind: "entity",
      title: source.label,
    });
    expect(
      path.stages.some(
        (stage) => stage.kind === "host" && stage.title === source.label,
      ),
    ).toBe(false);
    expect(path.stages).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ kind: "gap" }),
        expect.objectContaining({
          kind: "host",
          title: "node-b",
          observedBy: ["Hubble"],
        }),
      ]),
    );
    expect(path.stages.some((stage) => stage.kind === "switch")).toBe(false);
    expect(path.stages.findIndex((stage) => stage.kind === "gap")).toBeLessThan(
      path.stages.findIndex((stage) => stage.kind === "host"),
    );
  });

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
  it.each([true, false])(
    "keeps identical hostnames in separate clusters distinct (both hosts present: %s)",
    (bothHosts) => {
      const cross = structuredClone(graph);
      cross.nodes = [
        ...["a", "b"].map((cluster) => ({
          id: `pod:${cluster}/shop/client`,
          label: `client-${cluster}`,
          kind: "workload" as const,
          attributes: { node: "worker-1" },
        })),
        ...["a", ...(bothHosts ? ["b"] : [])].map((cluster) => ({
          id: `node:${cluster}/worker-1`,
          label: "worker-1",
          kind: "endpoint" as const,
          endpoint_kind: "k8s_node" as const,
          cluster,
          attributes: {
            attach_device: cluster === "a" ? "leaf-101" : "leaf-102",
          },
        })),
      ];
      const edge = {
        ...conv("frontend-7d9c6b5f4-x2k8p", "checkout-5f8b9c7d6-m4n7q"),
        source: "pod:a/shop/client",
        target: "pod:b/shop/client",
        observers: [],
      };
      cross.edges = [edge];
      const path = buildPath(edge, cross, indexGraph(cross), topo);
      expect(path.sameHost).toBe(false);
      const hosts = path.stages.filter((s) => s.kind === "host");
      expect(hosts.map((s) => s.nodeId)).toEqual([
        "node:a/worker-1",
        bothHosts ? "node:b/worker-1" : undefined,
      ]);
      expect(path.stages.some((s) => s.title === "leaf-101")).toBe(true);
      expect(path.stages.some((s) => s.title === "leaf-102")).toBe(bothHosts);
    },
  );
  it("does not assert a shared host for pods with an unknown cluster", () => {
    const g = structuredClone(graph);
    g.nodes = ["client", "server"].map((label) => ({
      id: `pod:unknown/shop/${label}`,
      label,
      kind: "workload",
      attributes: { node: "worker-1" },
    }));
    const edge = {
      ...graph.edges[0],
      source: g.nodes[0].id,
      target: g.nodes[1].id,
    };
    g.edges = [edge];
    const path = buildPath(
      edge,
      g,
      indexGraph(g),
      indexTopology(emptyTopology()),
    );
    expect(path.sameHost).toBe(false);
    expect(path.stages.some((s) => s.kind === "gap")).toBe(true);
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
  it("matches V2 ACI ACL aliases with exact edge scope and refuses scope conflicts", async () => {
    const { edgeMatches } = await import("./topology");
    const captured = demoGraph("catalyst-aci");
    const graphIndex = indexGraph(captured);
    const v2Topology = indexTopology(demoTopology("catalyst-aci"));
    const aclEdge = captured.edges.find(
      (edge) =>
        edge.relationship === "communicates_with" &&
        edge.acl_leaf === "pod-1/node-103",
    )!;
    expect(edgeMatches(aclEdge, "leaf-103", v2Topology, graphIndex)).toBe(true);
    const path = buildPath(aclEdge, captured, graphIndex, v2Topology);
    expect(path.policy.map((item) => item.text).join(" ")).toContain(
      "leaf-103",
    );

    const conflict = structuredClone(captured);
    const target = conflict.nodes.find((node) => node.id === aclEdge.target)!;
    target.attributes = { ...target.attributes, scope: "Campus-ACI" };
    const conflictIndex = indexGraph(conflict);
    const conflictEdge = conflictIndex.edge.get(aclEdge.id)!;
    expect(
      edgeMatches(conflictEdge, "leaf-103", v2Topology, conflictIndex),
    ).toBe(false);
  });

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

describe("Stream/IPFIX exporter resolution", () => {
  const LEAF_102 =
    "aci:ef405db29b9d1f604f20af39a492a8798198f746faa1004703a5b7f056b6a561";
  const scenario = () => {
    const graph = structuredClone(demoGraph("catalyst-aci"));
    const topology = structuredClone(demoTopology("catalyst-aci"));
    const edge = graph.edges.find((candidate) =>
      candidate.traffic_observations?.some(
        (item) => item.exporter_ip === "192.0.2.102",
      ),
    )!;
    return { graph, topology, edge };
  };
  const unresolvedKey = JSON.stringify([
    "192.0.2.102",
    "campus-aci",
    "cilium-aci-east",
  ]);
  const exporterContexts = (
    graph: Graph,
    topology: ReturnType<typeof demoTopology>,
  ) =>
    deviceSummaries(
      graph.edges,
      indexTopology(topology),
      indexGraph(graph),
    ).attachmentReferences.flatMap((reference) => reference.exporterContext);
  const seenBy = (
    graph: Graph,
    topology: ReturnType<typeof demoTopology>,
    edge: GraphEdge,
  ) =>
    observationsByDevice(
      { ...edge, observers: ["netflow:192.0.2.102:ifIndex 436400128>"] },
      indexTopology(topology),
      [],
      edgeDeviceContext(edge, indexGraph(graph)),
    );

  it("resolves an exporter whose authority is its own address to the inventory switch", () => {
    const { graph, topology, edge } = scenario();
    const observation = edge.traffic_observations!.find(
      (item) => item.exporter_ip === "192.0.2.102",
    )!;
    const leaf = topology.devices.find((device) => device.id === LEAF_102)!;
    expect(observation.source_authority).toBe("192.0.2.102");
    expect(leaf.device_authority).toBe("192.0.2.50");
    expect(exporterContexts(graph, topology)).toContain(
      `Exporter leaf-102 (${LEAF_102})`,
    );
    expect(seenBy(graph, topology, edge)[0]).toMatchObject({
      key: LEAF_102,
      label: "leaf-102",
      resolved: true,
    });
  });

  it("does not compare a controller authority from the edge context with the exporter", () => {
    const { graph, topology, edge } = scenario();
    const withAuthority = {
      ...edge,
      source_authority: "https://catalyst-center.example.invalid",
    } as GraphEdge;
    const context = edgeDeviceContext(withAuthority, indexGraph(graph));
    expect(context.authority).toBe("https://catalyst-center.example.invalid");
    expect(
      observationsByDevice(
        { ...withAuthority, observers: ["netflow:192.0.2.102:ifIndex 1>"] },
        indexTopology(topology),
        [],
        context,
      )[0],
    ).toMatchObject({ key: LEAF_102, resolved: true });
  });

  it("matches IPv6 exporter observers to their traffic observation", () => {
    const { graph, topology, edge } = scenario();
    const ipv6 = "2001:db8::66";
    for (const item of edge.traffic_observations!) {
      if (item.exporter_ip !== "192.0.2.102") continue;
      item.exporter_ip = ipv6;
      item.source_authority = ipv6;
    }
    const leaf = topology.devices.find((device) => device.id === LEAF_102)!;
    const ipv6SeenBy = () =>
      observationsByDevice(
        { ...edge, observers: [`netflow:${ipv6}:ifIndex 436400128>`] },
        indexTopology(topology),
        [],
        edgeDeviceContext(edge, indexGraph(graph)),
      );
    leaf.mgmt_ip = ipv6;
    expect(ipv6SeenBy()[0]).toMatchObject({ key: LEAF_102, resolved: true });
    leaf.scope = "meraki-nxos";
    expect(ipv6SeenBy()[0]).toMatchObject({
      key: JSON.stringify([ipv6, "campus-aci", "cilium-aci-east"]),
      resolved: false,
    });
  });

  it("does not resolve the same management IP from another scope", () => {
    const { graph, topology, edge } = scenario();
    const leaf = topology.devices.find((device) => device.id === LEAF_102)!;
    leaf.scope = "meraki-nxos";
    expect(exporterContexts(graph, topology)).not.toContain(
      `Exporter leaf-102 (${LEAF_102})`,
    );
    expect(seenBy(graph, topology, edge)[0]).toMatchObject({
      key: unresolvedKey,
      resolved: false,
    });
  });

  it("leaves an exporter unresolved when two switches share its IP in one scope", () => {
    const { graph, topology, edge } = scenario();
    const leaf = topology.devices.find((device) => device.id === LEAF_102)!;
    topology.devices.push({
      ...leaf,
      id: `aci:${"e".repeat(64)}`,
      name: "leaf-102-duplicate",
    });
    expect(
      exporterContexts(graph, topology).some((text) =>
        text.startsWith("Exporter leaf-102"),
      ),
    ).toBe(false);
    expect(seenBy(graph, topology, edge)[0].resolved).toBe(false);
  });

  it("leaves an exporter unresolved on V2 when neither observation nor context carries a scope", () => {
    const { graph, topology, edge } = scenario();
    for (const item of edge.traffic_observations!) delete item.scope;
    expect(exporterContexts(graph, topology)).not.toContain(
      `Exporter leaf-102 (${LEAF_102})`,
    );
    expect(
      observationsByDevice(
        {
          ...edge,
          traffic_observations: edge.traffic_observations,
          observers: ["netflow:192.0.2.102:ifIndex 1>"],
        },
        indexTopology(topology),
        [],
        {},
      )[0],
    ).toMatchObject({
      key: JSON.stringify(["192.0.2.102", "", "cilium-aci-east"]),
      resolved: false,
    });
  });

  it("leaves an exporter unresolved when its cluster differs from the inventory device's", () => {
    const { graph, topology, edge } = scenario();
    const leaf = topology.devices.find((device) => device.id === LEAF_102)!;
    leaf.cluster = "another-cluster";
    expect(leaf.cluster).not.toBe(
      edge.traffic_observations!.find(
        (item) => item.exporter_ip === "192.0.2.102",
      )!.cluster,
    );
    expect(exporterContexts(graph, topology)).not.toContain(
      `Exporter leaf-102 (${LEAF_102})`,
    );
    expect(seenBy(graph, topology, edge)[0]).toMatchObject({
      key: unresolvedKey,
      resolved: false,
    });
  });

  it("never resolves an exporter IP to a network client with the same address", () => {
    const { graph, topology, edge } = scenario();
    const leaf = topology.devices.find((device) => device.id === LEAF_102)!;
    leaf.mgmt_ip = "192.0.2.199";
    const client = topology.devices.find(
      (device) => device.kind === "network_client",
    )!;
    client.mgmt_ip = "192.0.2.102";
    expect(seenBy(graph, topology, edge)[0]).toMatchObject({
      key: unresolvedKey,
      resolved: false,
    });
  });

  it("keeps an exporter unresolved when its authority names a different address", () => {
    const { graph, topology, edge } = scenario();
    for (const item of edge.traffic_observations!)
      if (item.exporter_ip === "192.0.2.102")
        item.source_authority = "192.0.2.50";
    expect(exporterContexts(graph, topology)).not.toContain(
      `Exporter leaf-102 (${LEAF_102})`,
    );
    expect(seenBy(graph, topology, edge)).toEqual([]);
  });

  it("matches a normalized authority to a mixed-case IPv6 exporter address", () => {
    const { graph, topology, edge } = scenario();
    const leaf = topology.devices.find((device) => device.id === LEAF_102)!;
    leaf.mgmt_ip = "2001:db8::102";
    for (const item of edge.traffic_observations!)
      if (item.exporter_ip === "192.0.2.102") {
        item.exporter_ip = "2001:DB8::102";
        item.source_authority = "2001:db8::102";
      }
    expect(exporterContexts(graph, topology)).toContain(
      `Exporter leaf-102 (${LEAF_102})`,
    );
    for (const item of edge.traffic_observations!)
      if (item.exporter_ip === "2001:DB8::102")
        item.source_authority = " 2001:DB8::102 ";
    expect(exporterContexts(graph, topology)).toContain(
      `Exporter leaf-102 (${LEAF_102})`,
    );
    for (const item of edge.traffic_observations!)
      if (item.exporter_ip === "2001:DB8::102")
        item.source_authority = "2001:db8::103";
    expect(exporterContexts(graph, topology)).not.toContain(
      `Exporter leaf-102 (${LEAF_102})`,
    );
  });

  it("requires an exporter authority equal to the exporter address on a V2 topology", () => {
    const { graph, topology, edge } = scenario();
    for (const item of edge.traffic_observations!)
      if (item.exporter_ip === "192.0.2.102") item.source_authority = "";
    expect(exporterContexts(graph, topology)).not.toContain(
      `Exporter leaf-102 (${LEAF_102})`,
    );
    expect(seenBy(graph, topology, edge)).toEqual([]);
    for (const item of edge.traffic_observations!)
      if (item.exporter_ip === "192.0.2.102") delete item.source_authority;
    expect(exporterContexts(graph, topology)).not.toContain(
      `Exporter leaf-102 (${LEAF_102})`,
    );
    expect(seenBy(graph, topology, edge)).toEqual([]);
  });

  it("leaves an exporter unresolved when neither the observation nor the context carries a cluster", () => {
    const { graph, topology, edge } = scenario();
    for (const item of edge.traffic_observations!) delete item.cluster;
    expect(exporterContexts(graph, topology)).not.toContain(
      `Exporter leaf-102 (${LEAF_102})`,
    );
    const seen = observationsByDevice(
      { ...edge, observers: ["netflow:192.0.2.102:ifIndex 1>"] },
      indexTopology(topology),
      [],
      { scope: "campus-aci" },
    );
    expect(seen).toHaveLength(1);
    expect(seen[0].resolved).toBe(false);
  });

  it("leaves a netflow observer unresolved on V2 when the edge has no traffic observation and only a scope", () => {
    const { topology, edge } = scenario();
    const topo = indexTopology(topology);
    const bare = {
      ...edge,
      traffic_observations: undefined,
      observers: ["netflow:192.0.2.102:ifIndex 1>"],
    };
    for (const context of [{ scope: "campus-aci" }, {}]) {
      const seen = observationsByDevice(bare, topo, [], context);
      expect(seen).toHaveLength(1);
      expect(seen[0].resolved).toBe(false);
    }
    const full = observationsByDevice(bare, topo, [], {
      scope: "campus-aci",
      cluster: "cilium-aci-east",
    });
    expect(full[0].resolved).toBe(true);
  });

  it("leaves an exporter without a cluster unresolved even for a device whose cluster is empty", () => {
    const { topology, edge } = scenario();
    for (const item of edge.traffic_observations!) delete item.cluster;
    const leaf = topology.devices.find((d) => d.id === LEAF_102)!;
    leaf.cluster = "";
    const seen = observationsByDevice(
      { ...edge, observers: ["netflow:192.0.2.102:ifIndex 1>"] },
      indexTopology(topology),
      [],
      { scope: "campus-aci" },
    );
    expect(seen).toHaveLength(1);
    expect(seen[0].resolved).toBe(false);
  });

  it("keeps unresolved exporters with the same address in different scopes and clusters apart", () => {
    const { graph, topology, edge } = scenario();
    const template = edge.traffic_observations![0];
    const copy = (id: string, scope: string, cluster: string) =>
      ({
        ...structuredClone(edge),
        id,
        source: `missing:${id}:source`,
        target: `missing:${id}:target`,
        relationship: "communicates_with",
        scope,
        cluster,
        observers: ["netflow:192.0.2.77:ifIndex 1>"],
        traffic_observations: [
          {
            ...structuredClone(template),
            exporter_ip: "192.0.2.77",
            source_authority: "192.0.2.77",
            scope,
            cluster,
          },
        ],
      }) as GraphEdge;
    const edges = [
      copy("flow-a", "scope-a", "cluster-a"),
      copy("flow-b", "scope-b", "cluster-b"),
    ];
    const { devices } = deviceSummaries(
      edges,
      indexTopology(topology),
      indexGraph({ ...graph, edges }),
    );
    expect(devices).toHaveLength(2);
    expect(devices.map((item) => item.label).sort()).toEqual([
      "Exporter 192.0.2.77 · scope-a · cluster-a",
      "Exporter 192.0.2.77 · scope-b · cluster-b",
    ]);
    expect(devices.every((item) => item.edges.length === 1)).toBe(true);
  });
});

describe("Client attachment references", () => {
  const scenario = () => {
    const graph = structuredClone(demoGraph("catalyst-aci"));
    const topology = structuredClone(demoTopology("catalyst-aci"));
    const edge = graph.edges.find(
      (candidate) => candidate.attachment_evidence?.length,
    )!;
    for (const other of graph.edges)
      if (other !== edge) delete other.attachment_evidence;
    const client = graph.nodes.find((node) => node.id === edge.source)!;
    const second = (suffix: string, ssid: number) => {
      const node = structuredClone(client);
      node.id = `${client.id}-${suffix}`;
      node.label = `CLIENT-${suffix}`;
      const copy = structuredClone(edge);
      copy.id = `${edge.id}-${suffix}`;
      copy.source = node.id;
      copy.attachment_evidence![0].ssid_number = ssid;
      graph.nodes.push(node);
      graph.edges.push(copy);
      return { node, edge: copy };
    };
    const references = () =>
      deviceSummaries(graph.edges, indexTopology(topology), indexGraph(graph))
        .attachmentReferences;
    return { graph, edge, client, second, references };
  };

  it("keeps two clients on one access point separate with their own SSID and flows", () => {
    const { edge, client, second, references } = scenario();
    client.label = "CLIENT-ONE";
    edge.attachment_evidence![0].ssid_number = 1;
    const other = second("TWO", 7);
    const refs = references();
    expect(refs).toHaveLength(2);
    const one = refs.find((reference) => reference.client === "CLIENT-ONE")!;
    const two = refs.find((reference) => reference.client === "CLIENT-TWO")!;
    expect(one.device?.id).toBe(two.device?.id);
    expect(one.key).not.toBe(two.key);
    expect(one.evidence.ssid_number).toBe(1);
    expect(two.evidence.ssid_number).toBe(7);
    expect(one.flowEdges).toEqual([edge]);
    expect(two.flowEdges).toEqual([other.edge]);
  });

  it("keeps one client's flows under their own association record", () => {
    const { edge, graph, references } = scenario();
    edge.attachment_evidence![0].ssid_number = 1;
    const copy = structuredClone(edge);
    copy.id = `${edge.id}-later`;
    copy.attachment_evidence![0].ssid_number = 9;
    graph.edges.push(copy);
    const refs = references();
    expect(refs).toHaveLength(2);
    const first = refs.find(
      (reference) => reference.evidence.ssid_number === 1,
    )!;
    const later = refs.find(
      (reference) => reference.evidence.ssid_number === 9,
    )!;
    expect(first.flowEdges).toEqual([edge]);
    expect(later.flowEdges).toEqual([copy]);
  });

  it("merges one client's flows that share an association record", () => {
    const { edge, graph, references } = scenario();
    const copy = structuredClone(edge);
    copy.id = `${edge.id}-same`;
    graph.edges.push(copy);
    const refs = references();
    expect(refs).toHaveLength(1);
    expect(refs[0].flowEdges).toEqual([edge, copy]);
  });

  it("keeps one client's records that differ in any evidence field apart", () => {
    const { edge, references } = scenario();
    const base = edge.attachment_evidence![0];
    const fields = {
      basis: "other-basis",
      status: "other-status",
      device_name: "other-name",
      device_mac: "00:00:5e:00:53:01",
      device_serial: "OTHER-SERIAL",
      client_source: "other-source",
      client_authority: "other-authority",
      client_native_id: "other-native-id",
    } as const;
    edge.attachment_evidence = [
      base,
      ...Object.entries(fields).map(([field, value]) => ({
        ...structuredClone(base),
        [field]: value,
      })),
    ];
    expect(references()).toHaveLength(1 + Object.keys(fields).length);
  });

  it("merges identical records whose numeric and string values name the same thing", () => {
    const { edge, graph, references } = scenario();
    edge.attachment_evidence![0].ssid_number = 1;
    edge.attachment_evidence![0].event_time = 1700000000;
    const copy = structuredClone(edge);
    copy.id = `${edge.id}-text`;
    copy.attachment_evidence![0].ssid_number = "1";
    copy.attachment_evidence![0].event_time = "1700000000";
    graph.edges.push(copy);
    const refs = references();
    expect(refs).toHaveLength(1);
    expect(refs[0].flowEdges).toEqual([edge, copy]);
  });

  it("keeps two clients with the same unresolved attachment ID separate", () => {
    const { edge, client, second, references } = scenario();
    client.label = "CLIENT-ONE";
    edge.attachment_evidence![0].device_id = "catalyst:" + "0".repeat(64);
    const other = second("TWO", 7);
    other.edge.attachment_evidence![0].device_id = "catalyst:" + "0".repeat(64);
    const refs = references();
    expect(refs).toHaveLength(2);
    expect(refs.every((reference) => !reference.device)).toBe(true);
    expect(refs.map((reference) => reference.flowEdges.length)).toEqual([1, 1]);
  });

  it("does not attribute a client's flow to an access point without that client's association evidence", () => {
    const { graph, edge, second, references } = scenario();
    const other = second("TWO", 7);
    delete other.edge.attachment_evidence;
    const refs = references();
    expect(refs).toHaveLength(1);
    expect(refs[0].flowEdges).toEqual([edge]);
    expect(graph.edges).toContain(other.edge);
  });

  it("does not attribute association evidence that lacks a correlated flow", () => {
    const { edge, references } = scenario();
    edge.confidence = "observed";
    expect(references()).toHaveLength(0);
  });
});
