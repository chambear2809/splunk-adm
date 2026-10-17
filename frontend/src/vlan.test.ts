import { describe, expect, it } from "vitest";
import { vlanContexts, vlanEdges, vlanExporter, vlanInterface } from "./vlan";
import { indexGraph } from "./graph";
import type { GraphEdge } from "./graph";
import { indexTopology } from "./topology";

const edge = (
  id: string,
  observations: NonNullable<GraphEdge["vlan_observations"]>,
): GraphEdge => ({
  id,
  source: "a",
  target: "b",
  relationship: "communicates_with",
  confidence: "observed",
  evidence: [],
  count: 1,
  vlan_observations: observations,
});
const observation = (
  overrides: Partial<NonNullable<GraphEdge["vlan_observations"]>[number]> = {},
) => ({
  vlan: 120,
  position: "ingress" as const,
  exporter: "leaf-101",
  interface_index: "49",
  src_ip: "10.0.0.1",
  dest_ip: "10.0.0.2",
  first_seen: 10,
  last_seen: 20,
  ...overrides,
});

describe("vlanContexts", () => {
  it("resolves management-IP exporters through canonical device IDs", () => {
    const topo = indexTopology({
      devices: [
        {
          id: "leaf-101",
          name: "Leaf 101",
          kind: "switch",
          mgmt_ip: "192.0.2.10",
          sources: ["nd"],
        },
      ],
      links: [],
      interfaces: [
        { device_id: "leaf-101", interface: "Ethernet1/49", ifindex: 49 },
      ],
      warnings: [],
    });
    expect(
      vlanInterface(
        observation({ exporter: "192.0.2.10", interface_index: "49" }),
        topo,
      ),
    ).toBe("Eth1/49");
  });

  it("prefers explicit interfaces and keeps unknown exporter fallback", () => {
    const topo = indexTopology({
      devices: [],
      links: [],
      interfaces: [],
      warnings: [],
    });
    expect(
      vlanInterface(observation({ interface: "Port-Channel1" }), topo),
    ).toBe("Port-Channel1");
    expect(
      vlanInterface(
        observation({ exporter: "198.51.100.9", interface_index: "7" }),
        topo,
      ),
    ).toBe("ifIndex 7");
  });

  it("resolves V2 exporters by scoped management IP regardless of controller authority", () => {
    const leaf = {
      id: `aci:${"a".repeat(64)}`,
      name: "leaf-101",
      kind: "switch" as const,
      mgmt_ip: "192.0.2.10",
      sources: ["aci_topSystem"],
      scope: "campus-aci",
      cluster: "cilium-aci-east",
      device_authority: "192.0.2.50",
      mapping_status: "mapped",
    };
    const topo = indexTopology({
      devices: [
        leaf,
        { ...leaf, id: `aci:${"b".repeat(64)}`, name: "other", scope: "dc" },
      ],
      links: [],
      interfaces: [
        { device_id: leaf.id, interface: "Ethernet1/49", ifindex: 49 },
      ],
      warnings: [],
    });
    const context = {
      scope: "campus-aci",
      cluster: "cilium-aci-east",
      authority: "https://catalyst-center.example.invalid",
    };
    const sample = observation({ exporter: "192.0.2.10" });
    expect(vlanInterface(sample, topo, context)).toBe("Eth1/49");
    expect(vlanExporter(sample, topo, context)).toBe("leaf-101 (192.0.2.10)");
    expect(vlanInterface(sample, topo, { scope: "elsewhere" })).toBe(
      "ifIndex 49",
    );
    for (const partial of [
      { scope: "campus-aci" },
      { cluster: "cilium-aci-east" },
      {},
    ]) {
      expect(vlanInterface(sample, topo, partial)).toBe("ifIndex 49");
      expect(vlanExporter(sample, topo, partial)).toBe("192.0.2.10");
    }
  });

  it("deduplicates contexts while retaining the broadest timing", () => {
    const result = vlanContexts([
      edge("one", [observation({ first_seen: 10, last_seen: 20 })]),
      edge("two", [observation({ first_seen: 5, last_seen: 30 })]),
    ]);
    expect(result.contexts).toHaveLength(1);
    expect(result.contexts[0]).toMatchObject({ first_seen: 5, last_seen: 30 });
  });

  it("caps aggregate contexts and surfaces edge truncation", () => {
    const observations = Array.from({ length: 33 }, (_, i) =>
      observation({ vlan: i + 1 }),
    );
    expect(vlanContexts([edge("one", observations)]).truncated).toBe(true);
    expect(vlanContexts([edge("one", observations)]).contexts).toHaveLength(32);
    expect(
      vlanContexts([
        { ...edge("one", [observation()]), vlan_observations_truncated: true },
      ]).truncated,
    ).toBe(true);
  });

  it("keeps contexts on distinct interfaces and retains truncation-only edges", () => {
    const first = observation({ interface_index: "49" });
    const second = observation({ interface_index: "50" });
    expect(vlanContexts([edge("one", [first, second])]).contexts).toHaveLength(
      2,
    );
    const graph = {
      schema_version: 1 as const,
      snapshot_id: "x",
      generated_at: "2026-01-01T00:00:00Z",
      demo: false,
      window: { start: "2026-01-01T00:00:00Z", end: "2026-01-01T01:00:00Z" },
      boundary: {
        id: "b",
        service: "s",
        environment: "e",
        cluster: "c",
        namespace: "n",
        root_node_id: "svc",
      },
      nodes: [
        { id: "svc", label: "svc", kind: "service" as const },
        { id: "a", label: "a", kind: "endpoint" as const },
        { id: "b", label: "b", kind: "endpoint" as const },
      ],
      edges: [
        {
          ...edge("truncated", []),
          source: "a",
          target: "b",
          vlan_observations_truncated: true,
        },
      ],
      coverage: {
        spans: 0,
        conversations: 0,
        matched_conversations: 0,
        unresolved_conversations: 0,
        ambiguous_conversations: 0,
        warnings: [],
      },
    };
    expect(vlanEdges(indexGraph(graph), "a")).toHaveLength(1);
  });
});
