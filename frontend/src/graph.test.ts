import { describe, expect, it } from "vitest";
import { directionLabel } from "./glossary";
import {
  indexGraph,
  matchesQuery,
  parseGraph,
  validTrafficObservation,
  type Graph,
} from "./graph";
import { demoGraph } from "./provider";

const demo = demoGraph("nxos");
const clone = (): Record<string, any> => structuredClone(demo);
const handoffClone = (): Record<string, any> =>
  structuredClone(demoGraph("nxos"));
const kindOf = (g: Record<string, any>, id: string) =>
  g.nodes.find((n: { id: string }) => n.id === id).kind;
const edgeOf = (g: Record<string, any>, relationship: string) =>
  g.edges.find(
    (e: { relationship: string }) => e.relationship === relationship,
  );

describe("parseGraph", () => {
  it("accepts the demo fixture", () => {
    const g = parseGraph(clone());
    expect(g.boundary.root_node_id).toBe(demo.boundary.root_node_id);
    expect(g.nodes.length).toBeGreaterThan(0);
  });

  it("validates complete client handoff metadata against same-cluster pods", () => {
    const g = handoffClone();
    const cluster = g.boundary.cluster;
    const service = {
      id: "endpoint:k8s_service:test-service",
      label: "test-service",
      kind: "endpoint",
      endpoint_kind: "k8s_service",
      cluster,
    };
    const pod = {
      id: `pod:${cluster}/handoff/backend-a`,
      label: "backend-a",
      kind: "workload",
      cluster,
    };
    const client = {
      id: "network_client:test-client",
      label: "test-client",
      kind: "client",
      endpoint_kind: "network_client",
      addresses: ["192.0.2.40"],
    };
    g.nodes.push(pod, client, service);
    const edge = {
      id: "client-edge:tcp-443",
      source: client.id,
      target: service.id,
      relationship: "communicates_with",
      evidence: ["test"],
      confidence: "correlated",
      count: 1,
      server_port: 443,
      transport: "tcp",
      client_handoff_coverage: "complete",
      client_handoff_connections: 2,
      client_handoff_determined: 2,
      client_handoff_unresolved: 0,
      client_handoffs: [
        {
          target: pod.id,
          basis: "hubble_client_tuple",
          connections: 2,
          receiving_nodes: ["node-a"],
          observers: ["hubble:node-a"],
        },
      ],
    };
    g.edges.push(edge);
    expect(parseGraph(g).edges.at(-1)).toMatchObject(edge);

    edge.client_handoff_connections = 1;
    expect(() => parseGraph(g)).toThrow(/client handoff metadata/);
    edge.client_handoff_connections = 2;
    edge.client_handoff_coverage = "unknown";
    expect(() => parseGraph(g)).toThrow();
  });

  it("accepts pipeline client source kinds and rejects Service sources", () => {
    const make = () => {
      const g = handoffClone();
      const cluster = g.boundary.cluster;
      const service = {
        id: "endpoint:k8s_service:test-service",
        label: "test-service",
        kind: "endpoint",
        endpoint_kind: "k8s_service",
        cluster,
      };
      const pod = {
        id: `pod:${cluster}/handoff/backend-a`,
        label: "backend-a",
        kind: "workload",
        cluster,
      };
      const vm = {
        id: "vm:test-client",
        label: "test-client",
        kind: "endpoint",
        endpoint_kind: "vm",
      };
      const edge = {
        id: "vm-client-edge:tcp-443",
        source: vm.id,
        target: service.id,
        relationship: "communicates_with",
        evidence: ["test"],
        confidence: "correlated",
        count: 1,
        client_handoff_coverage: "complete",
        client_handoff_connections: 1,
        client_handoff_determined: 1,
        client_handoff_unresolved: 0,
        client_handoffs: [
          {
            target: pod.id,
            basis: "hubble_client_tuple",
            connections: 1,
            receiving_nodes: [],
            observers: [],
          },
        ],
      };
      g.nodes.push(pod, vm, service);
      g.edges.push(edge);
      return { g, edge, vm };
    };

    const validVm = make();
    expect(parseGraph(validVm.g).edges.at(-1)).toMatchObject(validVm.edge);

    for (const endpointKind of [
      "k8s_node",
      "k8s_node_proxy",
      "ambiguous",
      "unresolved",
      "external",
    ]) {
      const sourceCase = make();
      sourceCase.vm.endpoint_kind = endpointKind;
      expect(parseGraph(sourceCase.g).edges.at(-1)).toMatchObject(
        sourceCase.edge,
      );
    }

    const networkClientSource = make();
    networkClientSource.vm.kind = "client";
    networkClientSource.vm.endpoint_kind = "network_client";
    expect(parseGraph(networkClientSource.g).edges.at(-1)).toMatchObject(
      networkClientSource.edge,
    );

    const workloadSource = make();
    workloadSource.vm.kind = "workload";
    (workloadSource.vm as { endpoint_kind?: string }).endpoint_kind = undefined;
    expect(parseGraph(workloadSource.g).edges.at(-1)).toMatchObject(
      workloadSource.edge,
    );

    const serviceSource = make();
    serviceSource.vm.endpoint_kind = "k8s_service";
    expect(() => parseGraph(serviceSource.g)).toThrow(
      /invalid client handoff metadata/,
    );
  });

  it("accepts the captured unresolved IP handoff without promoting its identity", () => {
    const g = demoGraph("catalyst-aci");
    const sourceId = "ip:campus-aci/10.61.0.20";
    const edge = g.edges.find(
      (candidate) =>
        candidate.relationship === "communicates_with" &&
        candidate.source === sourceId &&
        candidate.target ===
          "k8s_service:cilium-aci-east/shop/checkout-api/10.50.0.20:8080",
    );
    expect(edge?.client_handoff_coverage).toBe("complete");
    const parsed = parseGraph(g);
    expect(parsed.nodes.find((node) => node.id === sourceId)).toMatchObject({
      kind: "endpoint",
      endpoint_kind: "unresolved",
    });
    expect(parsed.edges.find((candidate) => candidate.id === edge?.id)).toBe(
      edge,
    );
  });

  it("rejects duplicate, cross-cluster, oversized, and falsely empty handoff metadata", () => {
    const make = () => {
      const g = handoffClone();
      const cluster = g.boundary.cluster;
      const service = {
        id: "endpoint:k8s_service:test-service",
        label: "test-service",
        kind: "endpoint",
        endpoint_kind: "k8s_service",
        cluster,
      };
      const pod = {
        id: `pod:${cluster}/handoff/backend-a`,
        label: "backend-a",
        kind: "workload",
        cluster,
      };
      const client = {
        id: "network_client:test-client",
        label: "test-client",
        kind: "client",
        endpoint_kind: "network_client",
      };
      g.nodes.push(pod, client, service);
      const edge = {
        id: "client-edge:tcp-443",
        source: client.id,
        target: service.id,
        relationship: "communicates_with",
        evidence: ["test"],
        confidence: "correlated",
        count: 1,
        client_handoff_coverage: "complete",
        client_handoff_connections: 1,
        client_handoff_determined: 1,
        client_handoff_unresolved: 0,
        client_handoffs: [
          {
            target: pod.id,
            basis: "hubble_client_tuple",
            connections: 1,
            receiving_nodes: [],
            observers: [] as string[],
          },
        ],
      };
      g.edges.push(edge);
      return { g, edge, pod, cluster };
    };
    const duplicate = make();
    duplicate.edge.client_handoffs.push({
      ...duplicate.edge.client_handoffs[0],
      connections: 1,
    });
    duplicate.edge.client_handoff_connections = 2;
    duplicate.edge.client_handoff_determined = 2;
    expect(() => parseGraph(duplicate.g)).toThrow();

    const foreign = make();
    foreign.edge.client_handoffs[0].target =
      "pod:other-cluster/handoff/backend-a";
    expect(() => parseGraph(foreign.g)).toThrow();

    const oversized = make();
    oversized.edge.client_handoffs[0].observers =
      Array(65).fill("hubble:node-a");
    expect(() => parseGraph(oversized.g)).toThrow();

    const emptyPartial = make();
    emptyPartial.edge.client_handoff_coverage = "partial";
    emptyPartial.edge.client_handoff_determined = 0;
    emptyPartial.edge.client_handoff_unresolved = 1;
    emptyPartial.edge.client_handoff_connections = 1;
    emptyPartial.edge.client_handoffs = [];
    expect(() => parseGraph(emptyPartial.g)).toThrow();
  });

  it("accepts an optional evidence_truncated flag and rejects non-booleans", () => {
    const g = clone();
    g.edges[0].evidence_truncated = true;
    expect(() => parseGraph(g)).not.toThrow();
    g.edges[0].evidence_truncated = "yes";
    expect(() => parseGraph(g)).toThrow(/invalid relationships/);
  });

  it("accepts and validates optional NetFlow VLAN observations", () => {
    const g = clone();
    const edge = edgeOf(g, "communicates_with");
    edge.vlan_observations = [
      {
        vlan: 120,
        position: "ingress",
        exporter: "leaf-101",
        interface_index: "49",
        src_ip: "10.0.0.1",
        dest_ip: "10.0.0.2",
        first_seen: 1_700_000_000,
        last_seen: 1_700_000_001,
      },
    ];
    edge.vlan_observations_truncated = true;
    expect(
      parseGraph(g).edges.find((e) => e.id === edge.id)?.vlan_observations,
    ).toHaveLength(1);
    edge.vlan_observations[0].vlan = 4095;
    expect(() => parseGraph(g)).toThrow(/invalid relationships/);
  });

  it("accepts only complete, changed, scoped FTD NAT observations", () => {
    const g = clone();
    const edge = edgeOf(g, "communicates_with");
    edge.nat_observations = [
      {
        source_authority: "cisco:sfw:estreamer",
        event_type: "ConnectionEvent",
        scope: "firewall-prod",
        scope_mapping_verified: true,
        device_ip: "192.0.2.1",
        event_fingerprint: "a".repeat(64),
        event_time: 1_791_373_808,
        received_time: 1_791_373_809,
        protocol: "tcp",
        direction: "initiator_to_responder",
        reported_initiator_ip: "198.51.100.8",
        reported_initiator_port: 51400,
        reported_responder_ip: "203.0.113.10",
        reported_responder_port: 443,
        translated_initiator_ip: "192.0.2.44",
        translated_initiator_port: 35000,
        translated_responder_ip: "203.0.113.10",
        translated_responder_port: 443,
      },
    ];
    expect(
      parseGraph(g).edges.find((item) => item.id === edge.id)?.nat_observations,
    ).toHaveLength(1);

    edge.nat_observations[0].scope_mapping_verified = false;
    expect(() => parseGraph(g)).toThrow(/invalid relationships/);
  });

  it("validates FTD NAT evidence against the selected half-open time window", () => {
    const g = clone();
    const edge = edgeOf(g, "communicates_with");
    const start = Date.parse(g.window.start) / 1000;
    const end = Date.parse(g.window.end) / 1000;
    const observation = {
      source_authority: "cisco:sfw:estreamer" as const,
      event_type: "ConnectionEvent" as const,
      scope: "firewall-prod",
      scope_mapping_verified: true as const,
      device_ip: "192.0.2.1",
      event_fingerprint: "a".repeat(64),
      event_time: start,
      received_time: end,
      protocol: "tcp" as const,
      direction: "initiator_to_responder" as const,
      reported_initiator_ip: "198.51.100.8",
      reported_initiator_port: 51400,
      reported_responder_ip: "203.0.113.10",
      reported_responder_port: 443,
      translated_initiator_ip: "192.0.2.44",
      translated_initiator_port: 35000,
      translated_responder_ip: "203.0.113.10",
      translated_responder_port: 443,
    };
    edge.nat_observations = [
      observation,
      {
        ...observation,
        event_fingerprint: "b".repeat(64),
        event_time: end - 1,
      },
    ];
    expect(() => parseGraph(g)).not.toThrow();

    for (const eventTime of [start - 1, end]) {
      const invalid = structuredClone(g);
      invalid.edges.find(
        (candidate: { id: string }) => candidate.id === edge.id,
      ).nat_observations[0].event_time = eventTime;
      expect(() => parseGraph(invalid)).toThrow(/invalid relationships/);
    }
  });

  it("uses exact fractional NAT bounds instead of the rounded display window", () => {
    const graph = clone();
    const edge = edgeOf(graph, "communicates_with");
    const displayStart = Math.floor(Date.parse(graph.window.start) / 1000);
    const displayEnd = Math.floor(Date.parse(graph.window.end) / 1000);
    const observation = {
      source_authority: "cisco:sfw:estreamer" as const,
      event_type: "ConnectionEvent" as const,
      scope: "firewall-prod",
      scope_mapping_verified: true as const,
      device_ip: "192.0.2.1",
      event_fingerprint: "c".repeat(64),
      event_time: displayEnd,
      received_time: displayEnd + 1,
      protocol: "tcp" as const,
      direction: "initiator_to_responder" as const,
      reported_initiator_ip: "198.51.100.8",
      reported_initiator_port: 51400,
      reported_responder_ip: "203.0.113.10",
      reported_responder_port: 443,
      translated_initiator_ip: "192.0.2.44",
      translated_initiator_port: 35000,
      translated_responder_ip: "203.0.113.10",
      translated_responder_port: 443,
    };
    graph.nat_event_window = {
      start: displayStart + 0.25,
      end: displayEnd + 0.0005,
    };
    edge.nat_observations = [observation];
    expect(() => parseGraph(graph)).not.toThrow();

    graph.nat_event_window.end = displayEnd;
    expect(() => parseGraph(graph)).toThrow(/invalid relationships/);
  });

  it("rejects conflicting FTD NAT tuples with one event fingerprint", () => {
    const g = clone();
    const edge = edgeOf(g, "communicates_with");
    const observation = {
      source_authority: "cisco:sfw:estreamer" as const,
      event_type: "ConnectionEvent" as const,
      scope: "firewall-prod",
      scope_mapping_verified: true as const,
      device_ip: "192.0.2.1",
      event_fingerprint: "a".repeat(64),
      event_time: 1_791_373_808,
      received_time: 1_791_373_809,
      protocol: "tcp" as const,
      direction: "initiator_to_responder" as const,
      reported_initiator_ip: "198.51.100.8",
      reported_initiator_port: 51400,
      reported_responder_ip: "203.0.113.10",
      reported_responder_port: 443,
      translated_initiator_ip: "192.0.2.44",
      translated_initiator_port: 35000,
      translated_responder_ip: "203.0.113.10",
      translated_responder_port: 443,
    };
    edge.nat_observations = [
      observation,
      { ...observation, translated_initiator_ip: "192.0.2.45" },
    ];
    expect(() => parseGraph(g)).toThrow(/invalid relationships/);
  });

  it("accepts only documented attachment evidence text and finite scalar fields", () => {
    const g = clone();
    const edge = edgeOf(g, "communicates_with");
    edge.attachment_evidence = [
      {
        device_id: "meraki:serial-hash",
        client_authority: "org/network",
        event_time: 1_700_000_000,
        received_time: "1700000001.5",
        ssid_number: 7,
      },
    ];
    expect(() => parseGraph(g)).not.toThrow();

    edge.attachment_evidence[0].device_id = 42;
    expect(() => parseGraph(g)).toThrow(/invalid relationships/);
  });

  it.each([
    ["numeric authority", { client_authority: 42 }],
    ["invalid event time", { event_time: "yesterday" }],
    ["non-finite receive time", { received_time: Number.POSITIVE_INFINITY }],
    ["non-finite SSID", { ssid_number: Number.NaN }],
  ])("rejects attachment evidence with %s", (_label, invalidField) => {
    const g = clone();
    const edge = edgeOf(g, "communicates_with");
    edge.attachment_evidence = [
      { device_id: "meraki:serial-hash", ...invalidField },
    ];
    expect(() => parseGraph(g)).toThrow(/invalid relationships/);
  });

  it.each([4095, 4099])(
    "rejects saved VLAN %s while accepting 4094",
    (vlan) => {
      const g = clone();
      const edge = edgeOf(g, "communicates_with");
      edge.vlan_observations = [
        {
          vlan,
          position: "egress",
          exporter: "192.0.2.1",
          src_ip: "10.0.0.1",
          dest_ip: "10.0.0.2",
          first_seen: 1,
          last_seen: 2,
        },
      ];
      expect(() => parseGraph(g)).toThrow();
      edge.vlan_observations[0].vlan = 4094;
      expect(() => parseGraph(g)).not.toThrow();
    },
  );

  it("accepts an empty graph whose root is absent", () => {
    const g = clone();
    g.nodes = [];
    g.edges = [];
    expect(() => parseGraph(g)).not.toThrow();
  });

  it.each([
    [
      "endpoint_kind on a workload",
      (g: any) => {
        g.nodes.find((n: any) => n.kind === "workload").endpoint_kind = "vm";
      },
    ],
    [
      "unknown endpoint_kind",
      (g: any) => {
        g.nodes.find((n: any) => n.kind === "endpoint").endpoint_kind =
          "router";
      },
    ],
    [
      "non-string attribute",
      (g: any) => {
        g.nodes.find((n: any) => n.attributes).attributes.epg = 5;
      },
    ],
    [
      "out-of-range server_port",
      (g: any) => {
        edgeOf(g, "communicates_with").server_port = 70000;
      },
    ],
    [
      "unknown direction_basis",
      (g: any) => {
        edgeOf(g, "communicates_with").direction_basis = "guess";
      },
    ],
    [
      "array direction_basis",
      (g: any) => {
        edgeOf(g, "communicates_with").direction_basis = ["unknown"];
      },
    ],
    [
      "non-array sources",
      (g: any) => {
        edgeOf(g, "communicates_with").sources = "netflow";
      },
    ],
    [
      "old coverage shape",
      (g: any) => {
        g.coverage = {
          spans: 1,
          flows: 1,
          matched_flows: 1,
          unresolved_flows: 0,
          warnings: [],
        };
      },
    ],
  ])("rejects %s", (_name, mutate) => {
    const g = clone();
    mutate(g);
    expect(() => parseGraph(g)).toThrow();
  });

  it.each([
    ["empty snapshot id", (g: any) => (g.snapshot_id = "")],
    ["empty node id", (g: any) => (g.nodes[0].id = "")],
    ["empty edge id", (g: any) => (g.edges[0].id = "")],
    ["empty boundary id", (g: any) => (g.boundary.id = "")],
  ])("rejects %s", (_name, mutate) => {
    const g = clone();
    mutate(g);
    expect(() => parseGraph(g)).toThrow();
  });

  it("rejects a root that is not a service", () => {
    const g = clone();
    const workload = g.nodes.find(
      (n: { kind: string }) => n.kind === "workload",
    );
    g.boundary.root_node_id = workload.id;
    expect(() => parseGraph(g)).toThrow(/not a service/);
  });

  it("rejects a missing root", () => {
    const g = clone();
    g.boundary.root_node_id = "service:nope";
    expect(() => parseGraph(g)).toThrow(/root/);
  });

  it("rejects runs_on from a service to a service", () => {
    const g = clone();
    const e = edgeOf(g, "runs_on");
    const other = g.nodes.find(
      (n: { kind: string; id: string }) =>
        n.kind === "service" && n.id !== e.source,
    );
    e.target = other.id;
    expect(() => parseGraph(g)).toThrow(/incompatible node kinds/);
  });

  it("rejects calls into a workload", () => {
    const g = clone();
    const e = edgeOf(g, "calls");
    e.target = edgeOf(g, "runs_on").target;
    expect(kindOf(g, e.target)).toBe("workload");
    expect(() => parseGraph(g)).toThrow(/incompatible node kinds/);
  });

  it("rejects communicates_with involving a service", () => {
    const g = clone();
    const e = edgeOf(g, "communicates_with");
    e.source = g.boundary.root_node_id;
    expect(() => parseGraph(g)).toThrow(/incompatible node kinds/);
  });

  it.each([
    ["numeric-looking generated_at", (g: any) => (g.generated_at = "1")],
    [
      "timezone-less generated_at",
      (g: any) => (g.generated_at = "2026-10-07T12:00:00"),
    ],
    ["date-only window", (g: any) => (g.window.start = "2026-10-07")],
    [
      "reversed window",
      (g: any) => {
        [g.window.start, g.window.end] = [g.window.end, g.window.start];
      },
    ],
    ["zero-length window", (g: any) => (g.window.start = g.window.end)],
  ])("rejects %s", (_name, mutate) => {
    const g = clone();
    mutate(g);
    expect(() => parseGraph(g)).toThrow();
  });

  it("accepts offsets and fractional seconds", () => {
    const g = clone();
    g.generated_at = "2026-10-07T14:00:00.123456+02:00";
    expect(() => parseGraph(g)).not.toThrow();
  });

  it("rejects dangling edge references", () => {
    const g = clone();
    g.edges[0].target = "workload:missing";
    expect(() => parseGraph(g)).toThrow(/invalid relationships/);
  });
});

describe("traffic observation scalar metadata", () => {
  it("accepts finite numeric or textual raw sampling values and rejects non-finite numbers", () => {
    const base = { source: "stream_ipfix", raw_sampling: 100 };
    expect(validTrafficObservation(base)).toBe(true);
    expect(validTrafficObservation({ ...base, raw_sampling: "100" })).toBe(
      true,
    );
    expect(
      validTrafficObservation({
        ...base,
        raw_sampling: Number.POSITIVE_INFINITY,
      }),
    ).toBe(false);
  });
});

describe("graph helpers", () => {
  const g = parseGraph(clone()) as Graph;
  it("indexes incident and outgoing edges", () => {
    const index = indexGraph(g);
    const root = g.boundary.root_node_id;
    expect(index.node.get(root)?.kind).toBe("service");
    for (const e of index.outgoing.get(root) ?? []) expect(e.source).toBe(root);
    const incidentCount = g.edges.filter(
      (e) => e.source === root || e.target === root,
    ).length;
    expect(index.incident.get(root)?.length).toBe(incidentCount);
  });
  it("matches attributes such as VM name and EPG", () => {
    const vm = g.nodes.find((n) => n.endpoint_kind === "vm")!;
    expect(matchesQuery(vm, "orders-db")).toBe(true);
    expect(matchesQuery(vm, "EPG")).toBe(false);
    expect(matchesQuery(vm, "db")).toBe(true);
  });
  it("explains direction in plain words", () => {
    const edge = (basis: string, sources: string[]) =>
      ({ ...g.edges[0], direction_basis: basis, sources }) as Graph["edges"][0];
    expect(
      directionLabel(edge("initiator", ["netflow", "ftd", "isovalent"])),
    ).toBe("Initiator reported by Cisco FTD and Isovalent");
    expect(directionLabel(edge("port_rule", ["netflow"]))).toMatch(/ports/);
    expect(directionLabel(edge("unknown", []))).toBe("Direction unknown");
  });
  it("matches labels and addresses case-insensitively", () => {
    const withAddress = g.nodes.find((n) => n.addresses?.length)!;
    expect(matchesQuery(withAddress, withAddress.addresses![0])).toBe(true);
    expect(matchesQuery(withAddress, withAddress.label.toUpperCase())).toBe(
      true,
    );
    expect(matchesQuery(withAddress, "   ")).toBe(true);
    expect(matchesQuery(withAddress, "no-such-thing-zz")).toBe(false);
  });
});
