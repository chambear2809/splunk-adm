import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { Inspector } from "./Inspector";
import { indexGraph, type Graph } from "./graph";
import { demoGraph, demoTopology } from "./provider";
import { emptyTopology, indexTopology } from "./topology";

const noop = () => {};
const handoffGraph = (): Graph => ({
  schema_version: 1,
  snapshot_id: "client-handoff-inspector-test",
  generated_at: "2026-10-16T00:00:00Z",
  demo: true,
  window: { start: "2026-10-15T23:00:00Z", end: "2026-10-16T00:00:00Z" },
  boundary: {
    id: "frontend",
    service: "frontend",
    environment: "test",
    cluster: "cluster-a",
    namespace: "default",
    root_node_id: "service:cluster-a/default/frontend",
  },
  nodes: [
    {
      id: "service:cluster-a/default/frontend",
      label: "frontend",
      kind: "service",
      endpoint_kind: "k8s_service",
      cluster: "cluster-a",
      namespace: "default",
      attributes: {
        handoff_coverage: "partial",
        handoff_connections: "4",
        handoff_determined: "2",
        handoff_unresolved: "2",
      },
    },
    {
      id: "pod:cluster-a/default/aggregate-backend",
      label: "aggregate-backend",
      kind: "workload",
      cluster: "cluster-a",
      namespace: "default",
    },
    {
      id: "network_client:client-a",
      label: "client-a",
      kind: "client",
      endpoint_kind: "network_client",
      addresses: ["192.0.2.44"],
    },
  ],
  edges: [
    {
      id: "aggregate-forward",
      source: "service:cluster-a/default/frontend",
      target: "pod:cluster-a/default/aggregate-backend",
      relationship: "forwards_to",
      evidence: ["test"],
      confidence: "observed",
      count: 20,
      handoff_basis: "hubble_client_tuple",
    },
    {
      id: "client-edge",
      source: "network_client:client-a",
      target: "service:cluster-a/default/frontend",
      relationship: "communicates_with",
      evidence: ["test"],
      confidence: "correlated",
      count: 1,
      server_port: 443,
      transport: "tcp",
    },
  ],
  coverage: {
    spans: 0,
    conversations: 1,
    matched_conversations: 1,
    unresolved_conversations: 0,
    ambiguous_conversations: 0,
    warnings: [],
  },
});
const inspector = (
  graph: Graph,
  selection: { kind: "node" | "edge"; id: string },
  topo = indexTopology(emptyTopology()),
) =>
  renderToStaticMarkup(
    <Inspector
      selection={selection}
      index={indexGraph(graph)}
      topo={topo}
      onSelect={noop}
      onClose={noop}
      onShowPath={noop}
      summary={null}
    />,
  );

describe("network evidence inspectors", () => {
  it("withholds aggregate backend and receiving-node fields for partial client handoffs", () => {
    const graph = handoffGraph();
    const edge = graph.edges.find(
      (candidate) => candidate.id === "client-edge",
    )!;
    const service = graph.nodes.find((node) => node.id === edge.target)!;
    Object.assign(edge, {
      client_handoff_coverage: "partial",
      client_handoff_connections: 4,
      client_handoff_determined: 2,
      client_handoff_unresolved: 2,
      client_handoffs: [
        {
          target: "pod:cluster-a/default/aggregate-backend",
          basis: "hubble_client_tuple",
          connections: 2,
          receiving_nodes: ["client-receiver"],
          observers: ["hubble:client-proof"],
        },
      ],
    });
    edge.via_node = ["shared-receiving-node"];
    const backendLabel = "aggregate-backend";

    const html = inspector(graph, { kind: "edge", id: edge.id });
    expect(html).toContain("handoff coverage is partial");
    expect(html).toContain(
      "Backend and receiving-node assignments are unavailable",
    );
    expect(html).not.toContain("shared-receiving-node");
    expect(html).not.toContain(backendLabel);

    const aggregateHtml = inspector(graph, { kind: "node", id: service.id });
    expect(aggregateHtml).toContain("Any backend links shown here summarize");
    expect(aggregateHtml).toContain(
      "aggregate backends for determined connections",
    );
  });

  it("uses complete per-client handoffs even when shared frontend aggregates differ", () => {
    const graph = handoffGraph();
    const service = graph.nodes.find(
      (node) => node.endpoint_kind === "k8s_service",
    )!;
    const cluster = service.cluster ?? graph.boundary.cluster;
    service.attributes = {
      ...service.attributes,
      handoff_coverage: "complete",
      handoff_connections: "20",
      handoff_determined: "20",
      handoff_unresolved: "0",
    };
    const backendId = `pod:${cluster}/client-specific/backend`;
    graph.nodes.push({
      id: backendId,
      label: "client-specific-backend",
      kind: "workload",
      cluster,
    });
    const client = {
      id: "network_client:client-a",
      label: "client-a",
      kind: "client" as const,
      endpoint_kind: "network_client" as const,
      addresses: ["192.0.2.44"],
    };
    graph.nodes.push(client);
    graph.edges.push({
      id: "client-edge:client-a:443-tcp",
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
          target: backendId,
          basis: "hubble_client_tuple",
          connections: 1,
          receiving_nodes: ["receiver-a"],
          observers: ["hubble:client-a"],
        },
        {
          target: backendId,
          basis: "time_inferred",
          connections: 1,
          receiving_nodes: ["receiver-b"],
          observers: ["hubble:client-a-inferred"],
        },
      ],
    });
    const html = inspector(graph, {
      kind: "edge",
      id: "client-edge:client-a:443-tcp",
    });
    expect(html).toContain("client-specific-backend (2 connections");
    expect(html).toContain("Inferred from timing (1)");
    expect(html).toContain("receiver-a, receiver-b");
    const aggregateBackend = graph.nodes.find(
      (node) =>
        node.kind === "workload" &&
        graph.edges.some(
          (candidate) =>
            candidate.relationship === "forwards_to" &&
            candidate.target === node.id &&
            candidate.source === service.id,
        ),
    )!;
    expect(html).not.toContain(aggregateBackend.label);
  });

  it("resolves captured ND observer labels using agreed graph scope", () => {
    const graph = demoGraph("catalyst-aci");
    const vmId = "vm:campus-aci/10.20.30.40";
    const edge = graph.edges.find(
      (candidate) =>
        candidate.relationship === "communicates_with" &&
        (candidate.source === vmId || candidate.target === vmId),
    )!;
    const html = inspector(
      graph,
      { kind: "edge", id: edge.id },
      indexTopology(demoTopology("catalyst-aci")),
    );
    expect(html).toContain("leaf-102");
  });

  it("keeps unverified counters as per-observation evidence and separates records from connections", () => {
    const graph = structuredClone(demoGraph("nxos"));
    const edge = graph.edges.find(
      (candidate) => candidate.relationship === "communicates_with",
    )!;
    edge.traffic_observations = [
      {
        source: "cisco_sdwan_ipfix",
        exporter_ip: "192.0.2.10",
        flow_id: "flow-8",
        first_seen: 100,
        last_seen: 110,
        bytes_in: 2048,
        records: 1,
        counter_semantics: "stream_profile_required",
        metrics_authoritative: false,
        quality_status: "accepted_with_warning",
        quality_warnings: "direction_missing",
        ingress_overlay_session_id: "overlay-12",
        egress_overlay_session_id: "overlay-34",
        raw_bytes_in: 1200,
        raw_bytes_out: 3400,
        raw_packets_in: 12,
        raw_packets_out: 34,
        raw_sampling: "100",
      },
    ];
    const html = inspector(graph, { kind: "edge", id: edge.id });
    expect(html).toContain("Not aggregated from flow records");
    expect(html).toContain("Not aggregated; see per-observation counters");
    expect(html).toContain("1 flow records");
    expect(html).toContain("counters are not authoritative");
    expect(html).toContain("Routing domain and source scope unavailable");
    expect(html).toContain("Raw exporter values (non-authoritative)");
    expect(html).toContain("bytes in 1200");
    expect(html).toContain("bytes out 3400");
    expect(html).toContain("packets in 12");
    expect(html).toContain("sampling 100");
    expect(html).toContain("Flow flow-8");
    expect(html).toContain("Quality accepted with warning");
    expect(html).toContain("Quality warnings: direction_missing");
    expect(html).toContain("Overlay session references (unjoined)");
    expect(html).toContain("ingress overlay-12");
    expect(html).toContain("do not establish a tunnel peer or packet route");
  });

  it("does not infer an unmapped scope from an empty routing domain", () => {
    const graph = structuredClone(demoGraph("nxos"));
    const edge = graph.edges.find(
      (candidate) => candidate.relationship === "communicates_with",
    )!;
    edge.traffic_observations = [
      {
        source: "stream_ipfix",
        source_ip: "10.61.0.20",
        destination_ip: "10.61.0.30",
        server_port: 443,
        transport: "tcp",
        mapping_status: "mapped",
        scope: "meraki-nxos",
        cluster: "cilium-nxos-west",
      },
    ];
    const html = inspector(graph, { kind: "edge", id: edge.id });
    expect(html).toContain(
      "Routing domain not reported; source scope is meraki-nxos",
    );
    expect(html).not.toContain("not mapped to a unique source scope");
  });

  it("renders malformed quality metadata safely if a caller bypasses graph validation", () => {
    const graph = structuredClone(demoGraph("nxos"));
    const edge = graph.edges.find(
      (candidate) => candidate.relationship === "communicates_with",
    )!;
    edge.traffic_observations = [{ quality_status: ["accepted"] } as never];
    const html = inspector(graph, { kind: "edge", id: edge.id });
    expect(html).toContain("Quality unavailable");
  });

  it("marks point events, stale evidence, and scope gaps without claiming attachment", () => {
    const graph = structuredClone(demoGraph("nxos"));
    const client = graph.nodes.find((node) => node.kind === "endpoint")!;
    client.endpoint_kind = "network_client";
    client.attributes = {
      source_authority: "org-a/network-a",
      routing_domain: "",
      attachment_basis: "meraki_association_event",
      attachment_status: "unmapped",
      attachment_event_time: "100",
      attachment_received_time: "101",
      ssid_number: "7",
    };
    const html = inspector(graph, { kind: "node", id: client.id });
    expect(html).toContain("no unambiguous routing scope");
    expect(html).toContain("meraki_association_event");
    expect(html).toContain("SSID number");
    expect(html).not.toContain("Correlated from association and flow evidence");
  });
});
