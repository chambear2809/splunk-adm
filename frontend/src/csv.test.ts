import { describe, expect, it } from "vitest";
import {
  contextEvidenceCsv,
  CONTEXT_EVIDENCE_COLUMNS,
  csvCell,
  FLOW_COLUMNS,
  requiredFlowsCsv,
} from "./csv";
import { indexGraph } from "./graph";
import { demoGraph, demoTopology } from "./provider";
import { indexTopology } from "./topology";

describe("csvCell", () => {
  it.each([
    ['=HYPERLINK("x")', `"'=HYPERLINK(""x"")"`],
    ["+1", "'+1"],
    ["-1+2", "'-1+2"],
    ["@SUM(A1)", "'@SUM(A1)"],
    ["\tcmd", "'\tcmd"],
    ["\rcmd", `"'\rcmd"`],
    ["a,b", '"a,b"'],
    ['say "hi"', '"say ""hi"""'],
    ["line\nbreak", '"line\nbreak"'],
    ["10.42.0.20", "10.42.0.20"],
    [undefined, ""],
    [5432, "5432"],
  ])("escapes %j", (input, out) => {
    expect(csvCell(input)).toBe(out);
  });
});

describe("requiredFlowsCsv", () => {
  const graph = demoGraph("nxos");
  const csv = requiredFlowsCsv(
    graph,
    indexGraph(graph),
    indexTopology(demoTopology("nxos")),
  );
  const lines = csv.trimEnd().split("\r\n");
  it("writes a header and one row per conversation", () => {
    expect(lines[0]).toBe(FLOW_COLUMNS.join(","));
    expect(lines).toHaveLength(
      1 +
        graph.edges.filter((e) => e.relationship === "communicates_with")
          .length,
    );
  });
  it("includes EPG, port, identity and hostname-first devices", () => {
    const db = lines.find(
      (l) => l.includes("orders-db-01") && l.includes("5432"),
    )!;
    expect(db).toContain("checkout-5f8b9c7d6-m4n7q,Pod,10.42.0.20,,shop");
    expect(db).toContain("orders-db-01,VM,10.20.30.40,db,");
    expect(db).toContain(",5432,tcp,initiator,Identified,");
    expect(db).toContain("leaf-101");
    const ext = lines.find((l) => l.includes("203.0.113.40"))!;
    expect(ext).toContain(",External,");
    expect(ext).toContain("ftd-edge");
  });

  it("resolves captured ACI observer aliases with edge scope in CSV output", () => {
    const captured = demoGraph("catalyst-aci");
    const edge = captured.edges.find(
      (candidate) =>
        candidate.relationship === "communicates_with" &&
        (candidate.source === "vm:campus-aci/10.20.30.40" ||
          candidate.target === "vm:campus-aci/10.20.30.40"),
    )!;
    const output = requiredFlowsCsv(
      captured,
      indexGraph(captured),
      indexTopology(demoTopology("catalyst-aci")),
    );
    const row = output
      .trimEnd()
      .split("\r\n")
      .find(
        (line) =>
          line.includes("10.20.30.40") &&
          edge.observers?.some((observer) => observer.startsWith("nd:")) &&
          line.includes("leaf-102"),
      );
    expect(row).toContain("leaf-102");
  });

  it("resolves an IPFIX exporter in Seen by when the edge carries a controller authority", () => {
    const captured = structuredClone(demoGraph("catalyst-aci"));
    const edge = captured.edges.find(
      (candidate) =>
        candidate.relationship === "communicates_with" &&
        (candidate.source === "vm:campus-aci/10.20.30.40" ||
          candidate.target === "vm:campus-aci/10.20.30.40"),
    )!;
    for (const id of [edge.source, edge.target]) {
      const node = captured.nodes.find((item) => item.id === id)!;
      if (node.attributes) delete node.attributes.source_authority;
    }
    Object.assign(edge, {
      source_authority: "https://catalyst-center.example.invalid",
      observers: ["netflow:192.0.2.102:ifIndex 436400128>"],
    });
    const output = requiredFlowsCsv(
      captured,
      indexGraph(captured),
      indexTopology(demoTopology("catalyst-aci")),
    );
    expect(output).toContain("leaf-102");
    expect(output).not.toMatch(/aci:[a-f0-9]{64}/);
  });

  it("does not name a same-IP network client for an unresolved exporter in Seen by", () => {
    const captured = structuredClone(demoGraph("catalyst-aci"));
    const topology = structuredClone(demoTopology("catalyst-aci"));
    const edge = captured.edges.find(
      (candidate) =>
        candidate.relationship === "communicates_with" &&
        (candidate.source === "vm:campus-aci/10.20.30.40" ||
          candidate.target === "vm:campus-aci/10.20.30.40"),
    )!;
    const leaf = topology.devices.find(
      (device) => device.mgmt_ip === "192.0.2.102",
    )!;
    leaf.mgmt_ip = "192.0.2.199";
    const client = topology.devices.find(
      (device) => device.kind === "network_client",
    )!;
    client.mgmt_ip = "192.0.2.102";
    client.name = "SHADOW-CLIENT-NAME";
    client.scope = leaf.scope;
    client.cluster = leaf.cluster;
    edge.observers = ["netflow:192.0.2.102:ifIndex 436400128>"];
    const output = requiredFlowsCsv(
      captured,
      indexGraph(captured),
      indexTopology(topology),
    );
    expect(output).not.toContain("SHADOW-CLIENT-NAME");
    expect(output).toContain("Exporter 192.0.2.102");
  });

  it("does not export aggregate backend choices as a client-specific handoff", () => {
    const captured = structuredClone(demoGraph("catalyst-aci"));
    const edge = captured.edges.find(
      (candidate) =>
        candidate.relationship === "communicates_with" &&
        captured.nodes.find((node) => node.id === candidate.target)
          ?.endpoint_kind === "k8s_service",
    )!;
    const service = captured.nodes.find((node) => node.id === edge.target)!;
    service.attributes = {
      ...service.attributes,
      handoff_coverage: "partial",
      handoff_connections: "4",
      handoff_determined: "2",
      handoff_unresolved: "2",
    };
    const candidate = captured.edges.find(
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
    const source = captured.nodes.find((node) => node.id === edge.source)!;
    const target = service;
    const backendLabel = captured.nodes.find(
      (node) => node.id === candidate.target,
    )!.label;
    const output = requiredFlowsCsv(
      captured,
      indexGraph(captured),
      indexTopology(demoTopology("catalyst-aci")),
    );
    const row = output
      .trimEnd()
      .split("\r\n")
      .map((line) => line.split(","))
      .find((cells) => cells[0] === source.label && cells[5] === target.label)!;
    expect(row[FLOW_COLUMNS.indexOf("backend")]).toContain(
      "handoff coverage is partial",
    );
    expect(row[FLOW_COLUMNS.indexOf("handoff")]).toBe(
      "unavailable for individual client",
    );
    expect(row[FLOW_COLUMNS.indexOf("backend")]).not.toContain(backendLabel);
  });

  it("exports observed VLAN evidence and truncation state", () => {
    const graphWithVlan = structuredClone(graph);
    const edge = graphWithVlan.edges.find(
      (candidate) => candidate.relationship === "communicates_with",
    )!;
    edge.vlan_observations = [
      {
        vlan: 120,
        position: "ingress",
        exporter: "198.51.100.10",
        src_ip: "10.0.0.1",
        dest_ip: "10.0.0.2",
        first_seen: 1,
        last_seen: 2,
      },
    ];
    edge.vlan_observations_truncated = true;
    const output = requiredFlowsCsv(
      graphWithVlan,
      indexGraph(graphWithVlan),
      indexTopology(demoTopology("nxos")),
    );
    expect(output).toContain('""vlan"":120');
    expect(output).toContain(']",1,');
  });

  it("exports exact selected time bounds with NAT evidence", () => {
    const graphWithNat = structuredClone(graph);
    const edge = graphWithNat.edges.find(
      (candidate) => candidate.relationship === "communicates_with",
    )!;
    graphWithNat.nat_event_window = {
      start: 1791373500.25,
      end: 1791374400.0005,
    };
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
    edge.nat_observations_truncated = true;
    const output = requiredFlowsCsv(
      graphWithNat,
      indexGraph(graphWithNat),
      indexTopology(demoTopology("nxos")),
    );
    expect(FLOW_COLUMNS).toContain("nat_window_start");
    expect(FLOW_COLUMNS).toContain("nat_window_end");
    expect(output).toContain(']",1,1791373500.25,1791374400.0005,exact,');
  });
});

describe("contextEvidenceCsv", () => {
  it("exports late Catalyst source and receipt provenance without inventing collection time", () => {
    const contextGraph = structuredClone(demoGraph("nxos"));
    const edge = contextGraph.edges.find(
      (candidate) => candidate.relationship === "communicates_with",
    )!;
    edge.attachment_evidence = [
      {
        basis: "catalyst_client_snapshot",
        status: "observed_snapshot",
        client_source: "catalyst_client_snapshot",
        client_authority: "center-a",
        client_native_id: "client-a",
        event_time: 100,
        received_time: 259300,
      },
    ];
    const csv = contextEvidenceCsv(contextGraph);
    expect(csv).toContain('""event_time"":100');
    expect(csv).toContain('""received_time"":259300');
    expect(csv).toContain("center-a");
    expect(csv).not.toContain("collected_time");
    expect(edge.attachment_evidence[0].event_time).toBe(100);
  });

  it("keeps original per-edge attachments and traffic observations in separate rows", () => {
    const contextGraph = structuredClone(demoGraph("nxos"));
    const edge = contextGraph.edges.find(
      (candidate) => candidate.relationship === "communicates_with",
    )!;
    edge.attachment_evidence = [
      {
        basis: "meraki_association_flow",
        status: "associated",
        device_name: "MR-AP-01",
        ssid_number: 7,
        client_authority: "org-a/network-a",
      },
    ];
    edge.traffic_observations = [
      {
        source: "stream_ipfix",
        source_authority: "198.51.100.2",
        scope: "meraki-nxos",
        cluster: "cilium-nxos-west",
        mapping_status: "mapped",
        raw_bytes_in: 123,
      },
    ];
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
    edge.nat_observations_truncated = true;
    contextGraph.nat_event_window = {
      start: 1791373500.25,
      end: 1791374400.0005,
    };
    const csv = contextEvidenceCsv(contextGraph);
    const lines = csv.trimEnd().split("\r\n");
    expect(lines[0]).toBe(CONTEXT_EVIDENCE_COLUMNS.join(","));
    expect(lines).toHaveLength(4);
    expect(csv).toContain("attachment_evidence");
    expect(csv).toContain("traffic_observation");
    expect(csv).toContain("nat_observation");
    expect(csv).toContain("evidence_truncated");
    expect(csv).toContain(",nat_observation,1,");
    expect(csv).toContain("Cisco FTD eStreamer ConnectionEvent");
    expect(csv).toContain('""translated_initiator_ip"":""192.0.2.44""');
    expect(csv).toContain(
      '""nat_event_window"":{""start"":1791373500.25,""end"":1791374400.0005}',
    );
    expect(csv).toContain('""nat_event_window_exact"":true');
    expect(csv).toContain("MR-AP-01");
    expect(csv).toContain('""ssid_number"":7');
    expect(csv).toContain('""raw_bytes_in"":123');
    expect(csv).toContain("meraki-nxos");
  });

  it("exports an explicit marker when all capped NAT evidence was omitted", () => {
    const contextGraph = structuredClone(demoGraph("nxos"));
    const edge = contextGraph.edges.find(
      (candidate) => candidate.relationship === "communicates_with",
    )!;
    edge.nat_observations_truncated = true;
    contextGraph.nat_event_window = {
      start: 1791373500.25,
      end: 1791374400.0005,
    };
    const csv = contextEvidenceCsv(contextGraph);
    expect(csv).toContain("nat_observations_truncated,1");
    expect(csv).toContain('""truncated"":true');
    expect(csv).toContain('""nat_event_window_exact"":true');
  });
});
