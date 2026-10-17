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
});

describe("contextEvidenceCsv", () => {
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
    const csv = contextEvidenceCsv(contextGraph);
    const lines = csv.trimEnd().split("\r\n");
    expect(lines[0]).toBe(CONTEXT_EVIDENCE_COLUMNS.join(","));
    expect(lines).toHaveLength(3);
    expect(csv).toContain("attachment_evidence");
    expect(csv).toContain("traffic_observation");
    expect(csv).toContain("MR-AP-01");
    expect(csv).toContain('""ssid_number"":7');
    expect(csv).toContain('""raw_bytes_in"":123');
    expect(csv).toContain("meraki-nxos");
  });
});
