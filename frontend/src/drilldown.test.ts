import { describe, expect, it } from "vitest";
import {
  buildFlowSearch,
  buildTrafficObservationSearch,
  buildTraceSearch,
  evidenceSearch,
  flowRequest,
  searchUrl,
  strictIp,
} from "./drilldown";
import { demoGraph } from "./data/demoClient";
import {
  indexGraph,
  type Graph,
  type GraphEdge,
  type GraphNode,
} from "./graph";

const validFlow = {
  client: "10.42.0.20",
  server: "2001:db8::50",
  port: 443,
  transport: "tcp",
} as const;
const edge: GraphEdge = {
  id: "e",
  source: "client",
  target: "server",
  relationship: "communicates_with",
  evidence: ["netflow:flow-1"],
  confidence: "observed",
  count: 1,
  server_port: 443,
  transport: "tcp",
  direction_basis: "initiator",
};
const nodes: GraphNode[] = [
  {
    id: "client",
    label: "client",
    kind: "endpoint",
    addresses: [validFlow.client],
  },
  {
    id: "server",
    label: "server",
    kind: "endpoint",
    addresses: [validFlow.server],
  },
];
const graph: Graph = {
  nodes,
  edges: [edge],
  schema_version: 1,
  snapshot_id: "s",
  generated_at: "2026-01-01T00:00:00.000Z",
  demo: false,
  window: { start: "100", end: "200" },
  boundary: {
    id: "b",
    service: "s",
    environment: "e",
    cluster: "c",
    namespace: "n",
    root_node_id: "client",
  },
  coverage: {
    spans: 1,
    conversations: 1,
    matched_conversations: 1,
    unresolved_conversations: 0,
    ambiguous_conversations: 0,
    warnings: [],
  },
};

describe("drilldown safety", () => {
  it.each([
    "1.2.3.4",
    "192.0.2.1",
    "2001:DB8::1",
    "::ffff:192.0.2.1",
    "2001:db8:0:0:0:0:2:1",
    "::",
    "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
  ])("accepts valid IP %s", (ip) => expect(strictIp(ip)).toBe(true));
  it.each([
    "01.2.3.4",
    "256.1.1.1",
    "1.2.3",
    "2001:db8:::1",
    "2001:db8::1%eth0",
    "[2001:db8::1]",
    "2001:db8::ffff:999.1.1.1",
    "2001:db8:0:0:0:0:0:0:1",
    "2001:db8::1::2",
    "2001:db8::g",
    "host.example",
  ])("rejects malformed IP %s", (ip) => expect(strictIp(ip)).toBe(false));

  it("validates every flow argument and protocol/port boundaries", () => {
    expect(buildFlowSearch(validFlow)).toBe(
      '| `adm_flow_evidence("10.42.0.20","2001:db8::50",443,"tcp")`',
    );
    for (const transport of ["tcp", "udp", "sctp"])
      expect(buildFlowSearch({ ...validFlow, port: 1, transport })).toContain(
        `,1,"${transport}")`,
      );
    expect(buildFlowSearch({ ...validFlow, port: 65535 })).toContain(",65535,");
    for (const value of ["|", "'", '"', "`", "$", "\n", "\r"])
      for (const key of ["client", "server", "transport"] as const)
        expect(() =>
          buildFlowSearch({ ...validFlow, [key]: `${value}x` }),
        ).toThrow();
    for (const port of [0, -1, 65536, 1.5, Number.NaN])
      expect(() => buildFlowSearch({ ...validFlow, port })).toThrow();
    expect(() =>
      buildFlowSearch({ ...validFlow, transport: "icmp" }),
    ).toThrow();
  });

  it("opens exact traffic observations through the provenance-preserving macro", () => {
    const observationId = "a".repeat(64);
    const observation = {
      source_ip: "10.61.0.20",
      destination_ip: "10.61.0.30",
      server_port: 443,
      transport: "tcp",
      scope: "campus-aci",
      source_authority: "exporter-a",
    };
    const search = buildTrafficObservationSearch(observation, observationId);
    expect(search).toBe(
      `| \`adm_traffic_evidence_v2("10.61.0.20","10.61.0.30",443,"tcp","${observationId}")\``,
    );
    expect(
      new URL(
        searchUrl(
          search,
          { start: "100", end: "200" },
          { href: "https://splunk.example/en-US/app/splunk_adm/map" },
        ),
      ).searchParams.get("q"),
    ).toBe(search);
    for (const badId of ["a".repeat(63), "A".repeat(64), `"${observationId}`])
      expect(() => buildTrafficObservationSearch(observation, badId)).toThrow();
    expect(() =>
      searchUrl(
        search.replace("10.61.0.20", "10.999.0.20"),
        { start: "100", end: "200" },
        { href: "https://splunk.example/en-US/app/splunk_adm/map" },
      ),
    ).toThrow();
  });

  it("validates trace identifiers including newline and quote injection", () => {
    expect(
      buildTraceSearch("4bf92f3577b34da6a3ce929d0e0e4736", "d5c5e3f9e1926687"),
    ).toContain("adm_trace_evidence");
    for (const value of [
      "",
      "ABCDEF0123456789",
      "abc",
      "0".repeat(33),
      "abc\n",
      "abc`",
      "abc|",
      "abc$",
      "abc'",
      'abc"',
    ])
      expect(() => buildTraceSearch(value)).toThrow(/valid trace/i);
    expect(() => buildTraceSearch("0123456789abcdef", "bad|span")).toThrow(
      /valid trace/i,
    );
  });

  it("validates ordered bounded windows and preserves locale/proxy root", () => {
    const locations = [
      { href: "https://splunk.example/en-US/app/splunk_adm/map?old=1#x" },
      { href: "https://splunk.example/proxy/en-US/app/splunk_adm/map" },
      {
        href: "https://splunk.example/tools/app/proxy/en-US/app/splunk_adm/map",
      },
    ];
    const search = buildFlowSearch(validFlow);
    for (const location of locations) {
      const url = new URL(
        searchUrl(search, { start: "100", end: "200" }, location),
      );
      expect(url.pathname).toBe(
        new URL(location.href).pathname.replace(
          /\/app\/splunk_adm\/map$/,
          "/app/splunk_adm/search",
        ),
      );
      expect(url.hash).toBe("");
      expect(url.searchParams.get("earliest")).toBe("100");
    }
    for (const window of [
      { start: "200", end: "200" },
      { start: "201", end: "200" },
      { start: "1.5", end: "2" },
      { start: "-1", end: "2" },
      { start: "1", end: "253402300800" },
      { start: "1\n", end: "2" },
    ])
      expect(() => searchUrl(search, window, locations[0])).toThrow();
    expect(() =>
      searchUrl("| search *", { start: "1", end: "2" }, locations[0]),
    ).toThrow(/validated evidence/i);
  });

  it("rejects raw SPL, appended commands, and invalid macro arguments", () => {
    const location = {
      href: "https://splunk.example/en-US/app/splunk_adm/map",
    };
    const valid =
      '| `adm_flow_evidence("10.42.0.20","2001:db8::50",443,"tcp")`';
    for (const search of [
      valid + " | table *",
      valid.replace("443", "0"),
      valid.replace("tcp", "icmp"),
      valid.replace("10.42.0.20", "10.42.0.20\n"),
      `${valid} | delete`,
    ])
      expect(() =>
        searchUrl(search, { start: "1", end: "2" }, location),
      ).toThrow();
  });

  it("exports safe CSV and resolves captured flow/call evidence", () => {
    const index = indexGraph(graph);
    const csv = flowRequest(edge, index);
    expect(csv).toContain("10.42.0.20");
    expect(csv).toContain("2001:db8::50");
    expect(csv).toContain("netflow:flow-1");
    expect(csv).not.toContain("permit");
    expect(evidenceSearch(edge, index)).toContain("adm_flow_evidence");
    const captured = demoGraph("aci");
    const capturedIndex = indexGraph(captured);
    const flow = captured.edges.find(
      (item) =>
        item.relationship === "communicates_with" &&
        item.direction_basis !== "unknown",
    );
    const call = captured.edges.find((item) => item.relationship === "calls");
    expect(flow && evidenceSearch(flow, capturedIndex)).toContain(
      "adm_flow_evidence",
    );
    expect(call && evidenceSearch(call, capturedIndex)).toContain(
      "adm_trace_evidence",
    );
  });

  it("rejects unknown direction and multivalued endpoint addresses", () => {
    const index = indexGraph(graph);
    expect(() =>
      evidenceSearch({ ...edge, direction_basis: "unknown" }, index),
    ).toThrow(/known direction/i);
    const ambiguous: Graph = {
      ...graph,
      nodes: nodes.map((node) =>
        node.id === "server"
          ? { ...node, addresses: [validFlow.server, "2001:db8::51"] }
          : node,
      ),
    };
    expect(() => evidenceSearch(edge, indexGraph(ambiguous))).toThrow(
      /exact tuple|Multiple/i,
    );
  });

  it("searches only a traffic observation's exact tuple and matching identity", () => {
    const observationId = "c".repeat(64);
    const item = {
      source_ip: "10.61.0.20",
      destination_ip: "10.61.0.30",
      server_port: 443,
      transport: "tcp",
      scope: "campus-aci",
      mapping_status: "mapped",
    };
    const observationEdge: GraphEdge = {
      id: `traffic-observation:${observationId}`,
      traffic_observation_id: observationId,
      source: "client",
      target: "server",
      relationship: "traffic_observation",
      evidence: [],
      confidence: "correlated",
      count: 1,
      ...item,
      traffic_observations: [item],
    };
    expect(evidenceSearch(observationEdge, indexGraph(graph))).toContain(
      `adm_traffic_evidence_v2("10.61.0.20","10.61.0.30",443,"tcp","${observationId}")`,
    );
    expect(() =>
      evidenceSearch(
        { ...observationEdge, traffic_observation_id: "d".repeat(64) },
        indexGraph(graph),
      ),
    ).toThrow(/exact traffic observation identifier/i);
    expect(() => flowRequest(observationEdge, indexGraph(graph))).toThrow(
      /network conversation/i,
    );
  });
});
