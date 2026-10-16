import { describe, expect, it } from "vitest";
import { csvCell, FLOW_COLUMNS, requiredFlowsCsv } from "./csv";
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
    expect(output).toContain(",1\r\n");
  });
});
