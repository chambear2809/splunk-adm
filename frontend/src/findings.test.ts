import { describe, expect, it } from "vitest";
import { demoGraph } from "./data/demoClient";
import { indexGraph } from "./graph";
import { deriveFindings } from "./findings";
import type { HealthReport } from "./health";

describe("deriveFindings", () => {
  it("derives deterministic evidence findings from a captured graph", () => {
    const graph = demoGraph("aci");
    const index = indexGraph(graph);
    const findings = deriveFindings(graph, index);
    expect(findings.map(({ id }) => id)).toEqual(
      [...findings].map(({ id }) => id).sort(),
    );
    expect(
      findings.some((finding) => finding.kind === "blocked_conversation"),
    ).toBe(true);
    expect(
      findings.every(
        (finding) =>
          finding.edgeId === undefined || index.edge.has(finding.edgeId),
      ),
    ).toBe(true);
  });

  it("keeps exact evidence references for captured blocked and inferred edges", () => {
    const graph = demoGraph("aci");
    const findings = deriveFindings(graph, indexGraph(graph));
    expect(findings).toEqual([
      expect.objectContaining({
        id: "blocked:communicates:vm:prod/10.30.40.25>vm:prod/10.20.30.40:5432/tcp",
        kind: "blocked_conversation",
        edgeId: "communicates:vm:prod/10.30.40.25>vm:prod/10.20.30.40:5432/tcp",
        detail: "The fabric recorded a drop at pod-1/node-103.",
      }),
      expect.objectContaining({
        id: "contract:communicates:vm:prod/10.30.40.25>vm:prod/10.20.30.40:5432/tcp",
        kind: "missing_contract",
      }),
      expect.objectContaining({ kind: "inferred_backend" }),
    ]);
  });

  it("reports unknown and ambiguous identities from captured and derived evidence", () => {
    const nxos = demoGraph("nxos");
    const unknown = deriveFindings(nxos, indexGraph(nxos));
    expect(unknown).toEqual([
      expect.objectContaining({
        kind: "unknown_identity",
        edgeId: expect.any(String),
      }),
    ]);
    const ambiguous = structuredClone(nxos);
    const edge = ambiguous.edges.find(
      (candidate) => candidate.relationship === "communicates_with",
    )!;
    ambiguous.nodes.find((node) => node.id === edge.source)!.endpoint_kind =
      "ambiguous";
    expect(
      deriveFindings(ambiguous, indexGraph(ambiguous)).filter(
        (finding) => finding.kind === "ambiguous_identity",
      ),
    ).toEqual([
      expect.objectContaining({ kind: "ambiguous_identity", edgeId: edge.id }),
    ]);
  });

  it("does not report healthy policy, observed handoffs, or clean snapshots", () => {
    const graph = demoGraph("aci");
    const clean = { ...graph, edges: [] };
    expect(deriveFindings(clean, indexGraph(clean))).toEqual([]);
    const edge = {
      ...graph.edges.find((item) => item.relationship === "communicates_with")!,
      contract_basis: "intent" as const,
      contract: "permit-web",
    };
    const handoff = {
      ...graph,
      edges: [
        {
          ...edge,
          relationship: "forwards_to" as const,
          confidence: "observed" as const,
        },
      ],
    };
    expect(deriveFindings(handoff, indexGraph(handoff))).toEqual([]);
  });

  it("does not mutate input and reports only non-current source health", () => {
    const graph = demoGraph("aci");
    const before = structuredClone(graph);
    const health = {
      sources: [
        { name: "NetFlow", records: 10, latestIndexed: 2_000 },
        { name: "Traces", records: 1, latestIndexed: 700 },
      ],
      jobs: [],
      quality: { issues: [] },
      warnings: [],
      checkedAt: 2_000,
    } as HealthReport;
    const findings = deriveFindings(
      { ...graph, edges: [] },
      indexGraph({ ...graph, edges: [] }),
      health,
    );
    expect(findings).toEqual([
      expect.objectContaining({
        id: "source:Traces",
        title: "Traces source evidence needs review",
        detail: "No data received in 20 minutes",
      }),
    ]);
    expect(graph).toEqual(before);
  });

  it("reports stale and unavailable sources without inventing graph evidence", () => {
    const graph = demoGraph("aci");
    const health = {
      sources: [
        { name: "NetFlow", records: 10, latestIndexed: 100 },
        { name: "Traces" },
      ],
      jobs: [],
      quality: { issues: [] },
      warnings: [],
      checkedAt: 2_000,
    } as HealthReport;
    const findings = deriveFindings(graph, indexGraph(graph), health);
    expect(
      findings
        .filter((finding) => finding.kind === "stale_source")
        .map((finding) => finding.id),
    ).toEqual(["source:NetFlow", "source:Traces"]);
  });
});

it("ignores healthy cadence and nonrequired sources while retaining unknown and overdue partial-deployment evidence", () => {
  const graph = { ...demoGraph("aci"), edges: [] };
  const report: HealthReport = {
    sources: [
      {
        name: "NetFlow",
        expectation: "active",
        records: 1,
        latestIndexed: 1900,
        staleAfterSeconds: 1200,
        probeLookbackSeconds: 604800,
      },
      { name: "Catalyst", expectation: "staged" },
      { name: "Meraki", expectation: "not_selected" },
      {
        name: "Traces",
        expectation: "active",
        records: 1,
        staleAfterSeconds: 1200,
        probeLookbackSeconds: 604800,
      },
      {
        name: "FTD",
        expectation: "active",
        records: 1,
        latestIndexed: 700,
        staleAfterSeconds: 1200,
        probeLookbackSeconds: 604800,
      },
    ],
    jobs: [],
    quality: { issues: [] },
    warnings: [],
    checkedAt: 2000,
  };
  expect(
    deriveFindings(graph, indexGraph(graph), report).map((finding) => ({
      id: finding.id,
      detail: finding.detail,
    })),
  ).toEqual([
    { id: "source:FTD", detail: "Expected receipt is overdue" },
    { id: "source:Traces", detail: "Receipt time unavailable" },
  ]);
});
