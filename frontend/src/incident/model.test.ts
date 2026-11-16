import { describe, expect, it, vi } from "vitest";
import { demoGraph } from "../provider";
import type { Graph, GraphEdge, GraphNode } from "../graph";
import {
  adjacentBaseline,
  assertComparison,
  buildFindings,
  buildTimeline,
  coverageReasons,
  loadComparison,
} from "./model";

// Synthetic snapshots test the interpretation of the existing graph contract.
const node = (
  id: string,
  kind: GraphNode["kind"],
  attributes?: Record<string, string>,
): GraphNode => ({
  id,
  label: id,
  kind,
  namespace: "shop",
  cluster: "c",
  attributes,
});
const edge = (id: string, extra: Partial<GraphEdge> = {}): GraphEdge => ({
  id,
  source: "a",
  target: "b",
  relationship: "communicates_with",
  confidence: "observed",
  evidence: [],
  count: 1,
  ...extra,
});
const snapshot = (
  start: string,
  end: string,
  nodes: GraphNode[],
  edges: GraphEdge[],
): Graph => ({
  ...demoGraph(),
  window: { start, end },
  nodes,
  edges,
  coverage: {
    spans: 0,
    conversations: 0,
    matched_conversations: 0,
    unresolved_conversations: 0,
    ambiguous_conversations: 0,
    warnings: [],
  },
  truncation: undefined,
  read: undefined,
});
const before = () =>
  snapshot(
    "2026-01-01T00:00:00Z",
    "2026-01-01T01:00:00Z",
    [
      node("a", "workload", { owner: "a", node: "node-a" }),
      node("b", "endpoint"),
    ],
    [edge("old")],
  );
const during = () =>
  snapshot(
    "2026-01-01T01:00:00Z",
    "2026-01-01T02:00:00Z",
    [
      node("a", "workload", { owner: "a", node: "node-b" }),
      node("b", "endpoint"),
    ],
    [edge("new", { acl_action: "drop", acl_drops: 2 })],
  );

describe("incident interpretation", () => {
  it("finds reported drops, node placement changes and newly observed dependencies without asserting cause", () => {
    const findings = buildFindings(before(), during());
    expect(findings.map((item) => item.id)).toEqual([
      "drops",
      "new",
      "placement",
    ]);
    expect(findings[0].supports[0]).toContain("2 reported drops");
    expect(findings[0].missing.join(" ")).toContain("policy change");
    expect(findings[2].supports[0]).toContain("node-a → node-b");
    expect(findings[2].missing.join(" ")).toContain("exact movement time");
  });
  it("makes a collector gap and incomplete results visible before other findings", () => {
    const graph = during();
    graph.coverage.warnings.push("ACI collector is stale");
    graph.read = { coverage: 50, windowSeconds: 3600, pendingSeconds: 1800 };
    const findings = buildFindings(before(), graph);
    expect(findings[0]).toMatchObject({
      id: "coverage",
      status: "Needs evidence",
    });
    expect(findings[0].supports).toEqual(
      expect.arrayContaining([
        "ACI collector is stale",
        "The map read is incomplete.",
      ]),
    );
    expect(
      coverageReasons({
        ...graph,
        truncation: {
          truncated: true,
          shown: { nodes: 1, edges: 1 },
          total: { nodes: 2, edges: 2 },
          ranking: "test",
        },
      }),
    ).toContain("The map shows a ranked subset of the result.");
  });
  it("labels snapshot differences as intervals and missing connections as not observed", () => {
    const items = buildTimeline(before(), during());
    expect(items.some((item) => item.title.includes("not observed"))).toBe(
      true,
    );
    expect(
      items.every(
        (item) =>
          item.kind === "snapshot" &&
          item.start === before().window.end &&
          item.end === during().window.end,
      ),
    ).toBe(true);
  });
  it("requires returned scope and exact requested bounds", () => {
    const graph = before();
    expect(() => assertComparison(during(), graph, graph.window)).not.toThrow();
    expect(() => assertComparison(during(), graph, during().window)).toThrow(
      /window differs/,
    );
    expect(() =>
      assertComparison(
        during(),
        { ...graph, boundary: { ...graph.boundary, cluster: "other" } },
        graph.window,
      ),
    ).toThrow(/scope/);
  });
  it("defaults to the adjacent equal-duration baseline and rejects invalid time", () => {
    expect(adjacentBaseline(during().window)).toEqual({
      start: "2026-01-01T00:00:00.000Z",
      end: "2026-01-01T01:00:00.000Z",
    });
    expect(() =>
      adjacentBaseline({ start: "invalid", end: "invalid" }),
    ).toThrow();
    expect(() =>
      adjacentBaseline({
        start: "2026-01-01T01:00:00",
        end: "2026-01-01T02:00:00",
      }),
    ).toThrow();
  });

  it("does not accept a late response or start recovery after cancellation", async () => {
    let resolve!: (graph: Graph) => void;
    const loader = vi.fn(
      () =>
        new Promise<Graph>((done) => {
          resolve = done;
        }),
    );
    const controller = new AbortController();
    const pending = loadComparison(
      during(),
      before().window,
      { start: "2026-01-01T02:00:00Z", end: "2026-01-01T03:00:00Z" },
      loader,
      controller.signal,
    );
    controller.abort();
    resolve(before());
    await expect(pending).rejects.toThrow("cancelled");
    expect(loader).toHaveBeenCalledTimes(1);
  });
});

describe("source identity comparison boundary", () => {
  it("rejects mixed provenance and changed authority, scope or configuration", () => {
    const reference = before(),
      result = before();
    reference.identityContext = {
      schemaVersion: 1,
      contract: "qualified_v2",
      authority: "producer",
      scope: "scope",
      configRevision: "a".repeat(64),
      observedWindow: {
        start: Date.parse(reference.window.start) / 1000,
        end: Date.parse(reference.window.end) / 1000,
      },
    };
    expect(() => assertComparison(reference, result, result.window)).toThrow(
      "source identity",
    );
    result.identityContext = { ...reference.identityContext };
    expect(() =>
      assertComparison(reference, result, result.window),
    ).not.toThrow();
    for (const key of ["authority", "scope", "configRevision"] as const) {
      result.identityContext = {
        ...reference.identityContext,
        [key]: "different",
      };
      expect(() => assertComparison(reference, result, result.window)).toThrow(
        "source identity",
      );
    }
  });
});
