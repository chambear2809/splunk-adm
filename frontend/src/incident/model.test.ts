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
      "drops_unknown",
      "new",
      "placement",
    ]);
    expect(findings[0].supports[0]).toContain("incident drop reported");
    expect(findings[0].missing.join(" ")).toContain("policy change");
    expect(findings[2].supports[0]).toContain("node-a → node-b");
    expect(findings[2].missing.join(" ")).toContain("exact movement time");
  });
  it("reports collection gaps separately from ranked leads", () => {
    const graph = during();
    graph.coverage.warnings.push("ACI collector is stale");
    graph.read = { coverage: 50, windowSeconds: 3600, pendingSeconds: 1800 };
    const findings = buildFindings(before(), graph);
    expect(findings.every((item) => item.id !== "coverage")).toBe(true);
    expect(coverageReasons(graph)).toEqual(
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
  it("ranks direct permit-to-drop above previously blocked observations without inferring a cause", () => {
    const prior = before();
    prior.edges = [
      edge("already", {
        acl_action: "drop",
        acl_drops: 2,
        acl_policy_point: "a".repeat(64),
      }),
      edge("changed", {
        acl_action: "permit",
        acl_policy_point: "a".repeat(64),
      }),
    ];
    const current = during();
    current.edges = [
      edge("already", {
        acl_action: "drop",
        acl_drops: 2,
        acl_policy_point: "a".repeat(64),
      }),
      edge("changed", {
        acl_action: "drop",
        acl_drops: 1,
        acl_policy_point: "a".repeat(64),
      }),
    ];
    const findings = buildFindings(prior, current);
    expect(findings[0]).toMatchObject({
      id: "drops_changed",
      status: "Supported",
    });
    expect(findings[0].rankReason).toContain("same policy point");
    const priorBlocked = findings.find((item) => item.id === "drops_previous")!;
    expect(findings.indexOf(priorBlocked)).toBeGreaterThan(0);
    expect(priorBlocked.contradicts.join(" ")).toContain(
      "already reported blocked",
    );
    expect(priorBlocked.missing.join(" ")).toContain("do not establish");
  });
  it("distinguishes an explicit zero from unknown baseline state without inventing a permit", () => {
    const prior = before();
    prior.edges = [edge("zero", { acl_drops: 0 }), edge("unknown")];
    const current = during();
    current.edges = [
      edge("zero", { acl_action: "drop" }),
      edge("unknown", { acl_action: "drop" }),
    ];
    const finding = buildFindings(prior, current).find(
      (item) => item.id === "drops_unknown",
    )!;
    expect(finding.supports.join(" ")).toContain(
      "baseline reports zero drops; a permit is not established",
    );
    expect(finding.supports.join(" ")).toContain(
      "baseline policy state is unknown",
    );
    expect(
      buildFindings(prior, current).some((item) => item.id === "drops_changed"),
    ).toBe(false);
  });
  it.each([
    ["different leaf", "b".repeat(64), "pod-1/node-102", false],
    ["same leaf ID in another fabric", "c".repeat(64), "pod-1/node-101", false],
    ["mixed ACL observers", undefined, "pod-1/node-101", false],
    ["same qualified policy point", "a".repeat(64), "pod-1/node-101", true],
  ] as const)(
    "qualifies ACL comparisons with %s",
    (_, point, leaf, supported) => {
      const prior = before();
      prior.edges = [
        edge("same-connection", {
          acl_action: "permit",
          acl_permits: 1,
          acl_leaf: "pod-1/node-101",
          acl_policy_point: "a".repeat(64),
        }),
      ];
      const current = during();
      current.edges = [
        edge("same-connection", {
          acl_action: "drop",
          acl_drops: 1,
          acl_leaf: leaf,
          acl_policy_point: point,
        }),
      ];
      const findings = buildFindings(prior, current);
      expect(findings[0]).toMatchObject(
        supported
          ? { id: "drops_changed", status: "Supported" }
          : { id: "drops_unknown", status: "Needs evidence" },
      );
      if (!supported)
        expect(findings[0].supports[0]).toContain(
          "incident drop reported; baseline permit reported; a shared policy point is unverified",
        );
    },
  );

  it("keeps legacy ACL comparisons as unqualified observations", () => {
    const prior = before(),
      current = during();
    prior.edges = [
      edge("legacy", { acl_action: "permit", acl_leaf: "pod-1/node-101" }),
    ];
    current.edges = [
      edge("legacy", { acl_action: "drop", acl_leaf: "pod-1/node-101" }),
    ];
    expect(buildFindings(prior, current)[0]).toMatchObject({
      id: "drops_unknown",
      status: "Needs evidence",
    });
  });

  it("orders ranks and capped evidence deterministically when graph records are reordered", () => {
    const prior = before();
    prior.edges = Array.from({ length: 12 }, (_, i) =>
      edge(`item-${i}`, { acl_action: "permit", target: `destination-${i}` }),
    );
    const current = during();
    current.edges = prior.edges.map((item) => ({
      ...item,
      acl_action: "drop",
    }));
    const normal = buildFindings(prior, current);
    const reversed = buildFindings(
      {
        ...prior,
        nodes: [...prior.nodes].reverse(),
        edges: [...prior.edges].reverse(),
      },
      {
        ...current,
        nodes: [...current.nodes].reverse(),
        edges: [...current.edges].reverse(),
      },
    );
    expect(normal).toEqual(reversed);
    expect(normal[0].supports).toHaveLength(10);
    expect(normal[0].edgeIds).toEqual([...normal[0].edgeIds].sort());
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
