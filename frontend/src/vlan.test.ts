import { describe, expect, it } from "vitest";
import { vlanContexts, vlanEdges } from "./vlan";
import { indexGraph } from "./graph";
import type { GraphEdge } from "./graph";

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
