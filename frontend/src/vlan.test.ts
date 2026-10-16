import { describe, expect, it } from "vitest";
import { vlanContexts } from "./vlan";
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
});
