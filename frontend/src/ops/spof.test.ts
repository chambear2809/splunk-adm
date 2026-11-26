import { describe, expect, it } from "vitest";
import { resiliencePosture } from "./spof";
import type { DependsResult } from "../impact/model";

const result = (rows: DependsResult["rows"]): DependsResult => ({
  mode: "depends",
  label: "payments",
  headline: "test",
  rows,
  conversations: rows.length,
});

describe("resilience posture", () => {
  it("names observed single points without inventing alternates", () => {
    const posture = resiliencePosture(
      result([
        {
          id: "leaf-1",
          label: "leaf-201",
          tier: "leaf",
          severity: "outage",
          alternate: [],
          conversations: 4,
          bytes: 10,
          evidence: "observed",
          token: "leaf-201",
        },
        {
          id: "leaf-2",
          label: "leaf-202",
          tier: "leaf",
          severity: "degraded",
          alternate: ["leaf-203"],
          conversations: 2,
          bytes: 4,
          evidence: "observed",
          token: "leaf-202",
        },
      ]),
    );
    expect(posture.singlePoints).toHaveLength(1);
    expect(posture.headline).toContain("1 single point");
    expect(posture.redundant[0]?.alternate).toEqual(["leaf-203"]);
  });
});
