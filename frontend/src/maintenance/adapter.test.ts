import { describe, expect, it } from "vitest";
import type { ImpactData } from "../impact/data";
import type { FailsResult } from "../impact/model";
import { assessmentInputFromImpact } from "./adapter";
import { assessMaintenance } from "./model";

describe("impact maintenance adapter", () => {
  it("keeps observed topology and alternate candidates unqualified", () => {
    const data = {
      source: "impact reader",
      elements: [{ token: "leaf-1" }],
      capped: false,
      truncated: false,
    } as unknown as ImpactData;
    const result = {
      rows: [
        {
          traversal: "observed",
          alternate: ["leaf-2"],
          conv: { app: "Payments", lastSeen: 200 },
        },
      ],
    } as unknown as FailsResult;
    const input = assessmentInputFromImpact(data, result, {
      id: "capture",
      capturedAt: 300,
      window: { start: 100, end: 200 },
      scope: "site-a",
    });
    expect(input.services[0].topology).toMatchObject({
      value: "exposed",
      qualified: false,
    });
    expect(input.services[0].alternatives).toEqual([{ name: "leaf-2" }]);
    const assessment = assessMaintenance(input);
    expect(assessment.headline).toBe("Readiness cannot be confirmed");
    expect(assessment.services[0].topology).toBe("unknown");
    expect(assessment.services[0].alternatives[0]).toMatchObject({
      reachability: "unknown",
      health: "unknown",
      readiness: "unknown",
      substitution: "unknown",
      failureDomain: "unknown",
      capacity: "unknown",
    });
  });
});
