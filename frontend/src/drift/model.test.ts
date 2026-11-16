import { describe, expect, it } from "vitest";
import {
  compare,
  eligibility,
  signature,
  watchStatus,
  type Capture,
  type Dependency,
} from "./model";

const dependency: Dependency = {
  authority: "sensor",
  scope: "site",
  source: "service:checkout",
  destination: "service:orders",
  protocol: "tcp",
  port: 443,
  relation: "calls",
  direction: "forward",
  blocked: false,
  redundancyDomains: ["zone-a", "zone-b"],
};
const capture = (start: number, dependencies = [dependency]): Capture => ({
  id: String(start),
  coverage: {
    requested: { start, end: start + 300 },
    returned: { start, end: start + 300 },
    authority: "sensor",
    scope: "site",
    sourceRevision: "v1",
    configRevision: "c1",
    normalizationRevision: "n1",
    signatureVersion: 1,
    permission: "allowed",
    complete: true,
    capped: false,
    progressive: false,
    sampled: false,
    stale: false,
    knowledgeHorizon: start + 360,
    requiredLatenessSeconds: 60,
  },
  dependencies,
});

describe("dependency baselines", () => {
  it("rejects incomplete, sampled, capped, progressive and late evidence", () => {
    for (const change of [
      { capped: true },
      { complete: false },
      { progressive: true },
      { sampled: true },
      { stale: true },
      { permission: "denied" as const },
      { knowledgeHorizon: 300 },
    ]) {
      const c = capture(0);
      Object.assign(c.coverage, change);
      expect(eligibility(c).length).toBeGreaterThan(0);
    }
    const c = capture(0);
    c.coverage.returned.end = 200;
    expect(eligibility(c).length).toBeGreaterThan(0);
  });
  it("requires compatible configuration and normalization", () => {
    for (const field of [
      "sourceRevision",
      "configRevision",
      "normalizationRevision",
    ] as const) {
      const c = capture(300);
      c.coverage[field] = "different";
      expect(compare(capture(0), c).comparable).toBe(false);
    }
  });
  it("reports new, changed, blocked, missing and reduced domains without claiming removal", () => {
    const current = capture(300, [
      { ...dependency, blocked: true, redundancyDomains: ["zone-a"] },
      { ...dependency, destination: "service:inventory", port: 8443 },
      { ...dependency, port: 80 },
    ]);
    const result = compare(capture(0), current);
    expect(result.findings.map((f) => f.kind)).toEqual(
      expect.arrayContaining([
        "new_destination_port",
        "changed_dependency",
        "newly_blocked",
        "lost_redundancy",
      ]),
    );
    const missing = compare(capture(0), capture(300, []));
    expect(missing.findings[0].kind).toBe("not_observed");
    expect(missing.findings[0].description).toContain("not observed");
  });
  it("does not compare an ambiguous or wrong-scope dependency", () => {
    expect(eligibility(capture(0, [dependency, dependency]))).not.toEqual([]);
    expect(
      eligibility(capture(0, [{ ...dependency, scope: "other" }])),
    ).not.toEqual([]);
  });
  it("deduplicates recurring windows and identifies expected periods and cooldown", () => {
    const sig = signature(dependency),
      window = { start: 0, end: 300 };
    const status = watchStatus(
      {
        id: "w",
        threshold: 2,
        cooldownSeconds: 60,
        expectedWindows: [{ start: 400, end: 500 }],
      },
      [
        { signature: sig, window, observedAt: 320 },
        { signature: sig, window, observedAt: 330 },
        { signature: sig, window: { start: 300, end: 600 }, observedAt: 450 },
      ],
      sig,
      460,
    );
    expect(status).toEqual({
      count: 2,
      thresholdMet: true,
      expected: true,
      coolingDown: true,
    });
  });
});
