import { describe, expect, it } from "vitest";
import vectors from "../../../fixtures/contracts/dependency-signatures.json";
import { checkedCapture } from "./client";
import { eligibility, signature } from "./model";

const capture = () => ({
  id: "capture-1",
  coverage: {
    requested: { start: 100, end: 200 },
    returned: { start: 100, end: 200 },
    authority: "collector:α",
    scope: "realm:東京",
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
    knowledgeHorizon: 260,
    requiredLatenessSeconds: 60,
  },
  dependencies: [vectors.vectors[0].dependency],
});
describe("dependency capture transport", () => {
  it("matches the Python signature contract for Unicode without normalizing source identities", () => {
    for (const vector of vectors.vectors)
      expect(signature(vector.dependency)).toBe(vector.signature);
    expect(vectors.vectors[1].dependency.source).not.toBe(
      vectors.vectors[1].dependency.destination,
    );
  });
  it("retains incomplete evidence for review without making it eligible", () => {
    const data = capture();
    data.coverage.complete = false;
    expect(eligibility(checkedCapture(data)).join(" ")).toContain("incomplete");
    expect(() => checkedCapture({ ...data, coverage: null })).toThrow(
      "malformed",
    );
    expect(() => checkedCapture({ ...data, dependencies: [null] })).toThrow(
      "malformed",
    );
    expect(() =>
      checkedCapture({
        ...data,
        dependencies: Array(10001).fill(data.dependencies[0]),
      }),
    ).toThrow("limit");
  });
});
