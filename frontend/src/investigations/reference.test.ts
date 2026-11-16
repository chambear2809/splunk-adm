import { describe, expect, it } from "vitest";
import type { Graph } from "../graph";
import { comparisonReference } from "./reference";

const capture = (start: number, end: number): Graph =>
  ({
    demo: false,
    boundary: {
      cluster: "a",
      environment: "lab",
      namespace: "shop",
      service: "checkout",
    },
    window: {
      start: new Date(start * 1000).toISOString(),
      end: new Date(end * 1000).toISOString(),
    },
  }) as Graph;

describe("server comparison reference", () => {
  it("sends canonical selectors and returned windows without graph data", () => {
    const result = comparisonReference({
      baseline: capture(100, 200),
      incident: capture(200, 300),
      recovery: capture(300, 400),
    });
    expect(result).toBe(
      '{"schema":1,"scope":{"cluster":"a","environment":"lab","namespace":"shop","service":"checkout"},"windows":[{"end":200,"start":100},{"end":300,"start":200},{"end":400,"start":300}]}',
    );
  });
  it("withholds unsupported, mismatched and synthetic selections", () => {
    const baseline = capture(100, 200),
      incident = capture(200, 300);
    expect(
      comparisonReference({ baseline: { ...baseline, demo: true }, incident }),
    ).toBeUndefined();
    expect(
      comparisonReference({ baseline, incident: capture(199, 300) }),
    ).toBeUndefined();
    expect(
      comparisonReference({ baseline, incident: capture(200, 501) }),
    ).toBeUndefined();
    expect(
      comparisonReference({ baseline, incident: capture(200.5, 300) }),
    ).toBeUndefined();
    expect(
      comparisonReference({
        baseline,
        incident: {
          ...incident,
          boundary: { ...incident.boundary, namespace: "elsewhere" },
        },
      }),
    ).toBeUndefined();
    expect(
      comparisonReference({
        baseline: {
          ...baseline,
          boundary: { ...baseline.boundary, service: 'x"|delete' },
        },
        incident,
      }),
    ).toBeUndefined();
  });
});
