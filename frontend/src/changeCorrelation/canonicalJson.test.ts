import { describe, expect, it } from "vitest";
import activationGolden from "../../../fixtures/change-correlation/shared/activation_python_v1.json";
import { canonicalJson, parseCanonicalJson } from "./canonicalJson";

describe("Python and browser bounded decimal JSON parity", () => {
  it("preserves exact millisecond decimals and the shared history fixture", () => {
    expect(canonicalJson(1.001)).toBe("1.001");
    expect(canonicalJson(1793102400.123)).toBe("1793102400.123");
    expect(canonicalJson(activationGolden.activation.source_latest)).toBe(
      "1793102400.123",
    );
    expect(canonicalJson(Number(activationGolden.expected_search_latest))).toBe(
      "1793102400.124",
    );
    expect(parseCanonicalJson("1.001")).toBe(1.001);
  });

  it("rejects finer precision without rounding and invalid finite values", () => {
    for (const value of [
      1.0001,
      1.001 + Number.EPSILON,
      1.001 - Number.EPSILON,
      0.000001,
      Number.NaN,
      Number.POSITIVE_INFINITY,
      Number.NEGATIVE_INFINITY,
      253402300799.001,
      Number.MAX_SAFE_INTEGER + 1,
    ])
      expect(() => canonicalJson(value)).toThrow();
  });

  it("keeps safe integers and canonical negative zero", () => {
    expect(canonicalJson(Number.MAX_SAFE_INTEGER)).toBe("9007199254740991");
    expect(canonicalJson(-0)).toBe("0");
  });
});
