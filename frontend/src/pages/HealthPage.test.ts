import { describe, expect, it } from "vitest";
import { healthWindow } from "./HealthPage";

describe("Data health window", () => {
  const now = 1793833200; // 2026-11-04 23:00 UTC
  it("defaults to the current seven-day check", () => {
    expect(healthWindow("", now)).toEqual({ earliest: "-7d", latest: "now" });
  });
  it("evaluates an absolute past window at its end", () => {
    expect(
      healthWindow("?earliest=1793772000&latest=1793800800", now, "UTC"),
    ).toEqual({
      earliest: "1793772000",
      latest: "1793800800",
      asOf: 1793800800,
    });
  });
  it("resolves a relative end", () => {
    expect(healthWindow("?earliest=-1d&latest=-9h", now, "UTC").asOf).toBe(
      now - 9 * 3600,
    );
  });
  it("rejects unsafe or reversed bounds", () => {
    expect(healthWindow("?earliest=now&latest=-1d", now)).toEqual({
      earliest: "-7d",
      latest: "now",
    });
    expect(healthWindow("?earliest=x%20OR&latest=now", now).asOf).toBe(
      undefined,
    );
  });
});
