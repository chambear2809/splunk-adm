import { describe, expect, it } from "vitest";
import { formatUtc, formatUtcRange, isoTime } from "./time";

describe("time", () => {
  it("requires an explicit offset", () => {
    expect(isoTime("2026-10-07T12:00:00Z")).toBe(true);
    expect(isoTime("2026-10-07T12:00:00.5-05:00")).toBe(true);
    expect(isoTime("2026-10-07T12:00:00")).toBe(false);
    expect(isoTime("2026-10-07")).toBe(false);
    expect(isoTime("1")).toBe(false);
    expect(isoTime(1)).toBe(false);
  });
  it("renders UTC regardless of input offset", () => {
    expect(formatUtc("2026-10-07T14:30:00+02:00")).toBe("2026-10-07 12:30");
    expect(formatUtc("2026-10-07T12:30:05Z")).toBe("2026-10-07 12:30:05");
  });
  it("shows the end date only when the day changes", () => {
    expect(formatUtcRange("2026-10-07T11:45:00Z", "2026-10-07T12:00:00Z")).toBe(
      "2026-10-07 11:45 → 12:00",
    );
    expect(formatUtcRange("2026-10-06T23:00:00Z", "2026-10-07T01:00:00Z")).toBe(
      "2026-10-06 23:00 → 2026-10-07 01:00",
    );
    expect(
      formatUtcRange("2026-10-07T23:30:00-02:00", "2026-10-08T00:30:00-02:00"),
    ).toBe("2026-10-08 01:30 → 02:30");
  });
});
