import { describe, expect, it } from "vitest";
import {
  formatUtc,
  formatUtcRange,
  graphWindowLabel,
  isoTime,
  formatInZone,
} from "./time";

describe("time", () => {
  it("formats the signed-in user's timezone and falls back on an invalid zone", () => {
    expect(formatInZone("2026-10-07T12:00:00Z", "Pacific/Honolulu")).toContain(
      "02:00:00",
    );
    expect(formatInZone("2026-10-07T12:00:00Z", "invalid")).toBe(
      formatInZone("2026-10-07T12:00:00Z"),
    );
    expect(() => formatInZone("2026-10-07T12:00:00")).toThrow();
  });
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
  it("labels the counted graph window and refuses offset-less bounds", () => {
    expect(
      graphWindowLabel(
        {
          window: {
            start: "2026-11-04T10:05:00Z",
            end: "2026-11-04T14:03:21Z",
          },
        },
        "UTC",
      ),
    ).toBe(
      `${formatInZone("2026-11-04T10:05:00Z", "UTC")} → ${formatInZone("2026-11-04T14:03:21Z", "UTC")}`,
    );
    expect(
      graphWindowLabel({
        window: { start: "2026-11-04T10:05:00", end: "2026-11-04T14:03:21Z" },
      }),
    ).toBeUndefined();
  });
});
