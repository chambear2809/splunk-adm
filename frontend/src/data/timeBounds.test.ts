import { describe, expect, it } from "vitest";
import {
  isIncompleteWindow,
  isSafeTime,
  resolveTime,
  timeError,
} from "./timeBounds";

const NOW = Date.UTC(2024, 0, 15, 12) / 1000;

describe("time bounds", () => {
  it("resolves chained relative offsets and snaps", () => {
    expect(resolveTime("-1h+30m", "UTC", NOW)).toBe(NOW - 1800);
    expect(resolveTime("now-1d@d", "UTC", NOW)).toBe(
      Date.UTC(2024, 0, 14) / 1000,
    );
    expect(resolveTime("+15m", "UTC", NOW)).toBe(NOW + 900);
  });

  it("supports decimal epochs and rejects unsafe or unbounded values", () => {
    expect(resolveTime("1791373500.5")).toBe(1791373500.5);
    expect(resolveTime("253402300799")).toBe(253402300799);
    expect(resolveTime("253402300800")).toBeUndefined();
    for (const value of [
      "-1h | delete",
      "-1h\n",
      "123\n",
      "253402300800",
      "-xx+1h",
      "-||+1h",
      "now+1h\n+2m",
      "now+1h`+2m",
      'now+1h"+2m',
    ]) {
      expect(isSafeTime(value)).toBe(false);
      expect(resolveTime(value, "UTC", NOW)).toBeUndefined();
    }
  });

  it("orders mixed absolute and relative bounds", () => {
    expect(timeError("-2h", "now", "UTC", NOW)).toBeUndefined();
    expect(timeError("now", "-1h", "UTC", NOW)).toMatch(/precede/);
    expect(timeError("1791374400", "1791373500", "UTC", NOW)).toMatch(
      /precede/,
    );
  });

  it("snaps calendar boundaries in a DST timezone", () => {
    const beforeSpringForward = Date.UTC(2024, 2, 10, 16) / 1000;
    const midnight = resolveTime("@d", "America/New_York", beforeSpringForward);
    expect(midnight).toBe(Date.UTC(2024, 2, 10, 5) / 1000);
    expect(resolveTime("@mon", "UTC", NOW)).toBe(Date.UTC(2024, 0, 1) / 1000);
    expect(resolveTime("@q", "UTC", NOW)).toBe(Date.UTC(2024, 0, 1) / 1000);
    expect(resolveTime("@w0", "UTC", NOW)).toBe(Date.UTC(2024, 0, 14) / 1000);
    expect(resolveTime("@w7", "UTC", NOW)).toBe(Date.UTC(2024, 0, 14) / 1000);
    expect(resolveTime("@w", "UTC", NOW)).toBe(Date.UTC(2024, 0, 14) / 1000);
    expect(
      resolveTime(
        "@h",
        "America/New_York",
        Date.UTC(2024, 10, 3, 6, 30) / 1000,
      ),
    ).toBe(Date.UTC(2024, 10, 3, 6) / 1000);
  });

  it("marks recent and future latest bounds as incomplete", () => {
    expect(isIncompleteWindow("-5m", NOW)).toBe(true);
    expect(isIncompleteWindow("+1h", NOW)).toBe(true);
    expect(isIncompleteWindow("-11m", NOW)).toBe(false);
  });
});
