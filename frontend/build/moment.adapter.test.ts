import { createRequire } from "node:module";
import { describe, expect, it } from "vitest";

const require = createRequire(import.meta.url);
const plainMoment = require("moment");
const adapterMoment = require("./moment.cjs");

const commonMomentBehavior = (moment: typeof plainMoment) => {
  const value = moment("2026-01-02T03:04:05Z");
  return {
    iso: value.toISOString(),
    formatted: value.utc().format("YYYY-MM-DD HH:mm"),
    locale: value.locale("en").format("MMM"),
    duration: moment.duration(90, "minutes").asMinutes(),
    isMoment: moment.isMoment(value),
    shifted: value
      .clone()
      .add(1, "day")
      .subtract(2, "hours")
      .isSame(moment("2026-01-03T01:04:05Z")),
  };
};

describe("the CommonJS Moment adapter", () => {
  it("exports a callable Moment compatible with plain Moment APIs", () => {
    expect(typeof adapterMoment).toBe("function");
    expect(commonMomentBehavior(adapterMoment)).toEqual(
      commonMomentBehavior(plainMoment),
    );
  });

  it("retains timezone support required by Splunk time-range utilities", () => {
    expect(typeof plainMoment.tz).toBe("undefined");
    expect(typeof adapterMoment.tz).toBe("function");
    expect(
      adapterMoment("2026-01-02T03:04:05Z")
        .tz("America/New_York")
        .format("YYYY-MM-DD HH:mm Z"),
    ).toBe("2026-01-01 22:04 -05:00");
  });
});
