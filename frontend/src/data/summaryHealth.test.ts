import { describe, expect, it } from "vitest";
import { rowsToSummaryHealth, summaryHealthText } from "./summaryHealth";

describe("summary health", () => {
  it("parses the probe row and summarizes lag and gaps", () => {
    const h = rowsToSummaryHealth([
      {
        status: "gaps",
        lateness: "90",
        newest_summary_end: "1800000000",
        lag_seconds: "330",
        slices_24h: "280",
        due_slices_24h: "284",
        missing_slices_24h: "4",
        oldest_missing: "1799990000",
        empty_slices_24h: "2",
        superseded_or_incomplete_runs: "1",
        duplicated_runs: "0",
      },
    ]);
    expect(h).toMatchObject({
      status: "gaps",
      missingSlices: 4,
      lagSeconds: 330,
    });
    expect(summaryHealthText(h)).toBe(
      "Gaps · lag 6 min · 280 of 284 slices · 4 missing",
    );
    expect(
      summaryHealthText(rowsToSummaryHealth([{ status: "disabled" }])),
    ).toBe("Not enabled");
  });

  it("rejects malformed rows", () => {
    expect(() => rowsToSummaryHealth([])).toThrow();
    expect(() => rowsToSummaryHealth([{ status: "great" }])).toThrow();
  });
});
