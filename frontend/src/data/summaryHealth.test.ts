import { describe, expect, it, vi } from "vitest";
import {
  loadSummaryHealth,
  rowsToSummaryHealth,
  summaryHealthText,
} from "./summaryHealth";

describe("summary health", () => {
  it("parses the probe row and summarizes lag and gaps", () => {
    const h = rowsToSummaryHealth([
      {
        status: "gaps",
        lateness: "90",
        newest_summary_end: "1800000000",
        lag_seconds: "330",
        slices_24h: "282",
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
    expect(() =>
      rowsToSummaryHealth([{ status: "ok", slices_24h: "not-a-count" }]),
    ).toThrow(/Invalid summary health/);
    expect(() =>
      rowsToSummaryHealth([
        {
          status: ["ok", "gaps"],
          slices_24h: 1,
          due_slices_24h: 1,
          missing_slices_24h: 0,
          empty_slices_24h: 0,
          superseded_or_incomplete_runs: 0,
          duplicated_runs: 0,
        },
      ]),
    ).toThrow(/Invalid summary health/);
  });

  it("keeps the disabled response supported without fabricated counts", () => {
    expect(rowsToSummaryHealth([{ status: "disabled" }])).toMatchObject({
      status: "disabled",
      slices: 0,
      dueSlices: 0,
    });
  });

  it("uses the selected historical end for the preceding 24-hour check", async () => {
    const search = vi.fn(async () => ({
      rows: [{ status: "disabled" }],
      errors: [],
      warnings: [],
    }));
    const signal = new AbortController().signal;
    await loadSummaryHealth({ search }, signal, 1800000000);
    expect(search).toHaveBeenCalledWith(
      expect.objectContaining({
        earliest: "1799913600",
        latest: "1800000000",
        signal,
      }),
    );
  });

  it("fails closed when Splunk warns that the probe is incomplete", async () => {
    const client = {
      search: async () => ({ rows: [], errors: [], warnings: ["partial"] }),
    };
    await expect(
      loadSummaryHealth(client, new AbortController().signal),
    ).rejects.toThrow(/partial/);
  });
});
