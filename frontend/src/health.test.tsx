import { describe, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { HealthPanel, HealthResults } from "./HealthPanel";
import {
  jobRows,
  jobStatus,
  sourceRows,
  sourceStatus,
  loadHealth,
  qualityRows,
  type HealthReport,
} from "./health";
import type { SearchClient } from "./data/searchClient";
const now = 200000;
const report: HealthReport = {
  sources: sourceRows([]),
  jobs: jobRows([]),
  quality: qualityRows([]),
  warnings: [],
  checkedAt: now,
};
const search = vi.fn();
const client: SearchClient = { search };
describe("pipeline health", () => {
  it("preserves unknown values instead of inventing successful empty results", () => {
    expect(sourceRows([])).toHaveLength(8);
    expect(jobRows([])).toHaveLength(11);
    expect(sourceStatus(sourceRows([])[0], now)).toBe("Unavailable");
    expect(jobStatus(jobRows([])[0], now)).toBe("Configuration unavailable");
    const source = sourceRows([
      { kind: "source", name: "NetFlow", records: "0" },
    ])[0];
    expect(sourceStatus(source, now)).toBe("No visible data in 24 hours");
  });
  it("classifies source silence and clock skew without asserting outage", () => {
    expect(
      sourceStatus(
        { name: "NetFlow", records: 1, latestIndexed: now - 10 },
        now,
      ),
    ).toBe("Data received within 20 minutes");
    expect(
      sourceStatus(
        { name: "NetFlow", records: 1, latestIndexed: now - 1300 },
        now,
      ),
    ).toBe("No data received in 20 minutes");
    expect(
      sourceStatus(
        { name: "NetFlow", records: 1, latestIndexed: now + 100 },
        now,
      ),
    ).toBe("Clock is ahead");
  });
  it("distinguishes disabled, unobserved, failed, and overdue jobs", () => {
    const job = {
      name: "ADM - Identity builder",
      disabled: false,
      lastRun: now - 10,
      lastSuccess: now - 10,
      lastStatus: "success",
    };
    expect(jobStatus(job, now)).toBe("Recent successful run");
    expect(jobStatus({ ...job, disabled: true }, now)).toBe("Disabled");
    expect(jobStatus({ ...job, lastRun: undefined }, now)).toBe(
      "No visible run in 24 hours",
    );
    expect(jobStatus({ ...job, lastStatus: "skipped" }, now)).toBe(
      "Last run: skipped",
    );
    expect(jobStatus({ ...job, lastSuccess: now - 1300 }, now)).toBe(
      "Successful run is overdue",
    );
    expect(
      jobStatus(
        { ...job, name: "ADM - Interface inventory", lastSuccess: now - 3600 },
        now,
      ),
    ).toBe("Recent successful run");
    expect(
      jobStatus(
        { ...job, name: "ADM - Identity prune", lastSuccess: now - 23 * 3600 },
        now,
      ),
    ).toBe("Recent successful run");
  });
  it("rejects invalid timestamps and counters", () => {
    const s = sourceRows([
      {
        kind: "source",
        name: "NetFlow",
        records: "oops",
        latest_event: -1,
        latest_indexed: "NaN",
        max_ingest_lag: -2,
      },
    ])[0];
    expect(s).toEqual({
      name: "NetFlow",
      records: undefined,
      latestEvent: undefined,
      latestIndexed: undefined,
      maxIngestLag: undefined,
    });
  });
  it("keeps successful source evidence when scheduler visibility fails", async () => {
    search
      .mockReset()
      .mockResolvedValueOnce({
        rows: [{ kind: "source", name: "NetFlow", records: 1 }],
        warnings: ["Search may be incomplete"],
      })
      .mockRejectedValueOnce(new Error("Permission denied"))
      .mockResolvedValueOnce({
        rows: [
          {
            kind: "quality",
            source: "all",
            status: "checked",
            reason: "evaluated",
            records: 0,
          },
        ],
        warnings: [],
      });
    const result = await loadHealth(client, new AbortController().signal);
    expect(search.mock.calls.map((call) => call[0].search)).toEqual([
      "| `adm_health_sources`",
      "| `adm_health_jobs`",
      "| `adm_health_quality`",
    ]);
    expect(result.sources[0].records).toBe(1);
    expect(result.jobs.every((j) => j.disabled === undefined)).toBe(true);
    expect(result.warnings.join(" ")).toContain("Permission denied");
    expect(result.warnings.join(" ")).toContain("Search may be incomplete");
  });
  it("counts excluded records once while showing overlapping reasons", () => {
    const quality = qualityRows([
      {
        kind: "quality",
        source: "all",
        status: "checked",
        reason: "evaluated",
        records: 10,
      },
      {
        kind: "quality",
        source: "netflow",
        status: "excluded",
        reason: "evaluated",
        records: 2,
      },
      {
        kind: "quality",
        source: "netflow",
        status: "excluded",
        reason: "invalid_source_ip",
        records: 2,
      },
      {
        kind: "quality",
        source: "netflow",
        status: "excluded",
        reason: "invalid_time",
        records: 1,
      },
    ]);
    expect(quality.evaluated).toBe(10);
    expect(quality.excluded).toBe(2);
    expect(quality.issues).toHaveLength(2);
    const html = renderToStaticMarkup(
      <HealthResults report={{ ...report, quality }} />,
    );
    expect(html).toContain("2 excluded");
    expect(html).toContain("Invalid source address");
    expect(qualityRows([]).excluded).toBeUndefined();
    expect(
      qualityRows([
        {
          kind: "quality",
          source: "all",
          status: "checked",
          reason: "evaluated",
          records: "bad",
        },
      ]).evaluated,
    ).toBeUndefined();
  });
  it("does not publish a cancelled check", async () => {
    search.mockReset().mockResolvedValue({ rows: [], warnings: [] });
    const c = new AbortController();
    c.abort();
    await expect(loadHealth(client, c.signal)).rejects.toThrow("cancelled");
  });
  it("renders accessible partial health and treats messages as text", () => {
    const html = renderToStaticMarkup(
      <HealthResults
        report={{ ...report, warnings: ["<script>bad</script>"] }}
      />,
    );
    expect(html).toContain('role="alert"');
    expect(html).toContain("Health check is incomplete");
    expect(html).toContain("&lt;script&gt;");
    expect(html).not.toContain("<script>");
    expect(html).toContain('scope="col"');
    expect(html).toContain("Configuration unavailable");
  });
  it("does not present demo fixtures as live health", () => {
    const html = renderToStaticMarkup(
      <HealthPanel live={false} close={() => {}} />,
    );
    expect(html).toContain(
      "Synthetic demo data cannot establish pipeline health",
    );
    expect(html).not.toContain("Recent successful run");
  });
});
