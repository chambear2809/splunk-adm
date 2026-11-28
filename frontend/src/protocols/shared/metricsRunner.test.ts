import { describe, expect, it, vi } from "vitest";
import {
  SearchAccessDeniedError,
  type SearchClient,
} from "../../data/searchClient";
import type { BaseProtocolProfile } from "./contract";
import {
  autoMetricsSpanSeconds,
  buildBoundedMstatsSummarySpl,
  buildBoundedMstatsTrendSpl,
  clampNonNegativeRate,
  runBoundedMetricsSummary,
  runBoundedMetricsTrend,
} from "./metricsRunner";

const NOW = 1764246600;
const PROFILE: BaseProtocolProfile = {
  id: "sc4snmp-dc1",
  source: "protocol_interface_health",
  lens: "interface_health",
  scope: "dc1",
  index: "netmetrics",
  observer: "sc4snmp-01",
  validFrom: NOW - 86400 * 30,
  validUntil: NOW + 86400 * 30,
};

describe("metricsRunner bounded | mstats contract", () => {
  it("quotes hyphenated metric names, omits span in summary SPL, and ranks before head", () => {
    const spl = buildBoundedMstatsSummarySpl({
      lens: "interface_health",
      profile: PROFILE,
      metrics: [
        {
          metric: "sc4snmp.IF-MIB.ifHCInOctets",
          agg: "rate",
          alias: "in_octets",
        },
        {
          metric: "sc4snmp.IF-MIB.ifInErrors",
          agg: "rate",
          alias: "in_errors",
        },
      ],
      dimensions: ["host", "interface_name"],
      filters: [{ field: "host", op: "=", values: ["leaf-01"] }],
      rankBy: "in_errors",
      earliest: NOW - 86400 * 7,
      latest: NOW,
      maxRows: 100,
    });
    expect(spl).toContain('rate("sc4snmp.IF-MIB.ifHCInOctets") AS in_octets');
    expect(spl).toContain('rate("sc4snmp.IF-MIB.ifInErrors") AS in_errors');
    expect(spl).toContain('WHERE index=netmetrics AND host="leaf-01"');
    expect(spl).not.toContain("span=");
    expect(spl).toContain("| sort 0 - in_errors | head 101");
  });

  it("rejects wildcard metrics and unallowlisted aliases or dimensions before dispatch", () => {
    expect(() =>
      buildBoundedMstatsSummarySpl({
        lens: "interface_health",
        profile: PROFILE,
        metrics: [
          {
            metric: "openconfig.qos.interfaces.*.queues.dropped",
            agg: "rate",
            alias: "in_discards",
          },
        ],
        dimensions: ["host"],
        earliest: NOW - 3600,
        latest: NOW,
      }),
    ).toThrow(/Invalid metric name/);

    expect(() =>
      buildBoundedMstatsSummarySpl({
        lens: "interface_health",
        profile: PROFILE,
        metrics: [
          {
            metric: "sc4snmp.IF-MIB.ifInErrors",
            agg: "rate",
            alias: "not_in_allowlist",
          },
        ],
        dimensions: ["host"],
        earliest: NOW - 3600,
        latest: NOW,
      }),
    ).toThrow(/not allowlisted/);

    expect(() =>
      buildBoundedMstatsSummarySpl({
        lens: "interface_health",
        profile: PROFILE,
        metrics: [
          {
            metric: "sc4snmp.IF-MIB.ifInErrors",
            agg: "rate",
            alias: "in_errors",
          },
        ],
        dimensions: ["host", "community"],
        earliest: NOW - 3600,
        latest: NOW,
      }),
    ).toThrow(/not allowlisted/);
  });

  it("enforces top-8 entity limit and auto-scales span for trend queries", () => {
    const span7d = autoMetricsSpanSeconds(NOW - 86400 * 7, NOW, 32);
    expect(Math.ceil((86400 * 7) / span7d)).toBeLessThanOrEqual(32);

    const trendSpl = buildBoundedMstatsTrendSpl({
      lens: "interface_health",
      profile: PROFILE,
      metrics: [
        {
          metric: "sc4snmp.IF-MIB.ifHCInOctets",
          agg: "rate",
          alias: "in_octets",
        },
      ],
      dimensions: ["host"],
      entityField: "host",
      entityValues: ["leaf-01", "leaf-02"],
      earliest: NOW - 86400 * 7,
      latest: NOW,
    });
    expect(trendSpl).toContain(`span=${span7d}s`);
    expect(trendSpl).toContain('host IN ("leaf-01", "leaf-02")');

    expect(() =>
      buildBoundedMstatsTrendSpl({
        lens: "interface_health",
        profile: PROFILE,
        metrics: [
          {
            metric: "sc4snmp.IF-MIB.ifHCInOctets",
            agg: "rate",
            alias: "in_octets",
          },
        ],
        dimensions: ["host"],
        entityField: "host",
        entityValues: ["h1", "h2", "h3", "h4", "h5", "h6", "h7", "h8", "h9"],
        earliest: NOW - 3600,
        latest: NOW,
      }),
    ).toThrow(/1\.\.8 entityValues/);
  });

  it("clamps negative counter-reset rates to undefined instead of synthetic zero", () => {
    expect(clampNonNegativeRate(-42.5)).toBeUndefined();
    expect(clampNonNegativeRate(NaN)).toBeUndefined();
    expect(clampNonNegativeRate(0)).toBe(0);
    expect(clampNonNegativeRate("125.4")).toBe(125.4);
  });

  it("maps blocked and capped outcomes truthfully via runBoundedMetricsSummary/Trend", async () => {
    const deniedClient: SearchClient = {
      search: vi.fn().mockRejectedValue(new SearchAccessDeniedError()),
    };
    const blocked = await runBoundedMetricsSummary(deniedClient, {
      lens: "interface_health",
      profile: PROFILE,
      metrics: [
        {
          metric: "sc4snmp.IF-MIB.ifInErrors",
          agg: "rate",
          alias: "in_errors",
        },
      ],
      dimensions: ["host"],
      earliest: NOW - 3600,
      latest: NOW,
      signal: new AbortController().signal,
    });
    expect(blocked.outcome.state).toBe("blocked");
    expect(blocked.rows).toEqual([]);

    const cappedClient: SearchClient = {
      search: vi.fn().mockResolvedValue({
        rows: [
          { _time: NOW - 120, host: "leaf-01", in_errors: 2, _raw: "secret" },
          { _time: NOW - 60, host: "leaf-01", in_errors: 3 },
        ],
        warnings: [],
        errors: [],
      }),
    };
    const trend = await runBoundedMetricsTrend(cappedClient, {
      lens: "interface_health",
      profile: PROFILE,
      metrics: [
        {
          metric: "sc4snmp.IF-MIB.ifInErrors",
          agg: "rate",
          alias: "in_errors",
        },
      ],
      dimensions: ["host"],
      entityField: "host",
      entityValues: ["leaf-01"],
      earliest: NOW - 3600,
      latest: NOW,
      maxRows: 1,
      signal: new AbortController().signal,
    });
    expect(trend.capped).toBe(true);
    expect(trend.outcome.state).toBe("partial");
    expect(trend.rows).toHaveLength(1);
    expect(trend.rows[0]).not.toHaveProperty("_raw");

    // Verify negative rate counter-reset is stripped in dispatchMetricsSpl
    const resetClient: SearchClient = {
      search: vi.fn().mockResolvedValue({
        rows: [{ _time: NOW - 60, host: "leaf-01", in_errors: -5.2 }],
        warnings: [],
        errors: [],
      }),
    };
    const resetRes = await runBoundedMetricsSummary(resetClient, {
      lens: "interface_health",
      profile: PROFILE,
      metrics: [
        {
          metric: "sc4snmp.IF-MIB.ifInErrors",
          agg: "rate",
          alias: "in_errors",
        },
      ],
      dimensions: ["host"],
      earliest: NOW - 3600,
      latest: NOW,
      signal: new AbortController().signal,
    });
    expect(resetRes.rows[0]).not.toHaveProperty("in_errors");
  });
});
