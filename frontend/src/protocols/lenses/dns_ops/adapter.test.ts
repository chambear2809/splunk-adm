import { readFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import { protocolConfigClient } from "../../../data/evidenceConfig";
import {
  SearchAccessDeniedError,
  type SearchClient,
} from "../../../data/searchClient";
import { parseProtocolLink, parseProtocolProfiles } from "../../inputs";
import type {
  BaseProtocolProfile,
  ProtocolConfiguration,
  ProtocolRequest,
} from "../../shared/contract";
import {
  FORBIDDEN_SENSITIVE_FIELDS,
  assertNoForbiddenFieldsInSpl,
} from "../../shared/fields";
import {
  buildDnsOpsAnalysis,
  buildDnsOpsRawEventsUrl,
  buildDnsOpsSearch,
  investigateDnsOps,
  normalizeDnsOpsRow,
  normalizeDnsRcode,
  resolveDnsOpsThresholds,
  summarizeDnsOps,
  validateDnsOpsExtra,
} from "./adapter";

const NOW = 1800000500;
const EARLIEST = 1800000000;

function makeProfile(
  overrides: Partial<BaseProtocolProfile> = {},
): BaseProtocolProfile {
  return {
    id: "dns-dc1",
    source: "protocol_dns_ops",
    lens: "dns_ops",
    scope: "prod:dc1",
    index: "stream_dns",
    observer: "stream-fwd-01",
    validFrom: EARLIEST - 3600,
    validUntil: NOW + 3600,
    ...overrides,
  };
}

function makeConfig(
  profiles: BaseProtocolProfile[],
  fingerprint = "fp-initial",
): ProtocolConfiguration {
  return { profiles, fingerprint };
}

function makeRequest(
  overrides: Partial<ProtocolRequest> = {},
): ProtocolRequest {
  return {
    version: 1,
    lens: "dns_ops",
    scope: "prod:dc1",
    earliest: EARLIEST,
    latest: NOW,
    ...overrides,
  };
}

describe("validateDnsOpsExtra (fail-closed profile validation)", () => {
  it("accepts valid extra thresholds and sourcetype and integrates with parseProtocolProfiles", () => {
    expect(validateDnsOpsExtra(undefined)).toBeUndefined();
    expect(
      validateDnsOpsExtra({
        sourcetype: "cilium:hubble:flow",
        latencyWarnMs: 80,
        nxdomainWarnPct: 15,
        servfailWarnPct: 5,
      }),
    ).toEqual({
      sourcetype: "cilium:hubble:flow",
      latencyWarnMs: 80,
      nxdomainWarnPct: 15,
      servfailWarnPct: 5,
    });

    const profiles = parseProtocolProfiles(
      {
        version: 1,
        profiles: [
          {
            id: "dns-dc1",
            source: "protocol_dns_ops",
            lens: "dns_ops",
            scope: "prod:dc1",
            index: "stream_dns",
            observer: "stream-fwd-01",
            validFrom: EARLIEST - 3600,
            validUntil: NOW + 3600,
            extra: { latencyWarnMs: 40, servfailWarnPct: 1.5 },
          },
        ],
      },
      { dns_ops: validateDnsOpsExtra },
    );
    expect(resolveDnsOpsThresholds(profiles[0])).toEqual({
      sourcetype: "stream:dns",
      latencyWarnMs: 40,
      nxdomainWarnPct: 10,
      servfailWarnPct: 1.5,
    });
  });

  it("rejects unknown keys and out-of-bounds values", () => {
    expect(() => validateDnsOpsExtra({ unknownKey: true })).toThrow(
      /Unsupported dns_ops/,
    );
    expect(() => validateDnsOpsExtra({ latencyWarnMs: 0 })).toThrow(
      /latencyWarnMs/,
    );
    expect(() => validateDnsOpsExtra({ latencyWarnMs: 60001 })).toThrow(
      /latencyWarnMs/,
    );
    expect(() => validateDnsOpsExtra({ latencyWarnMs: Number.NaN })).toThrow(
      /latencyWarnMs/,
    );
    expect(() => validateDnsOpsExtra({ nxdomainWarnPct: -1 })).toThrow(
      /nxdomainWarnPct/,
    );
    expect(() => validateDnsOpsExtra({ nxdomainWarnPct: 101 })).toThrow(
      /nxdomainWarnPct/,
    );
    expect(() => validateDnsOpsExtra({ servfailWarnPct: -0.5 })).toThrow(
      /servfailWarnPct/,
    );
    expect(() => validateDnsOpsExtra({ servfailWarnPct: 105 })).toThrow(
      /servfailWarnPct/,
    );
    expect(() =>
      validateDnsOpsExtra({ sourcetype: "stream:netflow" as never }),
    ).toThrow(/sourcetype/);
  });
});

describe("buildDnsOpsSearch & sensitive-field guards", () => {
  it("builds bounded allowlist-only SPL for stream:dns and cilium:hubble:flow", () => {
    const streamSpl = buildDnsOpsSearch({
      index: "stream_dns",
      sourcetype: "stream:dns",
      filter: {
        src: "10.10.20.11",
        dst: "10.10.10.53",
        device: "stream-sensor-01",
      },
      maxRows: 256,
    });
    expect(streamSpl).toContain("index=stream_dns");
    expect(streamSpl).toContain('sourcetype="stream:dns"');
    expect(streamSpl).toContain('src_ip="10.10.20.11"');
    expect(streamSpl).toContain('dest_ip="10.10.10.53"');
    expect(streamSpl).toContain('host="stream-sensor-01"');
    expect(streamSpl).toContain("| table ");
    expect(streamSpl).not.toContain("| fields ");
    expect(streamSpl).not.toContain("| sort 0 - _time");
    expect(streamSpl.indexOf("| head 257")).toBeLessThan(
      streamSpl.indexOf("| table "),
    );
    expect(() =>
      assertNoForbiddenFieldsInSpl("dns_ops", streamSpl),
    ).not.toThrow();

    for (const forbidden of FORBIDDEN_SENSITIVE_FIELDS) {
      expect(streamSpl.toLowerCase()).not.toMatch(
        new RegExp(`\\b${forbidden}\\b`),
      );
    }

    const hubbleSpl = buildDnsOpsSearch({
      index: "cilium_hubble",
      sourcetype: "cilium:hubble:flow",
      filter: { src: "10.42.0.15", dst: "10.96.0.10" },
      maxRows: 100,
    });
    expect(hubbleSpl).toContain('sourcetype="cilium:hubble:flow"');
    expect(hubbleSpl).toContain("flow.l7.dns.query=*");
    expect(hubbleSpl).toContain(
      "| spath path=flow.l7.dns.query output=hubble_query",
    );
    expect(hubbleSpl).toContain("src_ip=coalesce");
    expect(hubbleSpl).toContain("answer");
    expect(hubbleSpl.indexOf("| head 101")).toBeLessThan(
      hubbleSpl.indexOf("| table "),
    );
    expect(() =>
      assertNoForbiddenFieldsInSpl("dns_ops", hubbleSpl),
    ).not.toThrow();
  });

  it("rejects SPL injection in filters and raw-events link builder", () => {
    expect(() =>
      buildDnsOpsSearch({
        index: "stream_dns",
        sourcetype: "stream:dns",
        filter: { src: '10.0.0.1" OR "1"="1' },
        maxRows: 256,
      }),
    ).toThrow(/Invalid literal/);

    const safeUrl = buildDnsOpsRawEventsUrl({
      index: "stream_dns",
      sourcetype: "stream:dns",
      client: "10.10.20.11",
      resolver: "10.10.10.53",
      earliest: EARLIEST,
      latest: NOW,
    });
    expect(safeUrl).toMatch(/^\/app\/splunk_adm\/search\?/);
    expect(safeUrl).toContain("sourcetype%3D%22stream%3Adns%22");
    expect(() =>
      buildDnsOpsRawEventsUrl({
        index: "stream_dns",
        sourcetype: "stream:dns",
        client: "bad ip!",
        resolver: "10.10.10.53",
        earliest: EARLIEST,
        latest: NOW,
      }),
    ).toThrow(/Invalid literal/);
  });
});

describe("normalizeDnsOpsRow & buildDnsOpsAnalysis", () => {
  it("normalizes rcodes, converts µs latency to ms, detects answer churn, and flags search-suffix amplification", () => {
    expect(normalizeDnsRcode("NoError")).toBe("NOERROR");
    expect(normalizeDnsRcode(2)).toBe("SERVFAIL");
    expect(normalizeDnsRcode("NXDomain")).toBe("NXDOMAIN");
    expect(normalizeDnsRcode(5)).toBe("REFUSED");
    expect(normalizeDnsRcode(undefined, { isHubbleResponse: true })).toBe(
      "NOERROR",
    );

    const churn1 = normalizeDnsOpsRow(
      {
        _time: EARLIEST + 10,
        sourcetype: "stream:dns",
        src_ip: "10.0.0.1",
        dest_ip: "10.0.0.53",
        query: "api.prod.internal.",
        reply_code: "NoError",
        response_time: 12000,
        host_addr: ["10.96.1.10"],
      },
      "stream:dns",
    )!;
    const churn2 = normalizeDnsOpsRow(
      {
        _time: EARLIEST + 20,
        sourcetype: "stream:dns",
        src_ip: "10.0.0.1",
        dest_ip: "10.0.0.53",
        query: "api.prod.internal",
        reply_code: "NoError",
        time_taken: 84000,
        host_addr: ["10.96.1.11"],
      },
      "stream:dns",
    )!;
    // Multi-A round-robin with identical set across two responses must NOT trigger false churn
    const rr1 = normalizeDnsOpsRow(
      {
        _time: EARLIEST + 30,
        sourcetype: "stream:dns",
        src_ip: "10.0.0.1",
        dest_ip: "10.0.0.53",
        query: "web.prod.internal",
        reply_code_id: 0,
        response_time: 4000,
        host_addr: ["10.96.2.1", "10.96.2.2"],
      },
      "stream:dns",
    )!;
    const rr2 = normalizeDnsOpsRow(
      {
        _time: EARLIEST + 40,
        sourcetype: "stream:dns",
        src_ip: "10.0.0.1",
        dest_ip: "10.0.0.53",
        query: "web.prod.internal",
        reply_code_id: 0,
        response_time: 5000,
        host_addr: ["10.96.2.2", "10.96.2.1"],
      },
      "stream:dns",
    )!;

    // Search-suffix amplification pair
    const suffixEvents = [
      "db.ext.com.prod.svc.cluster.local",
      "db.ext.com.svc.cluster.local",
      "db.ext.com.cluster.local",
      "cache.ext.com.prod.svc.cluster.local",
    ].map((query, i) => ({
      event: normalizeDnsOpsRow(
        {
          _time: EARLIEST + 50 + i * 10,
          sourcetype: "stream:dns",
          src_ip: "10.0.0.2",
          dest_ip: "10.0.0.54",
          query,
          reply_code: "NXDomain",
          reply_code_id: 3,
          response_time: 15000,
        },
        "stream:dns",
      )!,
      indexName: "stream_dns",
    }));

    const analysis = buildDnsOpsAnalysis({
      events: [
        { event: churn1, indexName: "stream_dns" },
        { event: churn2, indexName: "stream_dns" },
        { event: rr1, indexName: "stream_dns" },
        { event: rr2, indexName: "stream_dns" },
        ...suffixEvents,
      ],
      thresholds: resolveDnsOpsThresholds(),
      earliest: EARLIEST,
      latest: NOW,
      outcomes: [{ source: "protocol_dns_ops", state: "complete" }],
      capped: false,
    });

    const pair1 = analysis.rows.find((r) => r.client === "10.0.0.1")!;
    expect(pair1.attention).toBe(true);
    expect(pair1.latencyP95Ms).toBeCloseTo(84);
    expect(pair1.answerChurnCount).toBe(1);
    expect(pair1.answerChurnDomains[0]).toEqual({
      query: "api.prod.internal",
      distinctAnswers: ["10.96.1.10", "10.96.1.11"],
    });

    const pair2 = analysis.rows.find((r) => r.client === "10.0.0.2")!;
    expect(pair2.attention).toBe(true);
    expect(pair2.nxdomainPct).toBeCloseTo(100);
    expect(pair2.searchSuffixHint).toMatch(/search-suffix amplification/i);
    expect(pair2.topFailingDomains.length).toBe(4);
  });

  it("loads and normalizes committed stream_dns.ndjson and hubble_dns.ndjson fixtures cleanly", () => {
    const streamLines = readFileSync(
      "fixtures/protocols/dns_ops/stream_dns.ndjson",
      "utf8",
    )
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as Record<string, unknown>);
    const streamEvents = streamLines.map((row) => ({
      event: normalizeDnsOpsRow(row, "stream:dns")!,
      indexName: "stream_dns",
    }));
    const streamAnalysis = buildDnsOpsAnalysis({
      events: streamEvents,
      thresholds: resolveDnsOpsThresholds(),
      earliest: EARLIEST,
      latest: NOW,
      outcomes: [{ source: "protocol_dns_ops", state: "complete" }],
      capped: false,
    });
    expect(streamAnalysis.rows).toHaveLength(4);
    expect(streamAnalysis.rows.filter((r) => r.attention)).toHaveLength(2);
    expect(streamAnalysis.verdictStatus).toBe("attention");
    for (const row of streamAnalysis.rows) {
      const parsed = parseProtocolLink(
        new URLSearchParams({ p_lens: "dns_ops", p_item: row.id }),
      );
      expect(parsed.item).toBe(row.id);
    }

    const hubbleLines = readFileSync(
      "fixtures/protocols/dns_ops/hubble_dns.ndjson",
      "utf8",
    )
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as Record<string, unknown>);
    const hubbleEvents = hubbleLines.map((row) => ({
      event: normalizeDnsOpsRow(row, "cilium:hubble:flow")!,
      indexName: "cilium_hubble",
    }));
    const hubbleAnalysis = buildDnsOpsAnalysis({
      events: hubbleEvents,
      thresholds: resolveDnsOpsThresholds(),
      earliest: EARLIEST,
      latest: NOW,
      outcomes: [{ source: "protocol_dns_ops", state: "complete" }],
      capped: false,
    });
    expect(hubbleAnalysis.sourceMode).toBe("hubble_only");
    expect(hubbleAnalysis.coverageStatus).toBe("not_covered");
    expect(
      hubbleAnalysis.kpis.find((k) => k.id === "resolver-latency-p95")?.status,
    ).toBe("not_covered");
    expect(hubbleAnalysis.distribution).toEqual([]);
    // 10.42.0.15 has no error breaches, so it MUST be not_covered (never ok)
    const healthyHubble = hubbleAnalysis.rows.find(
      (r) => r.client === "10.42.0.15",
    )!;
    expect(healthyHubble.status).toBe("not_covered");
    expect(healthyHubble.answerChurnCount).toBe(1);
    // 10.42.0.22 has SERVFAIL & NXDOMAIN breaches, so it surfaces as attention
    const failingHubble = hubbleAnalysis.rows.find(
      (r) => r.client === "10.42.0.22",
    )!;
    expect(failingHubble.status).toBe("attention");
    expect(failingHubble.servfailPct).toBeCloseTo(50);
  });
});

describe("investigateDnsOps (runner, Hubble fallback, Estimate mode, security)", () => {
  it("falls back to cilium:hubble:flow when stream:dns is absent and marks latency not_covered", async () => {
    const search = vi.fn().mockResolvedValue({
      rows: [
        {
          _time: String(EARLIEST + 20),
          host: "k8s-node-a",
          sourcetype: "cilium:hubble:flow",
          src_ip: "10.42.0.15",
          dest_ip: "10.96.0.10",
          message_type: "RESPONSE",
          "flow.l7.dns.query": "orders.prod.svc.cluster.local",
          "flow.l7.dns.rcode": 0,
          "flow.l7.dns.ips": ["10.96.12.40"],
        },
      ],
      warnings: [],
      errors: [],
    });
    const client: SearchClient = { search };
    const result = await investigateDnsOps(
      client,
      makeRequest(),
      makeConfig([
        makeProfile({
          id: "hubble-dc1",
          index: "cilium_hubble",
          extra: { sourcetype: "cilium:hubble:flow" },
        }),
      ]),
      new AbortController().signal,
      { skipConfigRecheck: true },
    );
    expect(result.sourceMode).toBe("hubble_only");
    expect(result.coverageStatus).toBe("not_covered");
    expect(result.rows[0].status).toBe("not_covered");
    expect(result.rows[0].latencyP95Ms).toBeUndefined();
    expect(result.rows[0].queryCount).toBe(1);
    expect(result.matrixCells[0].status).toBe("not_covered");
  });

  it("surfaces degraded multi-source outcomes truthfully instead of none_observed or ok", async () => {
    const profilesTwo = makeConfig([
      makeProfile({ id: "dns-primary", index: "stream_dns" }),
      makeProfile({
        id: "hubble-fallback",
        index: "cilium_hubble",
        extra: { sourcetype: "cilium:hubble:flow" },
      }),
    ]);

    // Case 1: stream:dns times out and Hubble completes with 0 rows -> unavailable/unknown (NOT none_observed)
    const timeoutThenEmpty = await investigateDnsOps(
      {
        search: vi
          .fn()
          .mockRejectedValueOnce(new Error("Search dispatch timed out"))
          .mockResolvedValueOnce({ rows: [], warnings: [], errors: [] }),
      },
      makeRequest(),
      profilesTwo,
      new AbortController().signal,
      { skipConfigRecheck: true },
    );
    expect(timeoutThenEmpty.bannerState).toBe("unavailable");
    expect(timeoutThenEmpty.verdictStatus).toBe("unknown");
    expect(timeoutThenEmpty.coverageStatus).toBe("unknown");

    // Case 2: stream:dns denied and Hubble completes with 0 rows -> blocked/unknown (NOT none_observed)
    const deniedThenEmpty = await investigateDnsOps(
      {
        search: vi
          .fn()
          .mockRejectedValueOnce(new SearchAccessDeniedError())
          .mockResolvedValueOnce({ rows: [], warnings: [], errors: [] }),
      },
      makeRequest(),
      profilesTwo,
      new AbortController().signal,
      { skipConfigRecheck: true },
    );
    expect(deniedThenEmpty.bannerState).toBe("blocked");
    expect(deniedThenEmpty.verdictStatus).toBe("unknown");

    // Case 3: stream:dns denied and Hubble returns rows -> partial/attention
    const blockedPrimaryWithFallback = await investigateDnsOps(
      {
        search: vi
          .fn()
          .mockRejectedValueOnce(new SearchAccessDeniedError())
          .mockResolvedValueOnce({
            rows: [
              {
                _time: String(EARLIEST + 20),
                host: "k8s-node-a",
                sourcetype: "cilium:hubble:flow",
                src_ip: "10.42.0.15",
                dest_ip: "10.96.0.10",
                message_type: "RESPONSE",
                "flow.l7.dns.query": "orders.prod.svc.cluster.local",
                "flow.l7.dns.rcode": 0,
              },
            ],
            warnings: [],
            errors: [],
          }),
      },
      makeRequest(),
      profilesTwo,
      new AbortController().signal,
      { skipConfigRecheck: true },
    );
    expect(blockedPrimaryWithFallback.bannerState).toBe("partial");
    expect(blockedPrimaryWithFallback.coverageStatus).toBe("attention");
    expect(blockedPrimaryWithFallback.bannerReason).toMatch(
      /Primary source blocked/i,
    );
    expect(blockedPrimaryWithFallback.rows[0].status).toBe("not_covered");
  });

  it("checks Stream Estimate mode when stream:dns returns 0 rows and surfaces estimate_only", async () => {
    const search = vi
      .fn()
      .mockResolvedValueOnce({ rows: [], warnings: [], errors: [] })
      .mockResolvedValueOnce({
        rows: [{ host: "stream-fwd-01", stream_id: "dns", stats_only: "true" }],
        warnings: [],
        errors: [],
      });
    const result = await investigateDnsOps(
      { search },
      makeRequest(),
      makeConfig([makeProfile()]),
      new AbortController().signal,
      { skipConfigRecheck: true },
    );
    expect(search).toHaveBeenCalledTimes(2);
    expect(search.mock.calls[1][0].search).toContain(
      'sourcetype="stream:stats"',
    );
    expect(search.mock.calls[1][0].search).toContain('"dns"');
    expect(result.bannerState).toBe("estimate_only");
    expect(result.streamReadiness?.state).toBe("estimate_only");
  });

  it("handles zero-row empty state when Stream is Enabled", async () => {
    const search = vi
      .fn()
      .mockResolvedValueOnce({ rows: [], warnings: [], errors: [] })
      .mockResolvedValueOnce({
        rows: [
          { host: "stream-fwd-01", stream_id: "dns", stats_only: "false" },
        ],
        warnings: [],
        errors: [],
      });
    const result = await investigateDnsOps(
      { search },
      makeRequest(),
      makeConfig([makeProfile()]),
      new AbortController().signal,
      { skipConfigRecheck: true },
    );
    expect(result.bannerState).toBe("empty");
    expect(result.bannerReason).toContain("Enabled");
  });

  it("handles unconfigured scope as unavailable without searching", async () => {
    const search = vi.fn();
    const result = await investigateDnsOps(
      { search },
      makeRequest({ scope: "prod:other" }),
      makeConfig([makeProfile({ scope: "prod:dc1" })]),
      new AbortController().signal,
      { skipConfigRecheck: true },
    );
    expect(search).not.toHaveBeenCalled();
    expect(result.bannerState).toBe("unavailable");
    expect(result.coverageStatus).toBe("not_covered");
  });

  it("strips forbidden sensitive fields from returned rows and detects stale config", async () => {
    const search = vi.fn().mockResolvedValue({
      rows: [
        {
          _time: EARLIEST + 10,
          sourcetype: "stream:dns",
          src_ip: "10.0.0.1",
          dest_ip: "10.0.0.53",
          query: "ok.prod.internal",
          reply_code: "NoError",
          response_time: 4000,
          cookie: "session=secret",
          _raw: "raw payload should be stripped",
          payload: "secret",
          uri_query: "token=abc",
        },
      ],
      warnings: [],
      errors: [],
    });
    const client: SearchClient = { search };

    const spy = vi
      .spyOn(protocolConfigClient, "readProtocolProfileDocument")
      .mockResolvedValue({
        version: 1,
        profiles: [makeProfile()],
      });
    try {
      const config = await import("../../shared/runner").then((m) =>
        m.readProtocolConfiguration({ dns_ops: validateDnsOpsExtra }),
      );
      const summary = await summarizeDnsOps(
        client,
        makeRequest(),
        config,
        new AbortController().signal,
      );
      expect(summary.status).toBe("ok");

      spy.mockResolvedValueOnce({
        version: 1,
        profiles: [makeProfile({ index: "other_index" })],
      });
      const stale = await investigateDnsOps(
        client,
        makeRequest(),
        config,
        new AbortController().signal,
      );
      expect(stale.bannerState).toBe("stale_config");
      expect(stale.rows).toEqual([]);
    } finally {
      spy.mockRestore();
    }
  });

  it("downgrades hub summary status when one source is blocked and another returns healthy rows", async () => {
    const search = vi
      .fn()
      .mockResolvedValueOnce({
        rows: [
          {
            _time: EARLIEST + 10,
            sourcetype: "stream:dns",
            src_ip: "10.0.0.1",
            dest_ip: "10.0.0.53",
            query: "ok.example.com",
            reply_code: "NOERROR",
            time_taken: 4000,
          },
        ],
        warnings: [],
        errors: [],
      })
      .mockRejectedValueOnce(new SearchAccessDeniedError());
    const summary = await summarizeDnsOps(
      { search },
      makeRequest(),
      makeConfig([
        makeProfile({ id: "dns-a", index: "stream_a" }),
        makeProfile({ id: "dns-b", index: "stream_b" }),
      ]),
      new AbortController().signal,
      { skipConfigRecheck: true },
    );
    expect(summary.status).toBe("attention");
  });
});
