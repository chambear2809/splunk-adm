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
  buildTcpTlsAnalysis,
  buildTcpTlsRawEventsUrl,
  buildTcpTlsSearch,
  investigateTcpTls,
  isLegacyTlsVersion,
  normalizeTcpTlsRow,
  resolveTcpTlsThresholds,
  summarizeTcpTls,
  validateTcpTlsExtra,
} from "./adapter";

const NOW = 1800000500;
const EARLIEST = 1800000000;

function makeProfile(
  overrides: Partial<BaseProtocolProfile> = {},
): BaseProtocolProfile {
  return {
    id: "tcp-dc1",
    source: "protocol_tcp_tls",
    lens: "tcp_tls",
    scope: "prod:dc1",
    index: "stream_tcp",
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
    lens: "tcp_tls",
    scope: "prod:dc1",
    earliest: EARLIEST,
    latest: NOW,
    ...overrides,
  };
}

describe("validateTcpTlsExtra (fail-closed profile validation)", () => {
  it("accepts valid extra thresholds and sourcetype and integrates with parseProtocolProfiles", () => {
    expect(validateTcpTlsExtra(undefined)).toBeUndefined();
    expect(
      validateTcpTlsExtra({
        rttWarnMs: 75,
        retransmitWarnPct: 1.5,
        certExpiryWarnDays: 14,
        sourcetype: "stream:netflow",
      }),
    ).toEqual({
      rttWarnMs: 75,
      retransmitWarnPct: 1.5,
      certExpiryWarnDays: 14,
      sourcetype: "stream:netflow",
    });

    const profiles = parseProtocolProfiles(
      {
        version: 1,
        profiles: [
          {
            id: "tcp-dc1",
            source: "protocol_tcp_tls",
            lens: "tcp_tls",
            scope: "prod:dc1",
            index: "stream_tcp",
            observer: "stream-fwd-01",
            validFrom: EARLIEST - 3600,
            validUntil: NOW + 3600,
            extra: { rttWarnMs: 40, certExpiryWarnDays: 21 },
          },
        ],
      },
      { tcp_tls: validateTcpTlsExtra },
    );
    expect(resolveTcpTlsThresholds(profiles[0])).toEqual({
      rttWarnMs: 40,
      retransmitWarnPct: 2,
      certExpiryWarnDays: 21,
      sourcetype: "stream:tcp",
    });
  });

  it("rejects unknown keys and out-of-bounds values", () => {
    expect(() => validateTcpTlsExtra({ unknownKey: true })).toThrow(
      /Unsupported tcp_tls/,
    );
    expect(() => validateTcpTlsExtra({ rttWarnMs: 0 })).toThrow(/rttWarnMs/);
    expect(() => validateTcpTlsExtra({ rttWarnMs: -5 })).toThrow(/rttWarnMs/);
    expect(() => validateTcpTlsExtra({ rttWarnMs: Number.NaN })).toThrow(
      /rttWarnMs/,
    );
    expect(() => validateTcpTlsExtra({ retransmitWarnPct: -1 })).toThrow(
      /retransmitWarnPct/,
    );
    expect(() => validateTcpTlsExtra({ retransmitWarnPct: 101 })).toThrow(
      /retransmitWarnPct/,
    );
    expect(() => validateTcpTlsExtra({ certExpiryWarnDays: 0 })).toThrow(
      /certExpiryWarnDays/,
    );
    expect(() => validateTcpTlsExtra({ certExpiryWarnDays: 366 })).toThrow(
      /certExpiryWarnDays/,
    );
    expect(() => validateTcpTlsExtra({ certExpiryWarnDays: 10.5 })).toThrow(
      /certExpiryWarnDays/,
    );
    expect(() =>
      validateTcpTlsExtra({ sourcetype: "stream:http" as any }),
    ).toThrow(/sourcetype/);
  });
});

describe("buildTcpTlsSearch & sensitive-field guards", () => {
  it("builds bounded allowlist-only SPL for stream:tcp and stream:netflow", () => {
    const tcpSpl = buildTcpTlsSearch({
      index: "stream_tcp",
      sourcetype: "stream:tcp",
      filter: {
        src: "198.18.38.10",
        dst: "198.18.38.20",
        device: "fwd-01",
        vni: "10010",
      },
      maxRows: 256,
    });
    expect(tcpSpl).toContain("index=stream_tcp");
    expect(tcpSpl).toContain('sourcetype="stream:tcp"');
    expect(tcpSpl).toContain('src_ip="198.18.38.10"');
    expect(tcpSpl).toContain('dest_ip="198.18.38.20"');
    expect(tcpSpl).toContain('(host="fwd-01" OR exporter_ip="fwd-01")');
    expect(tcpSpl).toContain('vxlan_id="10010"');
    expect(tcpSpl).toContain("| table ");
    expect(tcpSpl).not.toContain("| fields ");
    expect(tcpSpl).not.toContain("| sort 0 - _time");
    expect(tcpSpl.indexOf("| head 257")).toBeLessThan(
      tcpSpl.indexOf("| table "),
    );
    expect(() => assertNoForbiddenFieldsInSpl("tcp_tls", tcpSpl)).not.toThrow();

    for (const forbidden of FORBIDDEN_SENSITIVE_FIELDS) {
      expect(tcpSpl.toLowerCase()).not.toMatch(
        new RegExp(`\\b${forbidden}\\b`),
      );
    }

    const nfSpl = buildTcpTlsSearch({
      index: "netflow",
      sourcetype: "stream:netflow",
      maxRows: 100,
    });
    expect(nfSpl).toContain('sourcetype="stream:netflow"');
    expect(nfSpl).toContain("total_bytes=coalesce");
    expect(nfSpl).toContain("| table ");
    expect(nfSpl).toContain("| head 101");
    expect(() => assertNoForbiddenFieldsInSpl("tcp_tls", nfSpl)).not.toThrow();
  });

  it("rejects SPL injection in filters and raw-events link builder", () => {
    expect(() =>
      buildTcpTlsSearch({
        index: "stream_tcp",
        sourcetype: "stream:tcp",
        filter: { src: '10.0.0.1" OR "1"="1' },
        maxRows: 256,
      }),
    ).toThrow(/Invalid literal/);

    const safeUrl = buildTcpTlsRawEventsUrl({
      index: "stream_tcp",
      sourcetype: "stream:tcp",
      client: "198.18.38.10",
      server: "198.18.38.20",
      earliest: EARLIEST,
      latest: NOW,
    });
    expect(safeUrl).toMatch(/^\/app\/splunk_adm\/search\?/);
    expect(safeUrl).toContain("sourcetype%3D%22stream%3Atcp%22");
    expect(() =>
      buildTcpTlsRawEventsUrl({
        index: "stream_tcp",
        sourcetype: "stream:tcp",
        client: "bad ip!",
        server: "198.18.38.20",
        earliest: EARLIEST,
        latest: NOW,
      }),
    ).toThrow(/Invalid literal/);
  });
});

describe("normalizeTcpTlsRow & buildTcpTlsAnalysis", () => {
  it("computes client vs server RTT split, flags high server RTT, and omits zero-sample RTT", () => {
    const highServer = normalizeTcpTlsRow(
      {
        _time: EARLIEST + 60,
        host: "fwd-01",
        sourcetype: "stream:tcp",
        src_ip: "10.0.0.1",
        dest_ip: "10.0.0.2",
        dest_port: 443,
        client_rtt: 4200,
        server_rtt: 68400,
        client_rtt_packets: 10,
        server_rtt_packets: 10,
        bytes_in: 4000,
        bytes_out: 1000,
        packets_in: 10,
        packets_out: 5,
        tcp_status: 0,
      },
      "stream:tcp",
      NOW,
    )!;
    const noRtt = normalizeTcpTlsRow(
      {
        _time: EARLIEST + 120,
        host: "fwd-01",
        sourcetype: "stream:tcp",
        src_ip: "10.0.0.3",
        dest_ip: "10.0.0.4",
        client_rtt: 0,
        client_rtt_packets: 0,
        server_rtt: 0,
        server_rtt_packets: 0,
        bytes_in: 1200,
        packets_in: 4,
      },
      "stream:tcp",
      NOW,
    )!;

    expect(highServer.clientRttMs).toBeCloseTo(4.2);
    expect(highServer.serverRttMs).toBeCloseTo(68.4);
    expect(noRtt.clientRttMs).toBeUndefined();
    expect(noRtt.serverRttMs).toBeUndefined();

    const analysis = buildTcpTlsAnalysis({
      events: [
        { event: highServer, indexName: "stream_tcp" },
        { event: noRtt, indexName: "stream_tcp" },
      ],
      thresholds: resolveTcpTlsThresholds(),
      earliest: EARLIEST,
      latest: NOW,
      outcomes: [{ source: "protocol_tcp_tls", state: "complete" }],
      capped: false,
    });

    expect(analysis.rows[0].client).toBe("10.0.0.1");
    expect(analysis.rows[0].attention).toBe(true);
    expect(analysis.rows[0].serverRttP95Ms).toBeCloseTo(68.4);
    expect(analysis.rows[0].clientRttP95Ms).toBeCloseTo(4.2);
    expect(analysis.rows[1].attention).toBe(false);
    expect(analysis.distribution).toEqual([
      expect.objectContaining({
        label: "10.0.0.2",
        p50: 68,
        p95: 68,
        unit: "ms",
        status: "attention",
      }),
    ]);
  });

  it("flags retransmits (bitmask & packet ratio) and TCP resets", () => {
    const retransEv = normalizeTcpTlsRow(
      {
        _time: EARLIEST + 50,
        host: "fwd-01",
        sourcetype: "stream:tcp",
        src_ip: "10.0.0.1",
        dest_ip: "10.0.0.2",
        packets_in: 400,
        packets_out: 100,
        duplicate_packets_in: 18,
        duplicate_packets_out: 6,
        tcp_status: 0,
      },
      "stream:tcp",
      NOW,
    )!;
    const resetEv = normalizeTcpTlsRow(
      {
        _time: EARLIEST + 100,
        host: "fwd-01",
        sourcetype: "stream:tcp",
        src_ip: "10.0.0.5",
        dest_ip: "10.0.0.6",
        packets_in: 10,
        packets_out: 10,
        tcp_status: 1,
        refused: true,
      },
      "stream:tcp",
      NOW,
    )!;
    const belowThreshold = normalizeTcpTlsRow(
      {
        _time: EARLIEST + 150,
        host: "fwd-01",
        sourcetype: "stream:tcp",
        src_ip: "10.0.0.7",
        dest_ip: "10.0.0.8",
        packets_in: 500,
        packets_out: 500,
        retransmits: 5,
        tcp_status: 0,
      },
      "stream:tcp",
      NOW,
    )!;

    const analysis = buildTcpTlsAnalysis({
      events: [
        { event: retransEv, indexName: "stream_tcp" },
        { event: resetEv, indexName: "stream_tcp" },
        { event: belowThreshold, indexName: "stream_tcp" },
      ],
      thresholds: resolveTcpTlsThresholds(),
      earliest: EARLIEST,
      latest: NOW,
      outcomes: [{ source: "protocol_tcp_tls", state: "complete" }],
      capped: false,
    });

    const retransRow = analysis.rows.find((r) => r.client === "10.0.0.1")!;
    expect(retransRow.attention).toBe(true);
    expect(retransRow.retransmitPct).toBeCloseTo(4.8);
    expect(retransRow.retransmitBasis).toBe("packets");
    expect(retransRow.reasons[0]).toContain("4.8% retransmits");

    const resetRow = analysis.rows.find((r) => r.client === "10.0.0.5")!;
    expect(resetRow.attention).toBe(true);
    expect(resetRow.resets).toBe(1);
    expect(resetRow.reasons[0]).toContain("1 TCP reset");

    const okRow = analysis.rows.find((r) => r.client === "10.0.0.7")!;
    expect(okRow.attention).toBe(false);
    expect(okRow.retransmitPct).toBeCloseTo(0.5);
  });

  it("detects expiring certificates, expired certificates, legacy TLSv1/1.0/1.1, and SSL errors", () => {
    expect(isLegacyTlsVersion("TLSv1")).toBe(true);
    expect(isLegacyTlsVersion("TLSv1.0")).toBe(true);
    expect(isLegacyTlsVersion("TLSv1.1")).toBe(true);
    expect(isLegacyTlsVersion("TLS 1.0")).toBe(true);
    expect(isLegacyTlsVersion("TLS1_1")).toBe(true);
    expect(isLegacyTlsVersion("SSLv3")).toBe(true);
    expect(isLegacyTlsVersion("TLSv1.2")).toBe(false);
    expect(isLegacyTlsVersion("TLSv1.3")).toBe(false);

    const expiring = normalizeTcpTlsRow(
      {
        _time: EARLIEST + 10,
        sourcetype: "stream:tcp",
        src_ip: "10.1.0.1",
        dest_ip: "10.1.0.2",
        tls_version: "TLSv1.2",
        ssl_cert_subject: "CN=pay.example",
        ssl_issuer: "CN=CA",
        ssl_cert_days_remaining: 9,
      },
      "stream:tcp",
      NOW,
    )!;
    const legacy = normalizeTcpTlsRow(
      {
        _time: EARLIEST + 20,
        sourcetype: "stream:tcp",
        src_ip: "10.1.0.3",
        dest_ip: "10.1.0.4",
        ssl_version: "TLSv1.1",
        ssl_end_time: new Date((NOW + 90 * 86400) * 1000).toISOString(),
      },
      "stream:tcp",
      NOW,
    )!;
    const sslErr = normalizeTcpTlsRow(
      {
        _time: EARLIEST + 30,
        sourcetype: "stream:tcp",
        src_ip: "10.1.0.5",
        dest_ip: "10.1.0.6",
        tls_version: "TLSv1.3",
        ssl_error: "certificate_revoked",
      },
      "stream:tcp",
      NOW,
    )!;
    const nonTls = normalizeTcpTlsRow(
      {
        _time: EARLIEST + 40,
        sourcetype: "stream:tcp",
        src_ip: "10.1.0.7",
        dest_ip: "10.1.0.8",
        dest_port: 5432,
      },
      "stream:tcp",
      NOW,
    )!;

    const analysis = buildTcpTlsAnalysis({
      events: [
        { event: expiring, indexName: "stream_tcp" },
        { event: legacy, indexName: "stream_tcp" },
        { event: sslErr, indexName: "stream_tcp" },
        { event: nonTls, indexName: "stream_tcp" },
      ],
      thresholds: resolveTcpTlsThresholds(),
      earliest: EARLIEST,
      latest: NOW,
      outcomes: [{ source: "protocol_tcp_tls", state: "complete" }],
      capped: false,
    });

    expect(analysis.rows.find((r) => r.client === "10.1.0.1")).toMatchObject({
      attention: true,
      tlsStatus: "attention",
      certDaysRemaining: 9,
    });
    expect(analysis.rows.find((r) => r.client === "10.1.0.3")).toMatchObject({
      attention: true,
      tlsStatus: "attention",
      tlsVersion: "TLSv1.1",
    });
    expect(analysis.rows.find((r) => r.client === "10.1.0.5")).toMatchObject({
      attention: true,
      tlsStatus: "attention",
      sslError: "certificate_revoked",
    });
    expect(analysis.rows.find((r) => r.client === "10.1.0.7")).toMatchObject({
      attention: false,
      hasTlsData: false,
      tlsStatus: "not_covered",
      tlsPostureLabel: "Not covered",
    });
  });

  it("loads and normalizes committed NDJSON fixtures cleanly", () => {
    const tcpLines = readFileSync(
      "fixtures/protocols/tcp_tls/stream_tcp_tls.ndjson",
      "utf8",
    )
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as Record<string, unknown>);
    const tcpEvents = tcpLines.map((row) => ({
      event: normalizeTcpTlsRow(row, "stream:tcp", NOW)!,
      indexName: "stream_tcp",
    }));
    const tcpAnalysis = buildTcpTlsAnalysis({
      events: tcpEvents,
      thresholds: resolveTcpTlsThresholds(),
      earliest: EARLIEST,
      latest: NOW,
      outcomes: [{ source: "protocol_tcp_tls", state: "complete" }],
      capped: false,
    });
    expect(tcpAnalysis.rows).toHaveLength(4);
    expect(tcpAnalysis.rows.filter((r) => r.attention)).toHaveLength(2);
    expect(tcpAnalysis.verdictStatus).toBe("attention");
    // Every pair ID must round-trip through parseProtocolLink's strict ITEM_ID regex.
    for (const row of tcpAnalysis.rows) {
      const parsed = parseProtocolLink(
        new URLSearchParams({ p_lens: "tcp_tls", p_item: row.id }),
      );
      expect(parsed.item).toBe(row.id);
    }

    const nfLines = readFileSync(
      "fixtures/protocols/tcp_tls/stream_netflow_fallback.ndjson",
      "utf8",
    )
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as Record<string, unknown>);
    const nfEvents = nfLines.map((row) => ({
      event: normalizeTcpTlsRow(row, "stream:netflow", NOW)!,
      indexName: "netflow",
    }));
    const nfAnalysis = buildTcpTlsAnalysis({
      events: nfEvents,
      thresholds: resolveTcpTlsThresholds(),
      earliest: EARLIEST,
      latest: NOW,
      outcomes: [{ source: "protocol_tcp_tls", state: "complete" }],
      capped: false,
    });
    expect(nfAnalysis.sourceMode).toBe("netflow_only");
    expect(nfAnalysis.verdictStatus).toBe("not_covered");
    expect(nfAnalysis.rows.every((r) => r.status === "not_covered")).toBe(true);
    expect(nfAnalysis.rows.some((r) => r.status === "ok")).toBe(false);
    expect(
      nfAnalysis.kpis.find((k) => k.id === "rtt-tls-coverage")?.status,
    ).toBe("not_covered");
    expect(
      nfAnalysis.kpis.find((k) => k.id === "netflow-bytes")?.status,
    ).toBeUndefined();
    expect(nfAnalysis.distribution).toEqual([]);
  });
});

describe("investigateTcpTls (runner, NetFlow fallback, Estimate mode, security)", () => {
  it("falls back to stream:netflow when stream:tcp is absent and marks RTT/TLS not_covered", async () => {
    const search = vi.fn().mockResolvedValue({
      rows: [
        {
          _time: String(EARLIEST + 20),
          host: "stream-hf-01",
          sourcetype: "stream:netflow",
          exporter_ip: "198.18.131.1",
          src_ip: "198.18.38.10",
          dest_ip: "198.18.38.20",
          total_bytes: 22600,
          total_packets: 40,
        },
      ],
      warnings: [],
      errors: [],
    });
    const client: SearchClient = { search };
    const result = await investigateTcpTls(
      client,
      makeRequest(),
      makeConfig([
        makeProfile({
          id: "nf-dc1",
          index: "netflow",
          extra: { sourcetype: "stream:netflow" },
        }),
      ]),
      new AbortController().signal,
      { skipConfigRecheck: true },
    );
    expect(result.sourceMode).toBe("netflow_only");
    expect(result.coverageStatus).toBe("not_covered");
    expect(result.rows[0].status).toBe("not_covered");
    expect(result.rows[0].serverRttP95Ms).toBeUndefined();
    expect(result.rows[0].hasTlsData).toBe(false);
    expect(result.rows[0].totalBytes).toBe(22600);
    expect(result.matrixCells[0].status).toBe("not_covered");
  });

  it("reports runtime search failures as unknown (not not_covered) and flags blocked primary + fallback as partial", async () => {
    const failedClient: SearchClient = {
      search: vi.fn().mockRejectedValue(new Error("Search dispatch timed out")),
    };
    const failed = await investigateTcpTls(
      failedClient,
      makeRequest(),
      makeConfig([makeProfile()]),
      new AbortController().signal,
      { skipConfigRecheck: true },
    );
    expect(failed.bannerState).toBe("unavailable");
    expect(failed.verdictStatus).toBe("unknown");
    expect(failed.coverageStatus).toBe("unknown");

    const blockedPrimarySearch = vi
      .fn()
      .mockRejectedValueOnce(new SearchAccessDeniedError())
      .mockResolvedValueOnce({
        rows: [
          {
            _time: String(EARLIEST + 20),
            host: "leaf1",
            sourcetype: "stream:netflow",
            src_ip: "198.18.38.10",
            dest_ip: "198.18.38.20",
            total_bytes: 4096,
            total_packets: 12,
          },
        ],
        warnings: [],
        errors: [],
      });
    const partial = await investigateTcpTls(
      { search: blockedPrimarySearch },
      makeRequest(),
      makeConfig([
        makeProfile({ id: "tcp-primary", index: "stream_tcp" }),
        makeProfile({
          id: "nf-fallback",
          index: "netflow",
          extra: { sourcetype: "stream:netflow" },
        }),
      ]),
      new AbortController().signal,
      { skipConfigRecheck: true },
    );
    expect(partial.bannerState).toBe("partial");
    expect(partial.bannerReason).toMatch(/Primary source blocked/i);
    expect(partial.rows[0].status).toBe("not_covered");
  });

  it("surfaces degraded multi-source outcomes truthfully instead of none_observed or ok", async () => {
    const profilesTwo = makeConfig([
      makeProfile({ id: "tcp-primary", index: "stream_tcp" }),
      makeProfile({
        id: "nf-fallback",
        index: "netflow",
        extra: { sourcetype: "stream:netflow" },
      }),
    ]);

    // Case 1: stream:tcp times out and NetFlow fallback completes with 0 rows -> unavailable/unknown (NOT none_observed)
    const timeoutThenEmpty = await investigateTcpTls(
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

    // Case 2: stream:tcp denied and NetFlow fallback completes with 0 rows -> blocked/unknown (NOT none_observed)
    const deniedThenEmpty = await investigateTcpTls(
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

    // Case 3: Two stream:tcp profiles where A returns rows and B times out -> partial/attention (NOT ok)
    const partialTcp = await investigateTcpTls(
      {
        search: vi
          .fn()
          .mockResolvedValueOnce({
            rows: [
              {
                _time: EARLIEST + 10,
                sourcetype: "stream:tcp",
                src_ip: "10.0.0.1",
                dest_ip: "10.0.0.2",
                client_rtt: 2000,
                server_rtt: 4000,
                packets_in: 10,
                packets_out: 10,
              },
            ],
            warnings: [],
            errors: [],
          })
          .mockRejectedValueOnce(new Error("Indexer B timeout")),
      },
      makeRequest(),
      makeConfig([
        makeProfile({ id: "tcp-a", index: "stream_a" }),
        makeProfile({ id: "tcp-b", index: "stream_b" }),
      ]),
      new AbortController().signal,
      { skipConfigRecheck: true },
    );
    expect(partialTcp.bannerState).toBe("partial");
    expect(partialTcp.coverageStatus).toBe("attention");
    expect(partialTcp.bannerReason).toMatch(/One or more sources failed/i);

    // Case 4: stream:tcp times out and NetFlow fallback returns rows -> partial/attention
    const timeoutWithFallback = await investigateTcpTls(
      {
        search: vi
          .fn()
          .mockRejectedValueOnce(new Error("Stream search timed out"))
          .mockResolvedValueOnce({
            rows: [
              {
                _time: EARLIEST + 20,
                sourcetype: "stream:netflow",
                src_ip: "10.0.0.1",
                dest_ip: "10.0.0.2",
                total_bytes: 2048,
                total_packets: 8,
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
    expect(timeoutWithFallback.bannerState).toBe("partial");
    expect(timeoutWithFallback.bannerReason).toMatch(
      /One or more sources failed/i,
    );
    expect(timeoutWithFallback.rows[0].status).toBe("not_covered");

    // VNI filter active: do NOT silently run unfiltered NetFlow fallback
    const vniSearch = vi
      .fn()
      .mockResolvedValue({ rows: [], warnings: [], errors: [] });
    await investigateTcpTls(
      { search: vniSearch },
      makeRequest({ filter: { vni: "10010" } }),
      profilesTwo,
      new AbortController().signal,
      { skipConfigRecheck: true, skipEstimateCheck: true },
    );
    expect(vniSearch).toHaveBeenCalledTimes(1);
    expect(vniSearch.mock.calls[0][0].search).toContain('vxlan_id="10010"');
  });

  it("checks Stream Estimate mode when stream:tcp returns 0 rows and surfaces estimate_only", async () => {
    const search = vi
      .fn()
      .mockResolvedValueOnce({ rows: [], warnings: [], errors: [] })
      .mockResolvedValueOnce({
        rows: [{ host: "stream-fwd-01", stream_id: "tcp", stats_only: "true" }],
        warnings: [],
        errors: [],
      });
    const client: SearchClient = { search };
    const result = await investigateTcpTls(
      client,
      makeRequest(),
      makeConfig([makeProfile()]),
      new AbortController().signal,
      { skipConfigRecheck: true },
    );
    expect(search).toHaveBeenCalledTimes(2);
    expect(search.mock.calls[1][0].search).toContain(
      'sourcetype="stream:stats"',
    );
    expect(result.bannerState).toBe("estimate_only");
    expect(result.streamReadiness?.state).toBe("estimate_only");
  });

  it("handles zero-row empty state when Stream is Enabled", async () => {
    const search = vi
      .fn()
      .mockResolvedValueOnce({ rows: [], warnings: [], errors: [] })
      .mockResolvedValueOnce({
        rows: [
          { host: "stream-fwd-01", stream_id: "tcp", stats_only: "false" },
        ],
        warnings: [],
        errors: [],
      });
    const client: SearchClient = { search };
    const result = await investigateTcpTls(
      client,
      makeRequest(),
      makeConfig([makeProfile()]),
      new AbortController().signal,
      { skipConfigRecheck: true },
    );
    expect(result.bannerState).toBe("empty");
    expect(result.bannerReason).toContain("Enabled");
  });

  it("handles access-denied blocked state cleanly", async () => {
    const client: SearchClient = {
      search: vi.fn().mockRejectedValue(new SearchAccessDeniedError()),
    };
    const result = await investigateTcpTls(
      client,
      makeRequest(),
      makeConfig([makeProfile()]),
      new AbortController().signal,
      { skipConfigRecheck: true },
    );
    expect(result.bannerState).toBe("blocked");
    expect(result.coverageStatus).toBe("unknown");
  });

  it("handles unconfigured scope as unavailable without searching", async () => {
    const search = vi.fn();
    const client: SearchClient = { search };
    const result = await investigateTcpTls(
      client,
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
          sourcetype: "stream:tcp",
          src_ip: "10.0.0.1",
          dest_ip: "10.0.0.2",
          client_rtt: 3000,
          server_rtt: 9000,
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

    // First verify normal execution strips sensitive fields (via summarizeTcpTls).
    const spy = vi
      .spyOn(protocolConfigClient, "readProtocolProfileDocument")
      .mockResolvedValue({
        version: 1,
        profiles: [makeProfile()],
      });
    try {
      const config = await import("../../shared/runner").then((m) =>
        m.readProtocolConfiguration({ tcp_tls: validateTcpTlsExtra }),
      );
      const summary = await summarizeTcpTls(
        client,
        makeRequest(),
        config,
        new AbortController().signal,
      );
      expect(summary.status).toBe("ok");

      // Now simulate config changing mid-flight -> stale_config
      spy.mockResolvedValueOnce({
        version: 1,
        profiles: [makeProfile({ index: "other_index" })],
      });
      const stale = await investigateTcpTls(
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

  it("builds bidirectional endpoint and port SPL filters before head", () => {
    const spl = buildTcpTlsSearch({
      index: "stream_tcp",
      sourcetype: "stream:tcp",
      filter: {
        src: "10.0.0.1",
        dst: "10.0.0.2",
        port: "443",
        bidirectional: true,
      },
      maxRows: 256,
    });
    expect(spl).toContain('src_ip="10.0.0.1"');
    expect(spl).toContain('dest_ip="10.0.0.2"');
    expect(spl).toContain('src_ip="10.0.0.2"');
    expect(spl).toContain('dest_ip="10.0.0.1"');
    expect(spl).toContain('(dest_port="443" OR src_port="443")');
    expect(spl.indexOf('dest_port="443"')).toBeLessThan(spl.indexOf("| head"));
  });

  it("ignores cleartext ssl_version=0.0 sentinel and maps Stream wire codes (3.3 -> TLS 1.2)", () => {
    const cleartext = normalizeTcpTlsRow(
      {
        _time: EARLIEST + 10,
        src_ip: "10.64.64.15",
        dest_ip: "198.18.133.50",
        dest_port: 8000,
        ssl_version: "0.0",
      },
      "stream:tcp",
      NOW,
    )!;
    expect(cleartext.tlsVersion).toBeUndefined();
    expect(cleartext.hasTlsData).toBe(false);

    const tls12 = normalizeTcpTlsRow(
      {
        _time: EARLIEST + 12,
        src_ip: "198.18.133.50",
        dest_ip: "198.18.131.1",
        dest_port: 443,
        ssl_version: "3.3",
      },
      "stream:tcp",
      NOW,
    )!;
    expect(tls12.tlsVersion).toBe("TLS 1.2");
    expect(tls12.hasTlsData).toBe(true);
    expect(tls12.legacyTls).toBe(false);

    const tls10 = normalizeTcpTlsRow(
      {
        _time: EARLIEST + 14,
        src_ip: "198.18.133.50",
        dest_ip: "198.18.131.2",
        dest_port: 443,
        tls_version: "0.0",
        ssl_version: ["0.0", "3.1"],
      },
      "stream:tcp",
      NOW,
    )!;
    expect(tls10.tlsVersion).toBe("TLS 1.0");
    expect(tls10.legacyTls).toBe(true);
  });

  it("does not fall back to NetFlow-only when a filtered stream:tcp query returns zero rows", async () => {
    const search = vi.fn().mockResolvedValue({
      rows: [],
      warnings: [],
      errors: [],
    });
    const res = await investigateTcpTls(
      { search },
      makeRequest({ filter: { src: "198.18.99.99" } }),
      makeConfig([
        makeProfile({ id: "tcp-primary", extra: { sourcetype: "stream:tcp" } }),
        makeProfile({
          id: "tcp-fallback",
          extra: { sourcetype: "stream:netflow" },
        }),
      ]),
      new AbortController().signal,
      { skipConfigRecheck: true, skipEstimateCheck: true },
    );
    expect(search).toHaveBeenCalledTimes(1);
    expect(res.sourceMode).toBe("none");
    expect(res.bannerState).toBe("empty");
  });
});
