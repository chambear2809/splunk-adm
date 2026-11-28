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
  ROW_EXPANSION_ONLY_FIELDS,
  assertNoForbiddenFieldsInSpl,
} from "../../shared/fields";
import {
  buildEnterpriseL7Analysis,
  buildEnterpriseL7RawEventsUrl,
  buildEnterpriseL7RowExpansionSearch,
  buildEnterpriseL7Search,
  fetchEnterpriseL7RowExpansion,
  investigateEnterpriseL7,
  isSmbV1Dialect,
  normalizeEnterpriseL7Row,
  resolveEnterpriseL7Thresholds,
  summarizeEnterpriseL7,
  validateEnterpriseL7Extra,
} from "./adapter";

const NOW = 1800000500;
const EARLIEST = 1800000000;

function makeProfile(
  overrides: Partial<BaseProtocolProfile> = {},
): BaseProtocolProfile {
  return {
    id: "enterprise-l7-dc1",
    source: "protocol_enterprise_l7",
    lens: "enterprise_l7",
    scope: "prod:dc1",
    index: "stream_l7",
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
    lens: "enterprise_l7",
    scope: "prod:dc1",
    earliest: EARLIEST,
    latest: NOW,
    ...overrides,
  };
}

describe("validateEnterpriseL7Extra (fail-closed profile validation)", () => {
  it("accepts valid thresholds and sourcetypes and integrates with parseProtocolProfiles", () => {
    expect(validateEnterpriseL7Extra(undefined)).toBeUndefined();
    expect(
      validateEnterpriseL7Extra({
        sourcetypes: ["stream:smb", "stream:ldap"],
        smbErrorWarnPct: 10,
        nfsLatencyWarnMs: 120,
        nfsErrorWarnPct: 3,
        ldapErrorWarnPct: 4,
        radiusRejectWarnCount: 8,
        voipMosWarnMin: 3.6,
        voipJitterWarnMs: 25,
        voipLossWarnPct: 1.5,
      }),
    ).toEqual({
      sourcetypes: ["stream:smb", "stream:ldap"],
      smbErrorWarnPct: 10,
      nfsLatencyWarnMs: 120,
      nfsErrorWarnPct: 3,
      ldapErrorWarnPct: 4,
      radiusRejectWarnCount: 8,
      voipMosWarnMin: 3.6,
      voipJitterWarnMs: 25,
      voipLossWarnPct: 1.5,
    });

    const profiles = parseProtocolProfiles(
      {
        version: 1,
        profiles: [
          {
            id: "enterprise-l7-dc1",
            source: "protocol_enterprise_l7",
            lens: "enterprise_l7",
            scope: "prod:dc1",
            index: "stream_l7",
            observer: "stream-fwd-01",
            validFrom: EARLIEST - 3600,
            validUntil: NOW + 3600,
            extra: {
              sourcetype: "stream:radius",
              radiusRejectWarnCount: 12,
            },
          },
        ],
      },
      { enterprise_l7: validateEnterpriseL7Extra },
    );
    expect(resolveEnterpriseL7Thresholds(profiles[0])).toMatchObject({
      sourcetypes: ["stream:radius"],
      radiusRejectWarnCount: 12,
      voipMosWarnMin: 3.5,
      voipJitterWarnMs: 30,
      voipLossWarnPct: 1,
    });
  });

  it("rejects unknown keys, conflicting sourcetype selectors, and out-of-range values", () => {
    expect(() => validateEnterpriseL7Extra({ unknownKey: true })).toThrow(
      /Unsupported enterprise_l7/,
    );
    expect(() =>
      validateEnterpriseL7Extra({
        sourcetype: "stream:smb",
        sourcetypes: ["stream:nfs"],
      }),
    ).toThrow(/cannot specify both/);
    expect(() =>
      validateEnterpriseL7Extra({ sourcetype: "stream:dns" as never }),
    ).toThrow(/sourcetype/);
    expect(() => validateEnterpriseL7Extra({ sourcetypes: [] })).toThrow(
      /non-empty/,
    );
    expect(() =>
      validateEnterpriseL7Extra({
        sourcetypes: ["stream:smb", "stream:smb"],
      }),
    ).toThrow(/duplicate/);
    expect(() => validateEnterpriseL7Extra({ smbErrorWarnPct: -1 })).toThrow(
      /smbErrorWarnPct/,
    );
    expect(() => validateEnterpriseL7Extra({ nfsLatencyWarnMs: 0 })).toThrow(
      /nfsLatencyWarnMs/,
    );
    expect(() => validateEnterpriseL7Extra({ nfsErrorWarnPct: 101 })).toThrow(
      /nfsErrorWarnPct/,
    );
    expect(() =>
      validateEnterpriseL7Extra({ ldapErrorWarnPct: Number.NaN }),
    ).toThrow(/ldapErrorWarnPct/);
    expect(() =>
      validateEnterpriseL7Extra({ radiusRejectWarnCount: 1.5 }),
    ).toThrow(/integer/);
    expect(() =>
      validateEnterpriseL7Extra({ radiusRejectWarnCount: 0 }),
    ).toThrow(/radiusRejectWarnCount/);
    expect(() => validateEnterpriseL7Extra({ voipMosWarnMin: 0.9 })).toThrow(
      /voipMosWarnMin/,
    );
    expect(() => validateEnterpriseL7Extra({ voipJitterWarnMs: 0 })).toThrow(
      /voipJitterWarnMs/,
    );
    expect(() => validateEnterpriseL7Extra({ voipLossWarnPct: 0 })).toThrow(
      /voipLossWarnPct/,
    );
  });
});

describe("buildEnterpriseL7Search & privacy / security boundaries", () => {
  it("never references forbidden sensitive fields or row-expansion fields in Overview SPL and emits head before table", () => {
    const spl = buildEnterpriseL7Search({
      index: "stream_l7",
      filter: {
        src: "10.10.20.11",
        dst: "10.10.30.10",
        device: "stream-fwd-01",
      },
      maxRows: 256,
    });
    expect(spl).toContain("index=stream_l7");
    expect(spl).toContain('sourcetype="stream:smb"');
    expect(spl).toContain('sourcetype="stream:rtcp"');
    expect(spl).toContain('src_ip="10.10.20.11"');
    expect(spl).toContain('dest_ip="10.10.30.10"');
    expect(spl).toContain("| table ");
    expect(spl).not.toContain("| fields ");
    expect(spl.indexOf("| head 257")).toBeLessThan(spl.indexOf("| table "));
    expect(() =>
      assertNoForbiddenFieldsInSpl("enterprise_l7", spl),
    ).not.toThrow();

    for (const forbidden of FORBIDDEN_SENSITIVE_FIELDS) {
      expect(spl.toLowerCase()).not.toMatch(new RegExp(`\\b${forbidden}\\b`));
    }
    for (const expansionOnly of ROW_EXPANSION_ONLY_FIELDS) {
      expect(spl.toLowerCase()).not.toMatch(
        new RegExp(`\\b${expansionOnly}\\b`),
      );
    }
  });

  it("includes user_id or calling_station_id ONLY in explicit single-row expansion SPL", () => {
    const smbExpansion = buildEnterpriseL7RowExpansionSearch({
      index: "stream_l7",
      protocol: "SMB",
      server: "10.10.30.10",
    });
    expect(smbExpansion).toContain("user_id");
    expect(smbExpansion).not.toContain("calling_station_id");
    expect(smbExpansion.indexOf("| head 33")).toBeLessThan(
      smbExpansion.indexOf("| table "),
    );
    expect(() =>
      assertNoForbiddenFieldsInSpl("enterprise_l7", smbExpansion),
    ).not.toThrow();

    const radiusExpansion = buildEnterpriseL7RowExpansionSearch({
      index: "stream_l7",
      protocol: "RADIUS",
      server: "10.10.30.30",
    });
    expect(radiusExpansion).toContain("calling_station_id");
    expect(radiusExpansion).not.toContain("user_id");
    expect(() =>
      assertNoForbiddenFieldsInSpl("enterprise_l7", radiusExpansion),
    ).not.toThrow();
  });

  it("rejects SPL injection in filters and raw-events link builder", () => {
    expect(() =>
      buildEnterpriseL7Search({
        index: "stream_l7",
        filter: { dst: '10.0.0.1" OR "1"="1' },
        maxRows: 256,
      }),
    ).toThrow(/Invalid literal/);

    const url = buildEnterpriseL7RawEventsUrl({
      index: "stream_l7",
      sourcetypes: ["stream:smb"],
      server: "10.10.30.10",
      earliest: EARLIEST,
      latest: NOW,
    });
    expect(url).toMatch(/^\/app\/splunk_adm\/search\?/);
    expect(url).toContain("sourcetype%3D%22stream%3Asmb%22");

    expect(() =>
      buildEnterpriseL7RawEventsUrl({
        index: "stream_l7",
        sourcetypes: ["stream:smb"],
        server: "bad server!",
        earliest: EARLIEST,
        latest: NOW,
      }),
    ).toThrow(/Invalid literal/);
  });
});

describe("normalizeEnterpriseL7Row & buildEnterpriseL7Analysis", () => {
  it("flags SMBv1, SMB NT errors, NFS errors/latency, LDAP simple bind, RADIUS NAS reject spike, and VoIP MOS/jitter/loss", () => {
    expect(isSmbV1Dialect("NT LM 0.12")).toBe(true);
    expect(isSmbV1Dialect("SMB1")).toBe(true);
    expect(isSmbV1Dialect("1.0")).toBe(true);
    expect(isSmbV1Dialect("SMB 3.1.1")).toBe(false);
    expect(isSmbV1Dialect("SMB 2.1")).toBe(false);

    const smbSmbv1 = normalizeEnterpriseL7Row({
      _time: EARLIEST + 10,
      sourcetype: "stream:smb",
      src_ip: "10.10.20.11",
      dest_ip: "10.10.30.10",
      dialect: "NT LM 0.12",
      nt_status: "STATUS_LOGON_FAILURE",
      response_time: 5000,
    })!;
    const smbHealthy = normalizeEnterpriseL7Row({
      _time: EARLIEST + 20,
      sourcetype: "stream:smb",
      src_ip: "10.10.20.12",
      dest_ip: "10.10.30.11",
      dialect: "SMB 3.1.1",
      nt_status: "STATUS_SUCCESS",
      response_time: 1800,
    })!;

    const nfsBad = normalizeEnterpriseL7Row({
      _time: EARLIEST + 30,
      sourcetype: "stream:nfs",
      src_ip: "10.10.20.20",
      dest_ip: "10.10.30.15",
      nfs_version: "3",
      status: "NFS3ERR_ACCES",
      time_taken: 80_000,
    })!;
    const nfsGood = normalizeEnterpriseL7Row({
      _time: EARLIEST + 40,
      sourcetype: "stream:nfs",
      src_ip: "10.10.20.21",
      dest_ip: "10.10.30.16",
      nfs_version: "4.1",
      status: "NFS4_OK",
      time_taken: 3_000,
    })!;

    const ldapSimple = normalizeEnterpriseL7Row({
      _time: EARLIEST + 50,
      sourcetype: "stream:ldap",
      src_ip: "10.10.20.30",
      dest_ip: "10.10.30.20",
      dest_port: 389,
      message_type: "bindRequest",
      auth_type: "simple",
      result_code: "49",
      response_time: 10_000,
    })!;
    const ldapSasl = normalizeEnterpriseL7Row({
      _time: EARLIEST + 60,
      sourcetype: "stream:ldap",
      src_ip: "10.10.20.31",
      dest_ip: "10.10.30.21",
      dest_port: 389,
      message_type: "bindRequest",
      auth_type: "sasl",
      sasl_mechanism: "GSSAPI",
      result_code: "0",
      response_time: 3_000,
    })!;

    const radiusSpikes = Array.from({ length: 5 }, (_, i) => ({
      event: normalizeEnterpriseL7Row({
        _time: EARLIEST + 70 + i * 5,
        sourcetype: "stream:radius",
        src_ip: "10.10.1.5",
        dest_ip: "10.10.30.30",
        nas_ip_address: "10.10.1.5",
        code: "Access-Reject",
        time_taken: 4000,
      })!,
      indexName: "stream_l7",
    }));

    const voipBadSip = normalizeEnterpriseL7Row({
      _time: EARLIEST + 100,
      sourcetype: "stream:sip",
      src_ip: "10.10.40.10",
      dest_ip: "10.10.30.50",
      method: "INVITE",
      response_code: 503,
      response_time: 14_000,
    })!;
    const voipBadRtp = normalizeEnterpriseL7Row({
      _time: EARLIEST + 110,
      sourcetype: "stream:rtp",
      src_ip: "10.10.40.10",
      dest_ip: "10.10.30.50",
      mos: 2.8,
      rtp_jitter: 44,
      packet_loss_pct: 2.3,
      codec: "G.711u",
    })!;
    // SIP 401 auth challenge is normal and must NOT be flagged as an error.
    const voipAuthChallenge = normalizeEnterpriseL7Row({
      _time: EARLIEST + 120,
      sourcetype: "stream:sip",
      src_ip: "10.10.40.11",
      dest_ip: "10.10.30.51",
      method: "REGISTER",
      response_code: 401,
      response_time: 5_000,
    })!;

    const analysis = buildEnterpriseL7Analysis({
      events: [
        { event: smbSmbv1, indexName: "stream_l7" },
        { event: smbHealthy, indexName: "stream_l7" },
        { event: nfsBad, indexName: "stream_l7" },
        { event: nfsGood, indexName: "stream_l7" },
        { event: ldapSimple, indexName: "stream_l7" },
        { event: ldapSasl, indexName: "stream_l7" },
        ...radiusSpikes,
        { event: voipBadSip, indexName: "stream_l7" },
        { event: voipBadRtp, indexName: "stream_l7" },
        { event: voipAuthChallenge, indexName: "stream_l7" },
      ],
      thresholds: resolveEnterpriseL7Thresholds(),
      earliest: EARLIEST,
      latest: NOW,
      outcomes: [{ source: "protocol_enterprise_l7", state: "complete" }],
      capped: false,
    });

    expect(analysis.verdictStatus).toBe("attention");
    expect(analysis.kpis).toHaveLength(4);
    expect(
      analysis.kpis.find((k) => k.id === "legacy-insecure-auth")?.value,
    ).toBe("2");
    expect(analysis.kpis.find((k) => k.id === "radius-rejects")?.value).toBe(
      "5",
    );
    expect(
      analysis.kpis.find((k) => k.id === "voip-quality-alerts")?.value,
    ).toBe("1");

    const smbFlagged = analysis.rows.find((r) => r.id === "SMB__10.10.30.10")!;
    expect(smbFlagged.attention).toBe(true);
    expect(smbFlagged.smbV1Count).toBe(1);
    expect(smbFlagged.errorPct).toBeCloseTo(100);

    const smbOk = analysis.rows.find((r) => r.id === "SMB__10.10.30.11")!;
    expect(smbOk.attention).toBe(false);
    expect(smbOk.status).toBe("ok");

    const nfsFlagged = analysis.rows.find((r) => r.id === "NFS__10.10.30.15")!;
    expect(nfsFlagged.attention).toBe(true);
    expect(nfsFlagged.latencyP95Ms).toBeCloseTo(80);

    const ldapFlagged = analysis.rows.find(
      (r) => r.id === "LDAP__10.10.30.20",
    )!;
    expect(ldapFlagged.attention).toBe(true);
    expect(ldapFlagged.ldapSimpleCleartextCount).toBe(1);

    const radiusFlagged = analysis.rows.find(
      (r) => r.id === "RADIUS__10.10.30.30",
    )!;
    expect(radiusFlagged.attention).toBe(true);
    expect(radiusFlagged.nasRejects[0]).toEqual({
      nasIp: "10.10.1.5",
      rejectCount: 5,
      totalCount: 5,
    });

    const voipFlagged = analysis.rows.find(
      (r) => r.id === "VoIP__10.10.30.50",
    )!;
    expect(voipFlagged.attention).toBe(true);
    expect(voipFlagged.voipMinMos).toBeCloseTo(2.8);
    expect(voipFlagged.voipMaxJitterMs).toBeCloseTo(44);
    expect(voipFlagged.voipMaxPacketLossPct).toBeCloseTo(2.3);

    const voipAuthOk = analysis.rows.find((r) => r.id === "VoIP__10.10.30.51")!;
    expect(voipAuthOk.attention).toBe(false);
    expect(voipAuthOk.sipErrorCount).toBe(0);
  });

  it("loads committed enterprise_l7 fixtures, validates link IDs, preserves IPv6, and marks unconfigured protocols not_covered", () => {
    const files = [
      "fixtures/protocols/enterprise_l7/stream_smb_nfs.ndjson",
      "fixtures/protocols/enterprise_l7/stream_ldap_radius.ndjson",
      "fixtures/protocols/enterprise_l7/stream_voip.ndjson",
    ];
    const events = files.flatMap((path) =>
      readFileSync(path, "utf8")
        .trim()
        .split("\n")
        .map((line) => ({
          event: normalizeEnterpriseL7Row(
            JSON.parse(line) as Record<string, unknown>,
          )!,
          indexName: "stream_l7",
        })),
    );
    const analysis = buildEnterpriseL7Analysis({
      events,
      thresholds: resolveEnterpriseL7Thresholds(),
      earliest: EARLIEST,
      latest: NOW,
      outcomes: [{ source: "protocol_enterprise_l7", state: "complete" }],
      capped: false,
    });

    expect(analysis.rows.length).toBe(10);
    expect(analysis.rows.filter((r) => r.attention)).toHaveLength(5);
    for (const row of analysis.rows) {
      const parsed = parseProtocolLink(
        new URLSearchParams({ p_lens: "enterprise_l7", p_item: row.id }),
      );
      expect(parsed.item).toBe(row.id);
    }

    // Verify full IPv6 server addresses are never truncated and unconfigured protocols become not_covered in Matrix.
    const ipv6Event = normalizeEnterpriseL7Row({
      _time: EARLIEST + 50,
      sourcetype: "stream:smb",
      src_ip: "2001:db8:1::10",
      dest_ip: "2001:db8:30::10",
      dialect: "SMB 3.1.1",
      nt_status: "STATUS_SUCCESS",
      response_time: 2000,
    })!;
    const partialProtoAnalysis = buildEnterpriseL7Analysis({
      events: [{ event: ipv6Event, indexName: "stream_l7" }],
      thresholds: resolveEnterpriseL7Thresholds(
        makeProfile({ extra: { sourcetype: "stream:smb" } }),
      ),
      configuredProtocols: ["SMB"],
      earliest: EARLIEST,
      latest: NOW,
      outcomes: [{ source: "protocol_enterprise_l7", state: "complete" }],
      capped: false,
    });
    expect(partialProtoAnalysis.rows[0].server).toBe("2001:db8:30::10");
    expect(partialProtoAnalysis.matrixCols).toContain("2001:db8:30::10");
    const nfsCell = partialProtoAnalysis.matrixCells.find(
      (c) => c.row === "NFS" && c.col === "2001:db8:30::10",
    );
    expect(nfsCell?.status).toBe("not_covered");
  });
});

describe("investigateEnterpriseL7, row expansion, degraded/capped downgrades, and stale config", () => {
  it("produces unknown/partial (never none_observed) on capped-empty searches", async () => {
    const search = vi.fn().mockResolvedValue({
      rows: [],
      warnings: [],
      errors: [],
      truncated: true,
    });
    const result = await investigateEnterpriseL7(
      { search },
      makeRequest(),
      makeConfig([makeProfile()]),
      new AbortController().signal,
      { skipConfigRecheck: true },
    );
    expect(result.capped).toBe(true);
    expect(result.verdictStatus).toBe("unknown");
    expect(result.coverageStatus).toBe("unknown");
    expect(result.bannerState).toBe("partial");
    expect(search).toHaveBeenCalledTimes(1);
  });

  it("checks Stream Estimate mode when streams return 0 uncapped rows and surfaces estimate_only", async () => {
    const search = vi
      .fn()
      .mockResolvedValueOnce({ rows: [], warnings: [], errors: [] })
      .mockResolvedValueOnce({
        rows: [
          { host: "stream-fwd-01", stream_id: "smb", stats_only: "true" },
          { host: "stream-fwd-01", stream_id: "nfs", stats_only: "false" },
        ],
        warnings: [],
        errors: [],
      });
    const result = await investigateEnterpriseL7(
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
    expect(search.mock.calls[1][0].search).toContain('"smb"');
    expect(search.mock.calls[1][0].search).toContain('"rtcp"');
    expect(result.bannerState).toBe("estimate_only");
    expect(result.verdictStatus).toBe("unknown");
  });

  it("downgrades summarizeEnterpriseL7 when a source is blocked or capped", async () => {
    const search = vi
      .fn()
      .mockResolvedValueOnce({
        rows: [
          {
            _time: EARLIEST + 10,
            sourcetype: "stream:smb",
            src_ip: "10.10.20.11",
            dest_ip: "10.10.30.11",
            dialect: "SMB 3.1.1",
            nt_status: "STATUS_SUCCESS",
            response_time: 1800,
          },
        ],
        warnings: [],
        errors: [],
      })
      .mockRejectedValueOnce(new SearchAccessDeniedError());

    const summary = await summarizeEnterpriseL7(
      { search },
      makeRequest(),
      makeConfig([
        makeProfile({ id: "l7-a", index: "stream_a" }),
        makeProfile({ id: "l7-b", index: "stream_b" }),
      ]),
      new AbortController().signal,
      { skipConfigRecheck: true },
    );
    expect(summary.status).toBe("attention");

    const blockedEmptySummary = await summarizeEnterpriseL7(
      {
        search: vi.fn().mockRejectedValue(new SearchAccessDeniedError()),
      },
      makeRequest(),
      makeConfig([makeProfile()]),
      new AbortController().signal,
      { skipConfigRecheck: true },
    );
    expect(blockedEmptySummary.status).toBe("unknown");
  });

  it("strips forbidden and row-expansion fields in Overview and fetches row-expansion only on explicit drilldown", async () => {
    const search = vi.fn().mockResolvedValue({
      rows: [
        {
          _time: EARLIEST + 10,
          sourcetype: "stream:smb",
          src_ip: "10.10.20.11",
          dest_ip: "10.10.30.10",
          dialect: "SMB 3.1.1",
          nt_status: "STATUS_SUCCESS",
          response_time: 2000,
          user_id: "alice-uid",
          calling_station_id: "00:11:22:33:44:55",
          login: "alice",
          content: "secret-file-data",
          _raw: "raw-leak",
        },
      ],
      warnings: [],
      errors: [],
    });
    const client: SearchClient = { search };

    const overview = await investigateEnterpriseL7(
      client,
      makeRequest(),
      makeConfig([makeProfile()]),
      new AbortController().signal,
      { skipConfigRecheck: true },
    );
    expect(JSON.stringify(overview)).not.toContain("alice-uid");
    expect(JSON.stringify(overview)).not.toContain("alice");
    expect(JSON.stringify(overview)).not.toContain("secret-file-data");
    expect(JSON.stringify(overview)).not.toContain("raw-leak");

    const expansion = await fetchEnterpriseL7RowExpansion(client, {
      profile: makeProfile(),
      protocol: "SMB",
      server: "10.10.30.10",
      earliest: EARLIEST,
      latest: NOW,
      signal: new AbortController().signal,
    });
    expect(expansion.fieldName).toBe("user_id");
    expect(expansion.values).toEqual(["alice-uid"]);
    expect(search.mock.calls[1][0].search).toContain("user_id");
    expect(search.mock.calls[1][0].search).not.toContain("login");
  });

  it("detects stale configuration via mocked protocolConfigClient.readProtocolProfileDocument", async () => {
    const search = vi.fn().mockResolvedValue({
      rows: [
        {
          _time: EARLIEST + 10,
          sourcetype: "stream:smb",
          src_ip: "10.10.20.11",
          dest_ip: "10.10.30.11",
          dialect: "SMB 3.1.1",
          nt_status: "STATUS_SUCCESS",
          response_time: 1800,
        },
      ],
      warnings: [],
      errors: [],
    });
    const spy = vi
      .spyOn(protocolConfigClient, "readProtocolProfileDocument")
      .mockResolvedValue({
        version: 1,
        profiles: [makeProfile()],
      });
    try {
      const config = await import("../../shared/runner").then((m) =>
        m.readProtocolConfiguration({
          enterprise_l7: validateEnterpriseL7Extra,
        }),
      );
      const okSummary = await summarizeEnterpriseL7(
        { search },
        makeRequest(),
        config,
        new AbortController().signal,
      );
      expect(okSummary.status).toBe("ok");

      spy.mockResolvedValueOnce({
        version: 1,
        profiles: [makeProfile({ index: "changed_index" })],
      });
      const stale = await investigateEnterpriseL7(
        { search },
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
});
