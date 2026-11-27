import { readFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import { protocolConfigClient } from "../../../data/evidenceConfig";
import {
  SearchAccessDeniedError,
  type SearchClient,
} from "../../../data/searchClient";
import { parseProtocolProfiles } from "../../inputs";
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
  buildMgmtFtpSearch,
  buildMgmtNetflowSearch,
  buildMgmtPlaneAnalysis,
  buildMgmtPlaneRawEventsUrl,
  buildMgmtSnmpSearch,
  buildMgmtSyslogSearch,
  classifySnmpVersion,
  investigateMgmtPlane,
  isSnmpSetOperation,
  makeMgmtPlaneRowId,
  normalizeMgmtPlaneRow,
  resolveMgmtPlaneThresholds,
  shortenDeviceLabel,
  summarizeMgmtPlane,
  validateMgmtPlaneExtra,
} from "./adapter";

const EARLIEST = 1764244700;
const NOW = 1764247100;

function makeProfile(
  overrides: Partial<BaseProtocolProfile> = {},
): BaseProtocolProfile {
  return {
    id: "mgmt-dc1",
    source: "protocol_mgmt_plane",
    lens: "mgmt_plane",
    scope: "prod:dc1",
    index: "netflow",
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
    lens: "mgmt_plane",
    scope: "prod:dc1",
    earliest: EARLIEST,
    latest: NOW,
    ...overrides,
  };
}

describe("validateMgmtPlaneExtra (fail-closed profile validation)", () => {
  it("accepts valid thresholds and integrates with parseProtocolProfiles", () => {
    expect(validateMgmtPlaneExtra(undefined)).toBeUndefined();
    expect(
      validateMgmtPlaneExtra({
        sourceKind: "netflow",
        receiptGapMinutes: 30,
        flagSnmpV2c: false,
        flagHttpPort80: false,
        mgmtIps: ["192.0.2.10", "192.0.2.11", "192.0.2.10"],
      }),
    ).toEqual({
      sourceKind: "netflow",
      receiptGapMinutes: 30,
      flagSnmpV2c: false,
      flagHttpPort80: false,
      mgmtIps: ["192.0.2.10", "192.0.2.11"],
    });

    const profiles = parseProtocolProfiles(
      {
        version: 1,
        profiles: [
          {
            id: "mgmt-dc1",
            source: "protocol_mgmt_plane",
            lens: "mgmt_plane",
            scope: "prod:dc1",
            index: "netflow",
            observer: "stream-fwd-01",
            validFrom: EARLIEST - 3600,
            validUntil: NOW + 3600,
            extra: { receiptGapMinutes: 20, flagHttpPort80: false },
          },
        ],
      },
      { mgmt_plane: validateMgmtPlaneExtra },
    );

    expect(resolveMgmtPlaneThresholds(profiles[0])).toEqual({
      sourceKind: "auto",
      receiptGapMinutes: 20,
      flagSnmpV2c: true,
      flagHttpPort80: false,
      mgmtIps: [],
    });
  });

  it("rejects unknown keys and out-of-range values", () => {
    expect(() => validateMgmtPlaneExtra({ unknownKey: true })).toThrow(
      /Unsupported mgmt_plane/,
    );
    expect(() =>
      validateMgmtPlaneExtra({ sourceKind: "bad_source" as never }),
    ).toThrow(/sourceKind/);
    expect(() => validateMgmtPlaneExtra({ receiptGapMinutes: 4 })).toThrow(
      /5 and 1440/,
    );
    expect(() => validateMgmtPlaneExtra({ receiptGapMinutes: 1441 })).toThrow(
      /5 and 1440/,
    );
    expect(() => validateMgmtPlaneExtra({ receiptGapMinutes: 15.5 })).toThrow(
      /5 and 1440/,
    );
    expect(() =>
      validateMgmtPlaneExtra({ flagSnmpV2c: "true" as never }),
    ).toThrow(/flagSnmpV2c/);
    expect(() =>
      validateMgmtPlaneExtra({ flagHttpPort80: 1 as never }),
    ).toThrow(/flagHttpPort80/);
    expect(() => validateMgmtPlaneExtra({ mgmtIps: ["not-an-ip"] })).toThrow(
      /mgmtIps/,
    );
  });
});

describe("SPL builders and security boundaries", () => {
  it("emits | head BEFORE | table and never references forbidden sensitive fields", () => {
    const queries = [
      buildMgmtSnmpSearch({
        index: "netflow",
        filter: { src: "198.51.100.20", dst: "192.0.2.11" },
        maxRows: 256,
      }),
      buildMgmtFtpSearch({
        index: "netflow",
        filter: { src: "198.51.100.30", device: "192.0.2.14" },
        maxRows: 256,
      }),
      buildMgmtNetflowSearch({
        index: "netflow",
        mgmtIps: ["192.0.2.11", "192.0.2.15"],
        flagHttpPort80: true,
        maxRows: 256,
      }),
      buildMgmtSyslogSearch({
        index: "cisco_dc",
        maxRows: 256,
      }),
    ];

    for (const spl of queries) {
      const headIdx = spl.indexOf("| head 257");
      const tableIdx = spl.indexOf("| table ");
      expect(headIdx).toBeGreaterThan(0);
      expect(tableIdx).toBeGreaterThan(headIdx);
      expect(() =>
        assertNoForbiddenFieldsInSpl("mgmt_plane", spl),
      ).not.toThrow();
      for (const bad of FORBIDDEN_SENSITIVE_FIELDS) {
        expect(spl.toLowerCase()).not.toMatch(new RegExp(`\\b${bad}\\b`));
      }
    }

    // NetFlow filters cleartext management ports (including 21 FTP) BEFORE | head
    const nfDefault = queries[2];
    const nfHeadIdx = nfDefault.indexOf("| head 257");
    expect(nfDefault.slice(0, nfHeadIdx)).toContain(
      "(dest_port=21 OR dest_port=23 OR dest_port=69 OR dest_port=161 OR dest_port=162 OR dest_port=80)",
    );
    expect(nfDefault.slice(0, nfHeadIdx)).toContain(
      'dest_ip IN ("192.0.2.11", "192.0.2.15")',
    );

    const nfNoHttp = buildMgmtNetflowSearch({
      index: "netflow",
      flagHttpPort80: false,
      maxRows: 256,
    });
    expect(nfNoHttp).not.toContain("dest_port=80");
    expect(nfNoHttp).toContain("dest_port=21");

    // FTP strips command/method arguments and redacts USER/PASS/ACCT inside SPL BEFORE | table
    const ftpSpl = queries[1];
    const ftpEvalIdx = ftpSpl.indexOf(
      '| eval command=upper(mvindex(split(trim(coalesce(command, method)), " "), 0))',
    );
    const ftpRedactIdx = ftpSpl.indexOf(
      '| eval command=if(in(command, "USER", "PASS", "ACCT"), "AUTH_CMD", command)',
    );
    const ftpTableIdx = ftpSpl.indexOf("| table ");
    expect(ftpEvalIdx).toBeGreaterThan(ftpSpl.indexOf("| head 257"));
    expect(ftpRedactIdx).toBeGreaterThan(ftpEvalIdx);
    expect(ftpTableIdx).toBeGreaterThan(ftpRedactIdx);

    // Syslog excludes auth categories and aggregates max(_time) AS last_seen count BY host sourcetype BEFORE | head
    const syslogSpl = queries[3];
    const syslogStatsIdx = syslogSpl.indexOf(
      "| stats max(_time) AS last_seen count BY host sourcetype",
    );
    const syslogHeadIdx = syslogSpl.indexOf("| head 257");
    const syslogTableIdx = syslogSpl.indexOf(
      "| table host sourcetype last_seen count",
    );
    expect(syslogStatsIdx).toBeGreaterThan(0);
    expect(syslogHeadIdx).toBeGreaterThan(syslogStatsIdx);
    expect(syslogTableIdx).toBeGreaterThan(syslogHeadIdx);
    expect(syslogSpl).toContain('sourcetype="cisco:ios"');
    expect(syslogSpl).toContain('sourcetype="cisco:dc:nexus9k:syslog"');
    expect(syslogSpl).toContain('sourcetype="cisco:aci"');
    expect(syslogSpl).toContain('sourcetype="cisco:dc:aci:syslog"');
    expect(syslogSpl).toContain('"AUTH"');
    expect(syslogSpl).toContain('"SSH"');
  });

  it("builds literal()-quoted raw events URLs, safe row IDs, and IP-preserving short labels", () => {
    const url = buildMgmtPlaneRawEventsUrl({
      index: "netflow",
      sourcetypes: ["stream:snmp"],
      sourceManager: "198.51.100.20",
      targetDevice: "192.0.2.12",
      destPort: 161,
      earliest: EARLIEST,
      latest: NOW,
    });
    expect(url).toContain("/app/splunk_adm/search?");
    const decoded = decodeURIComponent(url);
    expect(decoded).toContain("index=netflow");
    expect(decoded).toContain('src_ip="198.51.100.20"');
    expect(decoded).toContain('dest_ip="192.0.2.12"');
    expect(decoded).toContain("dest_port=161");

    const v6Id = makeMgmtPlaneRowId(
      "snmp",
      "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
      "2001:0db8:85a3:0000:0000:8a2e:0370:9999",
    );
    expect(v6Id).toMatch(/^[A-Za-z0-9._:/-]{1,128}$/);
    expect(v6Id).not.toContain("->");

    expect(shortenDeviceLabel("192.0.2.11")).toBe("192.0.2.11");
    expect(shortenDeviceLabel("2001:db8::1")).toBe("2001:db8::1");
    expect(shortenDeviceLabel("leaf-01.dc1.example")).toBe("leaf-01");
  });
});

describe("Classification, syslog receipt-gap rules, and fixture correlation", () => {
  it("classifies SNMP versions and SET operations accurately", () => {
    expect(classifySnmpVersion("1")).toBe("v1");
    expect(classifySnmpVersion("2c")).toBe("v2c");
    expect(classifySnmpVersion("SNMPv3")).toBe("v3");
    expect(classifySnmpVersion("")).toBe("unknown");
    expect(isSnmpSetOperation("SetRequest")).toBe(true);
    expect(isSnmpSetOperation("set-request")).toBe(true);
    expect(isSnmpSetOperation("set")).toBe(true);
    expect(isSnmpSetOperation("GetBulkRequest")).toBe(false);
  });

  it("normalizes aggregated syslog last_seen/count and redacts FTP auth verbs client-side", () => {
    const aggSyslog = normalizeMgmtPlaneRow(
      {
        host: "leaf-02",
        sourcetype: "cisco:ios",
        last_seen: EARLIEST + 120,
        count: 42,
      },
      "cisco:ios",
    );
    expect(aggSyslog).toEqual({
      sourceType: "cisco:ios",
      timestamp: EARLIEST + 120,
      count: 42,
      rawHost: "leaf-02",
      device: "leaf-02",
      category: "SYSLOG",
    });

    const peerSyslog = normalizeMgmtPlaneRow(
      {
        host: "spine-01",
        sourcetype: "cisco:ios",
        last_seen: EARLIEST + 2300,
        count: 180,
      },
      "cisco:ios",
    )!;
    const gapAnalysis = buildMgmtPlaneAnalysis({
      events: [
        { event: aggSyslog!, indexName: "cisco_dc" },
        { event: peerSyslog, indexName: "cisco_dc" },
      ],
      thresholds: resolveMgmtPlaneThresholds(),
      earliest: EARLIEST,
      latest: NOW,
      outcomes: [{ source: "protocol_mgmt_plane", state: "complete" }],
      capped: false,
      syslogConfigured: true,
    });
    const gapRow = gapAnalysis.rows.find((r) => r.targetDevice === "leaf-02")!;
    expect(gapRow.findingLabel).toBe("Receipt gap");
    expect(gapRow.eventCount).toBe(42);
    expect(gapRow.gapMinutes).toBe(36);

    const ftpPass = normalizeMgmtPlaneRow(
      {
        _time: EARLIEST + 50,
        sourcetype: "stream:ftp",
        src_ip: "198.51.100.30",
        dest_ip: "192.0.2.14",
        command: "PASS supersecret",
      },
      "stream:ftp",
    )!;
    expect(ftpPass.sourceType === "stream:ftp" && ftpPass.command).toBe(
      "AUTH_CMD",
    );
  });

  it("never false-positives on <2 syslog devices and strips auth syslog rows", () => {
    const singleDevice = normalizeMgmtPlaneRow(
      {
        _time: EARLIEST + 100,
        host: "leaf-02",
        sourcetype: "cisco:ios",
        category: "ETHPORT",
        facility: "ETHPORT",
      },
      "cisco:ios",
    )!;
    const authRow = normalizeMgmtPlaneRow(
      {
        _time: EARLIEST + 200,
        host: "leaf-01",
        sourcetype: "cisco:ios",
        category: "AAA",
        facility: "AUTH",
      },
      "cisco:ios",
    );
    expect(authRow).toBeUndefined();

    const analysis = buildMgmtPlaneAnalysis({
      events: [{ event: singleDevice, indexName: "cisco_dc" }],
      thresholds: resolveMgmtPlaneThresholds(),
      earliest: EARLIEST,
      latest: NOW,
      outcomes: [{ source: "protocol_mgmt_plane", state: "complete" }],
      capped: false,
      syslogConfigured: true,
    });

    expect(analysis.hasSyslogBaseline).toBe(false);
    expect(analysis.rows).toHaveLength(1);
    expect(analysis.rows[0].attention).toBe(false);
    expect(analysis.rows[0].status).toBe("not_covered");
    expect(analysis.verdictStatus).toBe("not_covered");
    expect(analysis.kpis.find((k) => k.id === "receipt-gaps")?.value).toBe(
      "Not covered",
    );
  });

  it("correlates grounded fixtures for SNMPv1/v2c, SNMP SET, cleartext FTP/Telnet/TFTP/HTTP, and syslog receipt gaps", () => {
    const snmpFtpLines = readFileSync(
      "fixtures/protocols/mgmt_plane/stream_snmp_ftp.ndjson",
      "utf8",
    )
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l) as Record<string, unknown>);
    const netflowLines = readFileSync(
      "fixtures/protocols/mgmt_plane/netflow_cleartext_mgmt.ndjson",
      "utf8",
    )
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l) as Record<string, unknown>);
    const syslogLines = readFileSync(
      "fixtures/protocols/mgmt_plane/syslog_receipt_gap.ndjson",
      "utf8",
    )
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l) as Record<string, unknown>);

    const events = [
      ...snmpFtpLines.map((r) => ({
        event: normalizeMgmtPlaneRow(r, "stream:snmp")!,
        indexName: "netflow",
      })),
      ...netflowLines.map((r) => ({
        event: normalizeMgmtPlaneRow(r, "stream:netflow")!,
        indexName: "netflow",
      })),
      ...syslogLines.map((r) => ({
        event: normalizeMgmtPlaneRow(r, "cisco:ios")!,
        indexName: "cisco_dc",
      })),
    ];

    const result = buildMgmtPlaneAnalysis({
      events,
      thresholds: resolveMgmtPlaneThresholds(),
      earliest: EARLIEST,
      latest: NOW,
      outcomes: [
        {
          source: "protocol_mgmt_plane",
          profile: "mgmt-dc1",
          state: "complete",
        },
      ],
      capped: false,
      snmpConfigured: true,
      ftpConfigured: true,
      netflowConfigured: true,
      syslogConfigured: true,
    });

    expect(result.verdictStatus).toBe("attention");
    expect(result.hasSyslogBaseline).toBe(true);
    expect(result.kpis).toHaveLength(4);
    expect(result.kpis.map((k) => k.id)).toEqual([
      "findings",
      "snmp-legacy",
      "cleartext",
      "receipt-gaps",
    ]);

    expect(result.kpis.find((k) => k.id === "cleartext")?.unit).toBe(
      "sessions",
    );

    for (const row of result.rows) {
      expect(row.id).toMatch(/^[A-Za-z0-9._:/-]{1,128}$/);
      expect(row.id).not.toContain("->");
    }

    // SNMPv2c SetRequest on 192.0.2.12
    const snmpSetRow = result.rows.find(
      (r) =>
        r.targetDevice === "192.0.2.12" &&
        r.sourcetypes.includes("stream:snmp"),
    )!;
    expect(snmpSetRow.attention).toBe(true);
    expect(snmpSetRow.findingLabel).toBe("SNMPv2c · SET");

    // SNMPv3 read-only on 192.0.2.10 is healthy OK
    const snmpV3Row = result.rows.find((r) => r.targetDevice === "192.0.2.10")!;
    expect(snmpV3Row.attention).toBe(false);
    expect(snmpV3Row.status).toBe("ok");

    // Cleartext FTP, Telnet, TFTP, HTTP
    expect(
      result.rows.some(
        (r) =>
          r.findingLabel === "Cleartext FTP" && r.targetDevice === "192.0.2.14",
      ),
    ).toBe(true);
    expect(
      result.rows.some(
        (r) =>
          r.findingLabel === "Cleartext Telnet" &&
          r.targetDevice === "192.0.2.15",
      ),
    ).toBe(true);
    expect(
      result.rows.some(
        (r) =>
          r.findingLabel === "Cleartext TFTP" &&
          r.targetDevice === "192.0.2.12",
      ),
    ).toBe(true);
    expect(
      result.rows.some(
        (r) =>
          r.findingLabel === "Cleartext HTTP" &&
          r.targetDevice === "192.0.2.16",
      ),
    ).toBe(true);

    // NetFlow port 161 for 198.51.100.20 -> 192.0.2.11 correlates into stream:snmp row
    expect(
      result.rows.filter(
        (r) =>
          r.sourceManager === "198.51.100.20" &&
          r.targetDevice === "192.0.2.11" &&
          r.destPort === 161,
      ),
    ).toHaveLength(1);

    // Receipt gap on leaf-02 (35m before spine-01), NEVER labeled "device down"
    const gapRow = result.rows.find((r) => r.targetDevice === "leaf-02")!;
    expect(gapRow.attention).toBe(true);
    expect(gapRow.findingLabel).toBe("Receipt gap");
    expect(gapRow.gapMinutes).toBe(35);
    expect(gapRow.reasons[0]).toContain("does not prove device down");
    expect(result.verdict.toLowerCase()).not.toContain("device down");
    expect(gapRow.findingLabel.toLowerCase()).not.toContain("device down");

    // DistributionBar covers all 4 categories
    expect(result.distribution.map((d) => d.id)).toEqual([
      "snmp_v1_v2c",
      "snmp_set",
      "cleartext",
      "receipt_gap",
    ]);
  });

  it("treats uncorrelated NetFlow port 161 as not_covered for SNMP version", () => {
    const nf161 = normalizeMgmtPlaneRow(
      {
        _time: EARLIEST + 60,
        host: "stream-fwd-01",
        sourcetype: "stream:netflow",
        exporter_ip: "192.0.2.1",
        src_ip: "198.51.100.20",
        dest_ip: "192.0.2.11",
        src_port: 51200,
        dest_port: 161,
        transport: "udp",
        bytes: 1514,
        packets: 2,
      },
      "stream:netflow",
    )!;
    const analysis = buildMgmtPlaneAnalysis({
      events: [{ event: nf161, indexName: "netflow" }],
      thresholds: resolveMgmtPlaneThresholds(),
      earliest: EARLIEST,
      latest: NOW,
      outcomes: [{ source: "protocol_mgmt_plane", state: "complete" }],
      capped: false,
      netflowConfigured: true,
    });
    expect(analysis.rows[0].status).toBe("not_covered");
    expect(analysis.rows[0].attention).toBe(false);
    expect(analysis.verdictStatus).toBe("not_covered");
  });
});

describe("investigateMgmtPlane & summarizeMgmtPlane", () => {
  it("runs Stream Estimate check ONLY when stream:snmp or stream:ftp returns 0 rows", async () => {
    const search = vi
      .fn()
      // stream:snmp (0 rows)
      .mockResolvedValueOnce({ rows: [], warnings: [], errors: [] })
      // stream:ftp (0 rows)
      .mockResolvedValueOnce({ rows: [], warnings: [], errors: [] })
      // stream:netflow (1 row)
      .mockResolvedValueOnce({
        rows: [
          {
            _time: EARLIEST + 60,
            sourcetype: "stream:netflow",
            exporter_ip: "192.0.2.1",
            src_ip: "198.51.100.40",
            dest_ip: "192.0.2.15",
            dest_port: 23,
            transport: "tcp",
            bytes: 1024,
            packets: 8,
          },
        ],
        warnings: [],
        errors: [],
      })
      // syslog (0 rows)
      .mockResolvedValueOnce({ rows: [], warnings: [], errors: [] })
      // checkStreamEstimateMode(["snmp", "ftp"])
      .mockResolvedValueOnce({
        rows: [
          { host: "stream-fwd-01", stream_id: "snmp", stats_only: "true" },
          { host: "stream-fwd-01", stream_id: "ftp", stats_only: "false" },
        ],
        warnings: [],
        errors: [],
      });

    const result = await investigateMgmtPlane(
      { search },
      makeRequest(),
      makeConfig([makeProfile()]),
      new AbortController().signal,
      { skipConfigRecheck: true },
    );

    expect(search).toHaveBeenCalledTimes(5);
    expect(search.mock.calls[4][0].search).toContain(
      'sourcetype="stream:stats"',
    );
    expect(search.mock.calls[4][0].search).toContain('"snmp"');
    expect(search.mock.calls[4][0].search).toContain('"ftp"');
    expect(result.hasActiveSnmp).toBe(false);
    expect(result.hasActiveFtp).toBe(true);
    expect(result.bannerState).toBe("estimate_only");
  });

  it("downgrades capped-empty to unknown (never none_observed) and degraded ok summaries to attention", async () => {
    const cappedEmpty = await summarizeMgmtPlane(
      {
        search: vi.fn().mockResolvedValue({
          rows: [],
          truncated: true,
          warnings: [],
          errors: [],
        }),
      },
      makeRequest(),
      makeConfig([makeProfile({ extra: { sourceKind: "netflow" } })]),
      new AbortController().signal,
      { skipConfigRecheck: true },
    );
    expect(cappedEmpty.status).toBe("unknown");
    expect(cappedEmpty.capped).toBe(true);

    // Healthy SNMPv3 + blocked syslog -> never "ok" (returns "unknown" because syslog is degraded)
    const searchBlocked = vi
      .fn()
      .mockResolvedValueOnce({
        rows: [
          {
            _time: EARLIEST + 20,
            sourcetype: "stream:snmp",
            src_ip: "198.51.100.20",
            dest_ip: "192.0.2.10",
            snmp_version: "3",
            pdu_type: "GetRequest",
            bytes_in: 120,
            bytes_out: 240,
          },
        ],
        warnings: [],
        errors: [],
      })
      .mockRejectedValueOnce(new SearchAccessDeniedError());

    const degradedOk = await summarizeMgmtPlane(
      { search: searchBlocked },
      makeRequest(),
      makeConfig([
        makeProfile({ id: "snmp", extra: { sourceKind: "stream_snmp" } }),
        makeProfile({
          id: "sys",
          index: "cisco_dc",
          extra: { sourceKind: "syslog" },
        }),
      ]),
      new AbortController().signal,
      { skipConfigRecheck: true },
    );
    expect(degradedOk.status).toBe("unknown");
    expect(degradedOk.status).not.toBe("ok");
  });

  it("never returns none_observed when rows failed normalization (unparsedRowCount > 0)", async () => {
    const result = await investigateMgmtPlane(
      {
        search: vi.fn().mockResolvedValue({
          rows: [{ host: "bad-host", sourcetype: "stream:snmp" }],
          warnings: [],
          errors: [],
        }),
      },
      makeRequest(),
      makeConfig([makeProfile({ extra: { sourceKind: "stream_snmp" } })]),
      new AbortController().signal,
      { skipConfigRecheck: true },
    );
    expect(result.verdictStatus).toBe("unknown");
    expect(result.coverageStatus).toBe("unknown");
    expect(result.bannerState).toBe("unavailable");
    expect(result.bannerReason).toContain("could not be normalized");
  });

  it("marks KPIs unknown (never ok) when contributing sources are capped or degraded, and scopes healthy verdicts to covered sources", () => {
    const snmpV3 = normalizeMgmtPlaneRow(
      {
        _time: EARLIEST + 20,
        sourcetype: "stream:snmp",
        src_ip: "198.51.100.20",
        dest_ip: "192.0.2.10",
        snmp_version: "3",
        pdu_type: "GetRequest",
        bytes_in: 120,
        bytes_out: 240,
      },
      "stream:snmp",
    )!;
    const peerA = normalizeMgmtPlaneRow(
      {
        host: "spine-01",
        sourcetype: "cisco:ios",
        last_seen: EARLIEST + 2300,
        count: 10,
      },
      "cisco:ios",
    )!;
    const peerB = normalizeMgmtPlaneRow(
      {
        host: "leaf-01",
        sourcetype: "cisco:ios",
        last_seen: EARLIEST + 2200,
        count: 12,
      },
      "cisco:ios",
    )!;

    // Degraded SNMP, NetFlow, and Syslog with 0 attention findings -> every KPI must be unknown, NEVER ok
    const degradedAnalysis = buildMgmtPlaneAnalysis({
      events: [
        { event: snmpV3, indexName: "netflow" },
        { event: peerA, indexName: "cisco_dc" },
        { event: peerB, indexName: "cisco_dc" },
      ],
      thresholds: resolveMgmtPlaneThresholds(),
      earliest: EARLIEST,
      latest: NOW,
      outcomes: [
        {
          source: "protocol_mgmt_plane",
          profile: "snmp",
          state: "partial",
          capped: true,
        },
        { source: "protocol_mgmt_plane", profile: "nf", state: "blocked" },
        {
          source: "protocol_mgmt_plane",
          profile: "sys",
          state: "partial",
          capped: true,
        },
      ],
      capped: true,
      snmpConfigured: true,
      ftpConfigured: false,
      netflowConfigured: true,
      syslogConfigured: true,
      snmpOutcomes: [
        {
          source: "protocol_mgmt_plane",
          profile: "snmp",
          state: "partial",
          capped: true,
        },
      ],
      netflowOutcomes: [
        { source: "protocol_mgmt_plane", profile: "nf", state: "blocked" },
      ],
      syslogOutcomes: [
        {
          source: "protocol_mgmt_plane",
          profile: "sys",
          state: "partial",
          capped: true,
        },
      ],
    });

    for (const kpi of degradedAnalysis.kpis) {
      expect(kpi.status).toBe("unknown");
      expect(kpi.status).not.toBe("ok");
    }
    expect(
      degradedAnalysis.kpis.find((k) => k.id === "receipt-gaps")?.value,
    ).toBe("Unknown");

    // SNMPv3-only healthy scope must NOT claim "no cleartext sessions" or "continuous syslog receipt"
    const snmpOnlyHealthy = buildMgmtPlaneAnalysis({
      events: [{ event: snmpV3, indexName: "netflow" }],
      thresholds: resolveMgmtPlaneThresholds(),
      earliest: EARLIEST,
      latest: NOW,
      outcomes: [{ source: "protocol_mgmt_plane", state: "complete" }],
      capped: false,
      snmpConfigured: true,
    });
    expect(snmpOnlyHealthy.verdictStatus).toBe("ok");
    expect(snmpOnlyHealthy.verdict).toContain("SNMPv3 only");
    expect(snmpOnlyHealthy.verdict).not.toContain("cleartext");
    expect(snmpOnlyHealthy.verdict).not.toContain("receipt gap");
  });

  it("strips forbidden sensitive fields and enforces stale-config recheck with profileValidators", async () => {
    const search = vi.fn().mockResolvedValue({
      rows: [
        {
          _time: EARLIEST + 20,
          sourcetype: "stream:snmp",
          src_ip: "198.51.100.20",
          dest_ip: "192.0.2.10",
          snmp_version: "3",
          pdu_type: "GetRequest",
          bytes_in: 120,
          bytes_out: 240,
          community: "public",
          value_raw: "secret",
          varbind_list: "1.3.6.1.2.1",
          login: "admin",
          password: "secret",
          _raw: "raw-secret",
        },
      ],
      warnings: [],
      errors: [],
    });
    const client: SearchClient = { search };
    const profile = makeProfile({ extra: { sourceKind: "stream_snmp" } });

    const spy = vi
      .spyOn(protocolConfigClient, "readProtocolProfileDocument")
      .mockResolvedValue({
        version: 1,
        profiles: [profile],
      });
    try {
      const config = await import("../../shared/runner").then((m) =>
        m.readProtocolConfiguration({ mgmt_plane: validateMgmtPlaneExtra }),
      );
      const summary = await summarizeMgmtPlane(
        client,
        makeRequest(),
        config,
        new AbortController().signal,
        { profileValidators: { mgmt_plane: validateMgmtPlaneExtra } },
      );
      expect(summary.status).toBe("ok");

      spy.mockResolvedValueOnce({
        version: 1,
        profiles: [
          makeProfile({
            index: "other_netflow",
            extra: { sourceKind: "stream_snmp" },
          }),
        ],
      });
      const stale = await investigateMgmtPlane(
        client,
        makeRequest(),
        config,
        new AbortController().signal,
        { profileValidators: { mgmt_plane: validateMgmtPlaneExtra } },
      );
      expect(stale.bannerState).toBe("stale_config");
      expect(stale.rows).toEqual([]);
    } finally {
      spy.mockRestore();
    }
  });

  it("aborts in-flight searches when AbortSignal fires", async () => {
    const controller = new AbortController();
    const search = vi.fn().mockImplementation(() => {
      controller.abort();
      return Promise.reject(new DOMException("Aborted", "AbortError"));
    });
    await expect(
      investigateMgmtPlane(
        { search },
        makeRequest(),
        makeConfig([makeProfile({ extra: { sourceKind: "netflow" } })]),
        controller.signal,
        { skipConfigRecheck: true },
      ),
    ).rejects.toThrow();
  });
});
