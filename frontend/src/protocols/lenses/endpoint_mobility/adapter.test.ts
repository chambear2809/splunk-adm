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
import { readProtocolConfiguration } from "../../shared/runner";
import {
  MOBILITY_SYSLOG_CATEGORIES,
  buildEndpointMobilityAnalysis,
  buildEndpointMobilityRawEventsUrl,
  buildMobilityAciSearch,
  buildMobilityDmeSearch,
  buildMobilityNdEndpointsSearch,
  buildMobilityStreamArpSearch,
  buildMobilitySyslogSearch,
  classifyMobilitySyslogEvent,
  investigateEndpointMobility,
  normalizeEndpointMobilityRow,
  resolveEndpointMobilityThresholds,
  shortenDeviceLabel,
  summarizeEndpointMobility,
  validateEndpointMobilityExtra,
} from "./adapter";

const NOW = 1800000500;
const EARLIEST = 1800000000;
const STRICT_ROW_ID_RE = /^[A-Za-z0-9._:/-]{1,128}$/;

function makeProfile(
  overrides: Partial<BaseProtocolProfile> = {},
): BaseProtocolProfile {
  return {
    id: "mobility-dc1",
    source: "protocol_endpoint_mobility",
    lens: "endpoint_mobility",
    scope: "prod:dc1",
    index: "cisco_dc",
    observer: "nd-01",
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
    lens: "endpoint_mobility",
    scope: "prod:dc1",
    earliest: EARLIEST,
    latest: NOW,
    ...overrides,
  };
}

describe("validateEndpointMobilityExtra (fail-closed profile validation)", () => {
  it("accepts valid extra thresholds and sourceKind and integrates with parseProtocolProfiles", () => {
    expect(validateEndpointMobilityExtra(undefined)).toBeUndefined();
    expect(
      validateEndpointMobilityExtra({
        sourceKind: "nd_endpoints",
        arpSpikeWarnCount: 30,
        macMoveWarnCount: 2,
        portFlapWarnCount: 3,
        anomalyScoreWarn: 65,
      }),
    ).toEqual({
      sourceKind: "nd_endpoints",
      arpSpikeWarnCount: 30,
      macMoveWarnCount: 2,
      portFlapWarnCount: 3,
      anomalyScoreWarn: 65,
    });

    const profiles = parseProtocolProfiles(
      {
        version: 1,
        profiles: [
          {
            id: "mobility-dc1",
            source: "protocol_endpoint_mobility",
            lens: "endpoint_mobility",
            scope: "prod:dc1",
            index: "cisco_dc",
            observer: "nd-01",
            validFrom: EARLIEST - 3600,
            validUntil: NOW + 3600,
            extra: { sourceKind: "stream_arp", arpSpikeWarnCount: 15 },
          },
        ],
      },
      { endpoint_mobility: validateEndpointMobilityExtra },
    );
    expect(resolveEndpointMobilityThresholds(profiles[0])).toEqual({
      sourceKind: "stream_arp",
      arpSpikeWarnCount: 15,
      macMoveWarnCount: 1,
      portFlapWarnCount: 2,
      anomalyScoreWarn: 50,
    });
  });

  it("rejects unknown keys and out-of-range values", () => {
    expect(() => validateEndpointMobilityExtra({ badKey: true })).toThrow(
      /Unsupported endpoint_mobility/,
    );
    expect(() =>
      validateEndpointMobilityExtra({ sourceKind: "netflow" as never }),
    ).toThrow(/sourceKind/);
    expect(() =>
      validateEndpointMobilityExtra({ arpSpikeWarnCount: 0 }),
    ).toThrow(/arpSpikeWarnCount/);
    expect(() =>
      validateEndpointMobilityExtra({ arpSpikeWarnCount: 100001 }),
    ).toThrow(/arpSpikeWarnCount/);
    expect(() =>
      validateEndpointMobilityExtra({ macMoveWarnCount: 1.5 }),
    ).toThrow(/macMoveWarnCount/);
    expect(() =>
      validateEndpointMobilityExtra({ portFlapWarnCount: 1001 }),
    ).toThrow(/portFlapWarnCount/);
    expect(() =>
      validateEndpointMobilityExtra({ anomalyScoreWarn: 0 }),
    ).toThrow(/anomalyScoreWarn/);
    expect(() =>
      validateEndpointMobilityExtra({ anomalyScoreWarn: 101 }),
    ).toThrow(/anomalyScoreWarn/);
  });
});

describe("SPL builders, DME predicates before | head, and sensitive-field guards", () => {
  it("emits bounded allowlisted SPL with class predicates and | head before | table", () => {
    const arpSpl = buildMobilityStreamArpSearch({
      index: "netflow",
      filter: { src: "10.10.20.42", device: "stream-fwd-01", vni: "10100" },
      maxRows: 256,
    });
    expect(arpSpl).toContain('sourcetype="stream:arp"');
    expect(arpSpl.indexOf("| head 257")).toBeLessThan(
      arpSpl.indexOf("| table "),
    );
    expect(() =>
      assertNoForbiddenFieldsInSpl("endpoint_mobility", arpSpl),
    ).not.toThrow();

    const ndSpl = buildMobilityNdEndpointsSearch({
      index: "cisco_dc",
      filter: { device: "leaf-201", vni: "10100" },
      maxRows: 128,
    });
    expect(ndSpl).toContain('sourcetype="cisco:dc:nd:endpoints"');
    expect(ndSpl.indexOf("| head 129")).toBeLessThan(ndSpl.indexOf("| table "));
    expect(() =>
      assertNoForbiddenFieldsInSpl("endpoint_mobility", ndSpl),
    ).not.toThrow();

    const aciSpl = buildMobilityAciSearch({
      index: "cisco_dc",
      filter: { device: "leaf-201" },
      maxRows: 256,
    });
    expect(aciSpl).toContain('component="fvCEp"');
    expect(aciSpl.indexOf('component="fvCEp"')).toBeLessThan(
      aciSpl.indexOf("| head 257"),
    );
    expect(aciSpl.indexOf("| head 257")).toBeLessThan(
      aciSpl.indexOf("| table "),
    );
    expect(() =>
      assertNoForbiddenFieldsInSpl("endpoint_mobility", aciSpl),
    ).not.toThrow();

    const dmeSpl = buildMobilityDmeSearch({
      index: "cisco_dc",
      filter: { device: "leaf-101" },
      maxRows: 200,
    });
    expect(dmeSpl).toContain('component="epmMacEp"');
    expect(dmeSpl).toContain('component="l2MacAddressEntry"');
    expect(dmeSpl).toContain('dn="sys/eps/*"');
    expect(dmeSpl).toContain('dn="sys/bd/*"');
    expect(dmeSpl.indexOf('component="epmMacEp"')).toBeLessThan(
      dmeSpl.indexOf("| head 201"),
    );
    expect(dmeSpl.indexOf("| head 201")).toBeLessThan(
      dmeSpl.indexOf("| table "),
    );
    expect(() =>
      assertNoForbiddenFieldsInSpl("endpoint_mobility", dmeSpl),
    ).not.toThrow();

    const syslogSpl = buildMobilitySyslogSearch({
      index: "cisco_dc",
      maxRows: 256,
    });
    expect(() =>
      assertNoForbiddenFieldsInSpl("endpoint_mobility", syslogSpl),
    ).not.toThrow();

    for (const spl of [arpSpl, ndSpl, aciSpl, dmeSpl, syslogSpl]) {
      for (const forbidden of FORBIDDEN_SENSITIVE_FIELDS) {
        expect(spl.toLowerCase()).not.toMatch(new RegExp(`\\b${forbidden}\\b`));
      }
    }
  });

  it("rejects SPL injection in filters and raw-events URL builder", () => {
    expect(() =>
      buildMobilityStreamArpSearch({
        index: "netflow",
        filter: { src: '10.0.0.1" OR "1"="1' },
        maxRows: 256,
      }),
    ).toThrow(/Invalid literal/);

    const safeUrl = buildEndpointMobilityRawEventsUrl({
      index: "cisco_dc",
      sourcetypes: ["stream:arp", "cisco:dc:nd:endpoints"],
      macs: ["00:50:56:aa:10:40"],
      ips: ["10.20.30.40"],
      switches: ["leaf-201"],
      earliest: EARLIEST,
      latest: NOW,
    });
    expect(safeUrl).toMatch(/^\/app\/splunk_adm\/search\?/);
    expect(safeUrl).toContain("sourcetype%3D%22stream%3Aarp%22");

    expect(() =>
      buildEndpointMobilityRawEventsUrl({
        index: "cisco_dc",
        sourcetypes: ["stream:arp"],
        macs: ["bad mac!"],
        ips: [],
        switches: [],
        earliest: EARLIEST,
        latest: NOW,
      }),
    ).toThrow(/Invalid literal/);
  });
});

describe("normalizeEndpointMobilityRow & buildEndpointMobilityAnalysis", () => {
  it("detects duplicate IP (2 MACs for 1 IP), MAC move across 2 ports/switches, ARP rate spike, and port flap correlation", () => {
    const arpLines = readFileSync(
      "fixtures/protocols/endpoint_mobility/stream_arp.ndjson",
      "utf8",
    )
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as Record<string, unknown>);
    const ndLines = readFileSync(
      "fixtures/protocols/endpoint_mobility/nd_endpoints_mobility.ndjson",
      "utf8",
    )
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as Record<string, unknown>);
    const aciNxosLines = readFileSync(
      "fixtures/protocols/endpoint_mobility/aci_nxos_mobility.ndjson",
      "utf8",
    )
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as Record<string, unknown>);

    const events = [
      ...arpLines.map((r, i) => ({
        event: normalizeEndpointMobilityRow(r, i)!,
        indexName: "netflow",
      })),
      ...ndLines.map((r, i) => ({
        event: normalizeEndpointMobilityRow(r, 100 + i)!,
        indexName: "cisco_dc",
      })),
      ...aciNxosLines.map((r, i) => ({
        event: normalizeEndpointMobilityRow(r, 200 + i)!,
        indexName: "cisco_dc",
      })),
    ];
    expect(events.every((e) => Boolean(e.event))).toBe(true);

    const analysis = buildEndpointMobilityAnalysis({
      events,
      thresholds: {
        ...resolveEndpointMobilityThresholds(),
        arpSpikeWarnCount: 5,
      },
      earliest: EARLIEST,
      latest: NOW,
      outcomes: [{ source: "protocol_endpoint_mobility", state: "complete" }],
      capped: false,
      activeSourceKinds: ["auto"],
    });

    expect(analysis.kpis).toHaveLength(4);
    expect(analysis.kpis.find((k) => k.id === "duplicate-ips")?.value).toBe(
      "2",
    );
    expect(
      Number(analysis.kpis.find((k) => k.id === "mac-moves")?.value),
    ).toBeGreaterThanOrEqual(2);
    expect(analysis.kpis.find((k) => k.id === "arp-spikes")?.value).toBe("1");
    expect(analysis.kpis.find((k) => k.id === "port-flaps")?.value).toBe("2");

    // Duplicate IP 10.10.20.42 across 2 MACs (never claims spoofing)
    const dupRow = analysis.rows.find((r) => r.ips.includes("10.10.20.42"))!;
    expect(dupRow).toBeDefined();
    expect(dupRow.attention).toBe(true);
    expect(dupRow.macs).toContain("00:50:56:aa:00:01");
    expect(dupRow.macs).toContain("00:50:56:aa:00:02");
    expect(dupRow.reasons.join(" ")).toMatch(/Duplicate IP 10\.10\.20\.42/);
    expect(dupRow.reasons.join(" ").toLowerCase()).not.toContain("spoof");

    // ND replacement duplicate IP 10.10.20.13
    const ndDupRow = analysis.rows.find((r) => r.ips.includes("10.10.20.13"))!;
    expect(ndDupRow).toBeDefined();
    expect(ndDupRow.attention).toBe(true);
    expect(ndDupRow.macs).toHaveLength(2);

    // MAC move across leaf-201 eth1/5 -> leaf-202 eth1/8 with port flap correlation on leaf-202 Ethernet1/8
    const moveRow = analysis.rows.find(
      (r) => r.primaryMac === "00:50:56:aa:10:40",
    )!;
    expect(moveRow).toBeDefined();
    expect(moveRow.attention).toBe(true);
    expect(moveRow.moveCount).toBeGreaterThanOrEqual(1);
    expect(moveRow.portFlapCount).toBe(2);
    expect(moveRow.reasons.some((r) => r.includes("MAC moved"))).toBe(true);
    expect(
      moveRow.reasons.some((r) => r.includes("Port flap correlation")),
    ).toBe(true);

    // ARP spike on 00:50:56:aa:00:55 (6 packets >= 5)
    const spikeRow = analysis.rows.find(
      (r) => r.primaryMac === "00:50:56:aa:00:55",
    )!;
    expect(spikeRow).toBeDefined();
    expect(spikeRow.attention).toBe(true);
    expect(spikeRow.arpCount).toBe(6);
    expect(spikeRow.reasons.some((r) => r.includes("ARP rate spike"))).toBe(
      true,
    );

    // Healthy endpoint 02:00:0a:0a:14:0b (10.10.20.11) sorts after flagged rows
    const okRow = analysis.rows.find(
      (r) => r.primaryMac === "02:00:0a:0a:14:0b",
    )!;
    expect(okRow).toBeDefined();
    expect(okRow.attention).toBe(false);
    expect(okRow.status).toBe("ok");

    // Every row ID must match ^[A-Za-z0-9._:/-]{1,128}$ (using __, never ->)
    for (const row of analysis.rows) {
      expect(row.id).toMatch(STRICT_ROW_ID_RE);
      expect(row.id).not.toContain("->");
      const parsed = parseProtocolLink(
        new URLSearchParams({ p_lens: "endpoint_mobility", p_item: row.id }),
      );
      expect(parsed.item).toBe(row.id);
    }

    // Matrix has flagged switches first
    expect(analysis.matrixRows.length).toBeGreaterThan(0);
    expect(analysis.matrixCols.length).toBeGreaterThan(0);
    expect(analysis.timeline.length).toBeGreaterThan(0);
  });

  it("marks uncollected capabilities as not_covered in stream_arp-only mode", () => {
    const arpEvent = normalizeEndpointMobilityRow(
      {
        _time: EARLIEST + 10,
        host: "stream-fwd-01",
        sourcetype: "stream:arp",
        sender_ip: "10.10.20.99",
        sender_mac: "00:50:56:aa:99:01",
        arp_opcode: 1,
        vlan_id: 20,
      },
      0,
    )!;
    const analysis = buildEndpointMobilityAnalysis({
      events: [{ event: arpEvent, indexName: "netflow" }],
      thresholds: resolveEndpointMobilityThresholds(),
      earliest: EARLIEST,
      latest: NOW,
      outcomes: [{ source: "protocol_endpoint_mobility", state: "complete" }],
      capped: false,
      activeSourceKinds: ["stream_arp"],
    });
    expect(analysis.kpis.find((k) => k.id === "mac-moves")?.status).toBe(
      "not_covered",
    );
    expect(analysis.kpis.find((k) => k.id === "port-flaps")?.status).toBe(
      "not_covered",
    );
    expect(analysis.rows[0].hasAttachmentCoverage).toBe(false);
    expect(analysis.rows[0].hasMoveCoverage).toBe(false);
    expect(analysis.rows[0].hasFlapCoverage).toBe(false);
    expect(analysis.rows[0].hasArpCoverage).toBe(true);
  });

  it("preserves distinct IPv4 and IPv6 addresses in timeline lane labels without truncation", () => {
    expect(shortenDeviceLabel("10.10.20.42")).toBe("10.10.20.42");
    expect(shortenDeviceLabel("2001:db8:1::10")).toBe("2001:db8:1::10");
    expect(shortenDeviceLabel("leaf1.dc1.example")).toBe("leaf1");

    const rows = [
      {
        _time: EARLIEST + 10,
        host: "stream-fwd-01",
        sourcetype: "stream:arp",
        sender_ip: "10.10.20.42",
        sender_mac: "00:50:56:aa:00:01",
        arp_opcode: 1,
      },
      {
        _time: EARLIEST + 20,
        host: "stream-fwd-01",
        sourcetype: "stream:arp",
        sender_ip: "10.10.20.42",
        sender_mac: "00:50:56:aa:00:02",
        arp_opcode: 2,
      },
      {
        _time: EARLIEST + 30,
        host: "stream-fwd-01",
        sourcetype: "stream:arp",
        sender_ip: "10.10.20.43",
        sender_mac: "00:50:56:aa:00:03",
        arp_opcode: 1,
      },
      {
        _time: EARLIEST + 40,
        host: "stream-fwd-01",
        sourcetype: "stream:arp",
        sender_ip: "10.10.20.43",
        sender_mac: "00:50:56:aa:00:04",
        arp_opcode: 2,
      },
      {
        _time: EARLIEST + 50,
        host: "stream-fwd-01",
        sourcetype: "stream:arp",
        sender_ip: "2001:db8:1::10",
        sender_mac: "00:50:56:aa:00:05",
        arp_opcode: 1,
      },
      {
        _time: EARLIEST + 60,
        host: "stream-fwd-01",
        sourcetype: "stream:arp",
        sender_ip: "2001:db8:1::10",
        sender_mac: "00:50:56:aa:00:06",
        arp_opcode: 2,
      },
      {
        _time: EARLIEST + 70,
        host: "stream-fwd-01",
        sourcetype: "stream:arp",
        sender_ip: "2001:db8:1::20",
        sender_mac: "00:50:56:aa:00:07",
        arp_opcode: 1,
      },
      {
        _time: EARLIEST + 80,
        host: "stream-fwd-01",
        sourcetype: "stream:arp",
        sender_ip: "2001:db8:1::20",
        sender_mac: "00:50:56:aa:00:08",
        arp_opcode: 2,
      },
    ];
    const events = rows.map((r, i) => ({
      event: normalizeEndpointMobilityRow(r, i)!,
      indexName: "netflow",
    }));
    const analysis = buildEndpointMobilityAnalysis({
      events,
      thresholds: resolveEndpointMobilityThresholds(),
      earliest: EARLIEST,
      latest: NOW,
      outcomes: [{ source: "protocol_endpoint_mobility", state: "complete" }],
      capped: false,
      activeSourceKinds: ["stream_arp"],
    });
    const lanes = new Set(analysis.timeline.map((t) => t.lane));
    expect(lanes).toContain("10.10.20.42");
    expect(lanes).toContain("10.10.20.43");
    expect(lanes).toContain("2001:db8:1::10");
    expect(lanes).toContain("2001:db8:1::20");
    expect(lanes).not.toContain("10");
  });

  it("keeps MOBILITY_SYSLOG_CATEGORIES aligned between SPL filter and classifier and strips auth/config syslog", async () => {
    const search = vi
      .fn()
      .mockResolvedValue({ rows: [], warnings: [], errors: [] });
    await investigateEndpointMobility(
      { search },
      makeRequest(),
      makeConfig([makeProfile({ extra: { sourceKind: "syslog" } })]),
      new AbortController().signal,
      { skipConfigRecheck: true },
    );
    const spl = String(search.mock.calls[0][0].search);
    for (const cat of MOBILITY_SYSLOG_CATEGORIES) {
      expect(spl).toContain(`"${cat}"`);
      expect(
        classifyMobilitySyslogEvent(cat, "TEST_MNEM", "test", 4),
      ).toBeDefined();
    }
    expect(
      classifyMobilitySyslogEvent("BGP", "ADJCHANGE", "bgp peer", 5),
    ).toBeUndefined();
    expect(spl).not.toContain('"BGP"');

    // Auth & config-change syslog events must be filtered out
    expect(
      normalizeEndpointMobilityRow(
        {
          _time: EARLIEST + 10,
          host: "leaf1.dc1.example",
          sourcetype: "cisco:ios",
          syslog_msg: "%AUTHPRIV-6-LOGIN_SUCCESS: user admin logged in",
        },
        0,
      ),
    ).toBeUndefined();
    expect(
      normalizeEndpointMobilityRow(
        {
          _time: EARLIEST + 20,
          host: "leaf1.dc1.example",
          sourcetype: "cisco:dc:nexus9k:syslog",
          category: "VSHD",
          severity_id: "5",
          mnemonics: "VSHD_SYSLOG_CONFIG_I",
          syslog_msg: "Configured from vty",
        },
        1,
      ),
    ).toBeUndefined();
  });
});

describe("investigateEndpointMobility & summarizeEndpointMobility (Estimate mode, degraded/capped, config recheck)", () => {
  it("checks Stream Estimate mode for arp when stream:arp returns 0 rows", async () => {
    const search = vi
      .fn()
      .mockResolvedValueOnce({ rows: [], warnings: [], errors: [] })
      .mockResolvedValueOnce({
        rows: [{ host: "stream-fwd-01", stream_id: "arp", stats_only: "true" }],
        warnings: [],
        errors: [],
      });
    const result = await investigateEndpointMobility(
      { search },
      makeRequest(),
      makeConfig([
        makeProfile({
          id: "mob-arp",
          index: "netflow",
          extra: { sourceKind: "stream_arp" },
        }),
      ]),
      new AbortController().signal,
      { skipConfigRecheck: true },
    );
    expect(search).toHaveBeenCalledTimes(2);
    expect(search.mock.calls[1][0].search).toContain(
      'sourcetype="stream:stats"',
    );
    expect(search.mock.calls[1][0].search).toContain('"arp"');
    expect(result.bannerState).toBe("estimate_only");
    expect(result.verdictStatus).toBe("unknown");
  });

  it("downgrades degraded and capped results truthfully instead of none_observed or ok", async () => {
    const twoProfiles = makeConfig([
      makeProfile({
        id: "mob-arp",
        index: "netflow",
        extra: { sourceKind: "stream_arp" },
      }),
      makeProfile({
        id: "mob-nd",
        index: "cisco_dc",
        extra: { sourceKind: "nd_endpoints" },
      }),
    ]);

    // 1. Blocked + empty -> blocked / unknown
    const blockedEmpty = await investigateEndpointMobility(
      {
        search: vi
          .fn()
          .mockRejectedValueOnce(new SearchAccessDeniedError())
          .mockResolvedValueOnce({ rows: [], warnings: [], errors: [] }),
      },
      makeRequest(),
      twoProfiles,
      new AbortController().signal,
      { skipConfigRecheck: true, skipEstimateCheck: true },
    );
    expect(blockedEmpty.bannerState).toBe("blocked");
    expect(blockedEmpty.verdictStatus).toBe("unknown");

    // 2. Unavailable + empty -> unavailable / unknown
    const unavailEmpty = await investigateEndpointMobility(
      {
        search: vi
          .fn()
          .mockRejectedValueOnce(new Error("Search dispatch timed out"))
          .mockResolvedValueOnce({ rows: [], warnings: [], errors: [] }),
      },
      makeRequest(),
      twoProfiles,
      new AbortController().signal,
      { skipConfigRecheck: true, skipEstimateCheck: true },
    );
    expect(unavailEmpty.bannerState).toBe("unavailable");
    expect(unavailEmpty.verdictStatus).toBe("unknown");

    // 3. Capped + empty -> partial / unknown (never none_observed)
    const cappedEmpty = await investigateEndpointMobility(
      {
        search: vi.fn().mockResolvedValue({
          rows: [],
          warnings: [],
          errors: [],
          truncated: true,
        }),
      },
      makeRequest(),
      makeConfig([makeProfile({ extra: { sourceKind: "nd_endpoints" } })]),
      new AbortController().signal,
      { skipConfigRecheck: true, skipEstimateCheck: true },
    );
    expect(cappedEmpty.bannerState).toBe("partial");
    expect(cappedEmpty.verdictStatus).toBe("unknown");
    expect(cappedEmpty.coverageStatus).toBe("unknown");

    // 4. summarizeEndpointMobility downgrades degraded ok -> attention and none_observed -> unknown
    const summaryCappedOk = await summarizeEndpointMobility(
      {
        search: vi
          .fn()
          .mockRejectedValueOnce(new SearchAccessDeniedError())
          .mockResolvedValueOnce({
            rows: [
              {
                _time: EARLIEST + 20,
                host: "splunk-hf-01",
                sourcetype: "cisco:dc:nd:endpoints",
                mac: "02:00:0a:0a:14:0b",
                ip: ["10.10.20.11"],
                nodeName: "leaf-101",
                displayInterface: ["eth1/11"],
                modType: "creation",
              },
            ],
            warnings: [],
            errors: [],
          }),
      },
      makeRequest(),
      twoProfiles,
      new AbortController().signal,
      { skipConfigRecheck: true, skipEstimateCheck: true },
    );
    expect(summaryCappedOk.status).toBe("attention");

    const summaryBlockedEmpty = await summarizeEndpointMobility(
      {
        search: vi
          .fn()
          .mockRejectedValueOnce(new SearchAccessDeniedError())
          .mockResolvedValueOnce({ rows: [], warnings: [], errors: [] }),
      },
      makeRequest(),
      twoProfiles,
      new AbortController().signal,
      { skipConfigRecheck: true, skipEstimateCheck: true },
    );
    expect(summaryBlockedEmpty.status).toBe("unknown");
  });

  it("strips sensitive fields and detects stale config via protocolConfigClient.readProtocolProfileDocument", async () => {
    const client: SearchClient = {
      search: vi.fn().mockResolvedValue({
        rows: [
          {
            _time: EARLIEST + 10,
            host: "splunk-hf-01",
            sourcetype: "cisco:dc:nd:endpoints",
            mac: "02:00:0a:0a:14:0b",
            ip: ["10.10.20.11"],
            nodeName: "leaf-101",
            displayInterface: ["eth1/11"],
            modType: "creation",
            _raw: "strip-me",
            cookie: "secret",
            payload: "secret",
          },
        ],
        warnings: [],
        errors: [],
      }),
    };

    const spy = vi
      .spyOn(protocolConfigClient, "readProtocolProfileDocument")
      .mockResolvedValue({
        version: 1,
        profiles: [makeProfile({ extra: { sourceKind: "nd_endpoints" } })],
      });

    try {
      const config = await readProtocolConfiguration({
        endpoint_mobility: validateEndpointMobilityExtra,
      });
      const okSummary = await summarizeEndpointMobility(
        client,
        makeRequest(),
        config,
        new AbortController().signal,
      );
      expect(okSummary.status).toBe("ok");

      // Mutate profile document so fingerprint mismatches -> stale_config
      spy.mockResolvedValueOnce({
        version: 1,
        profiles: [
          makeProfile({
            index: "other_idx",
            extra: { sourceKind: "nd_endpoints" },
          }),
        ],
      });
      const stale = await investigateEndpointMobility(
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

  it("marks Duplicate IPs KPI as none_observed when endpoints have no IP fields and omits uncovered claims from clean verdict", async () => {
    const client: SearchClient = {
      search: vi.fn().mockResolvedValue({
        rows: [
          {
            _time: String(EARLIEST + 120),
            host: "nd-1",
            sourcetype: "cisco:dc:nd:endpoints",
            mac: "00:50:56:aa:00:01",
            switchName: "leaf1",
            interfaceName: "Eth1/1",
            vlan: "100",
          },
        ],
        truncated: false,
        warnings: [],
        errors: [],
      }),
    };
    const res = await investigateEndpointMobility(
      client,
      makeRequest(),
      makeConfig([makeProfile({ extra: { sourceKind: "nd_endpoints" } })]),
      new AbortController().signal,
      { skipConfigRecheck: true },
    );
    const dupKpi = res.kpis.find((k) => k.id === "duplicate-ips");
    expect(dupKpi?.value).toBe("None observed");
    expect(dupKpi?.status).toBe("none_observed");
    expect(res.verdict).toContain("no endpoint IPs reported");
    expect(res.verdict).toContain("ARP spikes");
    expect(res.verdict).toContain("not covered");
  });
});
