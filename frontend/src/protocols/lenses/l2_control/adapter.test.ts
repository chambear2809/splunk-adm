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
  L2_SUBSYSTEMS,
  buildL2ControlAnalysis,
  buildL2ControlRawEventsUrl,
  buildL2DmeSearch,
  buildL2StreamSearch,
  investigateL2Control,
  normalizeL2ControlRow,
  resolveL2ControlThresholds,
  summarizeL2Control,
  validateL2ControlExtra,
} from "./adapter";

const NOW = 1800000500;
const EARLIEST = 1800000000;

function makeProfile(
  overrides: Partial<BaseProtocolProfile> = {},
): BaseProtocolProfile {
  return {
    id: "l2-dc1",
    source: "protocol_l2_control",
    lens: "l2_control",
    scope: "prod:dc1",
    index: "cisco_dc",
    observer: "sc4s-01",
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
    lens: "l2_control",
    scope: "prod:dc1",
    earliest: EARLIEST,
    latest: NOW,
    ...overrides,
  };
}

describe("validateL2ControlExtra (fail-closed profile validation)", () => {
  it("accepts valid extra thresholds and sourceKind and integrates with parseProtocolProfiles", () => {
    expect(validateL2ControlExtra(undefined)).toBeUndefined();
    expect(
      validateL2ControlExtra({
        sourceKind: "stream_dhcp",
        dhcpNakWarnCount: 2,
        stpTcnWarnCount: 3,
        lacpDropWarnCount: 1,
      }),
    ).toEqual({
      sourceKind: "stream_dhcp",
      dhcpNakWarnCount: 2,
      stpTcnWarnCount: 3,
      lacpDropWarnCount: 1,
    });

    const profiles = parseProtocolProfiles(
      {
        version: 1,
        profiles: [
          {
            id: "l2-dc1",
            source: "protocol_l2_control",
            lens: "l2_control",
            scope: "prod:dc1",
            index: "cisco_dc",
            observer: "sc4s-01",
            validFrom: EARLIEST - 3600,
            validUntil: NOW + 3600,
            extra: { sourceKind: "syslog", stpTcnWarnCount: 4 },
          },
        ],
      },
      { l2_control: validateL2ControlExtra },
    );
    expect(resolveL2ControlThresholds(profiles[0])).toEqual({
      sourceKind: "syslog",
      dhcpNakWarnCount: 1,
      stpTcnWarnCount: 4,
      lacpDropWarnCount: 1,
    });
  });

  it("rejects unknown keys and out-of-bounds values", () => {
    expect(() => validateL2ControlExtra({ unknownKey: true })).toThrow(
      /Unsupported l2_control/,
    );
    expect(() =>
      validateL2ControlExtra({ sourceKind: "netflow" as never }),
    ).toThrow(/sourceKind/);
    expect(() => validateL2ControlExtra({ dhcpNakWarnCount: 0 })).toThrow(
      /dhcpNakWarnCount/,
    );
    expect(() => validateL2ControlExtra({ dhcpNakWarnCount: 1001 })).toThrow(
      /dhcpNakWarnCount/,
    );
    expect(() => validateL2ControlExtra({ dhcpNakWarnCount: 1.5 })).toThrow(
      /dhcpNakWarnCount/,
    );
    expect(() => validateL2ControlExtra({ stpTcnWarnCount: -1 })).toThrow(
      /stpTcnWarnCount/,
    );
    expect(() => validateL2ControlExtra({ lacpDropWarnCount: 1001 })).toThrow(
      /lacpDropWarnCount/,
    );
  });
});

describe("buildL2StreamSearch, buildL2DmeSearch & sensitive-field guards", () => {
  it("builds bounded allowlist-only SPL with | head before | table", () => {
    const streamSpl = buildL2StreamSearch({
      index: "stream_net",
      includeArp: true,
      filter: {
        src: "10.10.110.25",
        dst: "10.10.10.5",
        device: "stream-fwd-01",
        vni: "10110",
      },
      maxRows: 256,
    });
    expect(streamSpl).toContain("index=stream_net");
    expect(streamSpl).toContain('sourcetype="stream:dhcp"');
    expect(streamSpl).toContain('sourcetype="stream:arp"');
    expect(streamSpl).toContain("| head 257");
    expect(streamSpl).toContain("| table ");
    expect(streamSpl.indexOf("| head 257")).toBeLessThan(
      streamSpl.indexOf("| table "),
    );
    expect(() =>
      assertNoForbiddenFieldsInSpl("l2_control", streamSpl),
    ).not.toThrow();

    const dmeSpl = buildL2DmeSearch({
      index: "cisco_dc",
      filter: { device: "leaf1.dc1.example" },
      maxRows: 100,
    });
    expect(dmeSpl).toContain('sourcetype="cisco:dc:nexus9k:dme"');
    expect(dmeSpl).toContain("| head 101");
    expect(dmeSpl).toContain("| table ");
    expect(dmeSpl.indexOf("| head 101")).toBeLessThan(
      dmeSpl.indexOf("| table "),
    );
    expect(() =>
      assertNoForbiddenFieldsInSpl("l2_control", dmeSpl),
    ).not.toThrow();

    for (const forbidden of FORBIDDEN_SENSITIVE_FIELDS) {
      expect(streamSpl.toLowerCase()).not.toMatch(
        new RegExp(`\\b${forbidden}\\b`),
      );
      expect(dmeSpl.toLowerCase()).not.toMatch(
        new RegExp(`\\b${forbidden}\\b`),
      );
    }
  });

  it("rejects SPL injection in filters and raw-events link builder", () => {
    expect(() =>
      buildL2StreamSearch({
        index: "stream_net",
        filter: { src: '10.0.0.1" OR "1"="1' },
        maxRows: 256,
      }),
    ).toThrow(/Invalid literal/);

    const safeUrl = buildL2ControlRawEventsUrl({
      index: "cisco_dc",
      sourcetypes: ["cisco:ios"],
      device: "leaf1.dc1.example",
      subsystem: "STP",
      subject: "Ethernet1/49",
      earliest: EARLIEST,
      latest: NOW,
    });
    expect(safeUrl).toMatch(/^\/app\/splunk_adm\/search\?/);
    expect(safeUrl).toContain("sourcetype%3D%22cisco%3Aios%22");

    expect(() =>
      buildL2ControlRawEventsUrl({
        index: "cisco_dc",
        sourcetypes: ["cisco:ios"],
        device: "bad device!",
        subsystem: "STP",
        subject: "Ethernet1/49",
        earliest: EARLIEST,
        latest: NOW,
      }),
    ).toThrow(/Invalid literal/);
  });
});

describe("normalizeL2ControlRow & buildL2ControlAnalysis", () => {
  it("normalizes stream:dhcp, stream:arp duplicate MAC conflicts, NX-OS syslog, and DME rows", () => {
    const dhcpAck = normalizeL2ControlRow(
      {
        _time: EARLIEST + 20,
        host: "stream-fwd-01",
        sourcetype: "stream:dhcp",
        dest_ip: "10.10.10.5",
        client_mac: "00:50:56:aa:10:01",
        dhcp_message_type: 5,
        yiaddr: "10.10.110.25",
        lease_time: 3600,
        vlan_id: 110,
      },
      0,
    )!;
    expect(dhcpAck).toMatchObject({
      subsystem: "DHCP",
      device: "10.10.10.5",
      subject: "vlan-110",
      anomaly: false,
      dhcpMessageType: "ACK",
      yiaddr: "10.10.110.25",
    });

    const arp1 = normalizeL2ControlRow(
      {
        _time: EARLIEST + 40,
        host: "stream-fwd-01",
        sourcetype: "stream:arp",
        src_ip: "10.10.110.50",
        dest_ip: "10.10.110.1",
        client_mac: "00:50:56:11:11:11",
        message_type: 1,
        vlan_id: 110,
      },
      1,
    )!;
    const arp2 = normalizeL2ControlRow(
      {
        _time: EARLIEST + 50,
        host: "stream-fwd-01",
        sourcetype: "stream:arp",
        src_ip: "10.10.110.50",
        dest_ip: "10.10.110.1",
        client_mac: "00:50:56:22:22:22",
        message_type: 2,
        vlan_id: 110,
      },
      2,
    )!;

    const dmeLacpDown = normalizeL2ControlRow(
      {
        _time: EARLIEST + 70,
        host: "leaf4.dc1.example",
        sourcetype: "cisco:dc:nexus9k:dme",
        port_channel: "po10",
        member_interface: "Ethernet1/5",
        operSt: "down",
        lacp_state: "suspended",
      },
      3,
    )!;
    expect(dmeLacpDown).toMatchObject({
      subsystem: "LACP",
      device: "leaf4.dc1.example",
      subject: "po10",
      anomaly: true,
    });

    // Auth and config-change syslog events must be stripped by nxosSyslog.ts
    expect(
      normalizeL2ControlRow(
        {
          _time: EARLIEST + 80,
          host: "leaf1.dc1.example",
          sourcetype: "cisco:ios",
          syslog_msg: "%AUTHPRIV-6-LOGIN_SUCCESS: user admin logged in",
        },
        4,
      ),
    ).toBeUndefined();
    expect(
      normalizeL2ControlRow(
        {
          _time: EARLIEST + 90,
          host: "leaf1.dc1.example",
          sourcetype: "cisco:dc:nexus9k:syslog",
          category: "VSHD",
          severity_id: "5",
          mnemonics: "VSHD_SYSLOG_CONFIG_I",
          syslog_msg: "Configured from vty",
        },
        5,
      ),
    ).toBeUndefined();

    const analysis = buildL2ControlAnalysis({
      events: [
        { event: dhcpAck, indexName: "stream_net" },
        { event: arp1, indexName: "stream_net" },
        { event: arp2, indexName: "stream_net" },
        { event: dmeLacpDown, indexName: "cisco_dc" },
      ],
      thresholds: resolveL2ControlThresholds(),
      earliest: EARLIEST,
      latest: NOW,
      outcomes: [{ source: "protocol_l2_control", state: "complete" }],
      capped: false,
      activeSourceKinds: ["auto"],
    });

    const arpRow = analysis.rows.find((r) => r.subsystem === "ARP")!;
    expect(arpRow.attention).toBe(true);
    expect(arpRow.reasons[0]).toContain("duplicate ARP");

    const lacpRow = analysis.rows.find((r) => r.subsystem === "LACP")!;
    expect(lacpRow.attention).toBe(true);
    expect(lacpRow.memberInterfaces).toEqual(["Ethernet1/5"]);

    const dhcpRow = analysis.rows.find((r) => r.subsystem === "DHCP")!;
    expect(dhcpRow.attention).toBe(false);
    expect(dhcpRow.status).toBe("ok");
  });

  it("loads and normalizes committed stream_dhcp and nxos_l2_syslog fixtures cleanly", () => {
    const dhcpLines = readFileSync(
      "fixtures/raw/protocols/l2_control/stream_dhcp.ndjson",
      "utf8",
    )
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as Record<string, unknown>);
    const syslogLines = readFileSync(
      "fixtures/raw/protocols/l2_control/nxos_l2_syslog.ndjson",
      "utf8",
    )
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as Record<string, unknown>);

    const dhcpEvents = dhcpLines.map((row, idx) => ({
      event: normalizeL2ControlRow(row, idx)!,
      indexName: "netflow",
    }));
    const syslogEvents = syslogLines.map((row, idx) => ({
      event: normalizeL2ControlRow(row, idx)!,
      indexName: "cisco_dc",
    }));
    expect(dhcpEvents.every((e) => Boolean(e.event))).toBe(true);
    expect(syslogEvents.every((e) => Boolean(e.event))).toBe(true);

    const combined = buildL2ControlAnalysis({
      events: [...dhcpEvents, ...syslogEvents],
      thresholds: resolveL2ControlThresholds(),
      earliest: EARLIEST,
      latest: NOW,
      outcomes: [{ source: "protocol_l2_control", state: "complete" }],
      capped: false,
      activeSourceKinds: ["auto"],
    });

    expect(combined.kpis).toHaveLength(4);
    expect(combined.kpis.find((k) => k.id === "dhcp-naks")?.value).toBe("2");
    expect(combined.kpis.find((k) => k.id === "stp-changes")?.value).toBe("1");
    expect(combined.kpis.find((k) => k.id === "lacp-drops")?.value).toBe("1");
    expect(combined.kpis.find((k) => k.id === "arp-l2-alerts")?.value).toBe(
      "1",
    );
    expect(combined.matrixCols).toEqual([...L2_SUBSYSTEMS]);
    expect(combined.timeline.length).toBeGreaterThan(0);

    // Every row ID must round-trip through parseProtocolLink's strict ITEM_ID regex without '->'.
    for (const row of combined.rows) {
      expect(row.id).not.toContain("->");
      const parsed = parseProtocolLink(
        new URLSearchParams({ p_lens: "l2_control", p_item: row.id }),
      );
      expect(parsed.item).toBe(row.id);
    }

    // Stream-only analysis must mark STP and LACP KPIs and Matrix cells as not_covered.
    const streamOnly = buildL2ControlAnalysis({
      events: dhcpEvents,
      thresholds: resolveL2ControlThresholds(),
      earliest: EARLIEST,
      latest: NOW,
      outcomes: [{ source: "protocol_l2_control", state: "complete" }],
      capped: false,
      activeSourceKinds: ["stream_dhcp"],
    });
    expect(streamOnly.kpis.find((k) => k.id === "stp-changes")?.status).toBe(
      "not_covered",
    );
    expect(streamOnly.kpis.find((k) => k.id === "lacp-drops")?.status).toBe(
      "not_covered",
    );
    expect(
      streamOnly.matrixCells.some(
        (c) => c.col === "STP" && c.status === "not_covered",
      ),
    ).toBe(true);
  });
});

describe("investigateL2Control (runner, Estimate mode, degraded coverage, security)", () => {
  it("checks Stream Estimate mode for dhcp/arp when stream:dhcp returns 0 rows", async () => {
    const search = vi
      .fn()
      .mockResolvedValueOnce({ rows: [], warnings: [], errors: [] })
      .mockResolvedValueOnce({
        rows: [
          { host: "stream-fwd-01", stream_id: "dhcp", stats_only: "true" },
        ],
        warnings: [],
        errors: [],
      });
    const client: SearchClient = { search };
    const result = await investigateL2Control(
      client,
      makeRequest(),
      makeConfig([
        makeProfile({
          id: "l2-dhcp",
          index: "netflow",
          extra: { sourceKind: "stream_dhcp" },
        }),
      ]),
      new AbortController().signal,
      { skipConfigRecheck: true },
    );
    expect(search).toHaveBeenCalledTimes(2);
    expect(search.mock.calls[1][0].search).toContain(
      'sourcetype="stream:stats"',
    );
    expect(search.mock.calls[1][0].search).toContain('"dhcp", "arp"');
    expect(result.bannerState).toBe("estimate_only");
    expect(result.verdictStatus).toBe("unknown");
  });

  it("handles degraded multi-source outcomes truthfully instead of none_observed or ok", async () => {
    const profilesTwo = makeConfig([
      makeProfile({
        id: "l2-dhcp",
        index: "netflow",
        extra: { sourceKind: "stream_dhcp" },
      }),
      makeProfile({
        id: "l2-syslog",
        index: "cisco_dc",
        extra: { sourceKind: "syslog" },
      }),
    ]);

    // 1. Blocked + empty -> blocked/unknown (never none_observed)
    const blockedEmpty = await investigateL2Control(
      {
        search: vi
          .fn()
          .mockRejectedValueOnce(new SearchAccessDeniedError())
          .mockResolvedValueOnce({ rows: [], warnings: [], errors: [] }),
      },
      makeRequest(),
      profilesTwo,
      new AbortController().signal,
      { skipConfigRecheck: true, skipEstimateCheck: true },
    );
    expect(blockedEmpty.bannerState).toBe("blocked");
    expect(blockedEmpty.verdictStatus).toBe("unknown");
    expect(blockedEmpty.coverageStatus).toBe("unknown");

    // 2. Unavailable + empty -> unavailable/unknown (never none_observed)
    const unavailEmpty = await investigateL2Control(
      {
        search: vi
          .fn()
          .mockRejectedValueOnce(new Error("Search dispatch timed out"))
          .mockResolvedValueOnce({ rows: [], warnings: [], errors: [] }),
      },
      makeRequest(),
      profilesTwo,
      new AbortController().signal,
      { skipConfigRecheck: true, skipEstimateCheck: true },
    );
    expect(unavailEmpty.bannerState).toBe("unavailable");
    expect(unavailEmpty.verdictStatus).toBe("unknown");

    // 3. One source blocked + syslog returns rows -> partial/attention with cause-specific bannerReason
    const partialBlocked = await investigateL2Control(
      {
        search: vi
          .fn()
          .mockRejectedValueOnce(new SearchAccessDeniedError())
          .mockResolvedValueOnce({
            rows: [
              {
                _time: EARLIEST + 30,
                host: "leaf1.dc1.example",
                sourcetype: "cisco:ios",
                category: "STP",
                severity_id: "2",
                mnemonics: "ROOTGUARD_BLOCK",
                syslog_msg: "Root guard blocking Ethernet1/49",
              },
            ],
            warnings: [],
            errors: [],
          }),
      },
      makeRequest(),
      profilesTwo,
      new AbortController().signal,
      { skipConfigRecheck: true, skipEstimateCheck: true },
    );
    expect(partialBlocked.bannerState).toBe("partial");
    expect(partialBlocked.coverageStatus).toBe("attention");
    expect(partialBlocked.bannerReason).toMatch(/denied access/i);
    expect(partialBlocked.rows).toHaveLength(1);
  });

  it("handles unconfigured scope without searching and strips sensitive fields + detects stale config", async () => {
    const emptySearch = vi.fn();
    const unconfigured = await investigateL2Control(
      { search: emptySearch },
      makeRequest({ scope: "prod:other" }),
      makeConfig([makeProfile({ scope: "prod:dc1" })]),
      new AbortController().signal,
      { skipConfigRecheck: true },
    );
    expect(emptySearch).not.toHaveBeenCalled();
    expect(unconfigured.bannerState).toBe("unavailable");
    expect(unconfigured.coverageStatus).toBe("not_covered");

    const client: SearchClient = {
      search: vi.fn().mockResolvedValue({
        rows: [
          {
            _time: EARLIEST + 10,
            host: "leaf1.dc1.example",
            sourcetype: "cisco:ios",
            category: "LLDP",
            severity_id: "5",
            mnemonics: "NEIGHBOR_ADDED",
            syslog_msg: "LLDP neighbor sw-core-01 on Ethernet1/48",
            _raw: "should be stripped",
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
        profiles: [makeProfile({ extra: { sourceKind: "syslog" } })],
      });
    try {
      const config = await readProtocolConfiguration({
        l2_control: validateL2ControlExtra,
      });
      const summary = await summarizeL2Control(
        client,
        makeRequest(),
        config,
        new AbortController().signal,
      );
      expect(summary.status).toBe("ok");

      spy.mockResolvedValueOnce({
        version: 1,
        profiles: [
          makeProfile({ index: "other_idx", extra: { sourceKind: "syslog" } }),
        ],
      });
      const stale = await investigateL2Control(
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

  it("keeps distinct IPv4 DHCP clients in separate timeline lanes and includes all classified IOS/NX-OS syslog categories in SPL", async () => {
    const dhcpRows = [
      {
        _time: EARLIEST + 100,
        host: "dhcp-01",
        sourcetype: "stream:dhcp",
        src_ip: "10.10.20.1",
        dest_ip: "10.10.20.99",
        client_mac: "00:50:56:aa:bb:01",
        dhcp_message_type: "NAK",
      },
      {
        _time: EARLIEST + 200,
        host: "dhcp-01",
        sourcetype: "stream:dhcp",
        src_ip: "10.10.20.1",
        dest_ip: "10.10.20.55",
        client_mac: "00:50:56:aa:bb:02",
        dhcp_message_type: "ACK",
      },
    ];
    const events = dhcpRows
      .map((r, i) => normalizeL2ControlRow(r, i)!)
      .map((event) => ({ event, indexName: "stream" }));
    const analysis = buildL2ControlAnalysis({
      events,
      thresholds: resolveL2ControlThresholds(),
      earliest: EARLIEST,
      latest: NOW,
      outcomes: [{ source: "protocol_l2_control", state: "complete" }],
      capped: false,
      activeSourceKinds: ["stream_dhcp"],
    });
    const lanes = [...new Set(analysis.timeline.map((e) => e.lane))];
    expect(lanes).toContain("DHCP · 10.10.20.99");
    expect(lanes).toContain("DHCP · 10.10.20.55");
    expect(lanes).not.toContain("DHCP · 10");

    const search = vi
      .fn()
      .mockResolvedValue({ rows: [], warnings: [], errors: [] });
    await investigateL2Control(
      { search },
      makeRequest(),
      makeConfig([makeProfile({ extra: { sourceKind: "syslog" } })]),
      new AbortController().signal,
      { skipConfigRecheck: true },
    );
    const spl = String(search.mock.calls[0][0].search);
    for (const cat of [
      "DHCP",
      "DHCP_SNOOPING",
      "STP",
      "MSTP",
      "SPANTREE",
      "LACP",
      "ETH_PORT_CHANNEL",
      "EC",
      "ARP",
      "DAI",
      "SW_DAI",
      "LLDP",
    ]) {
      expect(spl).toContain(`"${cat}"`);
    }
    expect(spl).not.toContain('"CDP"');
  });
});
