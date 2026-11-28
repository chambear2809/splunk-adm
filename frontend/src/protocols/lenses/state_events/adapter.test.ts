import { readFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import { protocolConfigClient } from "../../../data/evidenceConfig";
import { SearchAccessDeniedError } from "../../../data/searchClient";
import { parseProtocolLink, parseProtocolProfiles } from "../../inputs";
import type {
  BaseProtocolProfile,
  ProtocolConfiguration,
  ProtocolRequest,
} from "../../shared/contract";
import {
  FORBIDDEN_SENSITIVE_FIELDS,
  LENS_FIELD_ALLOWLISTS,
  assertNoForbiddenFieldsInSpl,
} from "../../shared/fields";
import {
  ACI_FAULT_EVENT_FIELDS,
  CONFIG_CHANGE_MNEMONICS,
  EXCLUDED_AUTH_CATEGORIES,
  buildAciFaultEventSearch,
  buildStateEventsAnalysis,
  buildStateEventsRawEventsUrl,
  buildStateSyslogSearch,
  investigateStateEvents,
  normalizeAciFaultEventRow,
  normalizeStateSyslogRow,
  resolveStateEventsThresholds,
  shortenDeviceLabel,
  summarizeStateEvents,
  validateStateEventsExtra,
} from "./adapter";

const EARLIEST = 1764246600;
const NOW = 1764248400;

function makeProfile(
  overrides: Partial<BaseProtocolProfile> = {},
): BaseProtocolProfile {
  return {
    id: "state-events-dc1",
    source: "protocol_state_events",
    lens: "state_events",
    scope: "prod:dc1",
    index: "cisco_dc",
    observer: "sc4s-dc1",
    validFrom: EARLIEST - 3600,
    validUntil: NOW + 3600,
    ...overrides,
  };
}

function makeConfig(
  profiles: BaseProtocolProfile[],
  fingerprint = "fp-state-events-initial",
): ProtocolConfiguration {
  return { profiles, fingerprint };
}

function makeRequest(
  overrides: Partial<ProtocolRequest> = {},
): ProtocolRequest {
  return {
    version: 1,
    lens: "state_events",
    scope: "prod:dc1",
    earliest: EARLIEST,
    latest: NOW,
    ...overrides,
  };
}

describe("validateStateEventsExtra (fail-closed profile validation)", () => {
  it("accepts valid extra options and integrates with parseProtocolProfiles", () => {
    expect(validateStateEventsExtra(undefined)).toBeUndefined();
    expect(
      validateStateEventsExtra({
        sourceKind: "syslog",
        burstWarnCount: 10,
        maxSeverityAttention: 2,
        includeAci: false,
      }),
    ).toEqual({
      sourceKind: "syslog",
      burstWarnCount: 10,
      maxSeverityAttention: 2,
      includeAci: false,
    });

    const profiles = parseProtocolProfiles(
      {
        version: 1,
        profiles: [
          {
            id: "state-dc1",
            source: "protocol_state_events",
            lens: "state_events",
            scope: "prod:dc1",
            index: "cisco_dc",
            observer: "sc4s-dc1",
            validFrom: EARLIEST - 3600,
            validUntil: NOW + 3600,
            extra: { burstWarnCount: 8, maxSeverityAttention: 4 },
          },
        ],
      },
      { state_events: validateStateEventsExtra },
    );

    expect(resolveStateEventsThresholds(profiles[0])).toEqual({
      sourceKind: "auto",
      burstWarnCount: 8,
      maxSeverityAttention: 4,
      includeAci: true,
    });
  });

  it("rejects unknown keys and out-of-range thresholds", () => {
    expect(() => validateStateEventsExtra({ unknownKey: 1 })).toThrow(
      /Unsupported state_events/,
    );
    expect(() =>
      validateStateEventsExtra({ sourceKind: "netflow" as never }),
    ).toThrow(/sourceKind/);
    expect(() => validateStateEventsExtra({ burstWarnCount: 0 })).toThrow(
      /burstWarnCount/,
    );
    expect(() => validateStateEventsExtra({ burstWarnCount: 1001 })).toThrow(
      /burstWarnCount/,
    );
    expect(() => validateStateEventsExtra({ burstWarnCount: 2.5 })).toThrow(
      /burstWarnCount/,
    );
    expect(() =>
      validateStateEventsExtra({ maxSeverityAttention: -1 }),
    ).toThrow(/maxSeverityAttention/);
    expect(() => validateStateEventsExtra({ maxSeverityAttention: 8 })).toThrow(
      /maxSeverityAttention/,
    );
    expect(() =>
      validateStateEventsExtra({ includeAci: "yes" as never }),
    ).toThrow(/includeAci/);
    expect(() =>
      validateStateEventsExtra({ sourceKind: "aci_faults", includeAci: false }),
    ).toThrow(/includeAci cannot be false/);
  });
});

describe("shortenDeviceLabel", () => {
  it("preserves IPv4 and IPv6 literals intact while shortening DNS hostnames", () => {
    expect(shortenDeviceLabel("192.0.2.11")).toBe("192.0.2.11");
    expect(shortenDeviceLabel("2001:db8::1")).toBe("2001:db8::1");
    expect(shortenDeviceLabel("leaf-01.dc1.local")).toBe("leaf-01");
    expect(shortenDeviceLabel("pod-1/node-201")).toBe("pod-1/node-201");
  });
});

describe("SPL builders & sensitive-field guards", () => {
  it("delegates syslog SPL to shared nxosSyslog adapter and respects includeAci", () => {
    const withAci = buildStateSyslogSearch({
      index: "cisco_dc",
      filter: { device: "leaf-01.dc1.local" },
      includeAci: true,
      maxRows: 256,
    });
    expect(withAci).toContain("index=cisco_dc");
    expect(withAci).toContain('sourcetype="cisco:ios"');
    expect(withAci).toContain('sourcetype="cisco:dc:nexus9k:syslog"');
    expect(withAci).toContain('sourcetype="cisco:aci"');
    expect(withAci).toContain('sourcetype="cisco:dc:aci:syslog"');
    expect(withAci).toContain('host="leaf-01.dc1.local"');
    expect(withAci).toContain("| head 257");
    expect(withAci.indexOf("| head 257")).toBeLessThan(
      withAci.indexOf("| table "),
    );
    for (const mnem of CONFIG_CHANGE_MNEMONICS) {
      expect(withAci).toContain(mnem);
    }
    for (const cat of EXCLUDED_AUTH_CATEGORIES) {
      expect(withAci).toContain(cat);
    }
    for (const cat of ["AUDIT", "SESSION", "LOGIN"]) {
      expect(withAci).toContain(cat);
    }
    expect(withAci.indexOf("AUDIT")).toBeLessThan(
      withAci.indexOf("| head 257"),
    );
    expect(() =>
      assertNoForbiddenFieldsInSpl("state_events", withAci),
    ).not.toThrow();

    const withoutAci = buildStateSyslogSearch({
      index: "cisco_dc",
      includeAci: false,
      maxRows: 256,
    });
    expect(withoutAci).toContain('sourcetype="cisco:ios"');
    expect(withoutAci).not.toContain('sourcetype="cisco:aci"');
    expect(withoutAci).not.toContain('sourcetype="cisco:dc:aci:syslog"');
  });

  it("builds bounded allowlisted ACI fault/event SPL with head before table and no post-head where", () => {
    const spl = buildAciFaultEventSearch({
      index: "cisco_dc",
      filter: { device: "apic-01.dc1.local" },
      maxRows: 256,
    });
    expect(spl).toContain("index=cisco_dc");
    expect(spl).toContain('sourcetype="cisco:dc:aci:fault"');
    expect(spl).toContain('sourcetype="cisco:dc:aci:event"');
    expect(spl).toContain('sourcetype="cisco:dc:aci:class"');
    expect(spl).toContain('component="faultInst"');
    expect(spl).toContain('component="eventRecord"');
    expect(spl).toContain(
      '(host="apic-01.dc1.local" OR device="apic-01.dc1.local" OR apic_host="apic-01.dc1.local")',
    );
    expect(spl).toContain('sourcetype="cisco:dc:nexus9k:dme"');
    expect(spl).toContain("| head 257");
    expect(spl).toContain("| table ");
    expect(spl.indexOf("| head 257")).toBeLessThan(spl.indexOf("| table "));
    const afterHead = spl.slice(spl.indexOf("| head 257"));
    expect(afterHead.toLowerCase()).not.toContain("| where");
    expect(() =>
      assertNoForbiddenFieldsInSpl("state_events", spl),
    ).not.toThrow();

    const allowSet = new Set(LENS_FIELD_ALLOWLISTS.state_events);
    for (const field of ACI_FAULT_EVENT_FIELDS) {
      expect(allowSet.has(field)).toBe(true);
    }
    for (const forbidden of FORBIDDEN_SENSITIVE_FIELDS) {
      expect(spl.toLowerCase()).not.toMatch(new RegExp(`\\b${forbidden}\\b`));
    }
  });

  it("rejects SPL injection in filters and raw-events URL builder", () => {
    expect(() =>
      buildAciFaultEventSearch({
        index: "cisco_dc",
        filter: { device: 'apic" OR "1"="1' },
        maxRows: 256,
      }),
    ).toThrow(/Invalid literal/);

    const url = buildStateEventsRawEventsUrl({
      index: "cisco_dc",
      rawHosts: ["192.0.2.11"],
      sourceCoverage: "syslog_only",
      includeAci: true,
      earliest: EARLIEST,
      latest: NOW,
    });
    expect(url).toMatch(/^\/app\/splunk_adm\/search\?/);
    expect(url).toContain("192.0.2.11");

    expect(() =>
      buildStateEventsRawEventsUrl({
        index: "cisco_dc",
        rawHosts: ["bad host!"],
        sourceCoverage: "syslog_only",
        includeAci: true,
        earliest: EARLIEST,
        latest: NOW,
      }),
    ).toThrow(/Invalid literal/);
  });
});

describe("normalization & exclusions", () => {
  it("excludes config-change mnemonics and AAA/auth categories client-side", () => {
    const configRow = normalizeStateSyslogRow(
      {
        _time: EARLIEST + 60,
        host: "leaf-01.dc1.local",
        sourcetype: "cisco:ios",
        syslog_msg:
          "%VSHD-5-VSHD_SYSLOG_CONFIG_I: Configured from vty by admin on pts/0",
      },
      0,
    );
    expect(configRow).toBeUndefined();

    const cfgLogRow = normalizeStateSyslogRow(
      {
        _time: EARLIEST + 90,
        host: "leaf-01.dc1.local",
        sourcetype: "cisco:dc:nexus9k:syslog",
        category: "PARSER",
        severity_id: "5",
        mnemonics: "CFGLOG_LOGGEDCMD",
        syslog_msg: "Logged command: router bgp 65001",
      },
      1,
    );
    expect(cfgLogRow).toBeUndefined();

    const authRow = normalizeStateSyslogRow(
      {
        _time: EARLIEST + 120,
        host: "leaf-01.dc1.local",
        sourcetype: "cisco:dc:nexus9k:syslog",
        category: "AUTHPRIV",
        severity_id: "6",
        mnemonics: "LOGIN_SUCCESS",
        syslog_msg: "user admin logged in",
      },
      2,
    );
    expect(authRow).toBeUndefined();

    const aciAuditRow = normalizeStateSyslogRow(
      {
        _time: EARLIEST + 130,
        host: "apic-01.dc1.local",
        sourcetype: "cisco:aci",
        syslog_msg:
          "%AUDIT-6-USER_LOGIN: user alice logged in from 198.51.100.5",
      },
      3,
    );
    expect(aciAuditRow).toBeUndefined();

    const aciSessionEvent = normalizeAciFaultEventRow(
      {
        _time: EARLIEST + 140,
        host: "apic-01.dc1.local",
        sourcetype: "cisco:dc:aci:event",
        component: "eventRecord",
        code: "E4200001",
        severity: "info",
        domain: "session",
        descr: "Session opened for user alice",
      },
      4,
    );
    expect(aciSessionEvent).toBeUndefined();
  });

  it("normalizes ACI faultInst and eventRecord rows while ignoring unrelated classes", () => {
    const fault = normalizeAciFaultEventRow(
      {
        _time: EARLIEST + 100,
        host: "apic-01.dc1.local",
        sourcetype: "cisco:dc:aci:fault",
        apic_host: "apic-01.dc1.local",
        component: "faultInst",
        code: "F0546",
        severity: "critical",
        domain: "infra",
        cause: "port-down",
        lifecycle: "raised",
        affected: "topology/pod-1/node-201/sys/phys-[eth1/1]/phys",
        descr: "Port eth1/1 is operationally down",
      },
      0,
    );
    expect(fault).toMatchObject({
      device: "pod-1/node-201",
      rawHost: "apic-01.dc1.local",
      domain: "aci_faults",
      domainLabel: "ACI Faults",
      severity: 2,
      codeOrMnemonic: "F0546",
    });

    const clearedFault = normalizeAciFaultEventRow(
      {
        _time: EARLIEST + 150,
        host: "apic-01.dc1.local",
        sourcetype: "cisco:dc:aci:class",
        component: "faultInst",
        code: "F0546",
        severity: "cleared",
        lifecycle: "cleared",
        affected: "topology/pod-1/node-201/sys/phys-[eth1/1]/phys",
      },
      1,
    );
    expect(clearedFault?.severity).toBe(6);

    const unrelated = normalizeAciFaultEventRow(
      {
        _time: EARLIEST + 180,
        host: "apic-01.dc1.local",
        sourcetype: "cisco:dc:aci:class",
        component: "topSystem",
        dn: "topology/pod-1/node-201/sys",
      },
      2,
    );
    expect(unrelated).toBeUndefined();
  });
});

describe("fixture aggregation, timelines, coverage & config recheck", () => {
  it("loads committed NDJSON fixtures and produces valid ITEM_IDs, KPIs, Matrix, Timeline, and DistributionBar", () => {
    const syslogRows = readFileSync(
      "fixtures/protocols/state_events/nxos_state_syslog.ndjson",
      "utf8",
    )
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as Record<string, unknown>);
    const aciRows = readFileSync(
      "fixtures/protocols/state_events/aci_fault_event.ndjson",
      "utf8",
    )
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as Record<string, unknown>);

    const events = [
      ...syslogRows
        .map((r, i) => normalizeStateSyslogRow(r, i))
        .filter((e): e is NonNullable<typeof e> => Boolean(e))
        .map((event) => ({ event, indexName: "cisco_dc" })),
      ...aciRows
        .map((r, i) => normalizeAciFaultEventRow(r, i))
        .filter((e): e is NonNullable<typeof e> => Boolean(e))
        .map((event) => ({ event, indexName: "cisco_dc" })),
    ];

    // topSystem row from aci_fault_event.ndjson is ignored -> 11 syslog + 3 aci = 14 events
    expect(events).toHaveLength(14);

    const analysis = buildStateEventsAnalysis({
      events,
      thresholds: resolveStateEventsThresholds(makeProfile()),
      earliest: EARLIEST,
      latest: NOW,
      outcomes: [
        {
          source: "protocol_state_events",
          profile: "state-events-dc1",
          state: "complete",
        },
      ],
      capped: false,
    });

    expect(analysis.verdictStatus).toBe("attention");
    expect(analysis.verdict).toContain("14 state changes across 6 devices");
    expect(analysis.kpis).toHaveLength(4);
    expect(analysis.rows.map((r) => r.device)).toEqual([
      "pod-1/node-201",
      "192.0.2.11",
      "leaf-01",
      "leaf-02",
      "spine-01",
      "apic-01",
    ]);
    // First 3 rows are flagged (pod-1/node-201 critical/major, 192.0.2.11 error + burst=5, leaf-01 critical)
    expect(analysis.rows.filter((r) => r.attention)).toHaveLength(3);
    expect(analysis.timelineEvents).toHaveLength(14);
    expect(analysis.matrixCols).toEqual([
      "Link",
      "BGP/OSPF/BFD",
      "STP/LACP",
      "HSRP/VRRP",
      "PIM",
      "ACI Faults",
    ]);
    expect(analysis.distribution.length).toBe(6);

    // Every row ID must pass parseProtocolLink ITEM_ID validation
    for (const row of analysis.rows) {
      const parsed = parseProtocolLink(
        new URLSearchParams({
          p_lens: "state_events",
          p_scope: "prod:dc1",
          p_earliest: String(EARLIEST),
          p_latest: String(NOW),
          p_item: row.id,
        }),
        NOW + 100,
      );
      expect(parsed.item).toBe(row.id);
    }
  });

  it("distinguishes none_observed from unknown when blocked, unavailable, or capped", async () => {
    const emptyComplete = buildStateEventsAnalysis({
      events: [],
      thresholds: resolveStateEventsThresholds(),
      earliest: EARLIEST,
      latest: NOW,
      outcomes: [{ source: "protocol_state_events", state: "complete" }],
      capped: false,
    });
    expect(emptyComplete.verdictStatus).toBe("none_observed");
    expect(emptyComplete.coverageStatus).toBe("none_observed");
    expect(emptyComplete.bannerState).toBe("empty");

    const emptyBlocked = buildStateEventsAnalysis({
      events: [],
      thresholds: resolveStateEventsThresholds(),
      earliest: EARLIEST,
      latest: NOW,
      outcomes: [
        {
          source: "protocol_state_events",
          state: "blocked",
          detail: "Access denied",
        },
      ],
      capped: false,
    });
    expect(emptyBlocked.verdictStatus).toBe("unknown");
    expect(emptyBlocked.coverageStatus).toBe("unknown");
    expect(emptyBlocked.bannerState).toBe("blocked");

    const emptyCapped = buildStateEventsAnalysis({
      events: [],
      thresholds: resolveStateEventsThresholds(),
      earliest: EARLIEST,
      latest: NOW,
      outcomes: [{ source: "protocol_state_events", state: "partial" }],
      capped: true,
    });
    expect(emptyCapped.verdictStatus).toBe("unknown");
    expect(emptyCapped.bannerState).toBe("partial");

    // Partial multi-source: syslog succeeds with healthy event, ACI faults blocked
    const search = vi
      .fn()
      .mockResolvedValueOnce({
        rows: [
          {
            _time: EARLIEST + 60,
            host: "leaf-02.dc1.local",
            sourcetype: "cisco:ios",
            syslog_msg:
              "%LINK-5-CHANGED: Interface eth1/1, changed state to up",
          },
        ],
        warnings: [],
        errors: [],
        truncated: false,
      })
      .mockRejectedValueOnce(new SearchAccessDeniedError());

    const spy = vi
      .spyOn(protocolConfigClient, "readProtocolProfileDocument")
      .mockResolvedValue({
        version: 1,
        profiles: [makeProfile()],
      });

    try {
      const summary = await summarizeStateEvents(
        { search },
        makeRequest(),
        makeConfig([makeProfile()]),
        new AbortController().signal,
        { skipConfigRecheck: true },
      );
      expect(summary.status).toBe("attention");
    } finally {
      spy.mockRestore();
    }
  });

  it("triggers stale_config when adm_protocol_profiles fingerprint changes mid-run", async () => {
    const search = vi.fn().mockResolvedValue({
      rows: [],
      warnings: [],
      errors: [],
      truncated: false,
    });
    const spy = vi
      .spyOn(protocolConfigClient, "readProtocolProfileDocument")
      .mockResolvedValue({
        version: 1,
        profiles: [makeProfile({ index: "other_index" })],
      });

    try {
      const res = await investigateStateEvents(
        { search },
        makeRequest(),
        makeConfig([makeProfile()], "stale-fingerprint"),
        new AbortController().signal,
      );
      expect(res.bannerState).toBe("stale_config");
      expect(res.coverageLabel).toBe("Stale config");
    } finally {
      spy.mockRestore();
    }
  });

  it("skips ACI fault queries and ACI syslog sourcetypes when includeAci is false", async () => {
    const search = vi.fn().mockResolvedValue({
      rows: [],
      warnings: [],
      errors: [],
      truncated: false,
    });
    const profile = makeProfile({ extra: { includeAci: false } });
    const res = await investigateStateEvents(
      { search },
      makeRequest(),
      makeConfig([profile]),
      new AbortController().signal,
      { skipConfigRecheck: true },
    );
    expect(search).toHaveBeenCalledTimes(1);
    const spl = search.mock.calls[0][0].search as string;
    expect(spl).toContain('sourcetype="cisco:ios"');
    expect(spl).not.toContain('sourcetype="cisco:aci"');
    expect(spl).not.toContain("faultInst");
    expect(res.includeAci).toBe(false);
    expect(res.verdictStatus).toBe("none_observed");
  });

  it("preserves ACI events from a second profile when profile 1 sets includeAci: false", async () => {
    const profile1 = makeProfile({
      id: "state-syslog-only",
      index: "nxos_idx",
      extra: { sourceKind: "syslog", includeAci: false },
    });
    const profile2 = makeProfile({
      id: "state-aci-faults",
      index: "aci_idx",
      extra: { sourceKind: "aci_faults", includeAci: true },
    });

    const search = vi
      .fn()
      .mockResolvedValueOnce({
        rows: [
          {
            _time: EARLIEST + 60,
            host: "leaf-02.dc1.local",
            sourcetype: "cisco:ios",
            syslog_msg:
              "%LINK-5-CHANGED: Interface eth1/1, changed state to up",
          },
        ],
        warnings: [],
        errors: [],
        truncated: false,
      })
      .mockResolvedValueOnce({
        rows: [
          {
            _time: EARLIEST + 120,
            host: "apic-01.dc1.local",
            sourcetype: "cisco:dc:aci:fault",
            component: "faultInst",
            code: "F0546",
            severity: "critical",
            domain: "infra",
            affected: "topology/pod-1/node-201/sys/phys-[eth1/1]/phys",
            descr: "Port eth1/1 is operationally down",
          },
        ],
        warnings: [],
        errors: [],
        truncated: false,
      });

    const res = await investigateStateEvents(
      { search },
      makeRequest(),
      makeConfig([profile1, profile2]),
      new AbortController().signal,
      { skipConfigRecheck: true },
    );
    expect(search).toHaveBeenCalledTimes(2);
    expect(res.includeAci).toBe(true);
    expect(res.sourceMode).toBe("syslog_and_aci_faults");
    expect(res.rows.map((r) => r.device)).toContain("pod-1/node-201");
    expect(res.rows.map((r) => r.device)).toContain("leaf-02");
  });

  it("reports unknown (never none_observed) when returned rows could not be normalized", async () => {
    const search = vi.fn().mockResolvedValue({
      rows: [
        {
          _time: EARLIEST + 60,
          host: "leaf-01.dc1.local",
          sourcetype: "cisco:ios",
          syslog_msg: "unstructured log without mnemonic",
        },
        {
          _time: EARLIEST + 90,
          host: "leaf-02.dc1.local",
          sourcetype: "cisco:dc:nexus9k:syslog",
        },
      ],
      warnings: [],
      errors: [],
      truncated: false,
    });

    const res = await investigateStateEvents(
      { search },
      makeRequest({ filter: undefined }),
      makeConfig([makeProfile({ extra: { sourceKind: "syslog" } })]),
      new AbortController().signal,
      { skipConfigRecheck: true },
    );
    expect(res.verdictStatus).toBe("unknown");
    expect(res.coverageStatus).toBe("unknown");
    expect(res.bannerState).toBe("unavailable");
    expect(res.bannerReason).toBe(
      "2 rows returned but could not be normalized.",
    );
    expect(res.verdict).toBe("2 rows returned but could not be normalized.");
  });

  it("pushes canonical interface variants before head and matches Ethernet1/1 without matching Ethernet1/10", async () => {
    const syslogSpl = buildStateSyslogSearch({
      index: "cisco_dc",
      filter: { device: "leaf-01", iface: "eth1/1" },
      maxRows: 256,
    });
    expect(syslogSpl).toContain('"eth1/1"');
    expect(syslogSpl).toContain('"Ethernet1/1"');
    expect(syslogSpl.indexOf('"Ethernet1/1"')).toBeLessThan(
      syslogSpl.indexOf("| head"),
    );

    const aciSpl = buildAciFaultEventSearch({
      index: "cisco_dc",
      filter: { iface: "eth1/1" },
      maxRows: 256,
    });
    expect(aciSpl).toContain('dn="*[eth1/1]*"');
    expect(aciSpl.indexOf('dn="*[eth1/1]*"')).toBeLessThan(
      aciSpl.indexOf("| head"),
    );

    const search = vi.fn().mockResolvedValue({
      rows: [
        {
          _time: EARLIEST + 60,
          host: "leaf-01.dc1.local",
          sourcetype: "cisco:dc:nexus9k:syslog",
          mnemonic: "ETHPORT-3-IF_DOWN_LINK_FAILURE",
          facility: "ETHPORT",
          severity: "3",
          interface: "Ethernet1/1",
          syslog_msg: "Interface Ethernet1/1 is down (Link failure)",
        },
        {
          _time: EARLIEST + 90,
          host: "leaf-01.dc1.local",
          sourcetype: "cisco:dc:nexus9k:syslog",
          mnemonic: "ETHPORT-3-IF_DOWN_LINK_FAILURE",
          facility: "ETHPORT",
          severity: "3",
          interface: "Ethernet1/10",
          syslog_msg: "Interface Ethernet1/10 is down (Link failure)",
        },
      ],
      warnings: [],
      errors: [],
    });

    const res = await investigateStateEvents(
      { search },
      makeRequest({ filter: { iface: "eth1/1" } }),
      makeConfig([makeProfile({ extra: { sourceKind: "syslog" } })]),
      new AbortController().signal,
      { skipConfigRecheck: true },
    );
    expect(res.rows).toHaveLength(1);
    expect(res.rows[0].eventCount).toBe(1);
    expect(res.rows[0].transitions[0].interfaceOrDn).toBe("Ethernet1/1");
  });

  it("scopes _index_earliest only to nexus9k:dme faults and dedupes repeated polled NX-OS faults", async () => {
    const spl = buildAciFaultEventSearch({
      index: "cisco_dc",
      maxRows: 256,
      earliest: EARLIEST,
      latest: NOW,
    });
    expect(spl).toContain(
      `sourcetype="cisco:dc:aci:fault" OR sourcetype="cisco:dc:aci:event"`,
    );
    expect(spl).toContain(`earliest=${EARLIEST} latest=${NOW}`);
    expect(spl).toContain(
      `sourcetype="cisco:dc:nexus9k:dme" (component="faultInst" OR component="eventRecord") ((earliest=${EARLIEST} latest=${NOW}) OR (_index_earliest=${EARLIEST} _index_latest=${NOW}))`,
    );
    expect(spl.indexOf("| dedup ")).toBeGreaterThan(-1);
    expect(spl.indexOf("| dedup ")).toBeLessThan(spl.indexOf("| head 257"));

    const repeatedFault = {
      _time: EARLIEST - 86400,
      host: "198.18.131.4",
      sourcetype: "cisco:dc:nexus9k:dme",
      component: "faultInst",
      dn: "sys/intf/encrtd-[spo512.10]/rtvrfMbr/fault-F1680",
      code: "F1680",
      severity: "warning",
      lifecycle: "raised",
      cause: "config-failure",
      descr: "RtVrfMbr configuration failure.",
    };
    const search = vi.fn().mockResolvedValue({
      rows: [repeatedFault, repeatedFault, repeatedFault],
      warnings: [],
      errors: [],
    });

    const res = await investigateStateEvents(
      { search },
      makeRequest(),
      makeConfig([makeProfile({ extra: { sourceKind: "aci_faults" } })]),
      new AbortController().signal,
      { skipConfigRecheck: true },
    );
    expect(res.rows).toHaveLength(1);
    expect(res.rows[0].eventCount).toBe(1);
    expect(res.rows[0].transitions[0].domainLabel).toBe("NX-OS Faults");
  });
});
