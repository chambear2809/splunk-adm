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
  buildInterfaceDmeSearch,
  buildInterfaceHealthAnalysis,
  buildInterfaceRawEventsUrl,
  buildInterfaceSyslogSearch,
  investigateInterfaceHealth,
  normalizeInterfaceDmeRow,
  normalizeInterfaceSyslogRow,
  resolveInterfaceHealthThresholds,
  summarizeInterfaceHealth,
  validateInterfaceHealthExtra,
} from "./adapter";

const NOW = 1800000500;
const EARLIEST = 1800000000;

function makeProfile(
  overrides: Partial<BaseProtocolProfile> = {},
): BaseProtocolProfile {
  return {
    id: "intf-dc1",
    source: "protocol_interface_health",
    lens: "interface_health",
    scope: "prod:dc1",
    index: "cisco_dc",
    observer: "n9k-dme-01",
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
    lens: "interface_health",
    scope: "prod:dc1",
    earliest: EARLIEST,
    latest: NOW,
    ...overrides,
  };
}

describe("validateInterfaceHealthExtra (fail-closed profile validation)", () => {
  it("accepts valid extra thresholds and sourceKind and integrates with parseProtocolProfiles", () => {
    expect(validateInterfaceHealthExtra(undefined)).toBeUndefined();
    expect(
      validateInterfaceHealthExtra({
        sourceKind: "dme",
        errorWarnCount: 5,
        discardWarnCount: 25,
        flapWarnCount: 3,
        utilizationWarnPct: 75.5,
      }),
    ).toEqual({
      sourceKind: "dme",
      errorWarnCount: 5,
      discardWarnCount: 25,
      flapWarnCount: 3,
      utilizationWarnPct: 75.5,
    });

    const profiles = parseProtocolProfiles(
      {
        version: 1,
        profiles: [
          {
            id: "intf-dc1",
            source: "protocol_interface_health",
            lens: "interface_health",
            scope: "prod:dc1",
            index: "cisco_dc",
            observer: "n9k-dme-01",
            validFrom: EARLIEST - 3600,
            validUntil: NOW + 3600,
            extra: { sourceKind: "syslog", flapWarnCount: 4 },
          },
        ],
      },
      { interface_health: validateInterfaceHealthExtra },
    );
    expect(resolveInterfaceHealthThresholds(profiles[0])).toEqual({
      sourceKind: "syslog",
      errorWarnCount: 1,
      discardWarnCount: 10,
      flapWarnCount: 4,
      utilizationWarnPct: 80,
    });
  });

  it("rejects unknown keys and out-of-bounds values", () => {
    expect(() => validateInterfaceHealthExtra({ unknownKey: true })).toThrow(
      /Unsupported interface_health/,
    );
    expect(() =>
      validateInterfaceHealthExtra({ sourceKind: "snmp" as any }),
    ).toThrow(/sourceKind/);
    expect(() => validateInterfaceHealthExtra({ errorWarnCount: 0 })).toThrow(
      /errorWarnCount/,
    );
    expect(() =>
      validateInterfaceHealthExtra({ errorWarnCount: 1_000_001 }),
    ).toThrow(/errorWarnCount/);
    expect(() => validateInterfaceHealthExtra({ errorWarnCount: 1.5 })).toThrow(
      /errorWarnCount/,
    );
    expect(() => validateInterfaceHealthExtra({ discardWarnCount: 0 })).toThrow(
      /discardWarnCount/,
    );
    expect(() =>
      validateInterfaceHealthExtra({ discardWarnCount: 1_000_001 }),
    ).toThrow(/discardWarnCount/);
    expect(() => validateInterfaceHealthExtra({ flapWarnCount: 0 })).toThrow(
      /flapWarnCount/,
    );
    expect(() => validateInterfaceHealthExtra({ flapWarnCount: 1001 })).toThrow(
      /flapWarnCount/,
    );
    expect(() =>
      validateInterfaceHealthExtra({ utilizationWarnPct: 0 }),
    ).toThrow(/utilizationWarnPct/);
    expect(() =>
      validateInterfaceHealthExtra({ utilizationWarnPct: 101 }),
    ).toThrow(/utilizationWarnPct/);
    expect(() =>
      validateInterfaceHealthExtra({ utilizationWarnPct: Number.NaN }),
    ).toThrow(/utilizationWarnPct/);
  });
});

describe("buildInterfaceDmeSearch, buildInterfaceSyslogSearch & security guards", () => {
  it("emits head before table for DME and delegates syslog to nxosSyslog", () => {
    const dmeSpl = buildInterfaceDmeSearch({
      index: "cisco_dc",
      filter: { device: "leaf1.dc1.example" },
      maxRows: 256,
    });
    expect(dmeSpl).toContain("index=cisco_dc");
    expect(dmeSpl).toContain('sourcetype="cisco:dc:nexus9k:dme"');
    expect(dmeSpl).toContain('sourcetype="cisco:dc:nd:*"');
    expect(dmeSpl).toContain('host="leaf1.dc1.example"');
    expect(dmeSpl).toContain("| table ");
    expect(dmeSpl).not.toContain("| fields ");
    expect(dmeSpl.indexOf("| head 257")).toBeLessThan(
      dmeSpl.indexOf("| table "),
    );
    expect(() =>
      assertNoForbiddenFieldsInSpl("interface_health", dmeSpl),
    ).not.toThrow();

    const sysSpl = buildInterfaceSyslogSearch({
      index: "cisco_dc",
      device: "leaf1.dc1.example",
      maxRows: 256,
    });
    expect(sysSpl).toContain("index=cisco_dc");
    expect(sysSpl).toContain('sourcetype="cisco:ios"');
    expect(sysSpl).toContain('sourcetype="cisco:dc:nexus9k:syslog"');
    expect(sysSpl).toContain("VSHD_SYSLOG_CONFIG_I");
    expect(sysSpl).toContain("AUTHPRIV");
    expect(sysSpl).toContain("| head 257");
    expect(() =>
      assertNoForbiddenFieldsInSpl("interface_health", sysSpl),
    ).not.toThrow();

    for (const forbidden of FORBIDDEN_SENSITIVE_FIELDS) {
      expect(dmeSpl.toLowerCase()).not.toMatch(
        new RegExp(`\\b${forbidden}\\b`),
      );
      expect(sysSpl.toLowerCase()).not.toMatch(
        new RegExp(`\\b${forbidden}\\b`),
      );
    }
  });

  it("rejects SPL injection in filters and raw-events link builder", () => {
    expect(() =>
      buildInterfaceDmeSearch({
        index: "cisco_dc",
        filter: { device: 'leaf1" OR "1"="1' },
        maxRows: 256,
      }),
    ).toThrow(/Invalid literal/);

    const safeUrl = buildInterfaceRawEventsUrl({
      index: "cisco_dc",
      device: "leaf1.dc1.example",
      iface: "Ethernet1/49",
      sourceMode: "mixed",
      earliest: EARLIEST,
      latest: NOW,
    });
    expect(safeUrl).toMatch(/^\/app\/splunk_adm\/search\?/);
    expect(safeUrl).toContain("Ethernet1%2F49");

    expect(() =>
      buildInterfaceRawEventsUrl({
        index: "cisco_dc",
        device: "bad host!",
        iface: "Ethernet1/1",
        sourceMode: "dme",
        earliest: EARLIEST,
        latest: NOW,
      }),
    ).toThrow(/Invalid literal/);
  });
});

describe("normalizeInterfaceDmeRow, normalizeInterfaceSyslogRow & buildInterfaceHealthAnalysis", () => {
  it("flags admin=up + oper=down, ignores admin=down + oper=down, and avoids double-counting DME polls", () => {
    const mismatched = normalizeInterfaceDmeRow({
      _time: EARLIEST + 30,
      host: "leaf1.dc1",
      sourcetype: "cisco:dc:nexus9k:dme",
      interface: "Ethernet1/1",
      admin_state: "up",
      oper_state: "down",
      speed: "25G",
      mtu: 9216,
      crc_errors: 0,
      in_errors: 0,
      out_errors: 0,
    })!;
    const adminShut = normalizeInterfaceDmeRow({
      _time: EARLIEST + 30,
      host: "leaf1.dc1",
      sourcetype: "cisco:dc:nexus9k:dme",
      interface: "Ethernet1/2",
      adminSt: "down",
      operSt: "down",
      speed: "10G",
      mtu: 1500,
    })!;
    const poll1 = normalizeInterfaceDmeRow({
      _time: EARLIEST + 30,
      host: "leaf1.dc1",
      sourcetype: "cisco:dc:nexus9k:dme",
      dn: "sys/intf/phys-[eth1/49]",
      admin_state: "up",
      oper_state: "up",
      crc_errors: 20,
      in_errors: 22,
      utilization_pct: 55,
    })!;
    const poll2 = normalizeInterfaceDmeRow({
      _time: EARLIEST + 90,
      host: "leaf1.dc1",
      sourcetype: "cisco:dc:nexus9k:dme",
      dn: "sys/intf/phys-[eth1/49]",
      crc_errors: 42,
      in_errors: 45,
      out_errors: 0,
      utilization_pct: 88,
    })!;

    const analysis = buildInterfaceHealthAnalysis({
      dmeEvents: [
        { event: mismatched, indexName: "cisco_dc" },
        { event: adminShut, indexName: "cisco_dc" },
        { event: poll1, indexName: "cisco_dc" },
        { event: poll2, indexName: "cisco_dc" },
      ],
      syslogEvents: [],
      thresholds: resolveInterfaceHealthThresholds(),
      earliest: EARLIEST,
      latest: NOW,
      outcomes: [{ source: "protocol_interface_health", state: "complete" }],
      capped: false,
    });

    const row1 = analysis.rows.find((r) => r.interface === "Ethernet1/1")!;
    expect(row1.attention).toBe(true);
    expect(row1.adminUpOperDown).toBe(true);
    expect(row1.reasons[0]).toContain("Admin up / Oper down");

    const row2 = analysis.rows.find((r) => r.interface === "Ethernet1/2")!;
    expect(row2.attention).toBe(false);
    expect(row2.status).toBe("ok");

    const row49 = analysis.rows.find((r) => r.interface === "eth1/49")!;
    expect(row49.attention).toBe(true);
    // Uses latest poll (42 CRC, 45 in_errors) rather than summing 20+42 across polls
    expect(row49.crcErrors).toBe(42);
    expect(row49.totalErrors).toBe(87);
    expect(row49.utilizationPct).toBe(88);
    expect(row49.adminState).toBe("up");
    expect(row49.operState).toBe("up");
  });

  it("filters out non-interface and auth/config syslog events and flags ETHPORT/DOM faults", () => {
    const bgp = normalizeInterfaceSyslogRow(
      {
        _time: EARLIEST + 10,
        host: "leaf1",
        sourcetype: "cisco:ios",
        syslog_msg:
          "%BGP-5-ADJCHANGE: neighbor 10.0.0.1 Down - Hold Timer Expired",
      },
      0,
    );
    expect(bgp).toBeUndefined();

    const auth = normalizeInterfaceSyslogRow(
      {
        _time: EARLIEST + 20,
        host: "leaf1",
        sourcetype: "cisco:dc:nexus9k:syslog",
        category: "AUTHPRIV",
        severity_id: "6",
        mnemonics: "LOGIN_SUCCESS",
        syslog_msg: "user admin logged in",
      },
      1,
    );
    expect(auth).toBeUndefined();

    const errEv = normalizeInterfaceSyslogRow(
      {
        _time: EARLIEST + 30,
        host: "leaf1",
        sourcetype: "cisco:ios",
        syslog_msg:
          "%ETHPORT-3-IF_ERROR_VLANS_SUSPENDED: Interface Ethernet1/5 error vlans suspended",
      },
      2,
    )!;
    expect(errEv.interface).toBe("Ethernet1/5");
    expect(errEv.isError).toBe(true);

    const domEv = normalizeInterfaceSyslogRow(
      {
        _time: EARLIEST + 40,
        host: "leaf1",
        sourcetype: "cisco:ios",
        syslog_msg:
          "%TRANSCEIVER-4-DOM_HIGH_RX_POWER_WARN: Interface Ethernet1/6, Rx power high",
      },
      3,
    )!;
    expect(domEv.interface).toBe("Ethernet1/6");
    expect(domEv.isDomWarning).toBe(true);
  });

  it("loads committed DME and syslog NDJSON fixtures and verifies ITEM_ID round-trip", () => {
    const dmeLines = readFileSync(
      "fixtures/protocols/interface_health/dcn_interface_dme.ndjson",
      "utf8",
    )
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as Record<string, unknown>);
    const syslogLines = readFileSync(
      "fixtures/protocols/interface_health/nxos_interface_syslog.ndjson",
      "utf8",
    )
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as Record<string, unknown>);

    const dmeEvents = dmeLines.map((row) => ({
      event: normalizeInterfaceDmeRow(row)!,
      indexName: "cisco_dc",
    }));
    const syslogEvents = syslogLines.map((row, idx) => ({
      event: normalizeInterfaceSyslogRow(row, idx)!,
      indexName: "cisco_dc",
    }));

    expect(dmeEvents.every((e) => Boolean(e.event))).toBe(true);
    expect(syslogEvents.every((e) => Boolean(e.event))).toBe(true);

    const combined = buildInterfaceHealthAnalysis({
      dmeEvents,
      syslogEvents,
      thresholds: resolveInterfaceHealthThresholds(),
      earliest: EARLIEST,
      latest: NOW,
      outcomes: [
        { source: "protocol_interface_health", state: "complete" },
        { source: "protocol_interface_health", state: "complete" },
      ],
      capped: false,
    });

    // 4 DME interfaces + 2 syslog-only interfaces (leaf1 Eth1/10, leaf2 Eth1/12) = 6 rows
    expect(combined.rows).toHaveLength(6);
    expect(combined.sourceMode).toBe("mixed");
    expect(combined.verdictStatus).toBe("attention");
    expect(combined.timelineEvents).toHaveLength(7);

    // Every row ID must round-trip through parseProtocolLink's strict ITEM_ID regex.
    for (const row of combined.rows) {
      const parsed = parseProtocolLink(
        new URLSearchParams({ p_lens: "interface_health", p_item: row.id }),
      );
      expect(parsed.item).toBe(row.id);
    }

    // Syslog-only fixture mode: never fake zeros, never mark benign syslog-only row ok
    const syslogOnly = buildInterfaceHealthAnalysis({
      dmeEvents: [],
      syslogEvents,
      thresholds: resolveInterfaceHealthThresholds(),
      earliest: EARLIEST,
      latest: NOW,
      outcomes: [{ source: "protocol_interface_health", state: "complete" }],
      capped: false,
    });
    expect(syslogOnly.sourceMode).toBe("syslog_only");
    expect(syslogOnly.kpis.find((k) => k.id === "crc-errors")?.value).toBe(
      "Not covered",
    );
    expect(
      syslogOnly.kpis.find((k) => k.id === "peak-utilization")?.value,
    ).toBe("Not covered");

    const benignSyslogRow = syslogOnly.rows.find(
      (r) => r.device === "leaf2.dc1.example" && r.interface === "Ethernet1/10",
    )!;
    expect(benignSyslogRow.status).toBe("not_covered");
    expect(benignSyslogRow.hasCounterCoverage).toBe(false);
    expect(benignSyslogRow.utilizationPct).toBeUndefined();
  });
});

describe("investigateInterfaceHealth (runner, degraded coverage, stale config)", () => {
  it("runs DME and syslog for sourceKind=auto and correlates into unified rows", async () => {
    const search = vi
      .fn()
      .mockResolvedValueOnce({
        rows: [
          {
            _time: EARLIEST + 10,
            host: "leaf1.dc1",
            sourcetype: "cisco:dc:nexus9k:dme",
            interface: "Ethernet1/10",
            admin_state: "up",
            oper_state: "up",
            speed: "25G",
            mtu: 9216,
            crc_errors: 0,
            in_errors: 0,
            out_errors: 0,
            utilization_pct: 42,
          },
        ],
        warnings: [],
        errors: [],
      })
      .mockResolvedValueOnce({
        rows: [
          {
            _time: EARLIEST + 20,
            host: "leaf1.dc1",
            sourcetype: "cisco:ios",
            syslog_msg:
              "%ETHPORT-5-IF_DOWN_LINK_FAILURE: Interface Ethernet1/10 is down",
          },
          {
            _time: EARLIEST + 40,
            host: "leaf1.dc1",
            sourcetype: "cisco:ios",
            syslog_msg:
              "%ETHPORT-5-IF_UP: Interface Ethernet1/10 is up in mode trunk",
          },
        ],
        warnings: [],
        errors: [],
      });

    const result = await investigateInterfaceHealth(
      { search },
      makeRequest(),
      makeConfig([makeProfile()]),
      new AbortController().signal,
      { skipConfigRecheck: true },
    );

    expect(search).toHaveBeenCalledTimes(2);
    expect(result.sourceMode).toBe("mixed");
    expect(result.rows).toHaveLength(1);
    expect(result.rows[0]).toMatchObject({
      device: "leaf1.dc1",
      interface: "Ethernet1/10",
      flapCount: 2,
      attention: true,
      sourceKind: "dme_and_syslog",
    });
  });

  it("treats blocked and unavailable outcomes as degraded coverage (never none_observed or ok)", async () => {
    const blockedZero = await investigateInterfaceHealth(
      {
        search: vi
          .fn()
          .mockRejectedValueOnce(new SearchAccessDeniedError())
          .mockResolvedValueOnce({ rows: [], warnings: [], errors: [] }),
      },
      makeRequest(),
      makeConfig([makeProfile()]),
      new AbortController().signal,
      { skipConfigRecheck: true },
    );
    expect(blockedZero.bannerState).toBe("blocked");
    expect(blockedZero.verdictStatus).toBe("unknown");
    expect(blockedZero.coverageStatus).toBe("unknown");

    const unavailableZero = await investigateInterfaceHealth(
      {
        search: vi
          .fn()
          .mockRejectedValueOnce(new Error("Indexer timeout"))
          .mockResolvedValueOnce({ rows: [], warnings: [], errors: [] }),
      },
      makeRequest(),
      makeConfig([makeProfile()]),
      new AbortController().signal,
      { skipConfigRecheck: true },
    );
    expect(unavailableZero.bannerState).toBe("unavailable");
    expect(unavailableZero.verdictStatus).toBe("unknown");

    const blockedPrimaryWithSyslog = await investigateInterfaceHealth(
      {
        search: vi
          .fn()
          .mockRejectedValueOnce(new SearchAccessDeniedError())
          .mockResolvedValueOnce({
            rows: [
              {
                _time: EARLIEST + 15,
                host: "leaf1.dc1",
                sourcetype: "cisco:ios",
                syslog_msg:
                  "%ETHPORT-5-IF_DOWN_LINK_FAILURE: Interface Ethernet1/1 is down",
              },
            ],
            warnings: [],
            errors: [],
          }),
      },
      makeRequest(),
      makeConfig([makeProfile()]),
      new AbortController().signal,
      { skipConfigRecheck: true },
    );
    expect(blockedPrimaryWithSyslog.bannerState).toBe("partial");
    expect(blockedPrimaryWithSyslog.coverageStatus).toBe("attention");
    expect(blockedPrimaryWithSyslog.bannerReason).toMatch(
      /Primary DME source blocked/i,
    );
  });

  it("handles unconfigured scope without searching and detects stale config", async () => {
    const search = vi.fn().mockResolvedValue({
      rows: [
        {
          _time: EARLIEST + 10,
          host: "leaf1.dc1",
          sourcetype: "cisco:dc:nexus9k:dme",
          interface: "Ethernet1/1",
          admin_state: "up",
          oper_state: "up",
          crc_errors: 0,
          _raw: "should be stripped",
          password: "secret",
        },
      ],
      warnings: [],
      errors: [],
    });
    const client: SearchClient = { search };

    const unconfigured = await investigateInterfaceHealth(
      client,
      makeRequest({ scope: "prod:other" }),
      makeConfig([makeProfile({ scope: "prod:dc1" })]),
      new AbortController().signal,
      { skipConfigRecheck: true },
    );
    expect(search).not.toHaveBeenCalled();
    expect(unconfigured.bannerState).toBe("unavailable");
    expect(unconfigured.coverageStatus).toBe("not_covered");

    const spy = vi
      .spyOn(protocolConfigClient, "readProtocolProfileDocument")
      .mockResolvedValue({
        version: 1,
        profiles: [makeProfile({ extra: { sourceKind: "dme" } })],
      });
    try {
      const config = await import("../../shared/runner").then((m) =>
        m.readProtocolConfiguration({
          interface_health: validateInterfaceHealthExtra,
        }),
      );
      const summary = await summarizeInterfaceHealth(
        client,
        makeRequest(),
        config,
        new AbortController().signal,
      );
      expect(summary.status).toBe("ok");

      spy.mockResolvedValueOnce({
        version: 1,
        profiles: [
          makeProfile({ index: "other_index", extra: { sourceKind: "dme" } }),
        ],
      });
      const stale = await investigateInterfaceHealth(
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

  it("includes every classified IOS and NX-OS interface syslog category in SPL", () => {
    const spl = buildInterfaceSyslogSearch({
      index: "cisco_dc",
      maxRows: 256,
    });
    for (const cat of [
      "ETHPORT",
      "ETH_PORT",
      "LINK",
      "LINEPROTO",
      "TRANSCEIVER",
      "SFP",
      "DOM",
      "ETH_PORT_CHANNEL",
      "PM",
    ]) {
      expect(spl).toContain(`"${cat}"`);
    }
  });
});
