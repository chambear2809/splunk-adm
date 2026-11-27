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
  assertNoForbiddenFieldsInSpl,
} from "../../shared/fields";
import {
  buildRoutingAnalysis,
  buildRoutingDmeSearch,
  buildRoutingRawEventsUrl,
  buildRoutingSyslogSearch,
  investigateRouting,
  normalizeRoutingDmeRow,
  normalizeRoutingSyslogRow,
  resolveRoutingThresholds,
  summarizeRouting,
  validateRoutingExtra,
} from "./adapter";

const NOW = 1764248400;
const EARLIEST = 1764246600;

function makeProfile(
  overrides: Partial<BaseProtocolProfile> = {},
): BaseProtocolProfile {
  return {
    id: "routing-dc1",
    source: "protocol_routing",
    lens: "routing",
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
  fingerprint = "fp-routing-initial",
): ProtocolConfiguration {
  return { profiles, fingerprint };
}

function makeRequest(
  overrides: Partial<ProtocolRequest> = {},
): ProtocolRequest {
  return {
    version: 1,
    lens: "routing",
    scope: "prod:dc1",
    earliest: EARLIEST,
    latest: NOW,
    ...overrides,
  };
}

describe("validateRoutingExtra (fail-closed profile validation)", () => {
  it("accepts valid extra options and integrates with parseProtocolProfiles", () => {
    expect(validateRoutingExtra(undefined)).toBeUndefined();
    expect(
      validateRoutingExtra({
        sourceKind: "syslog",
        flapWarnCount: 4,
        protocolFilter: "bgp",
      }),
    ).toEqual({
      sourceKind: "syslog",
      flapWarnCount: 4,
      protocolFilter: "bgp",
    });

    const profiles = parseProtocolProfiles(
      {
        version: 1,
        profiles: [
          {
            id: "routing-dc1",
            source: "protocol_routing",
            lens: "routing",
            scope: "prod:dc1",
            index: "cisco_dc",
            observer: "sc4s-dc1",
            validFrom: EARLIEST - 3600,
            validUntil: NOW + 3600,
            extra: { flapWarnCount: 3, protocolFilter: "ospf" },
          },
        ],
      },
      { routing: validateRoutingExtra },
    );
    expect(resolveRoutingThresholds(profiles[0])).toEqual({
      sourceKind: "auto",
      flapWarnCount: 3,
      protocolFilter: "ospf",
    });
  });

  it("rejects unknown keys and out-of-bounds values", () => {
    expect(() => validateRoutingExtra({ unknownKey: true })).toThrow(
      /Unsupported routing/,
    );
    expect(() =>
      validateRoutingExtra({ sourceKind: "netflow" as any }),
    ).toThrow(/sourceKind/);
    expect(() => validateRoutingExtra({ flapWarnCount: 0 })).toThrow(
      /flapWarnCount/,
    );
    expect(() => validateRoutingExtra({ flapWarnCount: 1001 })).toThrow(
      /flapWarnCount/,
    );
    expect(() => validateRoutingExtra({ flapWarnCount: 2.5 })).toThrow(
      /flapWarnCount/,
    );
    expect(() =>
      validateRoutingExtra({ protocolFilter: "isis" as any }),
    ).toThrow(/protocolFilter/);
  });
});

describe("buildRoutingDmeSearch & buildRoutingSyslogSearch & guards", () => {
  it("builds bounded allowlisted SPL for DME with head before table", () => {
    const spl = buildRoutingDmeSearch({
      index: "cisco_dc",
      filter: { device: "leaf1.dc1", dst: "10.255.0.2" },
      maxRows: 256,
    });
    expect(spl).toContain("index=cisco_dc");
    expect(spl).toContain('sourcetype="cisco:dc:nexus9k:dme"');
    expect(spl).toContain('sourcetype="cisco:dc:nd:*"');
    expect(spl).toContain('(host="leaf1.dc1" OR device="leaf1.dc1"');
    expect(spl).toContain('peer_ip="10.255.0.2"');
    expect(spl).toContain("| head 257");
    expect(spl).toContain("| table ");
    expect(spl).not.toContain("| fields ");
    expect(spl.indexOf("| head 257")).toBeLessThan(spl.indexOf("| table "));
    expect(() => assertNoForbiddenFieldsInSpl("routing", spl)).not.toThrow();

    for (const forbidden of FORBIDDEN_SENSITIVE_FIELDS) {
      expect(spl.toLowerCase()).not.toMatch(new RegExp(`\\b${forbidden}\\b`));
    }
  });

  it("delegates syslog query to shared nxosSyslog adapter without leaking auth/config", () => {
    const spl = buildRoutingSyslogSearch({
      index: "cisco_dc",
      filter: { device: "leaf1.dc1" },
      maxRows: 256,
    });
    expect(spl).toContain("index=cisco_dc");
    expect(spl).toContain('sourcetype="cisco:ios"');
    expect(spl).toContain('sourcetype="cisco:aci"');
    expect(spl).toContain('sourcetype="cisco:dc:nexus9k:syslog"');
    expect(spl).toContain('sourcetype="cisco:dc:aci:syslog"');
    expect(spl).toContain('host="leaf1.dc1"');
    expect(spl).toContain("CFGLOG_LOGGEDCMD");
    expect(spl).toContain("AUTHPRIV");
    expect(spl).not.toContain("_raw");
    expect(() => assertNoForbiddenFieldsInSpl("routing", spl)).not.toThrow();
  });

  it("rejects SPL injection in filters and raw-events link builder", () => {
    expect(() =>
      buildRoutingDmeSearch({
        index: "cisco_dc",
        filter: { device: 'leaf1" OR "1"="1' },
        maxRows: 256,
      }),
    ).toThrow(/Invalid literal/);

    const safeUrl = buildRoutingRawEventsUrl({
      index: "cisco_dc",
      device: "leaf1.dc1",
      peerIp: "10.255.0.2",
      sourceCoverage: "syslog_and_dme",
      earliest: EARLIEST,
      latest: NOW,
    });
    expect(safeUrl).toMatch(/^\/app\/splunk_adm\/search\?/);
    expect(safeUrl).toContain("cisco%3Adc%3Anexus9k%3Adme");

    expect(() =>
      buildRoutingRawEventsUrl({
        index: "cisco_dc",
        device: "bad host!",
        peerIp: "10.255.0.2",
        sourceCoverage: "syslog_only",
        earliest: EARLIEST,
        latest: NOW,
      }),
    ).toThrow(/Invalid literal/);
  });
});

describe("normalizeRoutingSyslogRow, normalizeRoutingDmeRow & buildRoutingAnalysis", () => {
  it("parses BGP, OSPF, and BFD syslog rows and ignores non-routing/auth rows", () => {
    const bgp = normalizeRoutingSyslogRow(
      {
        _time: EARLIEST + 60,
        host: "leaf1.dc1",
        sourcetype: "cisco:ios",
        syslog_msg:
          "%BGP-5-ADJCHANGE: bgp-65001 [vrf-prod] neighbor 10.255.0.2 Down - Hold Timer Expired",
      },
      0,
    )!;
    expect(bgp).toMatchObject({
      protocol: "BGP",
      device: "leaf1.dc1",
      vrf: "vrf-prod",
      peerIp: "10.255.0.2",
      localAsn: 65001,
      stateLabel: "Down",
      isDown: true,
      isTransition: true,
    });

    const ospf = normalizeRoutingSyslogRow(
      {
        _time: EARLIEST + 120,
        host: "leaf2.dc1",
        sourcetype: "cisco:dc:nexus9k:syslog",
        category: "OSPF",
        severity_id: "5",
        mnemonics: "ADJCHG",
        syslog_msg:
          "Process 100, Nbr 10.255.0.3 on Ethernet1/2 from LOADING to FULL, Loading Done",
        interface: "Ethernet1/2",
        neighbor_ip: "10.255.0.3",
      },
      1,
    )!;
    expect(ospf).toMatchObject({
      protocol: "OSPF",
      peerIp: "10.255.0.3",
      stateLabel: "Full",
      isDown: false,
      iface: "Ethernet1/2",
    });

    const bfdDown = normalizeRoutingSyslogRow(
      {
        _time: EARLIEST + 180,
        host: "leaf1.dc1",
        sourcetype: "cisco:ios",
        syslog_msg:
          "%BFD-5-SESSION_STATE_DOWN: BFD session 1090519041 to neighbor 10.255.0.2 on interface Ethernet1/1 has gone down",
      },
      2,
    )!;
    expect(bfdDown).toMatchObject({
      protocol: "BFD",
      peerIp: "10.255.0.2",
      stateLabel: "Down",
      isDown: true,
      iface: "Ethernet1/1",
    });

    const ethport = normalizeRoutingSyslogRow(
      {
        _time: EARLIEST + 200,
        host: "leaf1.dc1",
        sourcetype: "cisco:dc:nexus9k:syslog",
        category: "ETHPORT",
        severity_id: "5",
        mnemonics: "IF_DOWN_LINK_FAILURE",
        syslog_msg: "Interface Ethernet1/10 is down",
      },
      3,
    );
    expect(ethport).toBeUndefined();

    const nonRoutingDme = normalizeRoutingDmeRow(
      {
        _time: EARLIEST + 200,
        host: "leaf1.dc1",
        sourcetype: "cisco:dc:nexus9k:dme",
        dn: "sys/intf/phys-[eth1/1]",
        operSt: "up",
      },
      0,
    );
    expect(nonRoutingDme).toBeUndefined();
  });

  it("loads committed NDJSON fixtures, merges syslog + DME, and passes ITEM_ID validation", () => {
    const syslogRows = readFileSync(
      "fixtures/protocols/routing/nxos_routing_syslog.ndjson",
      "utf8",
    )
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as Record<string, unknown>);
    const dmeRows = readFileSync(
      "fixtures/protocols/routing/dcn_bgp_dme.ndjson",
      "utf8",
    )
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as Record<string, unknown>);

    const events = [
      ...syslogRows
        .map((r, i) => normalizeRoutingSyslogRow(r, i))
        .filter((e): e is NonNullable<typeof e> => Boolean(e))
        .map((event) => ({ event, indexName: "cisco_dc" })),
      ...dmeRows
        .map((r, i) => normalizeRoutingDmeRow(r, i))
        .filter((e): e is NonNullable<typeof e> => Boolean(e))
        .map((event) => ({ event, indexName: "cisco_dc" })),
    ];

    const analysis = buildRoutingAnalysis({
      events,
      thresholds: resolveRoutingThresholds(),
      earliest: EARLIEST,
      latest: NOW,
      outcomes: [{ source: "protocol_routing", state: "complete" }],
      capped: false,
    });

    expect(analysis.sourceMode).toBe("syslog_and_dme");
    expect(analysis.rows).toHaveLength(5);
    expect(analysis.rows.filter((r) => r.attention)).toHaveLength(3);
    expect(analysis.kpis.map((k) => k.label)).toEqual([
      "Down Sessions",
      "Total Flaps",
      "Tracked Sessions",
      "Affected Devices",
    ]);
    expect(analysis.kpis.find((k) => k.id === "down-peers")?.value).toBe("2");
    expect(analysis.kpis.find((k) => k.id === "affected-devices")?.value).toBe(
      "2",
    );
    expect(analysis.timelineEvents.length).toBe(8);
    expect(analysis.adjacencyNodes.length).toBeGreaterThanOrEqual(7);
    expect(analysis.adjacencyEdges).toHaveLength(5);

    const bgpDown = analysis.rows.find(
      (r) =>
        r.device === "leaf1.dc1" &&
        r.protocol === "BGP" &&
        r.peerIp === "10.255.0.2",
    )!;
    expect(bgpDown).toMatchObject({
      attention: true,
      isDown: true,
      currentState: "Active",
      flapCount: 3,
      peerAsn: 65002,
      localAsn: 65001,
      prefixesReceived: 0,
      sourceCoverage: "syslog_and_dme",
    });

    const spineHealthy = analysis.rows.find(
      (r) => r.device === "spine1.dc1" && r.peerIp === "10.255.0.10",
    )!;
    expect(spineHealthy).toMatchObject({
      attention: false,
      isDown: false,
      currentState: "Established",
      prefixesReceived: 4820,
    });

    // Ensure HeatMatrix cell for (leaf1.dc1, 10.255.0.2) remains attention even with multiple protocols.
    const leaf1Cell = analysis.matrixCells.find(
      (c) => c.row === "leaf1.dc1" && c.col === "10.255.0.2",
    )!;
    expect(leaf1Cell.status).toBe("attention");

    for (const row of analysis.rows) {
      expect(row.id).not.toContain("->");
      const parsed = parseProtocolLink(
        new URLSearchParams({ p_lens: "routing", p_item: row.id }),
      );
      expect(parsed.item).toBe(row.id);
    }
  });

  it("marks prefixesReceived undefined (Not covered) when syslog-only", () => {
    const syslogRows = readFileSync(
      "fixtures/protocols/routing/nxos_routing_syslog.ndjson",
      "utf8",
    )
      .trim()
      .split("\n")
      .map((line) => JSON.parse(line) as Record<string, unknown>);
    const events = syslogRows
      .map((r, i) => normalizeRoutingSyslogRow(r, i))
      .filter((e): e is NonNullable<typeof e> => Boolean(e))
      .map((event) => ({ event, indexName: "cisco_dc" }));

    const analysis = buildRoutingAnalysis({
      events,
      thresholds: resolveRoutingThresholds(),
      earliest: EARLIEST,
      latest: NOW,
      outcomes: [{ source: "protocol_routing", state: "complete" }],
      capped: false,
    });
    expect(analysis.sourceMode).toBe("syslog_only");
    expect(analysis.rows.every((r) => r.prefixesReceived === undefined)).toBe(
      true,
    );
  });
});

describe("investigateRouting (runner, degraded coverage, security)", () => {
  it("runs syslog and DME for sourceKind=auto and honors syslog/dme restrictions", async () => {
    const search = vi.fn().mockResolvedValue({
      rows: [],
      warnings: [],
      errors: [],
    });
    await investigateRouting(
      { search },
      makeRequest(),
      makeConfig([makeProfile()]),
      new AbortController().signal,
      { skipConfigRecheck: true },
    );
    expect(search).toHaveBeenCalledTimes(2);
    expect(search.mock.calls[0][0].search).toContain('sourcetype="cisco:ios"');
    expect(search.mock.calls[1][0].search).toContain(
      'sourcetype="cisco:dc:nexus9k:dme"',
    );

    const syslogOnly = vi.fn().mockResolvedValue({
      rows: [],
      warnings: [],
      errors: [],
    });
    await investigateRouting(
      { search: syslogOnly },
      makeRequest(),
      makeConfig([makeProfile({ extra: { sourceKind: "syslog" } })]),
      new AbortController().signal,
      { skipConfigRecheck: true },
    );
    expect(syslogOnly).toHaveBeenCalledTimes(1);
    expect(syslogOnly.mock.calls[0][0].search).toContain(
      'sourcetype="cisco:ios"',
    );
  });

  it("treats blocked/unavailable outcomes as degraded coverage (never none_observed or ok)", async () => {
    const deniedEmpty = await investigateRouting(
      { search: vi.fn().mockRejectedValue(new SearchAccessDeniedError()) },
      makeRequest(),
      makeConfig([makeProfile({ extra: { sourceKind: "dme" } })]),
      new AbortController().signal,
      { skipConfigRecheck: true },
    );
    expect(deniedEmpty.bannerState).toBe("blocked");
    expect(deniedEmpty.verdictStatus).toBe("unknown");
    expect(deniedEmpty.coverageStatus).toBe("unknown");

    const partialWithBlockedDme = await investigateRouting(
      {
        search: vi
          .fn()
          .mockResolvedValueOnce({
            rows: [
              {
                _time: String(EARLIEST + 60),
                host: "spine1.dc1",
                sourcetype: "cisco:ios",
                category: "BGP",
                severity_id: "5",
                mnemonics: "ADJCHANGE",
                syslog_msg: "bgp-65000 [default] neighbor 10.255.0.10 Up",
              },
            ],
            warnings: [],
            errors: [],
          })
          .mockRejectedValueOnce(new SearchAccessDeniedError()),
      },
      makeRequest(),
      makeConfig([makeProfile()]),
      new AbortController().signal,
      { skipConfigRecheck: true },
    );
    expect(partialWithBlockedDme.bannerState).toBe("partial");
    expect(partialWithBlockedDme.coverageStatus).toBe("attention");
    expect(partialWithBlockedDme.bannerReason).toMatch(/denied access/i);

    const failedEmpty = await investigateRouting(
      { search: vi.fn().mockRejectedValue(new Error("Search timed out")) },
      makeRequest(),
      makeConfig([makeProfile({ extra: { sourceKind: "dme" } })]),
      new AbortController().signal,
      { skipConfigRecheck: true },
    );
    expect(failedEmpty.bannerState).toBe("unavailable");
    expect(failedEmpty.verdictStatus).toBe("unknown");
  });

  it("handles unconfigured scope without searching", async () => {
    const search = vi.fn();
    const res = await investigateRouting(
      { search },
      makeRequest({ scope: "prod:other" }),
      makeConfig([makeProfile({ scope: "prod:dc1" })]),
      new AbortController().signal,
      { skipConfigRecheck: true },
    );
    expect(search).not.toHaveBeenCalled();
    expect(res.bannerState).toBe("unavailable");
    expect(res.coverageStatus).toBe("not_covered");
  });

  it("strips sensitive fields and detects stale config via protocolConfigClient", async () => {
    const search = vi.fn().mockResolvedValue({
      rows: [
        {
          _time: String(EARLIEST + 60),
          host: "spine1.dc1",
          sourcetype: "cisco:dc:nexus9k:dme",
          dn: "sys/bgp/inst/dom-default/peer-[10.255.0.10]/ent-[10.255.0.10]",
          peer_ip: "10.255.0.10",
          operSt: "established",
          protocol: "BGP",
          password: "bgp-md5-secret-should-be-stripped",
          _raw: "raw-should-be-stripped",
        },
      ],
      warnings: [],
      errors: [],
    });

    const spy = vi
      .spyOn(protocolConfigClient, "readProtocolProfileDocument")
      .mockResolvedValue({
        version: 1,
        profiles: [makeProfile({ extra: { sourceKind: "dme" } })],
      });
    try {
      const config = await import("../../shared/runner").then((m) =>
        m.readProtocolConfiguration({ routing: validateRoutingExtra }),
      );
      const summary = await summarizeRouting(
        { search },
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
      const stale = await investigateRouting(
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

  it("never reports none_observed when a capped search returns 257 non-matching rows", async () => {
    const nonMatchingRows = Array.from({ length: 257 }, (_, i) => ({
      _time: String(EARLIEST + i),
      host: "leaf1.dc1",
      sourcetype: "cisco:dc:nexus9k:syslog",
      category: "ETHPORT",
      severity_id: "5",
      mnemonics: "IF_UP",
      syslog_msg: "Interface Ethernet1/1 is up",
    }));
    const res = await investigateRouting(
      {
        search: vi.fn().mockResolvedValue({
          rows: nonMatchingRows,
          warnings: [],
          errors: [],
        }),
      },
      makeRequest(),
      makeConfig([makeProfile({ extra: { sourceKind: "syslog" } })]),
      new AbortController().signal,
      { skipConfigRecheck: true },
    );
    expect(res.capped).toBe(true);
    expect(res.verdictStatus).toBe("unknown");
    expect(res.bannerState).toBe("partial");
  });
});
