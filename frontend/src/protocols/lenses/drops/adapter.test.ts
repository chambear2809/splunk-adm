import { readFileSync } from "node:fs";
import { afterEach, describe, expect, it, vi } from "vitest";
import { protocolConfigClient } from "../../../data/evidenceConfig";
import {
  SearchAccessDeniedError,
  type SearchClient,
} from "../../../data/searchClient";
import type {
  BaseProtocolProfile,
  ProtocolConfiguration,
  ProtocolRequest,
} from "../../shared/contract";
import {
  assertNoForbiddenFieldsInSpl,
  LENS_FIELD_ALLOWLISTS,
  projectRowToLensAllowlist,
} from "../../shared/fields";
import {
  buildDropsAciSearch,
  buildDropsAnalysis,
  buildDropsFirewallSearch,
  buildDropsFtdSearch,
  buildDropsHubbleSearch,
  buildDropsNdSearch,
  buildDropsRawEventsUrl,
  investigateDrops,
  makeDropRowId,
  normalizeDropsRow,
  resolveDropsThresholds,
  shortenDeviceLabel,
  summarizeDrops,
  validateDropsExtra,
} from "./index";

const EARLIEST = 1791373700;
const LATEST = 1791374500;

function makeProfile(
  overrides: Partial<BaseProtocolProfile> = {},
): BaseProtocolProfile {
  return {
    id: "drops-dc1",
    source: "protocol_drops",
    lens: "drops",
    scope: "prod:dc1",
    index: "cisco_secure_fw",
    observer: "ftd-edge",
    validFrom: EARLIEST - 3600,
    validUntil: LATEST + 3600,
    ...overrides,
  };
}

function makeRequest(
  overrides: Partial<ProtocolRequest> = {},
): ProtocolRequest {
  return {
    version: 1,
    lens: "drops",
    scope: "prod:dc1",
    earliest: EARLIEST,
    latest: LATEST,
    ...overrides,
  };
}

function loadNdjsonEvents(relPath: string): Record<string, unknown>[] {
  return readFileSync(relPath, "utf8")
    .trim()
    .split("\n")
    .map((line) => {
      const env = JSON.parse(line) as {
        time: number;
        host: string;
        sourcetype: string;
        event: Record<string, unknown>;
      };
      return {
        _time: env.time,
        host: env.host,
        sourcetype: env.sourcetype,
        ...env.event,
      };
    });
}

describe("validateDropsExtra", () => {
  it("accepts valid configuration and rejects unknown keys or out-of-range values", () => {
    expect(validateDropsExtra(undefined)).toBeUndefined();
    expect(
      validateDropsExtra({
        sourceKind: "ftd",
        sourcetype: "cisco:sfw:estreamer",
        dropWarnCount: 5,
      }),
    ).toEqual({
      sourceKind: "ftd",
      sourcetype: "cisco:sfw:estreamer",
      dropWarnCount: 5,
    });

    expect(() => validateDropsExtra({ unknownKey: true })).toThrow(
      /Unsupported drops profile extra configuration key/,
    );
    expect(() =>
      validateDropsExtra({ sourceKind: "netflow" as never }),
    ).toThrow(/drops extra\.sourceKind/);
    expect(() => validateDropsExtra({ sourcetype: "bad sourcetype!" })).toThrow(
      /drops extra\.sourcetype/,
    );
    expect(() => validateDropsExtra({ dropWarnCount: 0 })).toThrow(
      /drops extra\.dropWarnCount/,
    );
    expect(() => validateDropsExtra({ dropWarnCount: 1.5 })).toThrow(
      /drops extra\.dropWarnCount/,
    );
  });
});

describe("drops SPL builders and allowlist safety", () => {
  it("emits | head before | table, unquoted dotted flow.verdict, and passes sensitive-field checks", () => {
    const ftdSpl = buildDropsFtdSearch({
      index: "cisco_secure_fw",
      filter: { src: "10.30.40.25", dst: "10.20.30.40", device: "ftd-edge" },
      maxRows: 256,
    });
    const hubbleSpl = buildDropsHubbleSearch({
      index: "cilium_hubble",
      filter: { src: "10.42.0.15", dst: "10.96.12.40", device: "k8s-node-b" },
      maxRows: 256,
    });
    const ndSpl = buildDropsNdSearch({
      index: "cisco_dc",
      maxRows: 256,
    });
    const aciSpl = buildDropsAciSearch({
      index: "cisco_dc",
      maxRows: 256,
    });
    const fwSpl = buildDropsFirewallSearch({
      index: "pan",
      sourcetype: "pan:traffic",
      maxRows: 256,
    });

    for (const spl of [ftdSpl, hubbleSpl, ndSpl, aciSpl, fwSpl]) {
      assertNoForbiddenFieldsInSpl("drops", spl);
      const headIdx = spl.indexOf("| head 257");
      const tableIdx = spl.indexOf("| table ");
      expect(headIdx).toBeGreaterThan(0);
      expect(tableIdx).toBeGreaterThan(headIdx);
      expect(spl).not.toContain("_raw");
    }

    // Hubble base search must never quote dotted field names and must run | spath after | head
    expect(hubbleSpl).toContain('flow.verdict="DROPPED"');
    expect(hubbleSpl).not.toContain('"flow.verdict"');
    expect(hubbleSpl).not.toContain('"flow.IP.source"');
    expect(hubbleSpl.indexOf("| spath")).toBeGreaterThan(
      hubbleSpl.indexOf("| head 257"),
    );

    // ND | spath must follow | head
    expect(ndSpl.indexOf("| spath")).toBeGreaterThan(
      ndSpl.indexOf("| head 257"),
    );

    // Raw events URL quotes values with literal()
    const rawUrl = buildDropsRawEventsUrl({
      index: "cilium_hubble",
      enforcerKind: "hubble",
      sourcetypes: ["cilium:hubble:flow"],
      srcIp: "10.42.0.15",
      destIp: "10.96.12.40",
      earliest: EARLIEST,
      latest: LATEST,
    });
    expect(rawUrl).toMatch(/^\/app\/splunk_adm\/search\?/);
    expect(decodeURIComponent(rawUrl)).toContain('flow.verdict="DROPPED"');
    expect(decodeURIComponent(rawUrl)).toContain("index=cilium_hubble");
  });

  it("strips forbidden sensitive fields and unexpected keys via projectRowToLensAllowlist", () => {
    const projected = projectRowToLensAllowlist("drops", {
      _time: EARLIEST + 10,
      host: "pa-fw-01",
      sourcetype: "pan:traffic",
      src_ip: "10.20.1.15",
      dest_ip: "192.0.2.44",
      action: "deny",
      rule_name: "block-rdp",
      cookie: "secret-session",
      password: "secret",
      user_id: "alice",
      _raw: "raw-line",
    });
    expect(projected).not.toHaveProperty("cookie");
    expect(projected).not.toHaveProperty("password");
    expect(projected).not.toHaveProperty("user_id");
    expect(projected).not.toHaveProperty("_raw");
    expect(
      Object.keys(projected).every((k) =>
        LENS_FIELD_ALLOWLISTS.drops.includes(k),
      ),
    ).toBe(true);
  });
});

describe("drops normalizers and aggregation", () => {
  it("normalizes FTD eStreamer Block/Drop/Reset and ignores Allow", () => {
    const events = loadNdjsonEvents("fixtures/protocols/drops/ftd_drops.ndjson")
      .map((r) => normalizeDropsRow(r, "ftd"))
      .filter((e): e is NonNullable<typeof e> => Boolean(e));

    expect(events).toHaveLength(2);
    expect(events[0].enforcerLabel).toBe("FTD");
    expect(events[0].nativeReason).toBe("Block with reset (block-win-to-db)");
    expect(events[0].serviceLabel).toBe("TCP/5432");
    expect(events[0].packets).toBe(3);
    expect(events[0].bytes).toBe(180);
    expect(events[1].nativeReason).toBe("Drop (deny-ext-ssh)");
  });

  it("normalizes Cilium Hubble nested flow.* drops and ignores FORWARDED", () => {
    const events = loadNdjsonEvents(
      "fixtures/protocols/drops/hubble_drops.ndjson",
    )
      .map((r) => normalizeDropsRow(r, "hubble"))
      .filter((e): e is NonNullable<typeof e> => Boolean(e));

    expect(events).toHaveLength(2);
    expect(events[0].enforcerLabel).toBe("Hubble");
    expect(events[0].nativeReason).toBe("POLICY_DENIED");
    expect(events[0].attributed).toBe(true);
    expect(events[0].srcPodLabel).toBe("shop/web-1");
    expect(events[0].destPodLabel).toBe("payments/ledger-api-1");
    expect(events[0].device).toBe("k8s-node-b");

    // Also handles flat projected fields returned from | spath | table
    const flat = normalizeDropsRow(
      {
        _time: EARLIEST + 20,
        host: "k8s-node-b",
        sourcetype: "cilium:hubble:flow",
        verdict: "DROPPED",
        drop_reason_desc: "POLICY_DENIED",
        src_ip: "10.42.0.15",
        dest_ip: "10.96.12.40",
        dest_port: "8080",
        transport: "TCP",
        src_namespace: "shop",
        src_pod: "web-1",
        dest_namespace: "payments",
        dest_pod: "ledger-api-1",
        node: "prod-k8s/k8s-node-b",
      },
      "hubble",
    );
    expect(flat?.serviceLabel).toBe("TCP/8080");
    expect(flat?.device).toBe("k8s-node-b");
  });

  it("normalizes ND drops (attributed and unattributed) and deduplicates ACI acllogDropL3Pkt repolls", () => {
    const rawRows = loadNdjsonEvents(
      "fixtures/protocols/drops/nd_aci_drops.ndjson",
    );
    const events = rawRows
      .map((r) => normalizeDropsRow(r))
      .filter((e): e is NonNullable<typeof e> => Boolean(e));

    // 2 ND rows + 2 duplicate acllogDropL3Pkt rows + 1 ACI syslog row = 5 before dedup
    expect(events).toHaveLength(5);

    const analysis = buildDropsAnalysis({
      events: events.map((event) => ({ event, indexName: "cisco_dc" })),
      thresholds: resolveDropsThresholds(),
      earliest: EARLIEST,
      latest: LATEST,
      outcomes: [
        { source: "protocol_drops", profile: "drops-dc", state: "complete" },
      ],
      capped: false,
    });

    // Duplicate acllogDropL3Pkt DN collapsed to 1 -> 4 distinct tuples (3 attributed, 1 unattributed ND)
    expect(analysis.rows).toHaveLength(4);
    const aciClassRow = analysis.rows.find(
      (r) => r.enforcerKind === "aci" && r.srcIp === "10.30.40.25",
    );
    expect(aciClassRow?.eventCount).toBe(1);
    expect(aciClassRow?.primaryReason).toBe("acllogDropL3Pkt");

    const ndUnattributed = analysis.rows.find(
      (r) => r.enforcerKind === "nd" && r.srcIp === "10.42.0.25",
    );
    expect(ndUnattributed?.attributed).toBe(false);
    expect(analysis.verdict).toContain("3 of 4 blocked flows attributed");
    expect(analysis.verdict).toContain("(1 unattributed)");
  });

  it("normalizes generic firewall and cloud flow-log denies (PAN-OS, FortiGate, GCP)", () => {
    const pan = normalizeDropsRow(
      {
        _time: EARLIEST + 10,
        host: "pa-fw-01",
        sourcetype: "pan:traffic",
        src_ip: "10.20.1.15",
        dest_ip: "192.0.2.44",
        src_port: 51520,
        dest_port: 3389,
        transport: "tcp",
        action: "deny",
        reason: "policy-deny",
        rule_name: "block-rdp",
        packets: 1,
        bytes: 74,
        device: "pa-fw-01",
      },
      "firewall",
    );
    expect(pan?.enforcerLabel).toBe("Firewall");
    expect(pan?.nativeReason).toBe("deny · block-rdp (policy-deny)");
    expect(pan?.attributed).toBe(true);

    const gcp = normalizeDropsRow(
      {
        _time: EARLIEST + 20,
        host: "gcp-ta-hf",
        sourcetype: "google:gcp:compute:vpc_flows",
        src_ip: "192.0.2.10",
        dest_ip: "10.40.1.15",
        dest_port: 22,
        transport: "TCP",
        action: "DROPPED",
        reason: "FIREWALL_DENY",
        packets: 2,
        bytes: 120,
      },
      "firewall",
    );
    expect(gcp?.nativeReason).toBe("DROPPED (FIREWALL_DENY)");

    const unattributedFw = normalizeDropsRow(
      {
        _time: EARLIEST + 30,
        sourcetype: "custom:fw",
        src_ip: "192.0.2.99",
        dest_ip: "10.40.1.15",
        action: "reject",
        exporter_ip: "192.0.2.254",
      },
      "firewall",
    );
    expect(unattributedFw?.attributed).toBe(false);
    expect(unattributedFw?.device).toBe("192.0.2.254");
  });

  it("keeps IPv4 and IPv6 intact in shortenDeviceLabel and enforces safe row IDs", () => {
    expect(shortenDeviceLabel("192.0.2.60")).toBe("192.0.2.60");
    expect(shortenDeviceLabel("2001:db8::1")).toBe("2001:db8::1");
    expect(shortenDeviceLabel("ftd-edge.corp.example")).toBe("ftd-edge");

    const id = makeDropRowId(
      "0:0:0:0:0:FFFF:0A2A:0014",
      "10.20.30.40",
      "nd",
      "tcp_5432",
    );
    expect(id).toMatch(/^[A-Za-z0-9._:/-]{1,128}$/);
    expect(id).not.toContain("->");
    expect(id).toContain("__");
  });
});

describe("degraded coverage, capped-empty, and config recheck", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("treats capped-empty searches as unknown/partial (never none_observed)", () => {
    const analysis = buildDropsAnalysis({
      events: [],
      thresholds: resolveDropsThresholds(),
      earliest: EARLIEST,
      latest: LATEST,
      outcomes: [
        {
          source: "protocol_drops",
          profile: "drops-dc1",
          state: "partial",
          capped: true,
        },
      ],
      capped: true,
    });
    expect(analysis.verdictStatus).toBe("unknown");
    expect(analysis.coverageStatus).toBe("unknown");
    expect(analysis.bannerState).toBe("partial");
    expect(analysis.verdictStatus).not.toBe("none_observed");
  });

  it("downgrades degraded/capped summaries in summarizeDrops (ok->attention, none_observed->unknown)", async () => {
    const config: ProtocolConfiguration = {
      profiles: [
        makeProfile({
          extra: { sourceKind: "ftd", dropWarnCount: 10 },
        }),
      ],
      fingerprint: "fp-drops-1",
    };

    // Case 1: 1 drop event below dropWarnCount=10 -> ok in analysis, but capped/truncated -> downgraded to attention
    const cappedOkClient: SearchClient = {
      search: vi.fn().mockResolvedValue({
        rows: [
          {
            _time: EARLIEST + 10,
            host: "192.0.2.70",
            sourcetype: "cisco:sfw:estreamer",
            InitiatorIP: "10.30.40.25",
            ResponderIP: "10.20.30.40",
            ResponderPort: 5432,
            Protocol: "TCP",
            AC_RuleAction: "Block",
            Device: "ftd-edge",
          },
        ],
        truncated: true,
        warnings: [],
        errors: [],
      }),
    };
    const sum1 = await summarizeDrops(
      cappedOkClient,
      makeRequest(),
      config,
      new AbortController().signal,
      { skipConfigRecheck: true },
    );
    expect(sum1.capped).toBe(true);
    expect(sum1.status).toBe("attention");

    // Case 2: 0 events with one blocked outcome -> none_observed must never occur; unknown
    const multiConfig: ProtocolConfiguration = {
      profiles: [
        makeProfile({ id: "p1", extra: { sourceKind: "ftd" } }),
        makeProfile({
          id: "p2",
          index: "cilium_hubble",
          extra: { sourceKind: "hubble" },
        }),
      ],
      fingerprint: "fp-drops-2",
    };
    const blockedClient: SearchClient = {
      search: vi
        .fn()
        .mockRejectedValueOnce(new SearchAccessDeniedError())
        .mockResolvedValueOnce({ rows: [], warnings: [], errors: [] }),
    };
    const sum2 = await summarizeDrops(
      blockedClient,
      makeRequest(),
      multiConfig,
      new AbortController().signal,
      { skipConfigRecheck: true },
    );
    expect(sum2.status).toBe("unknown");
  });

  it("discards results when adm_protocol_profiles fingerprint changes during investigation", async () => {
    vi.spyOn(
      protocolConfigClient,
      "readProtocolProfileDocument",
    ).mockResolvedValue({
      version: 1,
      profiles: [
        makeProfile({
          id: "drops-dc1-updated",
          extra: { sourceKind: "ftd", dropWarnCount: 2 },
        }),
      ],
    });

    const config: ProtocolConfiguration = {
      profiles: [makeProfile({ extra: { sourceKind: "ftd" } })],
      fingerprint: "stale-fingerprint",
    };
    const client: SearchClient = {
      search: vi.fn().mockResolvedValue({
        rows: [
          {
            _time: EARLIEST + 10,
            host: "192.0.2.70",
            sourcetype: "cisco:sfw:estreamer",
            InitiatorIP: "10.30.40.25",
            ResponderIP: "10.20.30.40",
            ResponderPort: 5432,
            Protocol: "TCP",
            AC_RuleAction: "Block with reset",
            AccessControlRuleName: "block-win-to-db",
            Device: "ftd-edge",
          },
        ],
        warnings: [],
        errors: [],
      }),
    };

    const result = await investigateDrops(
      client,
      makeRequest(),
      config,
      new AbortController().signal,
    );
    expect(result.bannerState).toBe("stale_config");
    expect(result.coverageLabel).toBe("Stale config");
    expect(result.rows).toHaveLength(0);
  });

  it("queries Nexus Dashboard JSON array brace fields before | head with no post-head | where", () => {
    const ndSpl = buildDropsNdSearch({
      index: "cisco_dc",
      filter: { src: "10.10.20.11", dst: "10.10.30.22", device: "leaf2" },
      maxRows: 256,
    });
    expect(ndSpl).toContain("stats{}.dropPktCount>0");
    expect(ndSpl).toContain("stats{}.dropReasons{}=*");
    expect(ndSpl).toContain('stats{}.nodeNames{}="leaf2"');
    expect(ndSpl).not.toContain("stats.dropPktCount");
    expect(ndSpl).not.toContain("stats.nodeNames=");
    expect(ndSpl).not.toContain("| where ");

    const rawUrl = buildDropsRawEventsUrl({
      index: "cisco_dc",
      enforcerKind: "nd",
      sourcetypes: ["cisco:dc:nd:flows"],
      srcIp: "10.10.20.11",
      destIp: "10.10.30.22",
      earliest: EARLIEST,
      latest: LATEST,
    });
    const decoded = decodeURIComponent(rawUrl);
    expect(decoded).toContain("stats{}.dropPktCount>0");
    expect(decoded).toContain("stats{}.dropReasons{}=*");
  });
});
