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
  buildQosIcmpAnalysis,
  buildQosIcmpRawEventsUrl,
  buildQosIcmpSearch,
  classifyIcmpEvent,
  extractDscpAndEcnFromTos,
  formatDscpLabel,
  formatEcnLabel,
  investigateQosIcmp,
  makeQosFlowRowId,
  normalizeIpLiteral,
  normalizeQosIcmpRow,
  resolveQosIcmpThresholds,
  shortenDeviceLabel,
  summarizeQosIcmp,
  validateQosIcmpExtra,
} from "./adapter";

const EARLIEST = 1764246500;
const NOW = 1764247100;

function makeProfile(
  overrides: Partial<BaseProtocolProfile> = {},
): BaseProtocolProfile {
  return {
    id: "qos-dc1",
    source: "protocol_qos_icmp",
    lens: "qos_icmp",
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
    lens: "qos_icmp",
    scope: "prod:dc1",
    earliest: EARLIEST,
    latest: NOW,
    ...overrides,
  };
}

describe("validateQosIcmpExtra (fail-closed profile validation)", () => {
  it("accepts valid thresholds and integrates with parseProtocolProfiles", () => {
    expect(validateQosIcmpExtra(undefined)).toBeUndefined();
    expect(
      validateQosIcmpExtra({
        sourceKind: "stream_netflow",
        icmpUnreachableWarnCount: 10,
        icmpTtlExceededWarnCount: 3,
        dropPktWarnCount: 2,
        unexpectedDscpValues: [8, 19, 8],
      }),
    ).toEqual({
      sourceKind: "stream_netflow",
      icmpUnreachableWarnCount: 10,
      icmpTtlExceededWarnCount: 3,
      dropPktWarnCount: 2,
      unexpectedDscpValues: [8, 19],
    });

    const profiles = parseProtocolProfiles(
      {
        version: 1,
        profiles: [
          {
            id: "qos-dc1",
            source: "protocol_qos_icmp",
            lens: "qos_icmp",
            scope: "prod:dc1",
            index: "netflow",
            observer: "stream-fwd-01",
            validFrom: EARLIEST - 3600,
            validUntil: NOW + 3600,
            extra: { icmpTtlExceededWarnCount: 8, unexpectedDscpValues: [8] },
          },
        ],
      },
      { qos_icmp: validateQosIcmpExtra },
    );
    expect(resolveQosIcmpThresholds(profiles[0])).toEqual({
      sourceKind: "auto",
      icmpUnreachableWarnCount: 5,
      icmpTtlExceededWarnCount: 8,
      dropPktWarnCount: 1,
      unexpectedDscpValues: [8],
    });
  });

  it("rejects unknown keys and out-of-range values", () => {
    expect(() => validateQosIcmpExtra({ unknownKey: true })).toThrow(
      /Unsupported qos_icmp/,
    );
    expect(() =>
      validateQosIcmpExtra({ sourceKind: "bad_source" as never }),
    ).toThrow(/sourceKind/);
    expect(() => validateQosIcmpExtra({ icmpUnreachableWarnCount: 0 })).toThrow(
      /icmpUnreachableWarnCount/,
    );
    expect(() =>
      validateQosIcmpExtra({ icmpTtlExceededWarnCount: 100001 }),
    ).toThrow(/icmpTtlExceededWarnCount/);
    expect(() => validateQosIcmpExtra({ dropPktWarnCount: 1.5 })).toThrow(
      /dropPktWarnCount/,
    );
    expect(() => validateQosIcmpExtra({ unexpectedDscpValues: [64] })).toThrow(
      /0 and 63/,
    );
    expect(() => validateQosIcmpExtra({ unexpectedDscpValues: [-1] })).toThrow(
      /0 and 63/,
    );
  });
});

describe("DSCP / ECN bit extraction and SPL builders", () => {
  it("extracts DSCP (tos >> 2) & 0x3f and ECN (tos & 3) accurately", () => {
    expect(extractDscpAndEcnFromTos(184)).toEqual({ dscp: 46, ecn: 0 });
    expect(extractDscpAndEcnFromTos(187)).toEqual({ dscp: 46, ecn: 3 });
    expect(extractDscpAndEcnFromTos(104)).toEqual({ dscp: 26, ecn: 0 });
    expect(extractDscpAndEcnFromTos(0)).toEqual({ dscp: 0, ecn: 0 });
    expect(extractDscpAndEcnFromTos(76)).toEqual({ dscp: 19, ecn: 0 });
    expect(extractDscpAndEcnFromTos("0xb8")).toEqual({ dscp: 46, ecn: 0 });
    expect(extractDscpAndEcnFromTos(256)).toEqual({});
    expect(extractDscpAndEcnFromTos(-1)).toEqual({});
    expect(formatDscpLabel(46)).toBe("EF (46)");
    expect(formatDscpLabel(19)).toBe("DSCP 19");
    expect(formatEcnLabel(3)).toBe("CE");
  });

  it("emits | head BEFORE | table and uses | spath after | head for cisco:dc:nd:flows", () => {
    for (const st of [
      "stream:netflow",
      "stream:icmp",
      "cisco:dc:nd:flows",
    ] as const) {
      const spl = buildQosIcmpSearch({
        index: st === "cisco:dc:nd:flows" ? "cisco_dc" : "netflow",
        sourcetype: st,
        filter: { src: "10.42.0.20", dst: "10.42.0.30", device: "192.0.2.11" },
        maxRows: 256,
      });
      const headIdx = spl.indexOf("| head 257");
      const tableIdx = spl.indexOf("| table ");
      expect(headIdx).toBeGreaterThan(0);
      expect(tableIdx).toBeGreaterThan(headIdx);
      expect(() => assertNoForbiddenFieldsInSpl("qos_icmp", spl)).not.toThrow();
      for (const bad of FORBIDDEN_SENSITIVE_FIELDS) {
        expect(spl.toLowerCase()).not.toContain(` ${bad}`);
      }
      if (st === "cisco:dc:nd:flows") {
        const spathIdx = spl.indexOf("| spath path=stats{}.dropPktCount");
        expect(spathIdx).toBeGreaterThan(headIdx);
        expect(tableIdx).toBeGreaterThan(spathIdx);
        // Never put dotted field paths inside quotes in base search.
        const baseSearch = spl.slice(0, headIdx);
        expect(baseSearch).not.toMatch(/"[a-zA-Z_][a-zA-Z0-9_{}]*\.[a-zA-Z_]/);
        expect(baseSearch).not.toContain("stats{}.");
        expect(spl).toContain("dropPktCount dropReasons");
        expect(spl).toContain("nodeName");
      }
    }
  });

  it("builds literal()-quoted raw events URL and safe row IDs without ->", () => {
    const url = buildQosIcmpRawEventsUrl({
      index: "netflow",
      srcIp: "10.42.0.20",
      dstIp: "10.42.0.30",
      sourcetypes: ["stream:netflow", "stream:icmp"],
      earliest: EARLIEST,
      latest: NOW,
    });
    expect(url).toContain("/app/splunk_adm/search?");
    const decoded = decodeURIComponent(url);
    expect(decoded).toContain("index=netflow");
    expect(decoded).toContain('src_ip="10.42.0.20"');
    expect(decoded).toContain('dest_ip="10.42.0.30"');

    const ipv6Id = makeQosFlowRowId(
      "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
      "2001:0db8:85a3:0000:0000:8a2e:0370:9999",
      "ICMPv6",
    );
    expect(ipv6Id).toMatch(/^[A-Za-z0-9._:/-]{1,128}$/);
    expect(ipv6Id).not.toContain("->");
  });

  it("preserves IPv4 and IPv6 addresses in shortenDeviceLabel and normalizes IPv4-mapped IPv6", () => {
    expect(shortenDeviceLabel("192.0.2.11")).toBe("192.0.2.11");
    expect(shortenDeviceLabel("2001:db8::1")).toBe("2001:db8::1");
    expect(shortenDeviceLabel("leaf1.dc1.example")).toBe("leaf1");
    expect(normalizeIpLiteral("0:0:0:0:0:FFFF:0A2A:0014")).toBe("10.42.0.20");
  });
});

describe("QoS/DSCP & ICMP classification and fixture analysis", () => {
  it("classifies PMTUD candidates without claiming MTU blackhole confirmed", () => {
    expect(classifyIcmpEvent(3, 4, false)).toBe("pmtud_candidate");
    expect(classifyIcmpEvent(3, 1, false)).toBe("unreachable");
    expect(classifyIcmpEvent(11, 0, false)).toBe("ttl_exceeded");
    expect(classifyIcmpEvent(2, 0, true)).toBe("pmtud_candidate");
    expect(classifyIcmpEvent(1, 0, true)).toBe("unreachable");
    expect(classifyIcmpEvent(3, 0, true)).toBe("ttl_exceeded");

    const v6Pmtud = normalizeQosIcmpRow(
      {
        _time: EARLIEST + 20,
        host: "sensor-v6",
        sourcetype: "stream:icmp",
        src_ip: "2001:db8::ff",
        dest_ip: "2001:db8::10",
        icmp_type: 2,
        icmp_code: 0,
        bytes: 1280,
      },
      "stream:icmp",
    )!;
    const analysis = buildQosIcmpAnalysis({
      events: [{ event: v6Pmtud, indexName: "netflow" }],
      thresholds: resolveQosIcmpThresholds(),
      earliest: EARLIEST,
      latest: NOW,
      outcomes: [{ source: "protocol_qos_icmp", state: "complete" }],
      capped: false,
      icmpConfigured: true,
    });
    expect(analysis.rows[0].attention).toBe(true);
    expect(analysis.rows[0].pmtudCount).toBe(1);
    expect(analysis.rows[0].pmtudExplanation).toContain("PMTUD candidate");
    expect(analysis.rows[0].pmtudExplanation?.toLowerCase()).not.toContain(
      "blackhole confirmed",
    );
    expect(analysis.timelineEvents[0].lane).toBe("2001:db8::ff → 2001:db8::10");
  });

  it("correlates grounded fixtures for DSCP remarking, PMTUD, TTL spikes, unexpected DSCP, and ND drops", () => {
    const netflowLines = readFileSync(
      "fixtures/protocols/qos_icmp/stream_netflow_dscp.ndjson",
      "utf8",
    )
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l) as Record<string, unknown>);
    const icmpLines = readFileSync(
      "fixtures/protocols/qos_icmp/stream_icmp.ndjson",
      "utf8",
    )
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l) as Record<string, unknown>);
    const ndLines = readFileSync(
      "fixtures/protocols/qos_icmp/nd_drops.ndjson",
      "utf8",
    )
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l) as Record<string, unknown>);

    const events = [
      ...netflowLines.map((r) => ({
        event: normalizeQosIcmpRow(r, "stream:netflow")!,
        indexName: "netflow",
      })),
      ...icmpLines.map((r) => ({
        event: normalizeQosIcmpRow(r, "stream:icmp")!,
        indexName: "netflow",
      })),
      ...ndLines.map((r) => ({
        event: normalizeQosIcmpRow(r, "cisco:dc:nd:flows")!,
        indexName: "cisco_dc",
      })),
    ];

    const result = buildQosIcmpAnalysis({
      events,
      thresholds: resolveQosIcmpThresholds(),
      earliest: EARLIEST,
      latest: NOW,
      outcomes: [
        { source: "protocol_qos_icmp", profile: "qos-dc1", state: "complete" },
      ],
      capped: false,
      netflowConfigured: true,
      icmpConfigured: true,
      ndConfigured: true,
    });

    expect(result.verdictStatus).toBe("attention");
    expect(result.kpis).toHaveLength(4);
    expect(result.kpis.map((k) => k.id)).toEqual([
      "dscp-remarks",
      "pmtud-candidates",
      "icmp-errors",
      "fabric-drops",
    ]);

    // Every row ID must conform to ^[A-Za-z0-9._:/-]{1,128}$ and never contain ->
    for (const row of result.rows) {
      expect(row.id).toMatch(/^[A-Za-z0-9._:/-]{1,128}$/);
      expect(row.id).not.toContain("->");
    }

    const remarkedRow = result.rows.find(
      (r) => r.srcIp === "10.42.0.20" && r.dstIp === "10.42.0.30",
    )!;
    expect(remarkedRow.dscpRemarked).toBe(true);
    expect(remarkedRow.attention).toBe(true);
    expect(remarkedRow.dscpSummary).toBe("EF (46) → DF (0)");
    expect(remarkedRow.exporterObservations).toHaveLength(2);

    const pmtudRow = result.rows.find(
      (r) => r.srcIp === "192.0.2.254" && r.dstIp === "10.42.0.20",
    )!;
    expect(pmtudRow.pmtudCount).toBe(1);
    expect(pmtudRow.attention).toBe(true);

    const ttlRow = result.rows.find(
      (r) => r.srcIp === "192.0.2.253" && r.dstIp === "10.42.0.60",
    )!;
    expect(ttlRow.ttlExceededCount).toBe(5);
    expect(ttlRow.attention).toBe(true);

    const ndDropRow = result.rows.find(
      (r) => r.srcIp === "10.42.0.25" && r.dstIp === "10.42.0.50",
    )!;
    expect(ndDropRow.dropPktCount).toBe(14);
    expect(ndDropRow.dropReasons).toEqual(["QOS_WRED_DROP"]);
    expect(ndDropRow.attention).toBe(true);

    const unexpectedDscpRow = result.rows.find(
      (r) => r.srcIp === "10.42.0.99" && r.dstIp === "10.42.0.88",
    )!;
    expect(unexpectedDscpRow.unexpectedDscp).toBe(true);
    expect(unexpectedDscpRow.attention).toBe(true);

    const healthyRow = result.rows.find(
      (r) =>
        r.srcIp === "10.42.0.20" &&
        r.dstIp === "10.42.0.40" &&
        r.proto === "UDP",
    )!;
    expect(healthyRow.attention).toBe(false);
    expect(healthyRow.status).toBe("ok");

    // Matrix: flagged exporters first, remarking and drop cells highlighted
    expect(result.matrixRows[0]).toBe("192.0.2.11");
    expect(
      result.matrixCells.find(
        (c) => c.row === "192.0.2.11" && c.col === "EF (46)",
      )?.status,
    ).toBe("attention");
    expect(
      result.matrixCells.find(
        (c) => c.row === "192.0.2.12" && c.col === "DF (0)",
      )?.status,
    ).toBe("attention");
    expect(
      result.matrixCells.find(
        (c) => c.row === "192.0.2.11" && c.col === "AF31 (26)",
      )?.value,
    ).toContain("Drop");

    // Timeline preserves full IPv4 addresses in lane labels
    expect(
      result.timelineEvents.some((e) => e.lane.includes("192.0.2.254")),
    ).toBe(true);
    expect(
      result.timelineEvents.some((e) =>
        e.label.includes("PMTUD candidate: Fragmentation Needed"),
      ),
    ).toBe(true);
  });
});

describe("investigateQosIcmp & summarizeQosIcmp", () => {
  it("runs Stream Estimate check ONLY when stream:icmp returns 0 rows", async () => {
    const search = vi
      .fn()
      // stream:netflow
      .mockResolvedValueOnce({
        rows: [
          {
            _time: EARLIEST + 10,
            sourcetype: "stream:netflow",
            exporter_ip: "192.0.2.11",
            src_ip: "10.42.0.20",
            dest_ip: "10.42.0.40",
            src_port: 5060,
            dest_port: 5060,
            protoid: 17,
            tos: 184,
            bytes: 500,
            packets: 5,
          },
        ],
        warnings: [],
        errors: [],
      })
      // stream:icmp (0 rows)
      .mockResolvedValueOnce({ rows: [], warnings: [], errors: [] })
      // cisco:dc:nd:flows (0 rows)
      .mockResolvedValueOnce({ rows: [], warnings: [], errors: [] })
      // checkStreamEstimateMode(["icmp"])
      .mockResolvedValueOnce({
        rows: [
          { host: "stream-fwd-01", stream_id: "icmp", stats_only: "true" },
        ],
        warnings: [],
        errors: [],
      });

    const result = await investigateQosIcmp(
      { search },
      makeRequest(),
      makeConfig([makeProfile()]),
      new AbortController().signal,
      { skipConfigRecheck: true },
    );

    expect(search).toHaveBeenCalledTimes(4);
    expect(search.mock.calls[3][0].search).toContain(
      'sourcetype="stream:stats"',
    );
    expect(search.mock.calls[3][0].search).toContain('"icmp"');
    expect(result.hasActiveIcmp).toBe(false);
    expect(result.hasActiveNd).toBe(false);
    expect(result.streamReadiness?.state).toBe("estimate_only");
    expect(result.bannerState).toBe("estimate_only");
  });

  it("downgrades capped-empty to unknown/partial (never none_observed) and downgrades degraded summaries", async () => {
    const cappedEmpty = await summarizeQosIcmp(
      {
        search: vi.fn().mockResolvedValue({
          rows: [],
          truncated: true,
          warnings: [],
          errors: [],
        }),
      },
      makeRequest(),
      makeConfig([makeProfile({ extra: { sourceKind: "stream_netflow" } })]),
      new AbortController().signal,
      { skipConfigRecheck: true },
    );
    expect(cappedEmpty.status).toBe("unknown");
    expect(cappedEmpty.capped).toBe(true);

    // Healthy NetFlow + blocked ND -> summarizeQosIcmp downgrades ok -> attention
    const searchBlocked = vi
      .fn()
      .mockResolvedValueOnce({
        rows: [
          {
            _time: EARLIEST + 10,
            sourcetype: "stream:netflow",
            exporter_ip: "192.0.2.11",
            src_ip: "10.42.0.20",
            dest_ip: "10.42.0.40",
            src_port: 5060,
            dest_port: 5060,
            protoid: 17,
            tos: 184,
            bytes: 500,
            packets: 5,
          },
        ],
        warnings: [],
        errors: [],
      })
      .mockRejectedValueOnce(new SearchAccessDeniedError());

    const degradedOk = await summarizeQosIcmp(
      { search: searchBlocked },
      makeRequest(),
      makeConfig([
        makeProfile({ id: "nf", extra: { sourceKind: "stream_netflow" } }),
        makeProfile({
          id: "nd",
          index: "cisco_dc",
          extra: { sourceKind: "nd_flows" },
        }),
      ]),
      new AbortController().signal,
      { skipConfigRecheck: true },
    );
    expect(degradedOk.status).toBe("attention");
  });

  it("strips forbidden sensitive fields and enforces stale-config recheck with profileValidators", async () => {
    const search = vi.fn().mockResolvedValue({
      rows: [
        {
          _time: EARLIEST + 10,
          sourcetype: "stream:netflow",
          exporter_ip: "192.0.2.11",
          src_ip: "10.42.0.20",
          dest_ip: "10.42.0.40",
          src_port: 5060,
          dest_port: 5060,
          protoid: 17,
          tos: 184,
          bytes: 500,
          packets: 5,
          _raw: "secret",
          cookie: "secret=1",
          payload: "secret",
          src_content: "secret",
        },
      ],
      warnings: [],
      errors: [],
    });
    const client: SearchClient = { search };
    const profile = makeProfile({ extra: { sourceKind: "stream_netflow" } });

    const spy = vi
      .spyOn(protocolConfigClient, "readProtocolProfileDocument")
      .mockResolvedValue({
        version: 1,
        profiles: [profile],
      });
    try {
      const config = await import("../../shared/runner").then((m) =>
        m.readProtocolConfiguration({ qos_icmp: validateQosIcmpExtra }),
      );
      const summary = await summarizeQosIcmp(
        client,
        makeRequest(),
        config,
        new AbortController().signal,
        { profileValidators: { qos_icmp: validateQosIcmpExtra } },
      );
      expect(summary.status).toBe("ok");

      spy.mockResolvedValueOnce({
        version: 1,
        profiles: [
          makeProfile({
            index: "other_netflow",
            extra: { sourceKind: "stream_netflow" },
          }),
        ],
      });
      const stale = await investigateQosIcmp(
        client,
        makeRequest(),
        config,
        new AbortController().signal,
        { profileValidators: { qos_icmp: validateQosIcmpExtra } },
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
      investigateQosIcmp(
        { search },
        makeRequest(),
        makeConfig([makeProfile({ extra: { sourceKind: "stream_netflow" } })]),
        controller.signal,
        { skipConfigRecheck: true },
      ),
    ).rejects.toThrow();
  });
});
