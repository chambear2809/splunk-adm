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
  buildLbHealthAnalysis,
  buildLbHealthRawEventsUrl,
  buildLbHealthSearch,
  investigateLbHealth,
  makeLbHealthRowId,
  normalizeLbHealthRow,
  normalizeLbIp,
  resolveLbHealthThresholds,
  shortenDeviceLabel,
  summarizeLbHealth,
  validateLbHealthExtra,
} from "./adapter";

const EARLIEST = 1764246500;
const NOW = 1764247100;

function makeProfile(
  overrides: Partial<BaseProtocolProfile> = {},
): BaseProtocolProfile {
  return {
    id: "lb-prod",
    source: "protocol_lb_health",
    lens: "lb_health",
    scope: "prod:us-east",
    index: "lb_logs",
    observer: "bigip-01",
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
    lens: "lb_health",
    scope: "prod:us-east",
    earliest: EARLIEST,
    latest: NOW,
    ...overrides,
  };
}

describe("validateLbHealthExtra (fail-closed profile validation)", () => {
  it("accepts valid thresholds and integrates with parseProtocolProfiles", () => {
    expect(validateLbHealthExtra(undefined)).toBeUndefined();
    expect(
      validateLbHealthExtra({
        sourceKind: "aws_alb",
        errorRateWarnPct: 5,
        latencyWarnMs: 750,
        lbFailedWarnCount: 3,
      }),
    ).toEqual({
      sourceKind: "aws_alb",
      errorRateWarnPct: 5,
      latencyWarnMs: 750,
      lbFailedWarnCount: 3,
    });

    const profiles = parseProtocolProfiles(
      {
        version: 1,
        profiles: [
          {
            id: "lb-prod",
            source: "protocol_lb_health",
            lens: "lb_health",
            scope: "prod:us-east",
            index: "lb_logs",
            observer: "bigip-01",
            validFrom: EARLIEST - 3600,
            validUntil: NOW + 3600,
            extra: { errorRateWarnPct: 3.5, lbFailedWarnCount: 2 },
          },
        ],
      },
      { lb_health: validateLbHealthExtra },
    );

    expect(resolveLbHealthThresholds(profiles[0])).toEqual({
      sourceKind: "auto",
      errorRateWarnPct: 3.5,
      latencyWarnMs: 500,
      lbFailedWarnCount: 2,
    });
  });

  it("rejects unknown keys and out-of-range values", () => {
    expect(() => validateLbHealthExtra({ unknownKey: true })).toThrow(
      /Unsupported lb_health/,
    );
    expect(() =>
      validateLbHealthExtra({ sourceKind: "invalid_lb" as never }),
    ).toThrow(/sourceKind/);
    expect(() => validateLbHealthExtra({ errorRateWarnPct: 0 })).toThrow(
      /errorRateWarnPct/,
    );
    expect(() => validateLbHealthExtra({ errorRateWarnPct: 101 })).toThrow(
      /errorRateWarnPct/,
    );
    expect(() => validateLbHealthExtra({ latencyWarnMs: 0 })).toThrow(
      /latencyWarnMs/,
    );
    expect(() => validateLbHealthExtra({ latencyWarnMs: 60001 })).toThrow(
      /latencyWarnMs/,
    );
    expect(() => validateLbHealthExtra({ lbFailedWarnCount: 0 })).toThrow(
      /lbFailedWarnCount/,
    );
    expect(() => validateLbHealthExtra({ lbFailedWarnCount: 1.5 })).toThrow(
      /lbFailedWarnCount/,
    );
    expect(() => validateLbHealthExtra({ lbFailedWarnCount: 1001 })).toThrow(
      /lbFailedWarnCount/,
    );
  });
});

describe("SPL builders, literal quoting, and ID/IP helpers", () => {
  it("emits | head BEFORE | table, quotes filters via literal(), and excludes forbidden fields", () => {
    for (const target of ["f5_ltm", "aws_alb", "aws_nlb", "aws_elb"] as const) {
      const spl = buildLbHealthSearch({
        index: target === "f5_ltm" ? "f5" : "aws",
        target,
        filter: {
          src: "198.51.100.10",
          dst: "10.40.1.15",
          device: "203.0.113.80",
        },
        maxRows: 256,
      });
      const headIdx = spl.indexOf("| head 257");
      const tableIdx = spl.indexOf("| table ");
      expect(headIdx).toBeGreaterThan(0);
      expect(tableIdx).toBeGreaterThan(headIdx);
      if (target === "f5_ltm") {
        const rexIdx = spl.indexOf("| rex ");
        const evalIdx = spl.indexOf("| eval ");
        expect(rexIdx).toBeGreaterThan(0);
        expect(evalIdx).toBeGreaterThan(rexIdx);
        expect(headIdx).toBeGreaterThan(evalIdx);
        expect(spl).toContain("req_elapsed_time");
      }
      // No post-| head | where clause that could mask row capping
      expect(spl.slice(headIdx)).not.toMatch(/\|\s*where\b/i);
      expect(() =>
        assertNoForbiddenFieldsInSpl("lb_health", spl),
      ).not.toThrow();
      for (const bad of FORBIDDEN_SENSITIVE_FIELDS) {
        expect(spl.toLowerCase()).not.toContain(` ${bad}`);
      }
      expect(spl.toLowerCase()).not.toContain("user_id");
    }
  });

  it("builds literal()-quoted raw events URL and safe row IDs without ->", () => {
    const url = buildLbHealthRawEventsUrl({
      index: "f5",
      sourcetypes: ["f5:bigip:ltm:http:irule", "f5:bigip:ltm:lb:failed:irule"],
      vip: "203.0.113.80",
      memberIp: "10.40.1.15",
      earliest: EARLIEST,
      latest: NOW,
    });
    expect(url).toContain("/app/splunk_adm/search?");
    const decoded = decodeURIComponent(url);
    expect(decoded).toContain("index=f5");
    expect(decoded).toContain('vip="203.0.113.80"');
    expect(decoded).toContain('node="10.40.1.15"');

    const longId = makeLbHealthRowId(
      "aws_alb",
      "app/very-long-application-load-balancer-name-in-us-east-2/50dc6c495c0c9188",
      "arn:aws:elasticloadbalancing:us-east-2:123456789012:targetgroup/atlas-web-production/73e2d6bc24d8a067",
      "2001:0db8:85a3:0000:0000:8a2e:0370:7334:8443",
    );
    expect(longId).toMatch(/^[A-Za-z0-9._:/-]{1,128}$/);
    expect(longId).not.toContain("->");
  });

  it("preserves IPv4 and IPv6 addresses in shortenDeviceLabel and strips F5 route domains", () => {
    expect(shortenDeviceLabel("203.0.113.80")).toBe("203.0.113.80");
    expect(shortenDeviceLabel("2001:db8::1")).toBe("2001:db8::1");
    expect(shortenDeviceLabel("bigip-01.dc1.example")).toBe("bigip-01");
    expect(normalizeLbIp("10.40.1.15%2")).toBe("10.40.1.15");
    expect(normalizeLbIp("0:0:0:0:0:FFFF:0A28:010F")).toBe("10.40.1.15");
  });
});

describe("Error classification and grounded fixture correlation", () => {
  it("splits F5 LB_FAILED vs backend 5xx, ALB balancer vs target 5xx, and NLB TLS failures accurately", () => {
    // F5 LB_FAILED (SC4S sourcetype) -> balancer error
    const sc4sFailed = normalizeLbHealthRow({
      _time: EARLIEST + 10,
      host: "bigip-01",
      sourcetype: "f5:bigip:ltm:failed:irule",
      f5_irule: "Splunk-iRule-LB_FAILED",
      vip: "10.60.0.10%2",
      pool: "/Tenant/pool_api",
    })!;
    expect(sc4sFailed.errorSide).toBe("balancer");
    expect(sc4sFailed.isLbFailed).toBe(true);
    expect(sc4sFailed.vip).toBe("10.60.0.10");

    // F5 backend 503 with member -> target error (prefers req_elapsed_time)
    const f5TargetErr = normalizeLbHealthRow({
      _time: EARLIEST + 20,
      host: "bigip-01",
      sourcetype: "f5:bigip:ltm:http:irule",
      f5_irule: "Splunk-iRule-HTTP",
      vip: "203.0.113.80",
      pool: "/Common/pool_web",
      node: "10.40.1.15",
      node_port: 8080,
      http_status: 503,
      req_elapsed_time: 18,
    })!;
    expect(f5TargetErr.errorSide).toBe("target");
    expect(f5TargetErr.latencyMs).toBe(18);

    // ALB 503 with target_status_code="-" -> balancer error
    const albBal503 = normalizeLbHealthRow({
      _time: EARLIEST + 30,
      host: "aws-ta-hf",
      sourcetype: "aws:alb:accesslogs",
      elb: "app/atlas-web/50dc6c495c0c9188",
      target_group: "atlas-web",
      elb_status_code: 503,
      target_status_code: "-",
      error_reason: "NoHealthyTargets",
    })!;
    expect(albBal503.errorSide).toBe("balancer");

    // ALB 504 with target_status_code=200 and error_reason=TargetTimeout -> balancer error
    const albBalTimeout = normalizeLbHealthRow({
      _time: EARLIEST + 40,
      host: "aws-ta-hf",
      sourcetype: "aws:elb:accesslogs",
      elb: "app/atlas-web/50dc6c495c0c9188",
      target_group: "atlas-web",
      target_ip: "10.40.1.21",
      target_port: 8443,
      elb_status_code: 504,
      target_status_code: 200,
      error_reason: "TargetTimeout",
      request_processing_time: 0.008,
      target_processing_time: 0.61,
      response_processing_time: 0.002,
    })!;
    expect(albBalTimeout.errorSide).toBe("balancer");
    expect(albBalTimeout.latencyMs).toBeCloseTo(620, 3);

    // ALB 502 with target_status_code=502 -> target error
    const albTarget502 = normalizeLbHealthRow({
      _time: EARLIEST + 50,
      host: "aws-ta-hf",
      sourcetype: "aws:alb:accesslogs",
      elb: "app/atlas-web/50dc6c495c0c9188",
      target_group: "atlas-web",
      target_ip: "10.40.1.21",
      target_port: 8443,
      elb_status_code: 502,
      target_status_code: 502,
      error_reason: "-",
    })!;
    expect(albTarget502.errorSide).toBe("target");

    // NLB TLS healthy uses handshake_time_ms (not connection_time_ms) for SLA latency
    const nlbHealthy = normalizeLbHealthRow({
      _time: EARLIEST + 60,
      host: "aws-ta-hf",
      sourcetype: "aws:elb:accesslogs",
      elb: "net/atlas-tls/c6e77e28c25b2234",
      listener: "g3d4b5e8bb8464cd",
      dest_ip: "203.0.113.90",
      connection_time_ms: 10000,
      handshake_time_ms: 2,
      tls_alert: "-",
      verify_status: "Success",
    })!;
    expect(nlbHealthy.errorSide).toBe("none");
    expect(nlbHealthy.latencyMs).toBe(2);
    expect(nlbHealthy.connectionTimeMs).toBe(10000);

    // NLB TLS failure -> balancer error
    const nlbFailed = normalizeLbHealthRow({
      _time: EARLIEST + 70,
      host: "aws-ta-hf",
      sourcetype: "aws:nlb:accesslogs",
      elb: "net/atlas-tls/c6e77e28c25b2234",
      listener: "g3d4b5e8bb8464cd",
      dest_ip: "203.0.113.90",
      connection_time_ms: 15,
      handshake_time_ms: 12,
      tls_alert: "bad_certificate",
      verify_status: "Failed:CertExpired",
    })!;
    expect(nlbFailed.errorSide).toBe("balancer");
    expect(nlbFailed.isNlbTlsFailure).toBe(true);
  });

  it("analyzes grounded F5, ALB, and NLB fixtures into verdict, KPIs, DistributionBar, HeatMatrix, and Timeline", () => {
    const f5Lines = readFileSync(
      "fixtures/protocols/lb_health/f5_ltm_irule.ndjson",
      "utf8",
    )
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l) as Record<string, unknown>);
    const awsLines = readFileSync(
      "fixtures/protocols/lb_health/aws_alb_nlb.ndjson",
      "utf8",
    )
      .trim()
      .split("\n")
      .map((l) => JSON.parse(l) as Record<string, unknown>);

    const events = [
      ...f5Lines.map((r) => ({
        event: normalizeLbHealthRow(r, "f5_ltm")!,
        indexName: "f5",
      })),
      ...awsLines.map((r) => ({
        event: normalizeLbHealthRow(r)!,
        indexName: "aws",
      })),
    ];

    const result = buildLbHealthAnalysis({
      events,
      thresholds: resolveLbHealthThresholds(),
      earliest: EARLIEST,
      latest: NOW,
      outcomes: [
        { source: "protocol_lb_health", profile: "lb-prod", state: "complete" },
      ],
      capped: false,
    });

    expect(result.verdictStatus).toBe("attention");
    expect(result.verdict).toContain("balancer vs");
    expect(result.verdict).toContain("F5 LB_FAILED");
    expect(result.verdict).toContain("NLB TLS");
    expect(result.kpis).toHaveLength(4);
    expect(result.kpis.map((k) => k.id)).toEqual([
      "requests",
      "balancer-errors",
      "target-errors",
      "latency-p95",
    ]);
    expect(result.kpis[0].value).toBe("14");
    expect(result.kpis[0].unit).toBe("reqs");
    expect(result.kpis[1].value).toBe("5");
    expect(result.kpis[1].unit).toBe("balancer errs");
    expect(result.kpis[2].value).toBe("3");
    expect(result.kpis[2].unit).toBe("target errs");
    expect(result.kpis[3].value).toBe("840 ms");
    expect(result.kpis[3].unit).toBeUndefined();
    expect(result.matrixCells.every((c) => !c.value.includes("1 reqs"))).toBe(
      true,
    );
    expect(result.matrixCells.some((c) => c.value.includes("Target 5xx"))).toBe(
      true,
    );

    expect(result.distribution.map((d) => d.label)).toEqual([
      "Balancer Errors",
      "Target Errors",
      "Healthy",
    ]);

    for (const row of result.rows) {
      expect(row.id).toMatch(/^[A-Za-z0-9._:/-]{1,128}$/);
      expect(row.id).not.toContain("->");
    }

    // Healthy F5 member 10.40.1.16:8080 and ALB target 10.40.1.20:8443 sort after flagged rows
    const flaggedCount = result.rows.filter((r) => r.attention).length;
    expect(flaggedCount).toBe(7);
    expect(result.rows.length).toBe(9);
    expect(result.rows.slice(flaggedCount).every((r) => !r.attention)).toBe(
      true,
    );

    expect(result.matrixRows.length).toBeGreaterThanOrEqual(4);
    expect(result.matrixCells.some((c) => c.value.includes("LB_FAILED"))).toBe(
      true,
    );
    expect(result.matrixCells.some((c) => c.value.includes("TLS fail"))).toBe(
      true,
    );
    expect(result.timelineEvents.length).toBe(8);
  });

  it("keeps NLB TLS targetErrorsCovered false even when target_ip is present and formats Latency p95 honestly", () => {
    const nlbWithTargetIp = normalizeLbHealthRow({
      _time: EARLIEST + 60,
      host: "aws-ta-hf",
      sourcetype: "aws:nlb:accesslogs",
      elb: "net/atlas-tls/c6e77e28c25b2234",
      listener: "g3d4b5e8bb8464cd",
      dest_ip: "203.0.113.90",
      target_ip: "10.40.3.10",
      target_port: 8443,
      tls_alert: "-",
      verify_status: "Success",
    })!;
    expect(nlbWithTargetIp.memberIp).toBe("10.40.3.10");

    const completeNoLatency = buildLbHealthAnalysis({
      events: [{ event: nlbWithTargetIp, indexName: "aws" }],
      thresholds: resolveLbHealthThresholds(),
      earliest: EARLIEST,
      latest: NOW,
      outcomes: [
        { source: "protocol_lb_health", profile: "lb-prod", state: "complete" },
      ],
      capped: false,
    });
    expect(completeNoLatency.hasTargetTelemetry).toBe(false);
    expect(completeNoLatency.rows[0].targetErrorsCovered).toBe(false);
    expect(
      completeNoLatency.kpis.find((k) => k.id === "target-errors"),
    ).toMatchObject({
      value: "Not covered",
      status: "not_covered",
    });
    expect(
      completeNoLatency.distribution.find((d) => d.id === "target-errors")
        ?.status,
    ).toBe("not_covered");
    expect(
      completeNoLatency.kpis.find((k) => k.id === "latency-p95"),
    ).toMatchObject({
      value: "Not covered",
      status: "not_covered",
    });

    const cappedNoLatency = buildLbHealthAnalysis({
      events: [{ event: nlbWithTargetIp, indexName: "aws" }],
      thresholds: resolveLbHealthThresholds(),
      earliest: EARLIEST,
      latest: NOW,
      outcomes: [
        {
          source: "protocol_lb_health",
          profile: "lb-prod",
          state: "partial",
          capped: true,
        },
      ],
      capped: true,
    });
    expect(
      cappedNoLatency.kpis.find((k) => k.id === "latency-p95"),
    ).toMatchObject({
      value: "Unknown",
      status: "unknown",
    });

    // Latency p95 >= 1000 ms uses formatDurationMs (e.g. "1.42 s")
    const f5Slow = normalizeLbHealthRow({
      _time: EARLIEST + 10,
      host: "bigip-01",
      sourcetype: "f5:bigip:ltm:http:irule",
      f5_irule: "Splunk-iRule-HTTP",
      vip: "203.0.113.80",
      pool: "/Common/pool_web",
      node: "10.40.1.16",
      node_port: 8080,
      http_status: 200,
      req_elapsed_time: 1420,
    })!;
    const slowRes = buildLbHealthAnalysis({
      events: [{ event: f5Slow, indexName: "f5" }],
      thresholds: resolveLbHealthThresholds(),
      earliest: EARLIEST,
      latest: NOW,
      outcomes: [
        { source: "protocol_lb_health", profile: "lb-prod", state: "complete" },
      ],
      capped: false,
    });
    expect(slowRes.kpis.find((k) => k.id === "latency-p95")).toMatchObject({
      value: "1.42 s",
      status: "attention",
    });

    // Matrix uses singular "1 req" for a single healthy request
    const singleHealthy = normalizeLbHealthRow({
      _time: EARLIEST + 10,
      host: "bigip-01",
      sourcetype: "f5:bigip:ltm:http:irule",
      f5_irule: "Splunk-iRule-HTTP",
      vip: "203.0.113.80",
      pool: "/Common/pool_web",
      node: "10.40.1.16",
      node_port: 8080,
      http_status: 200,
      req_elapsed_time: 20,
    })!;
    const singleMatrixRes = buildLbHealthAnalysis({
      events: [{ event: singleHealthy, indexName: "f5" }],
      thresholds: resolveLbHealthThresholds(),
      earliest: EARLIEST,
      latest: NOW,
      outcomes: [
        { source: "protocol_lb_health", profile: "lb-prod", state: "complete" },
      ],
      capped: false,
    });
    expect(singleMatrixRes.matrixCells[0].value).toBe("1 req");
  });

  it("rejects multivalue/injected F5 rows and prevents LB_FAILED from pinning failures onto an injected node", () => {
    const multivalueNode = normalizeLbHealthRow({
      _time: EARLIEST + 10,
      host: "bigip-01",
      sourcetype: "f5:bigip:ltm:http:irule",
      f5_irule: "Splunk-iRule-HTTP",
      vip: "203.0.113.80",
      pool: "/Common/pool_web",
      node: ["198.51.100.99", "10.40.1.16"],
      node_port: 8080,
      http_status: 200,
      req_elapsed_time: 12,
    });
    expect(multivalueNode).toBeUndefined();

    const embeddedKv = normalizeLbHealthRow({
      _time: EARLIEST + 10,
      host: "bigip-01",
      sourcetype: "f5:bigip:ltm:http:irule",
      f5_irule: "Splunk-iRule-HTTP",
      vip: "203.0.113.80",
      virtual_server: "/Common/pool_web,node=198.51.100.99",
      http_status: 200,
    });
    expect(embeddedKv).toBeUndefined();

    const lbFailedWithInjectedNode = normalizeLbHealthRow({
      _time: EARLIEST + 15,
      host: "bigip-01",
      sourcetype: "f5:bigip:ltm:lb:failed:irule",
      f5_irule: "Splunk-iRule-LB_FAILED",
      vip: "203.0.113.80",
      pool: "/Common/pool_web",
      node: "10.40.1.99",
      node_port: 8080,
      http_status: 503,
      req_elapsed_time: 999,
      bytes_out: 1024,
    })!;
    expect(lbFailedWithInjectedNode).toBeDefined();
    expect(lbFailedWithInjectedNode.isLbFailed).toBe(true);
    expect(lbFailedWithInjectedNode.memberIp).toBeUndefined();
    expect(lbFailedWithInjectedNode.memberPort).toBeUndefined();
    expect(lbFailedWithInjectedNode.balancerStatusCode).toBeUndefined();
    expect(lbFailedWithInjectedNode.targetStatusCode).toBeUndefined();
    expect(lbFailedWithInjectedNode.latencyMs).toBeUndefined();
    expect(lbFailedWithInjectedNode.bytesOut).toBe(0);

    const analysis = buildLbHealthAnalysis({
      events: [{ event: lbFailedWithInjectedNode, indexName: "f5" }],
      thresholds: resolveLbHealthThresholds(),
      earliest: EARLIEST,
      latest: NOW,
      outcomes: [
        { source: "protocol_lb_health", profile: "lb-prod", state: "complete" },
      ],
      capped: false,
    });
    expect(analysis.rows[0].memberIp).toBeUndefined();
    expect(analysis.rows[0].memberLabel).toBe("No member (LB_FAILED)");
  });
});

describe("investigateLbHealth & summarizeLbHealth", () => {
  it("reports unknown/unavailable (never none_observed) when Splunk returns rows that all fail normalization", async () => {
    const client: SearchClient = {
      search: vi.fn().mockResolvedValue({
        rows: [
          {
            _time: EARLIEST + 10,
            sourcetype: "f5:bigip:ltm:http:irule",
            f5_irule: "Splunk-iRule-HTTP",
            vip: "203.0.113.80",
            pool: "/Common/pool_web",
            node: ["198.51.100.99", "10.40.1.16"],
            http_status: ["503", "200"],
          },
          {
            _time: EARLIEST + 20,
            sourcetype: "f5:bigip:ltm:http:irule",
            f5_irule: "Splunk-iRule-HTTP",
            vip: "203.0.113.80",
            pool: "/Common/pool_web,node=198.51.100.99",
          },
        ],
        warnings: [],
        errors: [],
      }),
    };

    const result = await investigateLbHealth(
      client,
      makeRequest(),
      makeConfig([makeProfile({ extra: { sourceKind: "f5_ltm" } })]),
      new AbortController().signal,
      { skipConfigRecheck: true },
    );

    expect(result.verdictStatus).toBe("unknown");
    expect(result.coverageStatus).toBe("unknown");
    expect(result.bannerState).toBe("unavailable");
    expect(result.bannerReason).toBe(
      "2 rows returned but could not be normalized",
    );
  });
  it("downgrades capped-empty and blocked-empty to unknown (never none_observed)", async () => {
    const cappedEmpty = await summarizeLbHealth(
      {
        search: vi.fn().mockResolvedValue({
          rows: [],
          truncated: true,
          warnings: [],
          errors: [],
        }),
      },
      makeRequest(),
      makeConfig([makeProfile({ extra: { sourceKind: "f5_ltm" } })]),
      new AbortController().signal,
      { skipConfigRecheck: true },
    );
    expect(cappedEmpty.status).toBe("unknown");
    expect(cappedEmpty.capped).toBe(true);

    const blockedEmpty = await investigateLbHealth(
      {
        search: vi.fn().mockRejectedValue(new SearchAccessDeniedError()),
      },
      makeRequest(),
      makeConfig([makeProfile({ extra: { sourceKind: "aws_alb" } })]),
      new AbortController().signal,
      { skipConfigRecheck: true },
    );
    expect(blockedEmpty.verdictStatus).toBe("unknown");
    expect(blockedEmpty.coverageStatus).toBe("unknown");
    expect(blockedEmpty.bannerState).toBe("blocked");
  });

  it("downgrades healthy summary when a sibling source is blocked and strips sensitive fields", async () => {
    const search = vi
      .fn()
      .mockResolvedValueOnce({
        rows: [
          {
            _time: EARLIEST + 10,
            sourcetype: "f5:bigip:ltm:http:irule",
            f5_irule: "Splunk-iRule-HTTP",
            vip: "203.0.113.80",
            pool: "/Common/pool_web",
            node: "10.40.1.16",
            node_port: 8080,
            http_status: 200,
            time_taken: 25,
            _raw: "secret",
            cookie: "session=secret",
            uri_query: "token=secret",
            user_id: "alice",
            authorization: "Bearer secret",
          },
        ],
        warnings: [],
        errors: [],
      })
      .mockRejectedValueOnce(new SearchAccessDeniedError());

    const summary = await summarizeLbHealth(
      { search },
      makeRequest(),
      makeConfig([makeProfile({ extra: { sourceKind: "auto" } })]),
      new AbortController().signal,
      { skipConfigRecheck: true },
    );
    expect(summary.status).toBe("attention");

    const full = await investigateLbHealth(
      {
        search: vi.fn().mockResolvedValue({
          rows: [
            {
              _time: EARLIEST + 10,
              sourcetype: "f5:bigip:ltm:http:irule",
              f5_irule: "Splunk-iRule-HTTP",
              vip: "203.0.113.80",
              pool: "/Common/pool_web",
              node: "10.40.1.16",
              node_port: 8080,
              http_status: 200,
              time_taken: 25,
              _raw: "secret",
              cookie: "session=secret",
              uri_query: "token=secret",
              user_id: "alice",
              authorization: "Bearer secret",
            },
          ],
          warnings: [],
          errors: [],
        }),
      },
      makeRequest(),
      makeConfig([makeProfile({ extra: { sourceKind: "f5_ltm" } })]),
      new AbortController().signal,
      { skipConfigRecheck: true },
    );
    expect(full.verdictStatus).toBe("ok");
    expect(JSON.stringify(full)).not.toContain("secret");
    expect(JSON.stringify(full)).not.toContain("alice");
  });

  it("enforces stale-config recheck with profileValidators and supports AbortSignal", async () => {
    const client: SearchClient = {
      search: vi.fn().mockResolvedValue({
        rows: [
          {
            _time: EARLIEST + 10,
            sourcetype: "f5:bigip:ltm:http:irule",
            f5_irule: "Splunk-iRule-HTTP",
            vip: "203.0.113.80",
            pool: "/Common/pool_web",
            node: "10.40.1.16",
            node_port: 8080,
            http_status: 200,
            time_taken: 25,
          },
        ],
        warnings: [],
        errors: [],
      }),
    };
    const profile = makeProfile({ extra: { sourceKind: "f5_ltm" } });
    const spy = vi
      .spyOn(protocolConfigClient, "readProtocolProfileDocument")
      .mockResolvedValue({ version: 1, profiles: [profile] });

    try {
      const config = await import("../../shared/runner").then((m) =>
        m.readProtocolConfiguration({ lb_health: validateLbHealthExtra }),
      );
      const okSummary = await summarizeLbHealth(
        client,
        makeRequest(),
        config,
        new AbortController().signal,
        { profileValidators: { lb_health: validateLbHealthExtra } },
      );
      expect(okSummary.status).toBe("ok");

      spy.mockResolvedValueOnce({
        version: 1,
        profiles: [
          makeProfile({
            index: "other_lb",
            extra: { sourceKind: "f5_ltm" },
          }),
        ],
      });
      const stale = await investigateLbHealth(
        client,
        makeRequest(),
        config,
        new AbortController().signal,
        { profileValidators: { lb_health: validateLbHealthExtra } },
      );
      expect(stale.bannerState).toBe("stale_config");
      expect(stale.rows).toEqual([]);
    } finally {
      spy.mockRestore();
    }

    const controller = new AbortController();
    const abortClient: SearchClient = {
      search: vi.fn().mockImplementation(() => {
        controller.abort();
        return Promise.reject(new DOMException("Aborted", "AbortError"));
      }),
    };
    await expect(
      investigateLbHealth(
        abortClient,
        makeRequest(),
        makeConfig([profile]),
        controller.signal,
        { skipConfigRecheck: true },
      ),
    ).rejects.toThrow();
  });
});
