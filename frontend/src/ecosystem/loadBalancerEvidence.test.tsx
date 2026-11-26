import { readFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import {
  ALB_PATTERN,
  ALB_QUOTE_COUNTS,
  AWS_ELB_ACCESS,
  F5_IRULE_PATTERN,
  F5_LTM_HTTP,
  F5_QUOTE_COUNT,
  LB_LATE_LOG_SECONDS,
  NLB_PATTERN,
  buildLoadBalancerSearch,
  f5ZoneOffset,
  loadLoadBalancerEvidence,
  loadBalancerSearchWindow,
  normalizeLoadBalancerEvidence,
  type LoadBalancerContract,
} from "./loadBalancerEvidence";
import type { EvidenceSelection } from "../data/evidence";
import type {
  EvidenceConfigClient,
  SupplementalSourceConfiguration,
} from "../data/evidenceConfig";
import type { SearchClient } from "../data/searchClient";
import type { Row } from "../rows";
import { LoadBalancerResultView } from "./LoadBalancerEvidencePanel";

interface Envelope {
  time: number;
  host: string;
  index: string;
  sourcetype: string;
  event: string;
}
function envelopes(name: string): Envelope[] {
  return readFileSync(
    new URL(`../../../fixtures/raw-ecosystem/${name}`, import.meta.url),
    "utf8",
  )
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line) as Envelope);
}

const quotes = (raw: string) => raw.split('"').length - 1;
const socketIp = (value?: string) =>
  value ? /^\[?([0-9A-Fa-f:.]{2,45}?)\]?:\d{1,5}$/.exec(value)?.[1] : undefined;

/** The SPL projection: the same patterns, run as `rex`, plus the parse predicate. */
function extract(contract: LoadBalancerContract, raw: string): Row {
  const row: Row = {};
  const patterns =
    contract === F5_LTM_HTTP ? [F5_IRULE_PATTERN] : [ALB_PATTERN, NLB_PATTERN];
  for (const pattern of patterns) {
    const groups = new RegExp(pattern).exec(raw)?.groups ?? {};
    for (const [key, value] of Object.entries(groups))
      if (value !== undefined && value !== "") row[key] = value;
  }
  const count = quotes(raw);
  let ok: boolean;
  if (contract === F5_LTM_HTTP)
    ok = row.f5_irule !== undefined && count === F5_QUOTE_COUNT;
  else {
    row.alb_client_ip = socketIp(row.alb_client as string);
    row.alb_target_ip = socketIp(row.alb_target as string);
    row.nlb_client_ip = socketIp(row.nlb_client as string);
    row.nlb_destination_ip = socketIp(row.nlb_destination as string);
    ok =
      (row.alb_type !== undefined &&
        row.nlb_version === undefined &&
        (ALB_QUOTE_COUNTS as readonly number[]).includes(count)) ||
      (row.nlb_version !== undefined && row.alb_type === undefined);
  }
  return { ...row, lb_parse_ok: ok ? "1" : "0" };
}

function project(
  contract: LoadBalancerContract,
  envelope: Envelope,
  overrides: Row = {},
): Row {
  return {
    ...extract(contract, envelope.event),
    host: envelope.host,
    index: envelope.index,
    sourcetype: envelope.sourcetype,
    event_fingerprint: (Math.round(envelope.time * 1000) % 65536)
      .toString(16)
      .padStart(64, "0"),
    event_time_epoch: String(envelope.time),
    _time: String(envelope.time),
    _indextime: String(Math.floor(envelope.time) + 2),
    kind: "supplemental_record",
    ...overrides,
  };
}

/** The SPL `where`: unparsed rows plus rows with a selected address in any address column. */
function scoped(
  contract: LoadBalancerContract,
  rows: Row[],
  addresses: string[],
): Row[] {
  return rows.filter(
    (row) =>
      row.lb_parse_ok === "0" ||
      contract.addressColumns.some((column) =>
        addresses.includes(String(row[column])),
      ),
  );
}

const BASE = Date.UTC(2026, 10, 26, 15, 0, 0) / 1000;
const selection = (addresses: string[]): EvidenceSelection => ({
  schemaVersion: 1,
  workflow: "endpoint",
  selectionId: "lb-test",
  trafficContract: 1,
  window: { start: BASE, end: BASE + 300 },
  scope: "prod",
  addresses,
  contexts: [],
  identityBasis: "scoped address",
  configurationFingerprint: "a".repeat(64),
});

function config(
  contract: LoadBalancerContract,
  host: string,
  index: string,
  overrides: Partial<SupplementalSourceConfiguration> = {},
): SupplementalSourceConfiguration {
  return {
    source: contract.source,
    state: "active",
    indexes: [index],
    authorities: [host],
    schemaQualified: true,
    staleAfterSeconds: 1800,
    mappings: [
      {
        observer_kind: contract.observerKind,
        observer: host,
        scope: "prod",
        cluster: "",
        mapping_status: "verified",
      },
    ],
    ...overrides,
  };
}
const F5_CONFIG = config(F5_LTM_HTTP, "bigip-01", "f5");
const AWS_CONFIG = config(AWS_ELB_ACCESS, "aws-ta-hf", "aws");

describe("load balancer search contract", () => {
  it("extracts the documented iRule keys itself and never projects client-controlled values", () => {
    const search = buildLoadBalancerSearch(
      F5_LTM_HTTP,
      F5_CONFIG,
      selection(["10.40.1.15"]),
    );
    expect(search).toContain(
      'search index=f5 sourcetype IN ("f5:bigip:ltm:http:irule","f5:bigip:ltm:lb:failed:irule","f5:bigip:ltm:failed:irule") host IN ("bigip-01")',
    );
    expect(search).toContain('| rex field=_raw "^(?:<\\d{1,3}>)?');
    expect(search).toContain('http_user_agent=\\"[^\\"]{0,8192}\\"');
    expect(search).toContain('cidrmatch("10.40.1.15/32",f5_node)');
    expect(search).toContain("where lb_parse_ok=0 OR (");
    expect(search).toContain("| head 10001");
    expect(search).toContain("| fields - _raw");
    const fieldsLine = search
      .split("\n")
      .find((line) => line.startsWith("| fields f5_"))!;
    expect(fieldsLine).not.toMatch(/user_agent|cookie|http_uri|\buser\b/);
  });

  it("matches ALB client, target and node addresses and NLB client and destination", () => {
    const search = buildLoadBalancerSearch(
      AWS_ELB_ACCESS,
      AWS_CONFIG,
      selection(["10.40.1.20"]),
    );
    expect(search).toContain('sourcetype IN ("aws:elb:accesslogs")');
    for (const column of [
      "alb_client_ip",
      "alb_target_ip",
      "alb_node_ip",
      "nlb_client_ip",
      "nlb_destination_ip",
    ])
      expect(search).toContain(`cidrmatch("10.40.1.20/32",${column})`);
    expect(search).toContain("elb_quotes=24 OR elb_quotes=30");
  });

  it("refuses inactive, unqualified, unverified or out-of-scope sources", () => {
    for (const bad of [
      { state: "staged" as const },
      { schemaQualified: false },
      { mappings: [{ ...F5_CONFIG.mappings[0], scope: "lab" }] },
      { mappings: [{ ...F5_CONFIG.mappings[0], observer_kind: "aws_elb" }] },
    ])
      expect(() =>
        buildLoadBalancerSearch(
          F5_LTM_HTTP,
          { ...F5_CONFIG, ...bad },
          selection(["10.40.1.15"]),
        ),
      ).toThrow();
  });

  it("extends dispatch past the selection for completion-time logs", () => {
    expect(loadBalancerSearchWindow(selection(["10.40.1.15"]))).toEqual({
      start: BASE,
      end: BASE + 300 + LB_LATE_LOG_SECONDS,
    });
  });
});

describe("F5 BIG-IP LTM iRule normalization", () => {
  const rows = envelopes("f5_ltm_http.ndjson").map((envelope) =>
    project(F5_LTM_HTTP, envelope),
  );

  it("keeps client→VIP and SNAT→pool member as separate legs, with the SNAT source not reported", () => {
    const { records, rejected } = normalizeLoadBalancerEvidence(
      F5_LTM_HTTP,
      scoped(F5_LTM_HTTP, rows, ["10.40.1.15"]),
      selection(["10.40.1.15"]),
      F5_CONFIG,
    );
    expect(rejected).toBe(1);
    expect(records.map((record) => record.recordType)).toEqual([
      "f5_http",
      "f5_http",
    ]);
    const [first, routeDomain] = records;
    expect(first.clientLeg).toEqual({
      source: {
        role: "client",
        ip: "198.51.100.10",
        notReported: "The iRule does not log the client port.",
      },
      destination: {
        role: "virtual_server_address",
        ip: "203.0.113.80",
        port: 443,
      },
    });
    expect(first.serverLeg).toMatchObject({
      source: { role: "load_balancer_source" },
      destination: { role: "pool_member", ip: "10.40.1.15", port: 8080 },
    });
    expect(
      "source" in first.serverLeg && first.serverLeg.source.ip,
    ).toBeUndefined();
    expect(first.balancer).toBe("/Common/pool_web");
    expect(first.inferredZoneOffsetSeconds).toBe(18000);
    expect(first.interval).toEqual({ start: BASE + 60, end: BASE + 61 });
    expect(first.matchedAddressFields).toEqual(["server_destination"]);
    expect(first.limitations).toContain("server_side_source_not_logged");
    expect(first.counters.basis).toContain("Content-Length");
    expect(routeDomain.clientLeg.destination).toMatchObject({
      ip: "10.60.0.10",
      port: 80,
      routeDomain: 2,
    });
    expect(routeDomain.status.server).toBe("503");
  });

  it("reports LB_FAILED with no server leg and flags a VIP-only match", () => {
    const { records } = normalizeLoadBalancerEvidence(
      F5_LTM_HTTP,
      scoped(F5_LTM_HTTP, rows, ["203.0.113.80"]),
      selection(["203.0.113.80"]),
      F5_CONFIG,
    );
    const failed = records.find(
      (record) => record.recordType === "f5_lb_failed",
    )!;
    expect(failed.outcome).toBe("lb_failed");
    expect(failed.serverLeg).toEqual({
      notReported:
        "Load balancing failed; no pool member connection was made or logged.",
    });
    expect(failed.limitations).toContain(
      "selected_address_matched_balancer_address_only",
    );
  });

  it("rejects an injected User-Agent instead of reading forged keys", () => {
    const injected = rows[3];
    expect(injected.lb_parse_ok).toBe("0");
    const { records, rejected } = normalizeLoadBalancerEvidence(
      F5_LTM_HTTP,
      [injected],
      selection(["10.40.1.15"]),
      F5_CONFIG,
    );
    expect(records).toEqual([]);
    expect(rejected).toBe(1);
  });

  it("infers only a quarter-hour zone offset with bounded transport delay", () => {
    expect(f5ZoneOffset(BASE + 18030, [BASE])).toBe(18000);
    expect(() => f5ZoneOffset(BASE + 18400, [BASE])).toThrow();
    expect(() => f5ZoneOffset(BASE + 15 * 3600, [BASE])).toThrow();
  });

  it("rejects wrong hosts, sourcetypes and mismatched message types", () => {
    const http = rows[0];
    for (const overrides of [
      { host: "bigip-02" },
      { sourcetype: "f5:bigip:syslog" },
      { f5_res_start: undefined },
      { _time: String(BASE + 9999), event_time_epoch: String(BASE + 9999) },
    ])
      expect(
        normalizeLoadBalancerEvidence(
          F5_LTM_HTTP,
          [{ ...http, ...overrides }],
          selection(["10.40.1.15"]),
          F5_CONFIG,
        ).rejected,
      ).toBe(1);
  });
});

describe("AWS ALB/NLB access-log normalization", () => {
  const rows = envelopes("aws_elb_access.ndjson").map((envelope) =>
    project(AWS_ELB_ACCESS, envelope),
  );

  it("parses 36- and 29-field ALB lines and the NLB TLS line", () => {
    expect(rows.map((row) => row.lb_parse_ok)).toEqual(["1", "1", "1", "1"]);
  });

  it("shows client→ALB node and ALB→target legs without inventing the ALB source", () => {
    const { records, rejected } = normalizeLoadBalancerEvidence(
      AWS_ELB_ACCESS,
      scoped(AWS_ELB_ACCESS, rows, ["10.40.1.20"]),
      selection(["10.40.1.20"]),
      AWS_CONFIG,
    );
    expect(rejected).toBe(0);
    expect(records).toHaveLength(2);
    const full = records.find((record) => record.eventTime < BASE + 100)!;
    expect(full.clientLeg).toMatchObject({
      source: { role: "client", ip: "198.51.100.10", port: 2817 },
      destination: { role: "load_balancer_node", ip: "10.0.0.5" },
    });
    expect(full.serverLeg).toMatchObject({
      source: {
        role: "load_balancer_source",
        notReported:
          "ALB access logs do not record the address the load balancer uses toward the target.",
      },
      destination: { role: "target", ip: "10.40.1.20", port: 8443 },
    });
    const legacy = records.find((record) => record !== full)!;
    expect(legacy.clientLeg.destination.ip).toBeUndefined();
    expect(legacy.limitations).toContain("load_balancer_node_not_logged");
  });

  it("reports a request that never reached a target and an NLB client leg only", () => {
    const { records } = normalizeLoadBalancerEvidence(
      AWS_ELB_ACCESS,
      scoped(AWS_ELB_ACCESS, rows, ["198.51.100.11", "198.51.100.10"]),
      selection(["198.51.100.11", "198.51.100.10"]),
      AWS_CONFIG,
    );
    const unrouted = records.find(
      (record) => record.outcome === "not_forwarded",
    )!;
    expect(unrouted.serverLeg).toEqual({
      notReported:
        "No target connection is logged for this request (target is '-').",
    });
    expect(unrouted.status.balancer).toBe("503");
    const nlb = records.find((record) => record.recordType === "nlb_tls")!;
    expect(nlb.clientLeg.destination).toMatchObject({
      role: "listener_or_endpoint",
      ip: "203.0.113.90",
      port: 443,
    });
    expect(nlb.serverLeg).toEqual({
      notReported:
        "NLB access logs cover TLS listeners only and do not report the target.",
    });
    expect(nlb.interval).toEqual({ start: BASE + 140, end: BASE + 150 });
  });

  it("rejects an extra quote, a time outside the request and unknown versions", () => {
    const [alb, , , nlb] = envelopes("aws_elb_access.ndjson");
    const quoted = project(AWS_ELB_ACCESS, {
      ...alb,
      event: alb.event.replace('"curl/8.5.0"', '"curl/"8.5.0"'),
    });
    expect(quoted.lb_parse_ok).toBe("0");
    const late = project(AWS_ELB_ACCESS, alb, {
      event_time_epoch: String(alb.time + 30),
    });
    const version = project(AWS_ELB_ACCESS, {
      ...nlb,
      event: nlb.event.replace("tls 3.0", "tls 2.0"),
    });
    expect(
      normalizeLoadBalancerEvidence(
        AWS_ELB_ACCESS,
        [quoted, late, version],
        selection(["198.51.100.10"]),
        AWS_CONFIG,
      ),
    ).toEqual({ records: [], rejected: 3 });
  });
});

describe("load balancer loader and presentation", () => {
  it("runs through the shared bounded loader and renders separate legs honestly", async () => {
    const rows = scoped(
      F5_LTM_HTTP,
      envelopes("f5_ltm_http.ndjson").map((envelope) =>
        project(F5_LTM_HTTP, envelope),
      ),
      ["10.40.1.15"],
    );
    const client: SearchClient = {
      search: vi.fn().mockResolvedValue({
        rows: [
          ...rows,
          {
            kind: "supplemental_completion",
            schema_version: "1",
            input_count: String(rows.length),
            returned_count: String(rows.length),
            input_capped: "0",
            oversized: "0",
          },
        ],
        warnings: [],
        errors: [],
      }),
    };
    const configurationClient: EvidenceConfigClient = {
      read: async () => ({
        fingerprint: "a".repeat(64),
        trafficContract: 1,
        summaryIndexes: ["adm_summary"],
        mappings: [],
        identities: [],
        identityAvailable: true,
        dns: [],
        supplemental: [structuredClone(F5_CONFIG)],
        maxAgeSeconds: 3600,
      }),
    };
    const result = await loadLoadBalancerEvidence(
      client,
      "f5_ltm_http",
      selection(["10.40.1.15"]),
      new AbortController().signal,
      configurationClient,
    );
    const [request] = vi.mocked(client.search).mock.calls[0];
    expect(request.optionalSource).toBe("f5_ltm_http");
    expect(request.latest).toBe(String(BASE + 300 + LB_LATE_LOG_SECONDS));
    expect(result.state).toBe("complete");
    expect(result.records).toHaveLength(2);
    expect(result.rejected).toBe(1);
    const html = renderToStaticMarkup(
      <LoadBalancerResultView
        label="F5 BIG-IP LTM request legs"
        result={{ ...result, schemaQualified: false }}
      />,
    );
    expect(html).toContain("producer schema is not qualified");
    expect(html).toContain("Virtual server address (balancer-owned)");
    expect(html).toContain("Pool member: 10.40.1.15:8080");
    expect(html).toContain("Balancer source: not reported");
    expect(html).toContain("not endpoint identity");
  });
});
