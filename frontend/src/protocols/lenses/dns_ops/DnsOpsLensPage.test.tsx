import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import type { SearchClient } from "../../../data/searchClient";
import type {
  BaseProtocolProfile,
  ProtocolConfiguration,
} from "../../shared/contract";
import {
  DnsOpsLensPage,
  buildDnsOpsAnalysis,
  normalizeDnsOpsRow,
  resolveDnsOpsThresholds,
  type DnsOpsInvestigationResult,
} from "./index";

const NOW = 1800000500;
const EARLIEST = 1800000000;

const PROFILE: BaseProtocolProfile = {
  id: "dns-dc1",
  source: "protocol_dns_ops",
  lens: "dns_ops",
  scope: "prod:dc1",
  index: "stream_dns",
  observer: "stream-fwd-01",
  validFrom: EARLIEST - 3600,
  validUntil: NOW + 3600,
};

const CONFIG: ProtocolConfiguration = {
  profiles: [PROFILE],
  fingerprint: "fp-test",
};

function sampleDnsResult(): DnsOpsInvestigationResult {
  const events = [
    {
      event: normalizeDnsOpsRow(
        {
          _time: EARLIEST + 30,
          host: "stream-sensor-01",
          sourcetype: "stream:dns",
          src_ip: "10.10.20.12",
          dest_ip: "10.10.10.53",
          query: "payments-api.prod.internal",
          query_type: "A",
          reply_code: "ServFail",
          reply_code_id: 2,
          response_time: 142000,
        },
        "stream:dns",
      )!,
      indexName: "stream_dns",
    },
    {
      event: normalizeDnsOpsRow(
        {
          _time: EARLIEST + 60,
          host: "stream-sensor-01",
          sourcetype: "stream:dns",
          src_ip: "10.10.20.12",
          dest_ip: "10.10.10.53",
          query: "auth.prod.internal",
          query_type: "A",
          reply_code: "NoError",
          reply_code_id: 0,
          response_time: 64000,
          host_addr: ["10.96.20.10"],
        },
        "stream:dns",
      )!,
      indexName: "stream_dns",
    },
    {
      event: normalizeDnsOpsRow(
        {
          _time: EARLIEST + 90,
          host: "stream-sensor-01",
          sourcetype: "stream:dns",
          src_ip: "10.10.20.12",
          dest_ip: "10.10.10.53",
          query: "auth.prod.internal",
          query_type: "A",
          reply_code: "NoError",
          reply_code_id: 0,
          response_time: 61000,
          host_addr: ["10.96.20.11"],
        },
        "stream:dns",
      )!,
      indexName: "stream_dns",
    },
    {
      event: normalizeDnsOpsRow(
        {
          _time: EARLIEST + 120,
          host: "stream-sensor-01",
          sourcetype: "stream:dns",
          src_ip: "10.10.20.11",
          dest_ip: "10.10.10.53",
          query: "orders.prod.internal",
          query_type: "A",
          reply_code: "NoError",
          reply_code_id: 0,
          response_time: 4200,
          host_addr: ["10.96.12.40"],
        },
        "stream:dns",
      )!,
      indexName: "stream_dns",
    },
    {
      event: normalizeDnsOpsRow(
        {
          _time: EARLIEST + 180,
          host: "stream-sensor-02",
          sourcetype: "stream:dns",
          src_ip: "10.10.20.16",
          dest_ip: "10.10.10.54",
          query: "checkout.prod.internal",
          query_type: "A",
          reply_code: "NoError",
          reply_code_id: 0,
          response_time: 3100,
          host_addr: ["10.96.14.8"],
        },
        "stream:dns",
      )!,
      indexName: "stream_dns",
    },
  ];

  return buildDnsOpsAnalysis({
    events,
    thresholds: resolveDnsOpsThresholds(PROFILE),
    earliest: EARLIEST,
    latest: NOW,
    outcomes: [
      { source: "protocol_dns_ops", profile: "dns-dc1", state: "complete" },
    ],
    capped: false,
  });
}

const noop = () => undefined;

describe("DnsOpsLensPage", () => {
  it("never auto-searches or checks Stream mode on mount", () => {
    const search = vi.fn();
    const client: SearchClient = { search };
    const html = renderToStaticMarkup(
      <DnsOpsLensPage
        client={client}
        live
        scope="prod:dc1"
        scopes={["prod:dc1"]}
        earliest={EARLIEST}
        latest={NOW}
        view="overview"
        configuration={CONFIG}
        onChangeParams={noop}
        onBackToHub={noop}
        onRefreshConfig={noop}
      />,
    );
    expect(html).toContain("DNS Operations");
    expect(html).toContain("Investigate");
    expect(html).toContain("Not checked");
    expect(search).not.toHaveBeenCalled();
  });

  it("renders unavailable banner when no profile covers the scope", () => {
    const html = renderToStaticMarkup(
      <DnsOpsLensPage
        live
        scope="prod:dc2"
        scopes={["prod:dc2"]}
        earliest={EARLIEST}
        latest={NOW}
        view="overview"
        configuration={CONFIG}
        onChangeParams={noop}
        onBackToHub={noop}
        onRefreshConfig={noop}
      />,
    );
    expect(html).toContain('data-testid="protocol-state-unavailable"');
    expect(html).toContain("Not covered");
  });

  it("renders Overview with single-sentence verdict, <=4 KPIs, <=8 columns, flagged-first rows, and DistributionBar", () => {
    const initial = sampleDnsResult();
    const html = renderToStaticMarkup(
      <DnsOpsLensPage
        live
        scope="prod:dc1"
        scopes={["prod:dc1"]}
        earliest={EARLIEST}
        latest={NOW}
        view="overview"
        configuration={CONFIG}
        initialResult={initial}
        onChangeParams={noop}
        onBackToHub={noop}
        onRefreshConfig={noop}
      />,
    );
    expect(html).toContain('data-testid="protocol-verdict"');
    expect(html).toContain("1 of 3 pairs need attention");
    expect(html.match(/data-testid="protocol-kpi-tile"/g)?.length).toBe(4);
    expect(html).toContain("Resolver Latency p95");
    expect(html).toContain("SERVFAIL Rate");
    expect(html).toContain("NXDOMAIN Rate");
    expect(html).toContain("Flagged Pairs");
    expect(html).toContain("10.10.20.12");
    expect(html).not.toContain("10.10.20.11");
    expect(html).toContain("Show all (3)");
    expect(html).toContain('data-testid="protocol-distribution-bar"');
  });

  it("renders Matrix view with none_observed when complete and unknown when capped", () => {
    const initial = sampleDnsResult();
    const completeHtml = renderToStaticMarkup(
      <DnsOpsLensPage
        live
        scope="prod:dc1"
        scopes={["prod:dc1"]}
        earliest={EARLIEST}
        latest={NOW}
        view="matrix"
        configuration={CONFIG}
        initialResult={initial}
        onChangeParams={noop}
        onBackToHub={noop}
        onRefreshConfig={noop}
      />,
    );
    expect(completeHtml).toContain('data-testid="protocol-heat-matrix"');
    expect(completeHtml).toContain("None observed");
    expect(completeHtml).toContain("33.3% SERVFAIL");
    expect(completeHtml).toContain("10.10.20.12 to 10.10.10.53");

    const cappedHtml = renderToStaticMarkup(
      <DnsOpsLensPage
        live
        scope="prod:dc1"
        scopes={["prod:dc1"]}
        earliest={EARLIEST}
        latest={NOW}
        view="matrix"
        configuration={CONFIG}
        initialResult={{ ...initial, capped: true }}
        onChangeParams={noop}
        onBackToHub={noop}
        onRefreshConfig={noop}
      />,
    );
    expect(cappedHtml).toContain("Unknown");
  });

  it("renders Detail Drawer with Status first, CopyableIp, failing domains, churn, Exceptions, and safe raw events link", () => {
    const initial = sampleDnsResult();
    const drawerHtml = renderToStaticMarkup(
      <DnsOpsLensPage
        live
        scope="prod:dc1"
        scopes={["prod:dc1"]}
        earliest={EARLIEST}
        latest={NOW}
        view="overview"
        selectedItem="10.10.20.12__10.10.10.53"
        configuration={CONFIG}
        initialResult={initial}
        onChangeParams={noop}
        onBackToHub={noop}
        onRefreshConfig={noop}
      />,
    );
    expect(drawerHtml).toContain('data-testid="protocol-detail-drawer"');
    expect(drawerHtml).toContain("<dt>Status</dt>");
    expect(drawerHtml).toContain("Copy client 10.10.20.12");
    expect(drawerHtml).toContain("Copy resolver 10.10.10.53");
    expect(drawerHtml).toContain("payments-api.prod.internal (SERVFAIL × 1)");
    expect(drawerHtml).toContain("1 domain (auth.prod.internal (2 answers))");
    expect(drawerHtml).toContain("pl-kv-list");
    expect(drawerHtml).toContain("/app/splunk_adm/search?");
  });

  it("renders Estimate-mode banner with explicit Re-check Stream mode button", () => {
    const estimateResult = buildDnsOpsAnalysis({
      events: [],
      thresholds: resolveDnsOpsThresholds(PROFILE),
      earliest: EARLIEST,
      latest: NOW,
      outcomes: [{ source: "protocol_dns_ops", state: "complete" }],
      capped: false,
      streamReadiness: {
        streamId: "dns",
        state: "estimate_only",
        detail: "Stream is in Estimate mode (statsOnly=true).",
      },
    });
    const html = renderToStaticMarkup(
      <DnsOpsLensPage
        client={{ search: vi.fn() }}
        live
        scope="prod:dc1"
        scopes={["prod:dc1"]}
        earliest={EARLIEST}
        latest={NOW}
        view="overview"
        configuration={CONFIG}
        initialResult={estimateResult}
        onChangeParams={noop}
        onBackToHub={noop}
        onRefreshConfig={noop}
      />,
    );
    expect(html).toContain('data-testid="protocol-state-estimate_only"');
    expect(html).toContain("Re-check Stream mode");
  });

  it("renders Hubble-only fallback without fake latency and keeps chrome under 60 words", () => {
    const hubbleResult = buildDnsOpsAnalysis({
      events: [
        {
          event: normalizeDnsOpsRow(
            {
              _time: EARLIEST + 30,
              host: "k8s-node-a",
              sourcetype: "cilium:hubble:flow",
              src_ip: "10.42.0.15",
              dest_ip: "10.96.0.10",
              message_type: "RESPONSE",
              "flow.l7.dns.query": "orders.prod.svc.cluster.local",
              "flow.l7.dns.rcode": 0,
              "flow.l7.dns.ips": ["10.96.12.40"],
            },
            "cilium:hubble:flow",
          )!,
          indexName: "cilium_hubble",
        },
      ],
      thresholds: resolveDnsOpsThresholds(PROFILE),
      earliest: EARLIEST,
      latest: NOW,
      outcomes: [
        {
          source: "protocol_dns_ops",
          profile: "hubble-dc1",
          state: "complete",
        },
      ],
      capped: false,
    });
    const html = renderToStaticMarkup(
      <DnsOpsLensPage
        live
        scope="prod:dc1"
        scopes={["prod:dc1"]}
        earliest={EARLIEST}
        latest={NOW}
        view="overview"
        configuration={CONFIG}
        initialResult={hubbleResult}
        onChangeParams={noop}
        onBackToHub={noop}
        onRefreshConfig={noop}
      />,
    );
    expect(html).toContain("Hubble DNS L7 fallback only");
    expect(html).toContain("Not covered");
    expect(html).not.toContain('data-testid="protocol-distribution-bar"');

    // Measure chrome words using the same rule as tests/browser/protocols.spec.ts
    const overviewHtml = renderToStaticMarkup(
      <DnsOpsLensPage
        live
        scope="prod:dc1"
        scopes={["prod:dc1"]}
        earliest={EARLIEST}
        latest={NOW}
        view="overview"
        configuration={CONFIG}
        initialResult={sampleDnsResult()}
        onChangeParams={noop}
        onBackToHub={noop}
        onRefreshConfig={noop}
      />,
    );
    const stripped = overviewHtml
      .replace(/<svg[\s\S]*?<\/svg>/g, " ")
      .replace(
        /<([a-z0-9-]+)[^>]*data-pl-data="true"[^>]*>[\s\S]*?<\/\1>/g,
        " ",
      )
      .replace(/<span class="atlas-visually-hidden">[^<]*<\/span>/g, " ")
      .replace(/<[^>]+>/g, " ")
      .replace(/&amp;/g, "&")
      .trim();
    const words = stripped.split(/\s+/).filter(Boolean);
    expect(words.length).toBeLessThan(60);
  });
});
