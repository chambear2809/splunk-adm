import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import type { SearchClient } from "../../../data/searchClient";
import type {
  BaseProtocolProfile,
  ProtocolConfiguration,
} from "../../shared/contract";
import {
  TcpTlsLensPage,
  buildTcpTlsAnalysis,
  normalizeTcpTlsRow,
  resolveTcpTlsThresholds,
  type TcpTlsInvestigationResult,
} from "./index";

const NOW = 1800000500;
const EARLIEST = 1800000000;

const PROFILE: BaseProtocolProfile = {
  id: "tcp-dc1",
  source: "protocol_tcp_tls",
  lens: "tcp_tls",
  scope: "prod:dc1",
  index: "stream_tcp",
  observer: "stream-fwd-01",
  validFrom: EARLIEST - 3600,
  validUntil: NOW + 3600,
};

const CONFIG: ProtocolConfiguration = {
  profiles: [PROFILE],
  fingerprint: "fp-test",
};

function sampleTcpResult(): TcpTlsInvestigationResult {
  const events = [
    {
      event: normalizeTcpTlsRow(
        {
          _time: EARLIEST + 60,
          host: "stream-fwd-01",
          sourcetype: "stream:tcp",
          src_ip: "198.18.38.11",
          dest_ip: "198.18.38.21",
          dest_port: 443,
          client_rtt: 14200,
          server_rtt: 68400,
          packets_in: 400,
          packets_out: 100,
          bytes_in: 512000,
          bytes_out: 12800,
          retransmits: 24,
          tcp_status: 4,
          tls_version: "TLSv1.2",
          ssl_cipher: "ECDHE-RSA-AES128-GCM-SHA256",
          ssl_cert_subject: "CN=orders.internal.example",
          ssl_issuer: "CN=Corp Internal CA",
          ssl_cert_days_remaining: 9,
          sni: "orders.internal.example",
        },
        "stream:tcp",
        NOW,
      )!,
      indexName: "stream_tcp",
    },
    {
      event: normalizeTcpTlsRow(
        {
          _time: EARLIEST + 120,
          host: "stream-fwd-01",
          sourcetype: "stream:tcp",
          src_ip: "198.18.38.10",
          dest_ip: "198.18.38.20",
          dest_port: 443,
          client_rtt: 4200,
          server_rtt: 11800,
          packets_in: 24,
          packets_out: 16,
          bytes_in: 18400,
          bytes_out: 4200,
          tcp_status: 0,
          tls_version: "TLSv1.3",
          ssl_cipher: "TLS_AES_256_GCM_SHA384",
          ssl_cert_subject: "CN=api.internal.example",
          ssl_issuer: "CN=Corp Internal CA",
          ssl_cert_days_remaining: 180,
        },
        "stream:tcp",
        NOW,
      )!,
      indexName: "stream_tcp",
    },
    {
      event: normalizeTcpTlsRow(
        {
          _time: EARLIEST + 180,
          host: "stream-fwd-01",
          sourcetype: "stream:tcp",
          src_ip: "10.64.9.50",
          dest_ip: "198.18.38.30",
          dest_port: 5432,
          client_rtt: 1800,
          server_rtt: 3400,
          packets_in: 64,
          packets_out: 24,
          bytes_in: 64000,
          bytes_out: 8200,
          tcp_status: 0,
        },
        "stream:tcp",
        NOW,
      )!,
      indexName: "stream_tcp",
    },
  ];

  return buildTcpTlsAnalysis({
    events,
    thresholds: resolveTcpTlsThresholds(PROFILE),
    earliest: EARLIEST,
    latest: NOW,
    outcomes: [
      { source: "protocol_tcp_tls", profile: "tcp-dc1", state: "complete" },
    ],
    capped: false,
  });
}

const noop = () => undefined;

describe("TcpTlsLensPage", () => {
  it("never auto-searches or checks Stream mode on mount", () => {
    const search = vi.fn();
    const client: SearchClient = { search };
    const html = renderToStaticMarkup(
      <TcpTlsLensPage
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
    expect(html).toContain("TCP Health &amp; TLS");
    expect(html).toContain("Investigate");
    expect(html).toContain("Not checked");
    expect(search).not.toHaveBeenCalled();
  });

  it("renders unavailable banner when no profile covers the scope", () => {
    const html = renderToStaticMarkup(
      <TcpTlsLensPage
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
    const initial = sampleTcpResult();
    const html = renderToStaticMarkup(
      <TcpTlsLensPage
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
    expect(html).toContain("Server RTT p95");
    expect(html).toContain("Max Retransmit");
    expect(html).toContain("TCP Resets");
    expect(html).toContain("TLS Issues");
    // Overview hides healthy rows behind "Show all (3)" when flagged rows exist
    expect(html).toContain("198.18.38.11");
    expect(html).not.toContain("198.18.38.10");
    expect(html).toContain("Show all (3)");
    expect(html).toContain('data-testid="protocol-distribution-bar"');
  });

  it("renders Matrix view with none_observed when complete and unknown when capped", () => {
    const initial = sampleTcpResult();
    const completeHtml = renderToStaticMarkup(
      <TcpTlsLensPage
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
    expect(completeHtml).toContain("198.18.38.11 to 198.18.38.21");

    const cappedHtml = renderToStaticMarkup(
      <TcpTlsLensPage
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

  it("renders Detail Drawer for TLS pair with safe raw events link and for non-TLS pair with Not covered", () => {
    const initial = sampleTcpResult();
    const tlsDrawerHtml = renderToStaticMarkup(
      <TcpTlsLensPage
        live
        scope="prod:dc1"
        scopes={["prod:dc1"]}
        earliest={EARLIEST}
        latest={NOW}
        view="overview"
        selectedItem="198.18.38.11__198.18.38.21"
        configuration={CONFIG}
        initialResult={initial}
        onChangeParams={noop}
        onBackToHub={noop}
        onRefreshConfig={noop}
      />,
    );
    expect(tlsDrawerHtml).toContain('data-testid="protocol-detail-drawer"');
    expect(tlsDrawerHtml).toContain("ECDHE-RSA-AES128-GCM-SHA256");
    expect(tlsDrawerHtml).toContain("CN=orders.internal.example");
    expect(tlsDrawerHtml).toContain("CN=Corp Internal CA");
    expect(tlsDrawerHtml).toContain("9d");
    expect(tlsDrawerHtml).toContain("/app/splunk_adm/search?");
    expect(tlsDrawerHtml).toContain("pl-kv-list");

    const nonTlsDrawerHtml = renderToStaticMarkup(
      <TcpTlsLensPage
        live
        scope="prod:dc1"
        scopes={["prod:dc1"]}
        earliest={EARLIEST}
        latest={NOW}
        view="overview"
        selectedItem="10.64.9.50__198.18.38.30"
        configuration={CONFIG}
        initialResult={initial}
        onChangeParams={noop}
        onBackToHub={noop}
        onRefreshConfig={noop}
      />,
    );
    expect(nonTlsDrawerHtml).toContain('data-testid="protocol-detail-drawer"');
    expect(nonTlsDrawerHtml).toContain("Not covered");
  });

  it("renders Estimate-mode and Empty state banners with explicit Check Stream mode button", () => {
    const estimateResult = buildTcpTlsAnalysis({
      events: [],
      thresholds: resolveTcpTlsThresholds(PROFILE),
      earliest: EARLIEST,
      latest: NOW,
      outcomes: [{ source: "protocol_tcp_tls", state: "complete" }],
      capped: false,
      streamReadiness: {
        streamId: "tcp",
        state: "estimate_only",
        detail: "Stream is in Estimate mode (statsOnly=true).",
      },
    });
    const html = renderToStaticMarkup(
      <TcpTlsLensPage
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

  it("renders NetFlow-only fallback without fake RTT or TLS and keeps chrome under 60 words", () => {
    const nfResult = buildTcpTlsAnalysis({
      events: [
        {
          event: normalizeTcpTlsRow(
            {
              _time: EARLIEST + 30,
              host: "stream-hf-01",
              sourcetype: "stream:netflow",
              exporter_ip: "198.18.131.1",
              src_ip: "198.18.38.10",
              dest_ip: "198.18.38.20",
              total_bytes: 22600,
              total_packets: 40,
            },
            "stream:netflow",
            NOW,
          )!,
          indexName: "netflow",
        },
      ],
      thresholds: resolveTcpTlsThresholds(PROFILE),
      earliest: EARLIEST,
      latest: NOW,
      outcomes: [
        { source: "protocol_tcp_tls", profile: "tcp-dc1", state: "complete" },
      ],
      capped: false,
    });
    const html = renderToStaticMarkup(
      <TcpTlsLensPage
        live
        scope="prod:dc1"
        scopes={["prod:dc1"]}
        earliest={EARLIEST}
        latest={NOW}
        view="overview"
        configuration={CONFIG}
        initialResult={nfResult}
        onChangeParams={noop}
        onBackToHub={noop}
        onRefreshConfig={noop}
      />,
    );
    expect(html).toContain("NetFlow fallback only");
    expect(html).toContain("Not covered");
    expect(html).not.toContain('data-testid="protocol-distribution-bar"');

    // Measure chrome words using the same rule as tests/browser/protocols.spec.ts
    const overviewHtml = renderToStaticMarkup(
      <TcpTlsLensPage
        live
        scope="prod:dc1"
        scopes={["prod:dc1"]}
        earliest={EARLIEST}
        latest={NOW}
        view="overview"
        configuration={CONFIG}
        initialResult={sampleTcpResult()}
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
