import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import type { SearchClient } from "../../../data/searchClient";
import type {
  BaseProtocolProfile,
  ProtocolConfiguration,
} from "../../shared/contract";
import {
  AppTransactionsLensPage,
  buildAppTransactionsAnalysis,
  normalizeAppTransactionRow,
  resolveAppTransactionsThresholds,
  type AppTransactionsInvestigationResult,
} from "./index";

const EARLIEST = 1764246500;
const NOW = 1764247100;

const PROFILE: BaseProtocolProfile = {
  id: "app-txns-dc1",
  source: "protocol_app_transactions",
  lens: "app_transactions",
  scope: "prod:dc1",
  index: "stream_app",
  observer: "stream-fwd-01",
  validFrom: EARLIEST - 3600,
  validUntil: NOW + 3600,
};

const CONFIG: ProtocolConfiguration = {
  profiles: [PROFILE],
  fingerprint: "fp-test",
};

function sampleAppTransactionsResult(): AppTransactionsInvestigationResult {
  const events = [
    {
      event: normalizeAppTransactionRow(
        {
          _time: EARLIEST + 20,
          host: "stream-fwd-01",
          sourcetype: "stream:http",
          src_ip: "10.42.0.20",
          dest_ip: "10.42.0.30",
          dest_port: 8080,
          http_method: "POST",
          status: 503,
          uri_path: "/api/v1/checkout?token=secret",
          site: "checkout.shop.internal",
          time_taken: 840_000,
          bytes_in: 620,
          bytes_out: 240,
        },
        "http",
      )!,
      indexName: "stream_app",
    },
    {
      event: normalizeAppTransactionRow(
        {
          _time: EARLIEST + 60,
          host: "stream-fwd-01",
          sourcetype: "stream:http",
          src_ip: "10.42.0.21",
          dest_ip: "10.42.0.30",
          dest_port: 8080,
          http_method: "GET",
          status: 200,
          uri_path: "/api/v1/checkout",
          site: "checkout.shop.internal",
          time_taken: 120_000,
          bytes_in: 240,
          bytes_out: 1420,
        },
        "http",
      )!,
      indexName: "stream_app",
    },
    {
      event: normalizeAppTransactionRow(
        {
          _time: EARLIEST + 90,
          host: "stream-fwd-01",
          sourcetype: "stream:postgres",
          src_ip: "10.42.0.30",
          dest_ip: "10.42.0.50",
          dest_port: 5432,
          dbname: "orders_db",
          sql_error_code: "40001",
          time_taken: 680_000,
          result_row_count: 0,
          bytes_in: 300,
          bytes_out: 140,
        },
        "db",
      )!,
      indexName: "stream_app",
    },
    {
      event: normalizeAppTransactionRow(
        {
          _time: EARLIEST + 140,
          host: "stream-fwd-01",
          sourcetype: "stream:mysql",
          src_ip: "10.42.0.32",
          dest_ip: "10.42.0.51",
          dest_port: 3306,
          dbname: "inventory_db",
          sql_error_code: "0",
          time_taken: 24_000,
          result_row_count: 14,
          bytes_in: 180,
          bytes_out: 1280,
        },
        "db",
      )!,
      indexName: "stream_app",
    },
  ];

  return buildAppTransactionsAnalysis({
    events,
    thresholds: resolveAppTransactionsThresholds(PROFILE),
    earliest: EARLIEST,
    latest: NOW,
    outcomes: [
      {
        source: "protocol_app_transactions",
        profile: "app-txns-dc1",
        state: "complete",
      },
    ],
    capped: false,
    httpConfigured: true,
    dbConfigured: true,
  });
}

const noop = () => undefined;

describe("AppTransactionsLensPage", () => {
  it("never auto-searches or checks Stream mode on mount", () => {
    const search = vi.fn();
    const client: SearchClient = { search };
    const html = renderToStaticMarkup(
      <AppTransactionsLensPage
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
    expect(html).toContain("HTTP &amp; DB Transactions");
    expect(html).toContain("Investigate");
    expect(html).toContain("Not checked");
    expect(search).not.toHaveBeenCalled();
  });

  it("renders unavailable banner when no profile covers the scope", () => {
    const html = renderToStaticMarkup(
      <AppTransactionsLensPage
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

  it("renders Overview with verdict, 4 KPIs, DistributionBar, SwimlaneTimeline, flagged-first table, and <60 chrome words", () => {
    const initial = sampleAppTransactionsResult();
    const html = renderToStaticMarkup(
      <AppTransactionsLensPage
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
    expect(html).toContain("2 of 3 services need attention");
    expect(html.match(/data-testid="protocol-kpi-tile"/g)?.length).toBe(4);
    expect(html).toContain("Transactions");
    expect(html).toContain("Error Rate");
    expect(html).toContain("p95 Latency");
    expect(html).toContain("Flagged Services");
    expect(html).toContain("Show all (3)");
    // Healthy MySQL 10.42.0.51 sits behind "Show all (3)"
    const tablePart = html.split("Show all (3)")[0];
    expect(tablePart).toContain("10.42.0.30");
    expect(tablePart).toContain("10.42.0.50");
    expect(tablePart).not.toContain("10.42.0.51");
    expect(html).toContain('data-testid="protocol-distribution-bar"');
    expect(html).toContain('data-testid="protocol-timeline"');
    expect(html).toContain("HTTP 503");
    expect(html).toContain("SQL error 40001");
    expect(html).not.toContain("token=secret");

    const stripped = html
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

  it("renders Not covered status chips in table columns when status or latency is missing", () => {
    const partialTelemetry = buildAppTransactionsAnalysis({
      events: [
        {
          event: normalizeAppTransactionRow(
            {
              _time: EARLIEST + 30,
              host: "stream-fwd-01",
              sourcetype: "stream:http",
              src_ip: "10.42.0.20",
              dest_ip: "10.42.0.32",
              dest_port: 8080,
              http_method: "GET",
              uri_path: "/healthz",
            },
            "http",
          )!,
          indexName: "stream_app",
        },
      ],
      thresholds: resolveAppTransactionsThresholds(PROFILE),
      earliest: EARLIEST,
      latest: NOW,
      outcomes: [{ source: "protocol_app_transactions", state: "complete" }],
      capped: false,
      httpConfigured: true,
      dbConfigured: false,
    });

    const html = renderToStaticMarkup(
      <AppTransactionsLensPage
        live
        scope="prod:dc1"
        scopes={["prod:dc1"]}
        earliest={EARLIEST}
        latest={NOW}
        view="overview"
        configuration={CONFIG}
        initialResult={partialTelemetry}
        onChangeParams={noop}
        onBackToHub={noop}
        onRefreshConfig={noop}
      />,
    );
    expect(html).toContain("Not covered");
    expect(html).not.toContain('data-testid="protocol-timeline"');
  });

  it("renders Matrix view with Client x Server, none_observed when complete and unknown when capped or partial", () => {
    const initial = sampleAppTransactionsResult();
    const completeHtml = renderToStaticMarkup(
      <AppTransactionsLensPage
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
    expect(completeHtml).toContain("10.42.0.20");
    expect(completeHtml).toContain("10.42.0.30:8080");
    expect(completeHtml).toContain("None observed");

    const cappedHtml = renderToStaticMarkup(
      <AppTransactionsLensPage
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

  it("renders Detail Drawer with Status first, sanitized uri_path, privacy note, CopyableIp, and literal raw events link", () => {
    const initial = sampleAppTransactionsResult();
    const httpRow = initial.rows.find((r) => r.serverIp === "10.42.0.30")!;
    const httpDrawerHtml = renderToStaticMarkup(
      <AppTransactionsLensPage
        live
        scope="prod:dc1"
        scopes={["prod:dc1"]}
        earliest={EARLIEST}
        latest={NOW}
        view="overview"
        selectedItem={httpRow.id}
        configuration={CONFIG}
        initialResult={initial}
        onChangeParams={noop}
        onBackToHub={noop}
        onRefreshConfig={noop}
      />,
    );
    expect(httpDrawerHtml).toContain('data-testid="protocol-detail-drawer"');
    expect(httpDrawerHtml).toContain("<dt>Status</dt>");
    expect(httpDrawerHtml).toContain("Copy server 10.42.0.30");
    expect(httpDrawerHtml).toContain("Copy client 10.42.0.20");
    expect(httpDrawerHtml).toContain("/api/v1/checkout");
    expect(httpDrawerHtml).not.toContain("token=secret");
    expect(httpDrawerHtml).toContain("SQL query text, bind values");
    expect(httpDrawerHtml).toContain("/app/splunk_adm/search?");

    const dbRow = initial.rows.find((r) => r.serverIp === "10.42.0.50")!;
    const dbDrawerHtml = renderToStaticMarkup(
      <AppTransactionsLensPage
        live
        scope="prod:dc1"
        scopes={["prod:dc1"]}
        earliest={EARLIEST}
        latest={NOW}
        view="overview"
        selectedItem={dbRow.id}
        configuration={CONFIG}
        initialResult={initial}
        onChangeParams={noop}
        onBackToHub={noop}
        onRefreshConfig={noop}
      />,
    );
    expect(dbDrawerHtml).toContain("orders_db");
    expect(dbDrawerHtml).toContain("40001");
  });

  it("renders Estimate-mode banner with explicit Re-check Stream mode button and empty banner with Check Stream mode", () => {
    const estimateResult = buildAppTransactionsAnalysis({
      events: [],
      thresholds: resolveAppTransactionsThresholds(PROFILE),
      earliest: EARLIEST,
      latest: NOW,
      outcomes: [{ source: "protocol_app_transactions", state: "complete" }],
      capped: false,
      streamReadiness: [
        {
          streamId: "http",
          state: "estimate_only",
          detail: "Stream http is in Estimate mode (statsOnly=true).",
        },
      ],
    });
    const estimateHtml = renderToStaticMarkup(
      <AppTransactionsLensPage
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
    expect(estimateHtml).toContain(
      'data-testid="protocol-state-estimate_only"',
    );
    expect(estimateHtml).toContain("Re-check Stream mode");

    const emptyResult = buildAppTransactionsAnalysis({
      events: [],
      thresholds: resolveAppTransactionsThresholds(PROFILE),
      earliest: EARLIEST,
      latest: NOW,
      outcomes: [{ source: "protocol_app_transactions", state: "complete" }],
      capped: false,
      httpConfigured: true,
      dbConfigured: true,
    });
    const emptyHtml = renderToStaticMarkup(
      <AppTransactionsLensPage
        client={{ search: vi.fn() }}
        live
        scope="prod:dc1"
        scopes={["prod:dc1"]}
        earliest={EARLIEST}
        latest={NOW}
        view="overview"
        configuration={CONFIG}
        initialResult={emptyResult}
        onChangeParams={noop}
        onBackToHub={noop}
        onRefreshConfig={noop}
      />,
    );
    expect(emptyHtml).toContain('data-testid="protocol-state-empty"');
    expect(emptyHtml).toContain("Check Stream mode");
  });
});
