import { readFileSync } from "node:fs";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import type { SearchClient } from "../../../data/searchClient";
import type {
  BaseProtocolProfile,
  ProtocolConfiguration,
} from "../../shared/contract";
import {
  LbHealthLensPage,
  buildLbHealthAnalysis,
  normalizeLbHealthRow,
  resolveLbHealthThresholds,
  type LbHealthInvestigationResult,
} from "./index";

const EARLIEST = 1764246500;
const NOW = 1764247100;

const PROFILE: BaseProtocolProfile = {
  id: "lb-prod",
  source: "protocol_lb_health",
  lens: "lb_health",
  scope: "prod:us-east",
  index: "lb_logs",
  observer: "bigip-01",
  validFrom: EARLIEST - 3600,
  validUntil: NOW + 3600,
};

const CONFIG: ProtocolConfiguration = {
  profiles: [PROFILE],
  fingerprint: "fp-test",
};

function sampleLbHealthResult(): LbHealthInvestigationResult {
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

  return buildLbHealthAnalysis({
    events,
    thresholds: resolveLbHealthThresholds(PROFILE),
    earliest: EARLIEST,
    latest: NOW,
    outcomes: [
      { source: "protocol_lb_health", profile: "lb-prod", state: "complete" },
    ],
    capped: false,
  });
}

const noop = () => undefined;

describe("LbHealthLensPage", () => {
  it("never auto-searches on mount", () => {
    const search = vi.fn();
    const client: SearchClient = { search };
    const html = renderToStaticMarkup(
      <LbHealthLensPage
        client={client}
        live
        scope="prod:us-east"
        scopes={["prod:us-east"]}
        earliest={EARLIEST}
        latest={NOW}
        view="overview"
        configuration={CONFIG}
        onChangeParams={noop}
        onBackToHub={noop}
        onRefreshConfig={noop}
      />,
    );
    expect(html).toContain("Load Balancer Pool Health");
    expect(html).toContain("Investigate");
    expect(html).toContain("Not checked");
    expect(search).not.toHaveBeenCalled();
  });

  it("renders unavailable banner when no profile covers the scope", () => {
    const html = renderToStaticMarkup(
      <LbHealthLensPage
        live
        scope="prod:eu-west"
        scopes={["prod:eu-west"]}
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

  it("renders Overview with verdict, 4 KPIs, DistributionBar, flagged-first 8-col table, Timeline, and <60 chrome words", () => {
    const initial = sampleLbHealthResult();
    const html = renderToStaticMarkup(
      <LbHealthLensPage
        live
        scope="prod:us-east"
        scopes={["prod:us-east"]}
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
    expect(html).toContain("7 of 9 members need attention");
    expect(html.match(/data-testid="protocol-kpi-tile"/g)?.length).toBe(4);
    expect(html).toContain("Requests");
    expect(html).toContain("Balancer Errors");
    expect(html).toContain("Target Errors");
    expect(html).toContain("Latency p95");
    expect(html).toContain('data-testid="protocol-distribution-bar"');
    expect(html).toContain('data-testid="protocol-timeline"');
    expect(html).toContain("Show all (9)");
    expect(html).toContain("Balancer errors");
    expect(html).toContain("Target errors");

    // Healthy members sit behind "Show all (9)"
    const tablePart = html.split("Show all (9)")[0];
    expect(tablePart).toContain("10.40.1.15");
    expect(tablePart).not.toContain("10.40.1.16");

    // NLB listener row marks Target Errs as Not covered
    expect(tablePart).toContain("Not covered");

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

  it("renders Matrix view with None observed when complete and Unknown when capped or partial", () => {
    const initial = sampleLbHealthResult();
    const completeHtml = renderToStaticMarkup(
      <LbHealthLensPage
        live
        scope="prod:us-east"
        scopes={["prod:us-east"]}
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
    expect(completeHtml).toContain("203.0.113.80");
    expect(completeHtml).toContain("LB_FAILED (1)");
    expect(completeHtml).toContain("None observed");

    const cappedHtml = renderToStaticMarkup(
      <LbHealthLensPage
        live
        scope="prod:us-east"
        scopes={["prod:us-east"]}
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

    const partialHtml = renderToStaticMarkup(
      <LbHealthLensPage
        live
        scope="prod:us-east"
        scopes={["prod:us-east"]}
        earliest={EARLIEST}
        latest={NOW}
        view="matrix"
        configuration={CONFIG}
        initialResult={{
          ...initial,
          bannerState: "partial",
          bannerReason: "Access denied for one source.",
        }}
        onChangeParams={noop}
        onBackToHub={noop}
        onRefreshConfig={noop}
      />,
    );
    expect(partialHtml).toContain("Unknown");
  });

  it("renders Detail Drawer with Status first, CopyableIp, error split, error_reason/TLS details, and literal raw link", () => {
    const initial = sampleLbHealthResult();
    const albTimeoutRow = initial.rows.find(
      (r) => r.family === "aws_alb" && r.memberIp === "10.40.1.21",
    )!;
    const albDrawer = renderToStaticMarkup(
      <LbHealthLensPage
        live
        scope="prod:us-east"
        scopes={["prod:us-east"]}
        earliest={EARLIEST}
        latest={NOW}
        view="overview"
        selectedItem={albTimeoutRow.id}
        configuration={CONFIG}
        initialResult={initial}
        onChangeParams={noop}
        onBackToHub={noop}
        onRefreshConfig={noop}
      />,
    );
    expect(albDrawer).toContain('data-testid="protocol-detail-drawer"');
    expect(albDrawer).toContain("<dt>Status</dt>");
    expect(albDrawer).toContain("Copy member 10.40.1.21");
    expect(albDrawer).toContain("Balancer errors:");
    expect(albDrawer).toContain("Target errors:");
    expect(albDrawer).toContain("error_reason: TargetTimeout");
    expect(albDrawer).toContain("TLSv1.2 · ECDHE-RSA-AES128-GCM-SHA256");
    expect(albDrawer).toContain("/app/splunk_adm/search?");

    const nlbRow = initial.rows.find((r) => r.family === "aws_nlb")!;
    const nlbDrawer = renderToStaticMarkup(
      <LbHealthLensPage
        live
        scope="prod:us-east"
        scopes={["prod:us-east"]}
        earliest={EARLIEST}
        latest={NOW}
        view="overview"
        selectedItem={nlbRow.id}
        configuration={CONFIG}
        initialResult={initial}
        onChangeParams={noop}
        onBackToHub={noop}
        onRefreshConfig={noop}
      />,
    );
    expect(nlbDrawer).toContain("tls_alert: bad_certificate");
    expect(nlbDrawer).toContain("verify_status: Failed:CertExpired");
    expect(nlbDrawer).toContain("NLB TLS omits target status");
    expect(nlbDrawer).toContain("Not covered");
    expect(nlbDrawer).not.toContain("Target errors: 0");
  });

  it("renders Not covered (and NOT 0 target errors) in both table and drawer for NLB TLS rows with target_ip", () => {
    const nlbWithTargetEvent = normalizeLbHealthRow({
      _time: EARLIEST + 60,
      host: "aws-ta-hf",
      sourcetype: "aws:nlb:accesslogs",
      elb: "net/atlas-tls/c6e77e28c25b2234",
      listener: "g3d4b5e8bb8464cd",
      dest_ip: "203.0.113.90",
      target_ip: "10.40.3.10",
      target_port: 8443,
      handshake_time_ms: 4,
      tls_alert: "handshake_failure",
      verify_status: "Failed:Handshake",
    })!;

    const result = buildLbHealthAnalysis({
      events: [{ event: nlbWithTargetEvent, indexName: "aws" }],
      thresholds: resolveLbHealthThresholds(PROFILE),
      earliest: EARLIEST,
      latest: NOW,
      outcomes: [
        { source: "protocol_lb_health", profile: "lb-prod", state: "complete" },
      ],
      capped: false,
    });

    const html = renderToStaticMarkup(
      <LbHealthLensPage
        live
        scope="prod:us-east"
        scopes={["prod:us-east"]}
        earliest={EARLIEST}
        latest={NOW}
        view="overview"
        selectedItem={result.rows[0].id}
        configuration={CONFIG}
        initialResult={result}
        onChangeParams={noop}
        onBackToHub={noop}
        onRefreshConfig={noop}
      />,
    );

    expect(html).toContain("10.40.3.10");
    expect(html).not.toContain("Target errors: 0");
    const matches = html.match(/Not covered/g) ?? [];
    expect(matches.length).toBeGreaterThanOrEqual(3);
  });
});
