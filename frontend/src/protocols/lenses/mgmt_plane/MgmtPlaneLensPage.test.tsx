import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import type { SearchClient } from "../../../data/searchClient";
import type {
  BaseProtocolProfile,
  ProtocolConfiguration,
} from "../../shared/contract";
import {
  MgmtPlaneLensPage,
  buildMgmtPlaneAnalysis,
  normalizeMgmtPlaneRow,
  resolveMgmtPlaneThresholds,
  type MgmtPlaneInvestigationResult,
} from "./index";

const EARLIEST = 1764244700;
const NOW = 1764247100;

const PROFILE: BaseProtocolProfile = {
  id: "mgmt-dc1",
  source: "protocol_mgmt_plane",
  lens: "mgmt_plane",
  scope: "prod:dc1",
  index: "netflow",
  observer: "stream-fwd-01",
  validFrom: EARLIEST - 3600,
  validUntil: NOW + 3600,
};

const CONFIG: ProtocolConfiguration = {
  profiles: [PROFILE],
  fingerprint: "fp-test",
};

function sampleMgmtPlaneResult(): MgmtPlaneInvestigationResult {
  const events = [
    {
      event: normalizeMgmtPlaneRow(
        {
          _time: EARLIEST + 300,
          host: "stream-fwd-01",
          sourcetype: "stream:snmp",
          src_ip: "198.51.100.20",
          dest_ip: "192.0.2.12",
          dest_port: 161,
          snmp_version: "2c",
          pdu_type: "SetRequest",
          bytes_in: 128,
          bytes_out: 110,
        },
        "stream:snmp",
      )!,
      indexName: "netflow",
    },
    {
      event: normalizeMgmtPlaneRow(
        {
          _time: EARLIEST + 500,
          host: "stream-fwd-01",
          sourcetype: "stream:snmp",
          src_ip: "198.51.100.20",
          dest_ip: "192.0.2.10",
          dest_port: 161,
          snmp_version: "3",
          pdu_type: "GetRequest",
          bytes_in: 148,
          bytes_out: 312,
        },
        "stream:snmp",
      )!,
      indexName: "netflow",
    },
    {
      event: normalizeMgmtPlaneRow(
        {
          _time: EARLIEST + 700,
          host: "stream-fwd-01",
          sourcetype: "stream:ftp",
          src_ip: "198.51.100.30",
          dest_ip: "192.0.2.14",
          dest_port: 21,
          command: "RETR",
          reply_code: 226,
          bytes_out: 524288,
        },
        "stream:ftp",
      )!,
      indexName: "netflow",
    },
    {
      event: normalizeMgmtPlaneRow(
        {
          _time: EARLIEST + 900,
          host: "stream-fwd-01",
          sourcetype: "stream:netflow",
          exporter_ip: "192.0.2.1",
          src_ip: "198.51.100.40",
          dest_ip: "192.0.2.15",
          dest_port: 23,
          transport: "tcp",
          bytes: 4820,
          packets: 42,
        },
        "stream:netflow",
      )!,
      indexName: "netflow",
    },
    {
      event: normalizeMgmtPlaneRow(
        {
          _time: EARLIEST + 120,
          host: "leaf-02",
          sourcetype: "cisco:ios",
          category: "ETHPORT",
          facility: "ETHPORT",
        },
        "cisco:ios",
      )!,
      indexName: "cisco_dc",
    },
    {
      event: normalizeMgmtPlaneRow(
        {
          _time: EARLIEST + 2300,
          host: "spine-01",
          sourcetype: "cisco:ios",
          category: "BGP",
          facility: "BGP",
        },
        "cisco:ios",
      )!,
      indexName: "cisco_dc",
    },
  ];

  return buildMgmtPlaneAnalysis({
    events,
    thresholds: resolveMgmtPlaneThresholds(PROFILE),
    earliest: EARLIEST,
    latest: NOW,
    outcomes: [
      { source: "protocol_mgmt_plane", profile: "mgmt-dc1", state: "complete" },
    ],
    capped: false,
    snmpConfigured: true,
    ftpConfigured: true,
    netflowConfigured: true,
    syslogConfigured: true,
  });
}

const noop = () => undefined;

describe("MgmtPlaneLensPage", () => {
  it("never auto-searches or checks Stream mode on mount", () => {
    const search = vi.fn();
    const client: SearchClient = { search };
    const html = renderToStaticMarkup(
      <MgmtPlaneLensPage
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
    expect(html).toContain("Management-Plane Hygiene");
    expect(html).toContain("Investigate");
    expect(html).toContain("Not checked");
    expect(search).not.toHaveBeenCalled();
  });

  it("renders unavailable banner when no profile covers the scope", () => {
    const html = renderToStaticMarkup(
      <MgmtPlaneLensPage
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
    const initial = sampleMgmtPlaneResult();
    const html = renderToStaticMarkup(
      <MgmtPlaneLensPage
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
    expect(html).toContain("4 of 6 management items need attention");
    expect(html.match(/data-testid="protocol-kpi-tile"/g)?.length).toBe(4);
    expect(html).toContain("Hygiene Findings");
    expect(html).toContain("SNMPv1/v2c &amp; SET");
    expect(html).toContain("Cleartext Sessions");
    expect(html).toContain("Receipt Gaps");
    expect(html).toContain('data-testid="protocol-distribution-bar"');
    expect(html).toContain('data-testid="protocol-timeline"');
    expect(html).toContain("Receipt gap");
    expect(html).toContain("does not prove device down");
    expect(html).toContain("Show all (6)");

    // Healthy SNMPv3 192.0.2.10 sits behind "Show all (6)"
    const tablePart = html.split("Show all (6)")[0];
    expect(tablePart).toContain("192.0.2.12");
    expect(tablePart).toContain("1 session");
    expect(tablePart).not.toContain("192.0.2.10");

    // Measure chrome words using the same rule as tests/browser/protocols.spec.ts
    // (removing [data-pl-data="true"] subtrees including nested divs inside DistributionBar).
    const stripped = html
      .replace(/<svg[\s\S]*?<\/svg>/g, " ")
      .replace(
        /<div class="pl-dist-list" data-pl-data="true">[\s\S]*?<\/section>/g,
        "</section>",
      )
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

  it("renders Matrix view with none_observed when complete and unknown when capped or partial", () => {
    const initial = sampleMgmtPlaneResult();
    const completeHtml = renderToStaticMarkup(
      <MgmtPlaneLensPage
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
    expect(completeHtml).toContain("198.51.100.20");
    expect(completeHtml).toContain("192.0.2.12");
    expect(completeHtml).toContain("None observed");

    const cappedHtml = renderToStaticMarkup(
      <MgmtPlaneLensPage
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

    const partialHtml = renderToStaticMarkup(
      <MgmtPlaneLensPage
        live
        scope="prod:dc1"
        scopes={["prod:dc1"]}
        earliest={EARLIEST}
        latest={NOW}
        view="matrix"
        configuration={CONFIG}
        initialResult={{ ...initial, bannerState: "partial" }}
        onChangeParams={noop}
        onBackToHub={noop}
        onRefreshConfig={noop}
      />,
    );
    expect(partialHtml).toContain("Unknown");
  });

  it("renders Detail Drawer with Status first, CopyableIp, remediation, privacy notice, and raw events link", () => {
    const initial = sampleMgmtPlaneResult();
    const snmpRow = initial.rows.find((r) => r.targetDevice === "192.0.2.12")!;
    const drawerHtml = renderToStaticMarkup(
      <MgmtPlaneLensPage
        live
        scope="prod:dc1"
        scopes={["prod:dc1"]}
        earliest={EARLIEST}
        latest={NOW}
        view="overview"
        selectedItem={snmpRow.id}
        configuration={CONFIG}
        initialResult={initial}
        onChangeParams={noop}
        onBackToHub={noop}
        onRefreshConfig={noop}
      />,
    );
    expect(drawerHtml).toContain('data-testid="protocol-detail-drawer"');
    expect(drawerHtml).toContain("<dt>Status</dt>");
    expect(drawerHtml).toContain("Copy manager 198.51.100.20");
    expect(drawerHtml).toContain("Copy target 192.0.2.12");
    expect(drawerHtml).toContain("pl-kv-list");
    expect(drawerHtml).toContain("SNMPv3");
    expect(drawerHtml).toContain(
      "SNMP community strings and FTP credentials are never selected",
    );
    expect(drawerHtml).toContain("/app/splunk_adm/search?");

    const gapRow = initial.rows.find((r) => r.targetDevice === "leaf-02")!;
    const gapDrawerHtml = renderToStaticMarkup(
      <MgmtPlaneLensPage
        live
        scope="prod:dc1"
        scopes={["prod:dc1"]}
        earliest={EARLIEST}
        latest={NOW}
        view="overview"
        selectedItem={gapRow.id}
        configuration={CONFIG}
        initialResult={initial}
        onChangeParams={noop}
        onBackToHub={noop}
        onRefreshConfig={noop}
      />,
    );
    expect(gapDrawerHtml).toContain("Receipt gap");
    expect(gapDrawerHtml).toContain("does not prove device down");
    expect(gapDrawerHtml).toContain('<dd class="pl-mono">Receipt gap</dd>');
  });

  it("renders Estimate-mode banner with explicit Re-check Stream mode button", () => {
    const estimateResult = buildMgmtPlaneAnalysis({
      events: [],
      thresholds: resolveMgmtPlaneThresholds(PROFILE),
      earliest: EARLIEST,
      latest: NOW,
      outcomes: [{ source: "protocol_mgmt_plane", state: "complete" }],
      capped: false,
      streamReadiness: [
        {
          streamId: "snmp",
          state: "estimate_only",
          detail: "Stream snmp is in Estimate mode (statsOnly=true).",
        },
      ],
    });

    const html = renderToStaticMarkup(
      <MgmtPlaneLensPage
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
});
