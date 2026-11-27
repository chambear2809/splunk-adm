import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import type { SearchClient } from "../../../data/searchClient";
import type {
  BaseProtocolProfile,
  ProtocolConfiguration,
} from "../../shared/contract";
import {
  L2ControlLensPage,
  buildL2ControlAnalysis,
  normalizeL2ControlRow,
  resolveL2ControlThresholds,
  type L2ControlInvestigationResult,
} from "./index";

const NOW = 1800000500;
const EARLIEST = 1800000000;

const PROFILE: BaseProtocolProfile = {
  id: "l2-dc1",
  source: "protocol_l2_control",
  lens: "l2_control",
  scope: "prod:dc1",
  index: "cisco_dc",
  observer: "sc4s-01",
  validFrom: EARLIEST - 3600,
  validUntil: NOW + 3600,
  extra: { sourceKind: "auto" },
};

const CONFIG: ProtocolConfiguration = {
  profiles: [PROFILE],
  fingerprint: "fp-test",
};

function sampleL2Result(): L2ControlInvestigationResult {
  const events = [
    {
      event: normalizeL2ControlRow(
        {
          _time: EARLIEST + 40,
          host: "stream-fwd-01",
          sourcetype: "stream:dhcp",
          dest_ip: "10.10.10.6",
          client_mac: "00:50:56:aa:20:09",
          dhcp_message_type: "NAK",
          yiaddr: "10.10.200.88",
          lease_time: 1800,
          vlan_id: 200,
        },
        0,
      )!,
      indexName: "netflow",
    },
    {
      event: normalizeL2ControlRow(
        {
          _time: EARLIEST + 90,
          host: "leaf1.dc1.example",
          sourcetype: "cisco:ios",
          category: "STP",
          severity_id: "2",
          mnemonics: "ROOTGUARD_BLOCK",
          interface: "Ethernet1/49",
          syslog_msg: "Root guard blocking port Ethernet1/49 on VLAN0110",
        },
        1,
      )!,
      indexName: "cisco_dc",
    },
    {
      event: normalizeL2ControlRow(
        {
          _time: EARLIEST + 140,
          host: "leaf2.dc1.example",
          sourcetype: "cisco:dc:nexus9k:syslog",
          category: "LLDP",
          severity_id: "5",
          mnemonics: "NEIGHBOR_ADDED",
          interface: "Ethernet1/48",
          syslog_msg: "LLDP neighbor sw-core-01 discovered on Ethernet1/48",
        },
        2,
      )!,
      indexName: "cisco_dc",
    },
  ];

  return buildL2ControlAnalysis({
    events,
    thresholds: resolveL2ControlThresholds(PROFILE),
    earliest: EARLIEST,
    latest: NOW,
    outcomes: [
      { source: "protocol_l2_control", profile: "l2-dc1", state: "complete" },
    ],
    capped: false,
    activeSourceKinds: ["auto"],
  });
}

const noop = () => undefined;

describe("L2ControlLensPage", () => {
  it("never auto-searches or checks Stream mode on mount", () => {
    const search = vi.fn();
    const client: SearchClient = { search };
    const html = renderToStaticMarkup(
      <L2ControlLensPage
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
    expect(html).toContain("L2 Control Plane");
    expect(html).toContain("Investigate");
    expect(html).toContain("Not checked");
    expect(search).not.toHaveBeenCalled();
  });

  it("renders unavailable banner when no profile covers the scope", () => {
    const html = renderToStaticMarkup(
      <L2ControlLensPage
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

  it("renders Overview with single-sentence verdict, <=4 KPIs, flagged-first rows, and SwimlaneTimeline", () => {
    const initial = sampleL2Result();
    const html = renderToStaticMarkup(
      <L2ControlLensPage
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
    expect(html).toContain("2 of 3 L2 entities need attention");
    expect(html.match(/data-testid="protocol-kpi-tile"/g)?.length).toBe(4);
    expect(html).toContain("DHCP NAKs");
    expect(html).toContain("STP Changes");
    expect(html).toContain("LACP Drops");
    expect(html).toContain("ARP / L2 Alerts");
    expect(html).toContain("10.10.10.6");
    expect(html).toContain("leaf1.dc1.example");
    // Healthy LLDP row sits behind "Show all (3)" in the Overview table
    const tableMatch = /<table class="pl-table"[^>]*>[\s\S]*?<\/table>/.exec(
      html,
    );
    expect(tableMatch).not.toBeNull();
    expect(tableMatch![0]).not.toContain("leaf2.dc1.example");
    expect(html).toContain("Show all (3)");
    expect(html).toContain('data-testid="protocol-timeline"');
  });

  it("renders Matrix view (Device x Subsystem) with none_observed when complete and unknown when capped", () => {
    const initial = sampleL2Result();
    const completeHtml = renderToStaticMarkup(
      <L2ControlLensPage
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
    expect(completeHtml).toContain("DHCP");
    expect(completeHtml).toContain("LACP");

    const cappedHtml = renderToStaticMarkup(
      <L2ControlLensPage
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

  it("renders Detail Drawer with Status chip first, DHCP details, mnemonics, Exceptions, and raw events link", () => {
    const initial = sampleL2Result();
    const dhcpDrawerHtml = renderToStaticMarkup(
      <L2ControlLensPage
        live
        scope="prod:dc1"
        scopes={["prod:dc1"]}
        earliest={EARLIEST}
        latest={NOW}
        view="overview"
        selectedItem="DHCP__10.10.10.6__vlan-200"
        configuration={CONFIG}
        initialResult={initial}
        onChangeParams={noop}
        onBackToHub={noop}
        onRefreshConfig={noop}
      />,
    );
    expect(dhcpDrawerHtml).toContain('data-testid="protocol-detail-drawer"');
    expect(dhcpDrawerHtml).toContain("00:50:56:aa:20:09");
    expect(dhcpDrawerHtml).toContain("10.10.200.88");
    expect(dhcpDrawerHtml).toContain("DHCP_NAK");
    expect(dhcpDrawerHtml).toContain("pl-kv-list");
    expect(dhcpDrawerHtml).toContain("/app/splunk_adm/search?");
    const statusIdx = dhcpDrawerHtml.indexOf("<dt>Status</dt>");
    const subsystemIdx = dhcpDrawerHtml.indexOf("<dt>Subsystem</dt>");
    expect(statusIdx).toBeGreaterThan(-1);
    expect(statusIdx).toBeLessThan(subsystemIdx);
  });

  it("renders Estimate-mode banner with explicit Re-check Stream mode button and keeps chrome under 60 words", () => {
    const estimateResult = buildL2ControlAnalysis({
      events: [],
      thresholds: resolveL2ControlThresholds(PROFILE),
      earliest: EARLIEST,
      latest: NOW,
      outcomes: [{ source: "protocol_l2_control", state: "complete" }],
      capped: false,
      streamReadiness: {
        streamId: "dhcp",
        state: "estimate_only",
        detail: "Stream is in Estimate mode (statsOnly=true).",
      },
    });
    const estHtml = renderToStaticMarkup(
      <L2ControlLensPage
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
    expect(estHtml).toContain('data-testid="protocol-state-estimate_only"');
    expect(estHtml).toContain("Re-check Stream mode");

    const overviewHtml = renderToStaticMarkup(
      <L2ControlLensPage
        live
        scope="prod:dc1"
        scopes={["prod:dc1"]}
        earliest={EARLIEST}
        latest={NOW}
        view="overview"
        configuration={CONFIG}
        initialResult={sampleL2Result()}
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
