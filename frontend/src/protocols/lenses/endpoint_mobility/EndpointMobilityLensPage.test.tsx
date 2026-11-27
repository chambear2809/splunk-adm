import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import type { SearchClient } from "../../../data/searchClient";
import type {
  BaseProtocolProfile,
  ProtocolConfiguration,
} from "../../shared/contract";
import {
  EndpointMobilityLensPage,
  buildEndpointMobilityAnalysis,
  normalizeEndpointMobilityRow,
  resolveEndpointMobilityThresholds,
  type EndpointMobilityInvestigationResult,
} from "./index";

const NOW = 1800000500;
const EARLIEST = 1800000000;

const PROFILE: BaseProtocolProfile = {
  id: "mobility-dc1",
  source: "protocol_endpoint_mobility",
  lens: "endpoint_mobility",
  scope: "prod:dc1",
  index: "cisco_dc",
  observer: "nd-01",
  validFrom: EARLIEST - 3600,
  validUntil: NOW + 3600,
  extra: { sourceKind: "auto" },
};

const CONFIG: ProtocolConfiguration = {
  profiles: [PROFILE],
  fingerprint: "fp-test",
};

function sampleMobilityResult(): EndpointMobilityInvestigationResult {
  const events = [
    {
      event: normalizeEndpointMobilityRow(
        {
          _time: EARLIEST + 20,
          host: "stream-fwd-01",
          sourcetype: "stream:arp",
          sender_ip: "10.10.20.42",
          sender_mac: "00:50:56:aa:00:01",
          arp_opcode: 1,
          vlan_id: 20,
        },
        0,
      )!,
      indexName: "netflow",
    },
    {
      event: normalizeEndpointMobilityRow(
        {
          _time: EARLIEST + 40,
          host: "stream-fwd-01",
          sourcetype: "stream:arp",
          sender_ip: "10.10.20.42",
          sender_mac: "00:50:56:aa:00:02",
          arp_opcode: 2,
          vlan_id: 20,
        },
        1,
      )!,
      indexName: "netflow",
    },
    {
      event: normalizeEndpointMobilityRow(
        {
          _time: EARLIEST + 60,
          host: "splunk-hf-01",
          sourcetype: "cisco:dc:nd:endpoints",
          mac: "00:50:56:aa:10:40",
          ip: ["10.20.30.40"],
          nodeName: "leaf-201",
          displayInterface: ["eth1/5"],
          encap: "vlan-1040",
          modType: "creation",
          anomalyScore: 0,
        },
        2,
      )!,
      indexName: "cisco_dc",
    },
    {
      event: normalizeEndpointMobilityRow(
        {
          _time: EARLIEST + 140,
          host: "splunk-hf-01",
          sourcetype: "cisco:dc:nd:endpoints",
          mac: "00:50:56:aa:10:40",
          ip: ["10.20.30.40"],
          nodeName: "leaf-202",
          displayInterface: ["eth1/8"],
          encap: "vlan-1040",
          modType: "move",
          anomalyScore: 72,
        },
        3,
      )!,
      indexName: "cisco_dc",
    },
    {
      event: normalizeEndpointMobilityRow(
        {
          _time: EARLIEST + 150,
          host: "leaf-202",
          sourcetype: "cisco:ios",
          interface: "Ethernet1/8",
          syslog_msg:
            "%ETHPORT-5-IF_DOWN_LINK_FAILURE: Interface Ethernet1/8 is down",
        },
        4,
      )!,
      indexName: "cisco_dc",
    },
    {
      event: normalizeEndpointMobilityRow(
        {
          _time: EARLIEST + 200,
          host: "splunk-hf-01",
          sourcetype: "cisco:dc:nd:endpoints",
          mac: "02:00:0a:0a:14:0b",
          ip: ["10.10.20.11"],
          nodeName: "leaf-101",
          displayInterface: ["eth1/11"],
          encap: "vlan-20",
          modType: "creation",
          anomalyScore: 0,
        },
        5,
      )!,
      indexName: "cisco_dc",
    },
  ];

  return buildEndpointMobilityAnalysis({
    events,
    thresholds: resolveEndpointMobilityThresholds(PROFILE),
    earliest: EARLIEST,
    latest: NOW,
    outcomes: [
      {
        source: "protocol_endpoint_mobility",
        profile: "mobility-dc1",
        state: "complete",
      },
    ],
    capped: false,
    activeSourceKinds: ["auto"],
  });
}

const noop = () => undefined;

describe("EndpointMobilityLensPage", () => {
  it("never auto-searches or checks Stream mode on mount", () => {
    const search = vi.fn();
    const client: SearchClient = { search };
    const html = renderToStaticMarkup(
      <EndpointMobilityLensPage
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
    expect(html).toContain("Endpoint Mobility &amp; ARP");
    expect(html).toContain("Investigate");
    expect(html).toContain("Not checked");
    expect(search).not.toHaveBeenCalled();
  });

  it("renders unavailable banner when no profile covers the scope", () => {
    const html = renderToStaticMarkup(
      <EndpointMobilityLensPage
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

  it("renders Overview with plain-language verdict, <=4 KPIs, flagged-first rows, and SwimlaneTimeline", () => {
    const initial = sampleMobilityResult();
    const html = renderToStaticMarkup(
      <EndpointMobilityLensPage
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
    expect(html).toContain("2 of 3 endpoints need attention");
    expect(html.match(/data-testid="protocol-kpi-tile"/g)?.length).toBe(4);
    expect(html).toContain("Duplicate IPs");
    expect(html).toContain("MAC Moves");
    expect(html).toContain("ARP Rate Spikes");
    expect(html).toContain("Port Flaps");
    expect(html).toContain("10.10.20.42");
    expect(html).toContain("00:50:56:aa:10:40");
    // Healthy endpoint sits behind "Show all (3)"
    const tableMatch = /<table class="pl-table"[^>]*>[\s\S]*?<\/table>/.exec(
      html,
    );
    expect(tableMatch).not.toBeNull();
    expect(tableMatch![0]).not.toContain("02:00:0a:0a:14:0b");
    expect(html).toContain("Show all (3)");
    expect(html).toContain('data-testid="protocol-timeline"');
  });

  it("renders StatusChip not_covered instead of dash for uncollected columns", () => {
    const arpOnly = buildEndpointMobilityAnalysis({
      events: [
        {
          event: normalizeEndpointMobilityRow(
            {
              _time: EARLIEST + 20,
              host: "stream-fwd-01",
              sourcetype: "stream:arp",
              sender_ip: "10.10.20.42",
              sender_mac: "00:50:56:aa:00:01",
              arp_opcode: 1,
            },
            0,
          )!,
          indexName: "netflow",
        },
      ],
      thresholds: resolveEndpointMobilityThresholds(PROFILE),
      earliest: EARLIEST,
      latest: NOW,
      outcomes: [{ source: "protocol_endpoint_mobility", state: "complete" }],
      capped: false,
      activeSourceKinds: ["stream_arp"],
    });
    const html = renderToStaticMarkup(
      <EndpointMobilityLensPage
        live
        scope="prod:dc1"
        scopes={["prod:dc1"]}
        earliest={EARLIEST}
        latest={NOW}
        view="overview"
        configuration={CONFIG}
        initialResult={arpOnly}
        onChangeParams={noop}
        onBackToHub={noop}
        onRefreshConfig={noop}
      />,
    );
    const tableMatch = /<table class="pl-table"[^>]*>[\s\S]*?<\/table>/.exec(
      html,
    );
    expect(tableMatch).not.toBeNull();
    expect(tableMatch![0]).toContain("Not covered");
    expect(tableMatch![0]).not.toContain(">—<");
  });

  it("renders Matrix view (Switch x VLAN/VNI) with none_observed when complete and unknown when capped", () => {
    const initial = sampleMobilityResult();
    const completeHtml = renderToStaticMarkup(
      <EndpointMobilityLensPage
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
    expect(completeHtml).toContain("leaf-201");
    expect(completeHtml).toContain("vlan-1040");

    const cappedHtml = renderToStaticMarkup(
      <EndpointMobilityLensPage
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

  it("renders Detail Drawer with Status chip first, pl-kv-list details, CopyableIp controls, and raw events link", () => {
    const initial = sampleMobilityResult();
    const drawerHtml = renderToStaticMarkup(
      <EndpointMobilityLensPage
        live
        scope="prod:dc1"
        scopes={["prod:dc1"]}
        earliest={EARLIEST}
        latest={NOW}
        view="overview"
        selectedItem="ip__10.10.20.42"
        configuration={CONFIG}
        initialResult={initial}
        onChangeParams={noop}
        onBackToHub={noop}
        onRefreshConfig={noop}
      />,
    );
    expect(drawerHtml).toContain('data-testid="protocol-detail-drawer"');
    expect(drawerHtml).toContain("00:50:56:aa:00:01");
    expect(drawerHtml).toContain("00:50:56:aa:00:02");
    expect(drawerHtml).toContain("Copy endpoint IP 10.10.20.42");
    expect(drawerHtml).toContain("pl-kv-list");
    expect(drawerHtml).toContain("/app/splunk_adm/search?");
    const statusIdx = drawerHtml.indexOf("<dt>Status</dt>");
    const macsIdx = drawerHtml.indexOf("<dt>Observed MACs</dt>");
    expect(statusIdx).toBeGreaterThan(-1);
    expect(statusIdx).toBeLessThan(macsIdx);
  });

  it("renders Estimate-mode banner with Re-check Stream mode button and keeps chrome under 60 words", () => {
    const estimateResult = buildEndpointMobilityAnalysis({
      events: [],
      thresholds: resolveEndpointMobilityThresholds(PROFILE),
      earliest: EARLIEST,
      latest: NOW,
      outcomes: [{ source: "protocol_endpoint_mobility", state: "complete" }],
      capped: false,
      streamReadiness: {
        streamId: "arp",
        state: "estimate_only",
        detail: "Stream arp is in Estimate mode (statsOnly=true).",
      },
    });
    const estHtml = renderToStaticMarkup(
      <EndpointMobilityLensPage
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
      <EndpointMobilityLensPage
        live
        scope="prod:dc1"
        scopes={["prod:dc1"]}
        earliest={EARLIEST}
        latest={NOW}
        view="overview"
        configuration={CONFIG}
        initialResult={sampleMobilityResult()}
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
