import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import type { SearchClient } from "../../../data/searchClient";
import type {
  BaseProtocolProfile,
  ProtocolConfiguration,
} from "../../shared/contract";
import {
  QosIcmpLensPage,
  buildQosIcmpAnalysis,
  normalizeQosIcmpRow,
  resolveQosIcmpThresholds,
  type QosIcmpInvestigationResult,
} from "./index";

const EARLIEST = 1764246500;
const NOW = 1764247100;

const PROFILE: BaseProtocolProfile = {
  id: "qos-dc1",
  source: "protocol_qos_icmp",
  lens: "qos_icmp",
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

function sampleQosIcmpResult(): QosIcmpInvestigationResult {
  const events = [
    {
      event: normalizeQosIcmpRow(
        {
          _time: EARLIEST + 30,
          host: "stream-fwd-01",
          sourcetype: "stream:netflow",
          exporter_ip: "192.0.2.11",
          src_ip: "10.42.0.20",
          dest_ip: "10.42.0.30",
          src_port: 43121,
          dest_port: 8080,
          protoid: 6,
          tos: 184,
          min_ttl: 63,
          bytes: 12800,
          packets: 10,
        },
        "stream:netflow",
      )!,
      indexName: "netflow",
    },
    {
      event: normalizeQosIcmpRow(
        {
          _time: EARLIEST + 90,
          host: "stream-fwd-01",
          sourcetype: "stream:netflow",
          exporter_ip: "192.0.2.12",
          src_ip: "10.42.0.20",
          dest_ip: "10.42.0.30",
          src_port: 43121,
          dest_port: 8080,
          protoid: 6,
          tos: 0,
          min_ttl: 62,
          bytes: 12800,
          packets: 10,
        },
        "stream:netflow",
      )!,
      indexName: "netflow",
    },
    {
      event: normalizeQosIcmpRow(
        {
          _time: EARLIEST + 120,
          host: "stream-fwd-01",
          sourcetype: "stream:netflow",
          exporter_ip: "192.0.2.11",
          src_ip: "10.42.0.20",
          dest_ip: "10.42.0.40",
          src_port: 5060,
          dest_port: 5060,
          protoid: 17,
          tos: 184,
          min_ttl: 64,
          bytes: 6400,
          packets: 20,
        },
        "stream:netflow",
      )!,
      indexName: "netflow",
    },
    {
      event: normalizeQosIcmpRow(
        {
          _time: EARLIEST + 150,
          host: "stream-sensor-01",
          sourcetype: "stream:icmp",
          src_ip: "192.0.2.254",
          dest_ip: "10.42.0.20",
          type: 3,
          code: 4,
          bytes: 576,
          time_taken: 1200,
        },
        "stream:icmp",
      )!,
      indexName: "netflow",
    },
    {
      event: normalizeQosIcmpRow(
        {
          _time: EARLIEST + 180,
          host: "splunk-hf-01",
          sourcetype: "cisco:dc:nd:flows",
          srcIp: "10.42.0.25",
          dstIp: "10.42.0.50",
          srcPort: 44300,
          dstPort: 5432,
          protocolName: "TCP",
          dropPktCount: 14,
          dropReasons: ["QOS_WRED_DROP"],
          fabricName: "dc1-vxlan",
          nd_host: "192.0.2.60",
          nodeName: "leaf-101",
        },
        "cisco:dc:nd:flows",
      )!,
      indexName: "cisco_dc",
    },
  ];

  return buildQosIcmpAnalysis({
    events,
    thresholds: resolveQosIcmpThresholds(PROFILE),
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
}

const noop = () => undefined;

describe("QosIcmpLensPage", () => {
  it("never auto-searches or checks Stream mode on mount", () => {
    const search = vi.fn();
    const client: SearchClient = { search };
    const html = renderToStaticMarkup(
      <QosIcmpLensPage
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
    expect(html).toContain("QoS/DSCP &amp; ICMP");
    expect(html).toContain("Investigate");
    expect(html).toContain("Not checked");
    expect(search).not.toHaveBeenCalled();
  });

  it("renders unavailable banner when no profile covers the scope", () => {
    const html = renderToStaticMarkup(
      <QosIcmpLensPage
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

  it("renders Overview with verdict, 4 KPIs, flagged-first table, SwimlaneTimeline, and <60 chrome words", () => {
    const initial = sampleQosIcmpResult();
    const html = renderToStaticMarkup(
      <QosIcmpLensPage
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
    expect(html).toContain("3 of 4 flows need attention");
    expect(html.match(/data-testid="protocol-kpi-tile"/g)?.length).toBe(4);
    expect(html).toContain("DSCP Remarks");
    expect(html).toContain("PMTUD Candidates");
    expect(html).toContain("ICMP Errors");
    expect(html).toContain("Fabric Drops");
    expect(html).toContain("Show all (4)");
    // Healthy flow 10.42.0.40 sits behind "Show all (4)" in the overview table
    const tablePart = html.split("Show all (4)")[0];
    expect(tablePart).toContain("10.42.0.30");
    expect(tablePart).not.toContain("10.42.0.40");
    expect(html).toContain('data-testid="protocol-timeline"');
    expect(html).toContain("PMTUD candidate: Fragmentation Needed");
    expect(html).toContain("192.0.2.254");

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

  it("renders Not covered status chips in table columns when ICMP and ND were not collected", () => {
    const nfOnly = buildQosIcmpAnalysis({
      events: [
        {
          event: normalizeQosIcmpRow(
            {
              _time: EARLIEST + 30,
              host: "stream-fwd-01",
              sourcetype: "stream:netflow",
              exporter_ip: "192.0.2.11",
              src_ip: "10.42.0.20",
              dest_ip: "10.42.0.40",
              src_port: 5060,
              dest_port: 5060,
              protoid: 17,
              tos: 184,
              bytes: 6400,
              packets: 20,
            },
            "stream:netflow",
          )!,
          indexName: "netflow",
        },
      ],
      thresholds: resolveQosIcmpThresholds(PROFILE),
      earliest: EARLIEST,
      latest: NOW,
      outcomes: [{ source: "protocol_qos_icmp", state: "complete" }],
      capped: false,
      netflowConfigured: true,
      icmpConfigured: false,
      ndConfigured: false,
    });

    const html = renderToStaticMarkup(
      <QosIcmpLensPage
        live
        scope="prod:dc1"
        scopes={["prod:dc1"]}
        earliest={EARLIEST}
        latest={NOW}
        view="overview"
        configuration={CONFIG}
        initialResult={nfOnly}
        onChangeParams={noop}
        onBackToHub={noop}
        onRefreshConfig={noop}
      />,
    );
    expect(html).toContain("Not covered");
    expect(html).not.toContain('data-testid="protocol-timeline"');
  });

  it("renders Matrix view with Exporter x DSCP, none_observed when complete and unknown when capped", () => {
    const initial = sampleQosIcmpResult();
    const completeHtml = renderToStaticMarkup(
      <QosIcmpLensPage
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
    expect(completeHtml).toContain("192.0.2.11");
    expect(completeHtml).toContain("EF (46)");
    expect(completeHtml).toContain("Remarked (1)");
    expect(completeHtml).toContain("None observed");

    const cappedHtml = renderToStaticMarkup(
      <QosIcmpLensPage
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

  it("renders Detail Drawer with Status first, pl-kv-list findings, CopyableIp, and literal raw events link", () => {
    const initial = sampleQosIcmpResult();
    const drawerHtml = renderToStaticMarkup(
      <QosIcmpLensPage
        live
        scope="prod:dc1"
        scopes={["prod:dc1"]}
        earliest={EARLIEST}
        latest={NOW}
        view="overview"
        selectedItem="10.42.0.20__10.42.0.30__TCP__43121_8080"
        configuration={CONFIG}
        initialResult={initial}
        onChangeParams={noop}
        onBackToHub={noop}
        onRefreshConfig={noop}
      />,
    );
    expect(drawerHtml).toContain('data-testid="protocol-detail-drawer"');
    expect(drawerHtml).toContain("<dt>Status</dt>");
    expect(drawerHtml).toContain("Copy source 10.42.0.20");
    expect(drawerHtml).toContain("Copy destination 10.42.0.30");
    expect(drawerHtml).toContain("Copy exporter 192.0.2.11");
    expect(drawerHtml).toContain("pl-kv-list");
    expect(drawerHtml).toContain("DSCP remarking detected across 2 exporters");
    expect(drawerHtml).toContain("/app/splunk_adm/search?");

    const ndDrawerHtml = renderToStaticMarkup(
      <QosIcmpLensPage
        live
        scope="prod:dc1"
        scopes={["prod:dc1"]}
        earliest={EARLIEST}
        latest={NOW}
        view="overview"
        selectedItem="10.42.0.25__10.42.0.50__TCP__44300_5432"
        configuration={CONFIG}
        initialResult={initial}
        onChangeParams={noop}
        onBackToHub={noop}
        onRefreshConfig={noop}
      />,
    );
    expect(ndDrawerHtml).toContain("QOS_WRED_DROP");
    expect(ndDrawerHtml).toContain("dc1-vxlan");
  });

  it("renders Estimate-mode banner with explicit Re-check Stream mode button", () => {
    const estimateResult = buildQosIcmpAnalysis({
      events: [],
      thresholds: resolveQosIcmpThresholds(PROFILE),
      earliest: EARLIEST,
      latest: NOW,
      outcomes: [{ source: "protocol_qos_icmp", state: "complete" }],
      capped: false,
      streamReadiness: {
        streamId: "icmp",
        state: "estimate_only",
        detail: "Stream is in Estimate mode (statsOnly=true).",
      },
    });
    const html = renderToStaticMarkup(
      <QosIcmpLensPage
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

  it("renders None observed (not Not covered) for an ICMP-only row in a NetFlow-covered scope", () => {
    const mixedResult = buildQosIcmpAnalysis({
      events: [
        {
          event: normalizeQosIcmpRow(
            {
              _time: EARLIEST + 30,
              host: "leaf1",
              sourcetype: "stream:netflow",
              exporter_ip: "192.0.2.11",
              src_ip: "10.42.0.20",
              dest_ip: "10.42.0.40",
              src_port: 5060,
              dest_port: 5060,
              protoid: 17,
              tos: 184,
              bytes: 6400,
              packets: 20,
            },
            "stream:netflow",
          )!,
          indexName: "netflow",
        },
        {
          event: normalizeQosIcmpRow(
            {
              _time: EARLIEST + 60,
              host: "stream-fwd-01",
              sourcetype: "stream:icmp",
              src_ip: "10.42.0.99",
              dest_ip: "10.42.0.40",
              icmp_type: 3,
              icmp_code: 4,
              packets_in: 2,
            },
            "stream:icmp",
          )!,
          indexName: "stream_icmp",
        },
      ],
      thresholds: resolveQosIcmpThresholds(PROFILE),
      earliest: EARLIEST,
      latest: NOW,
      outcomes: [{ source: "protocol_qos_icmp", state: "complete" }],
      capped: false,
      netflowConfigured: true,
      icmpConfigured: true,
      ndConfigured: true,
    });
    const icmpRow = mixedResult.rows.find((r) => r.flowLabel === "ICMP");
    expect(icmpRow).toBeDefined();

    const overviewHtml = renderToStaticMarkup(
      <QosIcmpLensPage
        live
        scope="prod:dc1"
        scopes={["prod:dc1"]}
        earliest={EARLIEST}
        latest={NOW}
        view="overview"
        configuration={CONFIG}
        initialResult={mixedResult}
        onChangeParams={noop}
        onBackToHub={noop}
        onRefreshConfig={noop}
      />,
    );
    expect(overviewHtml).toContain("None observed");
    expect(overviewHtml).not.toContain("Not covered");

    const drawerHtml = renderToStaticMarkup(
      <QosIcmpLensPage
        live
        scope="prod:dc1"
        scopes={["prod:dc1"]}
        earliest={EARLIEST}
        latest={NOW}
        view="overview"
        selectedItem={icmpRow!.id}
        configuration={CONFIG}
        initialResult={mixedResult}
        onChangeParams={noop}
        onBackToHub={noop}
        onRefreshConfig={noop}
      />,
    );
    expect(drawerHtml).toContain("<dt>DSCP / ECN</dt>");
    expect(drawerHtml).toContain("None observed");
    expect(drawerHtml).not.toContain("Not covered");
  });

  it("renders Unknown (NetFlow sample capped) instead of None observed for DSCP/ECN when NetFlow was capped", () => {
    const cappedMixedResult = buildQosIcmpAnalysis({
      events: [
        {
          event: normalizeQosIcmpRow(
            {
              _time: EARLIEST + 30,
              host: "leaf-01",
              sourcetype: "stream:netflow",
              src_ip: "10.10.10.5",
              dest_ip: "10.20.20.9",
              src_port: 51234,
              dest_port: 443,
              transport: "tcp",
              tos: 184,
              bytes: 12000,
              packets: 20,
            },
            "stream:netflow",
          )!,
          indexName: "netflow",
        },
        {
          event: normalizeQosIcmpRow(
            {
              _time: EARLIEST + 60,
              host: "stream-fwd-01",
              sourcetype: "stream:icmp",
              src_ip: "10.42.0.99",
              dest_ip: "10.42.0.40",
              icmp_type: 3,
              icmp_code: 4,
              packets_in: 2,
            },
            "stream:icmp",
          )!,
          indexName: "stream_icmp",
        },
      ],
      thresholds: resolveQosIcmpThresholds(PROFILE),
      earliest: EARLIEST,
      latest: NOW,
      outcomes: [
        {
          source: "protocol_qos_icmp",
          state: "partial",
          capped: true,
          detail: "Capped at 256 rows.",
        },
        { source: "protocol_qos_icmp", state: "complete" },
      ],
      netflowOutcomes: [
        {
          source: "protocol_qos_icmp",
          state: "partial",
          capped: true,
          detail: "Capped at 256 rows.",
        },
      ],
      capped: true,
      netflowConfigured: true,
      icmpConfigured: true,
      ndConfigured: false,
    });
    expect(cappedMixedResult.netflowDegraded).toBe(true);
    expect(cappedMixedResult.netflowDegradedReason).toBe(
      "NetFlow sample capped",
    );
    const icmpRow = cappedMixedResult.rows.find((r) => r.flowLabel === "ICMP");
    expect(icmpRow).toBeDefined();

    const overviewHtml = renderToStaticMarkup(
      <QosIcmpLensPage
        live
        scope="prod:dc1"
        scopes={["prod:dc1"]}
        earliest={EARLIEST}
        latest={NOW}
        view="overview"
        configuration={CONFIG}
        initialResult={cappedMixedResult}
        onChangeParams={noop}
        onBackToHub={noop}
        onRefreshConfig={noop}
      />,
    );
    expect(overviewHtml).toContain("NetFlow sample capped");
    expect(overviewHtml).toContain("Unknown");
    expect(overviewHtml).not.toContain("None observed");

    const drawerHtml = renderToStaticMarkup(
      <QosIcmpLensPage
        live
        scope="prod:dc1"
        scopes={["prod:dc1"]}
        earliest={EARLIEST}
        latest={NOW}
        view="overview"
        selectedItem={icmpRow!.id}
        configuration={CONFIG}
        initialResult={cappedMixedResult}
        onChangeParams={noop}
        onBackToHub={noop}
        onRefreshConfig={noop}
      />,
    );
    expect(drawerHtml).toContain("<dt>DSCP / ECN</dt>");
    expect(drawerHtml).toContain("NetFlow sample capped");
    expect(drawerHtml).toContain("Unknown");
    expect(drawerHtml).not.toContain("None observed");
  });
});
