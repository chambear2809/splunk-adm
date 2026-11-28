import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import type { SearchClient } from "../../../data/searchClient";
import type {
  BaseProtocolProfile,
  ProtocolConfiguration,
} from "../../shared/contract";
import {
  InterfaceHealthLensPage,
  buildInterfaceHealthAnalysis,
  normalizeInterfaceDmeRow,
  normalizeInterfaceSyslogRow,
  resolveInterfaceHealthThresholds,
  type InterfaceHealthInvestigationResult,
} from "./index";

const NOW = 1800000500;
const EARLIEST = 1800000000;

const PROFILE: BaseProtocolProfile = {
  id: "intf-dc1",
  source: "protocol_interface_health",
  lens: "interface_health",
  scope: "prod:dc1",
  index: "cisco_dc",
  observer: "n9k-dme-01",
  validFrom: EARLIEST - 3600,
  validUntil: NOW + 3600,
};

const CONFIG: ProtocolConfiguration = {
  profiles: [PROFILE],
  fingerprint: "fp-test",
};

function sampleInterfaceResult(): InterfaceHealthInvestigationResult {
  const dmeEvents = [
    {
      event: normalizeInterfaceDmeRow({
        _time: EARLIEST + 60,
        host: "leaf1.dc1.example",
        sourcetype: "cisco:dc:nexus9k:dme",
        interface: "Ethernet1/1",
        descr: "server-a-nic0",
        admin_state: "up",
        oper_state: "down",
        speed: "25G",
        mtu: 9216,
        crc_errors: 0,
        in_errors: 0,
        out_errors: 0,
        in_discards: 0,
        out_discards: 0,
        utilization_pct: 0,
      })!,
      indexName: "cisco_dc",
    },
    {
      event: normalizeInterfaceDmeRow({
        _time: EARLIEST + 120,
        host: "leaf1.dc1.example",
        sourcetype: "cisco:dc:nexus9k:dme",
        interface: "Ethernet1/49",
        descr: "uplink-spine1",
        admin_state: "up",
        oper_state: "up",
        speed: "100G",
        mtu: 9216,
        crc_errors: 42,
        in_errors: 45,
        out_errors: 0,
        in_discards: 18,
        out_discards: 4,
        in_octets: 8420019200,
        out_octets: 7910023100,
        utilization_pct: 87.4,
      })!,
      indexName: "cisco_dc",
    },
    {
      event: normalizeInterfaceDmeRow({
        _time: EARLIEST + 180,
        host: "leaf2.dc1.example",
        sourcetype: "cisco:dc:nexus9k:dme",
        interface: "Ethernet1/10",
        descr: "app-node-02",
        admin_state: "up",
        oper_state: "up",
        speed: "25G",
        mtu: 9216,
        crc_errors: 0,
        in_errors: 0,
        out_errors: 0,
        in_discards: 0,
        out_discards: 0,
        utilization_pct: 34.2,
      })!,
      indexName: "cisco_dc",
    },
  ];

  const syslogEvents = [
    {
      event: normalizeInterfaceSyslogRow(
        {
          _time: EARLIEST + 90,
          host: "leaf1.dc1.example",
          sourcetype: "cisco:ios",
          syslog_msg:
            "%ETHPORT-5-IF_DOWN_LINK_FAILURE: Interface Ethernet1/1 is down",
        },
        0,
      )!,
      indexName: "cisco_dc",
    },
    {
      event: normalizeInterfaceSyslogRow(
        {
          _time: EARLIEST + 150,
          host: "leaf1.dc1.example",
          sourcetype: "cisco:ios",
          syslog_msg:
            "%ETHPORT-5-IF_DOWN_LINK_FAILURE: Interface Ethernet1/49 is down",
        },
        1,
      )!,
      indexName: "cisco_dc",
    },
    {
      event: normalizeInterfaceSyslogRow(
        {
          _time: EARLIEST + 210,
          host: "leaf1.dc1.example",
          sourcetype: "cisco:ios",
          syslog_msg: "%ETHPORT-5-IF_UP: Interface Ethernet1/49 is up",
        },
        2,
      )!,
      indexName: "cisco_dc",
    },
  ];

  return buildInterfaceHealthAnalysis({
    dmeEvents,
    syslogEvents,
    thresholds: resolveInterfaceHealthThresholds(PROFILE),
    earliest: EARLIEST,
    latest: NOW,
    outcomes: [
      {
        source: "protocol_interface_health",
        profile: "intf-dc1",
        state: "complete",
      },
    ],
    capped: false,
  });
}

const noop = () => undefined;

describe("InterfaceHealthLensPage", () => {
  it("never auto-searches on mount", () => {
    const search = vi.fn();
    const client: SearchClient = { search };
    const html = renderToStaticMarkup(
      <InterfaceHealthLensPage
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
    expect(html).toContain("Interface &amp; Link Health");
    expect(html).toContain("Investigate");
    expect(html).toContain("Not checked");
    expect(search).not.toHaveBeenCalled();
  });

  it("renders unavailable banner when no profile covers the scope", () => {
    const html = renderToStaticMarkup(
      <InterfaceHealthLensPage
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

  it("renders Overview with verdict, 4 KPIs, <=8 columns, flagged-first rows, and DistributionBar", () => {
    const initial = sampleInterfaceResult();
    const html = renderToStaticMarkup(
      <InterfaceHealthLensPage
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
    expect(html).toContain("2 of 3 interfaces need attention");
    expect(html.match(/data-testid="protocol-kpi-tile"/g)?.length).toBe(4);
    expect(html).toContain("Down / Mismatched");
    expect(html).toContain("CRC &amp; Errors");
    expect(html).toContain("Link Flaps");
    expect(html).toContain("Peak Utilization");
    // Healthy row (leaf2.dc1.example) stays behind "Show all (3)" in the overview table
    const tablePart = html.split("Show all (3)")[0];
    expect(tablePart).toContain("leaf1.dc1.example");
    expect(tablePart).not.toContain("leaf2.dc1.example");
    expect(html).toContain("Show all (3)");
    expect(html).toContain('data-testid="protocol-distribution-bar"');
  });

  it("renders Matrix view with SwimlaneTimeline, none_observed when complete, and unknown when capped", () => {
    const initial = sampleInterfaceResult();
    const completeHtml = renderToStaticMarkup(
      <InterfaceHealthLensPage
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
    expect(completeHtml).toContain('data-testid="protocol-timeline"');
    expect(completeHtml).toContain("Link flap &amp; state timeline");
    expect(completeHtml).toContain("None observed");
    expect(completeHtml).toContain("Admin up / Down");
    expect(completeHtml).toContain("42 CRC");

    const cappedHtml = renderToStaticMarkup(
      <InterfaceHealthLensPage
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

  it("renders Detail Drawer with breakdown, recent syslog, Exceptions list, and literal raw events link", () => {
    const initial = sampleInterfaceResult();
    const drawerHtml = renderToStaticMarkup(
      <InterfaceHealthLensPage
        live
        scope="prod:dc1"
        scopes={["prod:dc1"]}
        earliest={EARLIEST}
        latest={NOW}
        view="overview"
        selectedItem="leaf1.dc1.example__Ethernet1/49"
        configuration={CONFIG}
        initialResult={initial}
        onChangeParams={noop}
        onBackToHub={noop}
        onRefreshConfig={noop}
      />,
    );
    expect(drawerHtml).toContain('data-testid="protocol-detail-drawer"');
    expect(drawerHtml).toContain("100 Gbps / 9216");
    expect(drawerHtml).toContain("42 / 45 / 0");
    expect(drawerHtml).toContain("18 / 4");
    expect(drawerHtml).toContain("87.4%");
    expect(drawerHtml).toContain("IF_DOWN_LINK_FAILURE");
    expect(drawerHtml).toContain("/app/splunk_adm/search?");
    expect(drawerHtml).toContain("pl-kv-list");
  });

  it("renders syslog-only mode without fake error counters or utilization and keeps chrome under 60 words", () => {
    const syslogOnlyResult = buildInterfaceHealthAnalysis({
      dmeEvents: [],
      syslogEvents: [
        {
          event: normalizeInterfaceSyslogRow(
            {
              _time: EARLIEST + 30,
              host: "leaf2.dc1.example",
              sourcetype: "cisco:ios",
              syslog_msg: "%ETHPORT-5-IF_UP: Interface Ethernet1/10 is up",
            },
            0,
          )!,
          indexName: "cisco_dc",
        },
      ],
      thresholds: resolveInterfaceHealthThresholds(PROFILE),
      earliest: EARLIEST,
      latest: NOW,
      outcomes: [
        {
          source: "protocol_interface_health",
          profile: "intf-dc1",
          state: "complete",
        },
      ],
      capped: false,
    });
    const syslogHtml = renderToStaticMarkup(
      <InterfaceHealthLensPage
        live
        scope="prod:dc1"
        scopes={["prod:dc1"]}
        earliest={EARLIEST}
        latest={NOW}
        view="overview"
        configuration={CONFIG}
        initialResult={syslogOnlyResult}
        onChangeParams={noop}
        onBackToHub={noop}
        onRefreshConfig={noop}
      />,
    );
    expect(syslogHtml).toContain("Syslog events only");
    expect(syslogHtml).toContain("Not covered");
    expect(syslogHtml).not.toContain('data-testid="protocol-distribution-bar"');

    // Measure chrome words using the same DOM removal semantics as tests/browser/protocols.spec.ts
    const overviewHtml = renderToStaticMarkup(
      <InterfaceHealthLensPage
        live
        scope="prod:dc1"
        scopes={["prod:dc1"]}
        earliest={EARLIEST}
        latest={NOW}
        view="overview"
        configuration={CONFIG}
        initialResult={sampleInterfaceResult()}
        onChangeParams={noop}
        onBackToHub={noop}
        onRefreshConfig={noop}
      />,
    );
    const stripped = overviewHtml
      .replace(/<svg[\s\S]*?<\/svg>/g, " ")
      .replace(
        /<div class="pl-dist-list"[^>]*>[\s\S]*?<\/section>/g,
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
});
