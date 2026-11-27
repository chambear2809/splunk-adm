import { readFileSync } from "node:fs";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import type { SearchClient } from "../../../data/searchClient";
import type {
  BaseProtocolProfile,
  ProtocolConfiguration,
} from "../../shared/contract";
import {
  RoutingLensPage,
  buildRoutingAnalysis,
  normalizeRoutingDmeRow,
  normalizeRoutingSyslogRow,
  resolveRoutingThresholds,
  type RoutingInvestigationResult,
} from "./index";

const EARLIEST = 1764246600;
const NOW = 1764248400;

const PROFILE: BaseProtocolProfile = {
  id: "routing-dc1",
  source: "protocol_routing",
  lens: "routing",
  scope: "prod:dc1",
  index: "cisco_dc",
  observer: "sc4s-dc1",
  validFrom: EARLIEST - 3600,
  validUntil: NOW + 3600,
};

const CONFIG: ProtocolConfiguration = {
  profiles: [PROFILE],
  fingerprint: "fp-routing-test",
};

function sampleRoutingResult(syslogOnly = false): RoutingInvestigationResult {
  const syslogRows = readFileSync(
    "fixtures/raw/protocols/routing/nxos_routing_syslog.ndjson",
    "utf8",
  )
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line) as Record<string, unknown>);
  const dmeRows = syslogOnly
    ? []
    : readFileSync("fixtures/raw/protocols/routing/dcn_bgp_dme.ndjson", "utf8")
        .trim()
        .split("\n")
        .map((line) => JSON.parse(line) as Record<string, unknown>);

  const events = [
    ...syslogRows
      .map((r, i) => normalizeRoutingSyslogRow(r, i))
      .filter((e): e is NonNullable<typeof e> => Boolean(e))
      .map((event) => ({ event, indexName: "cisco_dc" })),
    ...dmeRows
      .map((r, i) => normalizeRoutingDmeRow(r, i))
      .filter((e): e is NonNullable<typeof e> => Boolean(e))
      .map((event) => ({ event, indexName: "cisco_dc" })),
  ];

  return buildRoutingAnalysis({
    events,
    thresholds: resolveRoutingThresholds(PROFILE),
    earliest: EARLIEST,
    latest: NOW,
    outcomes: [
      {
        source: "protocol_routing",
        profile: "routing-dc1",
        state: "complete",
      },
    ],
    capped: false,
  });
}

const noop = () => undefined;

describe("RoutingLensPage", () => {
  it("never auto-searches on mount", () => {
    const search = vi.fn();
    const client: SearchClient = { search };
    const html = renderToStaticMarkup(
      <RoutingLensPage
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
    expect(html).toContain("Routing Control Plane");
    expect(html).toContain("Investigate");
    expect(html).toContain("Not checked");
    expect(search).not.toHaveBeenCalled();
  });

  it("renders unavailable banner when no profile covers the scope", () => {
    const html = renderToStaticMarkup(
      <RoutingLensPage
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

  it("renders Overview with single-sentence verdict, 4 KPIs, flagged-first rows, SwimlaneTimeline, and <60 chrome words", () => {
    const initial = sampleRoutingResult();
    const html = renderToStaticMarkup(
      <RoutingLensPage
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
    expect(html).toContain("3 of 5 sessions need attention");
    expect(html.match(/data-testid="protocol-kpi-tile"/g)?.length).toBe(4);
    expect(html).toContain("Down Sessions");
    expect(html).toContain("Total Flaps");
    expect(html).toContain("Tracked Sessions");
    expect(html).toContain("Affected Devices");
    // Healthy rows hidden behind Show all (5) in the overview table
    const tablePart = html.split("Show all (5)")[0];
    expect(tablePart).toContain("leaf1.dc1");
    expect(tablePart).not.toContain("10.255.0.10");
    expect(tablePart).not.toContain("spine1.dc1");
    expect(html).toContain("Show all (5)");
    expect(html).toContain('data-testid="protocol-timeline"');
    expect(html).toContain("Adjacency transitions");

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

  it("renders Matrix view with AdjacencyOverlay and HeatMatrix (none_observed vs unknown when capped)", () => {
    const initial = sampleRoutingResult();
    const completeHtml = renderToStaticMarkup(
      <RoutingLensPage
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
    expect(completeHtml).toContain('data-testid="protocol-adjacency"');
    expect(completeHtml).toContain('data-testid="protocol-heat-matrix"');
    expect(completeHtml).toContain("None observed");
    expect(completeHtml).toContain("leaf1.dc1 to 10.255.0.2");

    const cappedHtml = renderToStaticMarkup(
      <RoutingLensPage
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

  it("renders Detail Drawer with Status chip first, CopyableIp, recent mnemonics, Exceptions list, and literal search link", () => {
    const initial = sampleRoutingResult();
    const drawerHtml = renderToStaticMarkup(
      <RoutingLensPage
        live
        scope="prod:dc1"
        scopes={["prod:dc1"]}
        earliest={EARLIEST}
        latest={NOW}
        view="overview"
        selectedItem="leaf1.dc1__BGP__10.255.0.2"
        configuration={CONFIG}
        initialResult={initial}
        onChangeParams={noop}
        onBackToHub={noop}
        onRefreshConfig={noop}
      />,
    );
    expect(drawerHtml).toContain('data-testid="protocol-detail-drawer"');
    expect(drawerHtml).toContain("Peer AS 65002");
    expect(drawerHtml).toContain("Local AS 65001");
    expect(drawerHtml).toContain("BGP-5-ADJCHANGE");
    expect(drawerHtml).toContain("pl-kv-list");
    expect(drawerHtml).toContain("/app/splunk_adm/search?");

    const syslogOnly = sampleRoutingResult(true);
    const syslogDrawerHtml = renderToStaticMarkup(
      <RoutingLensPage
        live
        scope="prod:dc1"
        scopes={["prod:dc1"]}
        earliest={EARLIEST}
        latest={NOW}
        view="overview"
        selectedItem="leaf1.dc1__BGP__10.255.0.2"
        configuration={CONFIG}
        initialResult={syslogOnly}
        onChangeParams={noop}
        onBackToHub={noop}
        onRefreshConfig={noop}
      />,
    );
    expect(syslogDrawerHtml).toContain("Not covered");
  });
});
