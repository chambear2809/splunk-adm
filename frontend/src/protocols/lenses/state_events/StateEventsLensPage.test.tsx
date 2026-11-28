import { readFileSync } from "node:fs";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import type { SearchClient } from "../../../data/searchClient";
import type {
  BaseProtocolProfile,
  ProtocolConfiguration,
} from "../../shared/contract";
import {
  StateEventsLensPage,
  buildStateEventsAnalysis,
  normalizeAciFaultEventRow,
  normalizeStateSyslogRow,
  resolveStateEventsThresholds,
  type StateEventsInvestigationResult,
} from "./index";

const EARLIEST = 1764246600;
const NOW = 1764248400;

const PROFILE: BaseProtocolProfile = {
  id: "state-events-dc1",
  source: "protocol_state_events",
  lens: "state_events",
  scope: "prod:dc1",
  index: "cisco_dc",
  observer: "sc4s-dc1",
  validFrom: EARLIEST - 3600,
  validUntil: NOW + 3600,
};

const CONFIG: ProtocolConfiguration = {
  profiles: [PROFILE],
  fingerprint: "fp-state-events-test",
};

function sampleStateEventsResult(): StateEventsInvestigationResult {
  const syslogRows = readFileSync(
    "fixtures/protocols/state_events/nxos_state_syslog.ndjson",
    "utf8",
  )
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line) as Record<string, unknown>);
  const aciRows = readFileSync(
    "fixtures/protocols/state_events/aci_fault_event.ndjson",
    "utf8",
  )
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line) as Record<string, unknown>);

  const events = [
    ...syslogRows
      .map((r, i) => normalizeStateSyslogRow(r, i))
      .filter((e): e is NonNullable<typeof e> => Boolean(e))
      .map((event) => ({ event, indexName: "cisco_dc" })),
    ...aciRows
      .map((r, i) => normalizeAciFaultEventRow(r, i))
      .filter((e): e is NonNullable<typeof e> => Boolean(e))
      .map((event) => ({ event, indexName: "cisco_dc" })),
  ];

  return buildStateEventsAnalysis({
    events,
    thresholds: resolveStateEventsThresholds(PROFILE),
    earliest: EARLIEST,
    latest: NOW,
    outcomes: [
      {
        source: "protocol_state_events",
        profile: "state-events-dc1",
        state: "complete",
      },
    ],
    capped: false,
  });
}

const noop = () => undefined;

describe("StateEventsLensPage", () => {
  it("never auto-searches on mount", () => {
    const search = vi.fn();
    const client: SearchClient = { search };
    const html = renderToStaticMarkup(
      <StateEventsLensPage
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
    expect(html).toContain("State-Change Timeline");
    expect(html).toContain("Investigate");
    expect(html).toContain("Not checked");
    expect(search).not.toHaveBeenCalled();
  });

  it("renders unavailable banner when no profile covers the scope", () => {
    const html = renderToStaticMarkup(
      <StateEventsLensPage
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

  it("renders Overview with verdict, <=4 KPIs, flagged-first rows, SwimlaneTimeline, DistributionBar, and <60 chrome words", () => {
    const initial = sampleStateEventsResult();
    const html = renderToStaticMarkup(
      <StateEventsLensPage
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
    expect(html).toContain("14 state changes across 6 devices");
    expect(html.match(/data-testid="protocol-kpi-tile"/g)?.length).toBe(4);
    expect(html).toContain("State Events");
    expect(html).toContain("Critical / Error");
    expect(html).toContain("Burst Devices");

    // Healthy rows hidden behind Show all (6) in the overview table
    const tablePart = html.split("Show all (6)")[0];
    expect(tablePart).toContain("192.0.2.11");
    expect(tablePart).toContain("pod-1/node-201");
    expect(tablePart).not.toContain("spine-01");
    expect(html).toContain("Show all (6)");

    expect(html).toContain('data-testid="protocol-timeline"');
    expect(html).toContain("Device timeline");
    expect(html).toContain('data-testid="protocol-distribution-bar"');
    expect(html).toContain("Operational domains");

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

  it("renders Matrix view with Device × operational domain HeatMatrix (none_observed vs unknown when capped/partial)", () => {
    const initial = sampleStateEventsResult();
    const completeHtml = renderToStaticMarkup(
      <StateEventsLensPage
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
    expect(completeHtml).toContain("192.0.2.11 to HSRP/VRRP");

    const cappedHtml = renderToStaticMarkup(
      <StateEventsLensPage
        live
        scope="prod:dc1"
        scopes={["prod:dc1"]}
        earliest={EARLIEST}
        latest={NOW}
        view="matrix"
        configuration={CONFIG}
        initialResult={{ ...initial, capped: true, bannerState: "partial" }}
        onChangeParams={noop}
        onBackToHub={noop}
        onRefreshConfig={noop}
      />,
    );
    expect(cappedHtml).toContain("Unknown");
  });

  it("renders Detail Drawer with Status first, CopyableIp, transitions list, HSRP/VRRP syslog note, and literal search link", () => {
    const initial = sampleStateEventsResult();
    const drawerHtml = renderToStaticMarkup(
      <StateEventsLensPage
        live
        scope="prod:dc1"
        scopes={["prod:dc1"]}
        earliest={EARLIEST}
        latest={NOW}
        view="overview"
        selectedItem="192.0.2.11"
        configuration={CONFIG}
        initialResult={initial}
        onChangeParams={noop}
        onBackToHub={noop}
        onRefreshConfig={noop}
      />,
    );
    expect(drawerHtml).toContain('data-testid="protocol-detail-drawer"');
    expect(drawerHtml).toContain("Copy device 192.0.2.11");
    expect(drawerHtml).toContain("pl-kv-list");
    expect(drawerHtml).toContain(
      "HSRP/VRRP transitions are qualified via syslog only",
    );
    expect(drawerHtml).toContain("ETHPORT-3-IF_DOWN_LINK_FAILURE");
    expect(drawerHtml).toContain("/app/splunk_adm/search?");
  });
});
