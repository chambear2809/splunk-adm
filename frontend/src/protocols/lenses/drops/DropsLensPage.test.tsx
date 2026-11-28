import { readFileSync } from "node:fs";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import type { SearchClient } from "../../../data/searchClient";
import type {
  BaseProtocolProfile,
  ProtocolConfiguration,
} from "../../shared/contract";
import {
  buildDropsAnalysis,
  DropsLensPage,
  normalizeDropsRow,
  resolveDropsThresholds,
  type DropsInvestigationResult,
} from "./index";

const EARLIEST = 1791373700;
const LATEST = 1791374500;

const PROFILE: BaseProtocolProfile = {
  id: "drops-dc1",
  source: "protocol_drops",
  lens: "drops",
  scope: "prod:dc1",
  index: "cisco_secure_fw",
  observer: "ftd-edge",
  validFrom: EARLIEST - 3600,
  validUntil: LATEST + 3600,
};

const CONFIG: ProtocolConfiguration = {
  profiles: [PROFILE],
  fingerprint: "fp-drops-ui-test",
};

function loadFixtureEvents(path: string, indexName: string) {
  return readFileSync(path, "utf8")
    .trim()
    .split("\n")
    .map((line) => {
      const env = JSON.parse(line) as {
        time: number;
        host: string;
        sourcetype: string;
        event: Record<string, unknown>;
      };
      return normalizeDropsRow({
        _time: env.time,
        host: env.host,
        sourcetype: env.sourcetype,
        ...env.event,
      });
    })
    .filter((e): e is NonNullable<typeof e> => Boolean(e))
    .map((event) => ({ event, indexName }));
}

function sampleDropsResult(dropWarnCount = 1): DropsInvestigationResult {
  const events = [
    ...loadFixtureEvents(
      "fixtures/protocols/drops/ftd_drops.ndjson",
      "cisco_secure_fw",
    ),
    ...loadFixtureEvents(
      "fixtures/protocols/drops/hubble_drops.ndjson",
      "cilium_hubble",
    ),
    ...loadFixtureEvents(
      "fixtures/protocols/drops/nd_aci_drops.ndjson",
      "cisco_dc",
    ),
  ];

  return buildDropsAnalysis({
    events,
    thresholds: resolveDropsThresholds({
      ...PROFILE,
      extra: { dropWarnCount },
    }),
    earliest: EARLIEST,
    latest: LATEST,
    outcomes: [
      { source: "protocol_drops", profile: "drops-dc1", state: "complete" },
    ],
    capped: false,
  });
}

const noop = () => undefined;

describe("DropsLensPage", () => {
  it("never auto-searches on mount", () => {
    const search = vi.fn();
    const client: SearchClient = { search };
    const html = renderToStaticMarkup(
      <DropsLensPage
        client={client}
        live
        scope="prod:dc1"
        scopes={["prod:dc1"]}
        earliest={EARLIEST}
        latest={LATEST}
        view="overview"
        configuration={CONFIG}
        onChangeParams={noop}
        onBackToHub={noop}
        onRefreshConfig={noop}
      />,
    );
    expect(html).toContain("Blocked Traffic &amp; Drops");
    expect(html).toContain("Investigate");
    expect(html).toContain("Not checked");
    expect(search).not.toHaveBeenCalled();
  });

  it("renders unavailable banner when no profile covers the scope", () => {
    const html = renderToStaticMarkup(
      <DropsLensPage
        live
        scope="prod:dc2"
        scopes={["prod:dc2"]}
        earliest={EARLIEST}
        latest={LATEST}
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

  it("renders Overview with verdict, <=4 KPIs, <=8 columns, SwimlaneTimeline, and <60 chrome words", () => {
    const initial = sampleDropsResult();
    const html = renderToStaticMarkup(
      <DropsLensPage
        live
        scope="prod:dc1"
        scopes={["prod:dc1"]}
        earliest={EARLIEST}
        latest={LATEST}
        view="overview"
        configuration={CONFIG}
        initialResult={initial}
        onChangeParams={noop}
        onBackToHub={noop}
        onRefreshConfig={noop}
      />,
    );
    expect(html).toContain('data-testid="protocol-verdict"');
    expect(html).toContain("blocked flows attributed");
    expect(html.match(/data-testid="protocol-kpi-tile"/g)?.length).toBe(4);
    expect(html).toContain("Drop Events");
    expect(html).toContain("Blocked Pairs");
    expect(html).toContain("Top Enforcer");
    expect(html).toContain("Dropped Packets");
    expect(html).toContain("FTD");
    expect(html).toContain("Hubble");
    expect(html).toContain("Nexus Dashboard");
    expect(html).toContain("ACI");
    expect(html).toContain('data-testid="protocol-timeline"');
    expect(html).toContain("Drops by enforcer");

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

  it("hides lower-volume rows behind Show all (n) when dropWarnCount > 1", () => {
    const initial = sampleDropsResult(2);
    const html = renderToStaticMarkup(
      <DropsLensPage
        live
        scope="prod:dc1"
        scopes={["prod:dc1"]}
        earliest={EARLIEST}
        latest={LATEST}
        view="overview"
        configuration={CONFIG}
        initialResult={initial}
        onChangeParams={noop}
        onBackToHub={noop}
        onRefreshConfig={noop}
      />,
    );
    // Hubble pair has 2 events (flagged); 6 single-event rows sit behind Show all (7)
    expect(html).toContain("10.42.0.15");
    expect(html).toContain("Show all (7)");
  });

  it("renders StatusChip not_covered (never dash) when Service/Port or Dropped Packets is not collected", () => {
    const hubbleNoPort = buildDropsAnalysis({
      events: [
        {
          event: normalizeDropsRow(
            {
              _time: EARLIEST + 30,
              host: "k8s-node-a",
              sourcetype: "cilium:hubble:flow",
              verdict: "DROPPED",
              drop_reason_desc: "POLICY_DENIED",
              src_ip: "10.42.0.15",
              dest_ip: "10.96.12.40",
            },
            "hubble",
          )!,
          indexName: "cilium_hubble",
        },
      ],
      thresholds: resolveDropsThresholds(PROFILE),
      earliest: EARLIEST,
      latest: LATEST,
      outcomes: [
        { source: "protocol_drops", profile: "drops-dc1", state: "complete" },
      ],
      capped: false,
    });
    const html = renderToStaticMarkup(
      <DropsLensPage
        live
        scope="prod:dc1"
        scopes={["prod:dc1"]}
        earliest={EARLIEST}
        latest={LATEST}
        view="overview"
        configuration={CONFIG}
        initialResult={hubbleNoPort}
        onChangeParams={noop}
        onBackToHub={noop}
        onRefreshConfig={noop}
      />,
    );
    expect(html).toContain("pl-status-not_covered");
    expect(html).toContain("Not covered");
  });

  it("renders Matrix view with None observed when complete and Unknown when capped", () => {
    const initial = sampleDropsResult();
    const completeHtml = renderToStaticMarkup(
      <DropsLensPage
        live
        scope="prod:dc1"
        scopes={["prod:dc1"]}
        earliest={EARLIEST}
        latest={LATEST}
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

    const cappedHtml = renderToStaticMarkup(
      <DropsLensPage
        live
        scope="prod:dc1"
        scopes={["prod:dc1"]}
        earliest={EARLIEST}
        latest={LATEST}
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

  it("renders Detail Drawer with Status first, native details ul.pl-kv-list, CopyableIp, and literal() raw link", () => {
    const initial = sampleDropsResult();
    const hubbleRow = initial.rows.find((r) => r.enforcerKind === "hubble")!;
    const drawerHtml = renderToStaticMarkup(
      <DropsLensPage
        live
        scope="prod:dc1"
        scopes={["prod:dc1"]}
        earliest={EARLIEST}
        latest={LATEST}
        view="overview"
        selectedItem={hubbleRow.id}
        configuration={CONFIG}
        initialResult={initial}
        onChangeParams={noop}
        onBackToHub={noop}
        onRefreshConfig={noop}
      />,
    );
    expect(drawerHtml).toContain('data-testid="protocol-detail-drawer"');
    expect(drawerHtml).toContain("<dt>Status</dt>");
    expect(drawerHtml).toContain("Copy source 10.42.0.15");
    expect(drawerHtml).toContain("Copy destination 10.96.12.40");
    expect(drawerHtml).toContain("pl-kv-list");
    expect(drawerHtml).toContain("drop_reason_desc: POLICY_DENIED");
    expect(drawerHtml).toContain("shop/web-1");
    expect(drawerHtml).toContain("/app/splunk_adm/search?");
  });

  it("uses None observed wording on empty result and never claims delivery", () => {
    const emptyResult = buildDropsAnalysis({
      events: [],
      thresholds: resolveDropsThresholds(PROFILE),
      earliest: EARLIEST,
      latest: LATEST,
      outcomes: [
        { source: "protocol_drops", profile: "drops-dc1", state: "complete" },
      ],
      capped: false,
    });
    expect(emptyResult.verdict).toBe(
      "No drops observed in configured sources.",
    );
    expect(emptyResult.verdictStatus).toBe("none_observed");
    const html = renderToStaticMarkup(
      <DropsLensPage
        live
        scope="prod:dc1"
        scopes={["prod:dc1"]}
        earliest={EARLIEST}
        latest={LATEST}
        view="overview"
        configuration={CONFIG}
        initialResult={emptyResult}
        onChangeParams={noop}
        onBackToHub={noop}
        onRefreshConfig={noop}
      />,
    );
    expect(html).toContain('data-testid="protocol-state-empty"');
    expect(html).toContain("None observed");
    expect(html.toLowerCase()).not.toContain("delivered");
  });
});
