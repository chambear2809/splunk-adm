import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";
import type { SearchClient } from "../../../data/searchClient";
import type {
  BaseProtocolProfile,
  ProtocolConfiguration,
} from "../../shared/contract";
import {
  EnterpriseL7LensPage,
  buildEnterpriseL7Analysis,
  normalizeEnterpriseL7Row,
  resolveEnterpriseL7Thresholds,
  type EnterpriseL7InvestigationResult,
} from "./index";

const NOW = 1800000500;
const EARLIEST = 1800000000;

const PROFILE: BaseProtocolProfile = {
  id: "enterprise-l7-dc1",
  source: "protocol_enterprise_l7",
  lens: "enterprise_l7",
  scope: "prod:dc1",
  index: "stream_l7",
  observer: "stream-fwd-01",
  validFrom: EARLIEST - 3600,
  validUntil: NOW + 3600,
};

const CONFIG: ProtocolConfiguration = {
  profiles: [PROFILE],
  fingerprint: "fp-test",
};

function sampleEnterpriseL7Result(): EnterpriseL7InvestigationResult {
  const events = [
    normalizeEnterpriseL7Row({
      _time: EARLIEST + 20,
      sourcetype: "stream:smb",
      src_ip: "10.10.20.11",
      dest_ip: "10.10.30.10",
      dialect: "NT LM 0.12",
      nt_status: "STATUS_LOGON_FAILURE",
      response_time: 8400,
      bytes_in: 410,
      bytes_out: 188,
    })!,
    normalizeEnterpriseL7Row({
      _time: EARLIEST + 40,
      sourcetype: "stream:smb",
      src_ip: "10.10.20.15",
      dest_ip: "10.10.30.11",
      dialect: "SMB 3.1.1",
      nt_status: "STATUS_SUCCESS",
      response_time: 1800,
      bytes_in: 190,
      bytes_out: 65536,
    })!,
    normalizeEnterpriseL7Row({
      _time: EARLIEST + 60,
      sourcetype: "stream:ldap",
      src_ip: "10.10.20.30",
      dest_ip: "10.10.30.20",
      dest_port: 389,
      message_type: "bindRequest",
      auth_type: "simple",
      response_time: 11_000,
      bytes_in: 128,
      bytes_out: 96,
    })!,
    ...Array.from({ length: 5 }, (_, i) =>
      normalizeEnterpriseL7Row({
        _time: EARLIEST + 80 + i * 5,
        sourcetype: "stream:radius",
        src_ip: "10.10.1.5",
        dest_ip: "10.10.30.30",
        nas_ip_address: "10.10.1.5",
        code: "Access-Reject",
        time_taken: 6100,
        bytes_in: 148,
        bytes_out: 64,
      })!,
    ),
    normalizeEnterpriseL7Row({
      _time: EARLIEST + 120,
      sourcetype: "stream:sip",
      src_ip: "10.10.40.10",
      dest_ip: "10.10.30.50",
      method: "INVITE",
      response_code: 200,
      response_time: 14_000,
    })!,
    normalizeEnterpriseL7Row({
      _time: EARLIEST + 130,
      sourcetype: "stream:rtp",
      src_ip: "10.10.40.10",
      dest_ip: "10.10.30.50",
      mos: 2.9,
      rtp_jitter: 42,
      packet_loss_pct: 1.6,
      codec: "G.711u",
    })!,
  ].map((event) => ({ event, indexName: "stream_l7" }));

  return buildEnterpriseL7Analysis({
    events,
    thresholds: resolveEnterpriseL7Thresholds(PROFILE),
    configuredProtocols: ["SMB", "LDAP", "RADIUS", "VoIP"],
    earliest: EARLIEST,
    latest: NOW,
    outcomes: [
      {
        source: "protocol_enterprise_l7",
        profile: "enterprise-l7-dc1",
        state: "complete",
      },
    ],
    capped: false,
  });
}

const noop = () => undefined;

describe("EnterpriseL7LensPage", () => {
  it("never auto-searches or checks Stream mode on mount", () => {
    const search = vi.fn();
    const client: SearchClient = { search };
    const html = renderToStaticMarkup(
      <EnterpriseL7LensPage
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
    expect(html).toContain("Enterprise L7");
    expect(html).toContain("Investigate");
    expect(html).toContain("Not checked");
    expect(search).not.toHaveBeenCalled();
  });

  it("renders unavailable banner when no profile covers the scope", () => {
    const html = renderToStaticMarkup(
      <EnterpriseL7LensPage
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

  it("renders Overview with verdict, <=4 KPIs, <=8 columns, flagged-first rows, Not covered for uncollected fields, and DistributionBar", () => {
    const initial = sampleEnterpriseL7Result();
    const html = renderToStaticMarkup(
      <EnterpriseL7LensPage
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
    expect(html).toContain("4 of 5 services need attention");
    expect(html.match(/data-testid="protocol-kpi-tile"/g)?.length).toBe(4);
    expect(html).toContain("Legacy / Insecure Auth");
    expect(html).toContain("L7 Error Rate");
    expect(html).toContain("RADIUS Rejects");
    expect(html).toContain("VoIP Quality Alerts");
    // LDAP row lacked result_code, so its Error / Reject column renders Not covered (not "—").
    expect(html).toContain("Not covered");
    // Flagged rows shown in Overview table; healthy SMB 10.10.30.11 hidden behind Show all (5)
    const tableSlice = html.slice(
      html.indexOf('data-testid="protocol-overview-table"'),
      html.indexOf("</table>"),
    );
    expect(tableSlice).toContain("10.10.30.10");
    expect(tableSlice).not.toContain("10.10.30.11");
    expect(html).toContain("Show all (5)");
    expect(html).toContain('data-testid="protocol-distribution-bar"');
    // Privacy: Overview table NEVER contains user_id or calling_station_id
    expect(html).not.toContain("user_id");
    expect(html).not.toContain("calling_station_id");

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

  it("renders Matrix view with Not covered for unconfigured NFS, None observed when complete, and Unknown when capped", () => {
    const initial = sampleEnterpriseL7Result();
    const completeHtml = renderToStaticMarkup(
      <EnterpriseL7LensPage
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
    expect(completeHtml).toContain("Not covered");
    expect(completeHtml).toContain("None observed");
    expect(completeHtml).toContain("SMBv1");
    expect(completeHtml).toContain("5 rejects");

    const cappedHtml = renderToStaticMarkup(
      <EnterpriseL7LensPage
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

  it("renders Detail Drawer with Status first, CopyableIp controls, pl-kv-list findings, row-expansion opt-in, and safe raw events link", () => {
    const initial = sampleEnterpriseL7Result();
    const radiusDrawerHtml = renderToStaticMarkup(
      <EnterpriseL7LensPage
        client={{ search: vi.fn() }}
        live
        scope="prod:dc1"
        scopes={["prod:dc1"]}
        earliest={EARLIEST}
        latest={NOW}
        view="overview"
        selectedItem="RADIUS__10.10.30.30"
        configuration={CONFIG}
        initialResult={initial}
        onChangeParams={noop}
        onBackToHub={noop}
        onRefreshConfig={noop}
      />,
    );
    expect(radiusDrawerHtml).toContain('data-testid="protocol-detail-drawer"');
    expect(radiusDrawerHtml).toContain("<dt>Status</dt>");
    expect(radiusDrawerHtml).toContain("Copy server 10.10.30.30");
    expect(radiusDrawerHtml).toContain("Copy NAS 10.10.1.5");
    expect(radiusDrawerHtml).toContain("pl-kv-list");
    expect(radiusDrawerHtml).toContain("Load calling_station_id");
    expect(radiusDrawerHtml).toContain("/app/splunk_adm/search?");
  });

  it("renders Estimate-mode banner with explicit Re-check Stream mode button", () => {
    const estimateResult = buildEnterpriseL7Analysis({
      events: [],
      thresholds: resolveEnterpriseL7Thresholds(PROFILE),
      earliest: EARLIEST,
      latest: NOW,
      outcomes: [{ source: "protocol_enterprise_l7", state: "complete" }],
      capped: false,
      streamReadiness: [
        {
          streamId: "smb",
          state: "estimate_only",
          detail: "Stream smb is in Estimate mode (statsOnly=true).",
        },
      ],
    });
    const html = renderToStaticMarkup(
      <EnterpriseL7LensPage
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

  it("renders Unknown (never None observed) when row-expansion lookup is blocked, unavailable, or capped-empty", () => {
    const initial = sampleEnterpriseL7Result();
    const blockedHtml = renderToStaticMarkup(
      <EnterpriseL7LensPage
        client={{ search: vi.fn() }}
        live
        scope="prod:dc1"
        scopes={["prod:dc1"]}
        earliest={EARLIEST}
        latest={NOW}
        view="overview"
        selectedItem="SMB__10.10.30.10"
        configuration={CONFIG}
        initialResult={initial}
        initialExpansion={{
          rowId: "SMB__10.10.30.10",
          result: {
            fieldName: "user_id",
            values: [],
            outcome: {
              source: "protocol_enterprise_l7",
              state: "blocked",
              detail: "Role lacks access to index=stream_smb.",
            },
            capped: false,
          },
        }}
        onChangeParams={noop}
        onBackToHub={noop}
        onRefreshConfig={noop}
      />,
    );
    expect(blockedHtml).toContain("Unknown");
    expect(blockedHtml).toContain("Role lacks access to index=stream_smb.");
    expect(blockedHtml).not.toContain("None observed");

    const cappedHtml = renderToStaticMarkup(
      <EnterpriseL7LensPage
        client={{ search: vi.fn() }}
        live
        scope="prod:dc1"
        scopes={["prod:dc1"]}
        earliest={EARLIEST}
        latest={NOW}
        view="overview"
        selectedItem="SMB__10.10.30.10"
        configuration={CONFIG}
        initialResult={initial}
        initialExpansion={{
          rowId: "SMB__10.10.30.10",
          result: {
            fieldName: "user_id",
            values: [],
            outcome: {
              source: "protocol_enterprise_l7",
              state: "complete",
            },
            capped: true,
          },
        }}
        onChangeParams={noop}
        onBackToHub={noop}
        onRefreshConfig={noop}
      />,
    );
    expect(cappedHtml).toContain("Unknown");
    expect(cappedHtml).toContain("row cap");
    expect(cappedHtml).not.toContain("None observed");
  });
});
