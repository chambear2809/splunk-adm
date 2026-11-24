import { describe, expect, it, vi } from "vitest";
import candidates from "../../../fixtures/multicast/candidates.json";
import {
  SearchAccessDeniedError,
  type SearchClient,
} from "../data/searchClient";
import type { ScopeWindow, StreamProfile } from "./contract";
import { buildGroupSummarySearch, loadGroupSummary } from "./groupSummary";
import { validateScopeWindow } from "./inputs";

const fixture = candidates.groupSummary;
const window: ScopeWindow = {
  version: 1,
  scope: "prod",
  earliest: 100,
  latest: 200,
};
const common = {
  id: "p1",
  scope: "prod",
  index: "multicast",
  observer: "sensor1",
  validFrom: 1,
  validUntil: 300,
};
const igmp: StreamProfile = {
  ...common,
  source: "multicast_igmp",
  captureInterface: "eth0",
  segment: { kind: "vlan", id: "10", domain: "fabric" },
  placement: "endpoint",
  endpointReporters: ["192.0.2.10"],
  proxyReporters: ["192.0.2.11"],
  v3Encoding: "flat-counted",
};
const flow: StreamProfile = {
  ...common,
  id: "p2",
  observer: "192.0.2.1",
  source: "multicast_netflow",
  observationDomain: "1",
  template: "256",
  direction: "ingress",
  samplingInterval: 100,
  replication: "after",
  counters: "total",
};
type Row = Record<string, unknown>;
const record = (row: Row) => ({ kind: "record", ...row });
function client(rows: Row[], overrides: Row = {}): SearchClient {
  const groups = rows.filter((row) => row.group !== "0.0.0.0").length;
  return {
    search: vi.fn(async () => ({
      rows: [
        ...rows.map(record),
        {
          kind: "completion",
          returned_count: rows.length,
          group_count: groups,
          ...overrides,
        },
      ],
      warnings: [],
      errors: [],
    })),
  };
}
const run = (profile: StreamProfile, rows: Row[], overrides?: Row) =>
  loadGroupSummary(
    client(rows, overrides),
    profile,
    window,
    new AbortController().signal,
  );

describe("multicast group summary", () => {
  it("summarises IGMP reports, leaves and group queries per group", async () => {
    const result = await run(igmp, [fixture.igmpV2Group]);
    expect(result.outcome).toMatchObject({ profile: "p1", state: "complete" });
    expect(result.droppedGroups).toBe(0);
    expect(result.summaries).toEqual([
      {
        kind: "igmp",
        profile: "p1",
        group: "239.1.2.3",
        segment: igmp.segment,
        reports: 1,
        leaves: 1,
        groupQueries: 1,
        endpointReporters: ["192.0.2.10"],
        otherReporters: 0,
        firstSeen: 150,
        lastSeen: 161,
        lastLeave: 160,
        lastGroupQuery: 161,
      },
    ]);
  });

  it("counts each IGMPv3 group record under its own group", async () => {
    const result = await run(igmp, fixture.igmpV3Groups);
    expect(result.outcome.state).toBe("complete");
    expect(result.summaries.map((row) => [row.group, row.kind])).toEqual([
      ["239.1.2.3", "igmp"],
      ["239.1.2.4", "igmp"],
    ]);
    for (const row of result.summaries)
      expect(row).toMatchObject({ reports: 1, leaves: 0 });
    const search = buildGroupSummarySearch(igmp, window);
    for (const field of [
      "group_record_multicast_address",
      "group_record_type",
      "group_record_num_sources",
    ])
      expect(search).toContain(
        `coalesce(json_array_to_mv(json_extract(_raw,"${field}")),json_extract(_raw,"${field}"))`,
      );
  });

  it("does not count v3 include records without sources as reports", () => {
    const search = buildGroupSummarySearch(igmp, window);
    const classify = search.indexOf("class=case(");
    const none = search.indexOf('t=34 AND op=1 AND n=0,"none"');
    expect(none).toBeGreaterThan(classify);
    expect(none).toBeLessThan(search.indexOf('"leave"', classify));
    expect(none).toBeLessThan(search.indexOf('"report"', classify));
    expect(search).toContain('| where class!="none"');
  });

  it("excludes general queries from group rows", async () => {
    const result = await run(igmp, [fixture.igmpGeneral, fixture.igmpV2Group]);
    expect(result.outcome.state).toBe("complete");
    expect(result.summaries.map((row) => row.group)).toEqual(["239.1.2.3"]);
    expect(result.queries).toEqual({
      profile: "p1",
      querySenders: [{ address: "192.0.2.1", first: 161, last: 170 }],
      lastGeneralQuery: 170,
    });
    const generalOnly = await run(igmp, [fixture.igmpGeneral]);
    expect(generalOnly.summaries).toEqual([]);
    expect(generalOnly.queries?.lastGeneralQuery).toBe(170);
  });

  it("attributes only attested endpoint reporters", async () => {
    const result = await run(igmp, [fixture.igmpMixedReporters]);
    expect(result.summaries[0]).toMatchObject({
      endpointReporters: ["192.0.2.10"],
      otherReporters: 1,
    });
    const transit = await run(
      { ...igmp, placement: "transit", endpointReporters: [] },
      [fixture.igmpMixedReporters],
    );
    expect(transit.summaries[0]).toMatchObject({
      endpointReporters: [],
      otherReporters: 2,
    });
  });

  it("summarises NetFlow by group with declared counter meaning", async () => {
    const result = await run(flow, [fixture.netflowGroup]);
    expect(result.outcome.state).toBe("complete");
    expect(result.queries).toBeUndefined();
    expect(result.summaries).toEqual([
      {
        kind: "flow",
        profile: "p2",
        group: "239.1.2.3",
        observer: "192.0.2.1",
        direction: "ingress",
        senders: ["192.0.2.20", "192.0.2.21"],
        packets: 16,
        bytes: 2048,
        samplingInterval: 100,
        replication: "after",
        counters: "total",
        firstSeen: 150,
        lastSeen: 160,
      },
    ]);
  });

  it("caps at 256 groups and reports partial", async () => {
    const rows = Array.from({ length: 256 }, (_, i) => ({
      ...fixture.igmpV2Group,
      group: `239.1.${Math.floor(i / 256)}.${i % 256}`,
    }));
    const result = await run(igmp, [fixture.igmpGeneral, ...rows], {
      group_count: 300,
    });
    expect(result.summaries).toHaveLength(256);
    expect(result.droppedGroups).toBe(44);
    expect(result.outcome.state).toBe("partial");
    expect(result.outcome.detail).toMatch(/44/);
    const withGeneral = await run(igmp, [fixture.igmpGeneral, ...rows], {
      group_count: 256,
    });
    expect(withGeneral.summaries).toHaveLength(256);
    expect(withGeneral.outcome.state).toBe("complete");
    const overflow = [
      ...rows,
      { ...fixture.igmpV2Group, group: "239.1.1.0", last_seen: 150 },
    ];
    const noGeneral = await run(igmp, overflow, {
      returned_count: 257,
      group_count: 300,
    });
    expect(noGeneral.outcome.state).toBe("partial");
    expect(noGeneral.summaries).toHaveLength(256);
    expect(noGeneral.summaries.map((row) => row.group)).not.toContain(
      "239.1.1.0",
    );
    expect(noGeneral.droppedGroups).toBe(44);
  });

  it("fails closed on invalid envelopes, groups and denied access", async () => {
    expect(
      (await run(igmp, [fixture.igmpV2Group], { returned_count: 2 })).outcome
        .state,
    ).toBe("unavailable");
    expect(
      (await run(igmp, [fixture.igmpV2Group], { group_count: 2 })).outcome
        .state,
    ).toBe("unavailable");
    const bad = await run(igmp, [
      fixture.igmpV2Group,
      { ...fixture.igmpV2Group, group: "10.0.0.1" },
    ]);
    expect(bad.summaries).toHaveLength(1);
    expect(bad.droppedGroups).toBe(1);
    expect(bad.outcome.state).toBe("partial");
    const denied = await loadGroupSummary(
      {
        search: async () => {
          throw new SearchAccessDeniedError();
        },
      },
      igmp,
      window,
      new AbortController().signal,
    );
    expect(denied.outcome.state).toBe("blocked");
  });

  it("blocks profiles that do not cover the window", async () => {
    const stub = client([fixture.igmpV2Group]);
    const result = await loadGroupSummary(
      stub,
      { ...igmp, validUntil: 199 },
      window,
      new AbortController().signal,
    );
    expect(stub.search).not.toHaveBeenCalled();
    expect(result.summaries).toEqual([]);
    expect(result.outcome).toMatchObject({
      profile: "p1",
      state: "unavailable",
      detail: "Source verification does not cover the selected time window.",
    });
  });

  it("the search binds scope inputs literally", async () => {
    const scoped: ScopeWindow = {
      ...window,
      earliest: 1795283857,
      latest: 1795284157,
    };
    const search = buildGroupSummarySearch({ ...igmp, index: "mclab" }, scoped);
    for (const value of ["mclab", "sensor1", "eth0"])
      expect(search.split(value).length).toBe(
        search.split(`"${value}"`).length,
      );
    expect(search).toContain(
      'index="mclab" sourcetype="stream:igmp" host="sensor1"',
    );
    expect(search).toContain('json_extract(_raw,"network_interface")="eth0"');
    expect(search).not.toContain("1795283857");
    expect(search).not.toContain("1795284157");
    expect(search).toContain("appendpipe [| stats count AS returned_count");
    expect(() =>
      buildGroupSummarySearch({ ...igmp, index: 'bad" OR index=*' }, scoped),
    ).toThrow();
    expect(() =>
      buildGroupSummarySearch({ ...igmp, observer: 'x" OR host=*' }, scoped),
    ).toThrow();
    const flowSearch = buildGroupSummarySearch(flow, scoped);
    expect(flowSearch).toContain(
      'json_extract(_raw,"exporter_ip")="192.0.2.1"',
    );
    expect(flowSearch).not.toContain("1795283857");
    const stub = client([]);
    await loadGroupSummary(
      stub,
      { ...igmp, validUntil: 1795290000 },
      scoped,
      new AbortController().signal,
    );
    expect(stub.search).toHaveBeenCalledWith(
      expect.objectContaining({
        search: buildGroupSummarySearch(igmp, scoped),
        earliest: "1795283857",
        latest: "1795284157",
        maxRows: 258,
      }),
    );
  });

  it("validates scope windows like investigation requests", () => {
    expect(
      validateScopeWindow({ ...window, group: "239.1.2.3" }, 1000),
    ).toEqual(window);
    expect(() =>
      validateScopeWindow({ ...window, scope: "unmapped:lab" }, 1000),
    ).toThrow(/scope/);
    expect(() =>
      validateScopeWindow({ ...window, latest: 100 + 3601 }, 10000),
    ).toThrow(/one hour/);
    expect(() => validateScopeWindow(window, 150)).toThrow(/one hour/);
    expect(() => validateScopeWindow({ ...window, version: 2 })).toThrow();
  });
});
