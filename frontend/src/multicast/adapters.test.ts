import { describe, expect, it, vi } from "vitest";
import candidates from "../../../fixtures/multicast/candidates.json";
import {
  SearchAccessDeniedError,
  type SearchClient,
} from "../data/searchClient";
import type { StreamProfile, MulticastRequest } from "./contract";
import { buildMulticastSearch, loadMulticastSource } from "./adapters";

const request: MulticastRequest = {
  version: 1,
  scope: "prod",
  group: "239.1.2.3",
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
  observer: "192.0.2.1",
  source: "multicast_netflow",
  observationDomain: "1",
  template: "256",
  direction: "ingress",
  samplingInterval: 1,
  replication: "before",
  counters: "delta",
};
const row = (payload: unknown, host = "sensor1") => ({
  kind: "record",
  index: "multicast",
  host,
  _time: 150,
  oversized: 0,
  payload: JSON.stringify({
    ...(payload as object),
    network_interface: "eth0",
  }),
});
function client(
  rows: ReturnType<typeof row>[],
  overrides: Record<string, unknown> = {},
): SearchClient {
  return {
    search: vi.fn(async () => ({
      rows: [
        ...rows,
        {
          kind: "completion",
          input_count: rows.length,
          returned_count: rows.length,
          oversized_count: 0,
          ...overrides,
        },
      ],
      warnings: [],
      errors: [],
    })),
  };
}
const run = (
  profile: StreamProfile,
  rows: ReturnType<typeof row>[],
  overrides?: Record<string, unknown>,
) =>
  loadMulticastSource(
    client(rows, overrides),
    profile,
    request,
    new AbortController().signal,
  );

describe("candidate multicast sources", () => {
  it("preserves repeated IGMP reports and distinct v3 records with exact source counts", async () => {
    const result = await run(igmp, [
      row(candidates.igmpV2),
      row(candidates.igmpV2),
      row(candidates.igmpV3Flat),
    ]);
    expect(result.outcome.state).toBe("complete");
    expect(result.evidence).toHaveLength(3);
    expect(result.evidence[0].id).not.toBe(result.evidence[1].id);
    expect(result.evidence[0]).toMatchObject({ reporterKind: "endpoint" });
    expect(result.evidence[2]).toMatchObject({
      reporterKind: "proxy",
      operation: "include",
      sources: ["192.0.2.20", "192.0.2.21"],
    });
  });
  it("rejects ambiguous or malformed group lists and oversize events", async () => {
    const bad = { ...candidates.igmpV3Flat, group_record_num_sources: [1, 1] };
    const result = await run(igmp, [
      row(bad),
      { ...row(candidates.igmpV2), payload: " ".repeat(33000) },
    ]);
    expect(result.evidence).toEqual([]);
    expect(result.outcome.state).toBe("partial");
    const single = await run({ ...igmp, v3Encoding: "single-record" }, [
      row(candidates.igmpV3Flat),
    ]);
    expect(single.outcome.state).toBe("partial");
  });
  it("keeps NetFlow sampling and replication attestations with the observation", async () => {
    const result = await run(flow, [
      row({ ...candidates.netflow, input_snmpidx: 11 }),
    ]);
    expect(result.evidence[0]).toMatchObject({
      kind: "flow",
      sender: "192.0.2.20",
      packets: 8,
      bytes: 1024,
      replication: "before",
      interface: "ifIndex 11",
    });
    const wrongExporter = await run(flow, [
      row({ ...candidates.netflow, exporter_ip: "192.0.2.2" }),
    ]);
    expect(wrongExporter.evidence).toEqual([]);
    expect(wrongExporter.outcome.state).toBe("partial");
  });
  it("rejects incomplete search envelopes and reports capped input", async () => {
    expect(
      (await run(igmp, [row(candidates.igmpV2)], { returned_count: 2 })).outcome
        .state,
    ).toBe("unavailable");
    const rows = Array.from({ length: 256 }, () => row(candidates.igmpV2));
    expect((await run(igmp, rows, { input_count: 257 })).outcome.state).toBe(
      "partial",
    );
  });
  it("caps v3 expansion and refuses profiles outside the requested history", async () => {
    const multi = {
      ...candidates.igmpV3Flat,
      num_groups: 64,
      group_record_type: Array(64).fill(1),
      group_record_multicast_address: Array(64).fill(request.group),
      group_record_num_sources: Array(64).fill(0),
      group_record_source_address: [],
    };
    const result = await run(
      igmp,
      Array.from({ length: 5 }, () => row(multi)),
    );
    expect(result.evidence).toHaveLength(256);
    expect(result.outcome.state).toBe("partial");
    const expired = await run({ ...igmp, validUntil: 199 }, [
      row(candidates.igmpV2),
    ]);
    expect(expired.outcome.state).toBe("blocked");
  });
  it("distinguishes denied access and propagates cancellation", async () => {
    const denied: SearchClient = {
      search: async () => {
        throw new SearchAccessDeniedError();
      },
    };
    const result = await loadMulticastSource(
      denied,
      igmp,
      request,
      new AbortController().signal,
    );
    expect(result.outcome.state).toBe("blocked");
    const controller = new AbortController();
    controller.abort();
    await expect(
      loadMulticastSource(denied, igmp, request, controller.signal),
    ).rejects.toThrow(/cancelled/);
  });
  it("uses fixed literal selectors and bounded projection", () => {
    const search = buildMulticastSearch(igmp, request);
    expect(search).toContain(
      'index="multicast" sourcetype="stream:igmp" host="sensor1"',
    );
    const candidateSearch = search.split("| head")[0];
    expect(candidateSearch).toContain(
      'json_extract(_raw,"network_interface")="eth0"',
    );
    expect(candidateSearch).toContain(
      'mvfind(json_array_to_mv(json_extract(_raw,"group_record_multicast_address")),"^239[.]1[.]2[.]3$")',
    );
    expect(search).toContain("head 257");
    expect(search).not.toContain("| lookup");
    expect(() =>
      buildMulticastSearch({ ...igmp, index: 'bad" OR index=*' }, request),
    ).toThrow();
  });
});
