import { beforeEach, describe, expect, it, vi } from "vitest";
import type { SearchClient, SearchRequest } from "../data/searchClient";
import type { ScopeWindow } from "./contract";
import {
  MulticastConfigurationChangedError,
  readMulticastConfiguration,
} from "./investigation";
import { investigateScope } from "./scopeOverview";

type Row = Record<string, unknown>;
type Responder = (source: string, request: SearchRequest) => Row[];

const stub = vi.hoisted(() => ({
  documents: [] as unknown[],
  runs: [] as { source: string; key: string; earliest: string }[],
  respond: (() => []) as (source: string, request: SearchRequest) => Row[],
}));

vi.mock("../data/evidenceConfig", () => ({
  multicastConfigClient: {
    readMulticastProfileDocument: vi.fn(async () =>
      stub.documents.length > 1 ? stub.documents.shift() : stub.documents[0],
    ),
  },
}));

vi.mock("../data/optionalJobs", () => ({
  optionalJobs: {
    run: vi.fn(
      async (
        source: string,
        key: string,
        _client: SearchClient,
        request: SearchRequest,
      ) => {
        stub.runs.push({ source, key, earliest: String(request.earliest) });
        const rows = stub.respond(source, request);
        return {
          rows: [
            ...rows.map((row) => ({ kind: "record", ...row })),
            {
              kind: "completion",
              returned_count: rows.length,
              group_count: rows.length,
            },
          ],
          warnings: [],
          errors: [],
        };
      },
    ),
  },
}));

const window: ScopeWindow = {
  version: 1,
  scope: "prod",
  earliest: 1000,
  latest: 1300,
};
const common = {
  scope: "prod",
  index: "multicast",
  validFrom: 1,
  validUntil: 5000,
};
const igmp = {
  ...common,
  id: "igmp",
  observer: "sensor1",
  source: "multicast_igmp",
  captureInterface: "eth0",
  segment: { kind: "vlan", id: "10", domain: "fabric" },
  placement: "endpoint",
  endpointReporters: ["192.0.2.10"],
  proxyReporters: [],
  v3Encoding: "flat-counted",
} as const;
const flow = {
  ...common,
  id: "flow",
  observer: "192.0.2.1",
  source: "multicast_netflow",
  observationDomain: "1",
  template: "256",
  direction: "ingress",
  samplingInterval: 1,
  replication: "after",
  counters: "delta",
} as const;
const nxos = {
  ...common,
  id: "nxos",
  observer: "leaf1",
  source: "multicast_nxos",
} as const;
const other = { ...flow, id: "other", scope: "other", observer: "192.0.2.2" };

const document = (profiles: object[]) => ({
  version: 1,
  profiles,
});

function flowRow(group: string, time: number, capped = false): Row {
  return {
    group,
    senders: ["192.0.2.20"],
    sender_count: capped ? 2 : 1,
    packets: 10,
    bytes: 1000,
    first_seen: time,
    last_seen: time,
  };
}
function igmpRow(group: string, time: number): Row {
  return {
    group,
    reports: 1,
    leaves: 0,
    group_queries: 0,
    reporters: "192.0.2.10",
    reporter_count: 1,
    first_seen: time,
    last_seen: time,
    query_sender_count: 0,
  };
}

/** Current window groups 239.1.1.1 and 239.1.1.2; previous window only 239.1.1.1. */
const respond: Responder = (source, request) => {
  const time = Number(request.earliest) + 10;
  const previous = Number(request.earliest) < window.earliest;
  const groups = previous ? ["239.1.1.1"] : ["239.1.1.1", "239.1.1.2"];
  return groups.map((group) =>
    source === "multicast_igmp" ? igmpRow(group, time) : flowRow(group, time),
  );
};

async function setup(profiles: object[] = [igmp, flow, nxos, other]) {
  stub.documents = [document(profiles)];
  const configuration = await readMulticastConfiguration();
  stub.runs = [];
  return configuration;
}
const client: SearchClient = { search: vi.fn() };
const signal = () => new AbortController().signal;

beforeEach(() => {
  stub.respond = respond;
  stub.runs = [];
});

describe("multicast scope overview", () => {
  it("names the forwarding snapshot when the scope has no Stream profile", async () => {
    const configuration = await setup([nxos]);
    await expect(
      investigateScope(client, window, configuration, signal()),
    ).rejects.toThrow(
      "This scope has only a verified forwarding snapshot. Overview and Matrix summarise Stream IGMP and NetFlow; open a group link to inspect the snapshot.",
    );
    expect(stub.runs).toHaveLength(0);
  });

  it("gives the generic message when the scope has no profile at all", async () => {
    const configuration = await setup([other]);
    await expect(
      investigateScope(client, window, configuration, signal()),
    ).rejects.toThrow(
      "Choose a routing scope with a verified multicast source.",
    );
  });

  it("searches only IGMP and NetFlow profiles of the scope", async () => {
    const configuration = await setup();
    const result = await investigateScope(
      client,
      window,
      configuration,
      signal(),
    );
    expect(stub.runs.map((run) => run.source).sort()).toEqual([
      "multicast_igmp",
      "multicast_netflow",
    ]);
    expect(result.profiles.map((profile) => profile.outcome.profile)).toEqual([
      "flow",
      "igmp",
    ]);
    expect(result.comparison).toEqual({ state: "not-run" });
    expect(result.rows.map((row) => row.group).sort()).toEqual([
      "239.1.1.1",
      "239.1.1.2",
    ]);
    expect(result.rows.flatMap((row) => row.flags)).not.toContain(
      "new-since-previous",
    );
    expect(result).toMatchObject({
      version: 1,
      window,
      configurationFingerprint: configuration.fingerprint,
    });
  });

  it("configuration change during the search throws MulticastConfigurationChangedError", async () => {
    const configuration = await setup();
    stub.documents = [document([igmp, flow, nxos, other]), document([igmp])];
    await expect(
      investigateScope(client, window, configuration, signal()),
    ).rejects.toBeInstanceOf(MulticastConfigurationChangedError);
    expect(stub.runs).toHaveLength(2);
    stub.runs = [];
    stub.documents = [document([igmp])];
    await expect(
      investigateScope(client, window, configuration, signal()),
    ).rejects.toBeInstanceOf(MulticastConfigurationChangedError);
    expect(stub.runs).toHaveLength(0);
  });

  it("previous window outside validity is unavailable", async () => {
    const configuration = await setup([{ ...igmp, validFrom: 800 }, flow]);
    const result = await investigateScope(
      client,
      window,
      configuration,
      signal(),
      { comparePrevious: true },
    );
    expect(result.comparison).toEqual({
      state: "unavailable",
      reason: "Source verification does not cover the previous window.",
    });
    expect(stub.runs).toHaveLength(2);
    expect(stub.runs.every((run) => run.earliest === "1000")).toBe(true);
    expect(result.rows.flatMap((row) => row.flags)).not.toContain(
      "new-since-previous",
    );
  });

  it("previous window incomplete is unavailable", async () => {
    const configuration = await setup([igmp, flow]);
    stub.respond = (source, request) =>
      Number(request.earliest) < window.earliest && source !== "multicast_igmp"
        ? [flowRow("239.1.1.1", Number(request.earliest) + 10, true)]
        : respond(source, request);
    const result = await investigateScope(
      client,
      window,
      configuration,
      signal(),
      { comparePrevious: true },
    );
    expect(result.comparison).toEqual({
      state: "unavailable",
      reason: "The previous-window search did not complete.",
    });
    expect(result.rows).toHaveLength(2);
    expect(result.rows.flatMap((row) => row.flags)).not.toContain(
      "new-since-previous",
    );
  });

  it("compare runs as a second admitted search", async () => {
    const configuration = await setup([igmp, flow]);
    const result = await investigateScope(
      client,
      window,
      configuration,
      signal(),
      { comparePrevious: true },
    );
    for (const source of ["multicast_igmp", "multicast_netflow"]) {
      const runs = stub.runs.filter((run) => run.source === source);
      expect(runs.map((run) => run.earliest).sort()).toEqual(["1000", "700"]);
      expect(new Set(runs.map((run) => run.key)).size).toBe(2);
    }
    expect(result.comparison).toEqual({ state: "complete" });
    const flags = Object.fromEntries(
      result.rows.map((row) => [row.group, row.flags]),
    );
    expect(flags["239.1.1.2"]).toContain("new-since-previous");
    expect(flags["239.1.1.1"]).not.toContain("new-since-previous");
  });
});
