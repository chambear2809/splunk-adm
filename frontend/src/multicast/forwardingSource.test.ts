import { describe, expect, it, vi } from "vitest";
import {
  SearchAccessDeniedError,
  type SearchClient,
} from "../data/searchClient";
import type { ForwardingProfile, MulticastRequest } from "./contract";
import {
  buildForwardingSearch,
  loadMulticastForwarding,
} from "./forwardingSource";

const request: MulticastRequest = {
  version: 1,
  scope: "prod",
  group: "239.1.2.3",
  sender: "192.0.2.20",
  earliest: 100,
  latest: 200,
};
const profile: ForwardingProfile = {
  source: "multicast_nxos",
  id: "nxos-1",
  index: "multicast",
  observer: "collector-1",
  scope: "prod",
  validFrom: 1,
  validUntil: 1000,
};
const cohort = {
  schemaVersion: 1,
  scope: "prod",
  group: "239.1.2.3",
  sender: "192.0.2.20",
  observedAt: 200,
  validUntil: 240,
  devices: [
    { observer: "leaf-1", input: "Ethernet1/1", outputs: ["Ethernet1/2"] },
    { observer: "leaf-2", input: "Ethernet1/3", outputs: ["Ethernet1/4"] },
  ],
  adjacencies: [
    {
      from: { observer: "leaf-1", interface: "Ethernet1/2" },
      to: { observer: "leaf-2", interface: "Ethernet1/3" },
    },
  ],
};
const row = (value: unknown, time = 200) => ({
  kind: "record",
  index: "multicast",
  host: "collector-1",
  _time: time,
  oversized: 0,
  payload: JSON.stringify(value),
});
const client = (rows: ReturnType<typeof row>[], extra = {}) => ({
  search: vi.fn<SearchClient["search"]>(async () => ({
    rows: [
      ...rows,
      {
        kind: "completion",
        input_count: rows.length,
        returned_count: rows.length,
        ...extra,
      },
    ],
    warnings: [],
    errors: [],
  })),
});
const run = (rows: ReturnType<typeof row>[], input = profile) =>
  loadMulticastForwarding(
    client(rows),
    input,
    request,
    new AbortController().signal,
  );

describe("indexed forwarding cohort", () => {
  it("loads one entire current cohort and its explicitly linked interfaces", async () => {
    const search = client([row(cohort)]);
    const result = await loadMulticastForwarding(
      search,
      profile,
      request,
      new AbortController().signal,
    );
    expect(result.outcome.state).toBe("complete");
    expect(result.evidence).toHaveLength(2);
    expect(result.adjacency).toEqual([
      {
        scope: "prod",
        ...cohort.adjacencies[0],
        validFrom: 200,
        validUntil: 240,
      },
    ]);
    expect(search.search.mock.calls[0][0]).toMatchObject({
      earliest: "100",
      latest: "201",
      maxRows: 257,
    });
  });
  it("selects only the newest complete cohort and rejects conflicting timestamps", async () => {
    const old = {
      ...cohort,
      observedAt: 180,
      validUntil: 220,
      devices: [cohort.devices[0]],
      adjacencies: [],
    };
    expect((await run([row(old, 180), row(cohort)])).evidence).toHaveLength(2);
    const conflict = { ...cohort, validUntil: 230 };
    expect((await run([row(cohort), row(conflict)])).outcome.state).toBe(
      "unavailable",
    );
  });
  it("rejects malformed interfaces, untrusted provenance, stale data, and inconsistent time", async () => {
    const invalid = {
      ...cohort,
      adjacencies: [
        {
          ...cohort.adjacencies[0],
          to: { observer: "leaf-2", interface: "Ethernet1/9" },
        },
      ],
    };
    expect((await run([row(invalid)])).outcome.state).toBe("unavailable");
    expect((await run([{ ...row(cohort), host: "other" }])).outcome.state).toBe(
      "unavailable",
    );
    expect((await run([row(cohort, 199)])).outcome.state).toBe("unavailable");
    expect(
      (await run([row({ ...cohort, validUntil: 200 })])).outcome.state,
    ).toBe("complete");
    expect(
      (await run([row({ ...cohort, observedAt: 180, validUntil: 199 }, 180)]))
        .outcome.state,
    ).toBe("partial");
  });
  it("rejects capped and incomplete envelopes and requires an exact sender", async () => {
    const capped = client([row(cohort)], { input_count: 257 });
    expect(
      (
        await loadMulticastForwarding(
          capped,
          profile,
          request,
          new AbortController().signal,
        )
      ).outcome.state,
    ).toBe("unavailable");
    const missing = await loadMulticastForwarding(
      client([]),
      profile,
      { ...request, sender: undefined },
      new AbortController().signal,
    );
    expect(missing.outcome.state).toBe("blocked");
    expect(() =>
      buildForwardingSearch({ ...profile, observer: 'x" OR *' }, request),
    ).toThrow();
  });
  it("scopes oversized results to the selected tuple before sorting and capping", () => {
    const spl = buildForwardingSearch(profile, request);
    const where = spl.split("\n").find((line) => line.startsWith("| where"));
    expect(where).toContain('json_extract(_raw,"scope")="prod"');
    expect(where).toContain('json_extract(_raw,"group")="239.1.2.3"');
    expect(where).toContain('json_extract(_raw,"sender")="192.0.2.20"');
    expect(where).not.toMatch(/oversized|\bOR\b/);
  });
  it("separates access denial from cancellation", async () => {
    const denied: SearchClient = {
      search: async () => {
        throw new SearchAccessDeniedError();
      },
    };
    expect(
      (
        await loadMulticastForwarding(
          denied,
          profile,
          request,
          new AbortController().signal,
        )
      ).outcome.state,
    ).toBe("blocked");
    const controller = new AbortController();
    controller.abort();
    await expect(
      loadMulticastForwarding(denied, profile, request, controller.signal),
    ).rejects.toThrow(/cancelled/);
  });
});
