import { describe, expect, it } from "vitest";
import type { SearchClient, SearchRequest } from "../data/searchClient";
import type { Assertion, ChangeWindows } from "./model";
import { livenessSearch, runVerification, traceSearch } from "./searches";

const assertion: Assertion = {
  id: "a1",
  name: "Web reaches DB",
  kind: "reaches",
  scope: "prod",
  src: "10.1.1.10",
  dst: "10.2.2.20",
  transport: "tcp",
  port: 5432,
};
const windows: ChangeWindows = {
  before: { start: 1000, end: 4600 },
  after: { start: 8200, end: 11_800 },
  basis: "manual",
};
const obs = {
  row_type: "observation",
  flow_source: "aci_acllog",
  observer_device: "pod-1/node-101",
  direction: "forward",
  records: "3",
  drops: "0",
  services: "tcp/5432",
};

function fakeClient(
  respond: (r: SearchRequest) => Record<string, unknown>[] | Error,
) {
  const calls: SearchRequest[] = [];
  const client: SearchClient = {
    search: async (request) => {
      calls.push(request);
      const rows = respond(request);
      if (rows instanceof Error) throw rows;
      return { rows, warnings: [], errors: [] };
    },
  };
  return { client, calls };
}

describe("search builders", () => {
  it("only emits validated literals", () => {
    expect(traceSearch("10.1.1.10", "10.2.2.20", "prod")).toBe(
      '| `adm_path_trace(10.1.1.10,10.2.2.20,prod)` | where row_type="observation"',
    );
    expect(() => traceSearch("10.1.1.10", "x) | delete", "prod")).toThrow();
    expect(() => traceSearch("10.1.1.10", "10.2.2.20", "unmapped:a")).toThrow();
    expect(livenessSearch("pod-1/node-101")).toBe(
      "| `adm_device_flows(pod-1/node-101)` | head 1",
    );
    expect(() => livenessSearch("a b")).toThrow();
  });
});

describe("runVerification", () => {
  it("runs bounded absolute-window searches as the caller", async () => {
    const { client, calls } = fakeClient(() => [obs]);
    const run = await runVerification(
      client,
      [assertion],
      windows,
      new AbortController().signal,
      20_000,
    );
    expect(run.results[0].verdict.status).toBe("pass");
    expect(
      calls.map((c) => [c.earliest, c.latest, c.maxRows, c.overflow]),
    ).toEqual([
      ["1000", "4600", 240, "error"],
      ["8200", "11800", 240, "error"],
    ]);
  });
  it("turns a failed or unsettled search into unknown, never pass", async () => {
    const failing = fakeClient((r) =>
      r.earliest === "8200" ? new Error("denied") : [obs],
    );
    const run = await runVerification(
      failing.client,
      [assertion],
      windows,
      new AbortController().signal,
      20_000,
    );
    expect(run.results[0].verdict.status).toBe("unknown");
    const unsettled = fakeClient(() => [obs]);
    const early = await runVerification(
      unsettled.client,
      [assertion],
      windows,
      new AbortController().signal,
      12_000,
    );
    expect(early.results[0].verdict.status).toBe("unknown");
  });
  it("probes baseline observers when the pair goes quiet", async () => {
    const { client, calls } = fakeClient((r) =>
      r.search.includes("adm_device_flows")
        ? [{ total_flows: "9" }]
        : r.earliest === "1000"
          ? [obs]
          : [],
    );
    const run = await runVerification(
      client,
      [assertion],
      windows,
      new AbortController().signal,
      20_000,
    );
    expect(run.results[0].verdict).toMatchObject({
      status: "fail",
      basis: "inferred",
    });
    expect(calls[2]).toMatchObject({
      earliest: "8200",
      latest: "11800",
      maxRows: 1,
    });
  });
  it("rejects overlapping windows and oversize runs before searching", async () => {
    const { client, calls } = fakeClient(() => []);
    const signal = new AbortController().signal;
    await expect(
      runVerification(
        client,
        [assertion],
        { ...windows, after: windows.before },
        signal,
      ),
    ).rejects.toThrow();
    await expect(
      runVerification(client, Array(11).fill(assertion), windows, signal),
    ).rejects.toThrow(/at most 10/);
    expect(calls).toEqual([]);
  });
});
