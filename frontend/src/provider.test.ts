import { describe, expect, it } from "vitest";
import demo from "../../fixtures/demo-rows.json";
import {
  buildGraphSearch,
  demoGraph,
  loadLive,
  loadTopology,
  resultRows,
  splunkErrors,
  splunkMessage,
  splunkWarnings,
  type LiveRequest,
} from "./provider";
import type { SearchClient, SearchRequest } from "./data/searchClient";
import { MAX_ROWS } from "./rows";

const ok: LiveRequest = { ...demo.args, earliest: "-1h" };
const fake = (
  rows: Record<string, unknown>[],
  warnings: string[] = [],
  errors: string[] = [],
): SearchClient & { seen?: SearchRequest } => ({
  search: async function (request) {
    this.seen = request;
    return { rows, warnings, errors };
  },
});

describe("buildGraphSearch", () => {
  it("calls the graph macro with quoted arguments", () =>
    expect(buildGraphSearch(ok)).toBe(
      '`adm_graph("frontend","demo","demo-cluster","shop")`',
    ));
  it("rejects unsafe arguments", () =>
    expect(() =>
      buildGraphSearch({ ...ok, namespace: 'x")|delete' }),
    ).toThrow());
});
describe("messages", () => {
  it("normalizes and bounds messages", () => {
    expect(splunkMessage("  Permission  denied ")).toBe("Permission denied");
    expect(splunkMessage("x".repeat(1000))?.length).toBeLessThanOrEqual(300);
  });
  it("filters informational warnings", () =>
    expect(
      splunkWarnings({
        content: {
          messages: [
            { type: "INFO", text: "done" },
            { type: "WARN", text: "truncated" },
          ],
        },
      }),
    ).toEqual(["truncated"]));
  it("includes top-level message arrays even when content messages exist", () => {
    expect(
      splunkWarnings({
        content: { messages: [{ type: "INFO", text: "done" }] },
        messages: [{ type: "WARN", text: "index denied" }],
      }),
    ).toEqual(["index denied"]);
  });
  it("ignores DEBUG and keeps errors among warnings", () => {
    const payload = {
      content: {
        messages: [
          { type: "DEBUG", text: "configuration initialization took 12ms" },
          { type: "WARN", text: "slow peer" },
          { type: "ERROR", text: "peer unreachable" },
          { type: "FATAL", text: "search process ended" },
        ],
      },
    };
    expect(splunkWarnings(payload)).toEqual([
      "slow peer",
      "peer unreachable",
      "search process ended",
    ]);
    expect(splunkErrors(payload)).toEqual([
      "peer unreachable",
      "search process ended",
    ]);
  });
  it("does not classify untyped or WARN messages as errors", () => {
    expect(splunkErrors("plain text")).toEqual([]);
    expect(
      splunkErrors({ messages: [{ type: "WARN", text: "x" }, { text: "y" }] }),
    ).toEqual([]);
  });
  it("keeps ERROR and FATAL messages that carry no text", () => {
    expect(
      splunkErrors({
        messages: [{ type: "FATAL" }, { type: "ERROR", text: "  " }],
      }),
    ).toEqual(["Splunk reported an error without a message."]);
  });
});
describe("resultRows", () => {
  it("round-trips json rows", () =>
    expect(resultRows({ fields: ["a", "b"], rows: [["x", null]] })).toEqual([
      { a: "x" },
    ]));
  it("accepts field descriptors", () =>
    expect(resultRows({ fields: [{ name: "a" }], rows: [["x"]] })).toEqual([
      { a: "x" },
    ]));
});
describe("demoGraph", () =>
  it("assembles captured rows", () =>
    expect(demoGraph("nxos").nodes.length).toBeGreaterThan(0)));
describe("loadLive", () => {
  it("dispatches a bounded request and assembles rows", async () => {
    const client = fake(demo.rows);
    const graph = await loadLive(client, ok, new AbortController().signal);
    expect(graph.boundary.service).toBe("frontend");
    expect(client.seen).toMatchObject({
      earliest: "-1h",
      latest: "now",
      maxRows: MAX_ROWS,
    });
  });
  it("surfaces non-error job messages as coverage warnings", async () => {
    const graph = await loadLive(
      fake(demo.rows, ["slow peer"]),
      ok,
      new AbortController().signal,
    );
    expect(graph.coverage.warnings).toContain("slow peer");
  });
  it("fails closed on error-bearing graph results", async () => {
    await expect(
      loadLive(
        fake(demo.rows, ["peer unreachable"], ["peer unreachable"]),
        ok,
        new AbortController().signal,
      ),
    ).rejects.toThrow(/incomplete.*peer unreachable/);
  });
  it("rejects invalid requests without searching", async () => {
    let called = false;
    const client: SearchClient = {
      search: async () => {
        called = true;
        return { rows: [], warnings: [], errors: [] };
      },
    };
    await expect(
      loadLive(
        client,
        { ...ok, namespace: 'x")|delete' },
        new AbortController().signal,
      ),
    ).rejects.toThrow();
    expect(called).toBe(false);
  });
  it("passes abort signal through", async () => {
    const client = fake(demo.rows);
    const controller = new AbortController();
    await loadLive(client, ok, controller.signal);
    expect(client.seen?.signal).toBe(controller.signal);
  });
  it("surfaces non-error topology messages as topology warnings", async () => {
    const topology = await loadTopology(
      fake([], ["slow peer"]),
      "-1h",
      new AbortController().signal,
    );
    expect(topology.warnings).toContain("slow peer");
  });
  it("fails closed on error-bearing topology searches", async () => {
    await expect(
      loadTopology(
        fake([], ["permission denied"], ["permission denied"]),
        "-1h",
        new AbortController().signal,
      ),
    ).rejects.toThrow(/incomplete.*permission denied/);
  });
});
