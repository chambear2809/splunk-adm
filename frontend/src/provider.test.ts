import { describe, expect, it } from "vitest";
import demo from "../../fixtures/demo-rows.json";
import {
  buildGraphSearch,
  demoGraph,
  loadLive,
  resultRows,
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
): SearchClient & { seen?: SearchRequest } => ({
  search: async function (request) {
    this.seen = request;
    return { rows, warnings };
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
  it("propagates warnings", async () => {
    const graph = await loadLive(
      fake(demo.rows, ["truncated"]),
      ok,
      new AbortController().signal,
    );
    expect(graph.coverage.warnings).toContain("truncated");
  });
  it("rejects invalid requests without searching", async () => {
    let called = false;
    const client: SearchClient = {
      search: async () => {
        called = true;
        return { rows: [], warnings: [] };
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
});
