import { describe, expect, it } from "vitest";
import { queryGraph } from "./useGraphQuery";
import type { SearchClient } from "./searchClient";
import rows from "../../../fixtures/demo-rows-aci.json";

describe("graph query coordination", () => {
  it("reports required graph failure immediately and cancels hanging topology", async () => {
    const controller = new AbortController();
    const client: SearchClient = {
      search: (request) =>
        request.search.includes("adm_graph")
          ? Promise.reject(new Error("permission denied"))
          : new Promise(() => {}),
    };
    await expect(
      queryGraph(client, { ...rows.args, earliest: "-1h" }, controller),
    ).rejects.toThrow("permission denied");
    expect(controller.signal.aborted).toBe(true);
  });
  it("retains a valid graph when optional inventory fails", async () => {
    const client: SearchClient = {
      search: async (request) => {
        if (request.search.includes("adm_topology"))
          throw new Error("inventory unavailable");
        return { rows: rows.rows, warnings: [], errors: [] };
      },
    };
    const result = await queryGraph(
      client,
      { ...rows.args, earliest: "-1h", latest: "now" },
      new AbortController(),
    );
    expect(result.graph.nodes.length).toBeGreaterThan(0);
    expect(result.topology.warnings).toContain(
      "Network inventory unavailable. inventory unavailable",
    );
  });
});

it("carries WARN job messages from both searches into the warnings MapPage renders", async () => {
  const client: SearchClient = {
    search: async (request) =>
      request.search.includes("adm_topology")
        ? { rows: [], warnings: ["inventory peer slow"], errors: [] }
        : {
            rows: rows.rows,
            warnings: ["peer indexer-3 unreachable"],
            errors: [],
          },
  };
  const { graph, topology } = await queryGraph(
    client,
    { ...rows.args, earliest: "-1h" },
    new AbortController(),
  );
  expect(graph.coverage.warnings).toContain("peer indexer-3 unreachable");
  expect(topology.warnings).toContain("inventory peer slow");
});
it("rejects a graph search that reports ERROR job messages", async () => {
  const client: SearchClient = {
    search: async () => ({
      rows: rows.rows,
      warnings: ["peer down"],
      errors: ["peer down"],
    }),
  };
  await expect(
    queryGraph(
      client,
      { ...rows.args, earliest: "-1h" },
      new AbortController(),
    ),
  ).rejects.toThrow(/incomplete.*peer down/);
});
it("sends the signed-in timezone and latest bound to both searches", async () => {
  const requests: Array<{ latest?: string; timezone?: string }> = [];
  const client: SearchClient = {
    search: async (request) => {
      requests.push(request);
      return {
        rows: request.search.includes("adm_topology") ? [] : rows.rows,
        warnings: [],
        errors: [],
      };
    },
  };
  await queryGraph(
    client,
    {
      ...rows.args,
      earliest: "1791373500",
      latest: "1791374400",
      timezone: "Pacific/Honolulu",
    },
    new AbortController(),
  );
  expect(requests).toHaveLength(2);
  expect(
    requests.every(
      (request) =>
        request.latest === "1791374400" &&
        request.timezone === "Pacific/Honolulu",
    ),
  ).toBe(true);
});
