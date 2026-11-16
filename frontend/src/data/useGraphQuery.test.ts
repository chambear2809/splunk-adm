import { describe, expect, it } from "vitest";
import {
  expectedWindow,
  explainGraphError,
  MAP_TOPOLOGY_SEARCHES,
  pinRequest,
  queryGraph,
} from "./useGraphQuery";
import type { SearchClient } from "./searchClient";
import rows from "../../../fixtures/demo-rows-aci.json";

/** Either half of the map inventory read. */
const isInventory = (search: string) =>
  (MAP_TOPOLOGY_SEARCHES as readonly string[]).includes(search);

describe("graph query coordination", () => {
  it("reports required graph failure immediately and cancels inventory", async () => {
    const controller = new AbortController();
    const client: SearchClient = {
      search: (request) =>
        request.search.includes("adm_application_graph_read")
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
        if (isInventory(request.search))
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
      isInventory(request.search)
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
        rows: isInventory(request.search) ? [] : rows.rows,
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
  // The graph and both inventory halves; the pinned window matched the graph's.
  expect(requests).toHaveLength(3);
  expect(
    requests.every(
      (request) =>
        request.latest === "1791374400" &&
        request.timezone === "Pacific/Honolulu",
    ),
  ).toBe(true);
});

it("pins relative bounds and re-reads inventory for a different returned window", async () => {
  const requests: Array<{
    search: string;
    earliest: string;
    latest?: string;
    timezone?: string;
  }> = [];
  const client: SearchClient = {
    search: async (request) => {
      requests.push(request);
      return {
        rows: request.search.includes("adm_application_graph_read")
          ? rows.rows
          : [],
        warnings: [],
        errors: [],
      };
    },
  };
  const result = await queryGraph(
    client,
    {
      ...rows.args,
      earliest: "-1h",
      latest: "now",
      timezone: "America/New_York",
    },
    new AbortController(),
  );
  const graph = requests.find((r) =>
    r.search.includes("adm_application_graph_read"),
  )!;
  expect(graph.earliest).toMatch(/^\d+$/);
  // Long windows start on the five-minute slice boundary at or before -1h.
  const span = Number(graph.latest) - Number(graph.earliest);
  expect(Number(graph.earliest) % 300).toBe(0);
  expect(span).toBeGreaterThanOrEqual(3600);
  expect(span).toBeLessThan(3900);
  // The captured fixture window differs from the pinned one, so the
  // inventory halves are read again for the graph's exact window.
  const inventory = requests.filter((r) => isInventory(r.search));
  expect(inventory).toHaveLength(4);
  expect(inventory.slice(2)).toEqual(
    MAP_TOPOLOGY_SEARCHES.map((search) =>
      expect.objectContaining({
        search,
        earliest: String(Date.parse(result.graph.window.start) / 1000),
        latest: String(Date.parse(result.graph.window.end) / 1000),
        timezone: "America/New_York",
      }),
    ),
  );
});
it("cancels parallel inventory when an aborted graph returns", async () => {
  const controller = new AbortController();
  const signals: AbortSignal[] = [];
  const client: SearchClient = {
    search: (request) => {
      signals.push(request.signal);
      if (isInventory(request.search)) return new Promise(() => {});
      controller.abort();
      return Promise.resolve({ rows: rows.rows, warnings: [], errors: [] });
    },
  };
  await expect(
    queryGraph(client, { ...rows.args, earliest: "-1h" }, controller),
  ).rejects.toThrow("cancelled");
  expect(signals).toHaveLength(3);
  expect(signals.every((signal) => signal.aborted)).toBe(true);
});
it("cannot publish a valid graph after inventory completes following cancellation", async () => {
  const controller = new AbortController();
  const client: SearchClient = {
    search: async (request) => {
      const graph = request.search.includes("adm_application_graph_read");
      if (!graph) controller.abort();
      return { rows: graph ? rows.rows : [], warnings: [], errors: [] };
    },
  };
  await expect(
    queryGraph(client, { ...rows.args, earliest: "-1h" }, controller),
  ).rejects.toThrow("cancelled");
});

describe("qualified identity window errors", () => {
  it("explains the five-minute limit instead of a generic failure", () => {
    const raw = new Error(
      "Splunk could not complete the search. Splunk reported: Error in 'admqualified' command: SearchError at \"search.py\", line 40 : identity window exceeds 300 seconds",
    );
    expect((explainGraphError(raw) as Error).message).toMatch(/up to 7 days/);
    const other = new Error("boom");
    expect(explainGraphError(other)).toBe(other);
  });
});

describe("progressive summary reads", () => {
  it("reads the deferred five-argument graph, then exact-window inventory", async () => {
    const searches: { search: string; earliest: string }[] = [];
    const client: SearchClient = {
      search: async (request) => {
        searches.push(request);
        return isInventory(request.search)
          ? { rows: [], warnings: [], errors: [] }
          : { rows: rows.rows, warnings: [], errors: [] };
      },
    };
    await queryGraph(
      client,
      { ...rows.args, earliest: "-4h", latest: "now" },
      new AbortController(),
      "deferred",
    );
    const graph = searches.find((s) =>
      s.search.includes("adm_application_graph_read"),
    )!;
    expect(graph.search).toContain('"shop","deferred")`');
    const inventory = searches.filter((s) => isInventory(s.search));
    expect(inventory.length).toBeGreaterThanOrEqual(2);
    expect(inventory.every((s) => /^\d+$/.test(s.earliest))).toBe(true);
  });
});

describe("map inventory split and window pinning", () => {
  it("pins relative bounds once and predicts the summary slice start", () => {
    const pinned = pinRequest(
      { ...rows.args, earliest: "-4h", latest: "now" },
      1793826101.7,
    );
    // The request itself starts on the counted slice boundary, so the
    // window shown is the window counted (no hidden earlier seconds).
    expect(pinned).toMatchObject({
      earliest: "1793811600",
      latest: "1793826101",
    });
    expect(expectedWindow(pinned)).toEqual({
      start: pinned.earliest,
      end: "1793826101",
    });
    // Five minutes or less is pinned exactly.
    expect(
      pinRequest(
        { ...rows.args, earliest: "-5m", latest: "now" },
        1793826101.7,
      ),
    ).toMatchObject({ earliest: "1793825801", latest: "1793826101" });
    // Five minutes or less is one raw window, not slice-aligned.
    expect(
      expectedWindow({
        ...rows.args,
        earliest: "1793825901",
        latest: "1793826101",
      }),
    ).toEqual({ start: "1793825901", end: "1793826101" });
    // Unresolvable bounds are sent unchanged and inventory waits for the graph.
    const raw = { ...rows.args, earliest: "rt-5m", latest: "now" };
    expect(pinRequest(raw)).toBe(raw);
  });
  it("concatenates topology then VMM rows, in the macro's append order", async () => {
    const seen: string[] = [];
    const base = rows.rows.slice(0, 0);
    const client: SearchClient = {
      search: async (request) => {
        seen.push(request.search);
        if (request.search === MAP_TOPOLOGY_SEARCHES[1])
          return { rows: [], warnings: ["vmm slow"], errors: [] };
        if (request.search === MAP_TOPOLOGY_SEARCHES[0])
          return { rows: base, warnings: ["base slow"], errors: [] };
        return { rows: rows.rows, warnings: [], errors: [] };
      },
    };
    const { topology } = await queryGraph(
      client,
      { ...rows.args, earliest: "1791373500", latest: "1791374400" },
      new AbortController(),
    );
    expect(topology.warnings).toEqual(
      expect.arrayContaining(["base slow", "vmm slow"]),
    );
    expect(seen.filter(isInventory)).toEqual([...MAP_TOPOLOGY_SEARCHES]);
  });
  it("reuses a shared exact-window inventory instead of reading it again", async () => {
    const seen: string[] = [];
    const client: SearchClient = {
      search: async (request) => {
        seen.push(request.search);
        return { rows: rows.rows, warnings: [], errors: [] };
      },
    };
    const first = await queryGraph(
      client,
      { ...rows.args, earliest: "1791373500", latest: "1791374400" },
      new AbortController(),
    );
    const start = String(Date.parse(first.graph.window.start) / 1000),
      end = String(Date.parse(first.graph.window.end) / 1000);
    seen.length = 0;
    const shared = Promise.resolve(first.topology);
    const again = await queryGraph(
      client,
      { ...rows.args, earliest: start, latest: end },
      new AbortController(),
      undefined,
      { inventory: { start, end, topology: shared } },
    );
    expect(seen.filter(isInventory)).toEqual([]);
    expect(again.topology).toBe(first.topology);
  });
  it("hands the graph and its inventory to the full read before inventory returns", async () => {
    let release: () => void = () => {};
    const held = new Promise<void>((done) => (release = done));
    const client: SearchClient = {
      search: async (request) => {
        if (isInventory(request.search)) {
          await held;
          return { rows: [], warnings: [], errors: [] };
        }
        return { rows: rows.rows, warnings: [], errors: [] };
      },
    };
    let handed: { start: string; end: string } | undefined;
    const done = queryGraph(
      client,
      { ...rows.args, earliest: "1791373500", latest: "1791374400" },
      new AbortController(),
      "deferred",
      { onGraph: (_graph, inventory) => (handed = inventory) },
    );
    await expect
      .poll(() => handed)
      .toMatchObject({
        start: "1791373500",
        end: "1791374400",
      });
    release();
    await done;
  });
});
