import { describe, expect, it } from "vitest";
import demo from "../../fixtures/demo-rows.json";
import {
  buildGraphSearch,
  demoGraph,
  loadLive,
  resultRows,
  splunkMessage,
  type LiveRequest,
  type SearchConstructor,
} from "./provider";
import { MAX_ROWS } from "./rows";

const ok: LiveRequest = { ...demo.args, earliest: "-1h" };

describe("buildGraphSearch", () => {
  it("calls the graph macro with quoted arguments and no leading pipe", () => {
    expect(buildGraphSearch(ok)).toBe(
      '`adm_graph("frontend","demo","demo-cluster","shop")`',
    );
  });

  it("accepts realistic identifiers", () => {
    expect(
      buildGraphSearch({
        ...ok,
        service: "payments/api:v2@eu",
        environment: "prod.eu-1",
        cluster: "prod_cluster-01.example",
        namespace: "team-a1",
      }),
    ).toBe(
      '`adm_graph("payments/api:v2@eu","prod.eu-1","prod_cluster-01.example","team-a1")`',
    );
  });

  const injections = [
    'shop") | delete',
    'shop","x',
    "shop | delete",
    "shop\\",
    "shop`adm_index_netflow`",
    "shop$service$",
    "shop(x)",
    "shop,x",
    "shop demo",
    "shop\tx",
    "shop\nx",
    "shop'x",
    "-leading",
    "",
  ];
  it.each(
    (["service", "environment", "cluster", "namespace"] as const).flatMap(
      (key) => injections.map((value) => [key, value] as const),
    ),
  )("rejects %s %j", (key, value) => {
    expect(() => buildGraphSearch({ ...ok, [key]: value })).toThrow();
  });

  it("enforces Kubernetes namespace rules", () => {
    expect(() => buildGraphSearch({ ...ok, namespace: "Shop" })).toThrow();
    expect(() =>
      buildGraphSearch({ ...ok, namespace: "a".repeat(64) }),
    ).toThrow();
    expect(() =>
      buildGraphSearch({ ...ok, namespace: "a".repeat(63) }),
    ).not.toThrow();
    expect(() => buildGraphSearch({ ...ok, namespace: "shop-" })).toThrow();
  });

  it("rejects unsupported time ranges", () => {
    expect(() => buildGraphSearch({ ...ok, earliest: "0" })).toThrow(
      /time range/,
    );
  });
});

describe("splunkMessage", () => {
  it("reads strings, message fields and content.messages", () => {
    expect(splunkMessage("  Permission  denied ")).toBe("Permission denied");
    expect(splunkMessage({ message: "quota" })).toBe("quota");
    expect(
      splunkMessage({
        content: { messages: [{ text: "a" }, { text: "" }, { text: "b" }] },
      }),
    ).toBe("a b");
    expect(splunkMessage({})).toBeUndefined();
    expect(splunkMessage(undefined)).toBeUndefined();
  });
  it("bounds length", () => {
    const m = splunkMessage("x".repeat(1000))!;
    expect(m.length).toBeLessThanOrEqual(300);
    expect(m.endsWith("…")).toBe(true);
  });
});

/** Converts row objects into SplunkJS json_rows. */
function jsonRows(rows: Record<string, unknown>[]) {
  const fields = [...new Set(rows.flatMap((r) => Object.keys(r)))];
  return { fields, rows: rows.map((r) => fields.map((f) => r[f] ?? null)) };
}

describe("resultRows", () => {
  it("round-trips json_rows, including multivalues and missing values", () => {
    const back = resultRows(jsonRows(demo.rows));
    expect(back).toEqual(demo.rows);
  });
  it("accepts field descriptors", () => {
    expect(
      resultRows({ fields: [{ name: "a" }], rows: [[["x", "y"]]] }),
    ).toEqual([{ a: ["x", "y"] }]);
  });
  it("rejects results without field names", () => {
    expect(() => resultRows({ fields: [{}], rows: [] })).toThrow();
  });
});

describe("demoGraph", () => {
  it("assembles the captured lab rows as a synthetic graph", () => {
    const g = demoGraph();
    expect(g.demo).toBe(true);
    expect(g.nodes.length).toBeGreaterThan(0);
  });
});

type Handler = (payload?: unknown) => void;
function fakeManager(
  script: (fire: (event: string, p?: unknown) => void) => void,
  seen: { options?: Record<string, unknown>; count?: number } = {},
) {
  const handlers = new Map<string, Handler[]>();
  let dataHandler: (() => void) | undefined;
  let data: ReturnType<typeof jsonRows> | undefined;
  const Manager = class {
    constructor(options: Record<string, unknown>) {
      seen.options = options;
    }
    data(_kind: string, options: { count: number }) {
      seen.count = options.count;
      return {
        on: (_: string, cb: () => void) => (dataHandler = cb),
        off: () => {},
        hasData: () => !!data,
        data: () => data!,
      };
    }
    on(event: string, cb: Handler) {
      handlers.set(event, [...(handlers.get(event) ?? []), cb]);
    }
    off() {}
    cancel() {}
    startSearch() {
      script((event, p) => {
        if (event === "data") {
          data = jsonRows(p as Record<string, unknown>[]);
          dataHandler?.();
        } else for (const h of handlers.get(event) ?? []) h(p);
      });
    }
  };
  return Manager as unknown as SearchConstructor;
}
const run = (m: SearchConstructor, request = ok) =>
  loadLive(m, request, new AbortController().signal);

describe("loadLive", () => {
  it("dispatches the macro over the chosen range and assembles rows", async () => {
    const seen: { options?: Record<string, unknown>; count?: number } = {};
    const g = await run(fakeManager((fire) => fire("data", demo.rows), seen));
    expect(g.demo).toBe(false);
    expect(g.boundary.service).toBe("frontend");
    expect(seen.options).toMatchObject({
      app: "splunk_adm",
      earliest_time: "-1h",
      latest_time: "now",
      search: '`adm_graph("frontend","demo","demo-cluster","shop")`',
    });
    expect(seen.count).toBe(MAX_ROWS + 1);
  });
  it("rejects results larger than the limit", async () => {
    const meta = demo.rows.find((r) => r.row_type === "meta")!;
    await expect(
      run(
        fakeManager((fire) => fire("data", new Array(MAX_ROWS + 1).fill(meta))),
      ),
    ).rejects.toThrow(/pilot limit/);
  });
  it("rejects early when the job reports too many results", async () => {
    await expect(
      run(
        fakeManager((fire) =>
          fire("search:done", { content: { resultCount: MAX_ROWS + 1 } }),
        ),
      ),
    ).rejects.toThrow(/pilot limit/);
  });
  it("rejects malformed rows", async () => {
    await expect(
      run(fakeManager((fire) => fire("data", [{ row_type: "trace" }]))),
    ).rejects.toThrow(/Invalid graph search result/);
  });
  it("reports cancellation with Splunk's message", async () => {
    await expect(
      run(
        fakeManager((fire) =>
          fire("search:cancelled", {
            content: { messages: [{ text: "Job was cancelled by admin" }] },
          }),
        ),
      ),
    ).rejects.toThrow(/cancelled.*Job was cancelled by admin/);
  });
  it.each(["search:fail", "search:failed"])(
    "reports %s with detail",
    async (event) => {
      await expect(
        run(fakeManager((fire) => fire(event, { message: "quota exceeded" }))),
      ).rejects.toThrow(/could not complete.*quota exceeded/);
    },
  );
  it("reports search:error string payloads", async () => {
    await expect(
      run(
        fakeManager((fire) =>
          fire("search:error", "Error in 'SearchParser': macro not found"),
        ),
      ),
    ).rejects.toThrow(/macro not found/);
  });
  it("reports zero results", async () => {
    await expect(
      run(
        fakeManager((fire) =>
          fire("search:done", { content: { resultCount: 0 } }),
        ),
      ),
    ).rejects.toThrow(/no rows/);
  });
  it("rejects invalid requests without starting a search", async () => {
    let constructed = false;
    const M = class {
      constructor() {
        constructed = true;
      }
    } as unknown as SearchConstructor;
    await expect(
      loadLive(
        M,
        { ...ok, namespace: 'x")|delete' },
        new AbortController().signal,
      ),
    ).rejects.toThrow();
    expect(constructed).toBe(false);
  });
});
