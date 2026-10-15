import { describe, expect, it, vi, type MockedFunction } from "vitest";

const { createRESTURLMock } = vi.hoisted(() => ({
  createRESTURLMock: vi.fn(
    (path: string, options?: Record<string, string>) =>
      `/rest/${path}${options ? `?app=${options.app}&owner=${options.owner}` : ""}`,
  ),
}));
vi.mock("@splunk/splunk-utils/url", () => ({
  createRESTURL: createRESTURLMock,
}));
vi.mock("@splunk/splunk-utils/fetch", () => ({
  getDefaultFetchInit: () => ({
    headers: new Headers({ "X-Splunk-Form-Key": "csrf-token" }),
  }),
}));
import {
  BUILDER_SEARCHES,
  INDEX_MACROS,
  ToolkitSetupClient,
  validateIndexName,
  indexName,
  indexNames,
  setupReadiness,
} from "./setupClient";

const response = (body: unknown, status = 200) =>
  ({
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
  }) as Response;
const record = (content: Record<string, unknown> = {}, canWrite = true) => ({
  entry: [{ content, acl: { can_write: canWrite } }],
});
type FetchMock = (
  input: RequestInfo | URL,
  init?: RequestInit,
) => Promise<Response>;
function fetcher(role: string[] = ["admin"]): MockedFunction<FetchMock> {
  return vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input);
    if (url.includes("authentication/current-context"))
      return response(
        record({
          roles: role,
          capabilities: role.some((name) =>
            ["admin", "sc_admin"].includes(name),
          )
            ? ["admin_all_objects"]
            : ["search"],
        }),
      );
    if (url.includes("configs/conf-macros/"))
      return response(
        record({
          definition: url.includes("summary_index_name")
            ? "adm_summary"
            : "index=netflow",
        }),
      );
    if (url.includes("saved/searches/"))
      return response(record({ disabled: "1" }));
    if (url.includes("data/indexes/"))
      return response(record({ disabled: "0" }));
    if (url.includes("adm_observer_scope")) return response([]);
    return response({});
  });
}
describe("ToolkitSetupClient", () => {
  it("validates bare index names strictly", () => {
    expect(validateIndexName("adm_summary")).toBeUndefined();
    expect(
      indexName({
        name: "adm_index_summary",
        definition: "index=adm_summary\n",
        canWrite: true,
      }),
    ).toBeUndefined();
    for (const value of ["", "Index", "a/b", "a b", "a\n", "a".repeat(81)])
      expect(validateIndexName(value)).toBeTruthy();
  });
  it("accepts only validated parenthesized index OR expressions", () => {
    const macro = {
      name: "adm_index_dcn" as const,
      definition: "(index=dcn OR index=dcn_archive)",
      canWrite: true,
    };
    expect(indexNames(macro)).toEqual(["dcn", "dcn_archive"]);
    expect(indexName(macro)).toBeUndefined();
    for (const definition of [
      "(index=dcn OR index=Bad)",
      "(index=dcn OR sourcetype=x)",
      "index=dcn OR index=dcn_archive",
      `(index=${"a".repeat(81)} OR index=dcn)`,
      "(index=dcn OR index=dcn_archive)\n",
    ])
      expect(indexNames({ ...macro, definition })).toEqual([]);
    expect(
      indexNames({ ...macro, definition: `index=${"a".repeat(79)}` }),
    ).toEqual(["a".repeat(79)]);
  });
  it("uses admin_all_objects independently of role names", async () => {
    const request = fetcher(["custom_setup_role"]);
    request.mockImplementation(async (input: RequestInfo | URL, init) => {
      const url = String(input);
      if (url.includes("authentication/current-context"))
        return response(
          record({
            roles: ["custom_setup_role"],
            capabilities: ["admin_all_objects"],
          }),
        );
      return fetcher(["admin"])(input, init);
    });
    const snapshot = await new ToolkitSetupClient(request).read();
    expect(snapshot.authorized).toBe(true);
  });
  it("reads authorized state and paged scope completion", async () => {
    const request = fetcher(["sc_admin"]);
    const controller = new AbortController();
    const snapshot = await new ToolkitSetupClient(request).read(
      controller.signal,
    );
    expect(snapshot.authorized).toBe(true);
    expect(snapshot.summaryIndex).toMatchObject({
      name: "adm_summary",
      exists: true,
    });
    expect(snapshot.observerScopes.complete).toBe(true);
    expect(snapshot.macros).toHaveLength(INDEX_MACROS.length);
    expect(snapshot.savedSearches).toHaveLength(BUILDER_SEARCHES.length);
    expect(
      request.mock.calls.some(
        ([url, init]) =>
          String(url).includes("output_mode=json") &&
          init?.signal &&
          init.signal !== controller.signal,
      ),
    ).toBe(true);
    expect(createRESTURLMock).toHaveBeenCalledWith(
      expect.stringContaining("configs/conf-macros"),
      { app: "splunk_adm", owner: "nobody" },
    );
  });
  it("walks scope pages and reports duplicate keys", async () => {
    const request = fetcher();
    const base = fetcher();
    let page = 0;
    request.mockImplementation(
      async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if (url.includes("adm_observer_scope")) {
          page += 1;
          return response(
            page === 1
              ? Array.from({ length: 1000 }, (_, index) => ({
                  _key: `k${index}`,
                  observer_kind: "aci",
                  observer: "leaf",
                  scope: "prod",
                  cluster: "c",
                }))
              : [
                  {
                    _key: "k0",
                    observer_kind: "aci",
                    observer: "leaf",
                    scope: "prod",
                    cluster: "c",
                  },
                ],
          );
        }
        return base(input, init);
      },
    );
    const snapshot = await new ToolkitSetupClient(request).read();
    expect(snapshot.observerScopes.complete).toBe(false);
    expect(snapshot.observerScopes.error).toContain("malformed");
    expect(
      request.mock.calls.some(([url]) => String(url).includes("skip=1000")),
    ).toBe(true);
  });
  it("marks a nonempty 20,000-row probe incomplete", async () => {
    const request = fetcher();
    const base = fetcher();
    request.mockImplementation(
      async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if (url.includes("adm_observer_scope")) {
          const skip = new URL(url, "https://test").searchParams.get("skip");
          return response(
            skip === "20000"
              ? [
                  {
                    _key: "overflow",
                    observer_kind: "aci",
                    observer: "leaf",
                    scope: "prod",
                    cluster: "c",
                  },
                ]
              : Array.from({ length: 1000 }, (_, index) => ({
                  _key: `${skip}-${index}`,
                  observer_kind: "aci",
                  observer: "leaf",
                  scope: "prod",
                  cluster: "c",
                })),
          );
        }
        return base(input, init);
      },
    );
    const state = await new ToolkitSetupClient(request).read();
    expect(state.observerScopes.complete).toBe(false);
    expect(state.observerScopes.error).toContain("20,000");
  });
  it("rejects blank observer scope fields", async () => {
    const request = fetcher();
    const base = fetcher();
    request.mockImplementation(
      async (input: RequestInfo | URL, init?: RequestInit) => {
        if (String(input).includes("adm_observer_scope"))
          return response([
            {
              _key: " ",
              observer_kind: "aci",
              observer: "leaf",
              scope: "prod",
              cluster: "c",
            },
          ]);
        return base(input, init);
      },
    );
    const state = await new ToolkitSetupClient(request).read();
    expect(state.observerScopes.complete).toBe(false);
    expect(state.observerScopes.error).toContain("malformed");
  });
  it("uses CSRF and exact mutation payloads, with writer macro special case", async () => {
    const request = fetcher();
    const client = new ToolkitSetupClient(request);
    await client.setIndexMacro("adm_summary_index_name", "adm_summary");
    await client.setIndexMacro("adm_index_summary", "other_index");
    await client.setBuilderEnabled("ADM - Identity builder", true);
    const posts = request.mock.calls.filter(
      ([, init]) => init?.method === "POST",
    );
    expect(posts).toHaveLength(3);
    expect(new Headers(posts[0][1]?.headers).get("X-Splunk-Form-Key")).toBe(
      "csrf-token",
    );
    expect(
      new URLSearchParams(String(posts[0][1]?.body)).get("definition"),
    ).toBe("adm_summary");
    expect(
      new URLSearchParams(String(posts[1][1]?.body)).get("definition"),
    ).toBe("index=other_index");
    expect(new URLSearchParams(String(posts[2][1]?.body)).toString()).toContain(
      "disabled=0",
    );
    expect(new URLSearchParams(String(posts[2][1]?.body)).toString()).toContain(
      "is_scheduled=1",
    );
  });
  it("does not POST for viewer, invalid names, or disallowed actions", async () => {
    const request = fetcher(["user"]);
    const client = new ToolkitSetupClient(request);
    await expect(
      client.setIndexMacro("adm_index_summary", "safe_index"),
    ).rejects.toThrow("Administrator");
    await expect(
      client.setIndexMacro("adm_index_summary", "safe/index"),
    ).rejects.toThrow("index name");
    await expect(
      client.setBuilderEnabled("ADM - Identity builder", false),
    ).rejects.toThrow("enabling");
    await expect(
      client.setBuilderEnabled("ADM - Recovery prune" as never, true),
    ).rejects.toThrow("approved");
    expect(request.mock.calls.some(([, init]) => init?.method === "POST")).toBe(
      false,
    );
  });
  it("blocks an administrator when the target ACL denies writes", async () => {
    const request = fetcher(["admin"]);
    request.mockImplementation(
      async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if (url.includes("authentication/current-context"))
          return response(
            record({ roles: ["admin"], capabilities: ["admin_all_objects"] }),
          );
        if (url.includes("configs/conf-macros/adm_index_summary"))
          return response(record({ definition: "index=netflow" }, false));
        return fetcher()(input, init);
      },
    );
    await expect(
      new ToolkitSetupClient(request).setIndexMacro(
        "adm_index_summary",
        "safe_index",
      ),
    ).rejects.toThrow("writable");
    expect(request.mock.calls.some(([, init]) => init?.method === "POST")).toBe(
      false,
    );
  });
  it("distinguishes absent summary index from forbidden and preserves partial warnings", async () => {
    const request = fetcher();
    request.mockImplementation(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes("authentication/current-context"))
        return response(record({ roles: ["admin"] }));
      if (url.includes("configs/conf-macros/adm_summary_index_name"))
        return response(record({ definition: "adm_summary" }));
      if (url.includes("data/indexes/adm_summary")) return response({}, 404);
      if (url.includes("adm_observer_scope")) return response({}, 403);
      return response(record({ definition: "index=netflow", disabled: "1" }));
    });
    const state = await new ToolkitSetupClient(request).read();
    expect(state.summaryIndex.error).toContain("not returned");
    expect(state.observerScopes.complete).toBe(false);
    expect(state.observerScopes.error).toContain("403");
  });
});

describe("ToolkitSetupClient request deadlines", () => {
  it("forwards external abort through a composed signal", async () => {
    const controller = new AbortController();
    let forwarded: AbortSignal | undefined;
    const request: MockedFunction<FetchMock> = vi.fn(
      async (_input, init) =>
        new Promise<Response>((_resolve, reject) => {
          forwarded = init?.signal ?? undefined;
          init?.signal?.addEventListener(
            "abort",
            () => reject(new Error("aborted")),
            { once: true },
          );
        }),
    );
    const promise = new ToolkitSetupClient(request).setIndexMacro(
      "adm_index_summary",
      "safe_index",
      controller.signal,
    );
    await vi.waitFor(() => expect(forwarded).toBeDefined());
    expect(forwarded).not.toBe(controller.signal);
    const rejection = expect(promise).rejects.toThrow("aborted");
    controller.abort();
    await rejection;
    expect(forwarded?.aborted).toBe(true);
  });
  it("times out a hanging POST without retrying the mutation", async () => {
    vi.useFakeTimers();
    try {
      let posts = 0;
      const request: MockedFunction<FetchMock> = vi.fn(async (input, init) => {
        const url = String(input);
        if (init?.method === "POST") {
          posts += 1;
          return new Promise<Response>((_resolve, reject) =>
            init.signal?.addEventListener(
              "abort",
              () => reject(new Error("network aborted")),
              { once: true },
            ),
          );
        }
        if (url.includes("authentication/current-context"))
          return response(
            record({ roles: ["admin"], capabilities: ["admin_all_objects"] }),
          );
        return response(record({ definition: "index=netflow" }));
      });
      const promise = new ToolkitSetupClient(request).setIndexMacro(
        "adm_index_summary",
        "safe_index",
      );
      const rejection = expect(promise).rejects.toThrow("timed out");
      await vi.advanceTimersByTimeAsync(30000);
      await rejection;
      expect(posts).toBe(1);
    } finally {
      vi.useRealTimers();
    }
  });
});

it("gates readiness on required pilot sources while reporting optional sources", () => {
  const macros = INDEX_MACROS.map((name) => ({
    name,
    definition:
      name === "adm_summary_index_name" ? "adm_summary" : "index=adm_summary",
    canWrite: true,
  }));
  macros.find((macro) => macro.name === "adm_index_dcn")!.definition =
    "(index=dcn OR index=dcn_archive)";
  const snapshot = {
    authorized: true,
    macros: macros.filter(
      (macro) =>
        !["adm_index_ftd", "adm_index_isovalent", "adm_index_hubble"].includes(
          macro.name,
        ),
    ),
    summaryIndex: { name: "adm_summary", exists: true },
    observerScopes: {
      rows: [
        {
          _key: "aci",
          observer_kind: "aci",
          observer: "leaf",
          scope: "prod",
          cluster: "c",
        },
      ],
      complete: true,
    },
    savedSearches: [],
    warnings: [],
  };
  expect(setupReadiness(snapshot).ready).toBe(true);
  expect(setupReadiness(snapshot).optionalWarnings).toHaveLength(3);
  const blocked = {
    ...snapshot,
    macros: snapshot.macros.filter((macro) => macro.name !== "adm_index_k8s"),
  };
  expect(setupReadiness(blocked).ready).toBe(false);
  expect(setupReadiness(blocked).missingRequired).toContain("adm_index_k8s");
});
