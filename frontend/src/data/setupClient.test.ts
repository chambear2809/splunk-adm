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
const stagedMacroDefinitions: Record<string, string> = {
  adm_data_contract_version: "1",
  "adm_graph(4)": "search index=adm_summary",
  "adm_graph_v2(4)": "search index=adm_summary_v2",
  adm_index_summary_v2: "index=adm_summary_v2",
  adm_summary_index_v2_name: "adm_summary_v2",
  adm_network_client_history_observations:
    "search index=adm_network_client_history",
  adm_network_client_history_build:
    "search index=cisco_catalyst OR index=cisco_meraki",
};
const sourceProfile = (overrides: Record<string, unknown> = {}) => ({
  _key: "a".repeat(64),
  mapping_key: "c".repeat(64),
  duplicate_count: 1,
  source: "stream_ipfix",
  source_authority: "192.0.2.20",
  domain_kind: "exporter",
  observation_domain_present: "1",
  observation_domain_id: "0",
  vpn_id: "42",
  routing_domain: "42",
  scope: "prod",
  cluster: "checkout-east",
  mapping_status: "mapped",
  profile: "catalyst_sdwan_ipfix",
  ...overrides,
});
const clusterSetting = (overrides: Record<string, unknown> = {}) => ({
  _key: "b".repeat(64),
  cluster: "checkout-east",
  lb_mode: "snat",
  ingress_mode: "dedicated",
  l2announcements_enabled: "0",
  mapping_status: "mapped",
  ...overrides,
});
// Mirrors the KV Store data endpoint, which pages with limit/skip and ignores
// count. The client must always send a positive limit.
const pageFromURL = (url: string, rows: unknown[]) => {
  const query = new URL(url, "https://test").searchParams;
  const skip = Number(query.get("skip") ?? "0");
  const limit = Number(query.get("limit"));
  if (!Number.isInteger(limit) || limit <= 0)
    throw new Error(`KV read without a positive limit: ${url}`);
  return rows.slice(skip, skip + limit);
};
function stagedIntegrationFetcher(
  sourceRows = [sourceProfile()],
  clusterRows = [clusterSetting()],
  inaccessibleCollection?: string,
): MockedFunction<FetchMock> {
  const request = fetcher();
  request.mockImplementation(async (input: RequestInfo | URL) => {
    const url = String(input);
    if (url.includes("authentication/current-context"))
      return response(record({ capabilities: ["admin_all_objects"] }));
    if (url.includes("configs/conf-macros/")) {
      const name = decodeURIComponent(
        url.split("configs/conf-macros/")[1]?.split("?")[0] ?? "",
      );
      if (name === "adm_graph" || name === "adm_graph_v2")
        return response({ message: "Unknown macro stanza" }, 404);
      const definition =
        stagedMacroDefinitions[name] ??
        (name === "adm_summary_index_name"
          ? "adm_summary"
          : name === "adm_index_summary"
            ? "index=adm_summary"
            : "index=netflow");
      return response(record({ definition }, false));
    }
    if (url.includes("saved/searches/"))
      return response(record({ disabled: "1", is_scheduled: "1" }, false));
    if (url.includes("data/indexes/"))
      return response(record({ disabled: "0" }, false));
    if (url.includes("adm_observer_scope")) return response([]);
    if (inaccessibleCollection && url.includes(inaccessibleCollection))
      return response({ message: "forbidden" }, 403);
    if (url.includes("adm_network_source_scope"))
      return response(pageFromURL(url, sourceRows));
    if (url.includes("adm_cilium_cluster_settings"))
      return response(pageFromURL(url, clusterRows));
    return response({});
  });
  return request;
}
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
        ![
          "adm_index_ftd",
          "adm_index_isovalent",
          "adm_index_hubble",
          "adm_index_catalyst",
          "adm_index_meraki",
        ].includes(macro.name),
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
    ciscoIntegration: {
      macros: [],
      searches: [],
      summaryIndex: {},
      sourceProfiles: { rows: [], complete: true },
      clusterSettings: { rows: [], complete: true },
      state: "staged" as const,
      reasons: [],
    },
    warnings: [],
  };
  expect(setupReadiness(snapshot).ready).toBe(true);
  expect(setupReadiness(snapshot).optionalWarnings).toHaveLength(5);
  const blocked = {
    ...snapshot,
    macros: snapshot.macros.filter((macro) => macro.name !== "adm_index_k8s"),
  };
  expect(setupReadiness(blocked).ready).toBe(false);
  expect(setupReadiness(blocked).missingRequired).toContain("adm_index_k8s");
});

it("reads complete staged Cisco integration state without writing or activating it", async () => {
  const request = stagedIntegrationFetcher();
  const state = await new ToolkitSetupClient(request).read();
  expect(state.ciscoIntegration).toMatchObject({
    state: "staged",
    summaryIndex: { name: "adm_summary_v2", exists: true },
    sourceProfiles: { complete: true, rows: [sourceProfile()] },
    clusterSettings: { complete: true, rows: [clusterSetting()] },
    searches: [
      {
        name: "ADM - Network client history builder",
        disabled: true,
        scheduled: true,
      },
      {
        name: "ADM - Conversation rollup v2",
        disabled: true,
        scheduled: true,
      },
      {
        name: "ADM - Traffic observation rollup v2",
        disabled: true,
        scheduled: true,
      },
    ],
  });
  expect(state.ciscoIntegration.reasons).toEqual([]);
  expect(request.mock.calls.some(([, init]) => init?.method === "POST")).toBe(
    false,
  );
});

it.each([
  { profile: "catalyst_campus_fnf", vpn_id: "", routing_domain: "" },
  { profile: "meraki_ms390_ipfix", vpn_id: "", routing_domain: "" },
  {
    profile: "standard_netflow",
    observation_domain_present: "0",
    observation_domain_id: "",
    vpn_id: "",
    routing_domain: "",
  },
])("accepts valid optional fields for $profile", async (fields) => {
  const profile = sourceProfile(fields);
  const state = await new ToolkitSetupClient(
    stagedIntegrationFetcher([profile]),
  ).read();
  expect(state.ciscoIntegration.state).toBe("staged");
  expect(state.ciscoIntegration.sourceProfiles).toMatchObject({
    complete: true,
    rows: [profile],
  });
  expect(state.ciscoIntegration.reasons).toEqual([]);
});

it.each([
  { source_authority: "" },
  { scope: " " },
  { cluster: "" },
  { vpn_id: undefined as unknown as string },
  { routing_domain: 42 as unknown as string },
])("rejects malformed source profile fields %j", async (fields) => {
  const state = await new ToolkitSetupClient(
    stagedIntegrationFetcher([sourceProfile(fields)]),
  ).read();
  expect(state.ciscoIntegration.state).toBe("incomplete");
  expect(state.ciscoIntegration.sourceProfiles.complete).toBe(false);
});

it("fails Cisco status closed for duplicate or unknown source profiles", async () => {
  const duplicate = sourceProfile({ _key: "c".repeat(64) });
  const duplicateState = await new ToolkitSetupClient(
    stagedIntegrationFetcher([sourceProfile(), duplicate]),
  ).read();
  expect(duplicateState.ciscoIntegration.state).toBe("incomplete");
  expect(duplicateState.ciscoIntegration.sourceProfiles.complete).toBe(false);
  expect(duplicateState.ciscoIntegration.reasons.join(" ")).toContain(
    "Duplicate seven-key",
  );
  const duplicateMappingKeyState = await new ToolkitSetupClient(
    stagedIntegrationFetcher([
      sourceProfile(),
      sourceProfile({
        _key: "d".repeat(64),
        source_authority: "192.0.2.21",
      }),
    ]),
  ).read();
  expect(
    duplicateMappingKeyState.ciscoIntegration.sourceProfiles.complete,
  ).toBe(false);
  expect(
    duplicateMappingKeyState.ciscoIntegration.sourceProfiles.error,
  ).toContain("Duplicate source mapping keys");
  const unknownState = await new ToolkitSetupClient(
    stagedIntegrationFetcher([
      sourceProfile({ profile: "unreviewed_source_profile" }),
    ]),
  ).read();
  expect(unknownState.ciscoIntegration.state).toBe("incomplete");
  expect(unknownState.ciscoIntegration.reasons.join(" ")).toContain(
    "Unknown source profiles",
  );
  const duplicateCountState = await new ToolkitSetupClient(
    stagedIntegrationFetcher([
      sourceProfile({ duplicate_count: 2, mapping_status: "mapped" }),
    ]),
  ).read();
  expect(duplicateCountState.ciscoIntegration.state).toBe("incomplete");
  expect(
    duplicateCountState.ciscoIntegration.sourceProfiles.rows[0],
  ).toMatchObject({
    duplicate_count: 2,
    mapping_status: "mapped",
  });
  expect(duplicateCountState.ciscoIntegration.reasons.join(" ")).toContain(
    "Duplicate source-profile candidates",
  );
  const missingMappingKeyState = await new ToolkitSetupClient(
    stagedIntegrationFetcher([
      { ...sourceProfile(), mapping_key: undefined as unknown as string },
    ]),
  ).read();
  expect(missingMappingKeyState.ciscoIntegration.sourceProfiles.complete).toBe(
    false,
  );
  const permissionState = await new ToolkitSetupClient(
    stagedIntegrationFetcher(
      [sourceProfile()],
      [clusterSetting()],
      "adm_network_source_scope",
    ),
  ).read();
  expect(permissionState.ciscoIntegration.state).toBe("incomplete");
  expect(permissionState.ciscoIntegration.sourceProfiles.complete).toBe(false);
});

it("walks source profile pages and marks collections at the configured cap incomplete", async () => {
  const makeProfiles = (count: number) =>
    Array.from({ length: count }, (_, i) =>
      sourceProfile({
        _key: i.toString(16).padStart(64, "0"),
        mapping_key: (i + 1).toString(16).padStart(64, "0"),
        source_authority: "192.0.2." + i,
      }),
    );
  const pagedRequest = stagedIntegrationFetcher(makeProfiles(251));
  const paged = await new ToolkitSetupClient(pagedRequest).read();
  expect(paged.ciscoIntegration.sourceProfiles.complete).toBe(true);
  expect(paged.ciscoIntegration.sourceProfiles.rows).toHaveLength(251);
  expect(
    pagedRequest.mock.calls.some(
      ([url]) =>
        String(url).includes("adm_network_source_scope") &&
        String(url).includes("skip=250"),
    ),
  ).toBe(true);

  const capped = await new ToolkitSetupClient(
    stagedIntegrationFetcher(makeProfiles(1001)),
  ).read();
  expect(capped.ciscoIntegration.sourceProfiles.complete).toBe(false);
  expect(capped.ciscoIntegration.sourceProfiles.error).toContain("1000-row");
  expect(capped.ciscoIntegration.state).toBe("incomplete");
});

describe("KV Store collection paging", () => {
  const makeProfiles = (count: number) =>
    Array.from({ length: count }, (_, i) =>
      sourceProfile({
        _key: i.toString(16).padStart(64, "0"),
        mapping_key: (i + 1).toString(16).padStart(64, "0"),
        source_authority: "192.0.2." + i,
      }),
    );
  const makeClusters = (count: number) =>
    Array.from({ length: count }, (_, i) =>
      clusterSetting({
        _key: i.toString(16).padStart(64, "0"),
        cluster: "cluster-" + i,
      }),
    );
  const collectionURLs = (
    request: MockedFunction<FetchMock>,
    collection: string,
  ) =>
    request.mock.calls
      .map(([url]) => String(url))
      .filter((url) => url.includes(`storage/collections/data/${collection}`));

  it("requests pages with limit and skip, never count", async () => {
    const request = stagedIntegrationFetcher(makeProfiles(600));
    await new ToolkitSetupClient(request).read();
    for (const collection of [
      "adm_network_source_scope",
      "adm_cilium_cluster_settings",
    ]) {
      const urls = collectionURLs(request, collection);
      expect(urls.length).toBeGreaterThan(0);
      for (const url of urls) {
        const query = new URL(url, "https://test").searchParams;
        expect(query.get("limit")).toMatch(/^[1-9][0-9]*$/);
        expect(query.has("skip")).toBe(true);
        expect(query.has("count")).toBe(false);
      }
    }
  });

  it("reads a collection larger than one page completely", async () => {
    const request = stagedIntegrationFetcher(
      makeProfiles(600),
      makeClusters(600),
    );
    const state = await new ToolkitSetupClient(request).read();
    expect(state.ciscoIntegration.sourceProfiles.complete).toBe(true);
    expect(state.ciscoIntegration.sourceProfiles.error).toBeUndefined();
    expect(state.ciscoIntegration.sourceProfiles.rows).toHaveLength(600);
    expect(state.ciscoIntegration.clusterSettings.complete).toBe(true);
    expect(state.ciscoIntegration.clusterSettings.rows).toHaveLength(600);
    expect(
      collectionURLs(request, "adm_network_source_scope").map((url) =>
        new URL(url, "https://test").searchParams.get("skip"),
      ),
    ).toEqual(["0", "250", "500"]);
  });

  it("treats exactly the review limit as complete", async () => {
    const request = stagedIntegrationFetcher(makeProfiles(1000));
    const state = await new ToolkitSetupClient(request).read();
    expect(state.ciscoIntegration.sourceProfiles.complete).toBe(true);
    expect(state.ciscoIntegration.sourceProfiles.error).toBeUndefined();
    expect(state.ciscoIntegration.sourceProfiles.rows).toHaveLength(1000);
    const probe = collectionURLs(request, "adm_network_source_scope").at(-1);
    const query = new URL(probe ?? "", "https://test").searchParams;
    expect(query.get("skip")).toBe("1000");
    expect(query.get("limit")).toBe("1");
  });

  it("reports the review limit when the collection exceeds it", async () => {
    const state = await new ToolkitSetupClient(
      stagedIntegrationFetcher(makeProfiles(1001)),
    ).read();
    expect(state.ciscoIntegration.sourceProfiles.complete).toBe(false);
    expect(state.ciscoIntegration.sourceProfiles.rows).toHaveLength(1000);
    expect(state.ciscoIntegration.sourceProfiles.error).toBe(
      "Collection exceeds the 1000-row setup review limit.",
    );
    expect(state.ciscoIntegration.state).toBe("incomplete");
  });
});
