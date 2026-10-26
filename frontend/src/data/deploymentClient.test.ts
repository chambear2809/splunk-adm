import { describe, expect, it, vi } from "vitest";
vi.mock("@splunk/splunk-utils/url", () => ({
  createRESTURL: (path: string) => `/rest/${path}`,
}));
vi.mock("@splunk/splunk-utils/fetch", () => ({
  getDefaultFetchInit: () => ({
    headers: new Headers({ "X-Splunk-Form-Key": "csrf-test" }),
  }),
}));
import {
  DeploymentWriteError,
  ToolkitDeploymentClient,
} from "./deploymentClient";
import {
  defaultExpectations,
  DATA_CONTRACT_SELECTORS,
  selectedHealthProbes,
} from "./deploymentHealth";

const response = (body: unknown, status = 200) =>
  ({ ok: status < 300, status, json: async () => body }) as Response;
const entry = (content: Record<string, unknown>, canWrite = true) => ({
  entry: [{ content, acl: { can_write: canWrite } }],
});
function barrier() {
  let release!: () => void;
  const promise = new Promise<void>((resolve) => {
    release = resolve;
  });
  return { promise, release };
}
function fixture({
  admin = true,
  writable = true,
  unreadable = false,
  readbackMismatch = false,
  contract = 1,
  mixedSelector = false,
  missingSelector = false,
  indexDefinition = "index=netflow",
  unreadableIndex = false,
  enabled = true,
  lostResponse = false,
  finalSlot = false,
  malformedCapacity = false,
} = {}) {
  let record: ReturnType<typeof defaultExpectations> | undefined;
  const revisions: string[] = [];
  const operations = new Map<string, { revision: string; signature: string }>();
  let lose = lostResponse;
  const fetcher = vi.fn(
    async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      if (path.includes("configs/conf-macros")) {
        const name = decodeURIComponent(
          path.split("conf-macros/")[1].split("?")[0],
        );
        if (name === "adm_index_netflow" || name === "adm_index_dns_stream")
          return unreadableIndex
            ? response({}, 403)
            : response(entry({ definition: indexDefinition }));
        if (name === "adm_index_summary")
          return response(entry({ definition: "index=adm_summary" }));
        if (name === "adm_summary_index_name")
          return response(entry({ definition: "adm_summary" }));
        if (missingSelector && name === "adm_topology")
          return response({}, 403);
        const selector = DATA_CONTRACT_SELECTORS.find(
          (item) => item.name === name,
        )!;
        return response(
          entry({
            definition:
              selector[
                mixedSelector && name === "adm_topology"
                  ? "before"
                  : contract === 1
                    ? "before"
                    : "after"
              ],
          }),
        );
      }
      if (!path.includes("adm/deployment-settings"))
        throw new Error(`Unexpected endpoint ${path}`);
      if (init?.method === "POST") {
        if (!admin || !writable)
          return response(
            { code: "forbidden", error: "Administrator access required." },
            403,
          );
        const body = JSON.parse(String(init.body));
        const signature = JSON.stringify([
          body.expectedRevision,
          body.settings.sources,
        ]);
        const existing = operations.get(body.requestId);
        if (existing && existing.signature !== signature)
          return response({ code: "conflict", error: "Request changed." }, 409);
        if (!existing && (record?.revision ?? null) !== body.expectedRevision)
          return response(
            {
              code: "conflict",
              error:
                "Deployment expectations changed. Your draft is preserved; reload before saving.",
            },
            409,
          );
        const revision = existing?.revision ?? `revision_${operations.size}`;
        if (!existing) {
          record = { ...body.settings, revision };
          revisions.push(revision);
          operations.set(body.requestId, { revision, signature });
        }
        if (lose) {
          lose = false;
          throw new Error("response lost");
        }
        return response({
          committedRevision: revision,
          requestId: body.requestId,
        });
      }
      if (unreadable) return response({}, 403);
      return response({
        state: record ? "configured" : "absent",
        settings: record,
        observedRevisions: readbackMismatch && record ? [] : [...revisions],
        recordCount: malformedCapacity ? 2 : record ? 1 : 0,
        maxRecords: 1,
        remainingRecords: malformedCapacity ? 0 : record ? 0 : 1,
        ...(finalSlot && record
          ? {
              capacityWarning:
                "Deployment settings history is nearly full. Review and schedule the separately approved migration before the remaining slots are consumed; records are never deleted or rotated automatically.",
            }
          : {}),
        canWrite: admin && writable && enabled && (!finalSlot || !record),
        canRetry: admin && writable && enabled && finalSlot && !!record,
        namespace: "namespace_a",
        ...(!enabled
          ? {
              writeUnavailableReason:
                "Settings writes are disabled pending topology qualification.",
            }
          : {}),
      });
    },
  );
  return { fetcher, client: new ToolkitDeploymentClient(fetcher), operations };
}

describe("administrator deployment settings persistence", () => {
  it("verifies selected index configuration and never scans defaults through an empty macro", async () => {
    for (const [options, expected] of [
      [{}, "configured"],
      [{ indexDefinition: "" }, "not_configured"],
      [{ indexDefinition: "index=netflow OR search *" }, "not_configured"],
      [{ unreadableIndex: true }, "unavailable"],
    ] as const) {
      const { client } = fixture(options);
      const settings = defaultExpectations();
      settings.sources.netflow.state = "active";
      const saved = await client.write(settings);
      expect(saved.sourceConfiguration?.netflow).toBe(expected);
      expect(
        selectedHealthProbes(saved).some(
          (probe) => probe.macro === "adm_health_source_netflow",
        ),
      ).toBe(expected === "configured");
      expect(
        selectedHealthProbes(saved).some(
          (probe) => probe.macro === "adm_health_quality_netflow",
        ),
      ).toBe(expected === "configured");
    }
  });
  it("treats the shipped DNS placeholder index as not configured", async () => {
    for (const [indexDefinition, expected] of [
      ["index=unconfigured_dns", "not_configured"],
      ["index=dns_prod", "configured"],
      ["(index=dns_a OR index=dns_b)", "configured"],
    ] as const) {
      const { client } = fixture({ indexDefinition });
      const settings = defaultExpectations();
      settings.sources.dns_stream.state = "active";
      const saved = await client.write(settings);
      expect(saved.sourceConfiguration?.dns_stream).toBe(expected);
    }
  });
  it("verifies public selector coherence instead of trusting the version marker", async () => {
    expect((await fixture({ contract: 2 }).client.read()).activeContract).toBe(
      2,
    );
    expect(
      (await fixture({ contract: 2, mixedSelector: true }).client.read())
        .activeContract,
    ).toBeUndefined();
    expect(
      (await fixture({ missingSelector: true }).client.read()).activeContract,
    ).toBeUndefined();
  });
  it("distinguishes absent settings from restricted evidence", async () => {
    expect((await fixture().client.read()).state).toBe("absent");
    expect((await fixture({ unreadable: true }).client.read()).state).toBe(
      "unavailable",
    );
  });
  it("requires both effective admin capability and collection permission", async () => {
    for (const options of [{ admin: false }, { writable: false }]) {
      const { client, fetcher } = fixture(options);
      await expect(client.write(defaultExpectations())).rejects.toThrow(
        "Administrator",
      );
      expect(
        fetcher.mock.calls.some(([, init]) => init?.method === "POST"),
      ).toBe(false);
    }
  });
  it("uses the authenticated endpoint with CSRF protection and verifies the committed revision", async () => {
    const { client, fetcher } = fixture();
    const settings = defaultExpectations();
    settings.sources.catalyst.state = "active";
    const saved = await client.write(settings);
    expect(saved.state).toBe("configured");
    expect(saved.settings?.sources.catalyst).toEqual(settings.sources.catalyst);
    expect(saved.activeContract).toBe(1);
    const write = fetcher.mock.calls.find(
      ([, init]) => init?.method === "POST",
    )!;
    expect(new Headers(write[1]?.headers).get("X-Splunk-Form-Key")).toBe(
      "csrf-test",
    );
    expect(String(write[0])).toContain("adm/deployment-settings");
    expect(JSON.parse(String(write[1]?.body)).namespace).toBe("namespace_a");
    expect(JSON.parse(String(write[1]?.body)).expectedRevision).toBeNull();
    await expect(client.write(settings)).rejects.toThrow("changed");
    expect((await client.write(settings, saved.settings!.revision)).state).toBe(
      "configured",
    );
  });
  it("fails readback and aborted writes without publishing a healthy configuration", async () => {
    await expect(
      fixture({ readbackMismatch: true }).client.write(defaultExpectations()),
    ).rejects.toThrow("verified");
    const { client, fetcher } = fixture();
    const controller = new AbortController();
    controller.abort();
    await expect(
      client.write(defaultExpectations(), undefined, controller.signal),
    ).rejects.toThrow("cancelled");
    expect(fetcher).not.toHaveBeenCalled();
  });
  it("preserves idempotent request identity after response loss and recovers after later saves", async () => {
    const { client, fetcher, operations } = fixture({ lostResponse: true });
    const first = defaultExpectations();
    await expect(client.write(first)).rejects.toMatchObject({
      code: "uncertain",
      message: expect.stringContaining("retry the same save"),
    });
    const another = new ToolkitDeploymentClient(fetcher);
    const head = await another.read();
    const next = defaultExpectations();
    next.sources.netflow.state = "staged";
    await another.write(next, head.settings!.revision);
    await expect(client.write(first)).rejects.toMatchObject({
      code: "conflict",
    });
    const posts = fetcher.mock.calls.filter(
      ([, init]) => init?.method === "POST",
    );
    expect(JSON.parse(String(posts[0][1]?.body)).requestId).toBe(
      JSON.parse(String(posts[2][1]?.body)).requestId,
    );
    expect(operations.size).toBe(2);
  });
  it("keeps existing settings readable with disabled writes and explains qualification", async () => {
    const { client, fetcher } = fixture({ enabled: false });
    const state = await client.read();
    expect(state.state).toBe("absent");
    expect(state.canWrite).toBe(false);
    expect(state.writeUnavailableReason).toContain("disabled");
    await expect(client.write(defaultExpectations())).rejects.toThrow(
      "qualification",
    );
    expect(fetcher.mock.calls.some(([, init]) => init?.method === "POST")).toBe(
      false,
    );
  });
  it("exposes a typed conflict while preserving the original settings object", async () => {
    const { client, fetcher } = fixture();
    const stale = defaultExpectations();
    await new ToolkitDeploymentClient(fetcher).write(defaultExpectations());
    await expect(client.write(stale)).rejects.toBeInstanceOf(
      DeploymentWriteError,
    );
    expect(stale.revision).toBe("draft");
  });
  it("arbitrates independent client creations at the server endpoint", async () => {
    const { fetcher, operations } = fixture();
    const outcomes = await Promise.allSettled([
      new ToolkitDeploymentClient(fetcher).write(defaultExpectations()),
      new ToolkitDeploymentClient(fetcher).write(defaultExpectations()),
    ]);
    expect(
      outcomes.filter((outcome) => outcome.status === "fulfilled"),
    ).toHaveLength(1);
    expect(
      outcomes.filter((outcome) => outcome.status === "rejected"),
    ).toHaveLength(1);
    expect(operations.size).toBe(1);
  });
  it("retains the request identity when cancellation follows server acceptance", async () => {
    const { fetcher, operations } = fixture();
    const controller = new AbortController();
    let cancel = true;
    const client = new ToolkitDeploymentClient(async (input, init) => {
      const result = await fetcher(input, init);
      if (cancel && init?.method === "POST") {
        cancel = false;
        controller.abort();
      }
      return result;
    });
    await expect(
      client.write(defaultExpectations(), undefined, controller.signal),
    ).rejects.toThrow("cancelled");
    await expect(client.write(defaultExpectations())).resolves.toMatchObject({
      state: "configured",
    });
    const posts = fetcher.mock.calls.filter(
      ([, init]) => init?.method === "POST",
    );
    expect(JSON.parse(String(posts[0][1]?.body)).requestId).toBe(
      JSON.parse(String(posts[1][1]?.body)).requestId,
    );
    expect(operations.size).toBe(1);
  });
  it("refuses a replica refresh that loses an already observed revision", async () => {
    const { fetcher } = fixture();
    let stale = false;
    const client = new ToolkitDeploymentClient(async (input, init) => {
      const result = await fetcher(input, init);
      if (
        stale &&
        String(input).includes("adm/deployment-settings") &&
        init?.method === "GET"
      )
        return response({
          state: "absent",
          settings: null,
          observedRevisions: [],
          canWrite: true,
          namespace: "namespace_a",
        });
      return result;
    });
    await client.write(defaultExpectations());
    stale = true;
    const read = await client.read();
    expect(read.state).toBe("unavailable");
    expect(read.canWrite).toBe(false);
    expect(read.error).toContain("previously observed");
  });
  it("calls the default native fetch without rebinding it to the client", async () => {
    const { fetcher } = fixture();
    vi.stubGlobal(
      "fetch",
      function (this: unknown, input: RequestInfo | URL, init?: RequestInit) {
        if (this !== undefined && this !== globalThis)
          throw new TypeError("Failed to execute 'fetch': Illegal invocation");
        return fetcher(input, init);
      },
    );
    try {
      expect((await new ToolkitDeploymentClient().read()).state).toBe("absent");
    } finally {
      vi.unstubAllGlobals();
    }
  });
  it("reports a non-JSON gateway failure on save as uncertain", async () => {
    const { fetcher } = fixture();
    const client = new ToolkitDeploymentClient(async (input, init) =>
      init?.method === "POST"
        ? ({
            ok: false,
            status: 504,
            json: async () => JSON.parse("<html>Gateway Timeout</html>"),
          } as Response)
        : fetcher(input, init),
    );
    await expect(client.write(defaultExpectations())).rejects.toMatchObject({
      code: "uncertain",
      message: expect.stringContaining("retry the same save"),
    });
  });
  it("reports a dropped or timed-out save as uncertain and retries the same operation", async () => {
    const { fetcher, operations } = fixture();
    let failure: "network" | "timeout" | undefined = "network";
    const client = new ToolkitDeploymentClient(async (input, init) => {
      if (init?.method !== "POST" || !failure) return fetcher(input, init);
      const mode = failure;
      failure = undefined;
      await fetcher(input, init);
      if (mode === "network") throw new TypeError("Failed to fetch");
      return new Promise<Response>((_, reject) =>
        init.signal?.addEventListener("abort", () =>
          reject(new DOMException("The operation was aborted.", "AbortError")),
        ),
      );
    });
    await expect(client.write(defaultExpectations())).rejects.toMatchObject({
      code: "uncertain",
      message: expect.stringContaining("retry the same save"),
    });
    await expect(client.write(defaultExpectations())).resolves.toMatchObject({
      state: "configured",
    });
    const posts = fetcher.mock.calls.filter(
      ([, init]) => init?.method === "POST",
    );
    expect(JSON.parse(String(posts[0][1]?.body)).requestId).toBe(
      JSON.parse(String(posts[1][1]?.body)).requestId,
    );
    expect(operations.size).toBe(1);

    vi.useFakeTimers();
    try {
      const head = await client.read();
      failure = "timeout";
      const next = defaultExpectations();
      next.sources.netflow.state = "staged";
      const pending = client.write(next, head.settings!.revision);
      const outcome = expect(pending).rejects.toMatchObject({
        code: "uncertain",
      });
      await vi.advanceTimersByTimeAsync(30000);
      await outcome;
    } finally {
      vi.useRealTimers();
    }
  });
  it("retries an uncertain final-slot save even after reads stop advertising new writes", async () => {
    const { client } = fixture({ lostResponse: true, finalSlot: true });
    const settings = defaultExpectations();
    await expect(client.write(settings)).rejects.toMatchObject({
      code: "uncertain",
    });
    await expect(client.write(settings)).resolves.toMatchObject({
      state: "configured",
      canWrite: false,
      remainingRecords: 0,
    });
  });
  it("rejects malformed capacity metadata instead of enabling writes or retries", async () => {
    const state = await fixture({ malformedCapacity: true }).client.read();
    expect(state.state).toBe("unavailable");
    expect(state.canWrite).toBe(false);
    await expect(
      fixture({ malformedCapacity: true }).client.write(defaultExpectations()),
    ).rejects.toMatchObject({ code: "unavailable" });
  });
  it("does not bypass authorization or disabled-namespace failures for a pending save", async () => {
    for (const options of [{ admin: false }, { enabled: false }]) {
      const { client } = fixture({ ...options, finalSlot: true });
      await expect(client.write(defaultExpectations())).rejects.toMatchObject({
        code: "forbidden",
      });
    }
  });
  it("reports a failed pre-save read as unavailable, not as missing permissions", async () => {
    const { fetcher } = fixture();
    const client = new ToolkitDeploymentClient(async (input, init) =>
      String(input).includes("adm/deployment-settings")
        ? ({
            ok: false,
            status: 502,
            json: async () => JSON.parse("<html>Bad Gateway</html>"),
          } as Response)
        : fetcher(input, init),
    );
    await expect(client.write(defaultExpectations())).rejects.toMatchObject({
      code: "unavailable",
    });
    expect(fetcher.mock.calls.some(([, init]) => init?.method === "POST")).toBe(
      false,
    );
  });
  it.each(["read", "verified save"])(
    "refuses an old read whose index macros finish after a newer %s",
    async (advance) => {
      const { fetcher } = fixture();
      const blocked = barrier();
      const resume = barrier();
      let pauseNextIndex = false;
      const client = new ToolkitDeploymentClient(async (input, init) => {
        const result = await fetcher(input, init);
        if (
          pauseNextIndex &&
          String(input).includes("conf-macros/adm_index_netflow?")
        ) {
          pauseNextIndex = false;
          blocked.release();
          await resume.promise;
        }
        return result;
      });
      const original = defaultExpectations();
      original.sources.netflow.state = "active";
      const initial = await client.write(original);
      pauseNextIndex = true;
      const oldRead = client.read();
      await blocked.promise;

      const changed = defaultExpectations();
      changed.sources.netflow.state = "active";
      changed.sources.netflow.cadenceSeconds = 120;
      const writer =
        advance === "read" ? new ToolkitDeploymentClient(fetcher) : client;
      const saved = await writer.write(changed, initial.settings!.revision);
      const newer = advance === "read" ? await client.read() : saved;
      expect(newer.state).toBe("configured");
      expect(newer.settings!.revision).not.toBe(initial.settings!.revision);
      expect(newer.settings!.sources.netflow.cadenceSeconds).toBe(120);

      resume.release();
      const lateOld = await oldRead;
      expect(lateOld.state).toBe("unavailable");
      expect(lateOld.canWrite).toBe(false);
      expect(lateOld.settings).toBeUndefined();
      expect(lateOld.error).toContain("previously observed revision");
      const ordinary = await client.read();
      expect(ordinary.state).toBe("configured");
      expect(ordinary.settings!.revision).toBe(newer.settings!.revision);
    },
  );
});

describe("caller-authorized app-merged metadata fallback", () => {
  function mergedFetcher(
    base: ReturnType<typeof fixture>,
    mode: "valid" | "denied" | "duplicate" | "mixed" = "valid",
  ) {
    return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const path = String(input);
      if (path.includes("configs/conf-macros/")) return response({}, 403);
      if (path.includes("configs/v1/conftypes/macros/stanzas:get")) {
        expect(init?.method).toBe("POST");
        expect(path).toContain("?view=app-merged&output_mode=json");
        expect(new Headers(init?.headers).get("X-Splunk-Form-Key")).toBe(
          "csrf-test",
        );
        const { stanza } = JSON.parse(String(init?.body));
        expect(stanza).toMatch(/^adm_[a-z0-9_]+(?:\([1-9][0-9]*\))?$/);
        if (mode === "denied") return response({}, 403);
        const selector = DATA_CONTRACT_SELECTORS.find(
          (item) => item.name === stanza,
        );
        const value = selector
          ? selector[
              mode === "mixed" && stanza === "adm_topology" ? "after" : "before"
            ]
          : "index=netflow";
        const definition = { setting: "definition", value };
        return response({
          settings:
            mode === "duplicate" ? [definition, definition] : [definition],
        });
      }
      const result = await base.fetcher(input, init);
      if (path.includes("adm/deployment-settings") && init?.method !== "POST")
        return response({
          ...(await result.json()),
          canWrite: false,
          canRetry: false,
        });
      return result;
    });
  }

  it("verifies contract and active index metadata without configuration writes", async () => {
    const base = fixture();
    const settings = defaultExpectations();
    settings.sources.netflow.state = "active";
    await base.client.write(settings);
    const fetcher = mergedFetcher(base);
    const snapshot = await new ToolkitDeploymentClient(fetcher).read();
    expect(snapshot.activeContract).toBe(1);
    expect(snapshot.sourceConfiguration?.netflow).toBe("configured");
    expect(snapshot.canWrite).toBe(false);
    const posts = fetcher.mock.calls.filter(
      ([, init]) => init?.method === "POST",
    );
    expect(posts.length).toBeGreaterThan(DATA_CONTRACT_SELECTORS.length);
    const stanzas = posts.map(
      ([, init]) => JSON.parse(String(init?.body)).stanza,
    );
    for (const selector of DATA_CONTRACT_SELECTORS)
      expect(stanzas).toContain(selector.name);
    expect(stanzas).toContain("adm_index_netflow");
    expect(
      posts.every(([path]) =>
        String(path).includes("configs/v1/conftypes/macros/stanzas:get"),
      ),
    ).toBe(true);
  });

  it.each(["denied", "duplicate", "mixed"] as const)(
    "keeps %s app-merged metadata unqualified",
    async (mode) => {
      const fetcher = mergedFetcher(fixture({ admin: false }), mode);
      const snapshot = await new ToolkitDeploymentClient(fetcher).read();
      expect(snapshot.activeContract).toBeUndefined();
      expect(snapshot.canWrite).toBe(false);
      expect(
        fetcher.mock.calls.some(
          ([path, init]) =>
            String(path).includes("adm/deployment-settings") &&
            init?.method === "POST",
        ),
      ).toBe(false);
    },
  );

  it("does not replace inconsistent readable legacy definitions with another view", async () => {
    const base = fixture({ admin: false, contract: 2, mixedSelector: true });
    const snapshot = await base.client.read();
    expect(snapshot.activeContract).toBeUndefined();
    expect(
      base.fetcher.mock.calls.some(([path]) =>
        String(path).includes("stanzas:get"),
      ),
    ).toBe(false);
  });
});
