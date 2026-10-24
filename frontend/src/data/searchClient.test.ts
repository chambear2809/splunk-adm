import { beforeEach, describe, expect, it, vi } from "vitest";
import { OptionalJobBudget, optionalJobs } from "./optionalJobs";
import {
  SearchResultLimitError,
  ToolkitSearchClient,
  timeError,
} from "./searchClient";

const runtime = vi.hoisted(() => ({
  progress: undefined as any,
  result: undefined as any,
  unsubscribes: [] as ReturnType<typeof vi.fn>[],
  cancel: vi.fn(),
  create: vi.fn(),
}));
vi.mock("@splunk/search-job/SearchJob", () => ({
  default: { setBaseFetchInit: vi.fn(), create: runtime.create },
}));
vi.mock("@splunk/splunk-utils/config", () => ({ username: "alice" }));
vi.mock("@splunk/splunk-utils/fetch", () => ({
  getDefaultFetchInit: () => ({ credentials: "same-origin" }),
}));
vi.mock("@splunk/splunk-utils/url", () => ({
  createRESTURL: (path: string) => `/rest/${path}`,
}));
const job = () => ({
  getProgress: () => ({
    subscribe: (observer: any) => {
      runtime.progress = observer;
      const unsubscribe = vi.fn();
      runtime.unsubscribes.push(unsubscribe);
      return { unsubscribe };
    },
  }),
  getResults: () => ({
    subscribe: (observer: any) => {
      runtime.result = observer;
      const unsubscribe = vi.fn();
      runtime.unsubscribes.push(unsubscribe);
      return { unsubscribe };
    },
  }),
  cancel: runtime.cancel,
});
const request = (signal = new AbortController().signal) => ({
  search: "| makeresults",
  earliest: "-1h",
  latest: "now",
  maxRows: 2,
  signal,
});
beforeEach(() => {
  runtime.progress = undefined;
  runtime.result = undefined;
  runtime.unsubscribes = [];
  runtime.cancel.mockReset();
  runtime.create.mockReset().mockImplementation(() => job());
});
describe("timeError", () => {
  it("accepts relative modifiers, now and ordered epochs", () => {
    expect(timeError("-15m", "now")).toBeUndefined();
    expect(timeError("-1h@m", "+15m")).toBeUndefined();
    expect(timeError("1791373500", "1791374400")).toBeUndefined();
  });
  it("rejects unsafe values and reversed epochs", () => {
    expect(timeError("-1h | delete")).toMatch(/Unsupported/);
    expect(timeError("20", "10")).toMatch(/precede/);
  });
});

describe("bounded investigation job lifecycle", () => {
  it("releases optional admission after synchronous SDK creation failure so retry can dispatch", async () => {
    const budget = new OptionalJobBudget();
    runtime.create.mockImplementation(() => {
      throw new Error("SDK creation failed before a handle exists");
    });
    const client = new ToolkitSearchClient();
    const bounded = {
      ...request(),
      budget: { serverSeconds: 30, clientMilliseconds: 35000 },
    };
    await expect(
      budget.run("dns_stream", "first", client, bounded),
    ).rejects.toThrow(/could not be acknowledged/);
    expect(budget.cleanupPending).toBe(0);
    expect(budget.cleanupUnverified).toBe(1);
    await expect(
      budget.run("dns_stream", "retry", client, bounded),
    ).rejects.toThrow(/could not be acknowledged/);
    expect(runtime.create).toHaveBeenCalledTimes(2);
    expect(budget.cleanupPending).toBe(0);
    expect(budget.cleanupUnverified).toBe(2);
  });
  it("observes SID creation failures without an unhandled observable error", async () => {
    runtime.create.mockImplementation(() => ({
      ...job(),
      getSid: () => ({
        subscribe: (observer: any) => {
          expect(observer.error).toBeTypeOf("function");
          observer.error(Error("dispatch rejected"));
          return { unsubscribe: vi.fn() };
        },
      }),
    }));
    const pending = new ToolkitSearchClient().search({
      ...request(),
      budget: { serverSeconds: 30, clientMilliseconds: 35000 },
    });
    runtime.progress.error(Error("dispatch rejected"));
    await expect(pending).rejects.toThrow(/dispatch rejected/);
  });
  it("sends native execution budgets and retains cleanup until a terminal status is verified", async () => {
    const lifecycle = vi.fn();
    const controller = new AbortController();
    runtime.create.mockImplementation(() => ({
      ...job(),
      getSid: () => ({
        subscribe: (observer: any) => {
          observer.next("native-safe-id");
          return { unsubscribe: vi.fn() };
        },
      }),
    }));
    runtime.cancel.mockReturnValue({
      subscribe: (observer: any) => {
        observer.error(Error("transient cancel failure"));
        return { unsubscribe: vi.fn() };
      },
    });
    const fetcher = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ entry: [{ content: { isDone: true } }] }),
    });
    vi.stubGlobal("fetch", fetcher);
    const pending = new ToolkitSearchClient().search({
      ...request(controller.signal),
      budget: { serverSeconds: 30, clientMilliseconds: 35000 },
      onLifecycle: lifecycle,
    });
    expect(runtime.create.mock.calls[0][0]).toMatchObject({
      max_time: "30",
      auto_cancel: "30",
      auto_pause: "0",
    });
    controller.abort();
    await expect(pending).rejects.toThrow(/cancelled/);
    await Promise.resolve();
    await Promise.resolve();
    expect(fetcher).toHaveBeenCalledTimes(1);
    expect(lifecycle).toHaveBeenCalledWith({
      state: "released",
      sid: "native-safe-id",
    });
    vi.unstubAllGlobals();
  });
  it("verifies a known SID when cancellation remains open without acknowledgment", async () => {
    vi.useFakeTimers();
    const lifecycle = vi.fn();
    const controller = new AbortController();
    runtime.create.mockImplementation(() => ({
      ...job(),
      getSid: () => ({
        subscribe: (observer: any) => {
          observer.next("native-stalled-cancel-id");
          return { unsubscribe: vi.fn() };
        },
      }),
    }));
    runtime.cancel.mockReturnValue({
      subscribe: () => ({ unsubscribe: vi.fn() }),
    });
    const fetcher = vi
      .fn()
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ entry: [{ content: { isDone: false } }] }),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ entry: [{ content: { isDone: true } }] }),
      });
    vi.stubGlobal("fetch", fetcher);
    const pending = new ToolkitSearchClient().search({
      ...request(controller.signal),
      budget: { serverSeconds: 30, clientMilliseconds: 35000 },
      onLifecycle: lifecycle,
    });

    controller.abort();
    await expect(pending).rejects.toThrow(/cancelled/);
    expect(fetcher).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(0);
    expect(lifecycle).toHaveBeenCalledWith({
      state: "cleanup_pending",
      sid: "native-stalled-cancel-id",
    });
    expect(lifecycle).not.toHaveBeenCalledWith({
      state: "released",
      sid: "native-stalled-cancel-id",
    });

    await vi.advanceTimersByTimeAsync(5000);
    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(lifecycle).toHaveBeenCalledWith({
      state: "released",
      sid: "native-stalled-cancel-id",
    });
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });
  it("returns the core counter to zero when onLifecycle or getSid throws synchronously", async () => {
    const drain = vi.spyOn(optionalJobs, "coreFinished");
    const started = vi.spyOn(optionalJobs, "coreStarted");
    runtime.create.mockImplementation(() => ({
      ...job(),
      getSid: () => ({
        subscribe: () => {
          throw new Error("subscribe failed");
        },
      }),
    }));
    runtime.cancel.mockReturnValue(undefined);
    await expect(new ToolkitSearchClient().search(request())).rejects.toThrow(
      /subscribe failed/,
    );
    expect(started).toHaveBeenCalledTimes(1);
    expect(drain).toHaveBeenCalledTimes(1);

    started.mockClear();
    drain.mockClear();
    runtime.create.mockImplementation(() => ({
      ...job(),
      getSid: () => ({
        subscribe: (observer: any) => {
          observer.next("sid-1");
          return { unsubscribe: vi.fn() };
        },
      }),
    }));
    await expect(
      new ToolkitSearchClient().search({
        ...request(),
        onLifecycle: (event) => {
          if (event.state === "created") throw new Error("lifecycle failed");
        },
      }),
    ).rejects.toThrow(/lifecycle failed/);
    expect(started).toHaveBeenCalledTimes(1);
    expect(drain).toHaveBeenCalledTimes(1);
    started.mockRestore();
    drain.mockRestore();
  });
  it("reports cleanup_unverified once after twelve unreadable status checks", async () => {
    vi.useFakeTimers();
    const lifecycle = vi.fn();
    const controller = new AbortController();
    runtime.create.mockImplementation(() => ({
      ...job(),
      getSid: () => ({
        subscribe: (observer: any) => {
          observer.next("native-unreadable-id");
          return { unsubscribe: vi.fn() };
        },
      }),
    }));
    runtime.cancel.mockReturnValue({
      subscribe: () => ({ unsubscribe: vi.fn() }),
    });
    const fetcher = vi.fn().mockResolvedValue({ ok: false, status: 503 });
    vi.stubGlobal("fetch", fetcher);
    const pending = new ToolkitSearchClient().search({
      ...request(controller.signal),
      budget: { serverSeconds: 30, clientMilliseconds: 35000 },
      onLifecycle: lifecycle,
    });
    controller.abort();
    await expect(pending).rejects.toThrow(/cancelled/);
    await vi.advanceTimersByTimeAsync(5000 * 14);
    expect(fetcher).toHaveBeenCalledTimes(12);
    expect(
      lifecycle.mock.calls.filter(([e]) => e.state === "cleanup_unverified"),
    ).toEqual([[{ state: "cleanup_unverified", sid: "native-unreadable-id" }]]);
    expect(lifecycle).not.toHaveBeenCalledWith(
      expect.objectContaining({ state: "released" }),
    );
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });
  it("reports cleanup_unverified when no SID ever arrives", async () => {
    vi.useFakeTimers();
    const lifecycle = vi.fn();
    const controller = new AbortController();
    runtime.create.mockImplementation(() => ({
      ...job(),
      getSid: () => ({ subscribe: () => ({ unsubscribe: vi.fn() }) }),
    }));
    runtime.cancel.mockReturnValue({
      subscribe: () => ({ unsubscribe: vi.fn() }),
    });
    const pending = new ToolkitSearchClient().search({
      ...request(controller.signal),
      budget: { serverSeconds: 30, clientMilliseconds: 35000 },
      onLifecycle: lifecycle,
    });
    controller.abort();
    await expect(pending).rejects.toThrow(/cancelled/);
    expect(lifecycle).not.toHaveBeenCalledWith(
      expect.objectContaining({ state: "cleanup_unverified" }),
    );
    await vi.advanceTimersByTimeAsync(60000);
    expect(lifecycle).toHaveBeenCalledWith({
      state: "cleanup_unverified",
      sid: undefined,
    });
    vi.useRealTimers();
  });
  it("refuses invalid budgets before native dispatch", async () => {
    await expect(
      new ToolkitSearchClient().search({
        ...request(),
        budget: { serverSeconds: 31, clientMilliseconds: 35000 },
      }),
    ).rejects.toThrow(/budget/);
    expect(runtime.create).not.toHaveBeenCalled();
  });
});
describe("ToolkitSearchClient", () => {
  it("does not dispatch an already aborted request", async () => {
    const c = new AbortController();
    c.abort();
    await expect(
      new ToolkitSearchClient().search(request(c.signal)),
    ).rejects.toThrow("cancelled");
    expect(runtime.create).not.toHaveBeenCalled();
  });
  it("dispatches exact time params and reports rows", async () => {
    const pending = new ToolkitSearchClient().search(request());
    expect(runtime.create).toHaveBeenCalledWith(
      expect.objectContaining({ earliest_time: "-1h", latest_time: "now" }),
      expect.anything(),
    );
    runtime.progress.next({
      content: { resultCount: 1, messages: [{ type: "WARN", text: "slow" }] },
    });
    runtime.result.next({ results: [{ row_type: "meta" }] });
    await expect(pending).resolves.toMatchObject({
      rows: [{ row_type: "meta" }],
      warnings: ["slow"],
    });
  });
  it("reports ERROR and FATAL job messages separately", async () => {
    const pending = new ToolkitSearchClient().search(request());
    runtime.progress.next({
      content: {
        resultCount: 1,
        messages: [
          { type: "DEBUG", text: "trace" },
          { type: "ERROR", text: "peer unreachable" },
        ],
      },
    });
    runtime.result.next({
      results: [{ row_type: "meta" }],
      messages: [{ type: "FATAL", text: "search process ended" }],
    });
    const result = await pending;
    expect(result.errors).toEqual(["peer unreachable", "search process ended"]);
    expect(result.warnings).toEqual([
      "peer unreachable",
      "search process ended",
    ]);
  });
  it("rejects finalized, truncated, and dropped result sets", async () => {
    for (const [field, value, pattern] of [
      ["isFinalized", "1", /finalized/],
      ["resultIsTruncated", true, /truncated/],
      ["eventIsTruncated", true, /truncated/],
      ["dropCount", "2", /dropped/],
    ] as const) {
      const pending = new ToolkitSearchClient().search(request());
      runtime.progress.next({ content: { resultCount: 1, [field]: value } });
      runtime.result.next({ results: [{ a: 1 }] });
      await expect(pending).rejects.toThrow(pattern);
    }
    const pending = new ToolkitSearchClient().search(request());
    runtime.progress.next({ content: { resultCount: 3 } });
    runtime.result.next({ results: [{ a: 1 }] });
    await expect(pending).rejects.toBeInstanceOf(SearchResultLimitError);
  });
  it("requires an exact safe final result count", async () => {
    let pending = new ToolkitSearchClient().search(request());
    runtime.progress.next({ content: { resultCount: 2 } });
    runtime.result.next({ results: [{ a: 1 }] });
    await expect(pending).rejects.toThrow(/did not match/);
    pending = new ToolkitSearchClient().search(request());
    runtime.progress.next({ content: { resultCount: "" } });
    runtime.result.next({ results: [{ a: 1 }] });
    await expect(pending).rejects.toThrow(/valid final result count/);
  });
  it("cleans up on active abort and timeout", async () => {
    const c = new AbortController();
    const pending = new ToolkitSearchClient().search(request(c.signal));
    c.abort();
    await expect(pending).rejects.toThrow("cancelled");
    expect(runtime.cancel).toHaveBeenCalled();
    expect(
      runtime.unsubscribes.every(
        (unsubscribe) => unsubscribe.mock.calls.length > 0,
      ),
    ).toBe(true);
    vi.useFakeTimers();
    const timeout = new ToolkitSearchClient().search(request());
    vi.advanceTimersByTime(120000);
    await expect(timeout).rejects.toThrow(/timed out/);
    vi.useRealTimers();
  });
  it("surfaces failed, malformed and empty results", async () => {
    let pending = new ToolkitSearchClient().search(request());
    runtime.progress.error(new Error("quota"));
    await expect(pending).rejects.toThrow(/quota/);
    pending = new ToolkitSearchClient().search(request());
    runtime.progress.next({ content: {} });
    runtime.result.next({ nope: [] });
    await expect(pending).rejects.toThrow(/invalid/);
    pending = new ToolkitSearchClient().search(request());
    runtime.progress.next({ content: { resultCount: 0 } });
    runtime.result.next({ results: [] });
    await expect(pending).rejects.toThrow(/no rows/);
  });
  it("rejects failed progress states before results subscribe", async () => {
    const pending = new ToolkitSearchClient().search(request());
    runtime.progress.next({
      content: {
        dispatchState: "FAILED",
        messages: [{ text: "quota exceeded" }],
      },
    });
    await expect(pending).rejects.toThrow(/quota exceeded/);
  });
});

it("allows verified empty catalog/Find results only when explicitly requested", async () => {
  let pending = new ToolkitSearchClient().search({
    ...request(),
    allowEmpty: true,
  });
  runtime.progress.next({ content: { resultCount: 0 } });
  runtime.result.next({ results: [] });
  await expect(pending).resolves.toEqual({
    rows: [],
    warnings: [],
    errors: [],
  });
  pending = new ToolkitSearchClient().search({
    ...request(),
    allowEmpty: true,
  });
  runtime.progress.next({ content: { resultCount: 1 } });
  runtime.result.next({ results: [] });
  await expect(pending).rejects.toThrow(/count did not match/);
});
