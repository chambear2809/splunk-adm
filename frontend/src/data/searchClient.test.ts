import { beforeEach, describe, expect, it, vi } from "vitest";
import { ToolkitSearchClient, timeError } from "./searchClient";

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
  it("adds finalized warning and rejects overflow", async () => {
    let pending = new ToolkitSearchClient().search(request());
    runtime.progress.next({ content: { resultCount: 1, isFinalized: "1" } });
    runtime.result.next({ results: [{ a: 1 }] });
    await expect(pending).resolves.toMatchObject({
      warnings: [expect.stringMatching(/finalized/)],
    });
    pending = new ToolkitSearchClient().search(request());
    runtime.progress.next({ content: { resultCount: 3 } });
    runtime.result.next({ results: [{ a: 1 }] });
    await expect(pending).rejects.toThrow(/exceeds/);
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
  await expect(pending).resolves.toEqual({ rows: [], warnings: [] });
  pending = new ToolkitSearchClient().search({
    ...request(),
    allowEmpty: true,
  });
  runtime.progress.next({ content: { resultCount: 1 } });
  runtime.result.next({ results: [] });
  await expect(pending).rejects.toThrow(/count did not match/);
});
