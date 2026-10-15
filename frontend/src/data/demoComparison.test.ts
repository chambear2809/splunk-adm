import { afterEach, expect, it, vi } from "vitest";
import { fetchPreviousDemo } from "./demoClient";
vi.mock("@splunk/splunk-utils/url", () => ({
  createStaticURL: (path: string) => path,
}));
afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});
it("cancels a stalled fixture fetch with its caller", async () => {
  let requested: AbortSignal | undefined;
  vi.stubGlobal(
    "fetch",
    vi.fn(
      (_url: string, init: RequestInit) =>
        new Promise((_resolve, reject) => {
          requested = init.signal as AbortSignal;
          requested.addEventListener("abort", () =>
            reject(new Error("cancelled")),
          );
        }),
    ),
  );
  const caller = new AbortController();
  const pending = fetchPreviousDemo(caller.signal);
  const assertion = expect(pending).rejects.toThrow("cancelled");
  caller.abort();
  await assertion;
  expect(requested?.aborted).toBe(true);
});
it("bounds a stalled fixture request with a deadline", async () => {
  vi.useFakeTimers();
  vi.stubGlobal(
    "fetch",
    vi.fn(
      (_url: string, init: RequestInit) =>
        new Promise((_resolve, reject) => {
          init.signal?.addEventListener("abort", () =>
            reject(new Error("timeout")),
          );
        }),
    ),
  );
  const assertion = expect(fetchPreviousDemo()).rejects.toThrow("timeout");
  await vi.advanceTimersByTimeAsync(10000);
  await assertion;
});
