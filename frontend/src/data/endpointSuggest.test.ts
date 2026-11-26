import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Row } from "../rows";
import type { RunResult, SearchClient, SearchRequest } from "./searchClient";
import {
  EndpointSuggester,
  SUGGEST_DEBOUNCE_MS,
  SUGGEST_LIMIT,
  cachedSuggestions,
  endpointSuggestSearch,
  mergeEndpointSuggestions,
  parseEndpointSuggestions,
  suggestPrefix,
  type EndpointSuggestState,
} from "./endpointSuggest";

const result = (rows: Row[], errors: string[] = []): RunResult => ({
  rows,
  warnings: [],
  errors,
});
const suggestion = (ip: string, label?: string): Row => ({
  row_type: "suggestion",
  ip,
  ...(label ? { label, entity_kind: "pod" } : {}),
  truncated: "0",
});
const completion = (truncated: boolean): Row => ({
  row_type: "completion",
  truncated: truncated ? "1" : "0",
});

/** A client whose searches resolve only when the test says so. */
function deferredClient() {
  const calls: {
    request: SearchRequest;
    resolve: (value: RunResult) => void;
    reject: (error: Error) => void;
  }[] = [];
  const client: SearchClient = {
    search: vi.fn(
      (request: SearchRequest) =>
        new Promise<RunResult>((resolve, reject) =>
          calls.push({ request, resolve, reject }),
        ),
    ),
  };
  return { client, calls };
}

describe("endpoint suggestion search", () => {
  it("accepts only bounded address or host-name prefixes", () => {
    expect(suggestPrefix("10.4")).toBe("10.4");
    expect(suggestPrefix(" web-0 ")).toBe("web-0");
    expect(suggestPrefix("2001:DB8")).toBe("2001:db8");
    for (const bad of [
      "10",
      "",
      "*10",
      '10.0"',
      "10.0 | delete",
      "a_b_c",
      "web)",
      "x".repeat(64),
    ])
      expect(suggestPrefix(bad), bad).toBeUndefined();
  });

  it("builds a macro call only from validated arguments", () => {
    expect(endpointSuggestSearch("10.4", "fabric-a")).toBe(
      "| `adm_ip_suggest(10.4,fabric-a)`",
    );
    for (const [prefix, scope] of [
      ["10", "fabric-a"],
      ["10.4", ""],
      ["10.4", "unmapped:x"],
      ["10.4", "unknown"],
      ["10.4", "fabric,a"],
      ["10.4)", "fabric-a"],
    ])
      expect(() => endpointSuggestSearch(prefix, scope)).toThrow();
  });

  it("parses distinct suggestions, labels and truncation", () => {
    const parsed = parseEndpointSuggestions([
      completion(true),
      suggestion("10.4.0.1", "web-0"),
      suggestion("10.4.0.1", "web-0"),
      suggestion("bad value"),
      suggestion("10.4.0.2"),
    ]);
    expect(parsed.truncated).toBe(true);
    expect(parsed.suggestions).toEqual([
      { value: "10.4.0.1", label: "web-0", kind: "pod", source: "server" },
      { value: "10.4.0.2", source: "server" },
    ]);
    const many = parseEndpointSuggestions(
      Array.from({ length: 30 }, (_, i) => suggestion(`10.4.0.${i}`)),
    );
    expect(many.suggestions).toHaveLength(SUGGEST_LIMIT);
    expect(many.truncated).toBe(true);
  });

  it("puts page suggestions first, dedupes and caps the merged list", () => {
    const server = Array.from({ length: 30 }, (_, i) => ({
      value: `10.4.0.${i}`,
      source: "server" as const,
    }));
    const merged = mergeEndpointSuggestions(
      ["10.4.0.3", "web-10.4", "db-01"],
      "10.4",
      server,
    );
    expect(merged.slice(0, 2)).toEqual([
      { value: "10.4.0.3", source: "page" },
      { value: "web-10.4", source: "page" },
    ]);
    expect(merged).toHaveLength(SUGGEST_LIMIT);
    expect(merged.filter((row) => row.value === "10.4.0.3")).toHaveLength(1);
    expect(
      mergeEndpointSuggestions(
        Array.from({ length: 20 }, (_, i) => `h${i}`),
        "",
      ),
    ).toHaveLength(8);
  });
});

describe("EndpointSuggester", () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it("debounces typing into one bounded, budgeted search", async () => {
    const { client, calls } = deferredClient();
    const states: EndpointSuggestState[] = [];
    const suggester = new EndpointSuggester(client, (s) => states.push(s));
    suggester.update("fabric-a", "10.");
    suggester.update("fabric-a", "10.4");
    suggester.update("fabric-a", "10.4.");
    vi.advanceTimersByTime(SUGGEST_DEBOUNCE_MS - 1);
    expect(client.search).not.toHaveBeenCalled();
    vi.advanceTimersByTime(1);
    expect(client.search).toHaveBeenCalledTimes(1);
    const request = calls[0].request;
    expect(request.search).toBe("| `adm_ip_suggest(10.4.,fabric-a)`");
    expect(request.maxRows).toBe(SUGGEST_LIMIT + 1);
    expect(request.overflow).toBe("truncate");
    expect(request.allowEmpty).toBe(true);
    expect(request.budget).toEqual({
      serverSeconds: 10,
      clientMilliseconds: 12000,
    });
    calls[0].resolve(result([suggestion("10.4.0.1"), completion(false)]));
    await vi.runAllTimersAsync();
    expect(states.at(-1)).toEqual({
      status: "ready",
      suggestions: [{ value: "10.4.0.1", source: "server" }],
      truncated: false,
    });
  });

  it("stays idle without a scope or below three characters", () => {
    const { client } = deferredClient();
    const states: EndpointSuggestState[] = [];
    const suggester = new EndpointSuggester(client, (s) => states.push(s));
    suggester.update("", "10.4.0");
    suggester.update("fabric-a", "10");
    suggester.update("unmapped:abc", "10.4");
    vi.runAllTimers();
    expect(client.search).not.toHaveBeenCalled();
    expect(states.every((s) => s.status === "idle")).toBe(true);
  });

  it("aborts the in-flight request when the input changes", async () => {
    const { client, calls } = deferredClient();
    const states: EndpointSuggestState[] = [];
    const suggester = new EndpointSuggester(client, (s) => states.push(s));
    suggester.update("fabric-b", "10.5");
    vi.advanceTimersByTime(SUGGEST_DEBOUNCE_MS);
    expect(calls).toHaveLength(1);
    suggester.update("fabric-b", "10.6");
    expect(calls[0].request.signal.aborted).toBe(true);
    calls[0].resolve(result([suggestion("10.5.0.1")]));
    vi.advanceTimersByTime(SUGGEST_DEBOUNCE_MS);
    expect(calls).toHaveLength(2);
    calls[1].resolve(result([suggestion("10.6.0.1")]));
    await vi.runAllTimersAsync();
    const ready = states.filter((s) => s.status === "ready");
    expect(ready).toHaveLength(1);
    expect(ready[0]).toMatchObject({
      suggestions: [{ value: "10.6.0.1" }],
    });
    suggester.dispose();
  });

  it("serves repeated and narrower prefixes from the session cache", async () => {
    const { client, calls } = deferredClient();
    const states: EndpointSuggestState[] = [];
    const suggester = new EndpointSuggester(client, (s) => states.push(s));
    suggester.update("fabric-c", "10.7");
    vi.advanceTimersByTime(SUGGEST_DEBOUNCE_MS);
    calls[0].resolve(
      result([
        suggestion("10.7.0.1"),
        suggestion("10.7.1.1", "web-1"),
        completion(false),
      ]),
    );
    await vi.runAllTimersAsync();
    suggester.update("fabric-c", "10.7.1");
    expect(states.at(-1)).toMatchObject({
      status: "ready",
      suggestions: [{ value: "10.7.1.1" }],
    });
    suggester.update("fabric-c", "10.7");
    vi.runAllTimers();
    expect(client.search).toHaveBeenCalledTimes(1);
    expect(cachedSuggestions(client, "fabric-c", "10.7")).toBeTruthy();
    expect(cachedSuggestions(client, "fabric-d", "10.7")).toBeUndefined();
  });

  it("searches again when the cached shorter prefix was truncated", async () => {
    const { client, calls } = deferredClient();
    const suggester = new EndpointSuggester(client, () => undefined);
    suggester.update("fabric-e", "10.8");
    vi.advanceTimersByTime(SUGGEST_DEBOUNCE_MS);
    calls[0].resolve(result([suggestion("10.8.0.1"), completion(true)]));
    await vi.runAllTimersAsync();
    suggester.update("fabric-e", "10.8.9");
    vi.advanceTimersByTime(SUGGEST_DEBOUNCE_MS);
    expect(client.search).toHaveBeenCalledTimes(2);
    expect(calls[1].request.search).toContain("adm_ip_suggest(10.8.9,");
  });

  it("reports search errors without caching them", async () => {
    const { client, calls } = deferredClient();
    const states: EndpointSuggestState[] = [];
    const suggester = new EndpointSuggester(client, (s) => states.push(s));
    suggester.update("fabric-f", "10.9");
    vi.advanceTimersByTime(SUGGEST_DEBOUNCE_MS);
    calls[0].resolve(result([], ["Error in 'inputlookup'"]));
    await vi.runAllTimersAsync();
    expect(states.at(-1)?.status).toBe("error");
    expect(cachedSuggestions(client, "fabric-f", "10.9")).toBeUndefined();
    suggester.update("fabric-f", "10.9");
    vi.advanceTimersByTime(SUGGEST_DEBOUNCE_MS);
    expect(client.search).toHaveBeenCalledTimes(2);
  });

  it("cancels pending and in-flight work on dispose", () => {
    const { client, calls } = deferredClient();
    const suggester = new EndpointSuggester(client, () => undefined);
    suggester.update("fabric-g", "10.10");
    suggester.dispose();
    vi.runAllTimers();
    expect(client.search).not.toHaveBeenCalled();
    suggester.update("fabric-g", "10.11");
    vi.advanceTimersByTime(SUGGEST_DEBOUNCE_MS);
    suggester.dispose();
    expect(calls[0].request.signal.aborted).toBe(true);
  });
});
