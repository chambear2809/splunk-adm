import { useEffect, useRef, useState } from "react";
import type { Row } from "../rows";
import { isImpactScope } from "../impact/url";
import { requireNoSearchErrors, type SearchClient } from "./searchClient";

export const SUGGEST_MIN_CHARS = 3;
export const SUGGEST_DEBOUNCE_MS = 300;
export const SUGGEST_LIMIT = 20;
export const LOCAL_SUGGEST_LIMIT = 8;
const PREFIX = /^[A-Za-z0-9][A-Za-z0-9.:-]{2,62}$/;

export interface EndpointSuggestion {
  value: string;
  label?: string;
  kind?: string;
  source: "page" | "server";
}
export interface EndpointSuggestResult {
  suggestions: EndpointSuggestion[];
  truncated: boolean;
}
export type EndpointSuggestState =
  | { status: "idle" }
  | { status: "loading" }
  | ({ status: "ready" } & EndpointSuggestResult)
  | { status: "error"; error: string };

/** Normalized prefix accepted by `adm_ip_suggest`, or undefined. */
export function suggestPrefix(query: string): string | undefined {
  const value = query.trim();
  if (!PREFIX.test(value)) return undefined;
  return value.includes(":") ? value.toLowerCase() : value;
}

export const suggestScope = (scope: string): string | undefined => {
  const value = scope.trim();
  return isImpactScope(value) &&
    !/^(unknown|reserved)$/i.test(value) &&
    !/^unmapped:/i.test(value)
    ? value
    : undefined;
};

export function endpointSuggestSearch(prefix: string, scope: string): string {
  const safePrefix = suggestPrefix(prefix);
  const safeScope = suggestScope(scope);
  if (!safePrefix || !safeScope)
    throw new Error("Endpoint suggestions need a valid prefix and scope.");
  return `| \`adm_ip_suggest(${safePrefix},${safeScope})\``;
}

const text = (value: unknown): string | undefined =>
  typeof value === "string" && value.trim() ? value.trim() : undefined;

export function parseEndpointSuggestions(
  rows: readonly Row[],
): EndpointSuggestResult {
  const seen = new Set<string>();
  const suggestions: EndpointSuggestion[] = [];
  let truncated = false;
  for (const row of rows) {
    if (row.truncated === "1" || row.truncated === 1) truncated = true;
    if (row.row_type !== "suggestion") continue;
    const value = text(row.ip);
    if (!value || seen.has(value) || !PREFIX.test(value)) continue;
    seen.add(value);
    const label = text(row.label);
    const kind = text(row.entity_kind);
    suggestions.push({
      value,
      source: "server",
      ...(label ? { label } : {}),
      ...(kind ? { kind } : {}),
    });
  }
  if (suggestions.length > SUGGEST_LIMIT) {
    suggestions.length = SUGGEST_LIMIT;
    truncated = true;
  }
  return { suggestions, truncated };
}

const startsWith = (suggestion: EndpointSuggestion, prefix: string) => {
  const lower = prefix.toLowerCase();
  return (
    suggestion.value.toLowerCase().startsWith(lower) ||
    !!suggestion.label?.toLowerCase().startsWith(lower)
  );
};

const caches = new WeakMap<SearchClient, Map<string, EndpointSuggestResult>>();
const cacheKey = (scope: string, prefix: string) =>
  JSON.stringify([scope, prefix]);

/**
 * Page-session cache per search client. A complete (untruncated) result for a
 * shorter prefix answers any longer prefix without another search.
 */
export function cachedSuggestions(
  client: SearchClient,
  scope: string,
  prefix: string,
): EndpointSuggestResult | undefined {
  const cache = caches.get(client);
  if (!cache) return undefined;
  const exact = cache.get(cacheKey(scope, prefix));
  if (exact) return exact;
  for (let length = prefix.length - 1; length >= SUGGEST_MIN_CHARS; length--) {
    const shorter = cache.get(cacheKey(scope, prefix.slice(0, length)));
    if (shorter && !shorter.truncated)
      return {
        suggestions: shorter.suggestions.filter((row) =>
          startsWith(row, prefix),
        ),
        truncated: false,
      };
  }
  return undefined;
}

export function clearEndpointSuggestCache(client: SearchClient) {
  caches.delete(client);
}

export async function fetchEndpointSuggestions(
  client: SearchClient,
  scope: string,
  prefix: string,
  signal: AbortSignal,
): Promise<EndpointSuggestResult> {
  const result = parseEndpointSuggestions(
    requireNoSearchErrors(
      await client.search({
        search: endpointSuggestSearch(prefix, scope),
        earliest: "-1m",
        latest: "now",
        maxRows: SUGGEST_LIMIT + 1,
        overflow: "truncate",
        allowEmpty: true,
        signal,
        budget: { serverSeconds: 10, clientMilliseconds: 12000 },
      }),
      "Endpoint suggestions",
    ).rows,
  );
  let cache = caches.get(client);
  if (!cache) caches.set(client, (cache = new Map()));
  cache.set(cacheKey(scope, prefix), result);
  return result;
}

/**
 * Debounces typed input, aborts the superseded request, and serves cached
 * prefixes immediately. One instance serves one input.
 */
export class EndpointSuggester {
  private timer: ReturnType<typeof setTimeout> | undefined;
  private controller: AbortController | undefined;
  private last = "";
  constructor(
    private readonly client: SearchClient,
    private readonly onChange: (state: EndpointSuggestState) => void,
    private readonly delay = SUGGEST_DEBOUNCE_MS,
  ) {}
  private cancel() {
    if (this.timer !== undefined) clearTimeout(this.timer);
    this.timer = undefined;
    this.controller?.abort();
    this.controller = undefined;
  }
  update(scope: string, query: string) {
    const safeScope = suggestScope(scope);
    const prefix = suggestPrefix(query);
    const key = safeScope && prefix ? cacheKey(safeScope, prefix) : "";
    if (key && key === this.last) return;
    this.last = key;
    this.cancel();
    if (!safeScope || !prefix) {
      this.onChange({ status: "idle" });
      return;
    }
    const cached = cachedSuggestions(this.client, safeScope, prefix);
    if (cached) {
      this.onChange({ status: "ready", ...cached });
      return;
    }
    this.timer = setTimeout(() => {
      this.timer = undefined;
      const controller = new AbortController();
      this.controller = controller;
      this.onChange({ status: "loading" });
      fetchEndpointSuggestions(
        this.client,
        safeScope,
        prefix,
        controller.signal,
      ).then(
        (result) => {
          if (controller.signal.aborted) return;
          this.controller = undefined;
          this.onChange({ status: "ready", ...result });
        },
        (error: unknown) => {
          if (controller.signal.aborted) return;
          this.controller = undefined;
          this.last = "";
          this.onChange({
            status: "error",
            error:
              error instanceof Error
                ? error.message
                : "Endpoint suggestions are unavailable.",
          });
        },
      );
    }, this.delay);
  }
  dispose() {
    this.last = "";
    this.cancel();
  }
}

/** Page suggestions first (in their given order), then distinct server rows. */
export function mergeEndpointSuggestions(
  local: readonly string[],
  query: string,
  server: readonly EndpointSuggestion[] = [],
  limit = SUGGEST_LIMIT,
): EndpointSuggestion[] {
  const needle = query.trim().toLowerCase();
  const seen = new Set<string>();
  const merged: EndpointSuggestion[] = [];
  for (const value of local) {
    if (merged.length >= Math.min(LOCAL_SUGGEST_LIMIT, limit)) break;
    if (seen.has(value) || value === query.trim()) continue;
    if (needle && !value.toLowerCase().includes(needle)) continue;
    seen.add(value);
    merged.push({ value, source: "page" });
  }
  for (const row of server) {
    if (merged.length >= limit) break;
    if (seen.has(row.value) || row.value === query.trim()) continue;
    seen.add(row.value);
    merged.push(row);
  }
  return merged;
}

/** Server suggestions for text the user typed; idle without a client or scope. */
export function useEndpointSuggestions(
  client: SearchClient | undefined,
  scope: string,
  query: string,
): EndpointSuggestState {
  const [state, setState] = useState<EndpointSuggestState>({ status: "idle" });
  const suggester = useRef<EndpointSuggester>();
  useEffect(() => {
    if (!client) {
      suggester.current = undefined;
      setState({ status: "idle" });
      return;
    }
    const instance = new EndpointSuggester(client, setState);
    suggester.current = instance;
    return () => {
      instance.dispose();
      if (suggester.current === instance) suggester.current = undefined;
    };
  }, [client]);
  useEffect(() => {
    suggester.current?.update(scope, query);
  }, [client, scope, query]);
  return state;
}
