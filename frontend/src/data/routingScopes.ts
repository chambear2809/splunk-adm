import { useEffect, useState } from "react";
import {
  observerMappingClient,
  type ObserverMapping,
} from "./observerMappingClient";
import { isImpactScope } from "../impact/url";

/**
 * "mapped" accepts administrator-mapped or verified observer scopes (Impact,
 * Trace). "verified" accepts only attested scopes (endpoint and DNS evidence).
 */
export type RoutingScopeRequirement = "mapped" | "verified";

export interface RoutingScopeOption {
  scope: string;
  observers: number;
  verified: boolean;
}

export type RoutingScopeState =
  | { status: "idle" }
  | { status: "loading" }
  | { status: "ready"; options: RoutingScopeOption[] }
  | { status: "error"; error: string };

/** Above this many scopes the select gains a local filter box. */
export const SCOPE_FILTER_THRESHOLD = 15;

export function routingScopeOptions(
  mappings: readonly ObserverMapping[],
  require: RoutingScopeRequirement = "mapped",
): RoutingScopeOption[] {
  const byScope = new Map<string, RoutingScopeOption>();
  for (const row of mappings) {
    const status = row.mapping_status?.trim().toLowerCase();
    const verified = status === "verified";
    if (!(verified || (require === "mapped" && status === "mapped"))) continue;
    if (
      !isImpactScope(row.scope) ||
      /^(unknown|reserved)(:|$)/i.test(row.scope)
    )
      continue;
    const option = byScope.get(row.scope) ?? {
      scope: row.scope,
      observers: 0,
      verified: false,
    };
    option.observers += 1;
    option.verified ||= verified;
    byScope.set(row.scope, option);
  }
  return [...byScope.values()].sort((a, b) => a.scope.localeCompare(b.scope));
}

/** Case-insensitive substring filter that always keeps the current value. */
export function filterScopeOptions(
  options: readonly RoutingScopeOption[],
  query: string,
  current = "",
): RoutingScopeOption[] {
  const needle = query.trim().toLowerCase();
  if (!needle) return [...options];
  return options.filter(
    (option) =>
      option.scope === current || option.scope.toLowerCase().includes(needle),
  );
}

/** The one scope to preselect, only when nothing was chosen or linked. */
export function singleScope(
  state: RoutingScopeState,
  value: string,
): string | undefined {
  return state.status === "ready" && state.options.length === 1 && !value.trim()
    ? state.options[0].scope
    : undefined;
}

/** True when a linked or typed value is not among the loaded scopes. */
export function isUnlistedScope(state: RoutingScopeState, value: string) {
  return (
    state.status === "ready" &&
    !!value &&
    !state.options.some((option) => option.scope === value)
  );
}

interface MappingLister {
  list(signal?: AbortSignal): Promise<ObserverMapping[]>;
}

const sessionCache = new WeakMap<MappingLister, Promise<ObserverMapping[]>>();

/** One caller-session read per page; a failure is not cached so Retry works. */
export function loadObserverMappings(
  client: MappingLister = observerMappingClient,
): Promise<ObserverMapping[]> {
  const cached = sessionCache.get(client);
  if (cached) return cached;
  const request = client.list().catch((error: unknown) => {
    sessionCache.delete(client);
    throw error;
  });
  sessionCache.set(client, request);
  return request;
}

export function clearRoutingScopeCache(client: MappingLister) {
  sessionCache.delete(client);
}

export function useRoutingScopes(
  enabled: boolean,
  require: RoutingScopeRequirement = "mapped",
  client: MappingLister = observerMappingClient,
): RoutingScopeState & { retry: () => void } {
  const [state, setState] = useState<RoutingScopeState>({ status: "idle" });
  const [revision, setRevision] = useState(0);
  useEffect(() => {
    if (!enabled) {
      setState({ status: "idle" });
      return;
    }
    let active = true;
    setState({ status: "loading" });
    loadObserverMappings(client)
      .then((rows) => {
        if (active)
          setState({
            status: "ready",
            options: routingScopeOptions(rows, require),
          });
      })
      .catch((error: unknown) => {
        if (active)
          setState({
            status: "error",
            error:
              error instanceof Error
                ? error.message
                : "Routing scopes are unavailable.",
          });
      });
    return () => {
      active = false;
    };
  }, [enabled, require, client, revision]);
  return {
    ...state,
    retry: () => {
      clearRoutingScopeCache(client);
      setRevision((value) => value + 1);
    },
  };
}
