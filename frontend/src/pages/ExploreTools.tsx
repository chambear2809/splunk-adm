import { useId, useState } from "react";
import { isSafeIdentifier, pageURL } from "../app/urlState";
import { useRoutingScopes } from "../data/routingScopes";
import type { SearchClient } from "../data/searchClient";
import type { GraphNode } from "../graph";
import { RoutingScopeSelect } from "../RoutingScopeSelect";
import {
  EndpointCombobox,
  SuggestCombobox,
  filterSuggestOptions,
  type SuggestOption,
} from "../SuggestCombobox";

const currentParams = () =>
  new URLSearchParams(typeof location === "undefined" ? "" : location.search);

/** Map link that carries the current scope plus a trace request. */
export function traceURL(
  src: string,
  dst: string,
  params: URLSearchParams = currentParams(),
  scope?: string,
): string {
  const next = new URLSearchParams(params);
  next.delete("id");
  next.set("trace_src", src);
  next.set("trace_dst", dst);
  if (scope) next.set("trace_scope", scope);
  else next.delete("trace_scope");
  return pageURL("map", next);
}

/** Device links retain the selected time and other navigation context. */
export function deviceURL(
  deviceId: string,
  params: URLSearchParams = currentParams(),
): string {
  const next = new URLSearchParams(params);
  next.delete("trace_src");
  next.delete("trace_dst");
  next.delete("trace_scope");
  if (next.has("window") && !next.has("earliest")) {
    next.set("earliest", next.get("window")!);
    if (!next.has("latest")) next.set("latest", "now");
  }
  next.delete("window");
  next.set("id", deviceId);
  return pageURL("device", next);
}

const navigate = (href: string) => location.assign(href);

export const MAX_TRACE_SUGGESTIONS = 100;

/**
 * Trace endpoint suggestions from nodes already on the page: the selected node
 * first, then node addresses and names. No search is issued.
 */
export function traceSuggestions(
  nodes: readonly Pick<GraphNode, "id" | "label" | "addresses">[],
  selectedId?: string,
  limit = MAX_TRACE_SUGGESTIONS,
): string[] {
  const selected = nodes.find((node) => node.id === selectedId);
  const ordered = selected
    ? [selected, ...nodes.filter((node) => node !== selected)]
    : nodes;
  const out = new Set<string>();
  for (const node of ordered)
    for (const value of [...(node.addresses ?? []), node.label]) {
      if (out.size >= limit) return [...out];
      if (isSafeIdentifier(value)) out.add(value);
    }
  return [...out];
}

/** Source → destination trace request (IP or name). */
export function TracePathForm({
  onSubmit = (src, dst, scope) =>
    navigate(traceURL(src, dst, currentParams(), scope)),
  initial,
  compact = false,
  live = false,
  suggestions = [],
  client,
}: {
  onSubmit?: (src: string, dst: string, scope?: string) => void;
  initial?: { src: string; dst: string; scope?: string };
  /** Map toolbar: no visible label. */
  compact?: boolean;
  /** Offer caller-visible mapped routing scopes instead of free text. */
  live?: boolean;
  /** Endpoint names or addresses already loaded on this page. */
  suggestions?: readonly string[];
  /** Live scope suggestions run as the caller through this client. */
  client?: SearchClient;
}) {
  const id = useId();
  const [src, setSrc] = useState(initial?.src ?? "");
  const [dst, setDst] = useState(initial?.dst ?? "");
  const [scope, setScope] = useState(initial?.scope ?? "");
  const scopes = useRoutingScopes(live);
  const valid = isSafeIdentifier(src.trim()) && isSafeIdentifier(dst.trim());
  const endpoint = {
    className: "atlas-input",
    spellCheck: false,
    scope,
    client,
    live,
    local: suggestions,
  } as const;
  return (
    <form
      className={`atlas-tool ${compact ? "compact" : ""}`}
      aria-label="Trace path"
      onSubmit={(event) => {
        event.preventDefault();
        if (valid) onSubmit(src.trim(), dst.trim(), scope.trim() || undefined);
      }}
    >
      <label htmlFor={`${id}-src`} className={compact ? "sr-only" : undefined}>
        Trace
      </label>
      <EndpointCombobox
        {...endpoint}
        id={`${id}-src`}
        wrapperClassName="atlas-trace-src"
        aria-label="Trace source"
        placeholder="Source IP or name"
        value={src}
        onChange={setSrc}
      />
      <span className="atlas-trace-arrow" aria-hidden="true">
        →
      </span>
      <EndpointCombobox
        {...endpoint}
        wrapperClassName="atlas-trace-dst"
        aria-label="Trace destination"
        placeholder="Destination"
        value={dst}
        onChange={setDst}
      />
      <button className="atlas-button" type="submit" disabled={!valid}>
        Trace
      </button>
      <RoutingScopeSelect
        compact
        className="atlas-trace-scope"
        value={scope}
        onChange={setScope}
        state={scopes}
      />
    </form>
  );
}

/** Device lookup by name, IP, serial or DN. */
export function DeviceLookup({
  onSelect = (deviceId) => navigate(deviceURL(deviceId)),
  initial = "",
  suggestions = [],
}: {
  onSelect?: (deviceId: string) => void;
  initial?: string;
  /** Devices already loaded on this page; no search is issued. */
  suggestions?: readonly SuggestOption[];
}) {
  const id = useId();
  const [value, setValue] = useState(initial);
  const valid = isSafeIdentifier(value.trim());
  return (
    <form
      className="atlas-tool"
      aria-label="Device lookup"
      onSubmit={(event) => {
        event.preventDefault();
        if (valid) onSelect(value.trim());
      }}
    >
      <label htmlFor={id}>Device</label>
      <SuggestCombobox
        id={id}
        className="atlas-input"
        aria-label="Device name or ID"
        placeholder="Name, IP, serial or DN"
        spellCheck={false}
        value={value}
        onChange={setValue}
        options={filterSuggestOptions(suggestions, value)}
      />
      <button className="atlas-button" type="submit" disabled={!valid}>
        Open
      </button>
    </form>
  );
}

const EXPLORE_TABS = [
  ["applications", "Applications"],
  ["endpoints", "Endpoints"],
  ["migration", "Move groups"],
] as const;
const ENDPOINT_KEYS = [
  "endpoint_ip",
  "endpoint_scope",
  "endpoint_start",
  "endpoint_end",
];

/** Explore views share one header; endpoint links keep only endpoint state. */
export function ExploreTabs({
  active,
}: {
  /** Undefined on pages reached from Explore, such as a device. */
  active?: (typeof EXPLORE_TABS)[number][0];
}) {
  const params = currentParams();
  return (
    <nav className="atlas-tabs" aria-label="Explore">
      {EXPLORE_TABS.map(([page, label]) => (
        <a
          key={page}
          href={pageURL(
            page,
            page === "endpoints"
              ? new URLSearchParams(
                  [...params].filter(([key]) => ENDPOINT_KEYS.includes(key)),
                )
              : new URLSearchParams(
                  [...params].filter(([key]) => !ENDPOINT_KEYS.includes(key)),
                ),
          )}
          aria-current={active === page ? "page" : undefined}
        >
          {label}
        </a>
      ))}
    </nav>
  );
}
