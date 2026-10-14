import { argError } from "../provider";
import { isSafeTime } from "../data/timeBounds";
import type { GraphArgs } from "../rows";

export const PAGES = [
  "applications",
  "map",
  "data_health",
  "setup",
  "help",
] as const;
export type Page = (typeof PAGES)[number];
export type UrlState = {
  args: GraphArgs;
  earliest: string;
  latest: string;
  mode: "demo" | "live";
  scenario: "aci" | "nxos";
  tab: "network" | "services" | "devices" | "table";
  query: string;
};
const defaults: GraphArgs = {
  service: "frontend",
  environment: "demo",
  cluster: "demo-cluster",
  namespace: "shop",
};

/** Reject unknown views before starting any search or rendering a page. */
export function pageFromPath(pathname: string): Page | "dependency_map" {
  const match = /^\/(?:[^/]+\/)*app\/splunk_adm\/([^/]+)\/?$/.exec(pathname);
  const name = match?.[1];
  if (name === "dependency_map") return name;
  if (!PAGES.includes(name as Page))
    throw new Error("Unsupported Application Atlas page.");
  return name as Page;
}

export function parseUrlState(
  params: URLSearchParams,
  inSplunk = false,
): UrlState {
  const args = { ...defaults };
  for (const key of Object.keys(args) as (keyof GraphArgs)[]) {
    const value = params.get(key) ?? args[key];
    const error = argError(key, value);
    if (error) throw new Error(error);
    args[key] = value;
  }
  const earliest = params.get("earliest") ?? "-1h";
  const latest = params.get("latest") ?? "now";
  if (!isSafeTime(earliest) || !isSafeTime(latest))
    throw new Error("Unsupported time window.");
  if (
    /^\d+(?:\.\d+)?$/.test(earliest) &&
    /^\d+(?:\.\d+)?$/.test(latest) &&
    Number(earliest) >= Number(latest)
  )
    throw new Error("Earliest must precede latest.");
  const mode = params.get("mode") ?? (inSplunk ? "live" : "demo");
  const scenario = params.get("scenario") ?? "aci";
  const tab = params.get("tab") ?? "network";
  if (mode !== "demo" && mode !== "live")
    throw new Error("Unsupported data mode.");
  if (scenario !== "aci" && scenario !== "nxos")
    throw new Error("Unsupported demo scenario.");
  if (!["network", "services", "devices", "table"].includes(tab))
    throw new Error("Unsupported map view.");
  const query = params.get("q") ?? "";
  if (
    query.length > 256 ||
    Array.from(query).some(
      (char) => char.charCodeAt(0) < 32 || char.charCodeAt(0) === 127,
    )
  )
    throw new Error("Invalid highlight query.");
  return {
    args,
    earliest,
    latest,
    mode,
    scenario,
    tab: tab as UrlState["tab"],
    query,
  };
}

export function stateParams(state: UrlState): URLSearchParams {
  const params = new URLSearchParams({
    ...state.args,
    earliest: state.earliest,
    latest: state.latest,
    mode: state.mode,
    scenario: state.scenario,
    tab: state.tab,
  });
  if (state.query) params.set("q", state.query);
  parseUrlState(params);
  return params;
}

export function writeUrlState(state: UrlState) {
  if (typeof window === "undefined") return;
  // Invalid text in a scope field stays in the form, never in a shared URL.
  try {
    const params = new URLSearchParams(location.search);
    for (const key of [
      "service",
      "environment",
      "cluster",
      "namespace",
      "earliest",
      "latest",
      "mode",
      "scenario",
      "tab",
      "q",
    ])
      params.delete(key);
    stateParams(state).forEach((value, key) => params.set(key, value));
    history.replaceState(
      null,
      "",
      `${location.pathname}?${params}${location.hash}`,
    );
  } catch {
    /* Form validation explains the invalid value. */
  }
}

export function pageURL(
  page: Page,
  params = new URLSearchParams(),
  pathname = typeof location === "undefined"
    ? "/app/splunk_adm/map"
    : location.pathname,
): string {
  const match = /^(.*\/app\/splunk_adm\/)[^/]+\/?$/.exec(pathname);
  const base = match?.[1] ?? "/";
  return `${base}${page}${params.size ? `?${params}` : ""}`;
}
