import { argError } from "../provider";
import { isSafeTime } from "../data/timeBounds";
import type { GraphArgs } from "../rows";
import type { DemoScenario } from "../data/demoClient";

export const PAGES = [
  "applications",
  "map",
  "endpoints",
  "data_health",
  "setup",
  "help",
  "device",
  "impact",
] as const;
export type Page = (typeof PAGES)[number];
/** Top-level navigation sections; each owns one or more Splunk views. */
export type Section = "explore" | "map" | "admin" | "help";
export const SECTION_OF: Record<Page, Section> = {
  applications: "explore",
  endpoints: "explore",
  device: "explore",
  impact: "explore",
  map: "map",
  setup: "admin",
  data_health: "admin",
  help: "help",
};
/** Friendly aliases resolve to the Splunk view that renders the section. */
const PAGE_ALIASES: Record<string, Page> = {
  explore: "applications",
  admin: "setup",
};
/** Endpoint, device and trace identifiers: a name, IPv4/IPv6 or DN-like path. */
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/@[\]-]{0,254}$/;
export const isSafeIdentifier = (value: string) => IDENTIFIER.test(value);
export type UrlState = {
  args: GraphArgs;
  earliest: string;
  latest: string;
  mode: "demo" | "live";
  scenario: DemoScenario;
  tab: "network" | "services" | "devices" | "table";
  query: string;
  /** Requested source → destination trace (Map `trace_src` / `trace_dst`). */
  trace?: { src: string; dst: string };
  /** Device lookup target (Device page `id`). */
  device?: string;
  appd?: {
    applicationId: string;
    snapshotId: string;
    snapshotAt: string;
    authority: string;
    scope: string;
  };
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
  const raw = match?.[1];
  if (raw === "dependency_map") return raw;
  const name = (raw && PAGE_ALIASES[raw]) ?? raw;
  if (!PAGES.includes(name as Page))
    throw new Error("Unsupported Application Atlas page.");
  return name as Page;
}

export function parseUrlState(
  params: URLSearchParams,
  inSplunk = false,
): UrlState {
  // Demo data ships only with the development server; the packaged app
  // ignores ?mode=demo and always reads live searches.
  // Impact's mode=fails|depends is a view choice, not a data mode.
  const rawMode = params.get("mode");
  const mode = __ADM_SPLUNK_BUILD__
    ? "live"
    : ((rawMode === "fails" || rawMode === "depends" ? null : rawMode) ??
      (inSplunk ? "live" : "demo"));
  const args =
    mode === "live"
      ? { service: "", environment: "", cluster: "", namespace: "" }
      : { ...defaults };
  for (const key of Object.keys(args) as (keyof GraphArgs)[]) {
    const value = params.get(key) ?? args[key];
    const error =
      mode === "live" && value === "" ? undefined : argError(key, value);
    if (error) throw new Error(error);
    args[key] = value;
  }
  const earliest = params.get("earliest") ?? "-15m";
  const latest = params.get("latest") ?? "now";
  if (!isSafeTime(earliest) || !isSafeTime(latest))
    throw new Error("Unsupported time window.");
  if (
    /^\d+(?:\.\d+)?$/.test(earliest) &&
    /^\d+(?:\.\d+)?$/.test(latest) &&
    Number(earliest) >= Number(latest)
  )
    throw new Error("Earliest must precede latest.");
  const scenario = params.get("scenario") ?? "aci";
  const tab = params.get("tab") ?? "network";
  if (mode !== "demo" && mode !== "live")
    throw new Error("Unsupported data mode.");
  if (
    scenario !== "aci" &&
    scenario !== "nxos" &&
    scenario !== "catalyst-aci" &&
    scenario !== "meraki-nxos"
  )
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
  const appdValues = [
    params.get("appd_app"),
    params.get("appd_snapshot"),
    params.get("appd_at"),
    params.get("appd_authority"),
    params.get("appd_scope"),
  ];
  if (
    appdValues.some((value) => value !== null) &&
    (appdValues.some((value) => value === null) ||
      !/^[0-9]{1,20}$/.test(appdValues[0] ?? "") ||
      !/^[A-Za-z0-9_-]{1,128}$/.test(appdValues[1] ?? "") ||
      !/^\d+(?:\.\d+)?$/.test(appdValues[2] ?? "") ||
      Number(appdValues[2]) > 253402300799 ||
      !/^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,254}$/.test(appdValues[3] ?? "") ||
      !/^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,252}$/.test(appdValues[4] ?? "") ||
      /^(unmapped|unknown|reserved)(:|$)/i.test(appdValues[4] ?? ""))
  )
    throw new Error("Invalid Controller snapshot link.");
  const traceSrc = params.get("trace_src");
  const traceDst = params.get("trace_dst");
  if (
    (traceSrc !== null || traceDst !== null) &&
    (!isSafeIdentifier(traceSrc ?? "") || !isSafeIdentifier(traceDst ?? ""))
  )
    throw new Error("Invalid trace endpoints.");
  // `id` is shared with other views' deep links; only a safe value is a device.
  const rawDevice = params.get("id");
  const device =
    rawDevice !== null && isSafeIdentifier(rawDevice) ? rawDevice : undefined;
  const appd = appdValues[0]
    ? {
        applicationId: appdValues[0],
        snapshotId: appdValues[1]!,
        snapshotAt: appdValues[2]!,
        authority: appdValues[3]!,
        scope: appdValues[4]!,
      }
    : undefined;
  return {
    ...(appd ? { appd } : {}),
    ...(traceSrc && traceDst
      ? { trace: { src: traceSrc, dst: traceDst } }
      : {}),
    ...(device ? { device } : {}),
    args,
    earliest,
    latest,
    mode,
    scenario,
    tab: tab as UrlState["tab"],
    query,
  };
}

/** Recover a user-entered deep link; persisted/shared state still uses strict parsing. */
export function recoverUrlState(params: URLSearchParams, inSplunk = false) {
  const clean = new URLSearchParams(params);
  const dropped: string[] = [];
  for (const key of [
    "mode",
    "service",
    "environment",
    "cluster",
    "namespace",
    "earliest",
    "latest",
    "scenario",
    "tab",
    "q",
  ]) {
    if (!clean.has(key)) continue;
    const probe = new URLSearchParams();
    if (key !== "mode" && clean.has("mode"))
      probe.set("mode", clean.get("mode")!);
    probe.set(key, clean.get(key)!);
    try {
      parseUrlState(probe, inSplunk);
    } catch {
      clean.delete(key);
      dropped.push(key);
    }
  }
  if (
    [
      "appd_app",
      "appd_snapshot",
      "appd_at",
      "appd_authority",
      "appd_scope",
    ].some((key) => clean.has(key))
  ) {
    try {
      const probe = new URLSearchParams();
      for (const key of [
        "appd_app",
        "appd_snapshot",
        "appd_at",
        "appd_authority",
        "appd_scope",
      ]) {
        const value = clean.get(key);
        if (value !== null) probe.set(key, value);
      }
      parseUrlState(probe, inSplunk);
    } catch {
      for (const key of [
        "appd_app",
        "appd_snapshot",
        "appd_at",
        "appd_authority",
        "appd_scope",
      ]) {
        clean.delete(key);
        dropped.push(key);
      }
    }
  }
  if (clean.has("trace_src") || clean.has("trace_dst")) {
    const probe = new URLSearchParams();
    for (const key of ["trace_src", "trace_dst"]) {
      const value = clean.get(key);
      if (value !== null) probe.set(key, value);
    }
    try {
      parseUrlState(probe, inSplunk);
    } catch {
      for (const key of ["trace_src", "trace_dst"]) {
        clean.delete(key);
        dropped.push(key);
      }
    }
  }
  try {
    parseUrlState(clean, inSplunk);
  } catch {
    // Individually valid absolute bounds can still be reversed as a pair.
    for (const key of ["earliest", "latest"]) {
      clean.delete(key);
      dropped.push(key);
    }
  }
  return {
    state: parseUrlState(clean, inSplunk),
    notice: dropped.length
      ? `Some link parameters were invalid and were reset: ${[...new Set(dropped)].join(", ")}.`
      : undefined,
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
  if (state.trace) {
    params.set("trace_src", state.trace.src);
    params.set("trace_dst", state.trace.dst);
  }
  if (state.device) params.set("id", state.device);
  if (state.appd) {
    params.set("appd_app", state.appd.applicationId);
    params.set("appd_snapshot", state.appd.snapshotId);
    params.set("appd_at", state.appd.snapshotAt);
    params.set("appd_authority", state.appd.authority);
    params.set("appd_scope", state.appd.scope);
  }
  parseUrlState(params);
  return params;
}

export const URL_STATE_CHANGED = "atlas:url-state-changed";

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
      "appd_app",
      "appd_snapshot",
      "appd_at",
      "appd_authority",
      "appd_scope",
      "trace_src",
      "trace_dst",
    ])
      params.delete(key);
    stateParams(state).forEach((value, key) => params.set(key, value));
    history.replaceState(
      null,
      "",
      `${location.pathname}?${params}${location.hash}`,
    );
    window.dispatchEvent(new Event(URL_STATE_CHANGED));
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
  const query = params.toString();
  return `${base}${page}${query ? `?${query}` : ""}`;
}
