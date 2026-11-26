import { argError } from "../provider";
import { validVmScope } from "../graph";
import { isSafeTime } from "../data/timeBounds";
import type { GraphArgs } from "../rows";
import type { DemoScenario } from "../data/demoClient";
import type { Facets, FocusDirection } from "../filters";

export const PAGES = [
  "applications",
  "cases",
  "map",
  "endpoints",
  "multicast",
  "data_health",
  "setup",
  "help",
  "device",
  "impact",
  "migration",
] as const;
export type Page = (typeof PAGES)[number];
/** Top-level navigation sections; each owns one or more Splunk views. */
export type Section =
  "explore" | "cases" | "map" | "multicast" | "admin" | "help";
export const SECTION_OF: Record<Page, Section> = {
  applications: "explore",
  cases: "cases",
  endpoints: "explore",
  multicast: "multicast",
  device: "explore",
  impact: "explore",
  migration: "explore",
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
  facets?: Facets;
  focus?: { id: string; hops: number; direction: FocusDirection };
  /** Requested source → destination trace (Map `trace_src` / `trace_dst`). */
  trace?: { src: string; dst: string; scope?: string };
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
  const vmScope = params.get("vm_scope");
  const args =
    mode === "live"
      ? {
          service: "",
          environment: "",
          cluster: "",
          namespace: "",
          ...(vmScope ? { vmScope } : {}),
        }
      : { ...defaults };
  for (const key of [
    "service",
    "environment",
    "cluster",
    "namespace",
  ] as const) {
    const value = params.get(key) ?? args[key];
    const error =
      mode === "live" && value === "" ? undefined : argError(key, value);
    if (error) throw new Error(error);
    args[key] = value;
  }
  if (vmScope !== null) {
    if (mode !== "live" || !validVmScope(vmScope))
      throw new Error("Invalid VM scope.");
    if (args.cluster || args.namespace)
      throw new Error("VM scope cannot be combined with a Kubernetes scope.");
    if (!args.service || !args.environment)
      throw new Error("VM scope requires a service and environment.");
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
  if (vmScope !== null) {
    if (!/^\d+$/.test(earliest) || !/^\d+$/.test(latest))
      throw new Error("VM scope requires absolute time bounds.");
    const seconds = Number(latest) - Number(earliest);
    if (!(seconds > 0 && seconds <= 300))
      throw new Error("VM scope requires a window of at most 300 seconds.");
  }
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
  const identity = params.get("facet_identity");
  if (
    identity !== null &&
    identity !== "identified" &&
    identity !== "external" &&
    identity !== "unknown"
  )
    throw new Error("Unsupported identity filter.");
  const portRaw = params.get("facet_port");
  if (
    portRaw !== null &&
    (!/^[1-9]\d{0,4}$/.test(portRaw) || Number(portRaw) > 65535)
  )
    throw new Error("Unsupported port filter.");
  const source = params.get("facet_source");
  if (source !== null && !isSafeIdentifier(source))
    throw new Error("Unsupported source filter.");
  const flag = (key: string) => {
    const value = params.get(key);
    if (value === null) return undefined;
    if (value !== "1") throw new Error(`Unsupported ${key} filter.`);
    return true;
  };
  const blocked = flag("facet_blocked");
  const hideInfrastructure = flag("facet_hide_infra");
  const hideInferred = flag("facet_hide_inferred");
  const facets: Facets | undefined =
    identity ||
    portRaw ||
    source ||
    blocked ||
    hideInfrastructure ||
    hideInferred
      ? {
          ...(identity ? { identity } : {}),
          ...(portRaw ? { port: Number(portRaw) } : {}),
          ...(source ? { source } : {}),
          ...(blocked ? { blocked } : {}),
          ...(hideInfrastructure ? { hideInfrastructure } : {}),
          ...(hideInferred ? { hideInferred } : {}),
        }
      : undefined;
  const focusId = params.get("focus_id");
  const focusHops = params.get("focus_hops");
  const focusDir = params.get("focus_dir");
  if (
    (focusId !== null || focusHops !== null || focusDir !== null) &&
    (!isSafeIdentifier(focusId ?? "") ||
      !/^[1-3]$/.test(focusHops ?? "") ||
      (focusDir !== null &&
        focusDir !== "any" &&
        focusDir !== "callers" &&
        focusDir !== "dependencies"))
  )
    throw new Error("Invalid focus selection.");
  const focus =
    focusId && focusHops
      ? {
          id: focusId,
          hops: Number(focusHops),
          direction: (focusDir ?? "any") as FocusDirection,
        }
      : undefined;
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
  const traceScope = params.get("trace_scope");
  if (
    (traceSrc !== null || traceDst !== null) &&
    (!isSafeIdentifier(traceSrc ?? "") || !isSafeIdentifier(traceDst ?? ""))
  )
    throw new Error("Invalid trace endpoints.");
  if (
    traceScope !== null &&
    (!/^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}$/.test(traceScope) ||
      /^unmapped:/i.test(traceScope))
  )
    throw new Error("Invalid trace scope.");
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
      ? {
          trace: {
            src: traceSrc,
            dst: traceDst,
            ...(traceScope ? { scope: traceScope } : {}),
          },
        }
      : {}),
    ...(device ? { device } : {}),
    ...(facets ? { facets } : {}),
    ...(focus ? { focus } : {}),
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
    "facet_identity",
    "facet_port",
    "facet_source",
    "facet_blocked",
    "facet_hide_infra",
    "facet_hide_inferred",
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
  if (
    clean.has("trace_src") ||
    clean.has("trace_dst") ||
    clean.has("trace_scope")
  ) {
    const probe = new URLSearchParams();
    for (const key of ["trace_src", "trace_dst", "trace_scope"]) {
      const value = clean.get(key);
      if (value !== null) probe.set(key, value);
    }
    try {
      parseUrlState(probe, inSplunk);
    } catch {
      for (const key of ["trace_src", "trace_dst", "trace_scope"]) {
        clean.delete(key);
        dropped.push(key);
      }
    }
  }
  if (
    clean.has("focus_id") ||
    clean.has("focus_hops") ||
    clean.has("focus_dir")
  ) {
    const probe = new URLSearchParams();
    for (const key of ["focus_id", "focus_hops", "focus_dir"]) {
      const value = clean.get(key);
      if (value !== null) probe.set(key, value);
    }
    try {
      parseUrlState(probe, inSplunk);
    } catch {
      for (const key of ["focus_id", "focus_hops", "focus_dir"]) {
        clean.delete(key);
        dropped.push(key);
      }
    }
  }
  if (clean.has("vm_scope")) {
    try {
      parseUrlState(clean, inSplunk);
    } catch {
      for (const key of ["vm_scope", "cluster", "namespace"]) {
        if (!clean.has(key)) continue;
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
    service: state.args.service,
    environment: state.args.environment,
    cluster: state.args.cluster,
    namespace: state.args.namespace,
    earliest: state.earliest,
    latest: state.latest,
    mode: state.mode,
    scenario: state.scenario,
    tab: state.tab,
  });
  if (state.args.vmScope) params.set("vm_scope", state.args.vmScope);
  if (state.query) params.set("q", state.query);
  if (state.facets?.identity)
    params.set("facet_identity", state.facets.identity);
  if (state.facets?.port !== undefined)
    params.set("facet_port", String(state.facets.port));
  if (state.facets?.source) params.set("facet_source", state.facets.source);
  if (state.facets?.blocked) params.set("facet_blocked", "1");
  if (state.facets?.hideInfrastructure) params.set("facet_hide_infra", "1");
  if (state.facets?.hideInferred) params.set("facet_hide_inferred", "1");
  if (state.focus) {
    params.set("focus_id", state.focus.id);
    params.set("focus_hops", String(state.focus.hops));
    if (state.focus.direction !== "any")
      params.set("focus_dir", state.focus.direction);
  }
  if (state.trace) {
    params.set("trace_src", state.trace.src);
    params.set("trace_dst", state.trace.dst);
    if (state.trace.scope) params.set("trace_scope", state.trace.scope);
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
      "vm_scope",
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
      "trace_scope",
      "facet_identity",
      "facet_port",
      "facet_source",
      "facet_blocked",
      "facet_hide_infra",
      "facet_hide_inferred",
      "focus_id",
      "focus_hops",
      "focus_dir",
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
  const safePath = pathname.startsWith("//")
    ? `/${pathname.replace(/^\/+/, "")}`
    : pathname;
  const match = /^(.*\/app\/splunk_adm\/)[^/]+\/?$/.exec(safePath);
  const base = match?.[1] ?? "/";
  const query = params.toString();
  return `${base}${page}${query ? `?${query}` : ""}`;
}
