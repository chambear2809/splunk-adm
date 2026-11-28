import { validateIndexName } from "../data/deploymentHealth";
import { isObject } from "../data/evidence";
import {
  MAX_METRICS_WINDOW_SECONDS,
  MAX_PROFILES,
  MAX_WINDOW_SECONDS,
  PROTOCOL_LENS_IDS,
  PROTOCOL_VERSION,
  sourceForLens,
  type BaseProtocolProfile,
  type LensProfileValidator,
  type ProtocolFilter,
  type ProtocolLensId,
  type ProtocolRequest,
  type ProtocolViewMode,
  type ProtocolWindowMode,
} from "./shared/contract";

const SELECTOR = /^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}$/;
const ITEM_ID = /^[A-Za-z0-9][A-Za-z0-9._:/@[\]-]{0,191}$/;
/** Must stay within the `literal()` SPL quoting charset used by filterSpl. */
const FILTER_VALUE = /^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}$/;
const IFACE_NAME = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,63}$/;

export function isProtocolLensId(value: unknown): value is ProtocolLensId {
  return (
    typeof value === "string" &&
    (PROTOCOL_LENS_IDS as readonly string[]).includes(value)
  );
}

export function protocolSelector(value: unknown, max = 128): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= max &&
    SELECTOR.test(value)
  );
}

export function protocolScopeName(value: unknown): string | undefined {
  if (
    protocolSelector(value) &&
    !/^(unmapped|unknown|reserved|none)(:|$)/i.test(value)
  )
    return value;
}

export function protocolEpoch(value: unknown): value is number {
  return (
    typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value > 0 &&
    value <= 253402300799
  );
}

export function protocolItemId(value: unknown): value is string {
  return typeof value === "string" && ITEM_ID.test(value);
}

export function validVni(value: unknown): string | undefined {
  if (
    typeof value === "string" &&
    /^[1-9][0-9]{0,7}$/.test(value) &&
    Number(value) >= 1 &&
    Number(value) <= 16777215
  )
    return value;
}

export function validateProtocolWindow(
  earliest: unknown,
  latest: unknown,
  now = Date.now() / 1000,
  windowMode: ProtocolWindowMode = "events",
): { earliest: number; latest: number } {
  const maxSpan =
    windowMode === "metrics" ? MAX_METRICS_WINDOW_SECONDS : MAX_WINDOW_SECONDS;
  if (
    !protocolEpoch(earliest) ||
    !protocolEpoch(latest) ||
    earliest >= latest ||
    latest > now + 60 ||
    latest - earliest > maxSpan
  )
    throw new Error(
      windowMode === "metrics"
        ? "Choose a past UTC metrics window of up to 7 days."
        : "Choose a past UTC window of up to one hour.",
    );
  return { earliest, latest };
}

export function validateProtocolRequest(
  request: unknown,
  now = Date.now() / 1000,
): ProtocolRequest {
  if (!isObject(request) || request.version !== PROTOCOL_VERSION)
    throw new Error("Unsupported protocol investigation version.");
  if (!isProtocolLensId(request.lens))
    throw new Error("Unsupported protocol lens.");
  const scope = protocolScopeName(request.scope);
  if (!scope) throw new Error("Choose one verified routing scope.");
  const windowMode: ProtocolWindowMode =
    request.windowMode === "metrics" ? "metrics" : "events";
  const { earliest, latest } = validateProtocolWindow(
    request.earliest,
    request.latest,
    now,
    windowMode,
  );
  const filter = validateProtocolFilter(request.filter);
  return {
    version: PROTOCOL_VERSION,
    lens: request.lens,
    scope,
    earliest,
    latest,
    ...(windowMode === "metrics" ? { windowMode } : {}),
    ...(filter ? { filter } : {}),
  };
}

export function validPort(value: unknown): string | undefined {
  if (typeof value === "number") {
    if (!Number.isInteger(value) || value < 1 || value > 65535)
      return undefined;
    return String(value);
  }
  if (typeof value !== "string" || !/^[1-9][0-9]{0,4}$/.test(value.trim())) {
    return undefined;
  }
  const n = Number(value.trim());
  return n >= 1 && n <= 65535 ? String(n) : undefined;
}

export function validateProtocolFilter(
  value: unknown,
): ProtocolFilter | undefined {
  if (value === undefined) return undefined;
  if (!isObject(value)) throw new Error("Invalid protocol filter.");
  const filter: ProtocolFilter = {};
  for (const key of ["src", "dst", "device"] as const) {
    const raw = value[key];
    if (raw === undefined || raw === "") continue;
    const trimmed = typeof raw === "string" ? raw.trim() : raw;
    if (trimmed === "") continue;
    if (typeof trimmed !== "string" || !FILTER_VALUE.test(trimmed))
      throw new Error(`Invalid protocol ${key} filter.`);
    filter[key] = trimmed;
  }
  if (value.vni !== undefined && value.vni !== "") {
    const vni = validVni(
      typeof value.vni === "string" ? value.vni.trim() : value.vni,
    );
    if (!vni) throw new Error("VNI must be an integer between 1 and 16777215.");
    filter.vni = vni;
  }
  if (value.port !== undefined && value.port !== "") {
    const port = validPort(value.port);
    if (!port) throw new Error("Port must be an integer between 1 and 65535.");
    filter.port = port;
  }
  if (value.iface !== undefined && value.iface !== "") {
    const iface = typeof value.iface === "string" ? value.iface.trim() : "";
    if (!iface || !IFACE_NAME.test(iface))
      throw new Error("Invalid interface filter.");
    filter.iface = iface;
  }
  if (value.bidirectional === true) {
    filter.bidirectional = true;
  } else if (
    value.bidirectional !== undefined &&
    value.bidirectional !== false
  ) {
    throw new Error("Invalid bidirectional filter flag.");
  }
  return Object.keys(filter).length ? filter : undefined;
}

const LINK_KEYS = [
  "p_v",
  "p_lens",
  "p_scope",
  "p_earliest",
  "p_latest",
  "p_wmode",
  "p_view",
  "p_src",
  "p_dst",
  "p_device",
  "p_vni",
  "p_port",
  "p_bidir",
  "p_iface",
  "p_item",
] as const;

const VIEWS: readonly ProtocolViewMode[] = ["overview", "matrix"];
const WINDOW_MODES: readonly ProtocolWindowMode[] = ["events", "metrics"];
const UNSUPPORTED_LINK = "The protocols link contains unsupported parameters.";

export interface ParsedProtocolLink {
  lens?: ProtocolLensId;
  scope?: string;
  earliest?: number;
  latest?: number;
  windowMode?: ProtocolWindowMode;
  view: ProtocolViewMode;
  filter?: ProtocolFilter;
  item?: string;
}

export function parseProtocolView(params: URLSearchParams): ProtocolViewMode {
  const values = params.getAll("p_view");
  if (!values.length) return "overview";
  const view = VIEWS.find((known) => known === values[0]);
  if (values.length > 1 || !view) throw new Error(UNSUPPORTED_LINK);
  return view;
}

export function parseProtocolLink(
  params: URLSearchParams,
  now = Date.now() / 1000,
): ParsedProtocolLink {
  const keys = [...params.keys()].filter((key) => key.startsWith("p_"));
  if (!keys.length) return { view: "overview" };
  if (
    LINK_KEYS.some((key) => params.getAll(key).length > 1) ||
    keys.some((key) => !LINK_KEYS.some((known) => known === key))
  )
    throw new Error(UNSUPPORTED_LINK);
  const versionRaw = params.get("p_v");
  if (versionRaw !== null && versionRaw !== String(PROTOCOL_VERSION))
    throw new Error(UNSUPPORTED_LINK);
  const rawLens = params.get("p_lens");
  if (rawLens !== null && !isProtocolLensId(rawLens))
    throw new Error(UNSUPPORTED_LINK);
  const rawScope = params.get("p_scope");
  const scope = rawScope === null ? undefined : protocolScopeName(rawScope);
  if (rawScope !== null && !scope) throw new Error(UNSUPPORTED_LINK);
  const parseTime = (key: string) => {
    const raw = params.get(key);
    if (raw === null) return undefined;
    return /^[1-9][0-9]{0,11}$/.test(raw) ? Number(raw) : NaN;
  };
  const rawWmode = params.get("p_wmode");
  if (
    rawWmode !== null &&
    !WINDOW_MODES.includes(rawWmode as ProtocolWindowMode)
  )
    throw new Error(UNSUPPORTED_LINK);
  const windowMode: ProtocolWindowMode | undefined =
    rawWmode === "metrics" ? "metrics" : undefined;
  const earliest = parseTime("p_earliest");
  const latest = parseTime("p_latest");
  if (earliest !== undefined || latest !== undefined) {
    validateProtocolWindow(earliest, latest, now, windowMode ?? "events");
  }
  const view = parseProtocolView(params);
  const rawBidir = params.get("p_bidir");
  if (rawBidir !== null && rawBidir !== "1" && rawBidir !== "0")
    throw new Error(UNSUPPORTED_LINK);
  const filter = validateProtocolFilter({
    src: params.get("p_src") ?? undefined,
    dst: params.get("p_dst") ?? undefined,
    device: params.get("p_device") ?? undefined,
    vni: params.get("p_vni") ?? undefined,
    port: params.get("p_port") ?? undefined,
    iface: params.get("p_iface") ?? undefined,
    ...(rawBidir === "1" ? { bidirectional: true } : {}),
  });
  const rawItem = params.get("p_item");
  if (rawItem !== null && !ITEM_ID.test(rawItem))
    throw new Error(UNSUPPORTED_LINK);
  return {
    ...(rawLens ? { lens: rawLens } : {}),
    ...(scope ? { scope } : {}),
    ...(earliest !== undefined ? { earliest } : {}),
    ...(latest !== undefined ? { latest } : {}),
    ...(windowMode ? { windowMode } : {}),
    view,
    ...(filter ? { filter } : {}),
    ...(rawItem ? { item: rawItem } : {}),
  };
}

export function protocolLink(
  input: ParsedProtocolLink,
  now = Date.now() / 1000,
): URLSearchParams {
  const params = new URLSearchParams();
  params.set("p_v", String(PROTOCOL_VERSION));
  if (input.lens) {
    if (!isProtocolLensId(input.lens)) throw new Error(UNSUPPORTED_LINK);
    params.set("p_lens", input.lens);
  }
  if (input.scope) {
    const scope = protocolScopeName(input.scope);
    if (!scope) throw new Error("Choose one verified routing scope.");
    params.set("p_scope", scope);
  }
  const windowMode: ProtocolWindowMode =
    input.windowMode === "metrics" ? "metrics" : "events";
  if (
    input.windowMode !== undefined &&
    !WINDOW_MODES.includes(input.windowMode)
  )
    throw new Error(UNSUPPORTED_LINK);
  if (windowMode === "metrics") params.set("p_wmode", "metrics");
  if (input.earliest !== undefined || input.latest !== undefined) {
    const win = validateProtocolWindow(
      input.earliest,
      input.latest,
      now,
      windowMode,
    );
    params.set("p_earliest", String(win.earliest));
    params.set("p_latest", String(win.latest));
  }
  if (!VIEWS.includes(input.view)) throw new Error(UNSUPPORTED_LINK);
  if (input.view !== "overview") params.set("p_view", input.view);
  const filter = validateProtocolFilter(input.filter);
  if (filter?.src) params.set("p_src", filter.src);
  if (filter?.dst) params.set("p_dst", filter.dst);
  if (filter?.device) params.set("p_device", filter.device);
  if (filter?.vni) params.set("p_vni", filter.vni);
  if (filter?.port) params.set("p_port", filter.port);
  if (filter?.iface) params.set("p_iface", filter.iface);
  if (filter?.bidirectional) params.set("p_bidir", "1");
  if (input.item) {
    if (!ITEM_ID.test(input.item)) throw new Error(UNSUPPORTED_LINK);
    params.set("p_item", input.item);
  }
  return params;
}

export function parseProtocolProfile(
  value: unknown,
  validators: Partial<Record<ProtocolLensId, LensProfileValidator>> = {},
): BaseProtocolProfile {
  if (!isObject(value)) throw new Error("Invalid protocol source profile.");
  const { id, source, lens, index, observer, validFrom, validUntil, extra } =
    value;
  if (!isProtocolLensId(lens))
    throw new Error("Unsupported protocol lens in profile.");
  const expectedSource = sourceForLens(lens);
  if (source !== expectedSource)
    throw new Error("Protocol profile source does not match lens.");
  const scope = protocolScopeName(value.scope);
  if (
    !protocolSelector(id, 64) ||
    !scope ||
    typeof index !== "string" ||
    validateIndexName(index) ||
    !protocolSelector(observer) ||
    !protocolEpoch(validFrom) ||
    !protocolEpoch(validUntil) ||
    validFrom >= validUntil
  )
    throw new Error("Invalid protocol source selectors or validity interval.");
  if (extra !== undefined && !isObject(extra))
    throw new Error("Protocol profile extra configuration must be an object.");
  const base: Omit<BaseProtocolProfile, "extra"> = {
    id,
    source: expectedSource,
    lens,
    scope,
    index,
    observer,
    validFrom,
    validUntil,
  };
  const validator = validators[lens];
  let validatedExtra: Record<string, unknown> | undefined;
  if (validator) {
    validatedExtra = validator(
      extra as Record<string, unknown> | undefined,
      base,
    );
  } else if (extra !== undefined && Object.keys(extra).length > 0) {
    throw new Error(
      `Protocol profile "${id}" contains unvalidated extra configuration for lens "${lens}".`,
    );
  }
  return {
    ...base,
    ...(validatedExtra ? { extra: validatedExtra } : {}),
  };
}

const SOURCE_SELECTOR_KEYS = [
  "sourcetype",
  "sourceKind",
  "sourcetypes",
  "sources",
] as const;

/** Stable key for the event selection a profile adds on top of its index. */
function profileSourceSelector(profile: BaseProtocolProfile): string {
  const extra = profile.extra ?? {};
  return JSON.stringify(
    SOURCE_SELECTOR_KEYS.map((key) => {
      const value = extra[key];
      if (typeof value === "string") return value.toLowerCase();
      if (Array.isArray(value) && value.every((v) => typeof v === "string"))
        return [...value].map((v) => v.toLowerCase()).sort();
      return value ?? null;
    }),
  );
}

function selectsEverything(profile: BaseProtocolProfile): boolean {
  const extra = profile.extra ?? {};
  return SOURCE_SELECTOR_KEYS.every(
    (key) =>
      extra[key] === undefined ||
      (key === "sourceKind" && extra.sourceKind === "auto"),
  );
}

function validityOverlaps(
  left: BaseProtocolProfile,
  right: BaseProtocolProfile,
): boolean {
  return left.validFrom < right.validUntil && right.validFrom < left.validUntil;
}

/** Same index and overlapping event selection: searches return the same events. */
function profilesReadSameEvents(
  left: BaseProtocolProfile,
  right: BaseProtocolProfile,
): boolean {
  return (
    left.lens === right.lens &&
    left.index === right.index &&
    validityOverlaps(left, right) &&
    (profileSourceSelector(left) === profileSourceSelector(right) ||
      selectsEverything(left) ||
      selectsEverything(right))
  );
}

function profileConflicts(
  left: BaseProtocolProfile,
  right: BaseProtocolProfile,
): boolean {
  if (left.id === right.id) return true;
  if (
    left.scope !== right.scope &&
    left.scope.toLowerCase() === right.scope.toLowerCase()
  )
    return true;
  if (!validityOverlaps(left, right)) return false;
  if (
    left.lens === right.lens &&
    left.scope === right.scope &&
    left.observer.toLowerCase() === right.observer.toLowerCase() &&
    left.index === right.index
  )
    return true;
  // Observer is not a search predicate, so two observers with an identical
  // selector on one index in one scope would run the same search twice.
  return (
    left.lens === right.lens &&
    left.scope === right.scope &&
    left.index === right.index &&
    profileSourceSelector(left) === profileSourceSelector(right)
  );
}

function annotateSharedIndexScopes(
  profiles: BaseProtocolProfile[],
): BaseProtocolProfile[] {
  return profiles.map((profile) => {
    const shared = [
      ...new Set(
        profiles
          .filter(
            (other) =>
              other.scope !== profile.scope &&
              profilesReadSameEvents(profile, other),
          )
          .map((other) => other.scope),
      ),
    ].sort((a, b) => a.localeCompare(b, "en"));
    return shared.length ? { ...profile, sharedIndexScopes: shared } : profile;
  });
}

/**
 * Fail-closed parser for `adm_protocol_profiles` active document.
 * Undefined document returns an empty profile list (lens searches disabled).
 */
export function parseProtocolProfiles(
  value: unknown,
  validators: Partial<Record<ProtocolLensId, LensProfileValidator>> = {},
): BaseProtocolProfile[] {
  if (value === undefined) return [];
  if (
    !isObject(value) ||
    value.version !== PROTOCOL_VERSION ||
    !Array.isArray(value.profiles) ||
    value.profiles.length > MAX_PROFILES
  )
    throw new Error("Invalid protocol source configuration.");
  const profiles = value.profiles.map((entry) =>
    parseProtocolProfile(entry, validators),
  );
  if (
    profiles.some((left, i) =>
      profiles.slice(i + 1).some((right) => profileConflicts(left, right)),
    )
  )
    throw new Error(
      "Protocol source profiles have ambiguous or duplicate mappings.",
    );
  return annotateSharedIndexScopes(profiles).sort((left, right) =>
    left.id.localeCompare(right.id, "en"),
  );
}
