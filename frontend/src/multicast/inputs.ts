import { validateIndexName } from "../data/deploymentHealth";
import { isObject } from "../data/evidence";
import {
  MAX_PROFILES,
  MAX_WINDOW_SECONDS,
  MULTICAST_VERSION,
  type MulticastProfile,
  type MulticastRequest,
  type ScopeWindow,
  type Segment,
} from "./contract";

const ipv4 = (value: unknown): value is string =>
  typeof value === "string" &&
  /^(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}$/.exec(value)?.[0] ===
    value &&
  value.split(".").every((octet) => Number(octet) <= 255);

export function groupAddress(value: unknown): string | undefined {
  if (!ipv4(value)) return;
  const first = Number(value.split(".")[0]);
  if (first >= 224 && first <= 239) return value;
}

export function sourceAddress(value: unknown): string | undefined {
  if (!ipv4(value)) return;
  const first = Number(value.split(".")[0]);
  if (first > 0 && first < 224 && first !== 127) return value;
}

function selector(value: unknown, max = 128): value is string {
  return (
    typeof value === "string" &&
    value.length <= max &&
    /^[A-Za-z0-9][A-Za-z0-9._:/@-]*$/.exec(value)?.[0] === value
  );
}

export function scopeName(value: unknown): string | undefined {
  if (selector(value) && !/^(unmapped|unknown|reserved|none)(:|$)/i.test(value))
    return value;
}

function epoch(value: unknown): value is number {
  return (
    typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value > 0 &&
    value <= 253402300799
  );
}

function pastWindow(
  value: Record<string, unknown>,
  now: number,
): { earliest: number; latest: number } {
  const { earliest, latest } = value;
  if (
    !epoch(earliest) ||
    !epoch(latest) ||
    earliest >= latest ||
    latest > now ||
    latest - earliest > MAX_WINDOW_SECONDS
  )
    throw new Error("Choose a past time window of up to one hour.");
  return { earliest, latest };
}

/** The scope-wide equivalent of validateRequest, without group and sender. */
export function validateScopeWindow(
  value: unknown,
  now = Date.now() / 1000,
): ScopeWindow {
  if (!isObject(value) || value.version !== MULTICAST_VERSION)
    throw new Error("Unsupported multicast investigation version.");
  const scope = scopeName(value.scope);
  if (!scope) throw new Error("Choose one verified routing scope.");
  return { version: MULTICAST_VERSION, scope, ...pastWindow(value, now) };
}

export function validateRequest(
  request: unknown,
  now = Date.now() / 1000,
): MulticastRequest {
  if (!isObject(request) || request.version !== MULTICAST_VERSION)
    throw new Error("Unsupported multicast investigation version.");
  const scope = scopeName(request.scope);
  if (!scope) throw new Error("Choose one verified routing scope.");
  const group = groupAddress(request.group);
  if (!group) throw new Error("Enter one IPv4 multicast group (224.0.0.0/4).");
  const sender = sourceAddress(request.sender);
  if (request.sender !== undefined && !sender)
    throw new Error("Enter one unicast IPv4 sender address.");
  const { earliest, latest } = pastWindow(request, now);
  return {
    version: MULTICAST_VERSION,
    scope,
    group,
    ...(sender ? { sender } : {}),
    earliest,
    latest,
  };
}

const LINK_KEYS = [
  "mc_v",
  "mc_scope",
  "mc_group",
  "mc_sender",
  "mc_earliest",
  "mc_latest",
  "mc_view",
] as const;

export type MulticastView = "overview" | "matrix" | "topology";
const VIEWS: readonly MulticastView[] = ["overview", "matrix", "topology"];
const UNSUPPORTED = "The multicast link contains unsupported parameters.";

/** True when the link carries multicast parameters, which are then all checked. */
function checkLink(params: URLSearchParams): boolean {
  if (![...params.keys()].some((key) => key.startsWith("mc_"))) return false;
  if (
    LINK_KEYS.some((key) => params.getAll(key).length > 1) ||
    [...params.keys()].some(
      (key) =>
        key.startsWith("mc_") && !LINK_KEYS.some((known) => known === key),
    )
  )
    throw new Error(UNSUPPORTED);
  parseMulticastView(params);
  return true;
}

function linkFields(params: URLSearchParams) {
  const time = (key: string) => {
    const value = params.get(key) ?? "";
    return /^[1-9][0-9]{0,11}$/.exec(value)?.[0] === value
      ? Number(value)
      : NaN;
  };
  return {
    version: params.get("mc_v") === "1" ? MULTICAST_VERSION : undefined,
    scope: params.get("mc_scope"),
    earliest: time("mc_earliest"),
    latest: time("mc_latest"),
  };
}

export function parseMulticastView(params: URLSearchParams): MulticastView {
  const values = params.getAll("mc_view");
  if (!values.length) return "overview";
  const view = VIEWS.find((known) => known === values[0]);
  if (values.length > 1 || !view) throw new Error(UNSUPPORTED);
  return view;
}

export function parseMulticastLink(
  params: URLSearchParams,
  now?: number,
): MulticastRequest | undefined {
  if (!checkLink(params)) return;
  return validateRequest(
    {
      ...linkFields(params),
      group: params.get("mc_group"),
      sender: params.get("mc_sender") ?? undefined,
    },
    now,
  );
}

/** The scope-wide link; a group, when present, is left to parseMulticastLink. */
export function parseScopeLink(
  params: URLSearchParams,
  now?: number,
): ScopeWindow | undefined {
  if (!checkLink(params)) return;
  return validateScopeWindow(linkFields(params), now);
}

export function scopeLink(
  window: ScopeWindow,
  view: MulticastView,
): URLSearchParams {
  const value = validateScopeWindow(window);
  if (!VIEWS.includes(view)) throw new Error(UNSUPPORTED);
  return new URLSearchParams({
    mc_v: String(value.version),
    mc_scope: value.scope,
    mc_earliest: String(value.earliest),
    mc_latest: String(value.latest),
    mc_view: view,
  });
}

export function multicastLink(request: MulticastRequest): URLSearchParams {
  const value = validateRequest(request);
  const params = new URLSearchParams({
    mc_v: String(value.version),
    mc_scope: value.scope,
    mc_group: value.group,
    mc_earliest: String(value.earliest),
    mc_latest: String(value.latest),
  });
  if (value.sender) params.set("mc_sender", value.sender);
  return params;
}

function uintString(value: unknown, max: number, min = 0): value is string {
  return (
    typeof value === "string" &&
    /^(?:0|[1-9][0-9]{0,9})$/.exec(value)?.[0] === value &&
    Number(value) >= min &&
    Number(value) <= max
  );
}

export function parseSegment(value: unknown): Segment | undefined {
  if (!isObject(value) || !selector(value.domain)) return;
  const { kind, id, domain } = value;
  if (
    (kind === "vlan" && uintString(id, 4094, 1)) ||
    (kind === "vni" && uintString(id, 16777215, 1)) ||
    (kind === "bridge-domain" && selector(id))
  )
    return { kind, id, domain };
}

function reporterAddresses(value: unknown): string[] {
  if (
    !Array.isArray(value) ||
    value.length > 64 ||
    !value.every(
      (address): address is string => sourceAddress(address) !== undefined,
    ) ||
    new Set(value).size !== value.length
  )
    throw new Error(
      "Configure up to 64 unique literal IPv4 reporter addresses.",
    );
  return [...value].sort();
}

export function parseProfile(value: unknown): MulticastProfile {
  if (!isObject(value)) throw new Error("Invalid multicast source profile.");
  const { id, index, observer, validFrom, validUntil } = value;
  const scope = scopeName(value.scope);
  if (
    !selector(id, 64) ||
    !scope ||
    typeof index !== "string" ||
    validateIndexName(index) ||
    !selector(observer) ||
    !epoch(validFrom) ||
    !epoch(validUntil) ||
    validFrom >= validUntil
  )
    throw new Error("Invalid multicast source selectors or validity interval.");
  const base = { id, index, observer, scope, validFrom, validUntil };
  if (value.source === "multicast_nxos")
    return { ...base, source: value.source };
  if (value.source === "multicast_igmp") {
    const { captureInterface, placement, v3Encoding } = value;
    const segment = parseSegment(value.segment);
    const endpointReporters = reporterAddresses(value.endpointReporters);
    const proxyReporters = reporterAddresses(value.proxyReporters);
    if (
      !selector(captureInterface) ||
      !segment ||
      (placement !== "endpoint" && placement !== "transit") ||
      (placement !== "endpoint" && endpointReporters.length > 0) ||
      endpointReporters.some((address) => proxyReporters.includes(address)) ||
      (v3Encoding !== "flat-counted" && v3Encoding !== "single-record")
    )
      throw new Error("Invalid IGMP capture or record profile.");
    return {
      ...base,
      source: value.source,
      captureInterface,
      segment,
      placement,
      endpointReporters,
      proxyReporters,
      v3Encoding,
    };
  }
  if (value.source === "multicast_netflow") {
    const {
      observationDomain,
      template,
      direction,
      samplingInterval,
      replication,
      counters,
    } = value;
    if (
      !sourceAddress(observer) ||
      !uintString(observationDomain, 4294967295) ||
      !uintString(template, 65535, 256) ||
      (direction !== "ingress" && direction !== "egress") ||
      typeof samplingInterval !== "number" ||
      !Number.isSafeInteger(samplingInterval) ||
      samplingInterval < 1 ||
      samplingInterval > 4294967295 ||
      (replication !== "before" &&
        replication !== "after" &&
        replication !== "unknown") ||
      (counters !== "delta" && counters !== "total")
    )
      throw new Error("Invalid multicast NetFlow exporter or counter profile.");
    return {
      ...base,
      source: value.source,
      observationDomain,
      template,
      direction,
      samplingInterval,
      replication,
      counters,
    };
  }
  throw new Error("Unsupported multicast source profile.");
}

function conflicts(left: MulticastProfile, right: MulticastProfile): boolean {
  if (
    left.id === right.id ||
    (left.scope !== right.scope &&
      left.scope.toLowerCase() === right.scope.toLowerCase())
  )
    return true;
  if (left.validFrom >= right.validUntil || right.validFrom >= left.validUntil)
    return false;
  if (left.source === "multicast_nxos" && right.source === "multicast_nxos")
    return left.scope === right.scope;
  if (left.observer.toLowerCase() !== right.observer.toLowerCase())
    return false;
  if (left.source === "multicast_igmp" && right.source === "multicast_igmp")
    return (
      left.captureInterface.toLowerCase() ===
      right.captureInterface.toLowerCase()
    );
  if (
    left.source === "multicast_netflow" &&
    right.source === "multicast_netflow"
  )
    return (
      left.observationDomain === right.observationDomain &&
      (left.scope !== right.scope ||
        (left.template === right.template &&
          left.direction === right.direction))
    );
  return false;
}

export function parseProfiles(value: unknown): MulticastProfile[] {
  if (value === undefined) return [];
  if (
    !isObject(value) ||
    value.version !== MULTICAST_VERSION ||
    !Array.isArray(value.profiles) ||
    value.profiles.length > MAX_PROFILES
  )
    throw new Error("Invalid multicast source configuration.");
  const profiles = value.profiles.map(parseProfile);
  if (
    profiles.some((left, i) =>
      profiles.slice(i + 1).some((right) => conflicts(left, right)),
    )
  )
    throw new Error(
      "Multicast source profiles have ambiguous or duplicate mappings.",
    );
  return profiles.sort((left, right) => left.id.localeCompare(right.id, "en"));
}
