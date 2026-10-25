import {
  literal,
  validText,
  validateServiceHealthSelection,
  type ServiceHealthSelection,
} from "./evidence";

export type O11yNavigationProduct =
  "apm" | "infrastructure" | "logs" | "detectors" | "incidents";

export interface O11yNavigationInput {
  selection: ServiceHealthSelection;
  realm: string;
  organizationId: string;
  /** Trusted tenant URL configured by an operator; must be an HTTPS origin. */
  configuredOrigin?: string;
  /** Exact MMS identity from a qualified health capture, copied as context only. */
  apmMmsId?: string;
  detectorIds?: string[];
  incidentIds?: string[];
}

export interface O11yNavigationAction {
  product: O11yNavigationProduct;
  title: string;
  location: string;
  instructions: string;
  searchHint?: string;
  ids: string[];
  href?: string;
  linkLabel: string;
}

export interface O11yNavigationModel {
  organizationId: string;
  realm: string;
  apmMmsId?: string;
  origin?: string;
  service: ServiceHealthSelection["service"];
  podUids: string[];
  startUtc: string;
  endUtc: string;
  detectorIds: string[];
  incidentIds: string[];
  copyText: string;
  actions: O11yNavigationAction[];
}

const REALM_PATTERN = /^[a-z][a-z0-9]{0,7}$/;
const MAX_NATIVE_IDS = 64;

/** Accept only an explicit HTTPS origin, never a route, credential, or query. */
export function configuredHttpsOrigin(value: string): string | undefined {
  if (!value || value !== value.trim()) return undefined;
  try {
    const url = new URL(value);
    if (
      url.protocol !== "https:" ||
      !url.hostname ||
      url.username ||
      url.password ||
      (url.pathname !== "" && url.pathname !== "/") ||
      url.search ||
      url.hash
    )
      return undefined;
    return url.origin;
  } catch {
    return undefined;
  }
}

/** Splunk's documented realm-based product UI origin on the current domain. */
export function observabilityRealmOrigin(realm: string): string | undefined {
  if (!REALM_PATTERN.test(realm)) return undefined;
  return `https://app.${realm}.observability.splunkcloud.com`;
}

function validateIds(ids: string[] | undefined, label: string): string[] {
  if (ids === undefined) return [];
  if (!Array.isArray(ids) || ids.length > MAX_NATIVE_IDS)
    throw new Error(`Invalid ${label} identifier list.`);
  return ids.map((id) => {
    if (!validText(id, 512)) throw new Error(`Invalid ${label} identifier.`);
    return id;
  });
}

function utc(seconds: number): string {
  return new Date(seconds * 1000).toISOString();
}

function contextText(input: {
  organizationId: string;
  realm: string;
  apmMmsId?: string;
  service: ServiceHealthSelection["service"];
  podUids: string[];
  startUtc: string;
  endUtc: string;
  detectorIds: string[];
  incidentIds: string[];
}): string {
  const lines = [
    `Organization: ${input.organizationId}`,
    `Realm: ${input.realm}`,
    `APM service: ${input.service.name}`,
    `Environment: ${input.service.environment}`,
    `Cluster: ${input.service.cluster}`,
    `Kubernetes namespace: ${input.service.namespace}`,
    `OTel service namespace: ${input.service.serviceNamespace ?? "not provided"}`,
    `Selected workload pod UIDs: ${input.podUids.length ? input.podUids.join(", ") : "not provided"}`,
    `APM MMS ID: ${input.apmMmsId ?? "not provided"}`,
    `Selected time window (UTC): ${input.startUtc} to ${input.endUtc}`,
    `Detector IDs: ${input.detectorIds.length ? input.detectorIds.join(", ") : "not provided"}`,
    `Incident IDs: ${input.incidentIds.length ? input.incidentIds.join(", ") : "not provided"}`,
  ];
  return lines.join("\n");
}

/**
 * Build manual product navigation. Links stop at the tenant home because the
 * product does not document stable public deep-link filters for this context.
 */
export function buildO11yNavigation(
  input: O11yNavigationInput,
): O11yNavigationModel {
  const selection = validateServiceHealthSelection(input.selection);
  const realm = literal(input.realm, 8);
  if (!REALM_PATTERN.test(realm))
    throw new Error("Invalid Observability Cloud realm.");
  const organizationId = literal(input.organizationId, 255);
  const apmMmsId =
    input.apmMmsId === undefined ? undefined : literal(input.apmMmsId, 255);
  const configuredOrigin =
    input.configuredOrigin === undefined
      ? undefined
      : configuredHttpsOrigin(input.configuredOrigin);
  const origin =
    input.configuredOrigin === undefined
      ? observabilityRealmOrigin(realm)
      : configuredOrigin;
  const detectorIds = validateIds(input.detectorIds, "detector");
  const incidentIds = validateIds(input.incidentIds, "incident");
  const startUtc = utc(selection.window.start);
  const endUtc = utc(selection.window.end);
  const href = origin ? `${origin}/` : undefined;
  const service = selection.service;
  const actions: O11yNavigationAction[] = [
    {
      product: "apm",
      title: "APM services",
      location: "APM → Overview → Services",
      instructions:
        "Use the documented global search prefix below, then verify environment, cluster, Kubernetes namespace and OTel service namespace as separate identity dimensions.",
      searchHint: `service: ${service.name}`,
      ids: [],
      href,
      linkLabel: "Open realm for APM",
    },
    {
      product: "infrastructure",
      title: "Infrastructure navigators",
      location: "Infrastructure → Infrastructure Catalog",
      instructions:
        "Choose the relevant navigator, such as Kubernetes, and manually apply the available cluster, namespace and service filters. Select the same time range in the product.",
      ids: [],
      href,
      linkLabel: "Open realm for infrastructure",
    },
    {
      product: "logs",
      title: "Logs",
      location: "Logs → Log Observer",
      instructions:
        "Select the matching time range and use fields that are present in your log data to find the service identity. Available fields depend on the connected log source.",
      ids: [],
      href,
      linkLabel: "Open realm for logs",
    },
    {
      product: "detectors",
      title: "Detectors and alerts",
      location: "Alerts → Detectors",
      instructions:
        "Use the top-bar global search with the documented detector prefix or open the detector list. Supplied detector IDs are shown for manual verification; this action does not open an ID-specific route.",
      searchHint: "detector: <detector name or substring>",
      ids: detectorIds,
      href,
      linkLabel: "Open realm for detectors",
    },
    {
      product: "incidents",
      title: "Incidents",
      location: "Incidents dashboard (if enabled for the organization)",
      instructions:
        "Use Entity and Environment filters with the selected time range. The documented incident table searches by incident name; supplied IDs remain available for manual lookup.",
      ids: incidentIds,
      href,
      linkLabel: "Open realm for incidents",
    },
  ];
  const copyInput = {
    organizationId,
    realm,
    apmMmsId,
    service,
    podUids: (selection.workloads ?? []).map((workload) => workload.podUid),
    startUtc,
    endUtc,
    detectorIds,
    incidentIds,
  };
  return {
    organizationId,
    realm,
    apmMmsId,
    origin,
    service,
    podUids: (selection.workloads ?? []).map((workload) => workload.podUid),
    startUtc,
    endUtc,
    detectorIds,
    incidentIds,
    copyText: contextText(copyInput),
    actions,
  };
}
