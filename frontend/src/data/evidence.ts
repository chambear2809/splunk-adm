import { strictIp } from "../drilldown";

export const EVIDENCE_LIMITS = {
  window: 86400,
  lookback: 3600,
  input: 10000,
  records: 64,
  answers: 64,
  aliases: 32,
  recordBytes: 1048576,
  contexts: 256,
  addresses: 8,
  peers: 100,
  relationships: 500,
} as const;
export type DnsSource = "dns_stream" | "dns_hubble";
export type SupplementalSource =
  | "proxy_envoy"
  | "aws_vpc_flow"
  | "asset_history"
  | "o11y_health"
  | "o11y_detector_events"
  | "appdynamics_inventory"
  | "thousandeyes";
export type OptionalSource = DnsSource | SupplementalSource;
export type EvidenceWindow = { start: number; end: number };
export interface TrafficContext {
  client: string;
  server: string;
  scope: string;
  first: number;
  last: number;
  timeBasis: "flow_observation" | "connection_open";
  clientOwner?: string;
  capped: boolean;
  serverPort?: number;
  transport?: string;
}
export interface EvidenceSelection {
  schemaVersion: 1;
  workflow: "endpoint" | "application";
  selectionId: string;
  trafficContract: 1 | 2;
  window: EvidenceWindow;
  scope: string;
  addresses: string[];
  /** Actual peer addresses included in selected graph identity revalidation. */
  identityAddresses?: string[];
  contexts: TrafficContext[];
  identityBasis: string;
  configurationFingerprint: string;
  /** Exact selected catalog boundary, never inferred from a display label. */
  application?: {
    service: string;
    environment: string;
    cluster: string;
    namespace: string;
  };
}
/** Exact service identity for optional health; namespace is the Kubernetes namespace. */
export interface ServiceHealthSelection {
  schemaVersion: 1;
  workflow: "service";
  selectionId: string;
  scope: string;
  window: EvidenceWindow;
  service: {
    name: string;
    environment: string;
    cluster: string;
    namespace: string;
    /** OTel service.namespace, independent of Kubernetes namespace. */
    serviceNamespace?: string;
  };
  workloads?: { podUid: string; validFrom: number; validTo?: number }[];
  identityBasis: string;
  configurationFingerprint: string;
}
export interface DnsObservation {
  schemaVersion: 1;
  source: DnsSource;
  authority: string;
  scope: string;
  client?: string;
  resolver?: string;
  query: string;
  comparisonName?: string;
  queryType: string;
  shape: "request" | "response" | "transaction";
  responseCode?: string;
  answers: { address: string; type: "A" | "AAAA"; ttl?: number }[];
  aliases: string[];
  reportedAddresses?: string[];
  reportedTtls?: number[];
  ttlSeconds?: number;
  ttlBasis?: "record" | "rrset_scalar";
  authorityNode?: string;
  requestStart?: number;
  sourceTimeBasis?: string;
  eventTime: number;
  rowTime?: number;
  indexedTime: number;
  responseInterval?: EvidenceWindow;
  latencySeconds?: number;
  transactionId?: string;
  duplicateId?: string;
  eventFingerprint: string;
  index: string;
  policy?: string;
  clientOwner?: string;
  limitations: string[];
  attribution: "context_only" | "scoped_client" | "compatible_observations";
  attributionReason: string;
}
export interface DnsSourceResult {
  source: DnsSource;
  intent?: "active" | "staged" | "not_selected";
  state: "not_selected" | "staged" | "complete" | "unavailable";
  inputCount: number;
  inputCapped: boolean;
  outputCapped: boolean;
  rejected: number;
  expansionCapped: number;
  durationMilliseconds?: number;
  errorCode?: "configuration" | "execution" | "completion" | "normalization";
  error?: string;
}
export interface DnsEvidenceResult {
  schemaVersion: 1;
  selection: EvidenceSelection;
  capturedAt: number;
  inspectedWindow: EvidenceWindow;
  configurationFingerprint: string;
  configurationChanged: boolean;
  sources: DnsSourceResult[];
  records: DnsObservation[];
  outputCapped: boolean;
  coverage: string[];
}
export const isObject = (value: unknown): value is Record<string, unknown> =>
  !!value && typeof value === "object" && !Array.isArray(value);
export function validText(value: unknown, max = 255): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= max &&
    !Array.from(value).some(
      (char) => char.charCodeAt(0) < 32 || char.charCodeAt(0) === 127,
    )
  );
}
export function literal(value: string, max = 255): string {
  if (!validText(value, max) || !/^[A-Za-z0-9][A-Za-z0-9._:/@-]*$/.test(value))
    throw new Error("Invalid literal evidence selector.");
  return value;
}
export function routingScope(value: string): string {
  literal(value, 253);
  if (/^(unmapped|unknown|reserved)(:|$)/i.test(value))
    throw new Error("Choose one verified routing scope.");
  return value;
}
/** Canonicalize all IP forms, including hexadecimal IPv4-mapped IPv6. */
export function normalizeIp(value: string): string {
  if (!strictIp(value))
    throw new Error("Use one literal IPv4 or IPv6 address.");
  if (!value.includes(":")) return value;
  const canonical = new URL(`http://[${value}]/`).hostname
    .slice(1, -1)
    .toLowerCase();
  const mapped = /^::ffff:([0-9a-f]+):([0-9a-f]+)$/.exec(canonical);
  if (mapped) {
    const hi = parseInt(mapped[1], 16),
      lo = parseInt(mapped[2], 16);
    return `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
  }
  return canonical;
}
/** Exact host-prefix matching accepts alternate IP encodings without raw-name search. */
export function scopedAddressPredicate(
  field: string,
  addresses: string[],
): string {
  if (
    ![
      "src_ip",
      "client_ip",
      "server_ip",
      "source_ip",
      "destination_ip",
      "'flow.IP.source'",
      "'flow.IP.destination'",
    ].includes(field) ||
    !addresses.length ||
    addresses.length > 8
  )
    throw new Error("Invalid scoped address predicate.");
  return addresses
    .map(normalizeIp)
    .map((ip) =>
      ip.includes(":")
        ? `cidrmatch("${ip}/128",${field})`
        : `(cidrmatch("${ip}/32",${field}) OR cidrmatch("::ffff:${ip}/128",${field}))`,
    )
    .join(" OR ");
}
export function validateWindow(value: EvidenceWindow): EvidenceWindow {
  if (
    !isObject(value) ||
    ![value.start, value.end].every(
      (n) =>
        typeof n === "number" &&
        Number.isFinite(n) &&
        n >= 0 &&
        n <= 253402300799,
    ) ||
    value.end <= value.start ||
    value.end - value.start > EVIDENCE_LIMITS.window
  )
    throw new Error(
      "Choose an evidence window greater than zero and at most 24 hours.",
    );
  return { start: value.start, end: value.end };
}
export function validateSelection(value: EvidenceSelection): EvidenceSelection {
  if (
    !isObject(value) ||
    value.schemaVersion !== 1 ||
    !["endpoint", "application"].includes(value.workflow) ||
    ![1, 2].includes(value.trafficContract) ||
    !validText(value.selectionId, 1024) ||
    !validText(value.identityBasis, 1024) ||
    !/^[a-f0-9]{64}$/.test(value.configurationFingerprint)
  )
    throw new Error("Invalid evidence selection contract.");
  validateWindow(value.window);
  routingScope(value.scope);
  if (value.application !== undefined) {
    if (!isObject(value.application))
      throw new Error("Invalid application evidence boundary.");
    for (const key of [
      "service",
      "environment",
      "cluster",
      "namespace",
    ] as const)
      literal(value.application[key]);
  }
  if (
    value.identityAddresses !== undefined &&
    (!Array.isArray(value.identityAddresses) ||
      value.identityAddresses.length > 16 ||
      value.identityAddresses.some((a) => normalizeIp(a) !== a) ||
      value.addresses.some((a) => !value.identityAddresses!.includes(a)))
  )
    throw new Error("Invalid scoped identity address selection.");
  if (
    !Array.isArray(value.addresses) ||
    value.addresses.length < 1 ||
    value.addresses.length > EVIDENCE_LIMITS.addresses ||
    value.addresses.some((a) => normalizeIp(a) !== a) ||
    !Array.isArray(value.contexts) ||
    value.contexts.length > EVIDENCE_LIMITS.contexts
  )
    throw new Error(
      "Narrow the evidence address or traffic context selection.",
    );
  for (const c of value.contexts) {
    if (
      !isObject(c) ||
      c.scope !== value.scope ||
      normalizeIp(c.client) !== c.client ||
      normalizeIp(c.server) !== c.server ||
      !Number.isFinite(c.first) ||
      !Number.isFinite(c.last) ||
      c.first < 0 ||
      c.last < c.first ||
      !["flow_observation", "connection_open"].includes(c.timeBasis) ||
      typeof c.capped !== "boolean" ||
      (c.serverPort !== undefined &&
        (!Number.isInteger(c.serverPort) ||
          c.serverPort < 1 ||
          c.serverPort > 65535)) ||
      (c.transport !== undefined &&
        (typeof c.transport !== "string" ||
          !/^[a-z][a-z0-9_-]{0,31}$/.test(c.transport)))
    )
      throw new Error("Invalid scoped traffic observation context.");
  }
  return value;
}
export function validateServiceHealthSelection(
  value: ServiceHealthSelection,
): ServiceHealthSelection {
  if (
    !isObject(value) ||
    value.schemaVersion !== 1 ||
    value.workflow !== "service" ||
    !validText(value.selectionId, 1024) ||
    !validText(value.identityBasis, 1024) ||
    !/^[a-f0-9]{64}$/.test(value.configurationFingerprint)
  )
    throw new Error("Invalid service health selection.");
  validateWindow(value.window);
  routingScope(value.scope);
  if (!isObject(value.service))
    throw new Error("Select one exact service identity.");
  for (const field of ["name", "environment", "cluster", "namespace"] as const)
    literal(value.service[field], 255);
  if (value.service.serviceNamespace !== undefined)
    literal(value.service.serviceNamespace, 255);
  if (
    value.workloads !== undefined &&
    (!Array.isArray(value.workloads) ||
      value.workloads.length > 64 ||
      value.workloads.some((workload) => {
        if (!isObject(workload)) return true;
        try {
          literal(workload.podUid, 255);
        } catch {
          return true;
        }
        return (
          !Number.isFinite(workload.validFrom) ||
          workload.validFrom < 0 ||
          (workload.validTo !== undefined &&
            (!Number.isFinite(workload.validTo) ||
              workload.validTo <= workload.validFrom))
        );
      }))
  )
    throw new Error("Invalid historical workload identity.");
  return value;
}
export async function fingerprint(value: unknown): Promise<string> {
  const bytes = new TextEncoder().encode(JSON.stringify(value));
  const hash = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(hash), (b) =>
    b.toString(16).padStart(2, "0"),
  ).join("");
}
export function validateDnsResult(value: DnsEvidenceResult): DnsEvidenceResult {
  const fail = () => {
    throw new Error("Invalid DNS result contract.");
  };
  const numeric = (n: unknown) =>
    typeof n === "number" && Number.isFinite(n) && n >= 0 && n <= 253402300799;
  const integer = (n: unknown, max: number) =>
    typeof n === "number" && Number.isSafeInteger(n) && n >= 0 && n <= max;
  const strings = (items: unknown, max: number, chars = 1024) =>
    Array.isArray(items) &&
    items.length <= max &&
    items.every((s) => validText(s, chars));
  if (!isObject(value) || !isObject(value.selection)) fail();
  validateSelection(value.selection);
  if (
    value.schemaVersion !== 1 ||
    !numeric(value.capturedAt) ||
    value.configurationFingerprint !==
      value.selection.configurationFingerprint ||
    typeof value.configurationChanged !== "boolean" ||
    typeof value.outputCapped !== "boolean" ||
    !Array.isArray(value.records) ||
    value.records.length > 64 ||
    !Array.isArray(value.sources) ||
    value.sources.length !== 2 ||
    new Set(value.sources.map((s) => s.source)).size !== 2 ||
    !strings(value.coverage, 32, 2048)
  )
    throw new Error("Invalid DNS result contract.");
  if (
    !isObject(value.inspectedWindow) ||
    !numeric(value.inspectedWindow.start) ||
    value.inspectedWindow.end !== value.selection.window.end ||
    value.inspectedWindow.start > value.selection.window.start ||
    value.selection.window.start - value.inspectedWindow.start > 86400
  )
    fail();
  for (const source of value.sources) {
    if (
      !isObject(source) ||
      !["dns_stream", "dns_hubble"].includes(source.source) ||
      !["complete", "unavailable", "staged", "not_selected"].includes(
        source.state,
      ) ||
      !integer(source.inputCount, 10001) ||
      !integer(source.rejected, source.inputCount) ||
      !integer(source.expansionCapped, Math.min(source.inputCount, 64)) ||
      typeof source.inputCapped !== "boolean" ||
      source.inputCapped !== source.inputCount > 10000 ||
      typeof source.outputCapped !== "boolean" ||
      (source.intent !== undefined &&
        !["active", "staged", "not_selected"].includes(source.intent)) ||
      (source.durationMilliseconds !== undefined &&
        !numeric(source.durationMilliseconds)) ||
      (source.errorCode !== undefined &&
        !["configuration", "execution", "completion", "normalization"].includes(
          source.errorCode,
        )) ||
      (source.error !== undefined && !validText(source.error, 1024)) ||
      (source.state !== "complete" &&
        (source.inputCount !== 0 ||
          source.rejected !== 0 ||
          source.expansionCapped !== 0 ||
          source.inputCapped ||
          source.outputCapped))
    )
      fail();
    if (
      value.records.filter((r) => r.source === source.source).length >
        Math.min(source.inputCount, 64) ||
      (source.outputCapped && !value.outputCapped)
    )
      fail();
  }
  for (const r of value.records) {
    const source = value.sources.find((s) => s.source === r.source);
    if (
      !isObject(r) ||
      r.schemaVersion !== 1 ||
      source?.state !== "complete" ||
      r.scope !== value.selection.scope ||
      !validText(r.query, 1024) ||
      !validText(r.queryType, 64) ||
      !validText(r.attributionReason, 2048) ||
      !validText(r.authority) ||
      !/^[a-f0-9]{64}$/.test(r.eventFingerprint) ||
      !numeric(r.eventTime) ||
      !numeric(r.indexedTime) ||
      (r.rowTime !== undefined && !numeric(r.rowTime)) ||
      !Array.isArray(r.answers) ||
      r.answers.length > 64 ||
      !strings(r.aliases, 32) ||
      !strings(r.limitations, 64, 2048) ||
      !["request", "response", "transaction"].includes(r.shape) ||
      !["context_only", "scoped_client", "compatible_observations"].includes(
        r.attribution,
      ) ||
      !/^[a-z][a-z0-9_-]{0,79}$/.test(r.index)
    )
      throw new Error("Invalid DNS observation contract.");
    for (const address of [r.client, r.resolver])
      if (address !== undefined && normalizeIp(address) !== address) fail();
    if (
      r.responseInterval &&
      (!isObject(r.responseInterval) ||
        !numeric(r.responseInterval.start) ||
        !numeric(r.responseInterval.end) ||
        r.responseInterval.end < r.responseInterval.start)
    )
      fail();
    for (const time of [r.requestStart, r.latencySeconds, r.ttlSeconds])
      if (time !== undefined && !numeric(time)) fail();
    if (
      r.ttlBasis !== undefined &&
      !["record", "rrset_scalar"].includes(r.ttlBasis)
    )
      fail();
    if (
      r.reportedTtls !== undefined &&
      (!Array.isArray(r.reportedTtls) ||
        r.reportedTtls.length > 64 ||
        r.reportedTtls.some((t) => !numeric(t)))
    )
      fail();
    if (
      r.reportedAddresses !== undefined &&
      (!Array.isArray(r.reportedAddresses) ||
        r.reportedAddresses.length > 64 ||
        r.reportedAddresses.some((a) => normalizeIp(a) !== a))
    )
      fail();
    for (const text of [
      r.responseCode,
      r.transactionId,
      r.duplicateId,
      r.policy,
      r.clientOwner,
      r.authorityNode,
      r.sourceTimeBasis,
    ])
      if (text !== undefined && !validText(text, 1024)) fail();
    if (
      (value.configurationChanged || source.inputCapped) &&
      r.attribution !== "context_only"
    )
      fail();
    r.answers.forEach((a) => {
      if (
        !isObject(a) ||
        normalizeIp(a.address) !== a.address ||
        !["A", "AAAA"].includes(a.type) ||
        (a.type === "A" && a.address.includes(":")) ||
        (a.type === "AAAA" && !a.address.includes(":")) ||
        (a.ttl !== undefined &&
          (!Number.isFinite(a.ttl) || a.ttl < 0 || a.ttl > 4294967295))
      )
        throw new Error("Invalid DNS answer.");
    });
  }
  return value;
}
