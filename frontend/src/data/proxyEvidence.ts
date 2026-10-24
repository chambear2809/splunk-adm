import type { Row } from "../rows";
import {
  EVIDENCE_LIMITS,
  isObject,
  literal,
  normalizeIp,
  routingScope,
  validateSelection,
  type EvidenceSelection,
  type EvidenceWindow,
} from "./evidence";
import { indexNames } from "./deploymentHealth";
import { type SupplementalSourceConfiguration } from "./evidenceConfig";

export const PROXY_SCHEMA = "application_atlas.envoy_http_access.v1";
export const PROXY_SOURCETYPE = "atlas:proxy:envoy_access";
/** Bound source-time lookback for requests that began before the selected interval. */
export const PROXY_START_LOOKBACK_SECONDS = EVIDENCE_LIMITS.window;

export const PROXY_COVERAGE = [
  "Each displayed record is one Envoy HTTP stream's DownstreamEnd access log, not a packet-flow record.",
  "The downstream direct peer is the adjacent transport peer; it is not an original client identity inferred through NAT or another proxy.",
  "The upstream remote address is the selected upstream endpoint for this exchange. Cluster membership and retry candidates are not reconstructed.",
  "X-Forwarded-For is not queried or used. Shared proxies, concurrent streams, reused tuples and records from other observers are never joined heuristically.",
  "Missing source records do not prove that traffic did not pass through the proxy; source coverage, clock parsing, index delay and configured access-log filters must be qualified.",
];

export interface ProxyAddress {
  ip: string;
  port?: number;
}

export interface ProxyObservation {
  schemaVersion: 1;
  source: "proxy_envoy";
  schema: typeof PROXY_SCHEMA;
  scope: string;
  routingAuthority: string;
  observer: string;
  index: string;
  eventFingerprint: string;
  eventTime: number;
  indexedTime: number;
  /** Envoy stream ID is retained as a reference only; it is never used to join records. */
  streamId?: string;
  durationMilliseconds?: number;
  durationBasis: "request_start_to_last_byte_out";
  downstream: {
    directPeer: ProxyAddress;
    listener?: ProxyAddress;
  };
  upstream?: {
    local?: ProxyAddress;
    remote?: ProxyAddress;
    cluster?: string;
  };
  /** This is present only when Envoy supplied an IP in UPSTREAM_REMOTE_ADDRESS. */
  selectedBackend?: ProxyAddress;
  routeName?: string;
  responseCode?: number;
  responseFlags?: string;
  upstreamAttemptCount?: number;
  matchedSelectionLegs: Array<
    "downstream_direct_peer" | "upstream_selected_endpoint"
  >;
  limitations: string[];
}

const SOURCE = "proxy_envoy" as const;
const OBSERVER_KIND = "envoy_proxy";
const INPUT_LIMIT = EVIDENCE_LIMITS.input;
const OUTPUT_LIMIT = EVIDENCE_LIMITS.records;
const RECORD_BYTES = EVIDENCE_LIMITS.recordBytes;

function checkedIndexes(config: SupplementalSourceConfiguration): string[] {
  const definition =
    config.indexes.length === 1
      ? `index=${config.indexes[0]}`
      : `(${config.indexes.map((value) => `index=${value}`).join(" OR ")})`;
  const indexes = indexNames({
    name: "adm_index_proxy_envoy",
    definition,
  });
  if (
    !indexes.length ||
    indexes.length > 16 ||
    indexes.length !== config.indexes.length ||
    new Set(indexes).size !== indexes.length
  )
    throw new Error("Envoy proxy index configuration is invalid.");
  return indexes;
}

function verifiedAuthorities(
  config: SupplementalSourceConfiguration,
  selection: EvidenceSelection,
): string[] {
  if (
    !Array.isArray(config.authorities) ||
    !config.authorities.length ||
    config.authorities.length > 32 ||
    !Array.isArray(config.mappings)
  )
    throw new Error("Envoy proxy observer mapping is unavailable.");
  const authorities = config.authorities.map((authority) => {
    literal(authority);
    return authority;
  });
  if (new Set(authorities).size !== authorities.length)
    throw new Error("Envoy proxy observers are ambiguous.");
  for (const authority of authorities) {
    const mappings = config.mappings.filter(
      (mapping) =>
        mapping.observer_kind === OBSERVER_KIND &&
        mapping.observer === authority,
    );
    if (
      mappings.length !== 1 ||
      mappings[0].scope !== selection.scope ||
      mappings[0].mapping_status !== "verified"
    )
      throw new Error("Envoy proxy observer scope is not uniquely verified.");
    routingScope(mappings[0].scope);
  }
  return authorities;
}

function assertConfiguration(
  config: SupplementalSourceConfiguration,
  selection: EvidenceSelection,
): { indexes: string[]; authorities: string[] } {
  validateSelection(selection);
  if (
    config.source !== SOURCE ||
    config.state !== "active" ||
    config.error ||
    config.schemaQualified !== true ||
    !Number.isFinite(config.staleAfterSeconds) ||
    config.staleAfterSeconds < 60 ||
    config.staleAfterSeconds > EVIDENCE_LIMITS.window
  )
    throw new Error("Envoy proxy evidence is not active and schema-qualified.");
  return {
    indexes: checkedIndexes(config),
    authorities: verifiedAuthorities(config, selection),
  };
}

function jsonField(name: string): string {
  return `json_extract(_raw,"${name}")`;
}

function exactIpPredicate(field: string, addresses: readonly string[]): string {
  const allowedFields = ["downstream_direct_remote_ip", "upstream_remote_ip"];
  if (
    !allowedFields.includes(field) ||
    !addresses.length ||
    addresses.length > 8
  )
    throw new Error("Invalid Envoy proxy endpoint filter.");
  return addresses
    .map((value) => normalizeIp(value))
    .map((ip) =>
      ip.includes(":")
        ? `cidrmatch("${ip}/128",${jsonField(field)})`
        : `(cidrmatch("${ip}/32",${jsonField(field)}) OR cidrmatch("::ffff:${ip}/128",${jsonField(field)}))`,
    )
    .join(" OR ");
}

function projectedProxyRecord(): string {
  const keys = [
    "schema",
    "routing_authority",
    "observer_id",
    "access_log_type",
    "stream_id",
    "start_time",
    "duration_ms",
    "downstream_direct_remote_ip",
    "downstream_direct_remote_port",
    "downstream_direct_local_ip",
    "downstream_direct_local_port",
    "upstream_local_ip",
    "upstream_local_port",
    "upstream_remote_ip",
    "upstream_remote_port",
    "upstream_cluster",
    "route_name",
    "response_code",
    "response_flags",
    "upstream_attempt_count",
  ];
  return `json_object(${keys.flatMap((key) => [`"${key}"`, jsonField(key)]).join(",")})`;
}

function searchWindowPredicate(selection: EvidenceSelection): string {
  const start = selection.window.start;
  const end = selection.window.end;
  const eventStart = `tonumber(${jsonField("start_time")})`;
  const durationSeconds = `(coalesce(tonumber(${jsonField("duration_ms")}),0)/1000)`;
  return `${eventStart}<${end} AND (${eventStart}+${durationSeconds})>=${start}`;
}

/** Build a bounded SPL projection for the selected Envoy v1.40 access-log contract. */
export function buildProxySearch(
  config: SupplementalSourceConfiguration,
  input: EvidenceSelection,
): string {
  const selection = validateSelection(input);
  const { indexes, authorities } = assertConfiguration(config, selection);
  const indexFilter = indexes.map((name) => `index=${name}`).join(" OR ");
  const indexClause = indexes.length === 1 ? indexFilter : `(${indexFilter})`;
  const authorityFilter = authorities
    .map((authority) => `"${literal(authority)}"`)
    .join(",");
  const matchedEndpoint = [
    exactIpPredicate("downstream_direct_remote_ip", selection.addresses),
    exactIpPredicate("upstream_remote_ip", selection.addresses),
  ].join(" OR ");
  const projected = projectedProxyRecord();
  return `search ${indexClause} sourcetype="${PROXY_SOURCETYPE}" host IN (${authorityFilter})
| where ${jsonField("schema")}="${PROXY_SCHEMA}" AND ${jsonField("access_log_type")}="DownstreamEnd" AND ${jsonField("routing_authority")}="${literal(selection.scope)}" AND ${jsonField("observer_id")}=host AND (${searchWindowPredicate(selection)}) AND (${matchedEndpoint})
| head ${INPUT_LIMIT + 1}
| eval event_time_epoch=tonumber(_time),event_fingerprint=if(isnotnull(_bkt) AND isnotnull(_cd),sha256(json_array(index,_bkt,_cd)),null()),oversized=if(len(_raw)>${RECORD_BYTES},1,0)
| eventstats count AS input_count sum(oversized) AS oversized_count
| sort 0 - _time index event_fingerprint
| head ${OUTPUT_LIMIT}
| eval _raw=if(oversized=1,"{}",${projected})
| fields _raw _time event_time_epoch _indextime host index event_fingerprint oversized input_count oversized_count
| eval kind="supplemental_record"
| appendpipe [| stats count AS returned_count max(input_count) AS input_count max(oversized_count) AS oversized
  | eval kind="supplemental_completion",schema_version=1,input_count=coalesce(input_count,0),input_capped=if(input_count>${INPUT_LIMIT},1,0),oversized=coalesce(oversized,0)]`;
}

function first(value: unknown): unknown {
  return Array.isArray(value) ? value[0] : value;
}

function text(value: unknown, max = 1024): string | undefined {
  value = first(value);
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > max ||
    value === "-" ||
    Array.from(value).some(
      (character) =>
        character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127,
    )
  )
    return undefined;
  return value;
}

function numberValue(value: unknown): number | undefined {
  value = first(value);
  if (value === null || value === undefined || value === "" || value === "-")
    return undefined;
  if (typeof value !== "number" && typeof value !== "string") return;
  if (typeof value === "string" && !/^-?\d+(?:\.\d+)?$/.test(value)) return;
  const n = Number(value);
  return Number.isFinite(n) ? n : undefined;
}

function requiredNumber(value: unknown): number | undefined {
  const n = numberValue(value);
  return n !== undefined && n >= 0 ? n : undefined;
}

function projectedEventTime(value: unknown): number | undefined {
  value = first(value);
  if (
    (typeof value !== "number" && typeof value !== "string") ||
    (typeof value === "string" && !/^\d{1,12}(?:\.\d{1,9})?$/.test(value))
  )
    return undefined;
  const epoch = Number(value);
  return Number.isFinite(epoch) && epoch >= 0 && epoch <= 253402300799
    ? epoch
    : undefined;
}

function optionalPort(value: unknown): number | undefined | null {
  if (value === null || value === undefined || value === "" || value === "-")
    return undefined;
  const port = numberValue(value);
  if (port === undefined || !Number.isInteger(port) || port < 0 || port > 65535)
    return null;
  return port;
}

function ip(value: unknown): string | undefined | null {
  value = first(value);
  if (value === null || value === undefined || value === "" || value === "-")
    return undefined;
  if (typeof value !== "string") return null;
  try {
    return normalizeIp(value);
  } catch {
    // Envoy can report non-IP internal addresses. They are not backend IPs.
    return undefined;
  }
}

function rawObject(row: Row): Record<string, unknown> | undefined {
  const raw = first(row._raw);
  if (isObject(raw)) return raw;
  if (typeof raw !== "string" || raw.length > RECORD_BYTES) return;
  try {
    const parsed: unknown = JSON.parse(raw);
    return isObject(parsed) ? parsed : undefined;
  } catch {
    return;
  }
}

function sourceTime(value: unknown): number | undefined {
  const raw = text(value, 32);
  if (!raw || !/^\d{9,12}(?:\.\d{1,9})?$/.test(raw)) return;
  const epoch = Number(raw);
  return Number.isFinite(epoch) && epoch >= 0 && epoch <= 253402300799
    ? epoch
    : undefined;
}

function canonicalPort(value: unknown): number | undefined | null {
  return optionalPort(value);
}

function address(
  addressValue: unknown,
  portValue: unknown,
): ProxyAddress | undefined | null {
  const normalizedIp = ip(addressValue);
  if (normalizedIp === null) return null;
  if (normalizedIp === undefined) return undefined;
  const port = canonicalPort(portValue);
  if (port === null) return null;
  return port === undefined ? { ip: normalizedIp } : { ip: normalizedIp, port };
}

function verifiedRowAuthority(
  observer: string,
  config: SupplementalSourceConfiguration,
  scope: string,
): boolean {
  const mappings = config.mappings.filter(
    (mapping) =>
      mapping.observer_kind === OBSERVER_KIND && mapping.observer === observer,
  );
  return (
    config.authorities.includes(observer) &&
    mappings.length === 1 &&
    mappings[0].scope === scope &&
    mappings[0].mapping_status === "verified"
  );
}

/** Strictly normalize the projected event; no XFF, tuple joins or payload fields are consumed. */
export function normalizeProxyEvidence(
  rows: readonly Row[],
  input: EvidenceSelection,
  config: SupplementalSourceConfiguration,
): { records: ProxyObservation[]; rejected: number } {
  const selection = validateSelection(input);
  assertConfiguration(config, selection);
  if (rows.length > INPUT_LIMIT)
    throw new Error(
      "Envoy proxy normalizer input exceeds its bounded row limit.",
    );
  const selected = new Set(selection.addresses.map(normalizeIp));
  const records: ProxyObservation[] = [];
  let rejected = 0;
  for (const row of rows) {
    const raw = rawObject(row);
    const index = text(row.index, 128);
    const host = text(row.host, 255);
    const eventFingerprint = text(row.event_fingerprint, 64);
    const observer = text(raw?.observer_id, 255);
    const scope = text(raw?.routing_authority, 253);
    const startTime = sourceTime(raw?.start_time);
    const indexedTime = requiredNumber(row._indextime);
    const rowTime = projectedEventTime(row.event_time_epoch);
    if (
      Number(row.oversized) === 1 ||
      !raw ||
      index === undefined ||
      !config.indexes.includes(index) ||
      host === undefined ||
      observer !== host ||
      !verifiedRowAuthority(observer, config, selection.scope) ||
      scope !== selection.scope ||
      raw.schema !== PROXY_SCHEMA ||
      raw.access_log_type !== "DownstreamEnd" ||
      eventFingerprint === undefined ||
      !/^[a-f0-9]{64}$/.test(eventFingerprint) ||
      startTime === undefined ||
      rowTime === undefined ||
      indexedTime === undefined ||
      Math.abs(startTime - rowTime) > 1 ||
      startTime <
        Math.max(0, selection.window.start - PROXY_START_LOOKBACK_SECONDS) ||
      startTime >= selection.window.end
    ) {
      rejected++;
      continue;
    }
    const directPeer = address(
      raw.downstream_direct_remote_ip,
      raw.downstream_direct_remote_port,
    );
    const listener = address(
      raw.downstream_direct_local_ip,
      raw.downstream_direct_local_port,
    );
    const upstreamLocal = address(
      raw.upstream_local_ip,
      raw.upstream_local_port,
    );
    const upstreamRemote = address(
      raw.upstream_remote_ip,
      raw.upstream_remote_port,
    );
    if (
      directPeer === undefined ||
      directPeer === null ||
      listener === null ||
      upstreamLocal === null ||
      upstreamRemote === null
    ) {
      rejected++;
      continue;
    }
    const matchedSelectionLegs: ProxyObservation["matchedSelectionLegs"] = [];
    if (selected.has(directPeer.ip))
      matchedSelectionLegs.push("downstream_direct_peer");
    if (upstreamRemote && selected.has(upstreamRemote.ip))
      matchedSelectionLegs.push("upstream_selected_endpoint");
    if (!matchedSelectionLegs.length) {
      rejected++;
      continue;
    }
    const durationMilliseconds = numberValue(raw.duration_ms);
    if (
      durationMilliseconds !== undefined &&
      (durationMilliseconds < 0 || durationMilliseconds > 31_536_000_000)
    ) {
      rejected++;
      continue;
    }
    const eventEnd = startTime + (durationMilliseconds ?? 0) / 1000;
    if (eventEnd < selection.window.start) {
      rejected++;
      continue;
    }
    const responseCode = numberValue(raw.response_code);
    if (
      responseCode !== undefined &&
      (!Number.isInteger(responseCode) ||
        responseCode < 0 ||
        responseCode > 599)
    ) {
      rejected++;
      continue;
    }
    const upstreamAttemptCount = numberValue(raw.upstream_attempt_count);
    if (
      upstreamAttemptCount !== undefined &&
      (!Number.isInteger(upstreamAttemptCount) ||
        upstreamAttemptCount < 0 ||
        upstreamAttemptCount > 10000)
    ) {
      rejected++;
      continue;
    }
    const streamId = text(raw.stream_id, 255);
    const upstreamCluster = text(raw.upstream_cluster, 255);
    const routeName = text(raw.route_name, 255);
    const responseFlags = text(raw.response_flags, 255);
    const upstream =
      upstreamLocal || upstreamRemote || upstreamCluster
        ? {
            ...(upstreamLocal ? { local: upstreamLocal } : {}),
            ...(upstreamRemote ? { remote: upstreamRemote } : {}),
            ...(upstreamCluster ? { cluster: upstreamCluster } : {}),
          }
        : undefined;
    const limitations = [
      "The downstream peer is the direct adjacent transport peer, not an XFF-derived original client.",
      "The upstream endpoint is Envoy's selected remote address for this exchange; configured cluster membership is not shown.",
      "Stream IDs and matching endpoint addresses are not used to join this record to another event or transport leg.",
    ];
    if (!streamId) limitations.push("Envoy did not provide a stream ID.");
    if (!upstreamRemote)
      limitations.push("Envoy did not provide a selected upstream remote IP.");
    if (upstreamAttemptCount !== undefined && upstreamAttemptCount > 1)
      limitations.push(
        "Retries are summarized; retry candidates are not available in this record.",
      );
    records.push({
      schemaVersion: 1,
      source: SOURCE,
      schema: PROXY_SCHEMA,
      scope: selection.scope,
      routingAuthority: scope,
      observer,
      index,
      eventFingerprint,
      eventTime: startTime,
      indexedTime,
      ...(streamId ? { streamId } : {}),
      ...(durationMilliseconds !== undefined ? { durationMilliseconds } : {}),
      durationBasis: "request_start_to_last_byte_out",
      downstream: {
        directPeer,
        ...(listener ? { listener } : {}),
      },
      ...(upstream ? { upstream } : {}),
      ...(upstreamRemote ? { selectedBackend: upstreamRemote } : {}),
      ...(routeName ? { routeName } : {}),
      ...(responseCode !== undefined ? { responseCode } : {}),
      ...(responseFlags ? { responseFlags } : {}),
      ...(upstreamAttemptCount !== undefined ? { upstreamAttemptCount } : {}),
      matchedSelectionLegs,
      limitations,
    });
  }
  return { records, rejected };
}

export function proxySearchWindow(
  selection: EvidenceSelection,
): EvidenceWindow {
  validateSelection(selection);
  const start = Math.max(
    0,
    selection.window.start - PROXY_START_LOOKBACK_SECONDS,
  );
  return { start, end: selection.window.end };
}
