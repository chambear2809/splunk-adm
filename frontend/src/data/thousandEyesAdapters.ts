import type { Row } from "../rows";
import {
  isObject,
  normalizeIp,
  validateSelection,
  type EvidenceSelection,
} from "./evidence";
import type { SupplementalSourceConfiguration } from "./evidenceConfig";
import {
  THOUSANDEYES_SOURCE,
  THOUSANDEYES_ADAPTER_VERSION,
  thousandEyesAccountGroupId,
  thousandEyesMappings,
  thousandEyesNativeId,
  thousandEyesTarget,
  type ThousandEyesSourceMapping,
} from "./thousandEyesConfiguration";
import type {
  ThousandEyesFamily,
  ThousandEyesHop,
  ThousandEyesMeasurement,
  ThousandEyesObservation,
  ThousandEyesSpan,
  ThousandEyesTarget,
} from "./thousandEyesTypes";

const MAX_EPOCH = 253_402_300_799;
const MAX_NANOSECONDS = BigInt(MAX_EPOCH) * 1_000_000_000n;
const MAX_RAW_BYTES = 1_048_576;
const MAX_ADAPTER_OUTPUT = 64;
const SCHEMA_PATH = "application_atlas.thousandeyes_path.v1";
const VENDOR_STREAM_SOURCE = "cisco:thousandeyes:stream";
const VENDOR_WEBHOOK_SOURCE = "cisco:thousandeyes:webhook";
const VENDOR_PATH_SOURCETYPE = "cisco:thousandeyes:path-vis";
const ATLAS_PATH_SOURCE = "atlas:thousandeyes:path";
const ATLAS_PATH_SOURCETYPE = "atlas:thousandeyes:path";

const SOURCETYPES: Record<ThousandEyesFamily, string> = {
  metric: "cisco:thousandeyes:metric",
  trace: "cisco:thousandeyes:trace",
  activity: "cisco:thousandeyes:activity",
  event: "cisco:thousandeyes:event",
  alert: "cisco:thousandeyes:alerts",
  path: VENDOR_PATH_SOURCETYPE,
};

const METRIC_UNITS: Record<string, readonly string[]> = {
  "http.server.request.availability": ["%"],
  "http.server.request.throughput": ["By/s"],
  "http.server.request.duration": ["s"],
  "http.server.throughput": ["By/s"],
  "http.client.request.duration": ["s"],
  "network.latency": ["s"],
  "network.loss": ["%"],
  "network.jitter": ["ms"],
  "network.availability": ["%"],
  "network.throughput": ["By/s"],
  "network.device.disconnection.duration": ["s"],
  "network.device.disconnection.packets_lost": ["{count}"],
  "network.device.partial_disconnection.transitions": ["{count}"],
  "web.transaction.duration": ["s"],
  "web.transaction.completion": ["%"],
  "web.transaction.errors.count": ["{count}"],
  "dns.lookup.availability": ["%"],
  "dns.lookup.duration": ["s"],
  "dns.lookup.validity": ["%"],
  "web.page_load.completion": ["%"],
  "web.page_load.duration": ["s"],
  "web.page_load.throughput": ["By/s"],
  "web.page_load.jitter": ["ms"],
  "ftp.server.request.availability": ["%"],
  "ftp.server.throughput": ["By/s"],
  "ftp.client.request.duration": ["s"],
  "sip.server.request.availability": ["%"],
  "sip.client.request.duration": ["s"],
  "sip.client.request.total_time": ["s"],
  "rtp.client.request.mos": ["{score}"],
  "rtp.client.request.loss": ["%"],
  "rtp.client.request.discards": ["%"],
  "rtp.client.request.duration": ["s"],
  "bgp.path_changes.count": ["{count}"],
  "bgp.reachability": ["%"],
  "bgp.updates.count": ["{count}"],
  "api.duration": ["s"],
  "api.completion": ["%"],
  "api.step.duration": ["s"],
  "api.step.completion": ["%"],
  "network.score": ["{score}"],
  "network.signal.quality": ["%"],
  "network.connection.throughput": ["By/s"],
  "network.connection.link_speed": ["By/s"],
  "network.wifi.retransmission.rate": ["%"],
  "network.wifi.roaming.events.count": ["{count}"],
  "network.wifi.channel.changes.count": ["{count}"],
  "network.connection.score": ["{score}"],
  "network.signal.rssi": ["dBm"],
  "network.signal.rsrp": ["dBm"],
  "network.signal.rsrq": ["dB"],
  "network.signal.sinr": ["dB"],
  "network.signal.rscp": ["dBm"],
  "system.battery.charge": ["%"],
  "system.battery.health": ["%"],
  "system.disk.free.utilization": ["%"],
  "system.cpu.utilization": ["%"],
  "system.memory.utilization": ["%"],
  "thousandeyes.endpoint.agent.score": ["{score}"],
};

export const THOUSANDEYES_SUPPORTED_SOURCETYPES = SOURCETYPES;

type AnyObject = Record<string, unknown>;
type ParsedPathEnvelope = {
  authority: string;
  accountGroupId: string;
  testId: string;
  testDomain: "cea";
  capturedAt?: number;
  result: AnyObject;
};

interface ParseContext {
  row: Row;
  raw: AnyObject;
  event: AnyObject;
  index: string;
  source: string;
  sourcetype: string;
  fingerprint: string;
  indexedTime: number;
  rowTime: number;
  truncated: boolean;
  mapping: ThousandEyesSourceMapping;
  selection: EvidenceSelection;
  config: SupplementalSourceConfiguration;
}

interface Candidate {
  key: string;
  fingerprint: string;
  record: ThousandEyesObservation;
}

class RecordError extends Error {}

function fail(message: string): never {
  throw new RecordError(message);
}

function text(value: unknown, max = 2_048): string | undefined {
  if (typeof value !== "string" || !value || value.length > max) return;
  if (
    Array.from(value).some(
      (character) =>
        character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127,
    )
  )
    return;
  return value;
}

function requiredText(value: unknown, label: string, max = 2_048): string {
  const result = text(value, max);
  if (!result) fail(`Missing or invalid ${label}.`);
  return result;
}

function number(value: unknown, label: string): number {
  if (
    (typeof value !== "string" && typeof value !== "number") ||
    value === "" ||
    (typeof value === "string" && !/^-?\d+(?:\.\d+)?$/.test(value))
  )
    fail(`Missing or invalid ${label}.`);
  const result = Number(value);
  if (!Number.isFinite(result)) fail(`Missing or invalid ${label}.`);
  return result;
}

function epochSeconds(value: unknown, label: string): number {
  const result = number(value, label);
  if (result < 0 || result > MAX_EPOCH) fail(`Invalid ${label}.`);
  return result;
}

function optionalEpochSeconds(
  value: unknown,
  label: string,
): number | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  return epochSeconds(value, label);
}

function epochMilliseconds(value: unknown, label: string): number {
  const milliseconds = number(value, label);
  if (milliseconds < 0 || milliseconds > MAX_EPOCH * 1000)
    fail(`Invalid ${label}.`);
  return milliseconds / 1000;
}

function isoSeconds(value: unknown, label: string): number {
  if (
    typeof value !== "string" ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:\d{2})$/.test(
      value,
    )
  )
    fail(`Invalid ${label}.`);
  const result = Date.parse(value) / 1000;
  if (!Number.isFinite(result) || result < 0 || result > MAX_EPOCH)
    fail(`Invalid ${label}.`);
  return result;
}

function nanoSeconds(value: unknown, label: string): number {
  if (
    (typeof value !== "string" &&
      !(typeof value === "number" && Number.isSafeInteger(value))) ||
    !/^\d{1,20}$/.test(String(value))
  )
    fail(`Invalid ${label}.`);
  const nanoseconds = BigInt(String(value));
  if (nanoseconds > MAX_NANOSECONDS) fail(`Invalid ${label}.`);
  return Number(nanoseconds) / 1_000_000_000;
}

function uniqueField(
  object: AnyObject,
  names: readonly string[],
  label: string,
): unknown {
  const present = names.filter((name) => object[name] !== undefined);
  if (present.length > 1) {
    const values = present.map((name) => JSON.stringify(object[name]));
    if (new Set(values).size > 1) fail(`Conflicting ${label} fields.`);
  }
  return present.length ? object[present[0]] : undefined;
}

function arrayField(
  object: AnyObject,
  names: readonly string[],
  label: string,
): unknown[] {
  const value = uniqueField(object, names, label);
  if (!Array.isArray(value)) fail(`Invalid ${label} collection.`);
  return value;
}

function optionalArrayField(
  object: AnyObject,
  names: readonly string[],
  label: string,
): unknown[] {
  const value = uniqueField(object, names, label);
  if (value === undefined || value === null) return [];
  if (!Array.isArray(value)) fail(`Invalid ${label} collection.`);
  return value;
}

function parseRaw(row: Row): AnyObject {
  if (typeof row._raw !== "string" || row._raw.length === 0)
    fail("Source row has no raw JSON payload.");
  if (new TextEncoder().encode(row._raw).byteLength > MAX_RAW_BYTES)
    fail("Source row exceeds the 1 MiB raw-record limit.");
  rejectDuplicateJsonKeys(row._raw);
  let value: unknown;
  try {
    value = JSON.parse(row._raw);
  } catch {
    fail("Source row is malformed JSON.");
  }
  if (!isObject(value)) fail("Source row is not a JSON object.");
  return value;
}

/** JSON.parse accepts duplicate object keys; reject them before field use. */
function rejectDuplicateJsonKeys(source: string): void {
  const stack: { kind: "object" | "array"; keys: Set<string> }[] = [];
  for (let index = 0; index < source.length; index += 1) {
    const character = source[index];
    if (character === '"') {
      const start = index;
      index += 1;
      for (; index < source.length; index += 1) {
        if (source[index] === "\\") {
          index += 1;
          continue;
        }
        if (source[index] === '"') break;
      }
      if (index >= source.length) return;
      const token = source.slice(start, index + 1);
      let next = index + 1;
      while (/\s/.test(source[next] ?? "")) next += 1;
      const parent = stack.at(-1);
      if (source[next] === ":" && parent?.kind === "object") {
        let key: string;
        try {
          key = JSON.parse(token) as string;
        } catch {
          return;
        }
        if (parent.keys.has(key))
          fail("Source JSON contains a duplicate object key.");
        parent.keys.add(key);
      }
      index += 0;
      continue;
    }
    if (character === "{") stack.push({ kind: "object", keys: new Set() });
    else if (character === "[") stack.push({ kind: "array", keys: new Set() });
    else if (character === "}" || character === "]") stack.pop();
  }
}

function fieldText(object: AnyObject, names: readonly string[], label: string) {
  return text(uniqueField(object, names, label));
}

function requireIdentity(value: unknown, label: string): string {
  try {
    if (typeof value === "number" && !Number.isSafeInteger(value))
      return fail(`Unsafe numeric native ${label}.`);
    return thousandEyesNativeId(
      typeof value === "number" ? String(value) : value,
    );
  } catch {
    return fail(`Missing or invalid native ${label}.`);
  }
}

function requireAccountGroupId(value: unknown, label: string): string {
  try {
    return thousandEyesAccountGroupId(value);
  } catch {
    return fail(`Missing or invalid native ${label}.`);
  }
}

function identityFromAttribute(value: unknown, label: string): string {
  const attribute = attributeScalar(value, label);
  return requireIdentity(attribute, label);
}

function optionalIdentityFromAttribute(
  value: unknown,
  label: string,
): string | undefined {
  return value === undefined || value === null || value === ""
    ? undefined
    : identityFromAttribute(value, label);
}

function attributeScalar(value: unknown, label: string): unknown {
  if (!isObject(value)) return value;
  const keys = [
    "string_value",
    "stringValue",
    "int_value",
    "intValue",
    "bool_value",
    "boolValue",
  ].filter((key) => value[key] !== undefined);
  if (keys.length !== 1) fail(`Invalid ${label} attribute value.`);
  return value[keys[0]];
}

function attributes(value: unknown): Map<string, unknown> {
  const result = new Map<string, unknown>();
  if (Array.isArray(value)) {
    for (const entry of value) {
      if (!isObject(entry)) fail("Invalid OpenTelemetry attribute entry.");
      const key = requiredText(entry.key, "OpenTelemetry attribute key", 255);
      if (result.has(key)) fail(`Duplicate OpenTelemetry attribute ${key}.`);
      if (entry.value === undefined)
        fail(`Missing OpenTelemetry value ${key}.`);
      result.set(key, attributeScalar(entry.value, key));
    }
    return result;
  }
  if (isObject(value)) {
    for (const [key, item] of Object.entries(value)) {
      if (!text(key, 255)) fail("Invalid OpenTelemetry attribute key.");
      if (result.has(key)) fail(`Duplicate OpenTelemetry attribute ${key}.`);
      result.set(key, attributeScalar(item, key));
    }
    return result;
  }
  if (value === undefined || value === null) return result;
  fail("Invalid OpenTelemetry attributes.");
}

function attr(
  values: Map<string, unknown>,
  name: string,
  label = name,
): string | undefined {
  const value = values.get(name);
  if (value === undefined || value === null || value === "") return undefined;
  return requiredText(typeof value === "number" ? String(value) : value, label);
}

function testDomain(value: unknown): "cea" | "endpoint" | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  if (value === "cea" || value === "endpoint") return value;
  fail("Unsupported ThousandEyes native test domain.");
}

function requiredAttr(values: Map<string, unknown>, name: string): string {
  const value = attr(values, name);
  if (!value) fail(`Missing OpenTelemetry ${name}.`);
  return value;
}

function mergeAttributes(
  resource: Map<string, unknown>,
  local: Map<string, unknown>,
): Map<string, unknown> {
  const merged = new Map(resource);
  for (const [key, value] of local) merged.set(key, value);
  return merged;
}

function nativeTimeInSelection(
  time: number,
  selection: EvidenceSelection,
): boolean {
  return time >= selection.window.start && time < selection.window.end;
}

function intervalOverlapsSelection(
  start: number,
  end: number,
  selection: EvidenceSelection,
): boolean {
  return (
    end >= start &&
    end >= selection.window.start &&
    start < selection.window.end
  );
}

function selectedMappings(
  config: SupplementalSourceConfiguration,
  selection: EvidenceSelection,
): ThousandEyesSourceMapping[] {
  if (
    config.source !== THOUSANDEYES_SOURCE ||
    config.state !== "active" ||
    config.error ||
    !config.schemaQualified ||
    !Number.isSafeInteger(config.staleAfterSeconds) ||
    config.staleAfterSeconds < 60 ||
    config.staleAfterSeconds > 30 * 24 * 60 * 60
  )
    throw new Error("ThousandEyes source is not active and schema-qualified.");
  return thousandEyesMappings(config, selection);
}

function sourceType(row: Row): string {
  return requiredText(row.sourcetype, "indexed sourcetype", 255);
}

function rowOrigin(row: Row, config: SupplementalSourceConfiguration) {
  const index = requiredText(row.index, "indexed index", 80);
  const source = requiredText(row.source, "indexed source", 255);
  if (!config.indexes.includes(index))
    fail("Indexed row is outside configured indexes.");
  return { index, source, sourcetype: sourceType(row) };
}

function checkedFingerprint(row: Row): string {
  const value = requiredText(row.event_fingerprint, "origin fingerprint", 64);
  if (!/^[a-f0-9]{64}$/.test(value)) fail("Invalid source origin fingerprint.");
  return value;
}

function checkedTimes(row: Row) {
  const indexedTime = epochSeconds(
    row.indexed_time_epoch,
    "Splunk indexed time",
  );
  const rowTime = epochSeconds(row.row_time_epoch, "Splunk _time row time");
  return { indexedTime, rowTime };
}

function sourceTimeField(
  object: AnyObject,
  names: readonly string[],
  unit: "ns" | "ms" | "s" | "iso8601",
  label: string,
): NonNullable<ThousandEyesObservation["sourceTimes"]>[number] | undefined {
  const field = names.find((name) => object[name] !== undefined);
  const value = uniqueField(object, names, label);
  if (value === undefined || value === null || value === "") return undefined;
  if (!field) fail(`Invalid precise ${label} source value.`);
  return sourceTimeValue(value, field, unit, label);
}

function sourceTimeValue(
  value: unknown,
  field: string,
  unit: "ns" | "ms" | "s" | "iso8601",
  label: string,
): NonNullable<ThousandEyesObservation["sourceTimes"]>[number] {
  if (
    typeof value === "number" &&
    (!Number.isSafeInteger(value) || !Number.isFinite(value))
  )
    fail(`Invalid precise ${label} source value.`);
  const encoded = text(typeof value === "number" ? String(value) : value, 64);
  if (!encoded) fail(`Invalid precise ${label} source value.`);
  return { field, value: encoded, unit };
}

function boolRow(value: unknown): boolean {
  return value === true || value === 1 || value === "1" || value === "true";
}

function rawPathEnvelope(
  raw: AnyObject,
  mapping: ThousandEyesSourceMapping,
): ParsedPathEnvelope | undefined {
  if (raw.schema !== SCHEMA_PATH) return;
  if (
    raw.schema_version !== 1 ||
    !text(raw.capture_id, 128) ||
    raw.authority !== mapping.authority ||
    raw.test_domain !== "cea"
  )
    fail("CEA path capture wrapper identity is invalid.");
  const accountGroupId = requireAccountGroupId(
    raw.account_group_id,
    "account-group ID",
  );
  if (accountGroupId !== mapping.accountGroupId)
    fail(
      "CEA path capture account-group identity does not match configuration.",
    );
  const testId = requireIdentity(raw.test_id, "test ID");
  const result = raw.result;
  if (!isObject(result)) fail("CEA path capture has no native result object.");
  const started = epochSeconds(raw.collection_started_at, "capture start time");
  const completed = epochSeconds(
    raw.collection_completed_at,
    "capture completion time",
  );
  if (completed < started)
    fail("CEA path capture completion precedes its start.");
  return {
    authority: mapping.authority,
    accountGroupId,
    testId,
    testDomain: "cea",
    capturedAt: completed,
    result,
  };
}

function expectedFamily(
  sourcetype: string,
  source: string,
  index: string,
  mapping: ThousandEyesSourceMapping,
): ThousandEyesFamily | undefined {
  if (sourcetype === SOURCETYPES.metric && source === VENDOR_STREAM_SOURCE)
    return "metric";
  if (sourcetype === SOURCETYPES.trace && source === VENDOR_STREAM_SOURCE)
    return "trace";
  if (sourcetype === SOURCETYPES.activity && source === VENDOR_STREAM_SOURCE)
    return "activity";
  if (sourcetype === SOURCETYPES.event) return "event";
  if (sourcetype === SOURCETYPES.alert && source === VENDOR_WEBHOOK_SOURCE)
    return "alert";
  if (
    sourcetype === ATLAS_PATH_SOURCETYPE &&
    source === ATLAS_PATH_SOURCE &&
    mapping.pathSources.some(
      (entry) => entry.index === index && entry.source === source,
    )
  )
    return "path";
  if (
    sourcetype === VENDOR_PATH_SOURCETYPE &&
    mapping.pathSources.some(
      (entry) => entry.index === index && entry.source === source,
    )
  )
    return "path";
  return undefined;
}

function isEnabled(
  mapping: ThousandEyesSourceMapping,
  family: ThousandEyesFamily,
): boolean {
  return mapping.families.includes(family);
}

function streamMapping(
  accountId: string,
  mappings: ThousandEyesSourceMapping[],
): ThousandEyesSourceMapping {
  const matches = mappings.filter(
    (mapping) => mapping.streamAccountId === accountId,
  );
  if (matches.length !== 1)
    fail("Stream account identity is missing or ambiguous.");
  return matches[0];
}

function eventMapping(
  accountGroupId: string,
  mappings: ThousandEyesSourceMapping[],
): ThousandEyesSourceMapping {
  const matches = mappings.filter(
    (mapping) => mapping.accountGroupId === accountGroupId,
  );
  if (matches.length !== 1)
    fail("Account-group identity is missing or ambiguous.");
  return matches[0];
}

function alertMapping(
  accountId: string,
  organizationId: string | undefined,
  mappings: ThousandEyesSourceMapping[],
): ThousandEyesSourceMapping {
  const matches = mappings.filter(
    (mapping) =>
      mapping.alertAccountId === accountId &&
      mapping.organizationId === organizationId,
  );
  if (matches.length !== 1)
    fail("Alert account or organization identity is missing or ambiguous.");
  return matches[0];
}

function resourceAttributes(resource: AnyObject): Map<string, unknown> {
  return attributes(
    uniqueField(resource, ["attributes"], "resource attributes"),
  );
}

function readTarget(values: Map<string, unknown>): ThousandEyesTarget {
  const target: Record<string, unknown> = {};
  const address = attr(values, "server.address");
  const port = values.get("server.port");
  const protocol = attr(values, "network.transport");
  if (address) {
    try {
      target.ip = normalizeIp(address);
    } catch {
      target.hostname = address;
    }
  }
  if (port !== undefined && port !== null && port !== "") {
    const parsedPort = number(port, "server.port");
    if (!Number.isInteger(parsedPort)) fail("Invalid server.port.");
    target.port = parsedPort;
  }
  if (protocol) target.protocol = protocol.toLowerCase();
  if (!target.ip && !target.hostname) return {};
  try {
    return thousandEyesTarget(target);
  } catch {
    fail("Invalid native target address, protocol or port.");
  }
}

function pathTarget(result: AnyObject): ThousandEyesTarget {
  const target: Record<string, unknown> = {};
  const address = fieldText(result, ["serverIp", "server_ip"], "server IP");
  const server = fieldText(result, ["server", "serverName"], "server target");
  const source = isObject(result.originalTargetProfile)
    ? result.originalTargetProfile
    : {};
  const protocol = fieldText(source, ["protocol"], "target protocol");
  const explicitPort = uniqueField(
    source,
    ["remotePort", "port"],
    "target port",
  );
  if (address) {
    try {
      target.ip = normalizeIp(address);
    } catch {
      fail("Invalid native target IP address.");
    }
  }
  if (server && !address) {
    const match =
      /^\[([0-9a-f:]+)\](?::([0-9]{1,5}))?$/i.exec(server) ??
      /^([^:]+)(?::([0-9]{1,5}))?$/.exec(server);
    if (!match) fail("Invalid native target hostname.");
    try {
      target.ip = normalizeIp(match[1]);
    } catch {
      target.hostname = match[1];
    }
    if (match[2] !== undefined) target.port = Number(match[2]);
  }
  const portValue = explicitPort ?? target.port;
  if (portValue !== undefined) target.port = number(portValue, "target port");
  if (protocol) target.protocol = protocol.toLowerCase();
  if (!target.ip && !target.hostname) return {};
  try {
    return thousandEyesTarget(target);
  } catch {
    fail("Invalid native target address, protocol or port.");
  }
}

function quality(
  context: ParseContext,
  complete: boolean,
): ThousandEyesObservation["quality"] {
  return {
    // Historical evidence remains valid for its selected measurement window.
    // Receipt freshness is reported separately for the selected cohort.
    stale: false,
    complete,
    conflicting: false,
    truncated: context.truncated,
  };
}

function baseRecord(
  context: ParseContext,
  family: ThousandEyesFamily,
  mapping: ThousandEyesSourceMapping,
  values: {
    accountId?: string;
    authorityBasis: ThousandEyesObservation["authorityBasis"];
    eventTime: number;
    interval: { start: number; end: number };
    intervalBasis: ThousandEyesObservation["intervalBasis"];
    target?: ThousandEyesTarget;
    testId?: string;
    agentId?: string;
    testName?: string;
    agentName?: string;
    agentLocation?: string;
    testType?: string;
    testDomain?: "cea" | "endpoint";
    streamId?: string;
    monitorId?: string;
    targetAgentId?: string;
    pathDirection?: "to-target" | "from-target";
    targetIsProxy?: boolean;
    sourceTimes?: NonNullable<ThousandEyesObservation["sourceTimes"]>;
    configurationId?: string;
    collectionTime?: number;
    outcome?: ThousandEyesObservation["outcome"];
    complete: boolean;
    measurements?: ThousandEyesMeasurement[];
    hops?: ThousandEyesHop[];
    spans?: ThousandEyesSpan[];
    lifecycle?: ThousandEyesObservation["lifecycle"];
    activity?: ThousandEyesObservation["activity"];
    limitations?: string[];
    relatedTestIds?: string[];
    relatedAgentIds?: string[];
    fingerprint?: string;
  },
): ThousandEyesObservation {
  const record = {
    schemaVersion: 1 as const,
    family,
    authority: mapping.authority,
    authorityBasis: values.authorityBasis,
    accountGroupId: mapping.accountGroupId,
    ...(values.accountId ? { accountId: values.accountId } : {}),
    ...(mapping.organizationId
      ? { organizationId: mapping.organizationId }
      : {}),
    adapterVersion: THOUSANDEYES_ADAPTER_VERSION,
    producerVersion: `Cisco ThousandEyes App for Splunk ${THOUSANDEYES_ADAPTER_VERSION}`,
    dataModelVersion:
      family === "metric" || family === "trace" || family === "activity"
        ? "v2"
        : family === "path"
          ? "api-v7"
          : "api-v7",
    ...(values.testId ? { testId: values.testId } : {}),
    ...(values.agentId ? { agentId: values.agentId } : {}),
    ...(values.testName ? { testName: values.testName } : {}),
    ...(values.agentName ? { agentName: values.agentName } : {}),
    ...(values.agentLocation ? { agentLocation: values.agentLocation } : {}),
    ...(values.testType ? { testType: values.testType } : {}),
    ...(values.testDomain ? { testDomain: values.testDomain } : {}),
    ...(values.streamId ? { streamId: values.streamId } : {}),
    ...(values.monitorId ? { monitorId: values.monitorId } : {}),
    ...(values.targetAgentId ? { targetAgentId: values.targetAgentId } : {}),
    ...(values.pathDirection ? { pathDirection: values.pathDirection } : {}),
    ...(values.targetIsProxy !== undefined
      ? { targetIsProxy: values.targetIsProxy }
      : {}),
    ...(values.sourceTimes?.length ? { sourceTimes: values.sourceTimes } : {}),
    ...(values.configurationId
      ? { configurationId: values.configurationId }
      : {}),
    target: values.target ?? {},
    interval: values.interval,
    intervalBasis: values.intervalBasis,
    eventTime: values.eventTime,
    indexedTime: context.indexedTime,
    ...(values.collectionTime !== undefined
      ? { collectionTime: values.collectionTime }
      : {}),
    index: context.index,
    source: context.source,
    sourcetype: context.sourcetype,
    fingerprint: values.fingerprint ?? context.fingerprint,
    ...(mapping.origin ? { navigationOrigin: mapping.origin } : {}),
    outcome: values.outcome ?? "unknown",
    quality: quality(context, values.complete),
    measurements: values.measurements ?? [],
    hops: values.hops ?? [],
    spans: values.spans ?? [],
    ...(values.lifecycle ? { lifecycle: values.lifecycle } : {}),
    ...(values.activity ? { activity: values.activity } : {}),
    limitations: values.limitations ?? [],
    ...(values.relatedTestIds?.length
      ? { relatedTestIds: values.relatedTestIds }
      : {}),
    ...(values.relatedAgentIds?.length
      ? { relatedAgentIds: values.relatedAgentIds }
      : {}),
    rowTime: context.rowTime,
  };
  return record as ThousandEyesObservation;
}

function parseMetricRecord(
  context: ParseContext,
  raw: AnyObject,
  mappings: ThousandEyesSourceMapping[],
): Candidate[] {
  const resourceMetrics = arrayField(
    raw,
    ["resource_metrics", "resourceMetrics"],
    "resource metrics",
  );
  const output: Candidate[] = [];
  for (const resourceMetric of resourceMetrics) {
    if (!isObject(resourceMetric) || !isObject(resourceMetric.resource))
      fail("Invalid OpenTelemetry metric resource.");
    const resourceAttrs = resourceAttributes(resourceMetric.resource);
    const accountId = identityFromAttribute(
      resourceAttrs.get("thousandeyes.account.id"),
      "account ID",
    );
    const mapping = streamMapping(accountId, mappings);
    if (!isEnabled(mapping, "metric")) continue;
    if (requiredAttr(resourceAttrs, "thousandeyes.data.version") !== "v2")
      fail("Unsupported ThousandEyes OpenTelemetry metric data model.");
    const testId = optionalIdentityFromAttribute(
      resourceAttrs.get("thousandeyes.test.id"),
      "test ID",
    );
    const agentId = optionalIdentityFromAttribute(
      resourceAttrs.get("thousandeyes.source.agent.id"),
      "agent ID",
    );
    const testName = attr(resourceAttrs, "thousandeyes.test.name");
    const testType = attr(resourceAttrs, "thousandeyes.test.type");
    const domain = testDomain(
      attributeScalar(
        resourceAttrs.get("thousandeyes.test.domain"),
        "test domain",
      ),
    );
    const streamId = optionalIdentityFromAttribute(
      resourceAttrs.get("thousandeyes.stream.id"),
      "stream ID",
    );
    const monitorId = optionalIdentityFromAttribute(
      uniqueField(
        Object.fromEntries(resourceAttrs),
        ["thousandeyes.monitor.id", "thousandeyes.bgp.monitor.id"],
        "monitor ID",
      ),
      "monitor ID",
    );
    const targetAgentId = optionalIdentityFromAttribute(
      resourceAttrs.get("thousandeyes.target.agent.id"),
      "target agent ID",
    );
    const agentName = attr(resourceAttrs, "thousandeyes.source.agent.name");
    const agentLocation = attr(
      resourceAttrs,
      "thousandeyes.source.agent.location",
    );
    const scopes = arrayField(
      resourceMetric,
      ["scope_metrics", "scopeMetrics"],
      "scope metrics",
    );
    for (const scope of scopes) {
      if (!isObject(scope)) fail("Invalid OpenTelemetry scope metrics.");
      const metrics = arrayField(scope, ["metrics"], "metrics");
      for (const metric of metrics) {
        if (!isObject(metric)) fail("Invalid OpenTelemetry metric.");
        const name = requiredText(metric.name, "metric name", 255);
        const isBgp = name.startsWith("bgp.");
        if ((!testId || !agentId) && !(isBgp && monitorId))
          fail(
            "Metric lacks a source-native test/agent identity or BGP monitor identity.",
          );
        const expectedUnits = METRIC_UNITS[name];
        if (!expectedUnits) fail(`Unsupported ThousandEyes metric ${name}.`);
        const unit = requiredText(metric.unit, "metric source unit", 32);
        if (!expectedUnits.includes(unit))
          fail(`Unexpected source unit for ${name}.`);
        const instruments = ["gauge", "sum"].filter(
          (key) => metric[key] !== undefined,
        );
        if (instruments.length !== 1 || !isObject(metric[instruments[0]]))
          fail(`Unsupported or conflicting instrument for ${name}.`);
        const instrumentKind = instruments[0];
        const instrument = metric[instrumentKind] as AnyObject;
        const dataPoints = arrayField(
          instrument,
          ["data_points", "dataPoints"],
          "metric data points",
        );
        const temporality = fieldText(
          instrument,
          ["aggregation_temporality", "aggregationTemporality"],
          "aggregation temporality",
        );
        const monotonic = uniqueField(
          instrument,
          ["is_monotonic", "isMonotonic"],
          "monotonic flag",
        );
        if (
          instrumentKind === "sum" &&
          temporality &&
          ![
            "AGGREGATION_TEMPORALITY_DELTA",
            "AGGREGATION_TEMPORALITY_CUMULATIVE",
            "1",
            "2",
          ].includes(temporality)
        )
          fail(`Unsupported aggregation temporality for ${name}.`);
        for (const dataPoint of dataPoints) {
          if (!isObject(dataPoint))
            fail("Invalid OpenTelemetry metric data point.");
          const timeValue = uniqueField(
            dataPoint,
            ["time_unix_nano", "timeUnixNano"],
            "datapoint timestamp",
          );
          const eventTime = nanoSeconds(
            timeValue,
            "metric datapoint timestamp",
          );
          const sourceTimes = [
            sourceTimeField(
              dataPoint,
              ["time_unix_nano", "timeUnixNano"],
              "ns",
              "metric timestamp",
            ),
            sourceTimeField(
              dataPoint,
              ["start_time_unix_nano", "startTimeUnixNano"],
              "ns",
              "metric start timestamp",
            ),
          ].filter(
            (item): item is NonNullable<typeof item> => item !== undefined,
          );
          const startValue = uniqueField(
            dataPoint,
            ["start_time_unix_nano", "startTimeUnixNano"],
            "datapoint start timestamp",
          );
          const start =
            startValue === undefined
              ? eventTime
              : nanoSeconds(startValue, "metric datapoint start timestamp");
          if (eventTime < start)
            fail("Metric datapoint end precedes its start.");
          if (!intervalOverlapsSelection(start, eventTime, context.selection))
            continue;
          const numericValues = [
            "as_double",
            "asDouble",
            "as_int",
            "asInt",
          ].filter((key) => dataPoint[key] !== undefined);
          if (numericValues.length !== 1)
            fail("Metric datapoint must have exactly one numeric value.");
          const value = number(
            dataPoint[numericValues[0]],
            "metric datapoint value",
          );
          const localAttrs = attributes(
            uniqueField(
              dataPoint,
              ["attributes"],
              "metric datapoint attributes",
            ),
          );
          const merged = mergeAttributes(resourceAttrs, localAttrs);
          const target = readTarget(merged);
          const direction =
            attr(merged, "network.io.direction") ?? "not_reported";
          const errorType = attr(merged, "error.type");
          const measurement: ThousandEyesMeasurement = {
            name,
            value,
            unit,
            sourceUnit: unit,
            aggregation:
              instrumentKind === "sum"
                ? `sum:${temporality ?? "unspecified"}${monotonic === true ? ":monotonic" : monotonic === false ? ":non_monotonic" : ""}`
                : "gauge",
            direction,
            denominator: unit === "%" ? "producer_defined" : "not_applicable",
            timeBasis:
              start < eventTime ? "interval_end" : "point_time_unix_nano",
          };
          const record = baseRecord(context, "metric", mapping, {
            accountId,
            authorityBasis: "producer_account",
            eventTime,
            interval: { start, end: eventTime },
            intervalBasis: start < eventTime ? "measurement" : "point",
            target,
            testId,
            agentId,
            testName,
            testType,
            testDomain: domain,
            streamId,
            monitorId,
            targetAgentId,
            agentName,
            agentLocation,
            outcome: errorType ? "failure" : "unknown",
            complete: true,
            sourceTimes,
            measurements: [measurement],
            limitations: [
              "Measurement units and names follow ThousandEyes OpenTelemetry data model v2; instrument details are only accepted for OTLP gauge and sum points.",
              ...(unit === "%"
                ? [
                    "The producer does not supply a denominator in this record; the percentage is preserved without recomputation.",
                  ]
                : []),
            ],
          });
          output.push({
            key: [
              "metric",
              mapping.authority,
              mapping.accountGroupId,
              testId ?? "",
              agentId ?? "",
              monitorId ?? "",
              eventTime,
              name,
              JSON.stringify(target),
            ].join("\u0000"),
            fingerprint: context.fingerprint,
            record,
          });
        }
      }
    }
  }
  return output;
}

function parseTraceRecord(
  context: ParseContext,
  raw: AnyObject,
  mappings: ThousandEyesSourceMapping[],
): Candidate[] {
  const resourceSpans = arrayField(
    raw,
    ["resource_spans", "resourceSpans"],
    "resource spans",
  );
  const output: Candidate[] = [];
  for (const resourceSpan of resourceSpans) {
    if (!isObject(resourceSpan) || !isObject(resourceSpan.resource))
      fail("Invalid OpenTelemetry trace resource.");
    const resourceAttrs = resourceAttributes(resourceSpan.resource);
    const accountId = identityFromAttribute(
      resourceAttrs.get("thousandeyes.account.id"),
      "account ID",
    );
    const mapping = streamMapping(accountId, mappings);
    if (!isEnabled(mapping, "trace")) continue;
    if (requiredAttr(resourceAttrs, "thousandeyes.data.version") !== "v2")
      fail("Unsupported ThousandEyes OpenTelemetry trace data model.");
    const testId = identityFromAttribute(
      resourceAttrs.get("thousandeyes.test.id"),
      "test ID",
    );
    const agentId = identityFromAttribute(
      resourceAttrs.get("thousandeyes.source.agent.id"),
      "agent ID",
    );
    const testName = attr(resourceAttrs, "thousandeyes.test.name");
    const testType = attr(resourceAttrs, "thousandeyes.test.type");
    if (testType?.toLowerCase().includes("api"))
      fail(
        "API trace support is not qualified by the current Cisco documentation.",
      );
    const domain = testDomain(
      attributeScalar(
        resourceAttrs.get("thousandeyes.test.domain"),
        "test domain",
      ),
    );
    const streamId = optionalIdentityFromAttribute(
      resourceAttrs.get("thousandeyes.stream.id"),
      "stream ID",
    );
    const agentName = attr(resourceAttrs, "thousandeyes.source.agent.name");
    const agentLocation = attr(
      resourceAttrs,
      "thousandeyes.source.agent.location",
    );
    const scopes = arrayField(
      resourceSpan,
      ["scope_spans", "scopeSpans"],
      "scope spans",
    );
    for (const scope of scopes) {
      if (!isObject(scope)) fail("Invalid OpenTelemetry scope spans.");
      const spans = arrayField(scope, ["spans"], "spans");
      for (const span of spans) {
        if (!isObject(span)) fail("Invalid OpenTelemetry span.");
        const traceId = requiredText(
          span.trace_id ?? span.traceId,
          "trace ID",
          64,
        );
        const spanId = requiredText(span.span_id ?? span.spanId, "span ID", 32);
        if (!/^[a-f0-9]{32}$/i.test(traceId) || !/^[a-f0-9]{16}$/i.test(spanId))
          fail("OpenTelemetry trace or span ID has an unsupported format.");
        const parentSpanIdValue = uniqueField(
          span,
          ["parent_span_id", "parentSpanId"],
          "parent span ID",
        );
        const parentSpanId =
          parentSpanIdValue === undefined ||
          /^0+$/.test(String(parentSpanIdValue))
            ? undefined
            : requiredText(parentSpanIdValue, "parent span ID", 32);
        if (parentSpanId && !/^[a-f0-9]{16}$/i.test(parentSpanId))
          fail("OpenTelemetry parent span ID has an unsupported format.");
        const startValue = uniqueField(
          span,
          ["start_time_unix_nano", "startTimeUnixNano"],
          "span start",
        );
        const endValue = uniqueField(
          span,
          ["end_time_unix_nano", "endTimeUnixNano"],
          "span end",
        );
        const start = nanoSeconds(startValue, "span start time");
        const end = nanoSeconds(endValue, "span end time");
        const preciseStart = sourceTimeField(
          span,
          ["start_time_unix_nano", "startTimeUnixNano"],
          "ns",
          "span start timestamp",
        )!;
        const preciseEnd = sourceTimeField(
          span,
          ["end_time_unix_nano", "endTimeUnixNano"],
          "ns",
          "span end timestamp",
        )!;
        if (end < start) fail("OpenTelemetry span ends before it starts.");
        if (!intervalOverlapsSelection(start, end, context.selection)) continue;
        const localAttrs = attributes(
          uniqueField(span, ["attributes"], "span attributes"),
        );
        const merged = mergeAttributes(resourceAttrs, localAttrs);
        const statusValue = span.status;
        let status: string | undefined;
        if (statusValue !== undefined) {
          if (isObject(statusValue)) {
            const code = uniqueField(statusValue, ["code"], "span status code");
            const message = text(
              uniqueField(statusValue, ["message"], "span status message"),
              2_048,
            );
            status =
              code === 2 || code === "2" || code === "STATUS_CODE_ERROR"
                ? "ERROR"
                : code === 1 || code === "1" || code === "STATUS_CODE_OK"
                  ? "OK"
                  : code === 0 || code === "0" || code === "STATUS_CODE_UNSET"
                    ? "UNSET"
                    : undefined;
            if (code !== undefined && !status)
              fail("Unsupported OpenTelemetry span status code.");
            if (message && status === "ERROR") status = `ERROR: ${message}`;
          } else if (
            [
              "ERROR",
              "OK",
              "UNSET",
              "STATUS_CODE_ERROR",
              "STATUS_CODE_OK",
              "STATUS_CODE_UNSET",
            ].includes(String(statusValue))
          ) {
            status = String(statusValue).replace("STATUS_CODE_", "");
          } else {
            fail("Unsupported OpenTelemetry span status.");
          }
        }
        const spanRecord: ThousandEyesSpan = {
          traceId: traceId.toLowerCase(),
          spanId: spanId.toLowerCase(),
          ...(parentSpanId ? { parentSpanId: parentSpanId.toLowerCase() } : {}),
          name: requiredText(span.name, "span name", 255),
          start,
          end,
          startTimeUnixNano: preciseStart.value,
          endTimeUnixNano: preciseEnd.value,
          ...(status ? { status } : {}),
        };
        const record = baseRecord(context, "trace", mapping, {
          accountId,
          authorityBasis: "producer_account",
          eventTime: end,
          interval: { start, end },
          intervalBasis: "measurement",
          target: readTarget(merged),
          testId,
          agentId,
          testName,
          testType,
          testDomain: domain,
          streamId,
          agentName,
          agentLocation,
          outcome: status?.startsWith("ERROR")
            ? "failure"
            : status === "OK"
              ? "success"
              : "unknown",
          complete: true,
          sourceTimes: [preciseStart, preciseEnd],
          spans: [spanRecord],
          limitations: [
            "This is a synthetic ThousandEyes span. It does not represent a production service call or establish a dependency edge.",
          ],
        });
        output.push({
          key: [
            "trace",
            mapping.authority,
            mapping.accountGroupId,
            testId,
            agentId,
            traceId.toLowerCase(),
            spanId.toLowerCase(),
          ].join("\u0000"),
          fingerprint: context.fingerprint,
          record,
        });
      }
    }
  }
  return output;
}

function parseActivityRecord(
  context: ParseContext,
  raw: AnyObject,
  mappings: ThousandEyesSourceMapping[],
): Candidate[] {
  const resourceLogs = arrayField(
    raw,
    ["resource_logs", "resourceLogs"],
    "resource logs",
  );
  const output: Candidate[] = [];
  for (const resourceLog of resourceLogs) {
    if (!isObject(resourceLog) || !isObject(resourceLog.resource))
      fail("Invalid OpenTelemetry activity resource.");
    const resourceAttrs = resourceAttributes(resourceLog.resource);
    const accountId = identityFromAttribute(
      resourceAttrs.get("thousandeyes.account.id"),
      "account ID",
    );
    const streamId = optionalIdentityFromAttribute(
      resourceAttrs.get("thousandeyes.stream.id"),
      "stream ID",
    );
    const mapping = streamMapping(accountId, mappings);
    if (!isEnabled(mapping, "activity")) continue;
    if (requiredAttr(resourceAttrs, "thousandeyes.data.version") !== "v2")
      fail("Unsupported ThousandEyes OpenTelemetry activity data model.");
    const scopes = arrayField(
      resourceLog,
      ["scope_logs", "scopeLogs"],
      "scope logs",
    );
    for (const scope of scopes) {
      if (!isObject(scope)) fail("Invalid OpenTelemetry scope logs.");
      const logRecords = arrayField(
        scope,
        ["log_records", "logRecords"],
        "log records",
      );
      for (const log of logRecords) {
        if (!isObject(log)) fail("Invalid OpenTelemetry log record.");
        const bodyValue = uniqueField(log, ["body", "Body"], "log body");
        const body = requiredText(
          attributeScalar(bodyValue, "log body"),
          "activity body",
          2_048,
        );
        const timeValue = uniqueField(
          log,
          ["time_unix_nano", "timeUnixNano", "Timestamp", "timestamp"],
          "activity timestamp",
        );
        const eventTime =
          typeof timeValue === "string" && timeValue.includes("T")
            ? isoSeconds(timeValue, "activity timestamp")
            : nanoSeconds(timeValue, "activity timestamp");
        const activityTimeSource = sourceTimeField(
          log,
          ["time_unix_nano", "timeUnixNano", "Timestamp", "timestamp"],
          typeof timeValue === "string" && timeValue.includes("T")
            ? "iso8601"
            : "ns",
          "activity timestamp",
        );
        if (!nativeTimeInSelection(eventTime, context.selection)) continue;
        const observedValue = uniqueField(
          log,
          [
            "observed_time_unix_nano",
            "observedTimeUnixNano",
            "ObservedTimestamp",
            "observedTimestamp",
          ],
          "activity observed timestamp",
        );
        const observedTime =
          observedValue === undefined ||
          observedValue === null ||
          observedValue === ""
            ? undefined
            : typeof observedValue === "string" && observedValue.includes("T")
              ? isoSeconds(observedValue, "activity observed timestamp")
              : nanoSeconds(observedValue, "activity observed timestamp");
        const observedTimeSource =
          observedValue === undefined ||
          observedValue === null ||
          observedValue === ""
            ? undefined
            : sourceTimeField(
                log,
                [
                  "observed_time_unix_nano",
                  "observedTimeUnixNano",
                  "ObservedTimestamp",
                  "observedTimestamp",
                ],
                typeof observedValue === "string" && observedValue.includes("T")
                  ? "iso8601"
                  : "ns",
                "activity observed timestamp",
              );
        const localAttrs = attributes(
          uniqueField(log, ["attributes"], "activity log attributes"),
        );
        const merged = mergeAttributes(resourceAttrs, localAttrs);
        const actor =
          attr(merged, "thousandeyes.user.name") ??
          attr(merged, "thousandeyes.user.email");
        const objectId = attr(merged, "thousandeyes.activitylog.resources");
        const activity = {
          action: attr(merged, "thousandeyes.activitylog.action") ?? body,
          ...(actor ? { actor } : {}),
          ...(objectId ? { objectId } : {}),
          ...(attr(merged, "thousandeyes.activitylog.resource.type")
            ? {
                objectType: attr(
                  merged,
                  "thousandeyes.activitylog.resource.type",
                ),
              }
            : {}),
        };
        const record = baseRecord(context, "activity", mapping, {
          accountId,
          authorityBasis: "producer_account",
          eventTime,
          interval: { start: eventTime, end: eventTime },
          intervalBasis: "point",
          ...(observedTime !== undefined
            ? { collectionTime: observedTime }
            : {}),
          streamId,
          sourceTimes: [
            activityTimeSource!,
            ...(observedTimeSource ? [observedTimeSource] : []),
          ],
          complete: true,
          activity,
          limitations: [
            "Activity records describe the supplied ThousandEyes account-group change log. They do not establish a test, agent or network outcome.",
          ],
        });
        output.push({
          key: [
            "activity",
            mapping.authority,
            mapping.accountGroupId,
            eventTime,
            body,
            actor ?? "",
          ].join("\u0000"),
          fingerprint: context.fingerprint,
          record,
        });
      }
    }
  }
  return output;
}

function parseEventRecord(
  context: ParseContext,
  event: AnyObject,
  mappings: ThousandEyesSourceMapping[],
): Candidate[] {
  const accountGroupId = requireAccountGroupId(event.aid, "account-group ID");
  const mapping = eventMapping(accountGroupId, mappings);
  if (!isEnabled(mapping, "event")) return [];
  const id = requireIdentity(event.id, "event ID");
  const startedAt = isoSeconds(event.startDate, "event start date");
  const endedAt =
    event.endDate === undefined ||
    event.endDate === null ||
    event.endDate === ""
      ? undefined
      : isoSeconds(event.endDate, "event end date");
  const sourceTimes = [
    sourceTimeField(event, ["startDate"], "iso8601", "event start date")!,
    ...(endedAt !== undefined
      ? [sourceTimeField(event, ["endDate"], "iso8601", "event end date")!]
      : []),
  ];
  if (endedAt !== undefined && endedAt < startedAt)
    fail("Event end date precedes its start date.");
  if (
    !intervalOverlapsSelection(
      startedAt,
      endedAt ?? startedAt,
      context.selection,
    )
  )
    return [];
  const affected = isObject(event.affectedTargets) ? event.affectedTargets : {};
  const relatedTestIds = optionalArrayField(
    affected,
    ["affectedTestIds"],
    "affected test IDs",
  ).map((value) => requireIdentity(value, "affected test ID"));
  const relatedAgentIds = optionalArrayField(
    affected,
    ["affectedAgentIds"],
    "affected agent IDs",
  ).map((value) => requireIdentity(value, "affected agent ID"));
  if (
    new Set(relatedTestIds).size !== relatedTestIds.length ||
    new Set(relatedAgentIds).size !== relatedAgentIds.length
  )
    fail("Event contains duplicate affected native identities.");
  const type =
    fieldText(event, ["type"], "event type") ??
    fieldText(event, ["typeName"], "event type name");
  const state = fieldText(event, ["state"], "event state");
  const severity = fieldText(event, ["severity"], "event severity");
  const title = fieldText(event, ["title"], "event title");
  const lifecycle = {
    id,
    ...(type ? { type } : {}),
    ...(state ? { state } : {}),
    startedAt,
    ...(endedAt !== undefined ? { endedAt } : {}),
    ...(severity ? { severity } : {}),
    ...(title ? { title } : {}),
    historyComplete: false,
  };
  const record = baseRecord(context, "event", mapping, {
    authorityBasis: "producer_account",
    eventTime: startedAt,
    interval: { start: startedAt, end: endedAt ?? startedAt },
    intervalBasis: "reported_event",
    complete: true,
    sourceTimes,
    lifecycle,
    relatedTestIds,
    relatedAgentIds,
    limitations: [
      "Event history completeness is not established by an indexed API event row.",
      ...(relatedTestIds.length || relatedAgentIds.length
        ? [
            "Affected test and agent IDs are preserved as context; they do not supply a target binding.",
          ]
        : [
            "This event has no source-native test or agent identity; names and host fields are not joined.",
          ]),
      "The vendor input does not explicitly set source or host; this row preserves its actual indexed source and sourcetype.",
    ],
  });
  return [
    {
      key: ["event", mapping.authority, mapping.accountGroupId, id].join(
        "\u0000",
      ),
      fingerprint: context.fingerprint,
      record,
    },
  ];
}

function parseAlertRecord(
  context: ParseContext,
  event: AnyObject,
  mappings: ThousandEyesSourceMapping[],
): Candidate[] {
  const alert = isObject(event.alert) ? event.alert : {};
  const rule = isObject(alert.rule) ? alert.rule : {};
  const account = isObject(rule.account) ? rule.account : {};
  const nestedOrganization = isObject(account.organization)
    ? account.organization.id
    : undefined;
  const rawAccountId =
    uniqueField(
      event,
      ["accountId", "thousandeyes_account_id"],
      "alert account ID",
    ) ?? account.id;
  const accountId = requireIdentity(rawAccountId, "alert account ID");
  const organizationId = requireIdentity(
    uniqueField(event, ["orgId", "organizationId"], "alert organization ID") ??
      nestedOrganization,
    "organization ID",
  );
  const mapping = alertMapping(accountId, organizationId, mappings);
  if (!isEnabled(mapping, "alert")) return [];
  const alertId = requireIdentity(
    alert.id ?? event.alertId ?? event.id,
    "alert ID",
  );
  const triggerValue = uniqueField(
    alert,
    ["triggered", "firstSeen"],
    "alert trigger time",
  );
  const triggerOuter =
    alert.triggered !== undefined ? "triggered" : "firstSeen";
  const triggerRaw = isObject(triggerValue)
    ? uniqueField(
        triggerValue,
        ["epochMilli", "epochMillis"],
        "alert trigger timestamp",
      )
    : triggerValue;
  const triggerInner = isObject(triggerValue)
    ? triggerValue.epochMilli !== undefined
      ? "epochMilli"
      : "epochMillis"
    : undefined;
  const trigger = isObject(triggerValue)
    ? epochMilliseconds(
        uniqueField(
          triggerValue,
          ["epochMilli", "epochMillis"],
          "alert trigger timestamp",
        ),
        "alert trigger timestamp",
      )
    : epochMilliseconds(triggerValue, "alert trigger timestamp");
  const clearValue = uniqueField(
    alert,
    ["cleared", "timeCleared"],
    "alert clear time",
  );
  const clearRaw = isObject(clearValue)
    ? uniqueField(
        clearValue,
        ["epochMilli", "epochMillis"],
        "alert clear timestamp",
      )
    : clearValue;
  const endedAt =
    clearRaw === undefined ||
    clearRaw === null ||
    clearRaw === "" ||
    clearRaw === false ||
    clearRaw === 0
      ? undefined
      : epochMilliseconds(clearRaw, "alert clear timestamp");
  const clearOuter = alert.cleared !== undefined ? "cleared" : "timeCleared";
  const clearInner = isObject(clearValue)
    ? clearValue.epochMilli !== undefined
      ? "epochMilli"
      : "epochMillis"
    : undefined;
  const sourceTimes = [
    sourceTimeValue(
      triggerRaw,
      `alert.${triggerOuter}${triggerInner ? `.${triggerInner}` : ""}`,
      "ms",
      "alert trigger timestamp",
    ),
    ...(endedAt !== undefined
      ? [
          sourceTimeValue(
            clearRaw,
            `alert.${clearOuter}${clearInner ? `.${clearInner}` : ""}`,
            "ms",
            "alert clear timestamp",
          ),
        ]
      : []),
  ];
  if (endedAt !== undefined && endedAt < trigger)
    fail("Alert clear time precedes its trigger time.");
  if (
    !intervalOverlapsSelection(trigger, endedAt ?? trigger, context.selection)
  )
    return [];
  const testIds = [
    event.testId,
    event.thousandeyes_test_id,
    isObject(alert.test) ? alert.test.id : undefined,
  ].filter((value) => value !== undefined && value !== null && value !== "");
  const normalizedTestIds = testIds.map((value) =>
    requireIdentity(value, "alert test ID"),
  );
  if (new Set(normalizedTestIds).size > 1)
    fail("Alert has conflicting native test IDs.");
  const testId = normalizedTestIds[0];
  const domain = testDomain(
    isObject(alert.test) ? alert.test.domain : undefined,
  );
  const stateValue = uniqueField(alert, ["cleared"], "alert state");
  const state =
    endedAt !== undefined || stateValue === true ? "cleared" : "triggered";
  const severityValue = uniqueField(alert, ["severity"], "alert severity");
  const severity = isObject(severityValue)
    ? fieldText(severityValue, ["name", "id"], "alert severity")
    : text(severityValue);
  const alertType = fieldText(rule, ["alertType"], "alert type");
  const title =
    fieldText(rule, ["name"], "alert rule name") ??
    fieldText(alert, ["test", "name"], "alert test name");
  const lifecycle = {
    id: alertId,
    ...(alertType ? { type: alertType } : {}),
    state,
    startedAt: trigger,
    ...(endedAt !== undefined ? { endedAt } : {}),
    ...(severity ? { severity } : {}),
    ...(title ? { title } : {}),
    historyComplete: false,
  };
  const target = alertTarget(alert);
  const record = baseRecord(context, "alert", mapping, {
    accountId,
    authorityBasis: "configured_account_binding",
    eventTime: trigger,
    interval: { start: trigger, end: endedAt ?? trigger },
    intervalBasis: "reported_event",
    ...(testId ? { testId } : {}),
    testDomain: domain,
    target,
    complete: true,
    sourceTimes,
    lifecycle,
    limitations: [
      "Alert lifecycle/history is preserved as supplied and does not establish current alert state or source completeness.",
      ...(testId
        ? []
        : [
            "This alert has no source-native test identity; names and host fields are not joined.",
          ]),
      ...(target.ip || target.hostname
        ? [
            "Alert target is source-reported target context and is not by itself a configured endpoint binding.",
          ]
        : []),
    ],
  });
  const eventId = text(event.eventId, 128);
  return [
    {
      key: [
        "alert",
        mapping.authority,
        accountId,
        organizationId,
        eventId ?? alertId,
        state,
        trigger,
        endedAt ?? "",
      ].join("\u0000"),
      fingerprint: context.fingerprint,
      record,
    },
  ];
}

function alertTarget(alert: AnyObject): ThousandEyesTarget {
  const targets = optionalArrayField(alert, ["targets"], "alert targets");
  if (targets.length !== 1 || !isObject(targets[0])) return {};
  const target = targets[0];
  const value = fieldText(
    target,
    ["description", "address", "name"],
    "alert target",
  );
  if (!value) return {};
  const attrs = new Map<string, unknown>([["server.address", value]]);
  return readTarget(attrs);
}

function pathEnvelope(
  context: ParseContext,
  raw: AnyObject,
  mapping: ThousandEyesSourceMapping,
): ParsedPathEnvelope | undefined {
  return rawPathEnvelope(raw, mapping);
}

function pathRows(
  context: ParseContext,
  raw: AnyObject,
  mapping: ThousandEyesSourceMapping,
): Candidate[] {
  const wrapped = pathEnvelope(context, raw, mapping);
  const result = wrapped?.result ?? raw;
  const accountGroupId = wrapped
    ? wrapped.accountGroupId
    : requireAccountGroupId(
        uniqueField(result, ["aid", "accountGroupId"], "path account-group ID"),
        "account-group ID",
      );
  const configured = eventMapping(accountGroupId, [mapping]);
  if (!isEnabled(configured, "path")) return [];
  const testId = wrapped
    ? wrapped.testId
    : requireIdentity(
        uniqueField(result, ["testId", "test_id"], "path test ID"),
        "test ID",
      );
  const agent = isObject(result.agent) ? result.agent : {};
  const agentId = requireIdentity(
    uniqueField(result, ["agentId", "agent_id"], "path agent ID") ??
      uniqueField(agent, ["agentId", "agent_id"], "path agent ID"),
    "agent ID",
  );
  const roundId = epochSeconds(
    uniqueField(result, ["roundId", "round_id"], "path round ID"),
    "path round ID",
  );
  const eventTime =
    result.date === undefined
      ? roundId
      : isoSeconds(result.date, "path result date");
  const startTime = optionalEpochSeconds(
    uniqueField(result, ["startTime", "start_time"], "path start time"),
    "path start time",
  );
  const endTime = optionalEpochSeconds(
    uniqueField(result, ["endTime", "end_time"], "path end time"),
    "path end time",
  );
  if (
    (startTime === undefined) !== (endTime === undefined) ||
    (startTime !== undefined && endTime !== undefined && endTime < startTime)
  )
    fail("Path result interval is incomplete or out of order.");
  const interval =
    startTime === undefined || endTime === undefined
      ? { start: roundId, end: roundId }
      : { start: startTime, end: endTime };
  if (
    !intervalOverlapsSelection(interval.start, interval.end, context.selection)
  )
    return [];
  const testName = fieldText(
    result,
    ["testName", "test_name"],
    "path test name",
  );
  const agentName = fieldText(agent, ["agentName", "name"], "path agent name");
  const agentLocation = fieldText(agent, ["location"], "path agent location");
  const target = pathTarget(result);
  const nativeDomain = testDomain(
    uniqueField(result, ["testDomain", "test_domain"], "path test domain"),
  );
  const pathTestDomain = wrapped?.testDomain ?? nativeDomain;
  const rawDirection = fieldText(result, ["direction"], "path direction");
  if (
    rawDirection !== undefined &&
    rawDirection !== "to-target" &&
    rawDirection !== "from-target"
  )
    fail("Unsupported native path direction.");
  const pathDirection = rawDirection;
  const targetIsProxy = result.targetIsProxy;
  if (targetIsProxy !== undefined && typeof targetIsProxy !== "boolean")
    fail("Invalid native targetIsProxy flag.");
  const sourceTimes = [
    ...(result.date !== undefined
      ? [sourceTimeField(result, ["date"], "iso8601", "path result date")!]
      : []),
    sourceTimeField(result, ["roundId", "round_id"], "s", "path round ID")!,
    ...(startTime !== undefined
      ? [
          sourceTimeField(
            result,
            ["startTime", "start_time"],
            "s",
            "path start time",
          )!,
        ]
      : []),
    ...(endTime !== undefined
      ? [
          sourceTimeField(
            result,
            ["endTime", "end_time"],
            "s",
            "path end time",
          )!,
        ]
      : []),
  ];
  const pathTraces = optionalArrayField(
    result,
    ["pathTraces", "path_traces"],
    "path traces",
  );
  const output: Candidate[] = [];
  if (!pathTraces.length) {
    const measurementRows = pathSummaryMeasurements(result);
    const record = baseRecord(context, "path", configured, {
      authorityBasis: wrapped
        ? "configured_account_binding"
        : "producer_account",
      eventTime,
      interval,
      intervalBasis: startTime === undefined ? "point" : "measurement",
      ...(wrapped?.capturedAt !== undefined
        ? { collectionTime: wrapped.capturedAt }
        : {}),
      target,
      testId,
      testDomain: pathTestDomain,
      agentId,
      testName,
      agentName,
      agentLocation,
      complete: false,
      sourceTimes,
      ...(pathDirection ? { pathDirection } : {}),
      ...(targetIsProxy !== undefined ? { targetIsProxy } : {}),
      measurements: measurementRows,
      limitations: [
        "The native record has no path trace details. Absence of hops does not indicate forwarding loss.",
      ],
    });
    output.push({
      key: [
        "path",
        configured.authority,
        accountGroupId,
        testId,
        agentId,
        roundId,
        "summary",
      ].join("\u0000"),
      fingerprint: context.fingerprint,
      record,
    });
    return output;
  }
  for (const pathTrace of pathTraces) {
    if (!isObject(pathTrace)) fail("Invalid native path trace.");
    const pathId = requireIdentity(
      uniqueField(pathTrace, ["pathId", "path_id"], "path trace ID"),
      "path trace ID",
    );
    const hopDetails = uniqueField(pathTrace, ["hops"], "path hops");
    const hasHopDetails = hopDetails !== undefined;
    const nativeHops = optionalArrayField(pathTrace, ["hops"], "path hops");
    const numberOfHops = uniqueField(
      pathTrace,
      ["numberOfHops", "number_of_hops"],
      "path hop count",
    );
    // Summary responses expose only destination RTT and hop count. They do
    // not identify intermediate hops, so never turn the count into fake
    // missing-hop observations. Only detail responses carry a `hops` array.
    const hops = hasHopDetails
      ? normalizeHops(nativeHops, numberOfHops, pathId)
      : [];
    const responseTime = uniqueField(
      pathTrace,
      ["responseTime", "response_time"],
      "path response time",
    );
    const hopCount =
      numberOfHops === undefined
        ? nativeHops.length
        : number(numberOfHops, "path hop count");
    const measurementRows: ThousandEyesMeasurement[] = [];
    if (responseTime !== undefined) {
      const measuredResponse = number(responseTime, "path response time");
      if (measuredResponse < 0) fail("Path response time is negative.");
      measurementRows.push({
        name: "path.round_trip_time",
        value: measuredResponse,
        unit: "ms",
        sourceUnit: "ms",
        aggregation: "reported_round_summary",
        direction: pathDirection ?? "not_reported",
        denominator: "not_applicable",
        timeBasis: "round",
      });
    }
    if (Number.isFinite(hopCount)) {
      measurementRows.push({
        name: "path.hop_count",
        value: hopCount,
        unit: "{count}",
        sourceUnit: "{count}",
        aggregation: "reported_round_summary",
        direction: pathDirection ?? "not_reported",
        denominator: "not_applicable",
        timeBasis: "round",
      });
    }
    const record = baseRecord(context, "path", configured, {
      authorityBasis: wrapped
        ? "configured_account_binding"
        : "producer_account",
      eventTime,
      interval,
      intervalBasis: startTime === undefined ? "point" : "measurement",
      ...(wrapped?.capturedAt !== undefined
        ? { collectionTime: wrapped.capturedAt }
        : {}),
      target,
      testId,
      testDomain: pathTestDomain,
      agentId,
      testName,
      agentName,
      agentLocation,
      outcome: fieldText(result, ["error"], "path outcome")
        ? "failure"
        : "unknown",
      complete:
        hasHopDetails &&
        nativeHops.length > 0 &&
        hops.every((hop) => !hop.missing),
      measurements: measurementRows,
      hops,
      sourceTimes,
      ...(pathDirection ? { pathDirection } : {}),
      ...(targetIsProxy !== undefined ? { targetIsProxy } : {}),
      limitations: [
        "Measured path hops are supplied by a ThousandEyes path visualization result, not inferred from inventory.",
        ...(hops.some((hop) => hop.missing)
          ? [
              "Unreported hop numbers are shown as missing; missing hops do not independently establish packet loss or forwarding loss.",
            ]
          : []),
        ...(!hasHopDetails || nativeHops.length === 0
          ? [
              "This path result contains no intermediate-hop detail; destination summary fields are not projected as hops, and their absence does not indicate forwarding loss.",
            ]
          : []),
        ...(targetIsProxy === true
          ? [
              "The agent reports that the trace target is a proxy; it may not be the final application destination.",
            ]
          : []),
      ],
      fingerprint: pathId
        ? `${context.fingerprint}:${pathId}`
        : context.fingerprint,
    });
    output.push({
      key: [
        "path",
        configured.authority,
        accountGroupId,
        testId,
        agentId,
        roundId,
        pathId ?? JSON.stringify(hops),
      ].join("\u0000"),
      fingerprint: context.fingerprint,
      record,
    });
  }
  return output;
}

function pathSummaryMeasurements(result: AnyObject): ThousandEyesMeasurement[] {
  const responseTime = uniqueField(
    result,
    ["responseTime", "response_time"],
    "path response time",
  );
  const numberOfHops = uniqueField(
    result,
    ["numberOfHops", "number_of_hops"],
    "path hop count",
  );
  const measurements: ThousandEyesMeasurement[] = [];
  if (responseTime !== undefined) {
    measurements.push({
      name: "path.round_trip_time",
      value: number(responseTime, "path response time"),
      unit: "ms",
      sourceUnit: "ms",
      aggregation: "reported_round_summary",
      direction: "not_reported",
      denominator: "not_applicable",
      timeBasis: "round",
    });
  }
  if (numberOfHops !== undefined) {
    measurements.push({
      name: "path.hop_count",
      value: number(numberOfHops, "path hop count"),
      unit: "{count}",
      sourceUnit: "{count}",
      aggregation: "reported_round_summary",
      direction: "not_reported",
      denominator: "not_applicable",
      timeBasis: "round",
    });
  }
  return measurements;
}

function normalizeHops(
  values: unknown[],
  numberOfHops: unknown,
  pathId: string,
): ThousandEyesHop[] {
  const parsed = values.map(
    (value): { number: number; hop: ThousandEyesHop } => {
      if (!isObject(value)) fail("Invalid native path hop.");
      const index = number(
        uniqueField(value, ["hop", "number", "hopNumber"], "hop number"),
        "hop number",
      );
      if (!Number.isSafeInteger(index) || index < 1 || index > 255)
        fail("Invalid native path hop number.");
      const ipValue = fieldText(
        value,
        ["ipAddress", "ip_address", "ip"],
        "hop IP address",
      );
      let ip: string | undefined;
      if (ipValue) {
        try {
          ip = normalizeIp(ipValue);
        } catch {
          fail("Invalid native path hop address.");
        }
      }
      const responseTime = uniqueField(
        value,
        ["responseTime", "response_time"],
        "hop response time",
      );
      const latencyMilliseconds =
        responseTime === undefined
          ? undefined
          : number(responseTime, "hop response time");
      if (latencyMilliseconds !== undefined && latencyMilliseconds < 0)
        fail("Negative path hop response time.");
      const hop: ThousandEyesHop = {
        pathId,
        number: index,
        ...(ip ? { ip } : {}),
        ...(fieldText(value, ["rdns", "name"], "hop name")
          ? { name: fieldText(value, ["rdns", "name"], "hop name") }
          : {}),
        ...(fieldText(value, ["prefix"], "hop prefix")
          ? { prefix: fieldText(value, ["prefix"], "hop prefix") }
          : {}),
        ...(fieldText(value, ["network"], "hop network")
          ? { network: fieldText(value, ["network"], "hop network") }
          : {}),
        ...(latencyMilliseconds !== undefined ? { latencyMilliseconds } : {}),
        missing: false,
      };
      return { number: index, hop };
    },
  );
  parsed.sort((left, right) => left.number - right.number);
  if (new Set(parsed.map(({ number: index }) => index)).size !== parsed.length)
    fail("Native path result contains duplicate hop numbers.");
  const expected =
    numberOfHops === undefined
      ? (parsed.at(-1)?.number ?? 0)
      : number(numberOfHops, "path hop count");
  if (!Number.isSafeInteger(expected) || expected < 0 || expected > 255)
    fail("Invalid path hop count.");
  if (parsed.some(({ number: index }) => index > expected && expected > 0))
    fail("A native hop number exceeds the reported hop count.");
  const byNumber = new Map(
    parsed.map(({ number: index, hop }) => [index, hop]),
  );
  return Array.from(
    { length: expected },
    (_, index) =>
      byNumber.get(index + 1) ?? {
        pathId,
        number: index + 1,
        missing: true,
      },
  );
}

function selectedAlertEvent(event: AnyObject): AnyObject {
  return event;
}

function familyCandidates(
  context: ParseContext,
  mappings: ThousandEyesSourceMapping[],
): Candidate[] {
  const family = expectedFamily(
    context.sourcetype,
    context.source,
    context.index,
    context.mapping,
  );
  if (!family || !context.mapping.families.includes(family)) return [];
  switch (family) {
    case "metric":
      return parseMetricRecord(context, context.raw, mappings);
    case "trace":
      return parseTraceRecord(context, context.raw, mappings);
    case "activity":
      return parseActivityRecord(context, context.raw, mappings);
    case "event":
      return parseEventRecord(context, context.event, mappings);
    case "alert":
      return parseAlertRecord(
        context,
        selectedAlertEvent(context.event),
        mappings,
      );
    case "path":
      return pathRows(context, context.raw, context.mapping);
  }
}

function candidateContext(
  row: Row,
  config: SupplementalSourceConfiguration,
  mappings: ThousandEyesSourceMapping[],
  selection: EvidenceSelection,
): ParseContext {
  const origin = rowOrigin(row, config);
  const mappingCandidates = mappings.filter((candidate) => {
    const family = expectedFamily(
      origin.sourcetype,
      origin.source,
      origin.index,
      candidate,
    );
    return !!family && candidate.families.includes(family);
  });
  if (!mappingCandidates.length)
    fail("Indexed source is not configured for a ThousandEyes family.");
  const mapping = mappingCandidates[0];
  const raw = parseRaw(row);
  const rawEnvelope =
    raw.schema === SCHEMA_PATH && isObject(raw.event) ? raw.event : raw;
  if (rawEnvelope !== raw) {
    if (raw.schema !== SCHEMA_PATH || raw.schema_version !== 1)
      fail("Unsupported Atlas path capture wrapper.");
  }
  const family = expectedFamily(
    origin.sourcetype,
    origin.source,
    origin.index,
    mapping,
  );
  if (!family || !mapping.families.includes(family))
    fail("Row producer/schema is not explicitly enabled.");
  const event =
    family === "event" || family === "alert"
      ? isObject(rawEnvelope.event)
        ? rawEnvelope.event
        : rawEnvelope
      : rawEnvelope;
  const { indexedTime, rowTime } = checkedTimes(row);
  const truncated =
    boolRow(row.record_truncated) ||
    boolRow(row.input_capped) ||
    boolRow(row.output_capped);
  return {
    row,
    raw: family === "path" && raw.schema === SCHEMA_PATH ? raw : rawEnvelope,
    event,
    ...origin,
    fingerprint: checkedFingerprint(row),
    indexedTime,
    rowTime,
    truncated,
    mapping,
    selection,
    config,
  };
}

/** Strict, versioned producer adapters. Unknown source types and identities are rejected. */
export function normalizeThousandEyesRows(
  rows: readonly Row[],
  input: EvidenceSelection,
  config: SupplementalSourceConfiguration,
): { records: ThousandEyesObservation[]; rejected: number } {
  const selection = validateSelection(input);
  const mappings = selectedMappings(config, selection);
  if (!Array.isArray(rows) || rows.length > MAX_ADAPTER_OUTPUT)
    return { records: [], rejected: Array.isArray(rows) ? rows.length : 1 };
  const candidates: Candidate[] = [];
  let rejected = 0;
  for (const row of rows) {
    if (!isObject(row) || row.kind !== "supplemental_record") {
      rejected += 1;
      continue;
    }
    try {
      const context = candidateContext(row, config, mappings, selection);
      const produced = familyCandidates(context, mappings);
      if (produced.length > MAX_ADAPTER_OUTPUT - candidates.length) {
        rejected += 1;
        continue;
      }
      candidates.push(...produced);
    } catch (error) {
      if (error instanceof RecordError) {
        rejected += 1;
        continue;
      }
      throw error;
    }
  }
  const byKey = new Map<string, Candidate>();
  const conflicts = new Map<string, Candidate[]>();
  for (const candidate of candidates) {
    const conflictingRecords = conflicts.get(candidate.key);
    if (conflictingRecords) {
      if (
        !conflictingRecords.some(
          (existing) =>
            existing.fingerprint === candidate.fingerprint &&
            sameObservation(existing.record, candidate.record),
        )
      ) {
        conflictingRecords.push(candidate);
        rejected += 1;
      }
      continue;
    }
    const previous = byKey.get(candidate.key);
    if (!previous) {
      byKey.set(candidate.key, candidate);
      continue;
    }
    if (
      previous.fingerprint === candidate.fingerprint &&
      sameObservation(previous.record, candidate.record)
    )
      continue;
    byKey.delete(candidate.key);
    conflicts.set(candidate.key, [previous, candidate]);
    rejected += 2;
  }
  const conflictRecords = [...conflicts.values()].flatMap((entries) =>
    entries.map(({ record }) => ({
      ...record,
      quality: { ...record.quality, conflicting: true },
      limitations: [
        ...record.limitations,
        "Conflicting producer rows share one native observation identity; retain as context without using this measurement for attribution or comparison.",
      ],
    })),
  );
  const records = [
    ...[...byKey.values()].map(({ record }) => record),
    ...conflictRecords,
  ].sort(
    (left, right) =>
      left.eventTime - right.eventTime ||
      left.family.localeCompare(right.family) ||
      left.fingerprint.localeCompare(right.fingerprint),
  );
  return { records, rejected };
}

function sameObservation(
  left: ThousandEyesObservation,
  right: ThousandEyesObservation,
): boolean {
  const omitObservationProvenance = (record: ThousandEyesObservation) =>
    Object.fromEntries(
      Object.entries(record).filter(
        ([key]) =>
          key !== "indexedTime" && key !== "rowTime" && key !== "fingerprint",
      ),
    );
  const leftContent = omitObservationProvenance(left);
  const rightContent = omitObservationProvenance(right);
  return JSON.stringify(leftContent) === JSON.stringify(rightContent);
}
