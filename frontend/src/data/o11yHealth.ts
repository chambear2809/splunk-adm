import type { Row } from "../rows";
import {
  configuredHttpsOrigin,
  evidenceConfigClient,
  type EvidenceConfigClient,
  type SupplementalSourceConfiguration,
} from "./evidenceConfig";
import {
  EVIDENCE_LIMITS,
  fingerprint,
  isObject,
  literal,
  routingScope,
  validateServiceHealthSelection,
  type EvidenceWindow,
  type ServiceHealthSelection,
} from "./evidence";
import { indexNames } from "./deploymentHealth";
import { optionalJobs } from "./optionalJobs";
import { parseSupplementalEnvelope } from "./supplementalEvidence";
import { requireNoSearchErrors, type SearchClient } from "./searchClient";

export const O11Y_HEALTH_SCHEMA = "application_atlas.o11y_health.v1";
export const O11Y_HEALTH_SOURCETYPE = "atlas:o11y_health";
export const O11Y_HEALTH_RECORD_LIMIT = EVIDENCE_LIMITS.records;
export const O11Y_HEALTH_INPUT_LIMIT = EVIDENCE_LIMITS.input;
export const O11Y_HEALTH_RECORD_BYTES = EVIDENCE_LIMITS.recordBytes;

/** Return a verified configured origin or the realm's Observability app root. */
export function observabilityOrigin(
  realm: string,
  configured?: string,
): string | undefined {
  if (configured !== undefined) {
    try {
      return configuredHttpsOrigin(configured);
    } catch {
      return undefined;
    }
  }
  if (!/^[a-z][a-z0-9]{0,7}$/.test(realm)) return undefined;
  return `https://app.${realm}.observability.splunkcloud.com/`;
}

const OBSERVER_KIND = "o11y_export";
const COVERAGE = [
  "Request count and error count are one time-aligned histogram count per SignalFlow resolution bucket; they are not totals across the selected window. Request p90 is computed from the service.request histogram and is expressed in nanoseconds for the qualified OTel APM schema.",
  "Container CPU and JVM memory are included only when those metrics carry the same exact service, environment, cluster, Kubernetes namespace and OTel service.namespace dimensions.",
  "A completed empty export or absent metric is missing telemetry, not a zero or healthy result.",
  "Detector and alert state is not queried by this metric export.",
  "Metrics are historical context and do not establish a network cause.",
];

export type O11yMetricLabel =
  | "request_count"
  | "request_errors"
  | "request_latency_p90"
  | "container_cpu_utilization"
  | "jvm_memory_used";

interface MetricContract {
  metric: string;
  statistic: string;
  aggregation: string;
  expectedUnit: string;
}

const METRICS: Record<O11yMetricLabel, MetricContract> = {
  request_count: {
    metric: "service.request",
    statistic: "count",
    aggregation: "histogram.count(by=apm_service_dimensions)",
    expectedUnit: "count",
  },
  request_errors: {
    metric: "service.request",
    statistic: "count",
    aggregation: "histogram.count(by=apm_service_dimensions, sf_error=true)",
    expectedUnit: "count",
  },
  request_latency_p90: {
    metric: "service.request",
    statistic: "percentile_90",
    aggregation: "histogram.percentile(pct=90, by=apm_service_dimensions)",
    expectedUnit: "ns",
  },
  container_cpu_utilization: {
    metric: "container.cpu.utilization",
    statistic: "mean",
    aggregation: "data.mean(by=service_identity_dimensions)",
    expectedUnit: "1",
  },
  jvm_memory_used: {
    metric: "jvm.memory.used",
    statistic: "mean",
    aggregation: "data.mean(by=service_identity_dimensions)",
    expectedUnit: "By",
  },
};

export interface O11yHealthObservation {
  schemaVersion: 1;
  source: "o11y_health";
  kind: "metric" | "export_completion";
  schema: typeof O11Y_HEALTH_SCHEMA;
  scope: string;
  observer: string;
  organizationId: string;
  realm: string;
  apmMmsId?: string;
  index: string;
  eventFingerprint: string;
  recordId: string;
  eventTime: number;
  indexedTime: number;
  captureId: string;
  capturedAt: number;
  captureWindow: EvidenceWindow;
  service: ServiceHealthSelection["service"];
  metric?: string;
  metricSourceBasis?: "sf_originatingMetric" | "fixed_signalflow_program";
  signalLabel?: O11yMetricLabel;
  statistic?: string;
  unit?: string;
  aggregation?: string;
  resolutionSeconds?: number;
  logicalTimestamp?: number;
  value?: number;
  sourceDimensions?: {
    serviceNamespace: string;
    sfMmsId?: string;
    sfDimensionalized?: string;
    sfService?: string;
    sfEnvironment?: string;
    sfError?: string;
    podUid?: string;
    containerName?: string;
    hostName?: string;
    jvmMemoryPoolName?: string;
  };
  expectedRecordCount?: number;
  signalsWithData?: number;
  detectorAlerts: "not_queried";
  limitations: string[];
}

export interface O11yHealthResult {
  schemaVersion: 1;
  source: "o11y_health";
  selection: ServiceHealthSelection;
  capturedAt: number;
  inspectedWindow: EvidenceWindow;
  configurationFingerprint: string;
  configurationChanged: boolean;
  /** Configured authority origin; never inferred from event content. */
  observabilityOrigin?: string;
  state: "not_selected" | "staged" | "complete" | "unavailable";
  schemaQualified: boolean;
  inputCount: number;
  inputCapped: boolean;
  outputCapped: boolean;
  rejected: number;
  replayDuplicates: number;
  oversized: number;
  records: O11yHealthObservation[];
  coverage: string[];
  errorCode?: "configuration" | "execution" | "completion" | "normalization";
  error?: string;
}

function jsonField(name: string): string {
  if (!/^[a-z][a-z0-9_]*$/.test(name))
    throw new Error("Invalid Observability Cloud field selector.");
  return `json_extract(_raw,"${name}")`;
}

function sourceAuthority(
  config: SupplementalSourceConfiguration,
  selection: ServiceHealthSelection,
) {
  if (
    config.source !== "o11y_health" ||
    config.state !== "active" ||
    config.error ||
    config.schemaQualified !== true ||
    !Number.isFinite(config.staleAfterSeconds) ||
    config.staleAfterSeconds < 60 ||
    config.staleAfterSeconds > EVIDENCE_LIMITS.window ||
    !Array.isArray(config.authorities) ||
    !Array.isArray(config.mappings)
  )
    throw new Error(
      "Observability Cloud health is not active and schema-qualified.",
    );

  const candidates = config.mappings.filter(
    (mapping) =>
      mapping.observer_kind === OBSERVER_KIND &&
      mapping.scope === selection.scope &&
      mapping.cluster === selection.service.cluster &&
      mapping.mapping_status === "verified",
  );
  if (candidates.length > 1)
    throw new Error(
      "Multiple verified Observability Cloud organizations or realms map to this scope and cluster. Narrow the configured authority before querying.",
    );
  if (candidates.length !== 1)
    throw new Error(
      "No uniquely verified Observability Cloud authority maps to this service scope and cluster.",
    );
  const mapping = candidates[0];
  literal(mapping.observer);
  literal(mapping.organization_id ?? "");
  const realm = mapping.realm ?? "";
  if (!/^[a-z][a-z0-9]{0,7}$/.test(realm))
    throw new Error("The mapped Observability Cloud realm is invalid.");
  const apmMmsId = mapping.apm_mms_id ?? "";
  if (!/^[A-Za-z0-9._:-]{1,128}$/.test(apmMmsId))
    throw new Error("The mapped APM MMS ID is invalid.");
  routingScope(mapping.scope);
  const mappedOrigin = observabilityOrigin(realm, mapping.observability_origin);
  if (
    config.authorities.filter((authority) => authority === mapping.observer)
      .length !== 1 ||
    config.mappings.filter(
      (other) =>
        other.observer_kind === OBSERVER_KIND &&
        other.observer === mapping.observer,
    ).length !== 1
  )
    throw new Error(
      "Observability Cloud authority mapping is ambiguous or conflicting.",
    );
  return {
    observer: mapping.observer,
    organizationId: mapping.organization_id!,
    realm,
    apmMmsId,
    ...(mappedOrigin ? { observabilityOrigin: mappedOrigin } : {}),
  };
}

function checkedIndex(config: SupplementalSourceConfiguration): string {
  const definition =
    config.indexes.length === 1
      ? `index=${config.indexes[0]}`
      : `(${config.indexes.map((value) => `index=${value}`).join(" OR ")})`;
  const indexes = indexNames({ name: "adm_index_o11y_health", definition });
  if (
    !indexes.length ||
    indexes.length > 16 ||
    indexes.length !== config.indexes.length ||
    new Set(indexes).size !== indexes.length
  )
    throw new Error(
      "Observability Cloud health index configuration is invalid.",
    );
  return indexes.length === 1
    ? `index=${indexes[0]}`
    : `(${indexes.map((name) => `index=${name}`).join(" OR ")})`;
}

const PROJECTED_FIELDS = [
  "schema",
  "event_type",
  "capture_id",
  "record_id",
  "captured_at",
  "capture_window_start",
  "capture_window_end",
  "observer_id",
  "organization_id",
  "realm",
  "routing_scope",
  "service_name",
  "environment",
  "cluster",
  "kubernetes_namespace",
  "service_namespace",
  "apm_mms_id",
  "sf_mms_id",
  "sf_dimensionalized",
  "signal_label",
  "metric_name",
  "metric_source_basis",
  "statistic",
  "unit",
  "aggregation",
  "resolution_seconds",
  "logical_timestamp",
  "value",
  "sf_service",
  "sf_environment",
  "sf_error",
  "pod_uid",
  "container_name",
  "host_name",
  "jvm_memory_pool_name",
  "expected_record_count",
  "signals_with_data",
] as const;

function projectedRecord(): string {
  return `json_object(${PROJECTED_FIELDS.flatMap((field) => [`"${field}"`, jsonField(field)]).join(",")})`;
}

/** Build a bounded SPL projection for the versioned atomic HEC export contract. */
export function buildO11yHealthSearch(
  config: SupplementalSourceConfiguration,
  input: ServiceHealthSelection,
): string {
  const selection = validateServiceHealthSelection(input);
  const authority = sourceAuthority(config, selection);
  const index = checkedIndex(config);
  const service = selection.service;
  const identity = [
    ["service_name", service.name],
    ["environment", service.environment],
    ["cluster", service.cluster],
    ["kubernetes_namespace", service.namespace],
  ] as const;
  const identityFilter = identity
    .map(([field, value]) => `${jsonField(field)}="${literal(value)}"`)
    .join(" AND ");
  const serviceNamespaceFilter = service.serviceNamespace
    ? ` AND ${jsonField("service_namespace")}="${literal(service.serviceNamespace)}"`
    : "";
  const redLabelFilter = [
    "request_count",
    "request_errors",
    "request_latency_p90",
  ]
    .map((label) => `${jsonField("signal_label")}="${label}"`)
    .join(" OR ");
  const runtimeLabelFilter = ["container_cpu_utilization", "jvm_memory_used"]
    .map((label) => `${jsonField("signal_label")}="${label}"`)
    .join(" OR ");
  const redIdentityFilter = `${jsonField("apm_mms_id")}="${literal(authority.apmMmsId)}" AND ${jsonField("sf_mms_id")}="${literal(authority.apmMmsId)}" AND ${jsonField("sf_dimensionalized")}="true"`;
  const completionFilter = `${jsonField("event_type")}="export_completion" AND ${redIdentityFilter}`;
  const redFilter = `${jsonField("event_type")}="metric" AND (${redLabelFilter}) AND ${redIdentityFilter}`;
  const runtimeFilter = `${jsonField("event_type")}="metric" AND (${runtimeLabelFilter}) AND isnull(${jsonField("apm_mms_id")}) AND isnull(${jsonField("sf_mms_id")}) AND isnull(${jsonField("sf_dimensionalized")})`;
  const streamContractFilter = `(${completionFilter} OR ${redFilter} OR ${runtimeFilter})`;
  const projected = projectedRecord();
  return `search ${index} sourcetype="${O11Y_HEALTH_SOURCETYPE}" host="${authority.observer}" earliest=-${config.staleAfterSeconds}s latest=now
| where ${jsonField("schema")}="${O11Y_HEALTH_SCHEMA}" AND ${streamContractFilter} AND ${jsonField("observer_id")} = host AND ${jsonField("observer_id")}="${authority.observer}" AND ${jsonField("organization_id")}="${authority.organizationId}" AND ${jsonField("realm")}="${authority.realm}" AND ${jsonField("routing_scope")}="${literal(selection.scope)}" AND ${identityFilter} AND tonumber(${jsonField("capture_window_start")})=${selection.window.start} AND tonumber(${jsonField("capture_window_end")})=${selection.window.end}${serviceNamespaceFilter}
| eval adm_capture_time=tonumber(${jsonField("captured_at")})
| eventstats max(adm_capture_time) AS adm_latest_capture
| where adm_capture_time=adm_latest_capture
| head ${O11Y_HEALTH_INPUT_LIMIT + 1}
| eval event_time_epoch=tonumber(_time),indexed_time_epoch=tonumber(_indextime),event_fingerprint=if(isnotnull(_bkt) AND isnotnull(_cd),sha256(json_array(index,_bkt,_cd)),null()),oversized=if(len(_raw)>${O11Y_HEALTH_RECORD_BYTES},1,0)
| eventstats count AS input_count sum(oversized) AS oversized_count
| sort 0 - _time index event_fingerprint
| head ${O11Y_HEALTH_RECORD_LIMIT}
| eval _raw=if(oversized=1,"{}",${projected})
| fields _raw _time _indextime event_time_epoch indexed_time_epoch host index event_fingerprint oversized input_count oversized_count
| eval kind="supplemental_record"
| appendpipe [| stats count AS returned_count max(input_count) AS input_count max(oversized_count) AS oversized
  | eval kind="supplemental_completion",schema_version=1,input_count=coalesce(input_count,0),input_capped=if(input_count>${O11Y_HEALTH_INPUT_LIMIT},1,0),oversized=coalesce(oversized,0)]`;
}

function first(value: unknown): unknown {
  return Array.isArray(value) ? value[0] : value;
}

function canonicalJson(value: unknown): string {
  const canonicalize = (item: unknown): unknown => {
    if (Array.isArray(item)) return item.map(canonicalize);
    if (isObject(item))
      return Object.fromEntries(
        Object.keys(item)
          .sort()
          .map((key) => [key, canonicalize(item[key])]),
      );
    return item;
  };
  return JSON.stringify(canonicalize(value));
}

function text(value: unknown, max = 1024): string | undefined {
  value = first(value);
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > max ||
    Array.from(value).some(
      (character) =>
        character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127,
    )
  )
    return undefined;
  return value;
}

function numeric(value: unknown): number | undefined {
  value = first(value);
  if (typeof value === "boolean" || value === null || value === undefined)
    return undefined;
  if (typeof value !== "number" && typeof value !== "string") return undefined;
  if (typeof value === "string" && !/^-?\d+(?:\.\d+)?$/.test(value))
    return undefined;
  const result = Number(value);
  return Number.isFinite(result) ? result : undefined;
}

function rawObject(row: Row): Record<string, unknown> | undefined {
  const raw = first(row._raw);
  if (isObject(raw)) return raw;
  if (typeof raw !== "string" || raw.length > O11Y_HEALTH_RECORD_BYTES)
    return undefined;
  try {
    const parsed: unknown = JSON.parse(raw);
    return isObject(parsed) ? parsed : undefined;
  } catch {
    return undefined;
  }
}

function captureWindow(
  raw: Record<string, unknown>,
): EvidenceWindow | undefined {
  const start = numeric(raw.capture_window_start);
  const end = numeric(raw.capture_window_end);
  if (
    start === undefined ||
    end === undefined ||
    start < 0 ||
    end <= start ||
    end - start > EVIDENCE_LIMITS.window
  )
    return undefined;
  return { start, end };
}

function metricLabel(value: unknown): O11yMetricLabel | undefined {
  const label = text(value, 64);
  return label && Object.hasOwn(METRICS, label)
    ? (label as O11yMetricLabel)
    : undefined;
}

function verifiedIdentity(
  raw: Record<string, unknown>,
  selection: ServiceHealthSelection,
  authority: {
    observer: string;
    organizationId: string;
    realm: string;
    apmMmsId: string;
  },
) {
  const service = selection.service;
  return (
    text(raw.observer_id, 255) === authority.observer &&
    text(raw.organization_id, 255) === authority.organizationId &&
    text(raw.realm, 8) === authority.realm &&
    text(raw.routing_scope, 253) === selection.scope &&
    text(raw.service_name, 255) === service.name &&
    text(raw.environment, 255) === service.environment &&
    text(raw.cluster, 255) === service.cluster &&
    text(raw.kubernetes_namespace, 255) === service.namespace &&
    (service.serviceNamespace === undefined ||
      text(raw.service_namespace, 255) === service.serviceNamespace)
  );
}

function sourceDimensions(raw: Record<string, unknown>) {
  const serviceNamespace = text(raw.service_namespace, 255);
  if (!serviceNamespace) return undefined;
  const sfMmsId = text(raw.sf_mms_id, 128);
  const sfDimensionalized = text(raw.sf_dimensionalized, 8);
  const sfService = text(raw.sf_service, 255);
  const sfEnvironment = text(raw.sf_environment, 255);
  const sfError = text(raw.sf_error, 16);
  const podUid = text(raw.pod_uid, 255);
  const containerName = text(raw.container_name, 255);
  const hostName = text(raw.host_name, 255);
  const jvmMemoryPoolName = text(raw.jvm_memory_pool_name, 255);
  return {
    serviceNamespace,
    ...(sfMmsId ? { sfMmsId } : {}),
    ...(sfDimensionalized ? { sfDimensionalized } : {}),
    ...(sfService ? { sfService } : {}),
    ...(sfEnvironment ? { sfEnvironment } : {}),
    ...(sfError ? { sfError } : {}),
    ...(podUid ? { podUid } : {}),
    ...(containerName ? { containerName } : {}),
    ...(hostName ? { hostName } : {}),
    ...(jvmMemoryPoolName ? { jvmMemoryPoolName } : {}),
  };
}

function indexedTimes(row: Row, raw: Record<string, unknown>) {
  // Splunk's REST results can serialize `_time` as ISO text. Keep this
  // comparison numeric by projecting the internal epoch values in SPL.
  const eventTime = numeric(row.event_time_epoch);
  const capturedAt = numeric(raw.captured_at);
  const indexedTime = numeric(row.indexed_time_epoch);
  if (
    eventTime === undefined ||
    capturedAt === undefined ||
    indexedTime === undefined ||
    eventTime < 0 ||
    indexedTime < 0 ||
    Math.abs(eventTime - capturedAt) > 1
  )
    return undefined;
  return { eventTime, capturedAt, indexedTime };
}

/** Normalize only a complete, uniquely mapped capture; any rejected row drops the capture. */
export function normalizeO11yHealthEvidence(
  rows: readonly Row[],
  input: ServiceHealthSelection,
  config: SupplementalSourceConfiguration,
): {
  records: O11yHealthObservation[];
  rejected: number;
  replayDuplicates: number;
} {
  const selection = validateServiceHealthSelection(input);
  const authority = sourceAuthority(config, selection);
  if (rows.length > O11Y_HEALTH_INPUT_LIMIT)
    throw new Error(
      "Observability Cloud normalizer input exceeds its row cap.",
    );
  if (rows.length === 0)
    return { records: [], rejected: 0, replayDuplicates: 0 };

  let rejected = 0;
  let replayDuplicates = 0;
  let completionCount = 0;
  let expectedRecords: number | undefined;
  let signalsWithData: number | undefined;
  let captureId: string | undefined;
  let capturedAt: number | undefined;
  const recordsById = new Map<
    string,
    { canonical: string; eventTime: number; host: string }
  >();
  const metrics: O11yHealthObservation[] = [];
  let completion: O11yHealthObservation | undefined;
  for (const row of rows) {
    const raw = rawObject(row);
    const index = text(row.index, 128);
    const host = text(row.host, 255);
    const eventFingerprint = text(row.event_fingerprint, 64);
    const times = raw ? indexedTimes(row, raw) : undefined;
    const window = raw ? captureWindow(raw) : undefined;
    const sourceKind = text(raw?.event_type, 32);
    if (
      !raw ||
      !index ||
      !host ||
      !eventFingerprint ||
      !/^[a-f0-9]{64}$/.test(eventFingerprint) ||
      !times ||
      !window ||
      raw.schema !== O11Y_HEALTH_SCHEMA ||
      !verifiedIdentity(raw, selection, authority) ||
      host !== authority.observer ||
      window.start !== selection.window.start ||
      window.end !== selection.window.end ||
      !/^[a-z][a-z0-9_-]{0,79}$/.test(index) ||
      !config.indexes.includes(index)
    ) {
      rejected++;
      continue;
    }
    const id = text(raw.capture_id, 128);
    const recordId = text(raw.record_id, 64);
    if (!id || !recordId || !/^[a-f0-9]{64}$/.test(recordId)) {
      rejected++;
      continue;
    }
    if (captureId !== undefined && captureId !== id) {
      rejected++;
      continue;
    }
    captureId = id;
    if (capturedAt !== undefined && capturedAt !== times.capturedAt) {
      rejected++;
      continue;
    }
    capturedAt = times.capturedAt;
    const canonical = canonicalJson(raw);
    const previousRecord = recordsById.get(recordId);
    if (previousRecord) {
      if (
        previousRecord.canonical === canonical &&
        previousRecord.eventTime === times.eventTime &&
        previousRecord.host === host
      ) {
        replayDuplicates++;
        continue;
      }
      rejected++;
      continue;
    }
    recordsById.set(recordId, {
      canonical,
      eventTime: times.eventTime,
      host,
    });
    const common = {
      schemaVersion: 1 as const,
      source: "o11y_health" as const,
      schema: O11Y_HEALTH_SCHEMA as typeof O11Y_HEALTH_SCHEMA,
      scope: selection.scope,
      observer: authority.observer,
      organizationId: authority.organizationId,
      realm: authority.realm,
      index,
      eventFingerprint,
      recordId,
      eventTime: times.eventTime,
      indexedTime: times.indexedTime,
      captureId: id,
      capturedAt: times.capturedAt,
      captureWindow: window,
      service: selection.service,
      detectorAlerts: "not_queried" as const,
      limitations: [...COVERAGE],
    };
    if (sourceKind === "export_completion") {
      completionCount++;
      const count = numeric(raw.expected_record_count);
      const signals = numeric(raw.signals_with_data);
      if (
        text(raw.apm_mms_id, 128) !== authority.apmMmsId ||
        text(raw.sf_mms_id, 128) !== authority.apmMmsId ||
        text(raw.sf_dimensionalized, 8) !== "true" ||
        count === undefined ||
        !Number.isSafeInteger(count) ||
        count < 0 ||
        count > O11Y_HEALTH_RECORD_LIMIT - 1 ||
        signals === undefined ||
        !Number.isSafeInteger(signals) ||
        signals < 0 ||
        signals > Object.keys(METRICS).length
      ) {
        rejected++;
        continue;
      }
      expectedRecords = count;
      signalsWithData = signals;
      completion = {
        ...common,
        kind: "export_completion",
        apmMmsId: authority.apmMmsId,
        expectedRecordCount: count,
        signalsWithData: signals,
      };
      continue;
    }
    if (sourceKind !== "metric") {
      rejected++;
      continue;
    }
    const label = metricLabel(raw.signal_label);
    const contract = label ? METRICS[label] : undefined;
    const metric = text(raw.metric_name, 128);
    const statistic = text(raw.statistic, 64);
    const unit = text(raw.unit, 64);
    const aggregation = text(raw.aggregation, 256);
    const resolution = numeric(raw.resolution_seconds);
    const logicalTimestamp = numeric(raw.logical_timestamp);
    const value = numeric(raw.value);
    const dimensions = sourceDimensions(raw);
    const requiresApmMms =
      label === "request_count" ||
      label === "request_errors" ||
      label === "request_latency_p90";
    if (
      !label ||
      !contract ||
      (requiresApmMms &&
        (text(raw.apm_mms_id, 128) !== authority.apmMmsId ||
          dimensions?.sfMmsId !== authority.apmMmsId ||
          dimensions?.sfDimensionalized !== "true")) ||
      (!requiresApmMms &&
        (text(raw.apm_mms_id, 128) !== undefined ||
          dimensions?.sfMmsId !== undefined ||
          dimensions?.sfDimensionalized !== undefined)) ||
      metric !== contract.metric ||
      statistic !== contract.statistic ||
      aggregation !== contract.aggregation ||
      unit !== contract.expectedUnit ||
      !["sf_originatingMetric", "fixed_signalflow_program"].includes(
        text(raw.metric_source_basis, 64) ?? "",
      ) ||
      !unit ||
      resolution === undefined ||
      resolution <= 0 ||
      logicalTimestamp === undefined ||
      logicalTimestamp < selection.window.start ||
      logicalTimestamp > selection.window.end ||
      value === undefined ||
      value < 0 ||
      !dimensions
    ) {
      rejected++;
      continue;
    }
    metrics.push({
      ...common,
      kind: "metric",
      ...(requiresApmMms ? { apmMmsId: authority.apmMmsId } : {}),
      metric,
      metricSourceBasis: raw.metric_source_basis as
        "sf_originatingMetric" | "fixed_signalflow_program",
      signalLabel: label,
      statistic,
      unit,
      aggregation,
      resolutionSeconds: resolution,
      logicalTimestamp,
      value,
      sourceDimensions: dimensions,
    });
  }
  if (
    rejected > 0 ||
    completionCount !== 1 ||
    expectedRecords === undefined ||
    signalsWithData === undefined ||
    metrics.length !== expectedRecords ||
    captureId === undefined ||
    !completion
  )
    return {
      records: [],
      rejected: Math.max(1, rejected),
      replayDuplicates,
    };
  const observedLabels = new Set(metrics.map((record) => record.signalLabel));
  const serviceNamespaces = new Set(
    metrics.map((record) => record.sourceDimensions?.serviceNamespace),
  );
  if (
    observedLabels.size !== signalsWithData ||
    serviceNamespaces.size > 1 ||
    serviceNamespaces.has(undefined)
  )
    return { records: [], rejected: 1, replayDuplicates };
  return { records: [...metrics, completion], rejected: 0, replayDuplicates };
}

function makeBase(
  selection: ServiceHealthSelection,
  config: SupplementalSourceConfiguration,
): O11yHealthResult {
  return {
    schemaVersion: 1,
    source: "o11y_health",
    selection,
    capturedAt: Date.now() / 1000,
    inspectedWindow: selection.window,
    configurationFingerprint: selection.configurationFingerprint,
    configurationChanged: false,
    state:
      config.state === "active"
        ? "unavailable"
        : config.state === "staged"
          ? "staged"
          : "not_selected",
    schemaQualified: config.schemaQualified,
    inputCount: 0,
    inputCapped: false,
    outputCapped: false,
    rejected: 0,
    replayDuplicates: 0,
    oversized: 0,
    records: [],
    coverage: [...COVERAGE],
  };
}

/** Caller-owned, caller-permission search with configuration recheck and full-capture admission. */
export async function loadO11yHealthEvidence(
  client: SearchClient,
  input: ServiceHealthSelection,
  signal: AbortSignal,
  configurationClient: EvidenceConfigClient = evidenceConfigClient,
): Promise<O11yHealthResult> {
  const selection = validateServiceHealthSelection(input);
  let config;
  try {
    config = await configurationClient.read(signal);
  } catch {
    throw new Error(
      "Service health configuration is unavailable to this caller.",
    );
  }
  if (config.fingerprint !== selection.configurationFingerprint)
    throw new Error(
      "Service health configuration changed. Refresh the selection.",
    );
  const source = config.supplemental?.find(
    (entry) => entry.source === "o11y_health",
  );
  if (!source)
    throw new Error("Observability Cloud source configuration is unavailable.");
  const base = makeBase(selection, source);
  if (source.state !== "active") return base;

  let stage: NonNullable<O11yHealthResult["errorCode"]> = "configuration";
  try {
    const search = buildO11yHealthSearch(source, selection);
    base.observabilityOrigin = sourceAuthority(
      source,
      selection,
    ).observabilityOrigin;
    const now = Date.now() / 1000;
    const searchKey = await fingerprint([
      config.fingerprint,
      selection,
      search,
      now - source.staleAfterSeconds,
      now,
    ]);
    stage = "execution";
    const result = requireNoSearchErrors(
      await optionalJobs.run("o11y_health", searchKey, client, {
        search,
        earliest: String(now - source.staleAfterSeconds),
        latest: String(now),
        maxRows: O11Y_HEALTH_RECORD_LIMIT + 1,
        budget: { serverSeconds: 30, clientMilliseconds: 35000 },
        signal,
      }),
      "Observability Cloud health",
    );
    if (result.warnings.length)
      throw new Error(
        "Splunk warnings prevent source completeness verification.",
      );
    stage = "completion";
    const envelope = parseSupplementalEnvelope(result.rows);
    if (
      envelope.rows.some(
        (row) =>
          typeof row.index !== "string" || !source.indexes.includes(row.index),
      )
    )
      throw new Error(
        "Optional result origin does not match source configuration.",
      );
    if (envelope.inputCapped || envelope.outputCapped || envelope.oversized > 0)
      throw new Error(
        "The latest export is capped or oversized; no partial health is shown.",
      );
    stage = "normalization";
    const normalized = normalizeO11yHealthEvidence(
      envelope.rows,
      selection,
      source,
    );
    if (normalized.rejected > 0)
      throw new Error(
        "The latest export is partial, ambiguous or not identity-qualified.",
      );
    base.state = "complete";
    base.inputCount = envelope.inputCount;
    base.inputCapped = envelope.inputCapped;
    base.outputCapped = envelope.outputCapped;
    base.rejected = normalized.rejected;
    base.replayDuplicates = normalized.replayDuplicates;
    base.oversized = envelope.oversized;
    base.records = normalized.records;
  } catch {
    if (signal.aborted) throw new Error("Optional investigation cancelled.");
    base.state = "unavailable";
    base.errorCode = stage;
    base.error =
      "Observability Cloud health unavailable: configuration, permissions, execution or complete source identity could not be verified.";
  }
  if (signal.aborted) throw new Error("Optional investigation cancelled.");
  try {
    const after = await configurationClient.read(signal);
    if (after.fingerprint !== selection.configurationFingerprint) {
      base.configurationChanged = true;
      base.schemaQualified = false;
      base.state = "unavailable";
      base.records = [];
      base.inputCount = 0;
      base.errorCode = "configuration";
      base.error = "Service health configuration changed during the search.";
    }
  } catch {
    base.configurationChanged = true;
    base.schemaQualified = false;
    base.state = "unavailable";
    base.records = [];
    base.inputCount = 0;
    base.errorCode = "configuration";
    base.error =
      "Service health configuration became unreadable during the search.";
  }
  if (signal.aborted) throw new Error("Optional investigation cancelled.");
  return base;
}
