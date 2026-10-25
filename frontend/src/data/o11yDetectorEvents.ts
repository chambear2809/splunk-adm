import type { Row } from "../rows";
import {
  configuredDetectorIds,
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
  validateServiceHealthSelection,
  type ServiceHealthSelection,
} from "./evidence";
import { indexNames } from "./deploymentHealth";
import { optionalJobs } from "./optionalJobs";
import { parseSupplementalEnvelope } from "./supplementalEvidence";
import { requireNoSearchErrors, type SearchClient } from "./searchClient";

export const DETECTOR_SCHEMA = "application_atlas.o11y_detector_event.v1";
export const DETECTOR_SOURCETYPE = "atlas:o11y_detector_event";
const SOURCE = "o11y_detector_events" as const;
export const DETECTOR_COVERAGE = [
  "Observed events for explicitly configured detectors in this cluster and routing scope do not establish a service or custom MMS association.",
  "Trigger, clear, stop and manual-resolution values remain source values. An incident may begin before the interval or remain unresolved afterward. These events do not reconstruct interval incident state; alert silence is not service health.",
  "The API retains at most 12 months. Complete capture means the selected pages were read within exporter limits. UI-created, API-created and AutoDetect coverage need separate qualification.",
  "Exact replayed rows are deduplicated. Conflicting identities, missing completion, truncated scans or multiple latest captures suppress the capture. Missing and completed empty evidence are not healthy states.",
] as const;
export interface DetectorEvent {
  recordId: string;
  detectorId: string;
  timestampMs: number;
  eventId?: string;
  incidentId?: string;
  ruleId?: string;
  label?: string;
  type?: string;
  anomalyState?: string;
  severity?: string;
  sourceEvent: Record<string, unknown>;
}
export interface DetectorCapture {
  captureId: string;
  capturedAt: number;
  observer: string;
  organizationId: string;
  realm: string;
  origin?: string;
  detectorIds: string[];
  events: DetectorEvent[];
}
export interface DetectorResult {
  state: "not_selected" | "staged" | "complete" | "unavailable";
  configurationChanged: boolean;
  capture?: DetectorCapture;
  error?: string;
}
function binding(
  config: SupplementalSourceConfiguration,
  selection: ServiceHealthSelection,
) {
  if (
    config.source !== SOURCE ||
    config.state !== "active" ||
    config.error ||
    !config.schemaQualified ||
    !Number.isSafeInteger(config.staleAfterSeconds) ||
    config.staleAfterSeconds < 60 ||
    config.staleAfterSeconds > EVIDENCE_LIMITS.window
  )
    throw new Error("Detector source is not active and qualified.");
  const candidates = config.mappings.filter(
    (m) =>
      m.observer_kind === "o11y_detector" &&
      m.mapping_status === "verified" &&
      m.scope === selection.scope &&
      m.cluster === selection.service.cluster,
  );
  if (candidates.length !== 1)
    throw new Error("Detector binding is missing or ambiguous.");
  const mapping = candidates[0];
  literal(mapping.observer);
  literal(mapping.organization_id ?? "");
  if (
    !/^[a-z][a-z0-9]{0,7}$/.test(mapping.realm ?? "") ||
    config.authorities.filter((v) => v === mapping.observer).length !== 1 ||
    config.mappings.filter(
      (v) =>
        v.observer_kind === "o11y_detector" && v.observer === mapping.observer,
    ).length !== 1
  )
    throw new Error("Detector authority is invalid or conflicting.");
  return {
    observer: mapping.observer,
    organizationId: mapping.organization_id!,
    realm: mapping.realm!,
    detectorIds: configuredDetectorIds(mapping.detector_ids ?? ""),
    origin: mapping.observability_origin
      ? configuredHttpsOrigin(mapping.observability_origin)
      : undefined,
  };
}
function indexes(config: SupplementalSourceConfiguration) {
  if (
    !Array.isArray(config.indexes) ||
    !config.indexes.length ||
    config.indexes.length > 16
  )
    throw new Error("Invalid detector indexes.");
  const definition = config.indexes
    .map((index) => `index=${index}`)
    .join(" OR ");
  const checked = indexNames({
    name: "adm_index_o11y_detector_events",
    definition: config.indexes.length === 1 ? definition : `(${definition})`,
  });
  if (
    checked.length !== config.indexes.length ||
    new Set(checked).size !== checked.length
  )
    throw new Error("Invalid detector indexes.");
  return definition;
}
const field = (name: string) => `json_extract(_raw,"${name}")`;
/** Capture time discovers indexed exports; source event time remains milliseconds. */
export function buildDetectorEventsSearch(
  config: SupplementalSourceConfiguration,
  input: ServiceHealthSelection,
): string {
  const selection = validateServiceHealthSelection(input),
    a = binding(config, selection);
  const identity = [
    ["schema", DETECTOR_SCHEMA],
    ["observer_id", a.observer],
    ["organization_id", a.organizationId],
    ["realm", a.realm],
    ["routing_scope", selection.scope],
    ["cluster", selection.service.cluster],
  ]
    .map(([name, value]) => `${field(name)}="${literal(value)}"`)
    .join(" AND ");
  return `search (${indexes(config)}) sourcetype="${DETECTOR_SOURCETYPE}" host="${a.observer}"
| where ${identity} AND ${field("observer_id")}=host AND tonumber(${field("capture_window_start")})=${selection.window.start} AND tonumber(${field("capture_window_end")})=${selection.window.end}
| head ${EVIDENCE_LIMITS.input + 1}
| eventstats count AS source_scan_count
| eval capture_time=tonumber(${field("captured_at")}),source_row_invalid=if(isnull(tonumber(${field("captured_at")})),1,0)
| eventstats sum(source_row_invalid) AS source_scan_invalid_count
| eventstats max(capture_time) AS latest_capture_time
| where capture_time=latest_capture_time
| dedup _raw
| eval oversized=if(len(_raw)>65535,1,0),event_time_epoch=tonumber(_time),indexed_time_epoch=tonumber(_indextime)
| eventstats count AS input_count sum(oversized) AS oversized_count
| sort 0 _raw
| head ${EVIDENCE_LIMITS.records}
| eval kind="supplemental_record",_raw=if(oversized=1,"{}",_raw)
| fields _raw host index event_time_epoch indexed_time_epoch input_count source_scan_count source_scan_invalid_count oversized_count kind
| appendpipe [| stats count AS returned_count max(input_count) AS input_count max(source_scan_count) AS source_scan_count max(source_scan_invalid_count) AS source_scan_invalid_count max(oversized_count) AS oversized
| eval kind="supplemental_completion",schema_version=1,input_count=coalesce(input_count,0),input_capped=if(input_count>${EVIDENCE_LIMITS.input},1,0),source_scan_count=coalesce(source_scan_count,0),source_scan_capped=if(source_scan_count>${EVIDENCE_LIMITS.input},1,0),oversized=coalesce(oversized,0)]`;
}
function text(value: unknown, max = 512): string | undefined {
  return typeof value === "string" &&
    value.length > 0 &&
    value.length <= max &&
    !Array.from(value).some(
      (character) =>
        character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127,
    )
    ? value
    : undefined;
}
function number(value: unknown): number | undefined {
  if ((typeof value !== "string" && typeof value !== "number") || value === "")
    return undefined;
  const result = Number(value);
  return Number.isFinite(result) && result >= 0 ? result : undefined;
}
/** Admit one complete latest capture; do not merge lifecycle or interval identities. */
export function normalizeDetectorEvents(
  rows: readonly Row[],
  input: ServiceHealthSelection,
  config: SupplementalSourceConfiguration,
): { capture?: DetectorCapture; rejected: number } {
  const selection = validateServiceHealthSelection(input),
    a = binding(config, selection);
  if (!rows.length) return { rejected: 0 };
  if (rows.length > EVIDENCE_LIMITS.records) return { rejected: rows.length };
  let capture: DetectorCapture | undefined,
    expected: number | undefined,
    completions = 0;
  const unique = new Map<string, string>(),
    eventIds = new Set<string>();
  for (const row of rows) {
    const encoded = text(row._raw, 65535);
    let raw: Record<string, unknown>, detectors: string[];
    try {
      const value: unknown = JSON.parse(encoded ?? "");
      if (!isObject(value)) throw new Error();
      raw = value;
      detectors = configuredDetectorIds(
        JSON.stringify(raw.configured_detector_ids),
      );
    } catch {
      return { rejected: 1 };
    }
    const capturedAt = number(raw.captured_at),
      captureId = text(raw.capture_id, 128),
      recordId = text(raw.record_id, 64),
      eventTime = number(row.event_time_epoch),
      indexedTime = number(row.indexed_time_epoch);
    if (
      raw.schema !== DETECTOR_SCHEMA ||
      raw.observer_id !== a.observer ||
      row.host !== a.observer ||
      raw.organization_id !== a.organizationId ||
      raw.realm !== a.realm ||
      raw.routing_scope !== selection.scope ||
      raw.cluster !== selection.service.cluster ||
      number(raw.capture_window_start) !== selection.window.start ||
      number(raw.capture_window_end) !== selection.window.end ||
      JSON.stringify(detectors) !== JSON.stringify(a.detectorIds) ||
      !config.indexes.includes(String(row.index)) ||
      !captureId ||
      !recordId ||
      !/^[a-f0-9]{64}$/.test(recordId) ||
      capturedAt === undefined ||
      capturedAt > 253402300799 ||
      eventTime === undefined ||
      indexedTime === undefined ||
      Math.abs(eventTime - capturedAt) > 1 ||
      (capture &&
        (capture.captureId !== captureId || capture.capturedAt !== capturedAt))
    )
      return { rejected: 1 };
    const previous = unique.get(recordId);
    if (previous !== undefined) {
      if (previous !== encoded) return { rejected: 1 };
      continue;
    }
    unique.set(recordId, encoded!);
    capture ??= { captureId, capturedAt, ...a, events: [] };
    if (raw.event_type === "export_completion") {
      completions++;
      expected = number(raw.expected_record_count);
      if (
        expected === undefined ||
        !Number.isSafeInteger(expected) ||
        expected > EVIDENCE_LIMITS.records - 1
      )
        return { rejected: 1 };
      continue;
    }
    const detectorId = text(raw.detector_id, 128),
      timestampMs = number(raw.event_timestamp_ms);
    let sourceEvent: Record<string, unknown>;
    try {
      const value: unknown = JSON.parse(
        text(raw.source_event_json, 65535) ?? "",
      );
      if (!isObject(value)) throw new Error();
      sourceEvent = value;
    } catch {
      return { rejected: 1 };
    }
    if (
      raw.event_type !== "detector_event" ||
      !detectorId ||
      !a.detectorIds.includes(detectorId) ||
      timestampMs === undefined ||
      !Number.isSafeInteger(timestampMs) ||
      timestampMs < selection.window.start * 1000 ||
      timestampMs > selection.window.end * 1000 ||
      sourceEvent.timestamp !== timestampMs ||
      (sourceEvent.detectorId !== undefined &&
        sourceEvent.detectorId !== detectorId)
    )
      return { rejected: 1 };
    const eventId = text(raw.event_id),
      identity = JSON.stringify([detectorId, eventId ?? recordId]);
    if (eventIds.has(identity)) return { rejected: 1 };
    eventIds.add(identity);
    const projections = [
      ["event_id", "id", "eventId"],
      ["incident_id", "incidentId"],
      ["rule_id", "ruleId"],
      ["detector_label", "detectLabel"],
      ["source_event_type", "eventType"],
      ["anomaly_state", "anomalyState"],
      ["severity", "severity"],
    ];
    if (
      projections.some(
        ([target, primary, fallback]) =>
          text(raw[target]) !==
          (text(sourceEvent[primary]) ??
            (fallback ? text(sourceEvent[fallback]) : undefined)),
      )
    )
      return { rejected: 1 };
    capture.events.push({
      recordId,
      detectorId,
      timestampMs,
      sourceEvent,
      eventId,
      incidentId: text(raw.incident_id),
      ruleId: text(raw.rule_id),
      label: text(raw.detector_label),
      type: text(raw.source_event_type),
      anomalyState: text(raw.anomaly_state),
      severity: text(raw.severity),
    });
  }
  return completions === 1 && capture && capture.events.length === expected
    ? { capture, rejected: 0 }
    : { rejected: 1 };
}
export async function loadDetectorEvents(
  client: SearchClient,
  input: ServiceHealthSelection,
  signal: AbortSignal,
  configurationClient: EvidenceConfigClient = evidenceConfigClient,
): Promise<DetectorResult> {
  const selection = validateServiceHealthSelection(input),
    configuration = await configurationClient.read(signal);
  if (configuration.fingerprint !== selection.configurationFingerprint)
    throw new Error("Detector configuration changed. Refresh selection.");
  const source = configuration.supplemental?.find(
    (entry) => entry.source === SOURCE,
  );
  if (!source) throw new Error("Detector source configuration unavailable.");
  const result: DetectorResult = {
    state: source.state === "active" ? "unavailable" : source.state,
    configurationChanged: false,
  };
  if (source.state !== "active") return result;
  try {
    const search = buildDetectorEventsSearch(source, selection),
      now = Date.now() / 1000;
    const key = await fingerprint([
      configuration.fingerprint,
      selection,
      search,
      Math.floor(now),
    ]);
    const response = requireNoSearchErrors(
      await optionalJobs.run(SOURCE, key, client, {
        search,
        earliest: String(now - source.staleAfterSeconds),
        latest: String(now + 1),
        maxRows: EVIDENCE_LIMITS.records + 1,
        signal,
      }),
      "Detector events",
    );
    if (response.warnings.length)
      throw new Error("Search warnings prevent completeness verification.");
    const envelope = parseSupplementalEnvelope(response.rows);
    if (
      envelope.inputCapped ||
      envelope.outputCapped ||
      envelope.sourceScanCapped ||
      envelope.sourceScanInvalidCount ||
      envelope.oversized
    )
      throw new Error("Detector capture capped.");
    const normalized = normalizeDetectorEvents(
      envelope.rows,
      selection,
      source,
    );
    if (normalized.rejected)
      throw new Error("Detector capture incomplete or ambiguous.");
    result.state = "complete";
    result.capture = normalized.capture;
  } catch {
    if (signal.aborted) throw new Error("Detector search cancelled.");
    result.error =
      "Detector events unavailable: source identity, permissions, execution or capture completeness could not be verified.";
  }
  try {
    const after = await configurationClient.read(signal);
    if (after.fingerprint !== configuration.fingerprint) throw new Error();
  } catch {
    result.configurationChanged = true;
    result.state = "unavailable";
    result.capture = undefined;
    result.error =
      "Detector configuration changed or became unreadable. Refresh selection.";
  }
  if (signal.aborted) throw new Error("Detector search cancelled.");
  return result;
}
