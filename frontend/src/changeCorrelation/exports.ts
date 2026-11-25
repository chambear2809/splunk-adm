import { csvRow } from "../csv";
import { canonicalJson } from "./canonicalJson";
import type {
  ChangeTimelineComparison,
  ChangeGenerationActivation,
  ChangeGenerationManifest,
  ChangeTimelineExclusions,
  ChangeTimelineRecordView,
  ChangeTimelineWindow,
} from "./types";
import type { Graph } from "../graph";

function csvDocument(
  header: readonly string[],
  rows: string[],
  context?: unknown,
): string {
  if (context !== undefined) {
    rows = [
      ",".repeat(header.length) + csvCell(JSON.stringify(context)),
      ...rows.map((row) => `${row},`),
    ];
    header = [...header, "export_context_json"];
  }
  return [csvRow([...header]), ...rows].join("\r\n");
}

function csvCell(value: unknown): string {
  let text = value === undefined || value === null ? "" : String(value);
  if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;
  return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

export interface ChangeTimelineDemoHandoff {
  capture: Record<string, unknown>;
  bundle_sha256: string;
  graph: Graph;
  control: Record<string, unknown>;
  blocked_monitoring: Record<string, Record<string, unknown>>;
  branch: {
    status: "captured";
    scenario_id: string;
    variant_id: string;
    expectation: string;
    claim_limits: string[];
  };
}

export interface ChangeTimelineExportContext {
  provenance: "validated_live" | "synthetic_demo";
  comparison?: ChangeTimelineComparison;
  index?: string;
  activation?: ChangeGenerationActivation;
  manifest: ChangeGenerationManifest;
  scope: string;
  window: ChangeTimelineWindow;
  exclusions: ChangeTimelineExclusions;
  relationship_evidence_complete?: boolean;
  relationship_evidence_reason?: string | null;
  demo_handoff?: ChangeTimelineDemoHandoff;
}

const CSV_COLUMNS = [
  "record_type",
  "provenance",
  "index",
  "activation_id",
  "generation_id",
  "scope",
  "window_start",
  "window_end",
  "excluded_different_verified_scope",
  "excluded_outside_selected_interval",
  "excluded_unknown_time_unpositioned",
  "relationship_evidence_complete",
  "relationship_evidence_reason",
  "record_id",
  "change_type",
  "attribution_class",
  "attribution_reason",
  "selected",
  "product",
  "authority",
  "source_version",
  "family",
  "partition",
  "object_id",
  "revision",
  "kind",
  "actor",
  "earliest_at",
  "latest_at",
  "event_at",
  "effective_at",
  "observed_at",
  "received_at",
  "time_qualification",
  "clock_uncertainty_unknown",
  "coverage_complete",
  "gap",
  "qualification",
  "projection_qualification",
  "native_sample_unqualified",
  "context_only",
  "source_refs",
  "field_diffs",
  "attributes",
  "binding_receipt_basis",
  "binding_query_input_coverage_sha256",
  "binding_receipt_qualification",
  "relationship_chains",
  "observation_context",
  "reported_chronology",
] as const;

function exportContextRow(context: ChangeTimelineExportContext) {
  return [
    "export_context",
    context.provenance,
    context.index ?? "",
    context.activation?.activation_id ?? "",
    context.manifest.generation_id,
    context.scope,
    context.window.start,
    context.window.end,
    context.exclusions.different_verified_scope,
    context.exclusions.outside_selected_interval,
    context.exclusions.unknown_time_unpositioned,
    context.relationship_evidence_complete ?? "",
    context.relationship_evidence_reason ?? "",
    ...Array.from({ length: CSV_COLUMNS.length - 15 }, () => ""),
    context.comparison ? canonicalJson(context.comparison) : "",
    "",
  ];
}

function exportViewRow(
  context: ChangeTimelineExportContext,
  view: ChangeTimelineRecordView,
) {
  const row = view.row;
  return [
    row.record_type,
    context.provenance,
    context.index ?? "",
    context.activation?.activation_id ?? "",
    context.manifest.generation_id,
    context.scope,
    context.window.start,
    context.window.end,
    "",
    "",
    "",
    context.relationship_evidence_complete ?? "",
    context.relationship_evidence_reason ?? "",
    row.record_id,
    row.change_type,
    view.attribution.attribution_class,
    view.attribution.reason,
    view.selected ? "true" : "false",
    row.product,
    row.authority,
    row.source_version,
    row.family,
    row.partition,
    row.object_id,
    row.revision,
    row.kind,
    row.actor,
    row.earliest_at,
    row.latest_at,
    row.event_at,
    row.effective_at,
    row.observed_at,
    row.received_at,
    row.time_qualification,
    row.clock_uncertainty_unknown,
    row.coverage_complete,
    row.gap,
    row.qualification,
    row.projection_qualification,
    row.native_sample_unqualified,
    row.context_only,
    canonicalJson(row.source_refs),
    canonicalJson(row.field_diffs),
    canonicalJson(row.attributes),
    typeof row.attributes.binding_receipt_basis === "string"
      ? row.attributes.binding_receipt_basis
      : "",
    typeof row.attributes.binding_query_input_coverage_sha256 === "string"
      ? row.attributes.binding_query_input_coverage_sha256
      : "",
    row.attributes.binding_receipt_basis === "query_input_coverage_v1"
      ? "query-level eligible input superset, not per-edge event lineage"
      : "",
    canonicalJson(view.attribution.chains ?? []),
    context.comparison ? canonicalJson(context.comparison) : "",
    view.chronology ? canonicalJson(view.chronology) : "",
  ];
}

/** JSON export retains every row in the current view, with selection as metadata. */
export function changeTimelineJson(
  context: ChangeTimelineExportContext,
  records: ChangeTimelineRecordView[],
): string {
  return canonicalJson({
    schema_version: 1,
    provenance: context.provenance,
    view: {
      index: context.index ?? null,
      activation_id: context.activation?.activation_id ?? null,
      generation_id: context.manifest.generation_id,
      scope: context.scope,
      window: context.window,
      ...(context.comparison ? { comparison: context.comparison } : {}),
      exclusions: context.exclusions,
      relationship_evidence: {
        complete: context.relationship_evidence_complete ?? true,
        reason: context.relationship_evidence_reason ?? null,
      },
      manifest: context.manifest,
      validation: context.activation
        ? {
            method: context.activation.validation_method,
            row_count: context.manifest.row_count,
            rows_sha256: context.manifest.rows_sha256,
          }
        : null,
      ...(context.demo_handoff
        ? { incident_handoff: context.demo_handoff }
        : {}),
    },
    records: records.map((record) => ({
      record: record.row,
      attribution: record.attribution,
      binding_receipt_basis:
        typeof record.row.attributes.binding_receipt_basis === "string"
          ? record.row.attributes.binding_receipt_basis
          : null,
      binding_query_input_coverage_sha256:
        typeof record.row.attributes.binding_query_input_coverage_sha256 ===
        "string"
          ? record.row.attributes.binding_query_input_coverage_sha256
          : null,
      binding_receipt_qualification:
        record.row.attributes.binding_receipt_basis ===
        "query_input_coverage_v1"
          ? "query-level eligible input superset, not per-edge event lineage"
          : null,
      selected: record.selected,
      ...(record.chronology ? { chronology: record.chronology } : {}),
    })),
  });
}

/** CSV export uses the shared spreadsheet-formula neutralization for every cell. */
export function changeTimelineCsv(
  context: ChangeTimelineExportContext,
  records: ChangeTimelineRecordView[],
): string {
  return csvDocument(
    CSV_COLUMNS,
    [
      csvRow(exportContextRow(context)),
      ...records.map((record) => csvRow(exportViewRow(context, record))),
    ],
    context.demo_handoff,
  );
}

export const changeTimelineCsvColumns = CSV_COLUMNS;
