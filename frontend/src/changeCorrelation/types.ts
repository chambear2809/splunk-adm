export type ChangeJsonValue =
  | null
  | boolean
  | number
  | string
  | ChangeJsonValue[]
  | { [key: string]: ChangeJsonValue };

export type ChangeRecordType =
  "change" | "coverage" | "baseline" | "observation";

export interface ChangeFieldDiff {
  field: string;
  before: ChangeJsonValue;
  after: ChangeJsonValue;
  before_present: boolean;
  after_present: boolean;
}

/** Projected immutable history row. Raw source payloads are never part of this type. */
export interface ChangeHistoryRow {
  schema_version: 1;
  record_type: ChangeRecordType;
  change_type: string | null;
  record_id: string;
  generation_id: string;
  product: string;
  authority: string;
  source_version: string | null;
  family: string;
  partition: string;
  scope: string;
  permissions_fingerprint: string | null;
  object_id: string | null;
  revision: string | null;
  kind: string | null;
  actor: string | null;
  event_at: number | null;
  effective_at: number | null;
  observed_at: number | null;
  received_at: number | null;
  earliest_at: number | null;
  latest_at: number | null;
  source_refs: string[];
  field_diffs: ChangeFieldDiff[];
  attributes: Record<string, ChangeJsonValue>;
  coverage_complete: boolean;
  gap: boolean;
  qualification: string;
  time_qualification: string;
  clock_uncertainty_unknown: boolean;
  projection_qualification: string;
  native_sample_unqualified: boolean;
  context_only: boolean;
}

export interface ChangeGenerationManifest {
  schema_version: 1;
  record_type: "generation_manifest";
  algorithm_version: "configuration-history-v1";
  source_receipt_hashes: string[];
  row_count: number;
  rows_sha256: string;
  canonicalization: "bounded-decimal-json-v1";
  row_order: "record_id-asc-v1";
  record_id_hash_excludes: ["record_id", "generation_id"];
  row_hash_excludes: ["generation_id"];
  generation_id: string;
  source_earliest: number;
  source_latest: number;
}

export interface ChangeGenerationActivation {
  schema_version: 1;
  record_type: "generation_activation";
  activation_id: string;
  generation_id: string;
  index: string;
  source_earliest: number;
  source_latest: number;
  index_earliest: number;
  index_latest: number;
  activated_at: number;
  viewer_entitlement_attested: true;
  validation_method: "sha256-full-generation-v1";
  manifest: ChangeGenerationManifest;
}

export interface ChangeTimelineWindow {
  start: number;
  end: number;
}

export interface QualifiedChangeIdentity {
  authority: string;
  type: string;
  id: string;
}

export interface ChangeRelationshipLink {
  from_authority: string;
  from_type: string;
  from_id: string;
  to_authority: string;
  to_type: string;
  to_id: string;
  scope: string;
  valid_from: number;
  valid_to: number;
  evidence_id: string;
  basis: "native" | "administrator_attestation";
  /** Present on persisted Atlas attestations; caller-supplied context links are caller-verified. */
  semantics?: "potential_dependency";
  issuer?: string;
  source_version?: string;
  attestation_version?: string;
  proof?: string;
  proof_qualification?: "administrator_supplied_unverified";
  actor?: string;
  qualification?:
    | "owned_local_lab_admin_unqualified"
    | "synthetic_admin_artifact_unqualified";
  target_binding?: CapturedDependencyBinding;
  generation_id?: string;
  record_id?: string;
  source_refs?: string[];
}

export interface CapturedDependencyBinding {
  authority: "atlas:observed_dependency";
  identity_type: "captured_dependency";
  scenario_id: string;
  execution_id: string;
  graph_result_key: string;
  graph_result_sha256: string;
  edge_id: string;
  scope: string;
  window: { earliest: number; latest: number };
  query_sha256: string;
  receipt_basis: "query_input_coverage_v1";
  query_input_coverage_sha256: string;
  active_traffic_contract_sha256: string;
  receipt_fingerprints: string[];
}

export interface ChangeAttributionChain {
  target: QualifiedChangeIdentity;
  target_class: "observed_dependency" | "selected_object";
  links: ChangeRelationshipLink[];
}

export interface ChangeTimelineContext {
  /** Demo-only incident handoff metadata; omitted for live history. */
  demo_handoff?: import("./exports").ChangeTimelineDemoHandoff;
  application?: {
    service: string;
    environment: string;
    cluster: string;
    namespace: string;
  };
  /** Exact identities from the selected application's verified evidence. */
  selectedObjects?: QualifiedChangeIdentity[];
  /** Exact dependencies observed in the selected application's evidence. */
  observedDependencies?: QualifiedChangeIdentity[];
  /** Retained, authority-qualified edges supplied by the integration. */
  relationships?: ChangeRelationshipLink[];
  /** Set only when the integration has independently verified each context link. */
  relationshipsVerified?: true;
}

export interface ChangeTimelineSelection {
  activation: ChangeGenerationActivation;
  scope: string;
  window: ChangeTimelineWindow;
}

export type ChangeTimelineConfiguration =
  | { state: "not_selected" }
  | { state: "selected"; index: string; activation_id: string };

export interface ChangeTimelineConfigurationClient {
  read(signal?: AbortSignal): Promise<ChangeTimelineConfiguration>;
}

export interface ChangeTimelineValidation {
  method: "sha256-full-generation-v1";
  row_count: number;
  rows_sha256: string;
}

export interface ChangeTimelineExclusions {
  different_verified_scope: number;
  outside_selected_interval: number;
  unknown_time_unpositioned: number;
}

export type ChangeTimelineResult =
  | {
      provenance: "validated_live";
      activation: ChangeGenerationActivation;
      manifest: ChangeGenerationManifest;
      rows: ChangeHistoryRow[];
      /** Full verified row set retained before selected-window display filtering. */
      generation_rows?: ChangeHistoryRow[];
      retained_relationships?: ChangeRelationshipLink[];
      relationship_evidence_complete?: boolean;
      relationship_evidence_reason?: string | null;
      validation: ChangeTimelineValidation;
      exclusions: ChangeTimelineExclusions;
    }
  | {
      provenance: "synthetic_demo";
      label: string;
      manifest: ChangeGenerationManifest;
      rows: ChangeHistoryRow[];
      /** Full verified row set retained before selected-window display filtering. */
      generation_rows?: ChangeHistoryRow[];
      retained_relationships?: ChangeRelationshipLink[];
      relationship_evidence_complete?: boolean;
      relationship_evidence_reason?: string | null;
    };

export type ChangeAttributionClass =
  "direct_object" | "observed_dependency" | "context_only" | "excluded";

export interface ChangeAttribution {
  attribution_class: ChangeAttributionClass;
  reason: string;
  /** Stable convenience view of the first chain; `chains` retains every eligible path. */
  chain: ChangeRelationshipLink[];
  chains?: ChangeAttributionChain[];
}

export interface ChangeTimelineRecordView {
  chronology?: {
    graph_phase: string;
    reported_observation: string;
    ordering_qualified: boolean;
  };
  row: ChangeHistoryRow;
  attribution: ChangeAttribution;
  selected: boolean;
}

export interface ChangeTimelineComparison {
  graph_window: ChangeTimelineWindow;
  selected_edge_id: string | null;
  reported_observation_interval: ChangeTimelineWindow | null;
  observation_clock_uncertainty_unknown: boolean;
}
