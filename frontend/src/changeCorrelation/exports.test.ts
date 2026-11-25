import { describe, expect, it } from "vitest";
import { csvRow } from "../csv";
import {
  changeTimelineCsv,
  changeTimelineJson,
  type ChangeTimelineDemoHandoff,
  type ChangeTimelineExportContext,
} from "./exports";
import type {
  ChangeGenerationManifest,
  ChangeHistoryRow,
  ChangeTimelineRecordView,
} from "./types";

const manifest: ChangeGenerationManifest = {
  schema_version: 1,
  record_type: "generation_manifest",
  algorithm_version: "configuration-history-v1",
  canonicalization: "bounded-decimal-json-v1",
  row_order: "record_id-asc-v1",
  record_id_hash_excludes: ["record_id", "generation_id"],
  row_hash_excludes: ["generation_id"],
  source_receipt_hashes: ["a".repeat(64)],
  row_count: 1,
  rows_sha256: "b".repeat(64),
  source_earliest: 100,
  source_latest: 110,
  generation_id: "c".repeat(64),
};

const row: ChangeHistoryRow = {
  schema_version: 1,
  record_type: "change",
  change_type: "modified",
  record_id: "d".repeat(64),
  generation_id: manifest.generation_id,
  product: "kubernetes",
  authority: "cluster:prod-east",
  source_version: "1.0",
  family: "service_snapshot",
  partition: "cluster-prod-east",
  scope: "prod-east",
  permissions_fingerprint: "perm-a",
  object_id: "service:payments",
  revision: "2",
  kind: "configuration",
  actor: "=1+1",
  event_at: null,
  effective_at: null,
  observed_at: 110,
  received_at: 111,
  earliest_at: 100,
  latest_at: 110,
  source_refs: ["snapshot:payments"],
  field_diffs: [
    {
      field: "service_type",
      before: "ClusterIP",
      after: "LoadBalancer",
      before_present: true,
      after_present: true,
    },
  ],
  attributes: {},
  coverage_complete: true,
  gap: false,
  qualification: "snapshot_interval",
  time_qualification: "snapshot_interval",
  clock_uncertainty_unknown: false,
  projection_qualification: "normalized_export_only",
  native_sample_unqualified: true,
  context_only: false,
};

const record: ChangeTimelineRecordView = {
  row,
  attribution: {
    attribution_class: "context_only",
    reason: "no_qualified_relationship_chain",
    chain: [],
  },
  selected: true,
};

const context = {
  provenance: "validated_live" as const,
  index: "atlas_changes",
  manifest,
  scope: "prod-east",
  window: { start: 100, end: 200 },
  exclusions: {
    different_verified_scope: 2,
    outside_selected_interval: 3,
    unknown_time_unpositioned: 1,
  },
};

describe("configuration history exports", () => {
  it("carries the current view, selection and exclusion summary in JSON", () => {
    const json = JSON.parse(changeTimelineJson(context, [record])) as {
      view: { scope: string; window: { start: number; end: number } };
      records: { selected: boolean; record: ChangeHistoryRow }[];
    };
    expect(json.view).toMatchObject({
      scope: "prod-east",
      window: { start: 100, end: 200 },
      exclusions: context.exclusions,
    });
    expect(json.records).toHaveLength(1);
    expect(json.records[0]).toMatchObject({
      selected: true,
      record: { record_id: row.record_id, actor: "=1+1" },
    });
  });

  it("includes demo capture and branch/control provenance only when supplied", () => {
    const handoff = {
      capture: { execution_id: "exec-1", package_sha256: "pkg-1" },
      bundle_sha256: "bundle-1",
      graph: {
        nodes: [{ id: "client" }],
        edges: [{ id: "client-to-api" }],
      },
      control: {
        status: "complete",
        rows: [{ id: "control-evidence" }],
      },
      blocked_monitoring: {
        "monitoring.appdynamics": {
          status: "blocked",
          reason: "not qualified",
          rows: [],
        },
      },
      branch: {
        status: "captured" as const,
        scenario_id: "track-a-firewall",
        variant_id: "a-meraki-ssid",
        expectation: "observed",
        claim_limits: ["No causation asserted."],
      },
    };
    const demoContext: ChangeTimelineExportContext = {
      ...context,
      provenance: "synthetic_demo",
      demo_handoff: handoff as unknown as ChangeTimelineDemoHandoff,
    };
    const demo = JSON.parse(changeTimelineJson(demoContext, [record])) as {
      view: { incident_handoff: typeof handoff };
    };
    expect(demo.view.incident_handoff).toEqual(handoff);
    expect(demo.view.incident_handoff.graph).toMatchObject({
      nodes: [{ id: "client" }],
      edges: [{ id: "client-to-api" }],
    });
    expect(demo.view.incident_handoff.control).toEqual(handoff.control);
    const emptyCsv = changeTimelineCsv(demoContext, []);
    expect(emptyCsv).toContain(csvRow([JSON.stringify(handoff)]));
    expect(emptyCsv).toContain("reported_chronology,export_context_json");
    expect(changeTimelineCsv(context, [])).not.toContain("export_context_json");
    const live = JSON.parse(changeTimelineJson(context, [record])) as {
      view: Record<string, unknown>;
    };
    expect(live.view).not.toHaveProperty("incident_handoff");
  });

  it("formula-neutralizes CSV and keeps checkbox selection as metadata", () => {
    const csv = changeTimelineCsv(context, [record]);
    expect(csv).toContain("'=1+1");
    expect(csv).toContain("excluded_different_verified_scope");
    expect(csv).toContain("2,3,1");
    expect(csv).toContain(",true,kubernetes,");
  });

  it("exports query-level receipt basis and coverage hash with its qualification", () => {
    const bound = {
      ...record,
      row: {
        ...row,
        attributes: {
          binding_receipt_basis: "query_input_coverage_v1",
          binding_query_input_coverage_sha256: "e".repeat(64),
        },
      },
    };
    const json = JSON.parse(changeTimelineJson(context, [bound])) as {
      records: {
        binding_receipt_basis: string;
        binding_query_input_coverage_sha256: string;
        binding_receipt_qualification: string;
      }[];
    };
    expect(json.records[0]).toEqual({
      binding_receipt_basis: "query_input_coverage_v1",
      binding_query_input_coverage_sha256: "e".repeat(64),
      binding_receipt_qualification:
        "query-level eligible input superset, not per-edge event lineage",
      record: expect.any(Object),
      attribution: expect.any(Object),
      selected: true,
    });
    const csv = changeTimelineCsv(context, [bound]);
    expect(csv).toContain("binding_receipt_basis");
    expect(csv).toContain("query_input_coverage_v1");
    expect(csv).toContain("e".repeat(64));
    expect(csv).toContain(
      "query-level eligible input superset, not per-edge event lineage",
    );
  });
});

it("exports distinct incident, graph and reported observation windows", () => {
  const comparison = {
    graph_window: { start: 420, end: 900 },
    selected_edge_id: "drop",
    reported_observation_interval: { start: 430, end: 430 },
    observation_clock_uncertainty_unknown: true,
  };
  const selected = {
    ...record,
    chronology: {
      graph_phase: "overlap",
      reported_observation: "after",
      ordering_qualified: false,
    },
  };
  const inspection = {
    ...context,
    window: { start: 0, end: 1200 },
    comparison,
  };
  const json = JSON.parse(changeTimelineJson(inspection, [selected]));
  expect(json.view.window).toEqual({ start: 0, end: 1200 });
  expect(json.view.comparison).toEqual(comparison);
  expect(json.records[0].chronology).toEqual(selected.chronology);
  const csv = changeTimelineCsv(inspection, [selected]);
  expect(csv).toContain("observation_context,reported_chronology");
  expect(csv).toContain("reported_observation_interval");
});
