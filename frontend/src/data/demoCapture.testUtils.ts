import { canonicalJson, sha256Hex } from "../changeCorrelation/canonicalJson";
import { demoTrack, type DemoPhase, type DemoScenario } from "./demoRegistry";
import { DEMO_CAPTURE_KEYS } from "./demoCapture";

const phases: Record<DemoPhase, [number, number]> = {
  baseline: [0, 300],
  change: [300, 420],
  impact: [420, 900],
  recovery: [900, 1200],
};

export function demoTemplate(scenario: DemoScenario = "track-a-firewall") {
  const track = demoTrack(scenario);
  return {
    scenario_id: scenario,
    template_revision: 2,
    application: track.args,
    selection: {
      change_scope: track.scope,
      client_ip: track.clientIp,
      client_mac:
        scenario === "track-a-firewall"
          ? "02:71:00:00:00:20"
          : "02:61:00:00:00:20",
      frontend_ip: "10.50.0.20",
      frontend_port: 8080,
      ...(scenario === "track-a-firewall"
        ? {
            database_ip: "10.20.30.40",
            database_port: 5432,
            control_scope: "change-a-control",
            control_cluster: "cc-a-control",
            control_namespace: "shop-control",
            control_service: "checkout-control",
            control_client_ip: "10.71.0.30",
            control_client_mac: "02:71:00:00:00:30",
            control_frontend_ip: "10.50.0.30",
            control_backend_ip: "10.42.2.30",
            unrelated_scope: "change-a-other",
            unrelated_cluster: "cc-a-other",
          }
        : {
            backend_ip: "10.42.1.20",
            database_ip: "10.20.30.40",
            database_port: 5432,
          }),
    },
    clock: {
      phases: Object.entries(phases).map(([id, [start, end]]) => ({
        id,
        start_offset_seconds: start,
        end_offset_seconds: end,
      })),
    },
  };
}

function indexBoundsForPhase(anchor: number, phase: DemoPhase) {
  const [start, end] = phases[phase];
  return {
    earliest: Math.floor((anchor + start) / 300) * 300,
    latest: Math.floor((anchor + end) / 300) * 300 + 300,
  };
}

export async function demoCaptureBundle(
  scenario: DemoScenario = "track-a-firewall",
) {
  const template = demoTemplate(scenario);
  const anchor = 1_793_102_000;
  const sourceBounds = { earliest: anchor - 120, latest: anchor + 1200 };
  const indexBounds = { earliest: anchor - 300, latest: anchor + 1800 };
  const emptyFixtureHashes = {};
  const configFields = {
    fingerprint: "a".repeat(64),
    trafficContract: 1,
    summaryIndexes: ["adm_summary"],
    mappings: [
      { scope: demoTrack(scenario).scope, mapping_status: "verified" },
      ...(scenario === "track-a-firewall"
        ? [{ scope: "change-a-control", mapping_status: "verified" }]
        : []),
    ],
    identities: [
      { ip: demoTrack(scenario).clientIp, scope: demoTrack(scenario).scope },
      ...(scenario === "track-a-firewall"
        ? [{ ip: "10.71.0.30", scope: "change-a-control" }]
        : []),
    ],
    identityAvailable: true,
    dns: [],
    maxAgeSeconds: 3600,
  };
  const configurationHash = await sha256Hex(canonicalJson(configFields));
  const manifest: Record<string, unknown> = {
    scenario_id: scenario,
    template_revision: 2,
    template_sha256: await sha256Hex(canonicalJson(template)),
    application: template.application,
    selection: template.selection,
    phase_windows: Object.fromEntries(
      Object.entries(phases).map(([id, [start, end]]) => [
        id,
        { earliest: anchor + start, latest: anchor + end },
      ]),
    ),
    anchor_utc: new Date(anchor * 1000).toISOString(),
    anchor_epoch: anchor,
    actual_run_started_epoch: anchor - 120,
    actual_run_ended_epoch: anchor + 1200,
    source_time_bounds: sourceBounds,
    index_time_bounds: indexBounds,
    execution_id: "execution-test-001",
    plan_sha256: "b".repeat(64),
    package_sha256: "c".repeat(64),
    execution_inventory_sha256: "d".repeat(64),
    fixture_sha256: await sha256Hex(canonicalJson(emptyFixtureHashes)),
    fixture_file_sha256: emptyFixtureHashes,
    query_sha256: {} as Record<string, string>,
    contract_sha256: "e".repeat(64),
    configuration_sha256: configurationHash,
    active_traffic_contract_sha256: "f".repeat(64),
    change_generation_id: null as string | null,
    change_generation_sha256: null as string | null,
    captured_dependencies: [],
    capture_status: "complete",
    services_contacted: true,
    capture_sha256: "0".repeat(64),
  };
  const readback = (rows: Record<string, unknown>[]) => ({
    complete: true,
    result_count: rows.length,
    index_time_bounds: indexBounds,
    receipt_fingerprints: ["1".repeat(64)],
    source: "splunk_rest",
    execution_id: manifest.execution_id,
    plan_sha256: manifest.plan_sha256,
  });
  const complete = (
    key: string,
    rows: Record<string, unknown>[],
    phase?: DemoPhase,
    input?: { field: string; value: string },
  ) => {
    const [startOffset, endOffset] = phase ? phases[phase] : [0, 1200];
    const earliest = anchor + startOffset;
    const latest = anchor + endOffset;
    const literal = `| makeresults | eval atlas_test="${key}"`;
    return {
      status: "complete",
      ...(!input ? { args: demoTrack(scenario).args } : {}),
      ...(input ? { input } : {}),
      window: { earliest, latest, basis: "source_time" },
      query: { literal, sha256: "0".repeat(64) },
      rows,
      readback: readback(rows),
    };
  };
  const results: Record<string, Record<string, unknown>> = {};
  for (const key of DEMO_CAPTURE_KEYS) {
    if (key.startsWith("monitoring.")) {
      results[key] = { status: "unavailable", reason: "Not captured." };
      continue;
    }
    if (key === "endpoint.control.impact" && scenario === "track-b-fabric") {
      results[key] = {
        status: "unavailable",
        reason: "No control is authored for this track.",
      };
      continue;
    }
    if (key.startsWith("endpoint.")) continue;
    const match =
      /^(?:graph|topology)\.(baseline|change|impact|recovery)$/.exec(key);
    const phase = match?.[1] as DemoPhase | undefined;
    let rows: Record<string, unknown>[] = [];
    if (key.startsWith("graph.")) {
      const [start, end] = phases[phase!];
      rows = [
        {
          row_type: "meta",
          nodes: "0",
          edges: "0",
          spans: "0",
          conversations_in_scope: "0",
          matched_conversations: "0",
          unresolved_conversations: "0",
          ambiguous_conversations: "0",
          warnings: [],
          window_start: String(anchor + start),
          window_end: String(anchor + end),
          generated_at: String(anchor + end),
        },
      ];
    }
    const input =
      key === "find.service"
        ? { field: "service", value: demoTrack(scenario).args.service }
        : key === "find.network_client"
          ? { field: "client_ip", value: demoTrack(scenario).clientIp }
          : undefined;
    const selectedPhase =
      phase ?? (key === "timeline.selected" ? undefined : "impact");
    results[key] = complete(key, rows, selectedPhase, input);
  }
  const endpointKeys = DEMO_CAPTURE_KEYS.filter(
    (key) =>
      (key.startsWith("endpoint.") && key !== "endpoint.control.impact") ||
      (key === "endpoint.control.impact" && scenario === "track-a-firewall"),
  );
  for (const key of endpointKeys) {
    const control = key === "endpoint.control.impact";
    const phaseMatch = /\.(baseline|change|impact|recovery)$/.exec(key);
    const phase = (phaseMatch?.[1] ?? "impact") as DemoPhase;
    const [startOffset, endOffset] = phases[phase];
    const scope = control ? "change-a-control" : demoTrack(scenario).scope;
    const address = control ? "10.71.0.30" : demoTrack(scenario).clientIp;
    const start = anchor + startOffset;
    const end = anchor + endOffset;
    const queryBounds = indexBoundsForPhase(anchor, phase);
    const literal = `| tstats count where index=adm_summary AND client_ip="${address}"`;
    const config = {
      ...configFields,
      caller_acl: {
        status: "owned_local_lab_admin",
        principal: "test-admin",
        checked_at: anchor,
        admin_all_objects: true,
        target_identity_sha256: "2".repeat(64),
      },
      readback: {
        complete: true,
        source: "ToolkitEvidenceConfigClient.read",
        captured_at: anchor,
        config_sha256: configurationHash,
        configuration_fingerprint: configFields.fingerprint,
        settings_revision: "1",
      },
    };
    results[key] = {
      status: "complete",
      selection: {
        schemaVersion: 1,
        id: `${scope}:${address}:${start}:${end}`,
        address,
        scope,
        start,
        end,
        configurationFingerprint: configFields.fingerprint,
        trafficContract: 1,
      },
      selectors: {
        summary_selector: "index=adm_summary",
        query_earliest: String(queryBounds.earliest),
        query_latest: String(queryBounds.latest),
      },
      config_snapshot: config,
      queries: {
        conversations: {
          literal,
          sha256: "0".repeat(64),
          earliest: String(queryBounds.earliest),
          latest: String(queryBounds.latest),
          max_rows: 502,
          rows: [],
          readback: readback([]),
        },
        observations: { status: "not_applicable", reason: "Contract V1." },
      },
    };
  }
  const generationManifest: Record<string, unknown> = {
    schema_version: 1,
    record_type: "generation_manifest",
    algorithm_version: "configuration-history-v1",
    source_receipt_hashes: [],
    row_count: 0,
    rows_sha256: await sha256Hex(""),
    canonicalization: "bounded-decimal-json-v1",
    row_order: "record_id-asc-v1",
    record_id_hash_excludes: ["record_id", "generation_id"],
    row_hash_excludes: ["generation_id"],
    source_earliest: sourceBounds.earliest,
    source_latest: sourceBounds.latest,
  };
  const generationId = await sha256Hex(canonicalJson(generationManifest));
  generationManifest.generation_id = generationId;
  manifest.change_generation_id = generationId;
  manifest.change_generation_sha256 = generationId;
  const timeline = results["timeline.selected"];
  timeline.selection = {
    scope: demoTrack(scenario).scope,
    window: { start: anchor, end: anchor + 1200 },
    change_ids: [],
  };
  timeline.generation_validation = {
    generation_id: generationId,
    manifest: generationManifest,
    complete_row_count: 0,
    rows_sha256: generationManifest.rows_sha256,
    ingest_bounds: sourceBounds,
    validated_before_filter: true,
  };
  timeline.generation_rows = [];
  for (const [key, result] of Object.entries(results)) {
    const nested = result.queries as
      Record<string, { literal?: string; sha256?: string }> | undefined;
    if (nested) {
      for (const [name, query] of Object.entries(nested)) {
        if (typeof query.literal === "string") {
          query.sha256 = await sha256Hex(query.literal);
          (manifest.query_sha256 as Record<string, string>)[`${key}.${name}`] =
            query.sha256;
        }
      }
    }
    const query = result.query as
      { literal: string; sha256: string } | undefined;
    if (query) {
      query.sha256 = await sha256Hex(query.literal);
      (manifest.query_sha256 as Record<string, string>)[key] = query.sha256;
    }
  }
  manifest.capture_sha256 = await sha256Hex(canonicalJson(results));
  const bundle = { schema_version: 1, manifest, results };
  return {
    template,
    bundle: {
      ...bundle,
      bundle_sha256: await sha256Hex(canonicalJson({ manifest, results })),
    },
  };
}

export async function rehashDemoCapture<
  T extends {
    schema_version: number;
    manifest: Record<string, unknown>;
    results: Record<string, unknown>;
  },
>(bundle: T) {
  bundle.manifest.capture_sha256 = await sha256Hex(
    canonicalJson(bundle.results),
  );
  const unsigned = {
    manifest: bundle.manifest,
    results: bundle.results,
  };
  return {
    ...bundle,
    bundle_sha256: await sha256Hex(canonicalJson(unsigned)),
  };
}
