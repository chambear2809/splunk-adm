import { describe, expect, it } from "vitest";
import { validateDemoCapture, type DemoCaptureReadback } from "./demoCapture";
import type { DemoScenario } from "./demoRegistry";
import { demoCaptureBundle, rehashDemoCapture } from "./demoCapture.testUtils";
import { canonicalJson, sha256Hex } from "../changeCorrelation/canonicalJson";
import pythonBundle from "../../../fixtures/change-correlation/shared/python_capture_bundle.json";
import pythonTemplate from "../../../fixtures/change-correlation/scenarios/track-a-firewall-capture-template.json";

describe("offline demo capture contract", () => {
  it("consumes the exact Python-built partial bundle and keeps it unavailable", async () => {
    expect(pythonBundle.manifest.captured_dependencies).toHaveLength(1);
    await expect(
      validateDemoCapture(pythonBundle, "track-a-firewall", pythonTemplate),
    ).rejects.toThrow(/not been accepted yet/);
  });

  it("round-trips the synthetic blocked bundle without enabling runtime capture", async () => {
    const scenario: DemoScenario = "track-a-firewall";
    const { template, bundle } = await demoCaptureBundle(scenario);
    const validated = await validateDemoCapture(bundle, scenario, template);

    expect(validated.manifest.scenario_id).toBe(scenario);
    expect(validated.manifest.capture_status).toBe("complete");
    expect(Object.keys(validated.results)).toHaveLength(19);
  });

  it("refuses a bundle with altered result content", async () => {
    const scenario: DemoScenario = "track-b-fabric";
    const { template, bundle } = await demoCaptureBundle(scenario);
    const altered = structuredClone(bundle);
    const impact = altered.results["graph.impact"] as { rows: unknown[] };
    impact.rows.push({ tampered: true });

    await expect(
      validateDemoCapture(altered, scenario, template),
    ).rejects.toThrow(/result hash|bundle hash/);
  });

  it("refuses timeline selections that are not bound to retained rows", async () => {
    const scenario: DemoScenario = "track-a-firewall";
    const { template, bundle } = await demoCaptureBundle(scenario);
    const altered = structuredClone(bundle);
    const timeline = altered.results["timeline.selected"] as {
      selection?: { change_ids?: string[] };
    };
    timeline.selection = { ...timeline.selection, change_ids: ["foreign"] };
    const resigned = await rehashDemoCapture(altered);
    await expect(
      validateDemoCapture(resigned, scenario, template),
    ).rejects.toThrow(/selection is not bound/);
  });

  it("accepts an open-ended retained coverage row", async () => {
    const scenario: DemoScenario = "track-a-firewall";
    const { template, bundle } = await demoCaptureBundle(scenario);
    const timeline = bundle.results["timeline.selected"] as unknown as {
      rows: Record<string, unknown>[];
      generation_rows: Record<string, unknown>[];
      selection: {
        change_ids: string[];
        scope: string;
        window: { start: number; end: number };
      };
      generation_validation: Record<string, unknown>;
    };
    const body = {
      schema_version: 1,
      record_type: "coverage",
      scope: "change-a",
      earliest_at: bundle.manifest.anchor_epoch,
      latest_at: null,
    };
    const recordId = await sha256Hex(canonicalJson(body));
    const manifest: Record<string, unknown> = {
      ...(timeline.generation_validation.manifest as Record<string, unknown>),
      row_count: 1,
      rows_sha256: "",
    };
    delete manifest.generation_id;
    const provisionalRow = { ...body, record_id: recordId };
    manifest.rows_sha256 = await sha256Hex(canonicalJson(provisionalRow));
    const generationId = await sha256Hex(canonicalJson(manifest));
    const row = { ...provisionalRow, generation_id: generationId };
    timeline.rows = [row];
    timeline.generation_rows = [row];
    (
      timeline as unknown as { readback: { result_count: number } }
    ).readback.result_count = 1;
    timeline.selection.change_ids = [recordId];
    timeline.generation_validation = {
      ...timeline.generation_validation,
      generation_id: generationId,
      manifest: { ...manifest, generation_id: generationId },
      complete_row_count: 1,
      rows_sha256: manifest.rows_sha256,
    };
    bundle.manifest.change_generation_id = generationId;
    bundle.manifest.change_generation_sha256 = generationId;
    const resigned = await rehashDemoCapture(bundle);
    const validated = await validateDemoCapture(resigned, scenario, template);
    expect(validated.results["timeline.selected"].rows).toHaveLength(1);
  });

  it("refuses shallow or foreign captured dependency identities", async () => {
    const scenario: DemoScenario = "track-a-firewall";
    const { template, bundle } = await demoCaptureBundle(scenario);
    const altered = structuredClone(bundle);
    altered.manifest.captured_dependencies = [
      {
        authority: "atlas:observed_dependency",
        type: "captured_dependency",
        id: "captured_dependency:fake",
        binding: { scenario_id: "other-track" },
      },
    ];
    const resigned = await rehashDemoCapture(altered);
    await expect(
      validateDemoCapture(resigned, scenario, template),
    ).rejects.toThrow(/dependency/);
  });

  it("accepts a Python-compatible dependency binding tied to graph evidence", async () => {
    const scenario: DemoScenario = "track-a-firewall";
    const { template, bundle } = await demoCaptureBundle(scenario);
    const graph = bundle.results["graph.impact"] as unknown as {
      rows: Record<string, unknown>[];
      readback: DemoCaptureReadback;
      query: { sha256: string };
      window: { earliest: number; latest: number };
    };
    const receipt = graph.readback.receipt_fingerprints[0];
    graph.rows.push({ row_type: "edge", id: "edge-1" });
    graph.readback.result_count = graph.rows.length;
    const coverage = {
      schema_version: 1,
      basis: "query_level_input_coverage",
      qualification: "eligible_input_superset_not_per_edge_lineage",
      execution_id: bundle.manifest.execution_id,
      query_sha256: graph.query.sha256,
      scope: "change-a",
      graph_window: {
        earliest: graph.window.earliest,
        latest: graph.window.latest,
      },
      summary_readback: {
        receipt_fingerprints: [receipt],
        index_window: graph.readback.index_time_bounds,
      },
    };
    graph.readback.query_job = { sid: "sid-python" };
    graph.readback.query_input_coverage = coverage;
    const binding = {
      authority: "atlas:observed_dependency",
      identity_type: "captured_dependency",
      scenario_id: scenario,
      execution_id: bundle.manifest.execution_id,
      graph_result_key: "graph.impact",
      graph_result_sha256: await sha256Hex(canonicalJson(graph)),
      edge_id: "edge-1",
      scope: "change-a",
      window: coverage.graph_window,
      query_sha256: graph.query.sha256,
      receipt_basis: "query_input_coverage_v1",
      query_input_coverage_sha256: await sha256Hex(canonicalJson(coverage)),
      active_traffic_contract_sha256:
        bundle.manifest.active_traffic_contract_sha256,
      receipt_fingerprints: [receipt],
    };
    bundle.manifest.captured_dependencies = [
      {
        authority: "atlas:observed_dependency",
        type: "captured_dependency",
        id: `captured_dependency:${await sha256Hex(canonicalJson(binding))}`,
        binding,
      },
    ];
    const resigned = await rehashDemoCapture(bundle);
    const validated = await validateDemoCapture(resigned, scenario, template);
    expect(validated.manifest.captured_dependencies).toHaveLength(1);
  });
});
