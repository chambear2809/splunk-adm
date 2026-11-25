import { describe, expect, it } from "vitest";
import {
  attributeChangeRow,
  capturedDependencyIdentity,
  extractRetainedRelationships,
} from "./relationships";
import type {
  CapturedDependencyBinding,
  ChangeHistoryRow,
  ChangeRelationshipLink,
  QualifiedChangeIdentity,
} from "./types";

const generationId = "1".repeat(64);
const captureBinding = (
  overrides: Partial<CapturedDependencyBinding> = {},
): CapturedDependencyBinding => ({
  authority: "atlas:observed_dependency",
  identity_type: "captured_dependency",
  scenario_id: "scenario-a",
  execution_id: "execution-a",
  graph_result_key: "graph:phase-a",
  graph_result_sha256: "a".repeat(64),
  edge_id: "edge-a",
  scope: "scope-a",
  window: { earliest: 0, latest: 100 },
  query_sha256: "b".repeat(64),
  receipt_basis: "query_input_coverage_v1",
  query_input_coverage_sha256: "f".repeat(64),
  active_traffic_contract_sha256: "c".repeat(64),
  receipt_fingerprints: ["d".repeat(64), "e".repeat(64)],
  ...overrides,
});

const changeRow = (): ChangeHistoryRow => ({
  schema_version: 1,
  record_type: "change",
  change_type: "modified",
  record_id: "2".repeat(64),
  generation_id: generationId,
  product: "fmc",
  authority: "fmc:prod-a",
  source_version: "1",
  family: "access_policy",
  partition: "domain-a",
  scope: "scope-a",
  permissions_fingerprint: "perm-a",
  object_id: "rule-a",
  revision: null,
  kind: "configuration",
  actor: null,
  event_at: null,
  effective_at: null,
  observed_at: 20,
  received_at: 21,
  earliest_at: 10,
  latest_at: 20,
  source_refs: ["capture:a", "capture:b"],
  field_diffs: [],
  attributes: {},
  coverage_complete: true,
  gap: false,
  qualification: "snapshot_interval",
  time_qualification: "snapshot_interval",
  clock_uncertainty_unknown: false,
  projection_qualification: "normalized_export_only",
  native_sample_unqualified: true,
  context_only: false,
});

function relationship(
  to: QualifiedChangeIdentity,
  evidenceId: string,
  overrides: Partial<ChangeRelationshipLink> = {},
): ChangeRelationshipLink {
  return {
    from_authority: "fmc:prod-a",
    from_type: "access_policy",
    from_id: "rule-a",
    to_authority: to.authority,
    to_type: to.type,
    to_id: to.id,
    scope: "scope-a",
    valid_from: 0,
    valid_to: 100,
    evidence_id: evidenceId,
    basis: "native",
    ...overrides,
  };
}

async function persistedRelationshipRow(
  binding: CapturedDependencyBinding,
  evidenceId = "admin:edge-a",
): Promise<ChangeHistoryRow> {
  const target = await capturedDependencyIdentity(binding);
  const attributes = {
    from_authority: "fmc:prod-a",
    from_type: "access_policy",
    from_id: "rule-a",
    to_authority: target.authority,
    to_type: target.type,
    to_id: target.id,
    scope: "scope-a",
    valid_from: 0,
    valid_to: 100,
    evidence_id: evidenceId,
    basis: "administrator_attestation",
    semantics: "potential_dependency",
    issuer: "network-admin",
    attestation_version: "v1",
    proof: "change-record:CHG-1",
    proof_qualification: "administrator_supplied_unverified",
    qualification: "synthetic_admin_artifact_unqualified",
    binding_scenario_id: binding.scenario_id,
    binding_execution_id: binding.execution_id,
    binding_graph_result_key: binding.graph_result_key,
    binding_graph_result_sha256: binding.graph_result_sha256,
    binding_edge_id: binding.edge_id,
    binding_scope: binding.scope,
    binding_query_sha256: binding.query_sha256,
    binding_receipt_basis: binding.receipt_basis,
    binding_query_input_coverage_sha256: binding.query_input_coverage_sha256,
    binding_active_traffic_contract_sha256:
      binding.active_traffic_contract_sha256,
    binding_window_earliest: binding.window.earliest,
    binding_window_latest: binding.window.latest,
    binding_receipt_fingerprints: binding.receipt_fingerprints,
  };
  return {
    ...changeRow(),
    record_type: "observation",
    change_type: "observation",
    record_id: "3".repeat(64),
    product: "atlas",
    authority: "atlas:administrator_attestation",
    source_version: "atlas-admin-v1",
    family: "relationship_attestation",
    partition: "administrator_relationship_attestations",
    scope: "scope-a",
    permissions_fingerprint: "unqualified-administrator-attestation",
    object_id: evidenceId,
    revision: "v1",
    kind: "operational",
    actor: "admin:alex",
    event_at: null,
    effective_at: null,
    observed_at: 2_000,
    received_at: 2_000,
    earliest_at: null,
    latest_at: null,
    source_refs: ["approval:CHG-1", "capture:admin-a"],
    attributes,
    coverage_complete: true,
    gap: false,
    qualification: "native_observation",
    time_qualification: "unknown_source_time",
    clock_uncertainty_unknown: true,
    projection_qualification: "administrator_attestation_unqualified",
    native_sample_unqualified: true,
    context_only: true,
  };
}

describe("captured dependency identities", () => {
  it("binds the full parsed graph result, edge, scope/window, query, contract and actual receipts", async () => {
    const base = captureBinding();
    const first = await capturedDependencyIdentity(base);
    const variants: Partial<CapturedDependencyBinding>[] = [
      { scenario_id: "scenario-b" },
      { execution_id: "execution-b" },
      { graph_result_key: "graph:phase-b" },
      { graph_result_sha256: "f".repeat(64) },
      { edge_id: "edge-b" },
      { scope: "scope-b" },
      { window: { earliest: 1, latest: 100 } },
      { query_sha256: "f".repeat(64) },
      { query_input_coverage_sha256: "0".repeat(64) },
      { active_traffic_contract_sha256: "f".repeat(64) },
      { receipt_fingerprints: ["d".repeat(64), "f".repeat(64)] },
    ];
    for (const variant of variants) {
      const next = await capturedDependencyIdentity({ ...base, ...variant });
      expect(next.id).not.toBe(first.id);
    }
    expect(first.authority).toBe("atlas:observed_dependency");
    expect(first.type).toBe("captured_dependency");
    expect(first.id).toBe(
      "captured_dependency:7678d6774c5229207738aa0a7df4923a648758a253e8f2260d8f59ebcb36fa3c",
    );
  });

  it("rejects missing, unsupported and malformed query-input proof fields", async () => {
    const base = captureBinding();
    const missing = Object.fromEntries(
      Object.entries(base).filter(([key]) => key !== "receipt_basis"),
    );
    const missingCoverageHash = Object.fromEntries(
      Object.entries(base).filter(
        ([key]) => key !== "query_input_coverage_sha256",
      ),
    );
    for (const malformed of [
      missing,
      missingCoverageHash,
      { ...base, receipt_basis: "raw_event_lineage" },
      { ...base, query_input_coverage_sha256: "F".repeat(64) },
    ])
      await expect(capturedDependencyIdentity(malformed)).rejects.toThrow();
  });

  it("retains the 100-receipt binding cap without truncating", async () => {
    const receipts = Array.from({ length: 100 }, (_, index) =>
      index.toString(16).padStart(64, "0"),
    );
    await expect(
      capturedDependencyIdentity({
        ...captureBinding(),
        receipt_fingerprints: receipts,
      }),
    ).resolves.toMatchObject({ binding: { receipt_fingerprints: receipts } });
    await expect(
      capturedDependencyIdentity({
        ...captureBinding(),
        receipt_fingerprints: [...receipts, "64".padStart(64, "0")],
      }),
    ).rejects.toThrow();
  });

  it("rejects invalid and finer-than-millisecond binding epochs", async () => {
    for (const window of [
      { earliest: 1.0001, latest: 2 },
      { earliest: true, latest: 2 },
      { earliest: 0, latest: 253402300800 },
      { earliest: 2, latest: 1 },
    ])
      await expect(
        capturedDependencyIdentity({ ...captureBinding(), window }),
      ).rejects.toThrow();
  });
});

describe("retained relationship extraction and traversal", () => {
  it("extracts a fully validated generation attestation before its display-time filter", async () => {
    const row = await persistedRelationshipRow(captureBinding());
    const result = await extractRetainedRelationships([row], generationId);
    expect(result.complete).toBe(true);
    expect(result.relationships).toHaveLength(1);
    expect(result.relationships[0]).toMatchObject({
      evidence_id: "admin:edge-a",
      basis: "administrator_attestation",
      semantics: "potential_dependency",
      issuer: "network-admin",
      actor: "admin:alex",
      proof: "change-record:CHG-1",
      proof_qualification: "administrator_supplied_unverified",
      qualification: "synthetic_admin_artifact_unqualified",
      source_version: "atlas-admin-v1",
      target_binding: { edge_id: "edge-a" },
    });
    const target = await capturedDependencyIdentity(captureBinding());
    const attribution = attributeChangeRow(
      changeRow(),
      { scope: "scope-a", window: { start: 5, end: 30 } },
      {
        observedDependencies: [
          { authority: target.authority, type: target.type, id: target.id },
        ],
      },
      result.relationships,
      result.complete,
      result.reason,
    );
    expect(attribution.attribution_class).toBe("observed_dependency");
    expect(attribution.chains).toHaveLength(1);
    expect(attribution.chains?.[0].links[0].proof).toBe("change-record:CHG-1");
  });

  it("keeps context-only output when proof is missing or inconsistent", async () => {
    const valid = await persistedRelationshipRow(captureBinding());
    const malformed = {
      ...valid,
      attributes: Object.fromEntries(
        Object.entries(valid.attributes).filter(([key]) => key !== "proof"),
      ),
    };
    const result = await extractRetainedRelationships(
      [malformed],
      generationId,
    );
    expect(result.complete).toBe(false);
    expect(result.relationships).toEqual([]);
  });

  it("retains every fanout target and every simple evidence chain", () => {
    const targetA: QualifiedChangeIdentity = {
      authority: "atlas:observed_dependency",
      type: "captured_dependency",
      id: `captured_dependency:${"a".repeat(64)}`,
    };
    const targetB: QualifiedChangeIdentity = {
      authority: "atlas:observed_dependency",
      type: "captured_dependency",
      id: `captured_dependency:${"b".repeat(64)}`,
    };
    const attribution = attributeChangeRow(
      changeRow(),
      { scope: "scope-a", window: { start: 5, end: 30 } },
      { observedDependencies: [targetA, targetB] },
      [relationship(targetA, "edge:a"), relationship(targetB, "edge:b")],
      true,
    );
    expect(attribution.attribution_class).toBe("observed_dependency");
    expect(attribution.chains).toHaveLength(2);
    expect(
      new Set((attribution.chains ?? []).map((chain) => chain.target.id)),
    ).toEqual(new Set([targetA.id, targetB.id]));
  });

  it("requires exact routing scope and caller verification for generic context links", () => {
    const target: QualifiedChangeIdentity = {
      authority: "atlas:observed_dependency",
      type: "captured_dependency",
      id: `captured_dependency:${"a".repeat(64)}`,
    };
    const link = relationship(target, "edge:a");
    expect(
      attributeChangeRow(
        changeRow(),
        { scope: "scope-b", window: { start: 5, end: 30 } },
        { observedDependencies: [target] },
        [link],
        true,
      ).reason,
    ).toBe("different_verified_scope");
    expect(
      attributeChangeRow(
        changeRow(),
        { scope: "scope-a", window: { start: 5, end: 30 } },
        { observedDependencies: [target], relationships: [link] },
      ).attribution_class,
    ).toBe("context_only");
  });

  it("requires a relationship end strictly after the inclusive latest change time", () => {
    const target: QualifiedChangeIdentity = {
      authority: "atlas:observed_dependency",
      type: "captured_dependency",
      id: `captured_dependency:${"a".repeat(64)}`,
    };
    const result = attributeChangeRow(
      changeRow(),
      { scope: "scope-a", window: { start: 5, end: 30 } },
      { observedDependencies: [target] },
      [relationship(target, "edge:a", { valid_to: 20 })],
      true,
    );
    expect(result.attribution_class).toBe("context_only");
    expect(result.reason).toBe("relationship_validity_incomplete");
  });

  it("fails closed on conflicting evidence identity and cycles do not hide fanout", () => {
    const target: QualifiedChangeIdentity = {
      authority: "atlas:observed_dependency",
      type: "captured_dependency",
      id: `captured_dependency:${"a".repeat(64)}`,
    };
    const conflicting = relationship(target, "edge:a", {
      to_id: `captured_dependency:${"b".repeat(64)}`,
    });
    const conflictResult = attributeChangeRow(
      changeRow(),
      { scope: "scope-a", window: { start: 5, end: 30 } },
      { observedDependencies: [target] },
      [relationship(target, "edge:a"), conflicting],
      true,
    );
    expect(conflictResult.attribution_class).toBe("context_only");
    expect(conflictResult.reason).toBe("conflicting_relationship_identity");

    const cycle = relationship(
      { authority: "device:a", type: "device", id: "device:a" },
      "edge:cycle",
      { to_authority: "fmc:prod-a", to_type: "access_policy", to_id: "rule-a" },
    );
    const cycleResult = attributeChangeRow(
      changeRow(),
      { scope: "scope-a", window: { start: 5, end: 30 } },
      { observedDependencies: [target] },
      [cycle, relationship(target, "edge:target")],
      true,
    );
    expect(cycleResult.attribution_class).toBe("observed_dependency");
    expect(cycleResult.chains).toHaveLength(1);
  });

  it("reports traversal truncation as context-only instead of partial attribution", () => {
    const target: QualifiedChangeIdentity = {
      authority: "atlas:observed_dependency",
      type: "captured_dependency",
      id: `captured_dependency:${"a".repeat(64)}`,
    };
    const links: ChangeRelationshipLink[] = [];
    for (let index = 0; index < 9; index += 1) {
      const from =
        index === 0
          ? { authority: "fmc:prod-a", type: "access_policy", id: "rule-a" }
          : { authority: "device:a", type: "device", id: `node-${index}` };
      const to =
        index === 8
          ? target
          : { authority: "device:a", type: "device", id: `node-${index + 1}` };
      links.push(
        relationship(to, `edge:${index}`, {
          from_authority: from.authority,
          from_type: from.type,
          from_id: from.id,
        }),
      );
    }
    const result = attributeChangeRow(
      changeRow(),
      { scope: "scope-a", window: { start: 5, end: 30 } },
      { observedDependencies: [target] },
      links,
      true,
    );
    expect(result.attribution_class).toBe("context_only");
    expect(result.reason).toBe("relationship_traversal_incomplete");
  });

  it("caps extracted retained links without returning a partial set", async () => {
    const rows = await Promise.all(
      Array.from({ length: 501 }, (_, index) =>
        persistedRelationshipRow(captureBinding(), `admin:edge-${index}`),
      ),
    );
    const result = await extractRetainedRelationships(rows, generationId);
    expect(result.complete).toBe(false);
    expect(result.relationships).toEqual([]);
  });
});
