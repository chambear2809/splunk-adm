import { describe, expect, it } from "vitest";
import { normalizeControllerCatalog } from "./appDynamicsCatalog";
import { APPDYNAMICS_SCHEMA } from "./appdynamicsEvidence";
import type { SupplementalSourceConfiguration } from "./evidenceConfig";
import type { Row } from "../rows";

const config: SupplementalSourceConfiguration = {
  source: "appdynamics_inventory",
  state: "active",
  indexes: ["appd_inventory"],
  authorities: ["controller-a"],
  schemaQualified: true,
  staleAfterSeconds: 3600,
  mappings: [
    {
      observer_kind: "appd_controller",
      observer: "controller-a",
      scope: "cv-lab",
      cluster: "",
      mapping_status: "verified",
    },
  ],
};
const common = {
  schema_version: 1,
  schema: APPDYNAMICS_SCHEMA,
  source: "appdynamics_inventory",
  controller_authority: "controller-a",
  scope: "cv-lab",
  identity_basis: "controller_application_model_ids",
  snapshot_id: "snapshot-1",
  snapshot_at: 990,
  collection_started_at: 980,
  collection_completed_at: 990,
  collection_skew_seconds: 10,
  observed_at: 990,
  snapshot_complete: true,
};
function rows(): Row[] {
  const records = [
    {
      record_type: "snapshot",
      record_id: "snapshot:snapshot-1",
      record_counts: {
        total_records: 6,
        applications: 2,
        tiers: 2,
        nodes: 1,
        backends: 0,
      },
    },
    {
      record_type: "application",
      record_id: "app:22",
      application_id: 22,
      application_name: "AD-Ecommerce",
    },
    {
      record_type: "application",
      record_id: "app:23",
      application_id: 23,
      application_name: "AD-Ecommerce-Fulfillment",
    },
    {
      record_type: "tier",
      record_id: "tier:22",
      application_id: 22,
      tier_id: 2,
      tier_name: "Web",
    },
    {
      record_type: "node",
      record_id: "node:22",
      application_id: 22,
      tier_id: 2,
      node_id: 4,
      node_name: "web",
      ip_addresses: [{ ip: "192.0.2.1", matchable: true }],
    },
    {
      record_type: "tier",
      record_id: "tier:23",
      application_id: 23,
      tier_id: 3,
      tier_name: "Fulfillment",
    },
  ];
  return records.map((r, i) => ({
    index: "appd_inventory",
    _indextime: "995",
    _raw: JSON.stringify({
      ...common,
      ...r,
      record_fingerprint: String(i + 1).padStart(64, "0"),
    }),
  }));
}
describe("Controller catalog admission", () => {
  it("retains separate applications and a tier with no nodes", () => {
    const catalog = normalizeControllerCatalog(rows(), config, 1000);
    expect(catalog).toMatchObject({
      authority: "controller-a",
      scope: "cv-lab",
      snapshotId: "snapshot-1",
      applications: [
        { id: "22", tiers: [{ nodes: [{ addresses: ["192.0.2.1"] }] }] },
        { id: "23", tiers: [{ nodes: [] }] },
      ],
    });
  });
  it("rejects missing records, duplicate fingerprints and receipts after the cutoff", () => {
    expect(() =>
      normalizeControllerCatalog(rows().slice(1), config, 1000),
    ).toThrow();
    const duplicate = rows();
    const first = JSON.parse(String(duplicate[0]._raw));
    const next = JSON.parse(String(duplicate[1]._raw));
    next.record_fingerprint = first.record_fingerprint;
    duplicate[1]._raw = JSON.stringify(next);
    expect(() => normalizeControllerCatalog(duplicate, config, 1000)).toThrow();
    const late = rows();
    late[0]._indextime = "1001";
    expect(() => normalizeControllerCatalog(late, config, 1000)).toThrow();
  });
  it("rejects unqualified or ambiguous configuration", () => {
    expect(() =>
      normalizeControllerCatalog(
        rows(),
        { ...config, schemaQualified: false },
        1000,
      ),
    ).toThrow();
    expect(() =>
      normalizeControllerCatalog(
        rows(),
        { ...config, mappings: [...config.mappings, config.mappings[0]] },
        1000,
      ),
    ).toThrow();
  });
});
