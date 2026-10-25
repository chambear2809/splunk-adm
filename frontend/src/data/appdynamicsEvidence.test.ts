import { describe, expect, it } from "vitest";
import {
  APPDYNAMICS_SCHEMA,
  buildAppDynamicsSearch,
  normalizeAppDynamicsEvidence,
  appDynamicsSearchWindow,
} from "./appdynamicsEvidence";
import type { EvidenceSelection } from "./evidence";
import type { SupplementalSourceConfiguration } from "./evidenceConfig";
import type { Row } from "../rows";

const selection: EvidenceSelection = {
  schemaVersion: 1,
  workflow: "endpoint",
  selectionId: "appd-test",
  trafficContract: 1,
  window: { start: 1_800_000_000, end: 1_800_000_200 },
  scope: "prod",
  addresses: ["192.0.2.10", "2001:db8::10"],
  contexts: [],
  identityBasis: "scoped endpoint",
  configurationFingerprint: "a".repeat(64),
};

const config: SupplementalSourceConfiguration = {
  source: "appdynamics_inventory",
  state: "active",
  indexes: ["appd_inventory"],
  authorities: ["controller.example.test"],
  schemaQualified: true,
  staleAfterSeconds: 3600,
  mappings: [
    {
      observer_kind: "appd_controller",
      observer: "controller.example.test",
      scope: "prod",
      cluster: "",
      mapping_status: "verified",
      controller_origin: "https://controller.example.test",
    },
  ],
};

const snapshotAt = Math.floor(Date.now() / 1000) - 30;
const baseRaw = {
  schema_version: 1,
  schema: APPDYNAMICS_SCHEMA,
  source: "appdynamics_inventory",
  controller_authority: "controller.example.test",
  scope: "prod",
  identity_basis: "controller_application_model_ids",
  snapshot_id: "snapshot-1",
  snapshot_at: snapshotAt,
  collection_started_at: snapshotAt - 10,
  collection_completed_at: snapshotAt,
  collection_skew_seconds: 10,
  snapshot_complete: true,
  observed_at: snapshotAt,
  expected_record_count: 8,
  capture_record_count: 8,
  capture_id_count: 8,
  snapshot_record_count: 1,
  capture_valid: 1,
  latest_snapshot_count: 1,
};

const record = (
  recordType: string,
  recordId: string,
  fingerprint: string,
  extra: Record<string, unknown> = {},
): Row => ({
  kind: "supplemental_record",
  index: "appd_inventory",
  _indextime: String(snapshotAt),
  _time: String(snapshotAt),
  _raw: JSON.stringify({
    ...baseRaw,
    record_type: recordType,
    record_id: recordId,
    record_fingerprint: fingerprint.padStart(64, "0"),
    ...extra,
  }),
});

const rows = (): Row[] => [
  record("snapshot", "snapshot:snapshot-1", "1", {
    record_counts: { total_records: 8 },
  }),
  record("application", "application:101", "2", {
    application_id: 101,
    application_name: "Payments",
  }),
  record("tier", "application:101:tier:7", "3", {
    application_id: 101,
    application_name: "Payments",
    tier_id: 7,
    tier_name: "API",
  }),
  record("node", "application:101:tier:7:node:70", "4", {
    application_id: 101,
    application_name: "Payments",
    tier_id: 7,
    tier_name: "API",
    node_id: 70,
    node_name: "payments-1",
    machine_name: "host-1",
    ip_addresses: [
      { reported: "192.0.2.10", ip: "192.0.2.10", matchable: true },
      { reported: "2001:db8::10", ip: "2001:db8::10", matchable: true },
    ],
  }),
  record("backend", "application:101:backend:88", "5", {
    application_id: 101,
    application_name: "Payments",
    backend_id: 88,
    backend_name: "orders-db",
    exit_point_type: "JDBC",
    association_status: "verified_node",
    reported_tier_id: 7,
    reported_application_component_node_id: 70,
    verified_tier_id: 7,
    verified_node_id: 70,
    endpoint_candidates: [
      { property: "HOST", kind: "ip", value: "192.0.2.10", port: 5432 },
      {
        property: "URL",
        kind: "hostname_unresolved",
        value: "db.example.test",
      },
    ],
  }),
];

describe("AppDynamics current inventory evidence", () => {
  it("builds a bounded current-snapshot scan and only exact selected-IP node context", () => {
    const search = buildAppDynamicsSearch(config, selection);
    expect(search).toContain('sourcetype="adm:appdynamics_inventory"');
    expect(search).toContain('controller_authority="controller.example.test"');
    expect(search).toContain('scope="prod"');
    expect(search).toContain("ip_addresses{}.ip");
    expect(search).toContain("mvfind(appd_node_ip_values");
    expect(search).toContain("dc(record_fingerprint)");
    expect(search).toContain("declared_record_count");
    expect(search).toContain("latest_snapshot_count");
    expect(search).toContain("head 10001");
    expect(search).toContain("head 65");
    expect(search).toContain('kind="supplemental_completion"');
    expect(search).not.toMatch(/join\s|lookup\s|transaction\s/i);
  });

  it("uses only the configured snapshot freshness window, not selected history time", () => {
    const window = appDynamicsSearchWindow(selection, config);
    expect(window.end).toBeGreaterThan(Math.floor(Date.now() / 1000));
    expect(window.end - window.start).toBe(config.staleAfterSeconds + 60);
    expect(window.start).not.toBe(selection.window.start);
  });

  it("keeps Controller/application/tier/node IDs distinct and surfaces candidates", () => {
    const result = normalizeAppDynamicsEvidence(rows(), selection, config);
    expect(result.rejected).toBe(0);
    expect(result.records).toHaveLength(1);
    expect(result.records[0]).toMatchObject({
      authority: "controller.example.test",
      scope: "prod",
      snapshotId: "snapshot-1",
      expectedRecordCount: 8,
      indexedRecordCount: 8,
      controllerOrigin: "https://controller.example.test",
      nodes: [
        {
          applicationId: "101",
          tierId: "7",
          nodeId: "70",
          matchedAddresses: ["192.0.2.10", "2001:db8::10"],
        },
      ],
      backends: [
        {
          applicationId: "101",
          backendId: "88",
          associationStatus: "verified_node",
          associatedWithMatchedNode: true,
          endpointCandidates: [
            expect.objectContaining({
              kind: "ip",
              matchesSelection: true,
              port: 5432,
            }),
            expect.objectContaining({
              kind: "hostname_unresolved",
              matchesSelection: false,
            }),
          ],
        },
      ],
    });
  });

  it("retains shared-IP nodes as separate identities and does not infer a backend node from zero IDs", () => {
    const sharedNode = record("node", "application:202:tier:8:node:80", "6", {
      application_id: 202,
      application_name: "Billing",
      tier_id: 8,
      tier_name: "Worker",
      node_id: 80,
      node_name: "billing-1",
      ip_addresses: [
        { reported: "192.0.2.10", ip: "192.0.2.10", matchable: true },
      ],
    });
    const unrelatedApp = record("application", "application:202", "7", {
      application_id: 202,
      application_name: "Billing",
    });
    const appScopedBackend = record(
      "backend",
      "application:202:backend:99",
      "8",
      {
        application_id: 202,
        application_name: "Billing",
        backend_id: 99,
        backend_name: "shared-service",
        association_status: "application_scope_only",
        reported_tier_id: 0,
        reported_application_component_node_id: 0,
        verified_tier_id: null,
        verified_node_id: null,
        endpoint_candidates: [],
      },
    );
    const result = normalizeAppDynamicsEvidence(
      [...rows(), unrelatedApp, sharedNode, appScopedBackend],
      selection,
      config,
    );
    expect(result.records[0].nodes.map((node) => node.nodeId)).toEqual([
      "70",
      "80",
    ]);
    expect(result.records[0].backends).toContainEqual(
      expect.objectContaining({
        backendId: "99",
        associationStatus: "application_scope_only",
        associatedWithMatchedNode: false,
      }),
    );
  });

  it("rejects invalid origins, schema, capture completeness and inconsistent duplicate fingerprints", () => {
    expect(() =>
      buildAppDynamicsSearch(
        {
          ...config,
          mappings: [
            {
              ...config.mappings[0],
              controller_origin: "http://evil.test/path",
            },
          ],
        },
        selection,
      ),
    ).toThrow();
    const wrongSchema = rows();
    const first = JSON.parse(String(wrongSchema[0]._raw));
    wrongSchema[0]._raw = JSON.stringify({ ...first, schema: "other.v1" });
    expect(
      normalizeAppDynamicsEvidence(wrongSchema, selection, config).rejected,
    ).toBeGreaterThan(0);

    const incomplete = rows();
    const badCapture = JSON.parse(String(incomplete[0]._raw));
    badCapture.capture_valid = 0;
    incomplete[0]._raw = JSON.stringify(badCapture);
    expect(
      normalizeAppDynamicsEvidence(incomplete, selection, config).records,
    ).toHaveLength(0);

    const duplicate = rows();
    duplicate.push({
      ...duplicate[1],
      _raw: JSON.stringify({
        ...JSON.parse(String(duplicate[1]._raw)),
        application_name: "different event with same fingerprint",
      }),
    });
    expect(
      normalizeAppDynamicsEvidence(duplicate, selection, config).records,
    ).toHaveLength(0);
  });
});
