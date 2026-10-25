import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { AppDynamicsEvidencePanel } from "./AppDynamicsEvidencePanel";
import type { AppDynamicsEvidenceResult } from "./data/appdynamicsEvidence";
import type { EvidenceSelection } from "./data/evidence";

const selection: EvidenceSelection = {
  schemaVersion: 1,
  workflow: "endpoint",
  selectionId: "panel-test",
  trafficContract: 1,
  window: { start: 1000, end: 1200 },
  scope: "prod",
  addresses: ["192.0.2.10"],
  contexts: [],
  identityBasis: "test",
  configurationFingerprint: "a".repeat(64),
};

const result = (outputCapped = false): AppDynamicsEvidenceResult => ({
  schemaVersion: 1,
  source: "appdynamics_inventory",
  selection,
  capturedAt: 1100,
  inspectedWindow: { start: 900, end: 1200 },
  configurationFingerprint: selection.configurationFingerprint,
  configurationChanged: false,
  state: "complete",
  schemaQualified: true,
  inputCount: 5,
  inputCapped: false,
  outputCapped,
  rejected: 0,
  oversized: 0,
  records: [
    {
      authority: "controller.example.test",
      scope: "prod",
      snapshotId: "snapshot-1",
      snapshotAt: 1090,
      collectionStartedAt: 1080,
      collectionCompletedAt: 1090,
      collectionSkewSeconds: 10,
      expectedRecordCount: 8,
      indexedRecordCount: 8,
      controllerOrigin: "https://controller.example.test",
      nodes: [
        {
          applicationId: "101",
          applicationName: "Payments",
          tierId: "7",
          tierName: "API",
          nodeId: "70",
          nodeName: "payments-1",
          addresses: ["192.0.2.10"],
          matchedAddresses: ["192.0.2.10"],
        },
      ],
      backends: [
        {
          applicationId: "101",
          applicationName: "Payments",
          backendId: "88",
          name: "orders-db",
          associationStatus: "verified_node",
          tierId: "7",
          nodeId: "70",
          associatedWithMatchedNode: true,
          endpointCandidates: [
            {
              property: "HOST",
              kind: "ip",
              value: "192.0.2.11",
              matchesSelection: false,
            },
          ],
        },
      ],
    },
  ],
  coverage: [],
});

describe("AppDynamics evidence panel", () => {
  it("shows exact IDs and only the configured Controller origin link", () => {
    const html = renderToStaticMarkup(
      <AppDynamicsEvidencePanel result={result()} />,
    );
    expect(html).toContain("Payments (ID 101)");
    expect(html).toContain("API (ID 7)");
    expect(html).toContain("payments-1 (ID 70)");
    expect(html).toContain('href="https://controller.example.test"');
    expect(html).not.toContain("/controller/rest/");
    expect(html).toContain("orders-db (ID 88)");
    expect(html).toContain("does not prove a request or connection");
  });

  it("suppresses relationships when focused rows were capped", () => {
    const html = renderToStaticMarkup(
      <AppDynamicsEvidencePanel result={result(true)} />,
    );
    expect(html).toContain("focused result cap was reached");
    expect(html).toContain("These rows are source context only");
    expect(html).not.toContain("payments-1");
    expect(html).not.toContain("orders-db");
  });
});
