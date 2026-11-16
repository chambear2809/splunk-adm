import { createRoot } from "react-dom/client";
import { JourneyLazyEvidence } from "../../frontend/src/JourneyLazyEvidence";
import {
  normalizeProxyEvidence,
  proxySearchWindow,
} from "../../frontend/src/data/proxyEvidence";
import type { EvidenceSelection } from "../../frontend/src/data/evidence";
import type { SupplementalSourceConfiguration } from "../../frontend/src/data/evidenceConfig";
import fixture from "../../fixtures/proxy/envoy-v1.40-http-access.json";

const selection: EvidenceSelection = {
  schemaVersion: 1,
  workflow: "endpoint",
  selectionId: "synthetic",
  trafficContract: 1,
  window: { start: 1791373400, end: 1791373600 },
  scope: "prod",
  addresses: ["192.0.2.10"],
  contexts: [],
  identityBasis: "synthetic replay",
  configurationFingerprint: "f".repeat(64),
};
const config: SupplementalSourceConfiguration = {
  source: "proxy_envoy",
  state: "active",
  indexes: ["proxy_logs"],
  authorities: ["edge-gateway-01"],
  schemaQualified: true,
  staleAfterSeconds: 3600,
  mappings: [
    {
      observer_kind: "envoy_proxy",
      observer: "edge-gateway-01",
      scope: "prod",
      cluster: "",
      mapping_status: "verified",
    },
  ],
};
const normalized = normalizeProxyEvidence(
  [{ ...fixture, event_time_epoch: Number(fixture._time) }],
  selection,
  config,
);
const result = {
  schemaVersion: 1 as const,
  source: "proxy_envoy" as const,
  selection,
  capturedAt: 1791373700,
  inspectedWindow: proxySearchWindow(selection),
  configurationFingerprint: selection.configurationFingerprint,
  configurationChanged: false,
  state: "complete" as const,
  schemaQualified: true,
  inputCount: 1,
  inputCapped: false,
  outputCapped: false,
  rejected: normalized.rejected,
  oversized: 0,
  records: normalized.records,
  coverage: [],
};
const kind = new URLSearchParams(location.search).get("kind");
createRoot(document.getElementById("root")!).render(
  kind === "ownershipImport" ? (
    <JourneyLazyEvidence kind="ownershipImport" />
  ) : kind === "maintenance" ? (
    <JourneyLazyEvidence
      kind="maintenance"
      selection={{ elements: [], earliest: "0", scope: "", demo: false }}
    />
  ) : kind === "baseline" ? (
    <JourneyLazyEvidence kind="baseline" window={selection.window} />
  ) : (
    <JourneyLazyEvidence kind="proxy" result={result} />
  ),
);
