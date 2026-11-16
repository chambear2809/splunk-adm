import { useState } from "react";
import { createRoot } from "react-dom/client";
import SplunkThemeProviderExport from "@splunk/themes/SplunkThemeProvider";
import { toolkitDefault } from "../../frontend/src/app/interop";
import { Shell } from "../../frontend/src/app/Shell";
import { JourneyEvidence } from "../../frontend/src/journeys/JourneyEvidence";
import { HubbleJourneyEvidence } from "../../frontend/src/journeys/HubbleJourneyEvidence";
import { natJourneys } from "../../frontend/src/journeys/model";
import { ProxyEvidencePanel } from "../../frontend/src/ProxyEvidencePanel";
import {
  normalizeProxyEvidence,
  proxySearchWindow,
} from "../../frontend/src/data/proxyEvidence";
import type { EvidenceSelection } from "../../frontend/src/data/evidence";
import type { SupplementalSourceConfiguration } from "../../frontend/src/data/evidenceConfig";
import { indexGraph, type Graph } from "../../frontend/src/graph";
import fixture from "../../fixtures/proxy/envoy-v1.40-http-access.json";
import "../../frontend/src/styles.css";

// All rows in this replay are synthetic; no source or deployment is qualified here.
const params = new URLSearchParams(location.search);
const mode = params.get("mode");
const theme = params.get("theme") === "dark" ? "dark" : "light";
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
const proxy = normalized.records[0];
if (mode === "missing") {
  delete proxy.upstream;
  delete proxy.selectedBackend;
}
if (mode === "retry") {
  proxy.upstreamAttemptCount = 3;
  if (proxy.upstream) delete proxy.upstream.local;
}
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
  inputCapped: mode === "capped",
  outputCapped: false,
  rejected: normalized.rejected,
  oversized: 0,
  records: [proxy],
  coverage: [],
};
const nat = {
  source_authority: "cisco:sfw:estreamer",
  event_type: "ConnectionEvent",
  scope: "prod",
  scope_mapping_verified: true,
  device_ip: "192.0.2.9",
  event_fingerprint: "a".repeat(64),
  event_time: 1791373500,
  received_time: 1791373502,
  protocol: "tcp",
  direction: "initiator_to_responder",
  reported_initiator_ip: "192.0.2.10",
  reported_initiator_port: 54321,
  reported_responder_ip: "198.51.100.20",
  reported_responder_port: 443,
  translated_initiator_ip: "192.0.2.3",
  translated_initiator_port: 45678,
  translated_responder_ip: "198.51.100.20",
  translated_responder_port: 443,
};
const nodes: Graph["nodes"] = [
  { id: "client:a", label: "Selected client", kind: "client" },
  {
    id: "service:cluster/ns/web",
    label: "Service frontend",
    kind: "service",
    endpoint_kind: "k8s_service",
    cluster: "cluster",
    attributes: { handoff_coverage: "complete" },
  },
  {
    id: "pod:cluster/ns/a",
    label: "Reported backend",
    kind: "workload",
    cluster: "cluster",
  },
];
const index = indexGraph({
  nodes,
  edges: [
    {
      id: "selected-client",
      source: nodes[0].id,
      target: nodes[1].id,
      relationship: "communicates_with",
      confidence: "observed",
      evidence: ["synthetic"],
      count: 2,
      scope: "prod",
      client_handoff_coverage: mode === "partial" ? "partial" : "complete",
      client_handoff_connections: mode === "partial" ? 3 : 2,
      client_handoff_determined: 2,
      client_handoff_unresolved: mode === "partial" ? 1 : 0,
      client_handoffs: [
        {
          target: nodes[2].id,
          basis: mode === "inferred" ? "time_inferred" : "hubble_client_tuple",
          connections: 2,
          receiving_nodes: ["node-a"],
          observers: ["hubble:observer-a"],
        },
      ],
    },
  ],
} as Graph);
const ThemeProvider = toolkitDefault(SplunkThemeProviderExport);
function Replay() {
  const [changed, setChanged] = useState(false);
  return (
    <ThemeProvider
      family="enterprise"
      colorScheme={theme}
      density="comfortable"
    >
      <Shell page="map">
        <main className="adm atlas-page" data-adm-theme={theme}>
          <h1>Synthetic journey replay</h1>
          <p>
            Independent source records. Matching addresses do not connect these
            cards.
          </p>
          <button
            type="button"
            onClick={() => setChanged((current) => !current)}
          >
            Next synthetic firewall event
          </button>
          <JourneyEvidence
            title="Firewall translation evidence"
            result={natJourneys(
              [
                {
                  ...nat,
                  event_fingerprint: changed
                    ? "c".repeat(64)
                    : nat.event_fingerprint,
                },
              ],
              "prod",
              selection.window,
              mode === "capped",
            )}
            window={selection.window}
          />
          <ProxyEvidencePanel result={result} />
          <HubbleJourneyEvidence
            edgeId="selected-client"
            index={index}
            window={selection.window}
          />
        </main>
      </Shell>
    </ThemeProvider>
  );
}
createRoot(document.getElementById("root")!).render(<Replay />);
