import { createRoot } from "react-dom/client";
import { MapServiceHealthInspection } from "../../frontend/src/MapServiceHealthInspection";
import { evidenceConfigClient } from "../../frontend/src/data/evidenceConfig";
import type { EvidenceConfiguration } from "../../frontend/src/data/evidenceConfig";
import type { SearchClient } from "../../frontend/src/data/searchClient";
import { indexGraph, type Graph } from "../../frontend/src/graph";
import "../../frontend/src/styles.css";

interface ScopeRead {
  aborted: boolean;
  settled: boolean;
}

declare global {
  interface Window {
    __MAP_SERVICE_HEALTH_TEST__?: { reads: ScopeRead[] };
  }
}

const rootId = "service:checkout-api";
const graph: Graph = {
  schema_version: 1,
  snapshot_id: "map-health-cancel-retry",
  generated_at: "2026-10-23T12:00:00Z",
  demo: false,
  window: { start: "1792763000", end: "1792763990" },
  boundary: {
    id: "boundary-checkout",
    service: "checkout-api",
    environment: "production",
    cluster: "eks-prod-east",
    namespace: "commerce",
    root_node_id: rootId,
  },
  nodes: [
    {
      id: rootId,
      label: "checkout-api",
      kind: "service",
      namespace: "commerce",
      cluster: "eks-prod-east",
    },
  ],
  edges: [],
  coverage: {
    spans: 0,
    conversations: 0,
    matched_conversations: 0,
    unresolved_conversations: 0,
    ambiguous_conversations: 0,
    warnings: [],
  },
};
const mapping = {
  observer_kind: "o11y_export",
  observer: "o11y-observer-prod",
  scope: "prod-east",
  cluster: "eks-prod-east",
  mapping_status: "verified",
  organization_id: "org-demo-01",
  realm: "us0",
  apm_mms_id: "checkout_service_mms_v1",
};
const configuration: EvidenceConfiguration = {
  fingerprint: "a".repeat(64),
  trafficContract: 1,
  summaryIndexes: ["adm_summary"],
  mappings: [mapping],
  identities: [],
  identityAvailable: true,
  dns: [],
  maxAgeSeconds: 3600,
};
const reads: ScopeRead[] = [];
let attempts = 0;
evidenceConfigClient.read = (signal) => {
  attempts++;
  const read: ScopeRead = { aborted: false, settled: false };
  reads.push(read);
  if (attempts === 1) {
    return new Promise((resolve, reject) => {
      const onAbort = () => {
        read.aborted = true;
        reject(new Error("cancelled"));
        window.setTimeout(() => {
          read.settled = true;
        }, 0);
      };
      if (signal?.aborted) onAbort();
      else signal?.addEventListener("abort", onAbort, { once: true });
    });
  }
  read.settled = true;
  return Promise.resolve(configuration);
};
const client: SearchClient = {
  search: async () => ({ rows: [], warnings: [], errors: [] }),
};

window.__MAP_SERVICE_HEALTH_TEST__ = { reads };
document.documentElement.dataset.theme = "light";
createRoot(document.getElementById("map-service-health-root")!).render(
  <div className="adm atlas">
    <MapServiceHealthInspection
      graph={graph}
      index={indexGraph(graph)}
      selection={{ kind: "node", id: rootId }}
      client={client}
      live
    />
  </div>,
);
