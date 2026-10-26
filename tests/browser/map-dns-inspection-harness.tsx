import { createRoot } from "react-dom/client";
import { MapDnsInspection } from "../../frontend/src/MapDnsInspection";
import { evidenceConfigClient } from "../../frontend/src/data/evidenceConfig";
import type { EvidenceConfiguration } from "../../frontend/src/data/evidenceConfig";
import type { SearchClient } from "../../frontend/src/data/searchClient";
import { indexGraph, type Graph } from "../../frontend/src/graph";
import "../../frontend/src/styles.css";

type Control = { reject: () => void; resolve: () => void };
declare global {
  interface Window {
    __MAP_DNS_TEST__?: { control: Control };
  }
}
const nodeId = "pod:checkout/api";
const graph: Graph = {
  schema_version: 1,
  snapshot_id: "map-dns-cancel",
  generated_at: "2026-10-25T12:00:00Z",
  demo: false,
  window: { start: "2026-10-25T11:00:00Z", end: "2026-10-25T12:00:00Z" },
  boundary: {
    id: "b",
    service: "checkout",
    environment: "prod",
    cluster: "prod",
    namespace: "commerce",
    root_node_id: nodeId,
  },
  nodes: [
    {
      id: nodeId,
      label: "checkout",
      kind: "workload",
      addresses: ["192.0.2.10", "192.0.2.11"],
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
const config: EvidenceConfiguration = {
  fingerprint: "a".repeat(64),
  trafficContract: 1,
  summaryIndexes: ["adm_summary"],
  maxAgeSeconds: 3600,
  identityAvailable: true,
  identities: [],
  dns: [],
  mappings: [
    {
      observer_kind: "dns_sensor",
      observer: "sensor",
      scope: "prod",
      cluster: "",
      mapping_status: "verified",
    },
  ],
};
let pending: Control | undefined;
evidenceConfigClient.read = async () => structuredClone(config);
const client: SearchClient = {
  search: () =>
    new Promise((resolve, reject) => {
      pending = {
        resolve: () => resolve({ rows: [], warnings: [], errors: [] }),
        reject: () => reject(new Error("late failure")),
      };
      window.__MAP_DNS_TEST__ = { control: pending };
    }),
};
document.documentElement.dataset.theme = "light";
createRoot(document.getElementById("map-dns-root")!).render(
  <div className="adm atlas">
    <MapDnsInspection
      graph={graph}
      index={indexGraph(graph)}
      selection={{ kind: "node", id: nodeId }}
      client={client}
      live
    />
  </div>,
);
