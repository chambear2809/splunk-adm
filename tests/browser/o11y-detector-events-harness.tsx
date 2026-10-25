import { createRoot } from "react-dom/client";
import { O11yDetectorEventsPanel } from "../../frontend/src/O11yDetectorEventsPanel";
import type { ServiceHealthSelection } from "../../frontend/src/data/evidence";
import type {
  EvidenceConfiguration,
  EvidenceConfigClient,
} from "../../frontend/src/data/evidenceConfig";
import type {
  SearchClient,
  SearchRequest,
} from "../../frontend/src/data/searchClient";
import fixture from "../../fixtures/o11y/detector_events.json";
import "../../frontend/src/styles.css";

interface LoggedSearch {
  search: string;
  aborted: boolean;
  released: boolean;
  abortSettled: boolean;
}

declare global {
  interface Window {
    __O11Y_DETECTOR_TEST__?: { searches: LoggedSearch[] };
  }
}

const observer = "o11y-detector-prod";
const selection: ServiceHealthSelection = {
  schemaVersion: 1,
  workflow: "service",
  selectionId: "service-cancel-retry",
  scope: "prod-east",
  window: { start: 1792763000, end: 1792763990 },
  service: {
    name: "checkout-api",
    environment: "production",
    cluster: "eks-prod-east",
    namespace: "commerce",
    serviceNamespace: "payments",
  },
  identityBasis: "exact graph-boundary service dimensions",
  configurationFingerprint: "a".repeat(64),
};
const mapping = {
  observer_kind: "o11y_detector",
  observer,
  scope: "prod-east",
  cluster: "eks-prod-east",
  mapping_status: "verified",
  organization_id: "org-demo-01",
  realm: "us0",
  detector_ids: JSON.stringify(["detector_checkout_latency"]),
  observability_origin: "https://app.us0.signalfx.com",
};
const supplemental = {
  source: "o11y_detector_events" as const,
  state: "active" as const,
  indexes: ["atlas_o11y"],
  authorities: [observer],
  schemaQualified: true,
  staleAfterSeconds: 3600,
  mappings: [mapping],
};
const configuration: EvidenceConfiguration = {
  fingerprint: selection.configurationFingerprint,
  trafficContract: 1,
  summaryIndexes: ["adm_summary"],
  mappings: [mapping],
  identities: [],
  identityAvailable: true,
  maxAgeSeconds: 3600,
  dns: [],
  supplemental: [supplemental],
};
const configurationClient: EvidenceConfigClient = {
  read: async () => structuredClone(configuration),
};
const metricRows = fixture.events.map((event, index) => ({
  kind: "supplemental_record",
  _raw: JSON.stringify(event.event),
  _time: new Date(event.time * 1000).toISOString(),
  _indextime: String(event.time + 1),
  event_time_epoch: String(event.time),
  indexed_time_epoch: String(event.time + 1),
  host: event.host,
  index: "atlas_o11y",
  event_fingerprint: String(index + 1).padStart(64, "0"),
}));
const result = {
  rows: [
    ...metricRows,
    {
      kind: "supplemental_completion",
      schema_version: "1",
      input_count: String(metricRows.length),
      returned_count: String(metricRows.length),
      input_capped: "0",
      oversized: "0",
    },
  ],
  warnings: [],
  errors: [],
};
const searches: LoggedSearch[] = [];
let attempts = 0;
const client: SearchClient = {
  search: (request: SearchRequest) => {
    attempts++;
    const current = attempts;
    const sid = `o11y-detector-events-${current}`;
    const log: LoggedSearch = {
      search: request.search,
      aborted: false,
      released: false,
      abortSettled: false,
    };
    searches.push(log);
    request.onLifecycle?.({ state: "creating" });
    request.onLifecycle?.({ state: "created", sid });

    if (current === 1) {
      return new Promise((_, reject) => {
        const onAbort = () => {
          log.aborted = true;
          request.onLifecycle?.({ state: "released", sid });
          log.released = true;
          reject(new Error("cancelled"));
          window.setTimeout(() => {
            log.abortSettled = true;
          }, 0);
        };
        if (request.signal.aborted) onAbort();
        else request.signal.addEventListener("abort", onAbort, { once: true });
      });
    }

    request.onLifecycle?.({ state: "released", sid });
    log.released = true;
    return Promise.resolve(result);
  },
};

window.__O11Y_DETECTOR_TEST__ = { searches };
document.documentElement.dataset.theme = "light";
createRoot(document.getElementById("o11y-detector-events-root")!).render(
  <div className="adm atlas">
    <O11yDetectorEventsPanel
      selection={selection}
      client={client}
      configurationClient={configurationClient}
    />
  </div>,
);
