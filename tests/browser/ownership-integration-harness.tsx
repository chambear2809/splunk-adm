import { useState } from "react";
import { createRoot } from "react-dom/client";
import ThemeProviderExport from "@splunk/themes/SplunkThemeProvider";
import { toolkitDefault } from "../../frontend/src/app/interop";
import { Shell } from "../../frontend/src/app/Shell";
import { ApplicationsPage } from "../../frontend/src/pages/ApplicationsPage";
import { MapPage } from "../../frontend/src/pages/MapPage";
import { ImpactPage } from "../../frontend/src/impact/ImpactPage";
import { parseUrlState } from "../../frontend/src/app/urlState";
import {
  SearchAccessDeniedError,
  type SearchClient,
  type SearchRequest,
  type RunResult,
} from "../../frontend/src/data/searchClient";
import {
  lifecycleArgs,
  lifecycleGraphRows,
  lifecycleTopologyRows,
  lifecycleWindow,
} from "./map-lifecycle-fixtures";
import fixture from "../../fixtures/business-services/synthetic-v2.json";
import "../../frontend/src/styles.css";

const params = new URLSearchParams(location.search);
const view = params.get("view") ?? "map";
const theme = params.get("theme") === "dark" ? "dark" : "light";
const configRevision = "a".repeat(64);
const start = Number(lifecycleWindow.earliest),
  end = Number(lifecycleWindow.latest);
const context = JSON.stringify({
  schemaVersion: 1,
  contract: "qualified_v2",
  authority: "native-producer",
  scope: "cluster-east",
  configRevision,
  observedWindow: { start, end },
});
const local = structuredClone(fixture);
local.snapshot_at = "2026-11-01T00:00:00Z";
local.records[0].valid_to = "2027-01-01T00:00:00Z";
local.bindings[0].valid_to = "2027-01-01T00:00:00Z";
local.bindings[0].target.config_revision = configRevision;
local.bindings[0].target.key = { ...lifecycleArgs };
localStorage.setItem(
  "application-atlas.business-service-import.v1",
  JSON.stringify(local),
);
const state = parseUrlState(
  new URLSearchParams({ ...lifecycleArgs, ...lifecycleWindow, mode: "live" }),
);
let held = false;
const pending: {
  request: SearchRequest;
  resolve: (result: RunResult) => void;
  reject: (error: Error) => void;
}[] = [];
const graph = () =>
  lifecycleGraphRows(1).map((row) =>
    row.row_type === "meta"
      ? { ...row, identity_context: context }
      : row.row_type === "node" &&
          row.kind === "service" &&
          row.id ===
            `service:${lifecycleArgs.cluster}/${lifecycleArgs.namespace}/${lifecycleArgs.service}/${lifecycleArgs.environment}`
        ? { ...row, attr_service: lifecycleArgs.service }
        : row,
  );
const client = (): SearchClient => ({
  search(request) {
    if (request.search.startsWith("| `adm_application_catalog_read`"))
      return Promise.resolve({
        rows: [
          {
            _key: "b".repeat(64),
            ...lifecycleArgs,
            identity_contract: "qualified_v2",
            identity_context: context,
            window_start: start,
            window_end: end,
            pods: 1,
          },
        ],
        warnings: [],
        errors: [],
      });
    if (request.search === "| `adm_map_vsphere_inventory`")
      return Promise.resolve({ rows: [], warnings: [], errors: [] });
    if (
      request.search.includes("adm_application_graph_read") ||
      request.search.includes("adm_graph")
    ) {
      if (held)
        return new Promise((resolve, reject) =>
          pending.push({ request, resolve, reject }),
        );
      return Promise.resolve({ rows: graph(), warnings: [], errors: [] });
    }
    if (request.search.includes("adm_topology"))
      return Promise.resolve({
        rows: lifecycleTopologyRows(1),
        warnings: [],
        errors: [],
      });
    return Promise.resolve({
      rows: [{ ...lifecycleArgs, pods: "1", last_seen: end }],
      warnings: [],
      errors: [],
    });
  },
});
const clients = [client(), client()];
const ThemeProvider = toolkitDefault(ThemeProviderExport);
function App() {
  const [clientIndex, setClientIndex] = useState(0);
  return (
    <ThemeProvider
      family="enterprise"
      colorScheme={theme}
      density="comfortable"
    >
      <Shell
        page={
          view === "catalog"
            ? "applications"
            : view === "impact"
              ? "impact"
              : "map"
        }
      >
        <div className="adm" data-adm-theme={theme}>
          <p>Synthetic ownership integration fixture</p>
          <button
            type="button"
            onClick={() => {
              held = true;
            }}
          >
            Hold synthetic graph refresh
          </button>
          <button
            type="button"
            onClick={() => {
              for (const item of pending.splice(0))
                item.reject(new SearchAccessDeniedError());
              held = false;
            }}
          >
            Deny held graph refresh
          </button>
          <button
            type="button"
            onClick={() => setClientIndex((value) => 1 - value)}
          >
            Replace synthetic source client
          </button>
          {view === "catalog" ? (
            <ApplicationsPage state={state} client={clients[clientIndex]} />
          ) : view === "impact" ? (
            <ImpactPage client={clients[clientIndex]} live theme={theme} />
          ) : (
            <MapPage
              initialState={state}
              client={clients[clientIndex]}
              theme={theme}
              user="synthetic"
            />
          )}
        </div>
      </Shell>
    </ThemeProvider>
  );
}
createRoot(document.getElementById("root")!).render(<App />);
