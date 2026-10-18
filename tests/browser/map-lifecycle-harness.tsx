import { useState } from "react";
import ThemeProviderExport from "@splunk/themes/SplunkThemeProvider";
import { toolkitDefault } from "../../frontend/src/app/interop";
import { MapPage } from "../../frontend/src/pages/MapPage";
import {
  lifecycleArgs,
  lifecycleGraphRows,
  lifecycleTopologyRows,
} from "./map-lifecycle-fixtures";
import "../../frontend/src/styles.css";
import { createRoot } from "react-dom/client";
import { useMapSnapshot } from "../../frontend/src/map/useMapSnapshot";
import { parseUrlState } from "../../frontend/src/app/urlState";
import { demoGraph } from "../../frontend/src/data/demoClient";
import { emptyTopology } from "../../frontend/src/topology";
import type {
  SearchClient,
  SearchRequest,
  RunResult,
} from "../../frontend/src/data/searchClient";
import rows from "../../fixtures/demo-rows-aci.json";

interface Pending {
  client: string;
  request: SearchRequest;
  resolve: (result: RunResult) => void;
  reject: (error: Error) => void;
}
const pending: Pending[] = [];
const surface = new URLSearchParams(location.search).get("surface");
const ThemeProvider = toolkitDefault(ThemeProviderExport);
const requestList = () =>
  pending.map(({ client, request }) => ({
    client,
    search: request.search,
    earliest: request.earliest,
    latest: request.latest,
    timezone: request.timezone,
    aborted: request.signal.aborted,
  }));
const complete = (index: number, version = 1) => {
  const item = pending[index];
  const graph = item.request.search.includes("adm_graph");
  const previous =
    graph && item.request.latest === "1792253100"
      ? { earliest: item.request.earliest, latest: item.request.latest }
      : undefined;
  item.resolve({
    rows: graph
      ? lifecycleGraphRows(version, previous)
      : lifecycleTopologyRows(version),
    warnings: [],
    errors: [],
  });
};
const clientFor = (client: string): SearchClient => ({
  // Deliberately ignore abort when resolving: providers must suppress late data
  // even if a transport finishes after it receives the cancellation signal.
  search: (request) => {
    if (
      surface === "map" &&
      !request.search.includes("adm_graph") &&
      !request.search.includes("adm_topology")
    )
      return Promise.resolve({
        rows: [{ ...lifecycleArgs, pods: "1", last_seen: "1792254300" }],
        warnings: [],
        errors: [],
      });
    return new Promise((resolve, reject) => {
      pending.push({ client, request, resolve, reject });
    });
  },
});
const clients = [clientFor("a"), clientFor("b")];
let demoVersion = 1;
const initialState = parseUrlState(
  new URLSearchParams({
    ...(surface === "map" ? lifecycleArgs : rows.args),
    mode: new URLSearchParams(location.search).get("mode") ?? "live",
    earliest: "-1h",
    latest: "now",
  }),
);
const demoData = {
  graph: () => ({ ...demoGraph("aci"), snapshot_id: `demo-${demoVersion}` }),
  topology: () => ({ ...emptyTopology(), warnings: [`demo-${demoVersion}`] }),
};
export interface LifecycleControl {
  requests(): Array<{
    client: string;
    search: string;
    earliest: string;
    latest?: string;
    timezone?: string;
    aborted: boolean;
  }>;
  resolve(index: number, version?: number): void;
  reject(index: number): void;
  replace(): void;
  refresh(): void;
  edit(): void;
  demo(): void;
  refreshDemo(): void;
  unmount(): void;
}
declare global {
  interface Window {
    mapLifecycle: LifecycleControl;
  }
}
const root = createRoot(document.getElementById("map-lifecycle-root")!);
function Harness() {
  const [clientIndex, setClientIndex] = useState(0);
  const map = useMapSnapshot({
    client: clients[clientIndex],
    initialState,
    timezone: "Pacific/Honolulu",
    demoData,
  });
  window.mapLifecycle = {
    requests: () =>
      pending.map(({ client, request }) => ({
        client,
        search: request.search,
        earliest: request.earliest,
        latest: request.latest,
        timezone: request.timezone,
        aborted: request.signal.aborted,
      })),
    resolve: (index, version = 1) => {
      const item = pending[index];
      const graph = item.request.search.includes("adm_graph");
      item.resolve({
        rows: graph
          ? rows.rows.map((row) =>
              row.row_type === "meta"
                ? {
                    ...row,
                    generated_at: String(Number(row.generated_at) + version),
                  }
                : row,
            )
          : [],
        warnings: [`${graph ? "graph" : "topology"}-${version}`],
        errors: [],
      });
    },
    reject: (index) =>
      pending[index].reject(new Error("Expected graph failure")),
    replace: () => setClientIndex((value) => 1 - value),
    refresh: () => {
      void map.refresh();
    },
    edit: () => {
      map.cancelQuery();
      map.setArgs({ ...map.args, namespace: "unbuilt" });
    },
    demo: () => {
      void map.showDemo();
    },
    refreshDemo: () => {
      demoVersion++;
      void map.refresh();
    },
    unmount: () => root.unmount(),
  };
  return (
    <output
      data-testid="snapshot"
      data-busy={map.busy}
      data-visible={map.visible}
    >
      {JSON.stringify({
        id: map.graph.snapshot_id,
        graphWarnings: map.graph.coverage.warnings,
        topologyWarnings: map.topology.warnings,
        draft: map.args,
        loaded: map.snapshot.request,
        client:
          clients.indexOf(map.snapshot.client!) === 0
            ? "a"
            : map.snapshot.client
              ? "b"
              : undefined,
        mode: map.mode,
        error: map.error,
      })}
    </output>
  );
}
function MapSurface() {
  window.mapLifecycle = {
    requests: requestList,
    resolve: complete,
    reject: (index) =>
      pending[index].reject(new Error("Expected graph failure")),
    replace: () => {
      throw new Error("Use the hook harness for client replacement.");
    },
    refresh: () => {
      throw new Error("Use the MapPage Build map control.");
    },
    edit: () => {
      throw new Error("Use the MapPage scope controls.");
    },
    demo: () => {
      throw new Error("Use the MapPage source controls.");
    },
    refreshDemo: () => {
      throw new Error("Use the hook harness for mutable demo fixtures.");
    },
    unmount: () => root.unmount(),
  };
  return (
    <ThemeProvider family="enterprise" colorScheme="light">
      <MapPage
        client={clients[0]}
        initialState={initialState}
        timezone="Pacific/Honolulu"
        theme="light"
        user="map-lifecycle-review"
      />
    </ThemeProvider>
  );
}
root.render(surface === "map" ? <MapSurface /> : <Harness />);
