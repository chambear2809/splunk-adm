import { createRoot } from "react-dom/client";
import { App } from "../../frontend/src/App";
import aciRows from "../../fixtures/demo-rows-aci.json";
import { rowsToGraph } from "../../frontend/src/rows";
import { rowsToTopology } from "../../frontend/src/topology";
import "../../frontend/src/styles.css";

type Listener = (payload?: unknown) => void;
type Results = { fields: string[]; rows: unknown[][] };

const fields = Object.keys(
  aciRows.rows.reduce<Record<string, unknown>>(
    (all, row) => Object.assign(all, row),
    {},
  ),
);
const rows = aciRows.rows.map((row) =>
  fields.map((field) => row[field as keyof typeof row]),
);

class ResultModel {
  private listeners: Listener[] = [];
  private result: Results = { fields, rows: [] };
  on(_event: string, callback: Listener) {
    this.listeners.push(callback);
  }
  off() {
    this.listeners = [];
  }
  hasData() {
    return this.result.rows.length > 0;
  }
  data() {
    return this.result;
  }
  publish(result: Results) {
    this.result = result;
    for (const callback of this.listeners) callback();
  }
}

class FakeSearchManager {
  private listeners = new Map<string, Listener[]>();
  private result = new ResultModel();
  private readonly options: Record<string, unknown>;
  constructor(options: Record<string, unknown>) {
    this.options = options;
  }
  data() {
    return this.result;
  }
  on(event: string, callback: Listener) {
    this.listeners.set(event, [...(this.listeners.get(event) ?? []), callback]);
  }
  off() {
    this.listeners.clear();
  }
  cancel() {}
  dispose() {}
  private emit(event: string, payload?: unknown) {
    for (const callback of this.listeners.get(event) ?? []) callback(payload);
  }
  startSearch() {
    const scenario = new URLSearchParams(location.search).get("scenario");
    const topology = String(this.options.search) === "`adm_topology`";
    if (!topology) {
      window.__ADM_LAST_EARLIEST__ = this.options.earliest_time;
      window.__ADM_LAST_GRAPH_SEARCH__ = this.options.search;
    }
    setTimeout(() => {
      if (scenario === "permission") {
        this.emit("search:error", { message: "index=otel permission denied" });
        return;
      }
      if (topology) {
        this.emit("search:done", { content: { resultCount: 0 } });
        return;
      }
      const incomplete = scenario === "incomplete";
      this.emit("search:done", {
        content: { resultCount: rows.length, isFinalized: incomplete },
      });
      this.result.publish({ fields, rows });
    }, 10);
  }
}

const root = document.getElementById("adm-root");
if (!root) throw new Error("Missing browser test root");
createRoot(root).render(
  <App
    SearchManager={FakeSearchManager}
    demoData={{
      graph: () => rowsToGraph(aciRows.rows, aciRows.args, { demo: true }),
      topology: () => rowsToTopology([]),
    }}
  />,
);
