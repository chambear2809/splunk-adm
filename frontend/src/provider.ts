import demo from "../../fixtures/demo-graph.json";
import { parseGraph, type Graph } from "./graph";
export const demoGraph = () => parseGraph(demo);
interface Results {
  fields: string[];
  rows: string[][];
}
interface ResultModel {
  on(event: string, callback: () => void): void;
  off(): void;
  hasData(): boolean;
  data(): Results;
}
interface Manager {
  data(kind: string, options: { count: number }): ResultModel;
  on(
    event: string,
    callback: (state: {
      content?: { resultCount?: number };
      message?: string;
    }) => void,
  ): void;
  off(): void;
  startSearch(): void;
  cancel(): void;
  dispose?(): void;
}
export type SearchConstructor = new (
  options: Record<string, unknown>,
) => Manager;
let sequence = 0;
export interface LiveRequest {
  index: string;
  boundary: string;
  earliest: string;
}
// Restrict user input to literal identifiers: it can never introduce SPL operators.
export function loadLive(
  SearchManager: SearchConstructor,
  request: LiveRequest,
  signal: AbortSignal,
  release?: (id: string) => void,
): Promise<Graph> {
  if (
    !/^[a-zA-Z0-9_-]{1,100}$/.test(request.index) ||
    !/^[a-zA-Z0-9_.:-]{1,160}$/.test(request.boundary)
  )
    return Promise.reject(
      new Error(
        "Use letters, numbers, dots, colons, underscores or hyphens for the boundary; index names cannot contain dots or colons.",
      ),
    );
  if (!["-15m", "-1h", "-24h", "-7d", "0"].includes(request.earliest))
    return Promise.reject(new Error("Unsupported search window."));
  return new Promise((resolve, reject) => {
    if (signal.aborted) {
      reject(new Error("Search cancelled."));
      return;
    }
    const id = `adm-snapshot-${++sequence}`;
    const manager = new SearchManager({
      id,
      app: "splunk_adm",
      autostart: false,
      preview: false,
      cancelOnUnload: true,
      earliest_time: request.earliest,
      latest_time: "now",
      search: `index="${request.index}" sourcetype="adm:graph" | spath path=boundary.id output=boundary_id | where boundary_id="${request.boundary}" | sort 0 - _time | head 1 | table _raw`,
    });
    const results = manager.data("results", { count: 1 });
    let finished = false;
    const cleanup = () => {
      clearTimeout(timer);
      signal.removeEventListener("abort", abort);
      // A cleanup failure must never prevent the load promise from settling.
      for (const dispose of [
        () => results.off(),
        () => manager.off(),
        () => manager.cancel(),
        () => manager.dispose?.(),
        () => release?.(id),
      ]) {
        try {
          dispose();
        } catch {
          /* Splunk versions differ in disposal APIs. */
        }
      }
    };
    const finish = (graph?: Graph, error?: Error) => {
      if (finished) return;
      finished = true;
      cleanup();
      if (graph) resolve(graph);
      else reject(error ?? new Error("No snapshot found."));
    };
    const abort = () => finish(undefined, new Error("Search cancelled."));
    const timer = setTimeout(
      () =>
        finish(
          undefined,
          new Error(
            "Search timed out after 60 seconds. Narrow the search window or check Splunk access.",
          ),
        ),
      60000,
    );
    signal.addEventListener("abort", abort);
    results.on("data", () => {
      if (!results.hasData()) return;
      try {
        const data = results.data();
        const raw = data.rows?.[0]?.[data.fields.indexOf("_raw")];
        if (!raw || raw.length > 2_000_000)
          throw new Error("Missing snapshot or snapshot exceeds 2 MB.");
        const graph = parseGraph(JSON.parse(raw));
        if (graph.boundary.id !== request.boundary)
          throw new Error("Snapshot boundary does not match selection.");
        finish(graph);
      } catch (e) {
        finish(
          undefined,
          e instanceof Error ? e : new Error("Invalid graph event."),
        );
      }
    });
    manager.on("search:done", (state) => {
      if (Number(state.content?.resultCount) === 0)
        finish(
          undefined,
          new Error(
            "No snapshot found for this boundary in the selected search window.",
          ),
        );
    });
    manager.on("search:error", () =>
      finish(
        undefined,
        new Error(
          "Splunk search failed. Check index access and search permissions.",
        ),
      ),
    );
    manager.on("search:failed", () =>
      finish(undefined, new Error("Splunk could not complete the search.")),
    );
    manager.startSearch();
  });
}
