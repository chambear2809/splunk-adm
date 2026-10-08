import nxosRows from "../../fixtures/demo-rows.json";
import nxosTopology from "../../fixtures/demo-topology.json";
import aciRows from "../../fixtures/demo-rows-aci.json";
import aciTopology from "../../fixtures/demo-topology-aci.json";
import { type Graph } from "./graph";
import { MAX_ROWS, rowsToGraph, type GraphArgs, type Row } from "./rows";
import {
  emptyTopology,
  MAX_TOPOLOGY_ROWS,
  rowsToTopology,
  type Topology,
} from "./topology";

/** Captured lab output of `adm_graph` and `adm_topology` for each demo scenario. */
const SCENARIOS = {
  aci: {
    label: "ACI pilot fabric",
    graph: aciRows,
    topology: aciTopology as unknown,
  },
  nxos: {
    label: "NX-OS fabric",
    graph: nxosRows,
    topology: nxosTopology as unknown,
  },
} as const;
export type DemoScenario = keyof typeof SCENARIOS;
export const DEMO_SCENARIOS = (Object.keys(SCENARIOS) as DemoScenario[]).map(
  (id) => ({ id, label: SCENARIOS[id].label }),
);
export const demoArgsFor = (scenario: DemoScenario): GraphArgs =>
  SCENARIOS[scenario].graph.args;
export const demoArgs: GraphArgs = demoArgsFor("aci");
/** Demo mode assembles captured lab rows through the same path as live mode. */
export const demoGraph = (scenario: DemoScenario = "aci"): Graph =>
  rowsToGraph(SCENARIOS[scenario].graph.rows, demoArgsFor(scenario), {
    demo: true,
  });
export const demoTopology = (scenario: DemoScenario = "aci"): Topology => {
  const file = SCENARIOS[scenario].topology;
  if (file === undefined) return emptyTopology();
  return rowsToTopology(
    Array.isArray(file) ? file : (file as { rows?: unknown }).rows,
  );
};
export const TOPOLOGY_SEARCH = "`adm_topology`";

interface Results {
  fields: (string | { name?: string })[];
  rows: unknown[][];
}
interface ResultModel {
  on(event: string, callback: () => void): void;
  off(): void;
  hasData(): boolean;
  data(): Results;
}
interface Manager {
  data(
    kind: string,
    options: { count: number; output_mode?: string },
  ): ResultModel;
  on(event: string, callback: (state?: unknown) => void): void;
  off(): void;
  startSearch(): void;
  cancel(): void;
  dispose?(): void;
}
export type SearchConstructor = new (
  options: Record<string, unknown>,
) => Manager;
let sequence = 0;
export const TIME_RANGES = [
  { value: "-15m", label: "Last 15 minutes" },
  { value: "-1h", label: "Last hour" },
  { value: "-4h", label: "Last 4 hours" },
  { value: "-24h", label: "Last 24 hours" },
] as const;
export interface LiveRequest extends GraphArgs {
  earliest: string;
}
const MAX_MESSAGE_CHARS = 300;
/**
 * Argument formats. None admits quotes, backslashes, backticks, parentheses,
 * commas, `$`, `|` or whitespace, so a value cannot close its quoted macro
 * argument, inject another argument, or reference a macro token.
 */
export const ARG_RULES: Record<keyof GraphArgs, { re: RegExp; hint: string }> =
  {
    service: {
      re: /^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,254}$/,
      hint: "letters, numbers and . _ : / @ -",
    },
    environment: {
      re: /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/,
      hint: "letters, numbers and . _ -",
    },
    cluster: {
      re: /^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$/,
      hint: "letters, numbers and . _ -",
    },
    namespace: {
      // Kubernetes namespace names are RFC 1123 labels.
      re: /^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$/,
      hint: "lowercase letters, numbers and -, at most 63 characters",
    },
  };
export function argError(key: keyof GraphArgs, value: string) {
  return ARG_RULES[key].re.test(value)
    ? undefined
    : `${key[0].toUpperCase()}${key.slice(1)} may contain ${ARG_RULES[key].hint}.`;
}
/** Builds the graph SPL from validated arguments only. */
export function buildGraphSearch(request: LiveRequest): string {
  for (const key of Object.keys(ARG_RULES) as (keyof GraphArgs)[]) {
    const error = argError(key, String(request[key] ?? ""));
    if (error) throw new Error(error);
  }
  if (!TIME_RANGES.some((r) => r.value === request.earliest))
    throw new Error("Unsupported time range.");
  const { service, environment, cluster, namespace } = request;
  return `\`adm_graph("${service}","${environment}","${cluster}","${namespace}")\``;
}
/** Extracts a bounded, plain-text Splunk message from a search event payload. */
export function splunkMessage(payload: unknown): string | undefined {
  let text: unknown;
  if (typeof payload === "string") text = payload;
  else if (payload && typeof payload === "object") {
    const p = payload as {
      message?: unknown;
      content?: { messages?: { text?: unknown }[] };
    };
    text =
      typeof p.message === "string"
        ? p.message
        : p.content?.messages
            ?.map((m) => m?.text)
            .filter((t) => typeof t === "string" && t.trim())
            .join(" ");
  }
  if (typeof text !== "string") return undefined;
  const clean = text.replace(/\s+/g, " ").trim();
  if (!clean) return undefined;
  return clean.length > MAX_MESSAGE_CHARS
    ? `${clean.slice(0, MAX_MESSAGE_CHARS - 1)}…`
    : clean;
}
/** Converts SplunkJS json_rows results into row objects. */
export function resultRows(data: Results): Row[] {
  const fields = data.fields.map((f) => (typeof f === "string" ? f : f?.name));
  if (!fields.every((f) => typeof f === "string" && f))
    throw new Error("Splunk returned results without field names.");
  return (data.rows ?? []).map((values) => {
    const row: Row = {};
    fields.forEach((f, i) => {
      if (values[i] !== null && values[i] !== undefined)
        row[f as string] = values[i];
    });
    return row;
  });
}
const withDetail = (base: string, payload: unknown) => {
  const detail = splunkMessage(payload);
  return new Error(detail ? `${base} Splunk reported: ${detail}` : base);
};
const tooLarge = () =>
  new Error(
    "Graph exceeds the pilot limit (500 nodes / 2,000 edges). Narrow the time range or namespace.",
  );
export function loadLive(
  SearchManager: SearchConstructor,
  request: LiveRequest,
  signal: AbortSignal,
  release?: (id: string) => void,
): Promise<Graph> {
  let search: string;
  try {
    search = buildGraphSearch(request);
  } catch (e) {
    return Promise.reject(e);
  }
  return runRows(SearchManager, {
    search,
    earliest: request.earliest,
    maxRows: MAX_ROWS,
    signal,
    release,
    tooLarge,
    empty:
      "The graph search returned no rows. Check that the Application Atlas macros are installed and shared with your role.",
  }).then((rows) => rowsToGraph(rows, request));
}
/** Loads network inventory for candidate paths; callers treat failure as "no topology". */
export function loadTopology(
  SearchManager: SearchConstructor,
  earliest: string,
  signal: AbortSignal,
  release?: (id: string) => void,
): Promise<Topology> {
  if (!TIME_RANGES.some((r) => r.value === earliest))
    return Promise.reject(new Error("Unsupported time range."));
  return runRows(SearchManager, {
    search: TOPOLOGY_SEARCH,
    earliest,
    maxRows: MAX_TOPOLOGY_ROWS,
    signal,
    release,
    tooLarge: () => new Error("Topology exceeds the pilot limit."),
    empty: "The topology search returned no rows.",
  }).then(rowsToTopology);
}
interface RunOptions {
  search: string;
  earliest: string;
  maxRows: number;
  signal: AbortSignal;
  release?: (id: string) => void;
  tooLarge: () => Error;
  empty: string;
}
function runRows(
  SearchManager: SearchConstructor,
  { search, earliest, maxRows, signal, release, tooLarge, empty }: RunOptions,
): Promise<Row[]> {
  return new Promise((resolve, reject) => {
    if (signal.aborted) {
      reject(new Error("Search cancelled."));
      return;
    }
    const id = `adm-search-${++sequence}`;
    const manager = new SearchManager({
      id,
      app: "splunk_adm",
      autostart: false,
      preview: false,
      cancelOnUnload: true,
      earliest_time: earliest,
      latest_time: "now",
      search,
    });
    // One more than the limit, so an oversized result is detected rather than cut.
    const results = manager.data("results", {
      count: maxRows + 1,
      output_mode: "json_rows",
    });
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
    const finish = (rows?: Row[], error?: Error) => {
      if (finished) return;
      finished = true;
      cleanup();
      if (rows) resolve(rows);
      else reject(error ?? new Error(empty));
    };
    const abort = () => finish(undefined, new Error("Search cancelled."));
    const timer = setTimeout(
      () =>
        finish(
          undefined,
          new Error(
            "Search timed out after 120 seconds. Narrow the time range or check that the ADM saved searches are enabled.",
          ),
        ),
      120000,
    );
    signal.addEventListener("abort", abort);
    results.on("data", () => {
      if (!results.hasData()) return;
      try {
        const rows = resultRows(results.data());
        if (rows.length > maxRows) throw tooLarge();
        finish(rows);
      } catch (e) {
        finish(
          undefined,
          e instanceof Error ? e : new Error("Invalid search result."),
        );
      }
    });
    manager.on("search:done", (state) => {
      const count = Number(
        (state as { content?: { resultCount?: unknown } })?.content
          ?.resultCount,
      );
      if (count === 0) finish(undefined, new Error(empty));
      else if (count > maxRows) finish(undefined, tooLarge());
    });
    manager.on("search:error", (payload) =>
      finish(
        undefined,
        withDetail(
          "Splunk search failed. Check index access and search permissions.",
          payload,
        ),
      ),
    );
    for (const event of ["search:fail", "search:failed"])
      manager.on(event, (payload) =>
        finish(
          undefined,
          withDetail("Splunk could not complete the search.", payload),
        ),
      );
    manager.on("search:cancelled", (payload) =>
      finish(
        undefined,
        withDetail(
          "The Splunk search was cancelled before the graph loaded.",
          payload,
        ),
      ),
    );
    manager.startSearch();
  });
}
