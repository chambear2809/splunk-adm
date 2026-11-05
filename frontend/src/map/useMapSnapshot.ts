import { useCallback, useEffect, useRef, useState } from "react";
import type { UrlState } from "../app/urlState";
import {
  demoArgsFor,
  demoGraph,
  demoTopology,
  prepareDemo,
  type DemoScenario,
} from "../data/demoClient";
import type { SearchClient } from "../data/searchClient";
import { useGraphQuery } from "../data/useGraphQuery";
import type { Graph } from "../graph";
import { ARG_RULES, argError, type LiveRequest } from "../provider";
import { serviceNodeId, type GraphArgs } from "../rows";
import { emptyTopology, type Topology } from "../topology";
import { pickerBound } from "./TimePicker";

export interface MapSnapshot {
  graph: Graph;
  topology: Topology;
  /** The exact draft and identity that produced this pair, not subsequent edits. */
  request?: LiveRequest;
  client?: SearchClient;
}

const measure = (name: string, start: number) => {
  try {
    performance.measure(name, { start });
  } catch {
    /* timing is diagnostic only */
  }
};

function pendingGraph(args: GraphArgs): Graph {
  const instant = new Date(0).toISOString();
  return {
    schema_version: 1,
    snapshot_id: "pending",
    generated_at: instant,
    demo: false,
    window: { start: instant, end: instant },
    boundary: { ...args, id: "pending", root_node_id: serviceNodeId(args) },
    nodes: [],
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
}

/** Own draft controls and publish complete graph/inventory snapshots together. */
export function useMapSnapshot({
  client,
  initialState,
  timezone,
  demoData,
}: {
  client?: SearchClient;
  initialState: UrlState;
  timezone?: string;
  demoData?: { graph: () => Graph; topology: () => Topology };
}) {
  // Demo captures exist only in the development build; the packaged app
  // never enters demo mode (parseUrlState forces live).
  const loadDemo = (scenario: DemoScenario): MapSnapshot => {
    if (__ADM_SPLUNK_BUILD__)
      throw new Error("Demo data is not available in the Splunk app.");
    return {
      graph: demoData ? demoData.graph() : demoGraph(scenario),
      topology: demoData ? demoData.topology() : demoTopology(scenario),
    };
  };
  const [snapshot, setSnapshot] = useState<MapSnapshot>(() =>
    initialState.mode === "demo"
      ? loadDemo(initialState.scenario)
      : { graph: pendingGraph(initialState.args), topology: emptyTopology() },
  );
  const [mode, setMode] = useState(initialState.mode);
  const [scenario, setScenario] = useState(initialState.scenario);
  const [args, setArgs] = useState<GraphArgs>(
    initialState.mode === "demo" ? snapshot.graph.boundary : initialState.args,
  );
  const [earliest, setEarliest] = useState(
    initialState.mode === "demo"
      ? pickerBound(snapshot.graph.window.start)
      : initialState.earliest,
  );
  const [latest, setLatest] = useState(
    initialState.mode === "demo"
      ? pickerBound(snapshot.graph.window.end)
      : initialState.latest,
  );
  const [hasLiveGraph, setHasLiveGraph] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const { queryGraph, abort } = useGraphQuery(client);
  const revision = useRef(0);
  const cancelQuery = useCallback(() => {
    revision.current++;
    abort();
    setBusy(false);
  }, [abort]);
  useEffect(() => {
    // A replacement search client is a different evidence authority. Retain
    // the prior snapshot, but never let its pending request publish afterward.
    cancelQuery();
    return () => {
      // revision is a request counter, not a DOM ref; bumping it invalidates in-flight work.
      // eslint-disable-next-line react-hooks/exhaustive-deps
      revision.current++;
      abort();
    };
  }, [client, cancelQuery, abort]);

  const refresh = async (): Promise<boolean | undefined> => {
    if (!__ADM_SPLUNK_BUILD__ && mode === "demo") {
      const captured = loadDemo(scenario);
      setSnapshot(captured);
      setEarliest(pickerBound(captured.graph.window.start));
      setLatest(pickerBound(captured.graph.window.end));
      setArgs(demoData ? captured.graph.boundary : demoArgsFor(scenario));
      return true;
    }
    if (!client) {
      setError("Live search is available inside the installed Splunk app.");
      return false;
    }
    cancelQuery();
    const current = revision.current;
    const request = { ...args, earliest, latest, timezone };
    setBusy(true);
    setError("");
    try {
      const started = performance.now();
      // Progressive load: summaries first; when minutes remain unread the
      // full window (summaries plus the newest raw minutes) follows. It starts
      // as soon as the summary graph returns, beside the inventory read, and
      // reuses that exact-window inventory instead of reading it again.
      let full: Promise<{ graph: Graph; topology: Topology }> | undefined;
      const result = await queryGraph(request, "deferred", {
        onGraph: (graph, inventory, pinned) => {
          if (graph.read?.pendingSeconds && revision.current === current) {
            full = queryGraph(pinned, undefined, {
              concurrent: true,
              inventory,
            });
            // A superseded build aborts this read; that is not an error.
            full.catch(() => undefined);
          }
        },
      });
      if (revision.current !== current) return undefined;
      setSnapshot({ ...result, request, client });
      setHasLiveGraph(true);
      measure("atlas:map:first", started);
      if (full) {
        setBusy(false);
        full
          .then((value) => {
            if (revision.current === current) {
              setSnapshot({ ...value, request, client });
              measure("atlas:map:full", started);
            }
          })
          .catch((error: unknown) => {
            if (revision.current !== current) return;
            // Keep the summarized map; the chip now shows partial coverage.
            setSnapshot((prior) => ({
              ...prior,
              graph: {
                ...prior.graph,
                read: { ...prior.graph.read!, pendingSeconds: 0 },
                coverage: {
                  ...prior.graph.coverage,
                  warnings: [
                    ...prior.graph.coverage.warnings,
                    `Newest minutes could not be read: ${error instanceof Error ? error.message.slice(0, 200) : "search failed"}`,
                  ],
                },
              },
            }));
          });
      }
      return true;
    } catch (error) {
      if (revision.current !== current) return undefined;
      setError(
        error instanceof Error ? error.message : "Unable to load the map.",
      );
      return false;
    } finally {
      if (revision.current === current) setBusy(false);
    }
  };
  const showDemo = async (next = scenario): Promise<boolean> => {
    cancelQuery();
    const current = revision.current;
    setBusy(true);
    setError("");
    try {
      if (__ADM_SPLUNK_BUILD__)
        throw new Error("Demo data is not available in the Splunk app.");
      await prepareDemo();
      if (revision.current !== current) return false;
      const captured = loadDemo(next);
      setSnapshot(captured);
      setScenario(next);
      setEarliest(pickerBound(captured.graph.window.start));
      setLatest(pickerBound(captured.graph.window.end));
      setMode("demo");
      setArgs(demoData ? captured.graph.boundary : demoArgsFor(next));
      setHasLiveGraph(false);
      return true;
    } catch (error) {
      if (revision.current === current)
        setError(
          error instanceof Error ? error.message : "Unable to load demo data.",
        );
      return false;
    } finally {
      if (revision.current === current) setBusy(false);
    }
  };
  const switchLive = () => {
    cancelQuery();
    setMode("live");
    setHasLiveGraph(false);
    setError("");
  };
  useEffect(() => {
    if (
      initialState.mode === "live" &&
      client &&
      (Object.keys(ARG_RULES) as (keyof GraphArgs)[]).every(
        (key) => !argError(key, initialState.args[key]),
      )
    )
      void refresh();
    // Initial deep links dispatch once. Draft edits require Build map.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
  return {
    ...snapshot,
    snapshot,
    mode,
    scenario,
    args,
    earliest,
    latest,
    busy,
    error,
    visible: mode === "demo" || hasLiveGraph,
    setArgs,
    setEarliest,
    setLatest,
    cancelQuery,
    refresh,
    showDemo,
    switchLive,
  };
}
