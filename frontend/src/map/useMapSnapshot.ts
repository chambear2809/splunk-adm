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
  const loadDemo = (scenario: DemoScenario): MapSnapshot => ({
    graph: demoData ? demoData.graph() : demoGraph(scenario),
    topology: demoData ? demoData.topology() : demoTopology(scenario),
  });
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
    if (mode === "demo") {
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
      const result = await queryGraph(request);
      if (revision.current !== current) return undefined;
      setSnapshot({ ...result, request, client });
      setHasLiveGraph(true);
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
