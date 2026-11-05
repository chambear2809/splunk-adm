import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  DEMO_PATH_TRACE_PAIR,
  demoGraph,
  demoPathTraceRows,
  demoVsphereTopology,
  prepareDemo,
} from "../data/demoClient";
import {
  fabricEvidenceRows,
  pathTraceDrops,
  pathTraceObservers,
  resolveTraceEndpoint,
  tracePath,
  type PathTrace,
} from "../data/pathTrace";
import { pathTraceSearch } from "../data/deviceFlows";
import { l3outRows } from "../data/l3outEgress";
import { requireNoSearchErrors, type SearchClient } from "../data/searchClient";
import type { Graph } from "../graph";
import { indexTopology, type Topology, type TopologyIndex } from "../topology";
import { traceSummary, traceTopology, type TraceSummary } from "./traceModel";
import { isIpLiteral, loadStandaloneTrace } from "./standaloneTrace";

export const MAX_PATH_TRACE_ROWS = 2000;

export interface TraceRequest {
  src: string;
  dst: string;
}
export type TraceResult =
  | { status: "idle" }
  | { status: "waiting" }
  | { status: "loading" }
  | { status: "error"; error: string }
  | {
      status: "done";
      trace: PathTrace;
      summary: TraceSummary;
      topo: TopologyIndex;
    };

/** Pure assembly once rows are known; exported for tests. */
export function assembleTrace(
  request: TraceRequest,
  graph: Graph,
  topology: Topology,
  rows: readonly unknown[],
) {
  const topo = indexTopology(traceTopology(topology, rows));
  const trace = tracePath({
    ...request,
    graph,
    topology: topo,
    observers: pathTraceObservers(rows),
    fabricEvidence: fabricEvidenceRows(rows),
    l3out: l3outRows(rows),
    drops: pathTraceDrops(rows),
  });
  return { trace, summary: traceSummary(rows), topo };
}

/** Resolves a name or IP to the IP adm_path_trace needs. */
export function traceAddress(
  query: string,
  graph: Graph,
  topo: TopologyIndex,
): string | undefined {
  const q = query.trim();
  if (isIpLiteral(q)) return q;
  const node = resolveTraceEndpoint(q, graph, topo).node;
  return node?.addresses?.find(isIpLiteral);
}

/**
 * Runs one source → destination trace. Demo uses the captured ACI pair; live
 * issues adm_path_trace for the resolved addresses within the time range and
 * assembles hops against the loaded map graph and inventory.
 */
export function usePathTrace({
  request,
  demo,
  client,
  graph,
  topology,
  earliest,
  latest,
  timezone,
}: {
  request?: TraceRequest;
  demo: boolean;
  client?: SearchClient;
  /** Loaded live map graph; undefined until the map is built. */
  graph?: Graph;
  topology?: Topology;
  earliest: string;
  latest?: string;
  timezone?: string;
}): TraceResult & { cancel: () => void; retry: () => void } {
  const [result, setResult] = useState<TraceResult>({ status: "idle" });
  const [nonce, setNonce] = useState(0);
  const controller = useRef<AbortController | undefined>(undefined);
  const cancel = useCallback(() => {
    controller.current?.abort();
    setResult((r) =>
      r.status === "loading" ? { status: "error", error: "Cancelled" } : r,
    );
  }, []);
  const retry = useCallback(() => setNonce((n) => n + 1), []);
  const src = request?.src,
    dst = request?.dst;
  useEffect(() => {
    controller.current?.abort();
    if (!src || !dst) {
      setResult({ status: "idle" });
      return;
    }
    const next = new AbortController();
    controller.current = next;
    const done = (r: TraceResult) => {
      if (!next.signal.aborted) setResult(r);
    };
    const pair = { src, dst };
    if (!__ADM_SPLUNK_BUILD__ && demo) {
      setResult({ status: "loading" });
      void prepareDemo()
        .then(() => {
          const rows =
            src === DEMO_PATH_TRACE_PAIR.src && dst === DEMO_PATH_TRACE_PAIR.dst
              ? demoPathTraceRows()
              : [];
          done({
            status: "done",
            ...assembleTrace(
              pair,
              demoGraph("aci"),
              demoVsphereTopology(),
              rows,
            ),
          });
        })
        .catch((e: unknown) =>
          done({
            status: "error",
            error: e instanceof Error ? e.message : "Demo data unavailable",
          }),
        );
      return () => next.abort();
    }
    if (!client) {
      setResult({ status: "waiting" });
      return () => next.abort();
    }
    const fail = (e: unknown) =>
      done({
        status: "error",
        error: e instanceof Error ? e.message : "Path trace failed",
      });
    if (!graph || !topology) {
      // No map: resolve names and assemble the path from server-side rows.
      setResult({ status: "loading" });
      void loadStandaloneTrace(client, pair, {
        earliest,
        latest,
        timezone,
        signal: next.signal,
      })
        .then((r) =>
          done({
            status: "done",
            ...assembleTrace(r.addresses, r.graph, r.topology, r.rows),
          }),
        )
        .catch(fail);
      return () => next.abort();
    }
    const topo = indexTopology(topology);
    const a = traceAddress(src, graph, topo),
      b = traceAddress(dst, graph, topo);
    if (!a || !b || a === b) {
      // tracePath explains which endpoint is unknown or duplicated.
      setResult({
        status: "done",
        ...assembleTrace(pair, graph, topology, []),
      });
      return () => next.abort();
    }
    setResult({ status: "loading" });
    void client
      .search({
        search: pathTraceSearch(a, b),
        earliest,
        latest,
        timezone,
        maxRows: MAX_PATH_TRACE_ROWS,
        allowEmpty: true,
        signal: next.signal,
      })
      .then((r) => {
        const rows = requireNoSearchErrors(r, "Path trace").rows;
        done({ status: "done", ...assembleTrace(pair, graph, topology, rows) });
      })
      .catch((e: unknown) =>
        done({
          status: "error",
          error: e instanceof Error ? e.message : "Path trace failed",
        }),
      );
    return () => next.abort();
  }, [
    src,
    dst,
    demo,
    client,
    graph,
    topology,
    earliest,
    latest,
    timezone,
    nonce,
  ]);
  return useMemo(() => ({ ...result, cancel, retry }), [result, cancel, retry]);
}
