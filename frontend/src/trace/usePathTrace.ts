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
import type { SearchClient } from "../data/searchClient";
import type { Graph } from "../graph";
import { indexTopology, type Topology, type TopologyIndex } from "../topology";
import { traceSummary, traceTopology, type TraceSummary } from "./traceModel";
import {
  isIpLiteral,
  loadStandaloneTrace,
  traceWindow,
} from "./standaloneTrace";
import { emptyTopology } from "../topology";
import { sourceLabel } from "../glossary";
import { resolveTime } from "../data/timeBounds";
import { assemblePathEvidence } from "./pathEvidence";
import { nativeObservationHops, nativeSourceHops } from "./nativeObservations";
import { attachGnmiContext } from "./gnmiContext";

export const MAX_PATH_TRACE_ROWS = 2000;

export interface TraceRequest {
  src: string;
  dst: string;
  scope?: string;
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

/** Scoped observations are not a reconstructed route. */
export function assembleScopedTrace(
  request: TraceRequest,
  graph: Graph,
  rows: readonly unknown[],
  window?: { start: number; end: number },
) {
  const topo = indexTopology(emptyTopology());
  const sources = new Map<string, { records: number; drops: number }>();
  let capped = false;
  for (const value of rows) {
    if (!value || typeof value !== "object") continue;
    const row = value as Record<string, unknown>;
    if (row.row_type !== "observation" || typeof row.flow_source !== "string")
      continue;
    if (row.observers_capped === "1" || row.observers_capped === 1)
      capped = true;
    const count = Number(row.records);
    if (Number.isFinite(count) && count >= 0) {
      const previous = sources.get(row.flow_source) ?? { records: 0, drops: 0 };
      const drops = Number(row.drops);
      sources.set(row.flow_source, {
        records: previous.records + count,
        drops:
          previous.drops + (Number.isFinite(drops) && drops > 0 ? drops : 0),
      });
    }
  }
  const nativeHops = attachGnmiContext(
    [
      ...nativeSourceHops(rows, request),
      ...nativeObservationHops(rows, request),
    ],
    rows,
    { scope: request.scope, earliest: window?.start, latest: window?.end },
  );
  const gap = "A complete scoped packet route is unavailable for this window.";
  const trace: PathTrace = {
    status: "partial",
    src: resolveTraceEndpoint(request.src, graph, topo),
    dst: resolveTraceEndpoint(request.dst, graph, topo),
    hops: nativeHops.length
      ? nativeHops
      : [{ kind: "gap", label: gap, evidence: "gap", sources: [], seen: [] }],
    gaps: nativeHops.length
      ? nativeHops
          .filter((hop) => hop.evidence === "gap")
          .map((hop) => hop.label)
      : [gap],
    conversations: [],
    drops: [],
    notes: [
      "Observations from different sources may describe the same traffic; counts are not combined.",
      ...[...sources].map(
        ([source, count]) =>
          `${sourceLabel(source)}: ${count.records} observed records${count.drops ? `, including ${count.drops} ${count.drops === 1 ? "drop" : "drops"}` : ""}.`,
      ),
      ...(capped
        ? [
            "The observation limit was reached; displayed source counts are incomplete.",
          ]
        : []),
      "Source coverage and identity may be incomplete; missing observations do not prove absence.",
    ],
  };
  return { trace, summary: traceSummary([]), topo };
}

/** Combine bounded captures with independently reported source observations. */
export function assembleStandaloneResult(
  request: TraceRequest,
  result: {
    addresses: TraceRequest;
    window?: { start: number; end: number };
    graph: Graph;
    rows: readonly unknown[];
    evidence: Parameters<typeof assemblePathEvidence>[2];
  },
) {
  const addresses = { ...result.addresses, scope: request.scope };
  const scoped = assembleScopedTrace(
    addresses,
    result.graph,
    result.rows,
    result.window,
  );
  if (!result.evidence.length) return scoped;
  const trace = assemblePathEvidence(request, result.graph, result.evidence);
  const nativeHops = scoped.trace.hops.filter(
    (hop) =>
      hop.kind !== "gap" || hop.sources.length || scoped.trace.hops.length > 1,
  );
  return {
    trace: {
      ...trace,
      hops: [...trace.hops, ...nativeHops],
      gaps: [
        ...trace.gaps,
        ...nativeHops
          .filter((hop) => hop.evidence === "gap")
          .map((hop) => hop.label),
      ],
      notes: [...trace.notes, ...scoped.trace.notes],
    },
    summary: traceSummary([]),
    topo: scoped.topo,
  };
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
    const pair = { src, dst, scope: request?.scope };
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
      const now = Date.now() / 1000;
      const start = resolveTime(earliest, timezone, now);
      const end = resolveTime(latest ?? "now", timezone, now);
      if (start === undefined || end === undefined || end <= start) {
        fail(new Error("Select a valid time window before tracing."));
        return () => next.abort();
      }
      const windowStart = String(Math.floor(start));
      const windowEnd = String(Math.floor(end));
      setResult({ status: "loading" });
      void loadStandaloneTrace(client, pair, {
        earliest: windowStart,
        latest: windowEnd,
        timezone,
        signal: next.signal,
        scope: pair.scope,
      })
        .then((r) =>
          done({
            status: "done",
            ...assembleStandaloneResult(pair, r),
          }),
        )
        .catch(fail);
      return () => next.abort();
    }
    const topo = indexTopology(topology);
    const a = traceAddress(src, graph, topo),
      b = traceAddress(dst, graph, topo);
    if (!a || !b || a === b) {
      fail(
        new Error(
          a && b
            ? "Source and destination are the same address."
            : "Choose two unambiguous endpoint addresses.",
        ),
      );
      return () => next.abort();
    }
    // Picker edits may describe a different window than the graph and
    // topology already displayed. Always use the loaded graph's bounds.
    const start = Date.parse(graph.window.start) / 1000;
    const end = Date.parse(graph.window.end) / 1000;
    let scope: string;
    try {
      traceWindow(String(start), String(end));
      const source = resolveTraceEndpoint(src, graph, topo).node;
      const target = resolveTraceEndpoint(dst, graph, topo).node;
      const sourceScope = source?.attributes?.scope;
      const targetScope = target?.attributes?.scope;
      const selectedScope =
        pair.scope ?? (sourceScope === targetScope ? sourceScope : undefined);
      if (
        !selectedScope ||
        sourceScope !== selectedScope ||
        targetScope !== selectedScope
      )
        throw new Error(
          "Select endpoints in one verified routing scope before tracing.",
        );
      pathTraceSearch(a, b, selectedScope);
      scope = selectedScope;
    } catch (e) {
      fail(e);
      return () => next.abort();
    }
    setResult({ status: "loading" });
    void loadStandaloneTrace(
      client,
      { src: a, dst: b },
      {
        earliest: String(start),
        latest: String(end),
        scope,
        timezone,
        signal: next.signal,
      },
    )
      .then((r) =>
        done({
          status: "done",
          ...assembleStandaloneResult({ ...pair, scope }, r),
        }),
      )
      .catch(fail);
    return () => next.abort();
  }, [
    src,
    dst,
    request?.scope,
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
