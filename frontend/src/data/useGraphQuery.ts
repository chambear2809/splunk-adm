import { useCallback, useEffect, useRef } from "react";
import {
  emptyTopology,
  MAX_TOPOLOGY_ROWS,
  rowsToTopology,
  type Topology,
} from "../topology";
import { loadLive, type GraphTail, type LiveRequest } from "../provider";
import type { Graph } from "../graph";
import { SearchResultLimitError, type SearchClient } from "./searchClient";
import { boundedGraphClient } from "../scale/graphSearch";
import { resolveTime } from "./timeBounds";

/** adm_topology plus APIC VMM virtual ports, their switches and hosts. */
export const MAP_TOPOLOGY_SEARCH = "`adm_topology_with_vsphere`";
/**
 * The map reads MAP_TOPOLOGY_SEARCH as its two halves, dispatched side by side:
 * `adm_topology` and the VMM half the macro appends (`adm_map_vsphere_inventory`).
 * Rows are concatenated in the macro's order, so the inventory is the same; the
 * halves just no longer run serially.
 */
export const MAP_TOPOLOGY_SEARCHES = [
  "`adm_topology`",
  "| `adm_map_vsphere_inventory`",
] as const;
/** Qualified summaries cover five-minute slices; their graph window starts on a slice. */
const SUMMARY_SLICE_SECONDS = 300;

/** Inventory for one exact window, shared between the summary and full reads. */
export interface InventoryRead {
  start: string;
  end: string;
  topology: Promise<Topology>;
}

export interface GraphQueryOptions {
  /** Reuse this inventory when the graph window is the same exact window. */
  inventory?: InventoryRead;
  /** Called once the graph is known, before inventory has necessarily returned. */
  onGraph?: (
    graph: Graph,
    inventory: InventoryRead,
    request: LiveRequest,
  ) => void;
}

const mark = (name: string, start: number) => {
  try {
    performance.measure(name, { start });
  } catch {
    /* timing is diagnostic only */
  }
};

/**
 * Resolve relative bounds once in the browser so every read of this map (the
 * summary read, inventory and the full read) describes the same window, and
 * inventory can be dispatched beside the graph instead of after it.
 */
export function pinRequest(
  request: LiveRequest,
  nowSeconds = Date.now() / 1000,
): LiveRequest {
  const start = resolveTime(request.earliest, request.timezone, nowSeconds);
  const end = resolveTime(
    request.latest ?? "now",
    request.timezone,
    nowSeconds,
  );
  if (start === undefined || end === undefined || !(end > start))
    return request;
  const first = Math.floor(start),
    last = Math.floor(end);
  return {
    ...request,
    // Windows over one slice are counted in whole five-minute slices from
    // the slice boundary at or before the start; request exactly that window
    // so the displayed bounds are the counted bounds.
    earliest: String(
      last - first > SUMMARY_SLICE_SECONDS
        ? first - (first % SUMMARY_SLICE_SECONDS)
        : first,
    ),
    latest: String(last),
  };
}

/** The graph window a pinned request is expected to return (verified afterwards). */
export function expectedWindow(request: LiveRequest) {
  const start = Number(request.earliest),
    end = Number(request.latest);
  if (!/^\d+$/.test(request.earliest) || !/^\d+$/.test(request.latest ?? ""))
    return undefined;
  return {
    start: String(
      end - start > SUMMARY_SLICE_SECONDS
        ? start - (start % SUMMARY_SLICE_SECONDS)
        : start,
    ),
    end: String(end),
  };
}

/** Map inventory: both halves of MAP_TOPOLOGY_SEARCH at once, concatenated in macro order. */
export async function loadMapInventory(
  client: SearchClient,
  start: string,
  signal: AbortSignal,
  end: string,
  timezone?: string,
): Promise<Topology> {
  const started = performance.now();
  const [base, vsphere] = await Promise.all(
    MAP_TOPOLOGY_SEARCHES.map((search, index) =>
      client.search({
        search,
        earliest: start,
        latest: end,
        timezone,
        maxRows: MAX_TOPOLOGY_ROWS,
        signal,
        // A stack without VMM evidence legitimately has no virtual ports.
        allowEmpty: index === 1,
      }),
    ),
  );
  mark("atlas:inventory", started);
  for (const part of [base, vsphere])
    if (part.errors.length)
      throw new Error(
        `Splunk topology search was incomplete: ${part.errors[0]}`,
      );
  if (base.rows.length + vsphere.rows.length > MAX_TOPOLOGY_ROWS)
    throw new SearchResultLimitError(MAX_TOPOLOGY_ROWS);
  const topology = rowsToTopology([...base.rows, ...vsphere.rows]);
  topology.warnings = [
    ...new Set([...topology.warnings, ...base.warnings, ...vsphere.warnings]),
  ];
  return topology;
}

const unavailable = (error: unknown) => {
  const topology = emptyTopology();
  topology.warnings.push(
    `Network inventory unavailable. ${error instanceof Error ? error.message.slice(0, 300) : "Search failed."}`,
  );
  return topology;
};

export async function queryGraph(
  client: SearchClient,
  draft: LiveRequest,
  controller: AbortController,
  tail?: GraphTail,
  options: GraphQueryOptions = {},
): Promise<{ graph: Graph; topology: Topology }> {
  const request = pinRequest(draft);
  const inventory = (
    start: string,
    end: string,
    signal = controller.signal,
  ): InventoryRead => ({
    start,
    end,
    topology: loadMapInventory(
      client,
      start,
      signal,
      end,
      request.timezone,
    ).catch(unavailable),
  });
  const matches = (
    read: InventoryRead | undefined,
    start: string,
    end: string,
  ) => (read && read.start === start && read.end === end ? read : undefined);
  const speculative = new AbortController();
  const cancelSpeculative = () => speculative.abort();
  controller.signal.addEventListener("abort", cancelSpeculative);
  try {
    const started = performance.now();
    // The graph read is a ranked top-N search: a large scope yields the
    // heaviest relationships and a truncation summary instead of an error.
    // It is dispatched first: it is what the first draw needs most.
    const graphRead = loadLive(
      boundedGraphClient(client),
      request,
      controller.signal,
      tail,
    );
    // Inventory must describe the same captured window as the graph. With
    // pinned bounds that window is known before dispatch, so inventory runs
    // beside the graph; a different returned window cancels it and is re-read.
    const expected = expectedWindow(request);
    const early =
      expected &&
      (matches(options.inventory, expected.start, expected.end) ??
        (options.inventory
          ? undefined
          : inventory(expected.start, expected.end, speculative.signal)));
    let graph: Graph;
    try {
      graph = await graphRead;
    } catch (error) {
      speculative.abort();
      throw error;
    }
    mark(`atlas:graph:${tail ?? "full"}`, started);
    if (controller.signal.aborted) throw new Error("Search cancelled.");
    const start = String(Date.parse(graph.window.start) / 1000),
      end = String(Date.parse(graph.window.end) / 1000);
    const reused =
      matches(early || undefined, start, end) ??
      matches(options.inventory, start, end);
    if (!reused || reused !== early) speculative.abort();
    const read = reused ?? inventory(start, end);
    options.onGraph?.(graph, read, request);
    const topology = await read.topology;
    if (controller.signal.aborted) throw new Error("Search cancelled.");
    return { graph, topology };
  } catch (error) {
    controller.abort();
    throw explainGraphError(error);
  } finally {
    controller.signal.removeEventListener("abort", cancelSpeculative);
  }
}

/** Qualified identity (admqualified) reads long windows as five-minute slices, up to 8 days. */
export function explainGraphError(error: unknown): unknown {
  if (
    error instanceof Error &&
    /identity window exceeds 300 seconds|between 1 second and 8 days/.test(
      error.message,
    )
  )
    return new Error(
      "This application uses qualified identity, which maps windows of up to 7 days. Choose a shorter time range.",
    );
  return error;
}

export function useGraphQuery(client: SearchClient | undefined) {
  const controllers = useRef(new Set<AbortController>());
  const abort = useCallback(() => {
    for (const controller of controllers.current) controller.abort();
    controllers.current.clear();
  }, []);
  const run = useCallback(
    async (
      request: LiveRequest,
      tail?: GraphTail,
      options?: GraphQueryOptions & {
        /** Keep earlier reads of the same build running (the full read). */
        concurrent?: boolean;
      },
    ): Promise<{ graph: Graph; topology: Topology }> => {
      if (!options?.concurrent) abort();
      const next = new AbortController();
      controllers.current.add(next);
      if (!client) throw new Error("Search client is unavailable.");
      try {
        return await queryGraph(client, request, next, tail, options);
      } finally {
        controllers.current.delete(next);
      }
    },
    [abort, client],
  );
  useEffect(() => abort, [abort, client]);
  return { queryGraph: run, abort };
}
