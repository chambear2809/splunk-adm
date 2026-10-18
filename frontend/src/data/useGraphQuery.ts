import { useCallback, useEffect, useRef } from "react";
import { emptyTopology, type Topology } from "../topology";
import { loadLive, loadTopology, type LiveRequest } from "../provider";
import type { Graph } from "../graph";
import type { SearchClient } from "./searchClient";

export async function queryGraph(
  client: SearchClient,
  request: LiveRequest,
  controller: AbortController,
): Promise<{ graph: Graph; topology: Topology }> {
  try {
    const graph = await loadLive(client, request, controller.signal);
    if (controller.signal.aborted) throw new Error("Search cancelled.");
    // Inventory must describe the same captured window as the graph. Relative
    // bounds (especially "now") can otherwise move between search dispatches.
    const topology = await loadTopology(
      client,
      String(Date.parse(graph.window.start) / 1000),
      controller.signal,
      String(Date.parse(graph.window.end) / 1000),
      request.timezone,
    ).catch((error: unknown) => {
      const unavailable = emptyTopology();
      unavailable.warnings.push(
        `Network inventory unavailable. ${error instanceof Error ? error.message.slice(0, 300) : "Search failed."}`,
      );
      return unavailable;
    });
    if (controller.signal.aborted) throw new Error("Search cancelled.");
    return { graph, topology };
  } catch (error) {
    controller.abort();
    throw error;
  }
}

export function useGraphQuery(client: SearchClient | undefined) {
  const controller = useRef<AbortController | undefined>(undefined);
  const abort = useCallback(() => controller.current?.abort(), []);
  const run = useCallback(
    async (
      request: LiveRequest,
    ): Promise<{ graph: Graph; topology: Topology }> => {
      controller.current?.abort();
      const next = new AbortController();
      controller.current = next;
      if (!client) throw new Error("Search client is unavailable.");
      return queryGraph(client, request, next);
    },
    [client],
  );
  useEffect(() => abort, [abort, client]);
  return { queryGraph: run, abort };
}
