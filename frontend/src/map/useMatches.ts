import { useMemo } from "react";
import { indexGraph, matchesQuery, type Graph } from "../graph";
import { edgeMatches, type indexTopology } from "../topology";
import type { computeLayout } from "../layout";
export function useMatches(
  graph: Graph,
  topo: ReturnType<typeof indexTopology>,
  layout: ReturnType<typeof computeLayout>,
  q: string,
) {
  const graphIndex = useMemo(() => indexGraph(graph), [graph]);
  const matchNodes = useMemo(
    () =>
      q
        ? new Set(
            graph.nodes.filter((n) => matchesQuery(n, q)).map((n) => n.id),
          )
        : undefined,
    [q, graph],
  );
  const matchEdges = useMemo(
    () =>
      q
        ? new Set(
            graph.edges
              .filter((e) => edgeMatches(e, q, topo, graphIndex))
              .map((e) => e.id),
          )
        : undefined,
    [q, graph, graphIndex, topo],
  );
  const matchList = useMemo(() => {
    if (!matchNodes || !matchEdges) return [];
    const seen = new Set<string>();
    const nodes = layout.order.filter((id) => {
      const it = layout.items.get(id)!;
      return (
        (it.members ?? [id]).some((m) => matchNodes.has(m)) &&
        !seen.has(id) &&
        seen.add(id)
      );
    });
    const edges = layout.edges
      .filter((r) => matchEdges.has(r.id))
      .sort((a, b) => a.mid.x - b.mid.x || a.mid.y - b.mid.y)
      .map((r) => r.id);
    return [
      ...nodes.map((id) => ({ kind: "node" as const, id })),
      ...edges.map((id) => ({ kind: "edge" as const, id })),
    ];
  }, [matchNodes, matchEdges, layout]);
  return { matchNodes, matchEdges, matchList };
}
