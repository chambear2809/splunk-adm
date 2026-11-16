import { useMemo } from "react";
import type { Graph } from "../graph";
import type { TopologyIndex } from "../topology";
import { graphConversations } from "./data";
import { isImpactToken, MAX_IMPACT_ELEMENTS, resolveElement } from "./elements";
import { failsImpact } from "./model";
import { pathContext } from "./paths";
import type { Severity } from "./classify";

export interface ImpactOverlay {
  /** Cards and conversations that are affected (everything else is dimmed). */
  nodes: Set<string>;
  edges: Set<string>;
  headline: string;
  /** `impact-outage` / `impact-degraded` / `impact-unknown` for a card's or line's member IDs. */
  className: (ids: readonly string[]) => string;
}

const RANK: Record<Exclude<Severity, "unaffected">, number> = {
  degraded: 1,
  unknown: 2,
  outage: 3,
};

/** `?impact=<element>` on the map: the same classification over the map's graph and topology. */
export function useImpactOverlay(
  graph: Graph | undefined,
  topo: TopologyIndex,
): ImpactOverlay | undefined {
  const tokens = useMemo(() => {
    if (typeof location === "undefined") return [];
    return new URLSearchParams(location.search)
      .getAll("impact")
      .filter(isImpactToken)
      .slice(0, MAX_IMPACT_ELEMENTS);
  }, []);
  return useMemo(() => {
    if (!graph || !tokens.length) return undefined;
    const topology = {
      devices: [...topo.byId.values()],
      links: [],
      interfaces: [],
      warnings: [],
    };
    const elements = tokens
      .map((t) => resolveElement(t, topology, topo, graph))
      .filter((e) => e.resolved);
    if (!elements.length) return undefined;
    const r = failsImpact(
      elements,
      graphConversations(graph),
      pathContext(topo, graph),
    );
    const sev = new Map<string, Exclude<Severity, "unaffected">>([
      ...r.nodes,
      ...r.edges,
    ]);
    return {
      nodes: new Set(r.nodes.keys()),
      edges: new Set(r.edges.keys()),
      headline: r.headline,
      className: (ids) => {
        let best: Exclude<Severity, "unaffected"> | undefined;
        for (const id of ids) {
          const s = sev.get(id);
          if (s && (!best || RANK[s] > RANK[best])) best = s;
        }
        return best ? `impact-${best}` : "";
      },
    };
  }, [graph, topo, tokens]);
}
