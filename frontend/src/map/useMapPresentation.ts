import { useCallback, useEffect, useMemo, useState } from "react";
import {
  indexGraph,
  type Graph,
  type GraphEdge,
  type GraphNode,
} from "../graph";
import {
  edgeIdentity,
  handoffConfidence,
  handoffShort,
  plural,
  portLabel,
  prettyBytes,
  summarize,
} from "../glossary";
import { computeLayout, type View } from "../layout";
import { FIT_MIN, type Selection } from "../MapView";
import { filterGraph, focusHops, type Facets } from "../filters";
import {
  buildPath,
  deviceName,
  edgeDeviceContext,
  indexTopology,
  nodeDeviceContext,
  observationsByDevice,
  type Topology,
} from "../topology";
import { useMatches } from "./useMatches";
type Tab = View | "devices" | "table";

export function useMapPresentation({
  graph,
  topology,
  tab,
  setTab,
  mergeFrontends,
  initialQuery,
}: {
  graph: Graph;
  topology: Topology;
  tab: Tab;
  setTab: (tab: Tab) => void;
  mergeFrontends: boolean;
  initialQuery: string;
}) {
  const [backend, setBackend] = useState<string>();
  const [collapse, setCollapse] = useState(false);
  const [expanded, setExpanded] = useState<ReadonlySet<string>>(new Set());
  const [facets, setFacets] = useState<Facets>({});
  const [focus, setFocus] = useState<{ id: string; hops: number } | null>(null);
  const clearFilters = () => {
    setFacets({});
    setFocus(null);
  };
  const changeFacets = (next: Facets) => {
    if (tab === "services") setTab("network");
    setFacets(next);
    select(null);
  };
  const [selection, setSelection] = useState<Selection | null>(null);
  const [pathHidden, setPathHidden] = useState(false);
  const [query, setQuery] = useState(initialQuery);
  const [matchIdx, setMatchIdx] = useState(-1);
  const [focusTarget, setFocusTarget] = useState<{
    kind: "node" | "edge";
    id: string;
    nonce: number;
  }>();
  const [focusRequest, setFocusRequest] = useState<{
    id: string;
    nonce: number;
  }>();
  const select = (s: Selection | null) => {
    setSelection(s);
    setPathHidden(false);
    setBackend(undefined);
  };
  /** Clears the selection and returns keyboard focus to its card on the map. */
  const clearSelection = () => {
    const prev = selection;
    select(null);
    if (!prev) return;
    const id = prev.kind === "node" ? prev.id : index.edge.get(prev.id)?.source;
    if (id) setFocusRequest({ id, nonce: Date.now() });
  };
  const resetView = () => {
    setCollapse(false);
    setExpanded(new Set());
  };
  const index = useMemo(() => indexGraph(graph), [graph]);
  const topo = useMemo(() => indexTopology(topology), [topology]);
  const node = useCallback((id: string) => index.node.get(id), [index]);
  const view: View = tab === "services" ? "services" : "network";
  const filtered = useMemo(() => filterGraph(graph, facets), [graph, facets]);
  const displayGraph = useMemo(() => {
    if (!focus) return filtered;
    const ids = focusHops(indexGraph(filtered), focus.id, focus.hops);
    return {
      ...filtered,
      nodes: filtered.nodes.filter((n) => ids.has(n.id)),
      edges: filtered.edges.filter(
        (e) => ids.has(e.source) && ids.has(e.target),
      ),
    };
  }, [filtered, focus]);
  const displayIndex = useMemo(() => indexGraph(displayGraph), [displayGraph]);
  useEffect(() => {
    if (
      selection &&
      !(selection.kind === "node" ? displayIndex.node : displayIndex.edge).has(
        selection.id,
      )
    ) {
      setSelection(null);
      setBackend(undefined);
      setPathHidden(false);
    }
  }, [displayIndex, selection]);
  const narrowed = displayGraph !== graph;
  const layout = useMemo(
    () =>
      computeLayout(displayGraph, displayIndex, view, {
        collapse,
        expanded,
        mergeFrontends,
      }),
    [displayGraph, displayIndex, view, collapse, expanded, mergeFrontends],
  );
  useEffect(() => resetView(), [view]);
  const onFitScale = useCallback(
    (raw: number) => setCollapse(raw < FIT_MIN),
    [],
  );

  const q = query.trim();
  const { matchNodes, matchEdges, matchList } = useMatches(
    displayGraph,
    topo,
    layout,
    q,
  );
  useEffect(() => setMatchIdx(-1), [query, layout]);
  // A search jump applies once; a remounted map must not replay it.
  useEffect(() => setFocusTarget(undefined), [query, tab]);
  const cycleMatch = (step: number) => {
    if (!matchList.length) return;
    const next = (matchIdx + step + matchList.length) % matchList.length;
    setMatchIdx(next);
    setFocusTarget({ ...matchList[next], nonce: Date.now() });
  };
  const nodeMatchCount = matchNodes?.size ?? 0;
  const edgeMatchCount = matchEdges?.size ?? 0;

  const totals = useMemo(
    () => summarize(graph.nodes, graph.edges, node),
    [graph, node],
  );
  const warnings = [
    ...new Set([...graph.coverage.warnings, ...topology.warnings]),
  ];
  const selectedFrontends =
    selection?.kind === "node"
      ? layout.items
          .get(selection.id)
          ?.members?.filter(
            (id) => index.node.get(id)?.endpoint_kind === "k8s_service",
          )
      : undefined;
  const selectedEdge =
    selection?.kind === "edge" ? index.edge.get(selection.id) : undefined;
  const pathTab = tab === "network" || tab === "services";
  const path = useMemo(
    () =>
      selectedEdge?.relationship === "communicates_with"
        ? buildPath(selectedEdge, graph, index, topo, { backend })
        : undefined,
    [selectedEdge, graph, index, topo, backend],
  );
  const label = (id: string) => index.node.get(id)?.label ?? id;
  const deviceLabel = useCallback(
    (raw: string, host?: GraphNode) =>
      deviceName(raw, topo, nodeDeviceContext(host)).name,
    [topo],
  );
  const describeEdge = useCallback(
    (e: GraphEdge) => {
      const name = (id: string) => node(id)?.label ?? id;
      const observation = e.relationship === "traffic_observation";
      const title = `${name(e.source)} ${observation ? "·" : e.direction_basis === "unknown" ? "↔" : "→"} ${name(e.target)}`;
      if (e.relationship === "calls")
        return {
          title,
          lines: [`Traced call · ${plural(e.count, "span")}`],
        };
      if (e.relationship === "forwards_to") {
        const all = (index.outgoing.get(e.source) ?? []).filter(
          (f) => f.relationship === "forwards_to" && f.target === e.target,
        );
        return {
          title,
          lines: all.map(
            (f) =>
              `${handoffConfidence(f.confidence)} · ${handoffShort[f.handoff_basis!]} · ${plural(f.count, "connection")}`,
          ),
        };
      }
      if (observation)
        return {
          title,
          lines: [
            `Traffic observation · ${plural(e.records ?? e.count, "flow record")} · counters non-authoritative`,
          ],
        };
      const seen = observationsByDevice(
        e,
        topo,
        [],
        edgeDeviceContext(e, index),
      )
        .map((d) => d.label)
        .join(", ");
      return {
        title,
        lines: [
          [
            portLabel(e),
            e.traffic_observations?.length
              ? "traffic observations; see inspector"
              : e.bytes !== undefined
                ? prettyBytes(e.bytes)
                : "bytes not reported",
            e.traffic_observations?.length
              ? "connection count not inferred from flow records"
              : plural(e.count, "connection"),
            edgeIdentity(e, node) === "identified"
              ? "Identified"
              : edgeIdentity(e, node) === "external"
                ? "External"
                : "Unknown IP",
          ].join(" · "),
          seen ? `Seen by ${seen}` : "No observer recorded",
          ...(e.acl_action === "drop"
            ? ["Blocked by the fabric (ACL log)"]
            : []),
          ...(e.contract_basis === "intent" && e.contract
            ? [`Contract ${e.contract} (intent)`]
            : []),
        ],
      };
    },
    [topo, node, index],
  );

  return {
    facets,
    focus,
    setFocus,
    clearFilters,
    changeFacets,
    selection,
    pathHidden,
    setPathHidden,
    query,
    setQuery,
    matchIdx,
    focusTarget,
    focusRequest,
    select,
    clearSelection,
    resetView,
    index,
    topo,
    node,
    displayGraph,
    displayIndex,
    narrowed,
    layout,
    onFitScale,
    q,
    matchNodes,
    matchEdges,
    matchList,
    cycleMatch,
    nodeMatchCount,
    edgeMatchCount,
    totals,
    warnings,
    selectedFrontends,
    selectedEdge,
    pathTab,
    path,
    label,
    deviceLabel,
    describeEdge,
    setExpanded,
    setBackend,
  };
}
