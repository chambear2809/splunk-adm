import { useCallback, useEffect, useMemo, useRef } from "react";
import { ArrowRight } from "lucide-react";
import type { Graph, GraphEdge, GraphIndex, GraphNode } from "../graph";
import { IdentityBadge } from "../Inspector";
import {
  contractCell,
  edgeIdentity,
  portLabel,
  prettyBytes,
  relationshipLabel,
} from "../glossary";
import {
  edgeDeviceContext,
  observationsByDevice,
  type indexTopology,
} from "../topology";
import { truncationChip } from "../scale/truncate";
import { VirtualTable, type VirtualColumn } from "../scale/VirtualTable";

const peers = (
  e: GraphEdge,
  label: (id: string) => string,
  onSelect: (id: string) => void,
  arrow = e.direction_basis !== "unknown",
) => (
  <button className="link" onClick={() => onSelect(e.id)}>
    {label(e.source)}
    {arrow ? <ArrowRight size={13} aria-label="to" /> : " ↔ "}
    {label(e.target)}
  </button>
);

export function TableView({
  graph,
  label,
  selected,
  onSelect,
  topo,
  index,
  node,
}: {
  graph: Graph;
  label: (id: string) => string;
  selected?: string;
  onSelect: (id: string) => void;
  topo: ReturnType<typeof indexTopology>;
  index: GraphIndex;
  node: (id: string) => GraphNode | undefined;
}) {
  const { conv, calls, observations } = useMemo(() => {
    const conv: GraphEdge[] = [],
      calls: GraphEdge[] = [],
      observations: GraphEdge[] = [];
    for (const e of graph.edges)
      if (e.relationship === "communicates_with") conv.push(e);
      else if (e.relationship === "calls") calls.push(e);
      else if (e.relationship === "traffic_observation") observations.push(e);
    return { conv, calls, observations };
  }, [graph.edges]);
  // Parents pass inline handlers; keep columns (and any sort) stable across
  // their renders so 100k-row tables are not re-sorted needlessly.
  const latestSelect = useRef(onSelect);
  useEffect(() => {
    latestSelect.current = onSelect;
  }, [onSelect]);
  const select = useCallback((id: string) => latestSelect.current(id), []);
  const pair = useCallback(
    (e: GraphEdge) => `${label(e.source)} ${label(e.target)}`,
    [label],
  );

  const convColumns = useMemo((): VirtualColumn<GraphEdge>[] => {
    const seenAt = (e: GraphEdge) =>
      observationsByDevice(e, topo, [], edgeDeviceContext(e, index))
        .map((d) => d.label)
        .join(", ");
    const identity = (e: GraphEdge) =>
      e.acl_action === "drop" ? "blocked" : edgeIdentity(e, node);
    return [
      {
        key: "pair",
        header: "Client → Server",
        sortValue: pair,
        render: (e) => peers(e, label, select),
      },
      {
        key: "port",
        header: "Port",
        sortValue: (e) => portLabel(e),
        render: (e) => portLabel(e),
      },
      {
        key: "seen",
        header: "Seen at",
        sortValue: seenAt,
        render: (e) => seenAt(e) || "—",
      },
      {
        key: "contract",
        header: "Contract",
        sortValue: (e) => contractCell(e),
        render: (e) => contractCell(e),
      },
      {
        key: "bytes",
        header: "Bytes",
        num: true,
        sortValue: (e) =>
          e.traffic_observations?.length ? -1 : (e.bytes ?? -1),
        filterText: () => "",
        render: (e) =>
          e.traffic_observations?.length
            ? "See observations"
            : e.bytes !== undefined
              ? prettyBytes(e.bytes)
              : "—",
      },
      {
        key: "identity",
        header: "Identity",
        sortValue: identity,
        render: (e) =>
          e.acl_action === "drop" ? (
            <span className="status blocked">Blocked</span>
          ) : (
            <IdentityBadge state={edgeIdentity(e, node)} />
          ),
      },
    ];
  }, [topo, index, node, label, pair, select]);

  const callColumns = useMemo(
    (): VirtualColumn<GraphEdge>[] => [
      {
        key: "pair",
        header: "Caller → Callee",
        sortValue: pair,
        render: (e) => peers(e, label, select, true),
      },
      {
        key: "spans",
        header: "Spans",
        num: true,
        sortValue: (e) => e.count,
        filterText: () => "",
        render: (e) => e.count.toLocaleString(),
      },
    ],
    [label, pair, select],
  );

  const observationColumns = useMemo(
    (): VirtualColumn<GraphEdge>[] => [
      {
        key: "tuple",
        header: "Observed tuple",
        sortValue: pair,
        filterText: (e) =>
          `${pair(e)} ${e.source_ip ?? ""} ${e.destination_ip ?? ""} ${e.source_port ?? ""} ${e.destination_port ?? ""} ${e.transport ?? ""}`,
        render: (e) => (
          <>
            {peers(e, label, select, true)}
            {(e.source_ip || e.destination_ip) && (
              <div className="muted small">
                {e.source_ip ?? "?"} → {e.destination_ip ?? "?"}
                {e.source_port !== undefined &&
                  ` · source port ${e.source_port}`}
                {e.destination_port !== undefined &&
                  ` · destination port ${e.destination_port}`}
                {e.transport && ` · transport ${e.transport}`}
                {e.source_port === undefined &&
                e.destination_port === undefined &&
                e.server_port !== undefined
                  ? `:${e.server_port}`
                  : ""}
              </div>
            )}
          </>
        ),
      },
      {
        key: "source",
        header: "Source",
        sortValue: (e) => e.sources?.join(", ") ?? "",
        render: (e) => e.sources?.join(", ") || "—",
      },
      {
        key: "records",
        header: "Records",
        num: true,
        sortValue: (e) => e.records ?? e.count,
        filterText: () => "",
        render: (e) => (e.records ?? e.count).toLocaleString(),
      },
    ],
    [label, pair, select],
  );

  return (
    <div className="table-view">
      {graph.truncation && (
        <p className="atlas-scale-chip" role="status">
          {truncationChip(graph.truncation)}, ranked by{" "}
          {graph.truncation.ranking}. Narrow the scope to see the rest.
        </p>
      )}
      <VirtualTable
        caption="Network conversations"
        rows={conv}
        columns={convColumns}
        rowKey={(e) => e.id}
        selected={selected}
      />
      <VirtualTable
        caption="Traced calls"
        rows={calls}
        columns={callColumns}
        rowKey={(e) => e.id}
        selected={selected}
        viewportHeight={280}
      />
      <VirtualTable
        caption="Source observations"
        rows={observations}
        columns={observationColumns}
        rowKey={(e) => e.id}
        selected={selected}
        rowHeight={48}
        viewportHeight={320}
      />
      <p className="muted small">
        {relationshipLabel.communicates_with} rows include every conversation
        that touches the namespace in the selected time range.
      </p>
    </div>
  );
}
