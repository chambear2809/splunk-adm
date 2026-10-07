import { useMemo, useState } from "react";
import { Maximize2, Minus, Plus } from "lucide-react";
import {
  relationshipLabel,
  type Graph,
  type GraphEdge,
  type GraphNode,
} from "./graph";
export type Selection =
  { kind: "node"; id: string } | { kind: "edge"; id: string };
interface Point {
  x: number;
  y: number;
}
export function DependencyGraph({
  graph,
  layer,
  query,
  selection,
  onSelect,
}: {
  graph: Graph;
  layer: "application" | "network";
  query: string;
  selection: Selection | null;
  onSelect: (s: Selection) => void;
}) {
  const [zoom, setZoom] = useState(1);
  const layout = useMemo(() => {
    const nodes = graph.nodes.filter(
      (n) => layer === "network" || n.kind === "service",
    );
    const ids = new Set(nodes.map((n) => n.id));
    const edges = graph.edges.filter(
      (e) => ids.has(e.source) && ids.has(e.target),
    );
    const depth = new Map<string, number>([[graph.boundary.root_node_id, 0]]);
    const queue = [graph.boundary.root_node_id];
    while (queue.length) {
      const id = queue.shift()!;
      for (const e of graph.edges.filter(
        (e) => e.source === id && e.relationship === "calls",
      )) {
        if (!depth.has(e.target)) {
          depth.set(e.target, Math.min((depth.get(id) ?? 0) + 1, 5));
          queue.push(e.target);
        }
      }
    }
    const maxDepth = Math.max(1, ...depth.values());
    for (const e of graph.edges.filter((e) => e.relationship === "runs_on"))
      if (!depth.has(e.target))
        depth.set(e.target, depth.get(e.source) ?? maxDepth);
    for (const n of nodes) if (!depth.has(n.id)) depth.set(n.id, maxDepth + 1);
    const groups = new Map<string, GraphNode[]>();
    for (const n of nodes) {
      const key = `${depth.get(n.id)}:${n.kind === "service" ? "service" : "workload"}`;
      groups.set(key, [...(groups.get(key) ?? []), n]);
    }
    const serviceRows = Math.max(
      1,
      ...[...groups.entries()]
        .filter(([k]) => k.endsWith("service"))
        .map(([, v]) => v.length),
    );
    const points = new Map<string, Point>();
    for (const n of nodes) {
      const group = groups.get(
        `${depth.get(n.id)}:${n.kind === "service" ? "service" : "workload"}`,
      )!;
      const row = group.indexOf(n);
      const y =
        n.kind === "service"
          ? 100 + row * 140
          : 100 + serviceRows * 140 + 70 + row * 125;
      points.set(n.id, { x: 52 + (depth.get(n.id) ?? 0) * 280, y });
    }
    return {
      nodes,
      edges,
      points,
      width: Math.max(950, ...[...points.values()].map((p) => p.x + 280)),
      height: Math.max(420, ...[...points.values()].map((p) => p.y + 150)),
      workloadY: 100 + serviceRows * 140 + 35,
    };
  }, [graph, layer]);
  const selectedNode = selection?.kind === "node" ? selection.id : null;
  const highlighted = (n: GraphNode) =>
    !query ||
    `${n.label} ${n.addresses?.join(" ") ?? ""}`
      .toLowerCase()
      .includes(query.toLowerCase());
  const selectKey = (event: React.KeyboardEvent, value: Selection) => {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      onSelect(value);
    }
  };
  const edgeColor = (e: GraphEdge) =>
    e.confidence === "unresolved"
      ? "#d59132"
      : e.relationship === "calls"
        ? "#8471f2"
        : e.relationship === "runs_on"
          ? "#64758f"
          : "#20a6ad";
  return (
    <div className="graph-wrap">
      <div
        className="graph-scroll"
        tabIndex={0}
        aria-label="Scrollable dependency graph"
      >
        {!layout.nodes.length ? (
          <div className="empty">
            <h3>No frontend spans found</h3>
            <p>
              The snapshot has no dependencies for this qualified boundary.
              Check instrumentation, scope, and time window.
            </p>
          </div>
        ) : (
          <svg
            width={layout.width * zoom}
            height={layout.height * zoom}
            viewBox={`0 0 ${layout.width} ${layout.height}`}
            aria-label="Application dependency graph"
          >
            <defs>
              <pattern
                id="adm-dots"
                width="22"
                height="22"
                patternUnits="userSpaceOnUse"
              >
                <circle cx="1" cy="1" r="1" fill="#dae1ec" />
              </pattern>
              {["call", "flow", "binding", "unknown"].map((name, i) => (
                <marker
                  key={name}
                  id={`adm-arrow-${name}`}
                  viewBox="0 0 10 10"
                  refX="9"
                  refY="5"
                  markerWidth="7"
                  markerHeight="7"
                  orient="auto-start-reverse"
                >
                  <path
                    d="M 0 0 L 10 5 L 0 10 z"
                    fill={["#8471f2", "#20a6ad", "#64758f", "#d59132"][i]}
                  />
                </marker>
              ))}
            </defs>
            <rect width="100%" height="100%" fill="url(#adm-dots)" />
            <text x="52" y="42" className="lane-label">
              APPLICATION SERVICES
            </text>
            {layer === "network" && (
              <>
                <line
                  x1="32"
                  x2={layout.width - 32}
                  y1={layout.workloadY - 20}
                  y2={layout.workloadY - 20}
                  stroke="#dae2ed"
                  strokeDasharray="5 5"
                />
                <text x="52" y={layout.workloadY + 5} className="lane-label">
                  WORKLOADS & NETWORK ENDPOINTS
                </text>
              </>
            )}
            {layout.edges.map((e, index) => {
              const a = layout.points.get(e.source)!,
                b = layout.points.get(e.target)!;
              const binding = e.relationship === "runs_on";
              const backwards = b.x <= a.x;
              const x1 = binding ? a.x + 105 : a.x + 210,
                y1 = binding ? a.y + 84 : a.y + 42;
              const x2 = binding ? b.x + 105 : backwards ? b.x + 210 : b.x,
                y2 = binding ? b.y : b.y + 42;
              const offset = 30 + (index % 4) * 15;
              const path = binding
                ? `M${x1},${y1} C${x1},${y1 + 40} ${x2},${y2 - 40} ${x2},${y2}`
                : backwards
                  ? `M${x1},${y1} C${x1 + offset},${y1 + 100} ${x2 + offset},${y2 + 100} ${x2},${y2}`
                  : `M${x1},${y1} C${x1 + 45},${y1} ${x2 - 45},${y2} ${x2},${y2}`;
              const active =
                selection?.kind === "edge" && selection.id === e.id;
              const dim =
                selectedNode &&
                selectedNode !== e.source &&
                selectedNode !== e.target;
              const marker =
                e.confidence === "unresolved"
                  ? "unknown"
                  : binding
                    ? "binding"
                    : e.relationship === "calls"
                      ? "call"
                      : "flow";
              return (
                <g
                  key={e.id}
                  role="button"
                  tabIndex={0}
                  aria-label={`${relationshipLabel[e.relationship]}: ${graph.nodes.find((n) => n.id === e.source)?.label} to ${graph.nodes.find((n) => n.id === e.target)?.label}`}
                  onClick={() => onSelect({ kind: "edge", id: e.id })}
                  onKeyDown={(event) =>
                    selectKey(event, { kind: "edge", id: e.id })
                  }
                  className="graph-edge"
                  opacity={dim ? 0.25 : 1}
                >
                  <path
                    d={path}
                    stroke="transparent"
                    strokeWidth="18"
                    fill="none"
                  />
                  <path
                    d={path}
                    stroke={edgeColor(e)}
                    strokeWidth={active ? 4 : 2}
                    strokeDasharray={
                      binding
                        ? "4 5"
                        : e.confidence === "unresolved"
                          ? "7 4"
                          : undefined
                    }
                    markerEnd={`url(#adm-arrow-${marker})`}
                    fill="none"
                  />
                  <title>
                    {relationshipLabel[e.relationship]} · {e.count} observations
                    · {e.confidence}
                  </title>
                </g>
              );
            })}
            {layout.nodes.map((n) => {
              const p = layout.points.get(n.id)!,
                root = n.id === graph.boundary.root_node_id;
              const active =
                selection?.kind === "node" && selection.id === n.id;
              const color = root
                ? "#7057dc"
                : n.kind === "service"
                  ? "#725bd7"
                  : n.kind === "workload"
                    ? "#23959c"
                    : "#c08020";
              return (
                <g
                  key={n.id}
                  transform={`translate(${p.x},${p.y})`}
                  role="button"
                  tabIndex={0}
                  className="graph-node"
                  aria-label={`${n.label}, ${n.kind}${root ? ", application boundary" : ""}`}
                  onClick={() => onSelect({ kind: "node", id: n.id })}
                  onKeyDown={(event) =>
                    selectKey(event, { kind: "node", id: n.id })
                  }
                  opacity={highlighted(n) ? 1 : 0.2}
                >
                  <rect
                    width="210"
                    height="84"
                    rx="12"
                    fill={root ? "#f1edff" : "#fff"}
                    stroke={active ? color : root ? "#b8a7ef" : "#dce2eb"}
                    strokeWidth={active ? 2.5 : 1.2}
                  />
                  <rect
                    x="14"
                    y="17"
                    width="28"
                    height="28"
                    rx="8"
                    fill={
                      root
                        ? "#7057dc"
                        : n.kind === "service"
                          ? "#eee9ff"
                          : n.kind === "workload"
                            ? "#e1f5f3"
                            : "#fff1d8"
                    }
                  />
                  <text
                    x="28"
                    y="36"
                    textAnchor="middle"
                    fontSize="14"
                    fill={root ? "#fff" : color}
                  >
                    {n.kind === "service"
                      ? "◈"
                      : n.kind === "workload"
                        ? "⬡"
                        : "↗"}
                  </text>
                  <text x="52" y="29" className="node-label">
                    {n.label.length > 21 ? n.label.slice(0, 20) + "…" : n.label}
                  </text>
                  <text x="52" y="46" className="node-kind">
                    {root
                      ? "Frontend · entry boundary"
                      : n.kind === "service"
                        ? "OTel service"
                        : n.kind === "workload"
                          ? "Kubernetes pod"
                          : "Unresolved endpoint"}
                  </text>
                  <circle cx="20" cy="66" r="3" fill={color} />
                  <text x="30" y="70" className="node-meta">
                    {n.addresses?.[0] ??
                      n.namespace ??
                      graph.boundary.namespace}
                  </text>
                  <title>
                    {n.label}
                    {n.reason ? `: ${n.reason}` : ""}
                  </title>
                </g>
              );
            })}
          </svg>
        )}
      </div>
      <div className="graph-tools" aria-label="Graph zoom">
        <button
          aria-label="Zoom out"
          onClick={() => setZoom((z) => Math.max(0.5, z - 0.15))}
        >
          <Minus size={16} />
        </button>
        <span>{Math.round(zoom * 100)}%</span>
        <button
          aria-label="Zoom in"
          onClick={() => setZoom((z) => Math.min(2, z + 0.15))}
        >
          <Plus size={16} />
        </button>
        <button aria-label="Reset zoom" onClick={() => setZoom(1)}>
          <Maximize2 size={15} />
        </button>
      </div>
    </div>
  );
}
