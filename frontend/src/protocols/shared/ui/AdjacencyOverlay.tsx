import type { ProtocolAdjacencyEdge, ProtocolAdjacencyNode } from "../contract";

/**
 * Compact radial adjacency overlay for Routing, L2 STP/Port-Channel, and
 * Multicast lenses (capped at 24 nodes for scannability).
 * Nodes are spread across a wide ellipse with outward-offset centered labels
 * so text never overlaps adjacency edges.
 */
export function AdjacencyOverlay({
  title,
  nodes,
  edges,
  onSelectNode,
}: {
  title: string;
  nodes: readonly ProtocolAdjacencyNode[];
  edges: readonly ProtocolAdjacencyEdge[];
  onSelectNode?: (node: ProtocolAdjacencyNode) => void;
}) {
  const visible = nodes.slice(0, 24);
  if (!visible.length) return null;
  const cx = 260;
  const cy = 86;
  const rx = Math.min(185, Math.max(120, visible.length * 42));
  const ry = Math.min(50, Math.max(38, visible.length * 12));
  const pos = new Map<string, { x: number; y: number; ly: number }>();
  visible.forEach((node, idx) => {
    const angle = (2 * Math.PI * idx) / visible.length - Math.PI / 2;
    const x = cx + Math.cos(angle) * rx;
    const y = cy + Math.sin(angle) * ry;
    const ly = Math.sin(angle) < -0.2 ? -14 : 21;
    pos.set(node.id, { x, y, ly });
  });

  return (
    <section
      className="pl-adj"
      aria-label={title}
      data-testid="protocol-adjacency"
    >
      <h3>{title}</h3>
      <svg
        className="pl-adj-svg"
        viewBox="0 0 520 176"
        aria-label={`${title} graph`}
      >
        {edges.map((edge) => {
          const a = pos.get(edge.from);
          const b = pos.get(edge.to);
          if (!a || !b) return null;
          return (
            <g key={edge.id} className={`pl-adj-edge pl-adj-${edge.status}`}>
              <line x1={a.x} y1={a.y} x2={b.x} y2={b.y} />
              {edge.label ? <title>{edge.label}</title> : null}
            </g>
          );
        })}
        {visible.map((node) => {
          const p = pos.get(node.id)!;
          return (
            <g
              key={node.id}
              className={`pl-adj-node pl-adj-${node.status}`}
              transform={`translate(${p.x.toFixed(1)}, ${p.y.toFixed(1)})`}
              tabIndex={0}
              role="button"
              aria-label={`${node.label} (${node.status})`}
              onClick={() => onSelectNode?.(node)}
              onKeyDown={(e) => {
                if (e.key === "Enter" || e.key === " ") {
                  e.preventDefault();
                  onSelectNode?.(node);
                }
              }}
            >
              <circle r={14} className="pl-mark-hit" />
              <circle r={7} />
              <text
                x={0}
                y={p.ly}
                textAnchor="middle"
                className="pl-adj-label pl-mono"
              >
                {node.label.slice(0, 18)}
              </text>
            </g>
          );
        })}
      </svg>
    </section>
  );
}
