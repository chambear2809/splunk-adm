import type { BlastGraph, NodeState } from "./blast";

const W = 1000;
const BAND_H = 64;
const PILL_H = 24;
const LABEL_W = 84;

const STATE_TEXT: Record<NodeState, string> = {
  down: "down",
  outage: "outage",
  degraded: "degraded",
  unknown: "unverified",
  alternate: "carries traffic",
  path: "on path",
};

/** Layered blast map: failed elements, outage red, degraded amber, alternates outlined, rest dimmed. */
export function BlastMap({ graph }: { graph: BlastGraph }) {
  if (!graph.bands.length) return null;
  const pos = new Map<string, { x: number; y: number; w: number }>();
  graph.bands.forEach((b, row) => {
    const slots = b.nodes.length + (b.more ? 1 : 0);
    const span = (W - LABEL_W - 12) / Math.max(slots, 1);
    b.nodes.forEach((n, i) => {
      const w = Math.min(span - 8, 150);
      pos.set(n.id, {
        x: LABEL_W + span * i + span / 2,
        y: row * BAND_H + BAND_H / 2,
        w,
      });
    });
  });
  const h = graph.bands.length * BAND_H;
  return (
    <figure className="atlas-blast" aria-label="Blast map">
      <svg
        viewBox={`0 0 ${W} ${h}`}
        role="img"
        aria-labelledby="atlas-blast-title"
      >
        <title id="atlas-blast-title">
          Blast map:{" "}
          {graph.bands
            .map((b) => `${b.band} ${b.nodes.length + b.more}`)
            .join(", ")}
        </title>
        {graph.bands.map((b, row) => (
          <g key={b.band}>
            <line
              className="band-rule"
              x1={0}
              x2={W}
              y1={row * BAND_H + BAND_H}
              y2={row * BAND_H + BAND_H}
            />
            <text
              className="band-label"
              x={4}
              y={row * BAND_H + BAND_H / 2 + 4}
            >
              {b.band}
            </text>
          </g>
        ))}
        {graph.links.map(([a, b]) => {
          const p = pos.get(a)!;
          const q = pos.get(b)!;
          const mid = (p.y + q.y) / 2;
          return (
            <path
              key={`${a}>${b}`}
              className="blast-link"
              d={`M${p.x},${p.y + PILL_H / 2} C${p.x},${mid} ${q.x},${mid} ${q.x},${q.y - PILL_H / 2}`}
            />
          );
        })}
        {graph.bands.flatMap((b) =>
          b.nodes.map((n) => {
            const p = pos.get(n.id)!;
            const chars = Math.max(4, Math.floor((p.w - 12) / 6.4));
            const text =
              n.label.length > chars
                ? `${n.label.slice(0, chars - 1)}…`
                : n.label;
            return (
              <g
                key={n.id}
                className={`blast-node ${n.state}`}
                transform={`translate(${p.x - p.w / 2},${p.y - PILL_H / 2})`}
              >
                <title>{`${n.label} · ${STATE_TEXT[n.state]}`}</title>
                <rect width={p.w} height={PILL_H} rx={PILL_H / 2} />
                <text x={p.w / 2} y={PILL_H / 2 + 4} textAnchor="middle">
                  {text}
                </text>
              </g>
            );
          }),
        )}
        {graph.bands.map((b, row) =>
          b.more ? (
            <text
              key={`${b.band}-more`}
              className="band-more"
              x={W - 40}
              y={row * BAND_H + BAND_H / 2 + 4}
            >
              +{b.more}
            </text>
          ) : null,
        )}
      </svg>
      <figcaption className="atlas-blast-legend">
        <span className="dot down" /> Down <span className="dot outage" />{" "}
        Outage <span className="dot degraded" /> Degraded{" "}
        <span className="dot alternate" /> Alternate
      </figcaption>
    </figure>
  );
}
