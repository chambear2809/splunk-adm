import {
  AlertTriangle,
  CheckCircle2,
  HelpCircle,
  Minus,
  Slash,
} from "lucide-react";
import { STATUS_LABELS, type ProtocolKpi } from "../contract";

const ICONS = {
  ok: CheckCircle2,
  attention: AlertTriangle,
  not_covered: Slash,
  none_observed: Minus,
  unknown: HelpCircle,
} as const;

function Sparkline({ points }: { points: readonly number[] }) {
  const clean = points.filter((n) => Number.isFinite(n));
  if (clean.length < 2) return null;
  const min = Math.min(...clean);
  const max = Math.max(...clean);
  const span = max - min || 1;
  const w = 64;
  const h = 18;
  const d = clean
    .map((p, i) => {
      const x = (i / (clean.length - 1)) * w;
      const y = h - ((p - min) / span) * (h - 2) - 1;
      return `${i === 0 ? "M" : "L"}${x.toFixed(1)},${y.toFixed(1)}`;
    })
    .join(" ");
  return (
    <svg
      className="pl-sparkline"
      width={w}
      height={h}
      viewBox={`0 0 ${w} ${h}`}
      aria-hidden="true"
    >
      <path d={d} fill="none" stroke="currentColor" strokeWidth="1.5" />
    </svg>
  );
}

/** Up to 4 equal-weight KPI tiles per the UX contract. */
export function KpiStrip({ tiles }: { tiles: readonly ProtocolKpi[] }) {
  const bounded = tiles.slice(0, 4);
  if (!bounded.length) return null;
  return (
    <section
      className="pl-kpi-strip"
      aria-label="Key metrics"
      data-testid="protocol-kpi-strip"
    >
      {bounded.map((tile) => {
        const Icon = tile.status ? ICONS[tile.status] : undefined;
        const statusText = tile.status ? STATUS_LABELS[tile.status] : undefined;
        return (
          <div
            key={tile.id}
            className={`pl-kpi-tile${tile.status ? ` pl-kpi-tile-${tile.status}` : ""}`}
            data-testid="protocol-kpi-tile"
            aria-label={
              statusText
                ? `${tile.label}: ${tile.value}${tile.unit ? ` ${tile.unit}` : ""} (${statusText})`
                : undefined
            }
          >
            <div className="pl-kpi-top">
              <span className="pl-kpi-label">{tile.label}</span>
              {Icon && tile.status ? (
                <span
                  className={`pl-kpi-icon-${tile.status}`}
                  title={statusText}
                  aria-hidden="true"
                >
                  <Icon size={14} />
                </span>
              ) : null}
            </div>
            <div className="pl-kpi-bottom" data-pl-data="true">
              <span className="pl-kpi-value">
                {tile.value}
                {tile.unit ? (
                  <span className="pl-kpi-unit"> {tile.unit}</span>
                ) : null}
              </span>
              {tile.sparkline?.length ? (
                <Sparkline points={tile.sparkline} />
              ) : null}
            </div>
          </div>
        );
      })}
    </section>
  );
}
