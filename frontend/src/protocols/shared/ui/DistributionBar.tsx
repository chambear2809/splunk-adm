import type { ProtocolDistributionMetric } from "../contract";

const SINGULAR_UNITS: Record<string, string> = {
  events: "event",
  sessions: "session",
  reqs: "req",
  pkts: "pkt",
  devices: "device",
  flows: "flow",
  errors: "error",
  drops: "drop",
  findings: "finding",
};

function formatCountUnit(value: number, unit: string): string {
  if (value === 1 && SINGULAR_UNITS[unit]) return SINGULAR_UNITS[unit];
  return unit;
}

export function DistributionBar({
  title,
  items,
  mode = "percentile",
}: {
  title: string;
  items: readonly ProtocolDistributionMetric[];
  mode?: "percentile" | "count";
}) {
  if (!items.length) return null;
  const maxVal =
    mode === "count"
      ? Math.max(...items.map((item) => item.count ?? item.p95), 1)
      : Math.max(
          ...items.map((item) =>
            Math.max(item.max ?? item.p95, item.p95, item.p50),
          ),
          1,
        );
  const width = 220;
  const height = 16;

  return (
    <section
      className="pl-dist"
      aria-label={title}
      data-testid="protocol-distribution-bar"
    >
      <h3>{title}</h3>
      <div className="pl-dist-list" data-pl-data="true">
        {items.map((item) => {
          const p50X = Math.min(
            width - 4,
            Math.max(2, (item.p50 / maxVal) * (width - 6)),
          );
          const p95X = Math.min(
            width - 2,
            Math.max(p50X + 2, (item.p95 / maxVal) * (width - 6)),
          );
          const countVal = item.count ?? item.p95;
          const countUnit = formatCountUnit(countVal, item.unit);
          const countX = Math.min(
            width - 2,
            Math.max(2, (countVal / maxVal) * (width - 6)),
          );
          const ariaLabel =
            mode === "count"
              ? `${item.label}: ${countVal} ${countUnit}`
              : `${item.label}: p50 ${item.p50} ${item.unit}, p95 ${item.p95} ${item.unit}`;
          return (
            <div className="pl-dist-row" key={item.id}>
              <span className="pl-dist-label pl-mono" title={item.label}>
                {item.label}
              </span>
              <svg
                className={`pl-dist-svg${item.status ? ` pl-dist-${item.status}` : ""}`}
                width={width}
                height={height}
                viewBox={`0 0 ${width} ${height}`}
                role="img"
                aria-label={ariaLabel}
              >
                <rect
                  x="0"
                  y="6"
                  width={width}
                  height="4"
                  rx="2"
                  className="pl-dist-track"
                />
                {mode === "count" ? (
                  <rect
                    x="0"
                    y="4"
                    width={countX}
                    height="8"
                    rx="3"
                    className="pl-dist-p50"
                  />
                ) : (
                  <>
                    <rect
                      x="0"
                      y="5"
                      width={p95X}
                      height="6"
                      rx="3"
                      className="pl-dist-p95"
                    />
                    <rect
                      x="0"
                      y="4"
                      width={p50X}
                      height="8"
                      rx="3"
                      className="pl-dist-p50"
                    />
                  </>
                )}
              </svg>
              <span className="pl-dist-nums pl-mono">
                {mode === "count"
                  ? `${countVal} ${countUnit}`
                  : `p50 ${item.p50} / p95 ${item.p95} ${item.unit}`}
              </span>
            </div>
          );
        })}
      </div>
    </section>
  );
}
