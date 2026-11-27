import type { ProtocolTimelineEvent } from "../contract";
import { formatUtcTimestamp, formatUtcWindow } from "../format";

export function SwimlaneTimeline({
  title,
  earliest,
  latest,
  events,
  onSelectEvent,
}: {
  title: string;
  earliest: number;
  latest: number;
  events: readonly ProtocolTimelineEvent[];
  onSelectEvent?: (event: ProtocolTimelineEvent) => void;
}) {
  const lanes = [...new Set(events.map((e) => e.lane))];
  const span = Math.max(1, latest - earliest);

  if (!events.length) {
    return (
      <div className="pl-empty-inline" data-testid="protocol-timeline-empty">
        No events observed in this UTC window.
      </div>
    );
  }

  return (
    <section
      className="pl-timeline"
      aria-label={title}
      data-testid="protocol-timeline"
    >
      <div className="pl-timeline-head">
        <h3>{title}</h3>
        <span className="pl-mono pl-muted-note" data-pl-data="true">
          {formatUtcWindow(earliest, latest)}
        </span>
      </div>
      <div className="pl-timeline-lanes">
        {lanes.map((lane) => {
          const laneEvents = events.filter((e) => e.lane === lane);
          return (
            <div key={lane} className="pl-lane">
              <div className="pl-lane-label pl-mono" title={lane}>
                {lane}
              </div>
              <svg
                className="pl-lane-svg"
                viewBox="0 0 800 30"
                preserveAspectRatio="none"
                aria-label={`${lane} event lane`}
              >
                <line
                  x1={8}
                  y1={15}
                  x2={792}
                  y2={15}
                  className="pl-lane-axis"
                />
                {laneEvents.map((ev) => {
                  const pct = Math.max(
                    0,
                    Math.min(1, (ev.timestamp - earliest) / span),
                  );
                  const x = 12 + pct * 776;
                  return (
                    <g
                      key={ev.id}
                      className={`pl-mark pl-mark-${ev.kind}`}
                      tabIndex={0}
                      role="button"
                      aria-label={`${lane} ${ev.label} at ${formatUtcTimestamp(ev.timestamp)}`}
                      onClick={() => onSelectEvent?.(ev)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter" || e.key === " ") {
                          e.preventDefault();
                          onSelectEvent?.(ev);
                        }
                      }}
                    >
                      <title>
                        {`${ev.label} — ${formatUtcTimestamp(ev.timestamp)}`}
                      </title>
                      <rect
                        x={x - 12}
                        y={3}
                        width={24}
                        height={24}
                        className="pl-mark-hit"
                      />
                      <circle cx={x} cy={15} r={5} />
                    </g>
                  );
                })}
              </svg>
            </div>
          );
        })}
      </div>
    </section>
  );
}
