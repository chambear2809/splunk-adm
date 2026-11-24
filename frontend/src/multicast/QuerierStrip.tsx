import type { MulticastResult } from "./contract";
import { formatTime } from "./format";
import {
  CHART_WIDTH,
  NO_IGMP_EVIDENCE,
  igmpLanes,
  utc,
  xScale,
} from "./IgmpTimeline";

const ROW_HEIGHT = 22;
const BAR_HEIGHT = 12;
const MIN_BAR = 4;

interface QuerySender {
  address: string;
  first: number;
  last: number;
}

export function QuerierStrip({
  result,
  timezone,
}: {
  result: MulticastResult;
  timezone: string;
}) {
  const lanes = igmpLanes(result);
  const x = xScale(result);
  const rows = lanes
    .map((lane) => {
      const senders = new Map<string, QuerySender>();
      for (const item of lane.evidence) {
        if (item.operation !== "query" || !item.reporter) continue;
        const sender = senders.get(item.reporter);
        if (!sender)
          senders.set(item.reporter, {
            address: item.reporter,
            first: item.timestamp,
            last: item.timestamp,
          });
        else sender.last = item.timestamp;
      }
      return { label: lane.label, senders: [...senders.values()] };
    })
    .filter((row) => row.senders.length);
  return (
    <section className="mc-querier-strip">
      <h3>Observed query senders</h3>
      {!lanes.length ? (
        <p className="mc-detail-empty">{NO_IGMP_EVIDENCE}</p>
      ) : !rows.length ? (
        <p className="mc-detail-empty">
          No query senders observed in this window
        </p>
      ) : (
        rows.map((row) => (
          <div className="mc-lane" key={row.label}>
            <h4>
              {row.label}
              {row.senders.length > 1 && (
                <span className="mc-flag">Query senders changed</span>
              )}
            </h4>
            <svg
              role="img"
              aria-label={`Query senders observed for ${row.label}: ${
                row.senders.length
              } ${row.senders.length === 1 ? "query sender" : "query senders"} (${row.senders
                .map((sender) => sender.address)
                .join(", ")})`}
              viewBox={`0 0 ${CHART_WIDTH} ${row.senders.length * ROW_HEIGHT}`}
            >
              {row.senders.map((sender, index) => {
                const start = x(sender.first);
                const width = Math.max(x(sender.last) - start, MIN_BAR);
                const top = index * ROW_HEIGHT + (ROW_HEIGHT - BAR_HEIGHT) / 2;
                return (
                  <g key={sender.address}>
                    <rect
                      className="mc-sender-bar"
                      x={start}
                      y={top}
                      width={width}
                      height={BAR_HEIGHT}
                    >
                      <title>{`${sender.address}: queries from ${utc(sender.first)} to ${utc(sender.last)}`}</title>
                    </rect>
                    <text
                      x={start + width + 4}
                      y={top + BAR_HEIGHT - 2}
                      className="mc-sender-label"
                    >
                      {sender.address}
                    </text>
                  </g>
                );
              })}
            </svg>
            <ul className="mc-sender-list">
              {row.senders.map((sender) => (
                <li key={sender.address}>
                  {sender.address}: {formatTime(sender.first, timezone)} to{" "}
                  {formatTime(sender.last, timezone)}
                </li>
              ))}
            </ul>
          </div>
        ))
      )}
    </section>
  );
}
