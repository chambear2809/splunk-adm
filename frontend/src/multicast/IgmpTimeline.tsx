import type {
  IgmpEvidence,
  IgmpOperation,
  MulticastResult,
  Segment,
} from "./contract";
import { formatTime } from "./format";

export const NO_IGMP_EVIDENCE = "No IGMP evidence in this window";
export const UNREPORTED_SEGMENT = "Segment not reported";
export const CHART_WIDTH = 640;
export const CHART_PAD = 12;

type MarkKind = "report" | "leave" | "group-query" | "general-query";
const MARK_KIND: Record<Exclude<IgmpOperation, "query">, MarkKind> = {
  "report-v1": "report",
  "report-v2": "report",
  include: "report",
  "change-to-exclude": "report",
  "allow-new-sources": "report",
  exclude: "report",
  leave: "leave",
  "block-old-sources": "leave",
  "change-to-include": "leave",
};
const LANE_HEIGHT = 32;
const MID = LANE_HEIGHT / 2;

export interface IgmpLane {
  label: string;
  evidence: IgmpEvidence[];
}

const segmentLabel = (segment?: Segment) =>
  segment
    ? `${segment.kind} ${segment.id} · ${segment.domain}`
    : UNREPORTED_SEGMENT;

/** IGMP evidence grouped by segment, unreported segment last, by timestamp. */
export function igmpLanes(result: MulticastResult): IgmpLane[] {
  const lanes = new Map<string, IgmpLane>();
  for (const item of result.evidence) {
    if (item.kind !== "igmp") continue;
    const label = segmentLabel(item.segment);
    const lane = lanes.get(label) ?? { label, evidence: [] };
    lane.evidence.push(item);
    lanes.set(label, lane);
  }
  return [...lanes.values()]
    .sort(
      (a, b) =>
        Number(a.label === UNREPORTED_SEGMENT) -
          Number(b.label === UNREPORTED_SEGMENT) ||
        a.label.localeCompare(b.label),
    )
    .map((lane) => ({
      ...lane,
      evidence: [...lane.evidence].sort((a, b) => a.timestamp - b.timestamp),
    }));
}

/** Maps a timestamp onto the shared x-axis, clamped to the request window. */
export function xScale(result: MulticastResult) {
  const { earliest, latest } = result.request;
  const span = Math.max(latest - earliest, 1);
  return (timestamp: number) => {
    const ratio = Math.min(Math.max((timestamp - earliest) / span, 0), 1);
    return (
      Math.round((CHART_PAD + ratio * (CHART_WIDTH - 2 * CHART_PAD)) * 10) / 10
    );
  };
}

export const utc = (seconds: number) =>
  new Date(seconds * 1000).toISOString().replace(/\.\d{3}Z$/, "Z");

const markKind = (item: IgmpEvidence): MarkKind =>
  item.operation === "query"
    ? item.queryScope === "general"
      ? "general-query"
      : "group-query"
    : MARK_KIND[item.operation];

const plural = (count: number, one: string, many: string) =>
  `${count} ${count === 1 ? one : many}`;

function Mark({ item, x }: { item: IgmpEvidence; x: number }) {
  const kind = markKind(item);
  const label =
    item.operation !== "query"
      ? item.operation
      : item.queryScope
        ? kind.replace("-", " ")
        : "query (scope not reported)";
  const who =
    item.reporter ??
    (item.operation === "query" ? "unknown sender" : "unknown reporter");
  const title = (
    <title>{`${label} from ${who} at ${utc(item.timestamp)}`}</title>
  );
  const className = `mc-mark ${kind}`;
  if (kind === "report" || kind === "leave")
    return (
      <circle
        data-t={item.timestamp}
        cx={x}
        cy={MID}
        r={5}
        className={className}
      >
        {title}
      </circle>
    );
  const reach = kind === "group-query" ? MID - 4 : 5;
  return (
    <line
      data-t={item.timestamp}
      x1={x}
      x2={x}
      y1={MID - reach}
      y2={MID + reach}
      className={className}
    >
      {title}
    </line>
  );
}

export function IgmpTimeline({
  result,
  timezone,
}: {
  result: MulticastResult;
  timezone: string;
}) {
  const lanes = igmpLanes(result);
  if (!lanes.length)
    return <p className="mc-detail-empty">{NO_IGMP_EVIDENCE}</p>;
  const x = xScale(result);
  return (
    <section className="mc-timeline">
      <h3>IGMP timeline</h3>
      <p className="mc-axis">
        {formatTime(result.request.earliest, timezone)} to{" "}
        {formatTime(result.request.latest, timezone)}
      </p>
      {lanes.map((lane) => {
        const kinds = lane.evidence.map(markKind);
        const counted = (
          match: (kind: MarkKind) => boolean,
          one: string,
          many: string,
        ) => plural(kinds.filter(match).length, one, many);
        const summary = [
          counted((kind) => kind === "report", "report", "reports"),
          counted((kind) => kind === "leave", "leave", "leaves"),
          counted((kind) => kind.endsWith("query"), "query", "queries"),
        ].join(", ");
        return (
          <div className="mc-lane" key={lane.label}>
            <h4>{lane.label}</h4>
            <svg
              role="img"
              aria-label={`IGMP evidence for ${lane.label}: ${summary}`}
              viewBox={`0 0 ${CHART_WIDTH} ${LANE_HEIGHT}`}
            >
              <line
                className="mc-lane-axis"
                x1={CHART_PAD}
                x2={CHART_WIDTH - CHART_PAD}
                y1={MID}
                y2={MID}
              />
              {lane.evidence.map((item) => (
                <Mark key={item.id} item={item} x={x(item.timestamp)} />
              ))}
            </svg>
          </div>
        );
      })}
    </section>
  );
}
