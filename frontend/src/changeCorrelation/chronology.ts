import type { Graph } from "../graph";
import type { ChangeHistoryRow, ChangeTimelineComparison } from "./types";

export function graphComparison(
  graph: Graph,
  edgeId?: string,
): ChangeTimelineComparison {
  const edge = graph.edges.find((candidate) => candidate.id === edgeId);
  const intervals = [
    ...(edge?.nat_observations ?? []).map((item) => ({
      start: item.event_time,
      end: item.event_time,
    })),
    ...(edge?.traffic_observations ?? []).flatMap((item) =>
      typeof item.first_seen === "number" && typeof item.last_seen === "number"
        ? [{ start: item.first_seen, end: item.last_seen }]
        : [],
    ),
  ].filter(
    (item) =>
      Number.isFinite(item.start) &&
      Number.isFinite(item.end) &&
      item.start <= item.end &&
      item.start >= Date.parse(graph.window.start) / 1000 &&
      item.end < Date.parse(graph.window.end) / 1000,
  );
  const unique = new Map(
    intervals.map((interval) => [JSON.stringify(interval), interval]),
  );
  return {
    graph_window: {
      start: Date.parse(graph.window.start) / 1000,
      end: Date.parse(graph.window.end) / 1000,
    },
    selected_edge_id: edge?.id ?? null,
    // Multiple distinct observations require an explicit narrower selection.
    reported_observation_interval:
      unique.size === 1 ? [...unique.values()][0] : null,
    observation_clock_uncertainty_unknown: true,
  };
}

export function reportedChronology(
  row: ChangeHistoryRow,
  comparison: ChangeTimelineComparison,
) {
  const start = row.earliest_at ?? row.event_at ?? row.observed_at;
  const end = row.latest_at ?? row.event_at ?? row.observed_at;
  const relation = (otherStart: number, otherEnd: number) =>
    start === null || end === null
      ? "unknown"
      : end < otherStart
        ? "before"
        : start > otherEnd
          ? "after"
          : "overlap";
  const observation = comparison.reported_observation_interval;
  return {
    graph_phase: relation(
      comparison.graph_window.start,
      comparison.graph_window.end - 0.001,
    ),
    reported_observation: observation
      ? relation(observation.start, observation.end)
      : "unknown",
    ordering_qualified:
      !row.clock_uncertainty_unknown &&
      !comparison.observation_clock_uncertainty_unknown &&
      observation !== null,
  } as const;
}
