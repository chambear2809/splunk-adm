import { expect, it } from "vitest";
import { reportedChronology } from "./chronology";
import type { ChangeHistoryRow, ChangeTimelineComparison } from "./types";

it("keeps a later restoration later than the selected impact even within one graph phase", () => {
  const comparison: ChangeTimelineComparison = {
    graph_window: { start: 420, end: 900 },
    selected_edge_id: "drop",
    reported_observation_interval: { start: 430, end: 430 },
    observation_clock_uncertainty_unknown: true,
  };
  const restore = {
    earliest_at: 850,
    latest_at: 860,
    clock_uncertainty_unknown: true,
  } as ChangeHistoryRow;
  expect(reportedChronology(restore, comparison)).toEqual({
    graph_phase: "overlap",
    reported_observation: "after",
    ordering_qualified: false,
  });
  expect(
    reportedChronology(restore, {
      ...comparison,
      reported_observation_interval: null,
    }).reported_observation,
  ).toBe("unknown");
  expect(
    reportedChronology(
      { ...restore, earliest_at: 900, latest_at: 910 },
      comparison,
    ).graph_phase,
  ).toBe("after");
});
