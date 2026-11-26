import type { Dependency, DependsResult } from "../impact/model";

export interface ResiliencePosture {
  singlePoints: Dependency[];
  redundant: Dependency[];
  unverified: Dependency[];
  headline: string;
}

/** Classify Depends-on rows without inventing topology the graph did not return. */
export function resiliencePosture(result: DependsResult): ResiliencePosture {
  const singlePoints = result.rows.filter((row) => row.severity === "outage");
  const redundant = result.rows.filter((row) => row.severity === "degraded");
  const unverified = result.rows.filter((row) => row.severity === "unknown");
  const headline =
    singlePoints.length === 0
      ? `${result.label}: no observed single points of failure in this window`
      : `${result.label}: ${singlePoints.length} single point${singlePoints.length === 1 ? "" : "s"} of failure`;
  return { singlePoints, redundant, unverified, headline };
}
