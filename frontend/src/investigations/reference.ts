import type { Graph } from "../graph";
import { ARG_RULES } from "../provider";

/** A bounded selection for a new server read; never a grant or uploaded graph. */
export function comparisonReference(graphs: {
  baseline: Graph;
  incident: Graph;
  recovery?: Graph;
}): string | undefined {
  const scope = {
    cluster: graphs.incident.boundary.cluster,
    environment: graphs.incident.boundary.environment,
    namespace: graphs.incident.boundary.namespace,
    service: graphs.incident.boundary.service,
  };
  const windows: Array<{ end: number; start: number }> = [];
  if (
    Object.entries(scope).some(
      ([key, value]) => !ARG_RULES[key as keyof typeof scope].re.test(value),
    )
  )
    return undefined;
  for (const graph of [graphs.baseline, graphs.incident, graphs.recovery]) {
    if (!graph) continue;
    if (
      graph.demo ||
      Object.entries(scope).some(
        ([key, value]) => graph.boundary[key as keyof typeof scope] !== value,
      )
    )
      return undefined;
    const start = Date.parse(graph.window.start) / 1000,
      end = Date.parse(graph.window.end) / 1000;
    if (
      !Number.isSafeInteger(start) ||
      !Number.isSafeInteger(end) ||
      start < 0 ||
      end <= start ||
      end - start > 300 ||
      (windows.length > 0 && windows.at(-1)!.end > start)
    )
      return undefined;
    windows.push({ end, start });
  }
  // This key order matches the versioned server canonical JSON contract.
  return JSON.stringify({ schema: 1, scope, windows });
}
