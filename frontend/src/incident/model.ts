import { diffGraphs, type GraphDiff } from "../diff";
import type { Graph, GraphEdge } from "../graph";

export type Window = { start: string; end: string };
export type Finding = {
  id: string;
  title: string;
  status: "Supported" | "Needs evidence";
  supports: string[];
  contradicts: string[];
  missing: string[];
  next: string;
  edgeIds: string[];
};
export type TimelineItem = {
  id: string;
  kind: "snapshot" | "native";
  start: string;
  end?: string;
  title: string;
  detail: string;
  edgeIds: string[];
};

export function validateWindow(window: Window): void {
  const start = Date.parse(window.start),
    end = Date.parse(window.end);
  if (
    !/(?:Z|[+-]\d{2}:\d{2})$/i.test(window.start) ||
    !/(?:Z|[+-]\d{2}:\d{2})$/i.test(window.end) ||
    !Number.isFinite(start) ||
    !Number.isFinite(end) ||
    end <= start ||
    start < 0
  )
    throw new Error(
      "Enter a valid absolute window with an end after its start.",
    );
}
export function adjacentBaseline(incident: Window): Window {
  validateWindow(incident);
  const start = Date.parse(incident.start),
    end = Date.parse(incident.end);
  if (start - (end - start) < 0)
    throw new Error("The previous window is outside the supported time range.");
  return {
    start: new Date(start - (end - start)).toISOString(),
    end: new Date(start).toISOString(),
  };
}
export function sameWindow(a: Window, b: Window): boolean {
  return (
    Date.parse(a.start) === Date.parse(b.start) &&
    Date.parse(a.end) === Date.parse(b.end)
  );
}
export function assertComparison(
  reference: Graph,
  result: Graph,
  requested: Window,
): void {
  validateWindow(requested);
  validateWindow(result.window);
  if (!sameWindow(result.window, requested))
    throw new Error("The returned window differs from the requested window.");
  const keys = [
    "id",
    "service",
    "environment",
    "cluster",
    "namespace",
  ] as const;
  if (
    reference.schema_version !== result.schema_version ||
    keys.some((key) => reference.boundary[key] !== result.boundary[key])
  )
    throw new Error("The returned map has a different scope or schema.");
}

/** Stop after cancellation even when an underlying loader ignores its signal. */
export async function loadComparison(
  incident: Graph,
  baselineWindow: Window,
  recoveryWindow: Window | undefined,
  loadWindow: (window: Window, signal: AbortSignal) => Promise<Graph>,
  signal: AbortSignal,
): Promise<{ baseline: Graph; recovery?: Graph }> {
  const ensureActive = () => {
    if (signal.aborted) throw new Error("Comparison cancelled.");
  };
  ensureActive();
  const baseline = await loadWindow(baselineWindow, signal);
  ensureActive();
  assertComparison(incident, baseline, baselineWindow);
  let recovery: Graph | undefined;
  if (recoveryWindow) {
    recovery = await loadWindow(recoveryWindow, signal);
    ensureActive();
    assertComparison(incident, recovery, recoveryWindow);
  }
  return { baseline, recovery };
}
export function coverageReasons(graph: Graph): string[] {
  return [
    ...graph.coverage.warnings,
    ...(graph.truncation
      ? ["The map shows a ranked subset of the result."]
      : []),
    ...(graph.read &&
    (graph.read.coverage < 100 || (graph.read.pendingSeconds ?? 0) > 0)
      ? ["The map read is incomplete."]
      : []),
    ...(graph.coverage.ambiguous_conversations > 0
      ? ["Some conversations have ambiguous identity."]
      : []),
    ...(graph.coverage.unresolved_conversations > 0
      ? ["Some conversations have unresolved identity."]
      : []),
    ...(graph.edges.some((edge) => edge.evidence_truncated)
      ? ["Some connection evidence is capped."]
      : []),
  ];
}
const label = (edge: GraphEdge, graph: Graph): string => {
  const name = (id: string) =>
    graph.nodes.find((node) => node.id === id)?.label ?? id;
  const arrow =
    edge.relationship === "communicates_with" &&
    edge.direction_basis === "unknown"
      ? "↔"
      : "→";
  return `${name(edge.source)} ${arrow} ${name(edge.target)}${edge.server_port ? ` · ${edge.server_port}/${edge.transport ?? "unknown"}` : ""}`;
};
const dependency = (edge: GraphEdge) =>
  edge.relationship === "calls" || edge.relationship === "communicates_with";

/** Graph snapshots describe observations, not complete coverage or causation. */
export function buildFindings(
  baseline: Graph,
  incident: Graph,
  diff: GraphDiff = diffGraphs(baseline, incident),
): Finding[] {
  const findings: Finding[] = [];
  const reasons = [
    ...new Set([...coverageReasons(baseline), ...coverageReasons(incident)]),
  ];
  if (reasons.length)
    findings.push({
      id: "coverage",
      title: "Collection coverage needs review",
      status: "Needs evidence",
      supports: reasons,
      contradicts: [],
      missing: [
        "Complete, comparable collection for both windows has not been established.",
      ],
      next: "Inspect data health and the affected source for this window.",
      edgeIds: [],
    });
  const drops = incident.edges.filter(
    (edge) => edge.acl_action === "drop" || (edge.acl_drops ?? 0) > 0,
  );
  if (drops.length)
    findings.push({
      id: "drops",
      title: `Policy drops observed on ${drops.length} connection${drops.length === 1 ? "" : "s"}`,
      status: "Supported",
      supports: drops
        .slice(0, 10)
        .map(
          (edge) =>
            `${label(edge, incident)}: ${edge.acl_drops !== undefined ? `${edge.acl_drops} reported drops` : "drop reported"}.`,
        ),
      contradicts: [],
      missing: [
        "An authoritative policy change or deployment record is not included in this comparison.",
      ],
      next: "Inspect the ACL evidence and policy audit for the affected connection.",
      edgeIds: drops.map((edge) => edge.id),
    });
  const newEdges = diff.addedEdges.filter(dependency);
  if (newEdges.length)
    findings.push({
      id: "new",
      title: `${newEdges.length} connection${newEdges.length === 1 ? "" : "s"} newly observed`,
      status: "Supported",
      supports: newEdges.slice(0, 10).map((edge) => label(edge, incident)),
      contradicts: [],
      missing: [
        "A newly observed connection may have existed outside the baseline evidence.",
      ],
      next: "Inspect the connection evidence and source coverage.",
      edgeIds: newEdges.map((edge) => edge.id),
    });
  const moved = diff.changedNodes.filter(({ previous, current }) => {
    const before = new Set(
      previous.map((node) => node.attributes?.node).filter(Boolean),
    );
    const after = new Set(
      current.map((node) => node.attributes?.node).filter(Boolean),
    );
    return (
      before.size > 0 &&
      after.size > 0 &&
      [...before].sort().join("|") !== [...after].sort().join("|")
    );
  });
  if (moved.length)
    findings.push({
      id: "placement",
      title: `${moved.length} workload group${moved.length === 1 ? "" : "s"} observed on different nodes`,
      status: "Supported",
      supports: moved
        .slice(0, 10)
        .map(
          ({ previous, current }) =>
            `${previous[0].label}: ${[...new Set(previous.map((node) => node.attributes?.node).filter(Boolean))].join(", ")} → ${[...new Set(current.map((node) => node.attributes?.node).filter(Boolean))].join(", ")}`,
        ),
      contradicts: [],
      missing: [
        "The snapshots do not establish an exact movement time or cause.",
      ],
      next: "Inspect workload and node history for the interval.",
      edgeIds: [],
    });
  return findings;
}

export function buildTimeline(
  baseline: Graph,
  incident: Graph,
  diff: GraphDiff = diffGraphs(baseline, incident),
): TimelineItem[] {
  const items: TimelineItem[] = [];
  const start = baseline.window.end,
    end = incident.window.end;
  if (Date.parse(start) <= Date.parse(end)) {
    for (const edge of diff.addedEdges.filter(dependency))
      items.push({
        id: `new:${edge.id}`,
        kind: "snapshot",
        start,
        end,
        title: "Connection newly observed",
        detail: label(edge, incident),
        edgeIds: [edge.id],
      });
    for (const edge of diff.removedEdges.filter(dependency))
      items.push({
        id: `missing:${edge.id}`,
        kind: "snapshot",
        start,
        end,
        title: "Connection not observed in incident window",
        detail: label(edge, baseline),
        edgeIds: [edge.id],
      });
    for (const change of diff.changedNodes)
      items.push({
        id: `node:${change.key}`,
        kind: "snapshot",
        start,
        end,
        title: "Entity group differs between snapshots",
        detail: change.current[0]?.label ?? change.key,
        edgeIds: [],
      });
  }
  for (const edge of incident.edges)
    for (const nat of edge.nat_observations ?? []) {
      if (
        nat.event_time * 1000 >= Date.parse(incident.window.start) &&
        nat.event_time * 1000 < Date.parse(incident.window.end)
      )
        items.push({
          id: `nat:${edge.id}:${nat.event_fingerprint}`,
          kind: "native",
          start: new Date(nat.event_time * 1000).toISOString(),
          title: "FTD translation observed",
          detail: `${label(edge, incident)} · ${nat.device_ip} · indexed ${new Date(nat.received_time * 1000).toISOString()}`,
          edgeIds: [edge.id],
        });
    }
  return items.sort(
    (a, b) =>
      Date.parse(a.start) - Date.parse(b.start) || a.id.localeCompare(b.id),
  );
}
