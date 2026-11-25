import { diffGraphs, type GraphDiff } from "../diff";
import type { AuditProjection } from "./audit";
import type { Graph, GraphEdge } from "../graph";

export type Window = { start: string; end: string };
export type Finding = {
  id: string;
  title: string;
  status: "Supported" | "Needs evidence";
  rankReason: string;
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
  const a = reference.identityContext,
    b = result.identityContext;
  if (
    !!a !== !!b ||
    (a &&
      b &&
      ["contract", "authority", "scope", "configRevision"].some(
        (key) => a[key as keyof typeof a] !== b[key as keyof typeof b],
      ))
  )
    throw new Error(
      "The maps use different source identity configurations. Reload comparable captures.",
    );
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

/** Leads are ordered by observed contrasts, not likelihood or cause. */
export function buildFindings(
  baseline: Graph,
  incident: Graph,
  diff: GraphDiff = diffGraphs(baseline, incident),
): Finding[] {
  type Ranked = Finding & { band: number; affected: number };
  const findings: Ranked[] = [];
  const ordered = (values: string[]) => [...new Set(values)].sort();
  const edgesById = new Map(baseline.edges.map((edge) => [edge.id, edge]));
  const blocked = (edge: GraphEdge) =>
    edge.acl_action === "drop" || (edge.acl_drops ?? 0) > 0;
  const permitted = (edge: GraphEdge) =>
    !blocked(edge) &&
    (edge.acl_action === "permit" || (edge.acl_permits ?? 0) > 0);
  const sameAclPolicyPoint = (before: GraphEdge, after: GraphEdge) =>
    !!before.acl_policy_point &&
    before.acl_policy_point === after.acl_policy_point;
  const drops = incident.edges
    .filter(blocked)
    .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  const changed = drops.filter((edge) => {
    const prior = edgesById.get(edge.id);
    return (
      prior !== undefined && permitted(prior) && sameAclPolicyPoint(prior, edge)
    );
  });
  const previous = drops.filter((edge) => {
    const prior = edgesById.get(edge.id);
    return !!prior && blocked(prior) && sameAclPolicyPoint(prior, edge);
  });
  const unknown = drops.filter((edge) => {
    const prior = edgesById.get(edge.id);
    return (
      !prior ||
      !sameAclPolicyPoint(prior, edge) ||
      (!blocked(prior) && !permitted(prior))
    );
  });
  const dropLabels = (items: GraphEdge[]) =>
    ordered(items.map((edge) => label(edge, incident))).slice(0, 10);
  const ids = (items: GraphEdge[]) => ordered(items.map((edge) => edge.id));
  if (changed.length)
    findings.push({
      id: "drops_changed",
      band: 1,
      affected: ids(changed).length,
      title: "Policy blocking may have changed",
      status: "Supported",
      rankReason:
        "Prioritized because the dependency had a baseline permit and an incident drop at the same policy point.",
      supports: dropLabels(changed).map(
        (name) => `${name}: baseline permit and incident drop reported.`,
      ),
      contradicts: [],
      missing: [
        "An authoritative policy change or deployment record is not included in this comparison.",
      ],
      next: "Inspect ACL evidence and the policy audit for these connections.",
      edgeIds: ids(changed),
    });
  if (unknown.length)
    findings.push({
      id: "drops_unknown",
      band: 2,
      affected: ids(unknown).length,
      title: "Policy blocking may be relevant",
      status: "Needs evidence",
      rankReason:
        "Prioritized as an incident observation without a comparable baseline policy state.",
      supports: ordered(
        unknown.map((edge) => {
          const prior = edgesById.get(edge.id);
          const baseline =
            prior && (blocked(prior) || permitted(prior))
              ? `baseline ${blocked(prior) ? "drop" : "permit"} reported; a shared policy point is unverified`
              : prior?.acl_drops === 0
                ? "baseline reports zero drops; a permit is not established"
                : "baseline policy state is unknown";
          return `${label(edge, incident)}: incident drop reported; ${baseline}.`;
        }),
      ).slice(0, 10),
      contradicts: [],
      missing: [
        "Comparable baseline ACL evidence at the incident policy point is missing.",
        "An authoritative policy change or deployment record is not included.",
      ],
      next: "Inspect ACL evidence and the policy audit for these connections.",
      edgeIds: ids(unknown),
    });
  if (previous.length)
    findings.push({
      id: "drops_previous",
      band: 3,
      affected: ids(previous).length,
      title: "Policy blocking was also observed before",
      status: "Needs evidence",
      rankReason:
        "Listed after observed changes because blocking was already reported in the baseline.",
      supports: dropLabels(previous).map(
        (name) => `${name}: incident drop reported.`,
      ),
      contradicts: dropLabels(previous).map(
        (name) => `${name}: already reported blocked in the baseline.`,
      ),
      missing: [
        "The snapshots do not establish whether blocking caused the incident or whether a policy changed.",
      ],
      next: "Inspect ACL evidence and the policy audit for these connections.",
      edgeIds: ids(previous),
    });
  const newEdges = diff.addedEdges.filter(dependency);
  if (newEdges.length)
    findings.push({
      id: "new",
      band: 2,
      affected: ids(newEdges).length,
      title: "Newly observed connections may need review",
      status: "Needs evidence",
      rankReason:
        "Prioritized as a dependency difference between the snapshots that needs corroboration.",
      supports: ordered(newEdges.map((edge) => label(edge, incident))).slice(
        0,
        10,
      ),
      contradicts: [],
      missing: [
        "A newly observed connection may have existed outside the baseline evidence.",
        "Complete comparable collection is not established by these snapshots.",
      ],
      next: "Inspect connection evidence and source coverage.",
      edgeIds: ids(newEdges),
    });
  const moved = diff.changedNodes.filter(({ previous, current }) => {
    const before = ordered(
      previous
        .map((node) => node.attributes?.node)
        .filter((value): value is string => !!value),
    );
    const after = ordered(
      current
        .map((node) => node.attributes?.node)
        .filter((value): value is string => !!value),
    );
    return (
      before.length > 0 &&
      after.length > 0 &&
      before.join("|") !== after.join("|")
    );
  });
  if (moved.length)
    findings.push({
      id: "placement",
      band: 2,
      affected: new Set(moved.map((change) => change.key)).size,
      title: "Workload placement may need review",
      status: "Needs evidence",
      rankReason:
        "Prioritized as a placement difference between snapshots that needs corroboration.",
      supports: ordered(
        moved.map(({ previous, current }) => {
          const labels = ordered(previous.map((node) => node.label));
          const before = ordered(
            previous
              .map((node) => node.attributes?.node)
              .filter((value): value is string => !!value),
          );
          const after = ordered(
            current
              .map((node) => node.attributes?.node)
              .filter((value): value is string => !!value),
          );
          return `${labels[0]}: ${before.join(", ")} → ${after.join(", ")}`;
        }),
      ).slice(0, 10),
      contradicts: [],
      missing: [
        "The snapshots do not establish an exact movement time or cause.",
        "Complete comparable collection is not established by these snapshots.",
      ],
      next: "Inspect workload and node history for the interval.",
      edgeIds: [],
    });
  findings.sort(
    (a, b) =>
      a.band - b.band ||
      a.contradicts.length - b.contradicts.length ||
      b.affected - a.affected ||
      (a.id < b.id ? -1 : a.id > b.id ? 1 : 0),
  );
  return findings.map((finding) => ({
    id: finding.id,
    title: finding.title,
    status: finding.status,
    rankReason: finding.rankReason,
    supports: finding.supports,
    contradicts: finding.contradicts,
    missing: finding.missing,
    next: finding.next,
    edgeIds: finding.edgeIds,
  }));
}

export function buildTimeline(
  baseline: Graph,
  incident: Graph,
  diff: GraphDiff = diffGraphs(baseline, incident),
  audit?: AuditProjection,
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
  for (const { event, binding } of audit?.events ?? []) {
    const time = Date.parse(event.actionTime);
    if (
      time >= Date.parse(incident.window.start) &&
      time < Date.parse(incident.window.end)
    )
      items.push({
        id: `audit:${JSON.stringify([event.authority, event.scope, event.eventId])}`,
        kind: "native",
        start: event.actionTime,
        title: "Audit action reported",
        detail: `${event.action} · native action time ${event.actionTime} · object ${event.objectId} · source ${event.authority} / ${event.scope} · event ${event.eventId} · received ${event.receivedTime} · binding ${binding.bindingAuthority} / ${binding.bindingEvidenceId} (${binding.validFrom} to ${binding.validUntil}, end exclusive)`,
        edgeIds: [],
      });
  }
  return items.sort(
    (a, b) =>
      Date.parse(a.start) - Date.parse(b.start) || a.id.localeCompare(b.id),
  );
}
