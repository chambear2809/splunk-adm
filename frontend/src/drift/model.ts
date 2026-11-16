/** Inputs must come from a dedicated, complete, caller-authorized evidence query. */
export interface Coverage {
  requested: Window;
  returned: Window;
  authority: string;
  scope: string;
  sourceRevision: string;
  configRevision: string;
  normalizationRevision: string;
  signatureVersion: 1;
  permission: "allowed" | "denied" | "unknown";
  complete: boolean;
  capped: boolean;
  progressive: boolean;
  sampled: boolean;
  stale: boolean;
  /** Time through which late arrivals were included, in epoch seconds. */
  knowledgeHorizon: number;
  requiredLatenessSeconds: number;
}
export interface Window {
  start: number;
  end: number;
}
export interface Dependency {
  authority: string;
  scope: string;
  /** Stable logical IDs, never pod IDs or display names. */
  source: string;
  destination: string;
  protocol: string;
  port: number;
  relation: string;
  direction: string;
  blocked: boolean | null;
  /** Distinct qualified failure domains, not replica names. */
  redundancyDomains?: string[];
}
export interface Capture {
  id: string;
  coverage: Coverage;
  dependencies: Dependency[];
}
export interface Baseline {
  id: string;
  version: number;
  name: string;
  capture: Capture;
}
export interface Finding {
  kind:
    | "new_destination_port"
    | "changed_dependency"
    | "newly_blocked"
    | "lost_redundancy"
    | "not_observed";
  signature: string;
  description: string;
}
export interface WatchDefinition {
  id: string;
  threshold: number;
  cooldownSeconds: number;
  expectedWindows: Window[];
}
export interface WatchOccurrence {
  signature: string;
  window: Window;
  observedAt: number;
}

const present = (value: string) =>
  typeof value === "string" && value.trim() === value && value.length > 0;
const validWindow = (w: Window) =>
  !!w &&
  Number.isFinite(w.start) &&
  Number.isFinite(w.end) &&
  w.start >= 0 &&
  w.end > w.start;
const sameWindow = (a: Window, b: Window) =>
  a.start === b.start && a.end === b.end;
const validDependency = (d: Dependency, c: Coverage) =>
  d.authority === c.authority &&
  d.scope === c.scope &&
  [
    d.authority,
    d.scope,
    d.source,
    d.destination,
    d.protocol,
    d.relation,
    d.direction,
  ].every(present) &&
  Number.isInteger(d.port) &&
  d.port >= 1 &&
  d.port <= 65535 &&
  (d.blocked === null || typeof d.blocked === "boolean") &&
  (d.redundancyDomains === undefined ||
    (Array.isArray(d.redundancyDomains) &&
      d.redundancyDomains.every(present) &&
      new Set(d.redundancyDomains).size === d.redundancyDomains.length));

/** Tuple encoding prevents delimiter collisions and excludes metrics and transient identities. */
export function signature(d: Dependency): string {
  return JSON.stringify([
    1,
    d.authority,
    d.scope,
    d.source,
    d.destination,
    d.protocol,
    d.port,
    d.relation,
    d.direction,
  ]);
}

export function eligibility(capture: Capture): string[] {
  const c = capture.coverage;
  const reasons: string[] = [];
  if (!present(capture.id)) reasons.push("Capture identity is unavailable.");
  if (
    !validWindow(c.requested) ||
    !validWindow(c.returned) ||
    !sameWindow(c.requested, c.returned)
  )
    reasons.push("Actual and requested windows are not confirmed.");
  if (
    ![
      c.authority,
      c.scope,
      c.sourceRevision,
      c.configRevision,
      c.normalizationRevision,
    ].every(present) ||
    c.signatureVersion !== 1
  )
    reasons.push("Source or model revision is unavailable.");
  if (c.permission !== "allowed")
    reasons.push("Source access is not confirmed.");
  if (
    c.complete !== true ||
    c.capped !== false ||
    c.progressive !== false ||
    c.sampled !== false ||
    c.stale !== false
  )
    reasons.push("Coverage is incomplete, capped, sampled, or stale.");
  if (
    !Number.isFinite(c.requiredLatenessSeconds) ||
    c.requiredLatenessSeconds < 0 ||
    !Number.isFinite(c.knowledgeHorizon) ||
    c.knowledgeHorizon < c.returned.end + c.requiredLatenessSeconds
  )
    reasons.push("Late-arrival horizon is not complete.");
  if (
    !Array.isArray(capture.dependencies) ||
    capture.dependencies.some((d) => !validDependency(d, c))
  )
    reasons.push("Dependency identity or scope is ambiguous.");
  else if (
    new Set(capture.dependencies.map(signature)).size !==
    capture.dependencies.length
  )
    reasons.push("Duplicate dependency signatures are ambiguous.");
  return reasons;
}

export function compare(
  baseline: Capture,
  current: Capture,
): { comparable: boolean; reasons: string[]; findings: Finding[] } {
  const reasons = [...eligibility(baseline), ...eligibility(current)];
  const a = baseline.coverage,
    b = current.coverage;
  if (
    [
      "authority",
      "scope",
      "sourceRevision",
      "configRevision",
      "normalizationRevision",
      "signatureVersion",
      "requiredLatenessSeconds",
    ].some((key) => a[key as keyof Coverage] !== b[key as keyof Coverage])
  )
    reasons.push("Source, configuration, sampling, or model revisions differ.");
  if (
    validWindow(a.returned) &&
    validWindow(b.returned) &&
    a.returned.end - a.returned.start !== b.returned.end - b.returned.start
  )
    reasons.push("Window durations differ.");
  if (reasons.length)
    return { comparable: false, reasons: [...new Set(reasons)], findings: [] };
  const before = new Map(baseline.dependencies.map((d) => [signature(d), d]));
  const after = new Map(current.dependencies.map((d) => [signature(d), d]));
  const findings: Finding[] = [];
  for (const [key, d] of after) {
    const old = before.get(key);
    if (!old) {
      const related = baseline.dependencies.some(
        (p) =>
          p.source === d.source &&
          p.authority === d.authority &&
          p.scope === d.scope &&
          p.relation === d.relation &&
          p.direction === d.direction &&
          (p.destination === d.destination ||
            (p.protocol === d.protocol && p.port === d.port)),
      );
      findings.push({
        kind: related ? "changed_dependency" : "new_destination_port",
        signature: key,
        description: `${d.source} → ${d.destination} · ${d.protocol}/${d.port} newly observed`,
      });
    } else {
      if (old.blocked === false && d.blocked === true)
        findings.push({
          kind: "newly_blocked",
          signature: key,
          description: `${d.source} → ${d.destination} · ${d.protocol}/${d.port} newly reported blocked`,
        });
      if (
        old.redundancyDomains &&
        d.redundancyDomains &&
        old.redundancyDomains.length > d.redundancyDomains.length
      )
        findings.push({
          kind: "lost_redundancy",
          signature: key,
          description: `${d.source} → ${d.destination}: fewer observed failure domains`,
        });
    }
  }
  for (const [key, d] of before)
    if (!after.has(key))
      findings.push({
        kind: "not_observed",
        signature: key,
        description: `${d.source} → ${d.destination} · ${d.protocol}/${d.port} not observed in this window`,
      });
  return { comparable: true, reasons: [], findings };
}

/** Evaluate recorded observations only; this does not schedule work or notify anyone. */
export function watchStatus(
  definition: WatchDefinition,
  occurrences: WatchOccurrence[],
  signatureValue: string,
  now: number,
): {
  count: number;
  thresholdMet: boolean;
  expected: boolean;
  coolingDown: boolean;
} {
  if (
    !present(definition.id) ||
    !Number.isInteger(definition.threshold) ||
    definition.threshold < 1 ||
    !Number.isFinite(definition.cooldownSeconds) ||
    definition.cooldownSeconds < 0 ||
    !Number.isFinite(now) ||
    !definition.expectedWindows.every(validWindow)
  )
    throw new Error("Invalid watch definition.");
  const unique = new Map<string, WatchOccurrence>();
  for (const item of occurrences) {
    if (
      item.signature !== signatureValue ||
      !validWindow(item.window) ||
      !Number.isFinite(item.observedAt) ||
      item.observedAt > now
    )
      continue;
    const key = JSON.stringify([
      item.signature,
      item.window.start,
      item.window.end,
    ]);
    const old = unique.get(key);
    if (!old || item.observedAt < old.observedAt) unique.set(key, item);
  }
  const values = [...unique.values()];
  const last = Math.max(...values.map((v) => v.observedAt), -Infinity);
  return {
    count: values.length,
    thresholdMet: values.length >= definition.threshold,
    expected: definition.expectedWindows.some(
      (w) => w.start <= now && now < w.end,
    ),
    coolingDown: now < last + definition.cooldownSeconds,
  };
}
