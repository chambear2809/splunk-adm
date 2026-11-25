/** Maintenance evidence is supplied explicitly; impact alternatives are candidates only. */
export type EvidenceState =
  "complete" | "partial" | "stale" | "denied" | "capped" | "unknown";
export interface Evidence<T> {
  value: T;
  scope: string;
  source: string;
  qualified: boolean;
  state: EvidenceState;
  observedAt: number;
  /** Optional source-established effective start for an operational state. */
  validFrom?: number;
  validUntil: number;
}
export interface Capacity {
  /** True only when the source establishes sufficient peak headroom for this scenario. */
  sufficientPeakHeadroom: boolean;
  value: number;
  unit: string;
  interval: { start: number; end: number };
  direction: string;
  sampling: string;
  deduplication: string;
  capacitySource: string;
  assumptions: string[];
}
export interface AlternativeEvidence {
  name: string;
  reachable?: Evidence<boolean>;
  healthy?: Evidence<boolean>;
  ready?: Evidence<boolean>;
  substitutable?: Evidence<boolean>;
  independentFailureDomain?: Evidence<boolean>;
  capacity?: Evidence<Capacity>;
}
export interface ServiceEvidence {
  id: string;
  name: string;
  owner?: string;
  scope: string;
  topology?: Evidence<"exposed" | "not_exposed">;
  alternatives: AlternativeEvidence[];
}
export interface AssessmentInput {
  id: string;
  capturedAt: number;
  window: { start: number; end: number };
  selectedElements: string[];
  services: ServiceEvidence[];
}
export type Check = "confirmed" | "blocked" | "unknown";
export interface AlternativeAssessment {
  name: string;
  reachability: Check;
  health: Check;
  readiness: Check;
  substitution: Check;
  failureDomain: Check;
  capacity: Check;
  capacityEvidence?: Capacity;
}
export interface ServiceAssessment {
  id: string;
  name: string;
  owner?: string;
  scope: string;
  topology: "exposed" | "not_exposed" | "unknown";
  alternatives: AlternativeAssessment[];
}
export interface Assessment {
  id: string;
  capturedAt: number;
  window: { start: number; end: number };
  selectedElements: string[];
  services: ServiceAssessment[];
  headline:
    | "Readiness cannot be confirmed"
    | "Identified blockers"
    | "No identified blockers in this evidence";
}

const present = (s: string) => typeof s === "string" && s.trim().length > 0;
function eligible<T>(
  e: Evidence<T> | undefined,
  scope: string,
  at: number,
  windowStart?: number,
): e is Evidence<T> {
  return (
    !!e &&
    e.qualified === true &&
    e.state === "complete" &&
    present(scope) &&
    e.scope === scope &&
    present(e.source) &&
    Number.isFinite(e.observedAt) &&
    Number.isFinite(e.validUntil) &&
    e.observedAt <= at &&
    (windowStart === undefined ||
      (e.validFrom === undefined
        ? e.observedAt <= windowStart
        : Number.isFinite(e.validFrom) &&
          e.validFrom <= e.observedAt &&
          e.validFrom <= windowStart)) &&
    at < e.validUntil
  );
}
function booleanCheck(
  e: Evidence<boolean> | undefined,
  scope: string,
  at: number,
  windowStart: number,
): Check {
  return eligible(e, scope, at, windowStart) && typeof e.value === "boolean"
    ? e.value
      ? "confirmed"
      : "blocked"
    : "unknown";
}
function validCapacity(
  c: Capacity,
  window: AssessmentInput["window"],
): boolean {
  return (
    !!c &&
    typeof c.sufficientPeakHeadroom === "boolean" &&
    Number.isFinite(c.value) &&
    c.value >= 0 &&
    present(c.unit) &&
    !!c.interval &&
    Number.isFinite(c.interval.start) &&
    Number.isFinite(c.interval.end) &&
    c.interval.start <= window.start &&
    c.interval.end >= window.end &&
    c.interval.end > c.interval.start &&
    present(c.direction) &&
    present(c.sampling) &&
    present(c.deduplication) &&
    present(c.capacitySource) &&
    Array.isArray(c.assumptions) &&
    c.assumptions.length > 0 &&
    c.assumptions.every(present)
  );
}

/** Build a detached assessment. Missing and unqualified inputs never imply readiness. */
export function assessMaintenance(input: AssessmentInput): Assessment {
  const validWindow =
    Number.isFinite(input.window.start) &&
    Number.isFinite(input.window.end) &&
    input.window.start < input.window.end &&
    Number.isFinite(input.capturedAt) &&
    input.capturedAt >= input.window.end;
  const services = input.services.map((s): ServiceAssessment => {
    const topology =
      validWindow &&
      eligible(s.topology, s.scope, input.capturedAt, input.window.start) &&
      (s.topology.value === "exposed" || s.topology.value === "not_exposed")
        ? s.topology.value
        : "unknown";
    const alternatives = s.alternatives.map((a): AlternativeAssessment => {
      const check = (e?: Evidence<boolean>) =>
        validWindow
          ? booleanCheck(e, s.scope, input.capturedAt, input.window.start)
          : "unknown";
      const cap =
        validWindow &&
        eligible(a.capacity, s.scope, input.capturedAt) &&
        validCapacity(a.capacity.value, input.window) &&
        a.capacity.observedAt >= a.capacity.value.interval.end
          ? a.capacity.value
          : undefined;
      return {
        name: a.name,
        reachability: check(a.reachable),
        health: check(a.healthy),
        readiness: check(a.ready),
        substitution: check(a.substitutable),
        failureDomain: check(a.independentFailureDomain),
        capacity: cap
          ? cap.sufficientPeakHeadroom
            ? "confirmed"
            : "blocked"
          : "unknown",
        ...(cap
          ? {
              capacityEvidence: {
                ...cap,
                interval: { ...cap.interval },
                assumptions: [...cap.assumptions],
              },
            }
          : {}),
      };
    });
    return {
      id: s.id,
      name: s.name,
      owner: s.owner,
      scope: s.scope,
      topology,
      alternatives,
    };
  });
  const checks = services.flatMap((s) =>
    s.topology === "not_exposed"
      ? []
      : s.alternatives.map((a) => [
          a.reachability,
          a.health,
          a.readiness,
          a.substitution,
          a.failureDomain,
          a.capacity,
        ]),
  );
  const incomplete =
    !validWindow ||
    !present(input.id) ||
    !input.selectedElements.length ||
    !services.length ||
    new Set(services.map((s) => s.id)).size !== services.length ||
    services.some(
      (s) =>
        !present(s.id) ||
        s.topology === "unknown" ||
        new Set(s.alternatives.map((a) => a.name)).size !==
          s.alternatives.length ||
        s.alternatives.some((a) => !present(a.name)) ||
        (s.topology === "exposed" && !s.alternatives.length),
    ) ||
    checks.some((row) => row.includes("unknown"));
  const blocked = checks.some((row) => row.includes("blocked"));
  return {
    id: input.id,
    capturedAt: input.capturedAt,
    window: { ...input.window },
    selectedElements: [...input.selectedElements],
    services,
    headline: incomplete
      ? "Readiness cannot be confirmed"
      : blocked
        ? "Identified blockers"
        : "No identified blockers in this evidence",
  };
}

/** Comparisons require the same selection, service scope and chronological, equal-duration windows. */
export function compareAssessments(
  before: Assessment,
  after: Assessment,
): { comparable: boolean; changed: string[] } {
  const same = (a: string[], b: string[]) =>
    JSON.stringify([...a].sort()) === JSON.stringify([...b].sort());
  const validIdentity = (assessment: Assessment) =>
    present(assessment.id) &&
    Number.isFinite(assessment.capturedAt) &&
    Number.isFinite(assessment.window.start) &&
    Number.isFinite(assessment.window.end) &&
    assessment.window.start < assessment.window.end &&
    assessment.capturedAt >= assessment.window.end &&
    assessment.selectedElements.length > 0 &&
    assessment.selectedElements.every(present) &&
    new Set(assessment.selectedElements).size ===
      assessment.selectedElements.length &&
    assessment.services.length > 0 &&
    assessment.services.every(
      (service) => present(service.id) && present(service.scope),
    ) &&
    new Set(assessment.services.map((service) => service.id)).size ===
      assessment.services.length;
  if (
    !validIdentity(before) ||
    !validIdentity(after) ||
    before.id === after.id ||
    before.capturedAt >= after.capturedAt ||
    before.window.start > after.window.start ||
    before.window.end - before.window.start !==
      after.window.end - after.window.start ||
    !same(before.selectedElements, after.selectedElements) ||
    !same(
      before.services.map((s) => JSON.stringify([s.id, s.scope])),
      after.services.map((s) => JSON.stringify([s.id, s.scope])),
    )
  )
    return { comparable: false, changed: [] };
  const changed = after.services.flatMap((s) => {
    const prior = before.services.find((p) => p.id === s.id)!;
    const out: string[] = [];
    if (prior.topology !== s.topology)
      out.push(`${s.name}: topology exposure changed`);
    const old = new Map(prior.alternatives.map((a) => [a.name, a]));
    for (const alt of s.alternatives) {
      const prev = old.get(alt.name);
      if (!prev) {
        out.push(`${s.name}: candidate ${alt.name} added`);
        continue;
      }
      old.delete(alt.name);
      for (const key of [
        "reachability",
        "health",
        "readiness",
        "substitution",
        "failureDomain",
        "capacity",
      ] as const)
        if (prev[key] !== alt[key])
          out.push(
            `${s.name} / ${alt.name}: ${key} ${prev[key]} → ${alt[key]}`,
          );
    }
    for (const name of old.keys())
      out.push(`${s.name}: candidate ${name} not present in later assessment`);
    return out;
  });
  return { comparable: true, changed };
}
