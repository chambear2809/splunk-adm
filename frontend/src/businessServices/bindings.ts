import type {
  BusinessBinding,
  BusinessClaim,
  TechnicalServiceTarget,
  Validity,
} from "./import";
import type { ObservationTime } from "./ownership";

/** Only a trusted qualified reader may construct this; imported flags are not proof. */
export interface NativeServiceIdentity extends TechnicalServiceTarget {
  contract: "qualified_v2";
  observedWindow: { start: number; end: number };
}
export interface BindingResolution {
  binding: BusinessBinding;
  claim?: BusinessClaim;
  native?: NativeServiceIdentity;
  status:
    | "resolved"
    | "unresolved_claim"
    | "unresolved_native"
    | "stale_configuration";
  coverage: "covers" | "partial" | "unknown";
  conflict: boolean;
  reasons: string[];
}

const tuple = (claim: BusinessBinding["claim"] | BusinessClaim) =>
  JSON.stringify([
    claim.authority,
    claim.recordId,
    claim.revision,
    claim.scope,
    claim.memberKind,
    claim.memberId,
  ]);
const recordKey = (authority: string, recordId: string) =>
  JSON.stringify([authority, recordId]);
const sameTarget = (
  a: TechnicalServiceTarget,
  b: TechnicalServiceTarget,
  revision = true,
) =>
  a.kind === "service" &&
  b.kind === "service" &&
  a.authority === b.authority &&
  a.scope === b.scope &&
  (!revision || a.configRevision === b.configRevision) &&
  a.key.service === b.key.service &&
  a.key.environment === b.key.environment &&
  a.key.cluster === b.key.cluster &&
  a.key.namespace === b.key.namespace;
const validNative = (n: NativeServiceIdentity) =>
  n !== null &&
  typeof n === "object" &&
  n.contract === "qualified_v2" &&
  n.kind === "service" &&
  [
    n.authority,
    n.scope,
    n.configRevision,
    n.key?.service,
    n.key?.environment,
    n.key?.cluster,
    n.key?.namespace,
  ].every((v) => typeof v === "string" && v.length > 0 && v === v.trim()) &&
  Number.isFinite(n.observedWindow?.start) &&
  Number.isFinite(n.observedWindow?.end) &&
  n.observedWindow.start >= 0 &&
  n.observedWindow.end > n.observedWindow.start;
const validTime = (t: ObservationTime) =>
  t.kind === "point"
    ? Number.isFinite(t.at) && t.at >= 0
    : Number.isFinite(t.from) &&
      Number.isFinite(t.to) &&
      t.from >= 0 &&
      t.to > t.from;
const at = (v: Validity, snapshot: number, point: number) =>
  v.basis === "snapshot_current"
    ? point === v.at
    : point >= v.from &&
      point <= snapshot &&
      (v.to === undefined || point < v.to);

/** Coverage of the intersection, without extending a source beyond its snapshot. */
function coverage(
  time: ObservationTime,
  evidence: { validity: Validity; snapshotAt: number }[],
  window?: { start: number; end: number },
): BindingResolution["coverage"] {
  if (!validTime(time)) return "unknown";
  const inWindow = (point: number) =>
    !window || (point >= window.start && point < window.end);
  const includes = (point: number) =>
    inWindow(point) &&
    evidence.every((e) => at(e.validity, e.snapshotAt, point));
  if (time.kind === "point") return includes(time.at) ? "covers" : "unknown";
  const points = evidence
    .filter((e) => e.validity.basis === "snapshot_current")
    .map((e) => (e.validity as { basis: "snapshot_current"; at: number }).at);
  if (points.length)
    return points.every((p) => p === points[0]) &&
      points[0] >= time.from &&
      points[0] < time.to &&
      includes(points[0])
      ? "partial"
      : "unknown";
  let start = Math.max(time.from, window?.start ?? 0);
  let end = Math.min(time.to, window?.end ?? Infinity);
  for (const e of evidence) {
    if (e.validity.basis !== "source_interval") return "unknown";
    start = Math.max(start, e.validity.from);
    end = Math.min(end, e.validity.to ?? Infinity, e.snapshotAt);
  }
  if (start > end) return "unknown";
  if (start === end)
    return start < time.to && includes(start) ? "partial" : "unknown";
  return start === time.from && end === time.to ? "covers" : "partial";
}

/** Resolves imported assertions only against caller-supplied authorized native identities.
 * No names, IPs, graph strings, labels, edges, or priority are inferred or changed.
 */
export function resolveBusinessOwnership(
  claims: BusinessClaim[],
  bindings: BusinessBinding[],
  nativeIdentities: NativeServiceIdentity[],
  time: ObservationTime,
): BindingResolution[] {
  const claimLatest = new Map<string, number>();
  const bindingLatest = new Map<string, number>();
  for (const c of claims)
    claimLatest.set(
      recordKey(c.authority, c.recordId),
      Math.max(
        claimLatest.get(recordKey(c.authority, c.recordId)) ?? -1,
        c.revision,
      ),
    );
  for (const b of bindings)
    bindingLatest.set(
      recordKey(b.authority, b.recordId),
      Math.max(
        bindingLatest.get(recordKey(b.authority, b.recordId)) ?? -1,
        b.revision,
      ),
    );
  const candidates = bindings.filter(
    (b) => bindingLatest.get(recordKey(b.authority, b.recordId)) === b.revision,
  );
  const valid = nativeIdentities.filter(validNative);
  return candidates.map((binding) => {
    const matches = claims.filter(
      (c) =>
        tuple(c) === tuple(binding.claim) &&
        claimLatest.get(recordKey(c.authority, c.recordId)) === c.revision,
    );
    const claim = matches.length === 1 ? matches[0] : undefined;
    const exact = valid.filter((n) => sameTarget(binding.target, n));
    const native =
      exact.find(
        (n) =>
          claim &&
          coverage(time, [claim, binding], n.observedWindow) !== "unknown",
      ) ?? exact[0];
    const stale =
      !native && valid.some((n) => sameTarget(binding.target, n, false));
    const status: BindingResolution["status"] = !claim
      ? "unresolved_claim"
      : native
        ? "resolved"
        : stale
          ? "stale_configuration"
          : "unresolved_native";
    const overlap = (other: BusinessBinding) =>
      coverage(time, [binding, other]) !== "unknown";
    const duplicateRevision =
      bindings.filter(
        (other) =>
          other.authority === binding.authority &&
          other.recordId === binding.recordId &&
          other.revision === binding.revision,
      ).length > 1;
    const competing = candidates.some(
      (other) =>
        other !== binding &&
        tuple(other.claim) === tuple(binding.claim) &&
        overlap(other),
    );
    const conflictingClaim =
      !!claim &&
      claims.some(
        (other) =>
          other !== claim &&
          other.authority === claim.authority &&
          claimLatest.get(recordKey(other.authority, other.recordId)) ===
            other.revision &&
          other.serviceId === claim.serviceId &&
          (other.teamId !== claim.teamId ||
            other.criticality !== claim.criticality) &&
          coverage(time, [claim, other]) !== "unknown",
      );
    const conflict =
      duplicateRevision || competing || matches.length > 1 || conflictingClaim;
    const resolvedCoverage =
      claim && native
        ? coverage(time, [claim, binding], native.observedWindow)
        : "unknown";
    const reasons = [
      ...(!claim
        ? ["The referenced current claim is unavailable or ambiguous."]
        : []),
      ...(status === "unresolved_native"
        ? ["Qualified native identity is unavailable."]
        : []),
      ...(stale
        ? ["Native configuration revision differs from the imported binding."]
        : []),
      ...(resolvedCoverage === "unknown" && claim && native
        ? ["The claim, binding and observation do not cover the selected time."]
        : []),
      ...(conflict
        ? ["Duplicate or overlapping assertions require review."]
        : []),
    ];
    return {
      binding,
      ...(claim ? { claim } : {}),
      ...(native ? { native } : {}),
      status,
      coverage: resolvedCoverage,
      conflict,
      reasons,
    };
  });
}
