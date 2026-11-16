import type { BusinessClaim } from "./import";

/** Callers must resolve these identifiers against a qualified graph source. */
export interface ResolvedMember {
  authority: string;
  scope: string;
  memberKind: BusinessClaim["memberKind"];
  memberId: string;
}
export type ObservationTime =
  | { kind: "point"; at: number }
  | { kind: "interval"; from: number; to: number };
export interface OwnershipAnnotation {
  claim: BusinessClaim;
  coverage: "covers" | "partial" | "unknown";
  conflict: boolean;
}

function claimsOverlap(
  a: BusinessClaim,
  b: BusinessClaim,
  time: ObservationTime,
): boolean {
  const includes = (claim: BusinessClaim, point: number) =>
    claim.validity.basis === "snapshot_current"
      ? point === claim.validity.at
      : point >= claim.validity.from &&
        point <= claim.snapshotAt &&
        (claim.validity.to === undefined || point < claim.validity.to);
  if (time.kind === "point")
    return includes(a, time.at) && includes(b, time.at);
  if (
    a.validity.basis === "snapshot_current" ||
    b.validity.basis === "snapshot_current"
  ) {
    const point =
      a.validity.basis === "snapshot_current"
        ? a.validity.at
        : (b.validity as { at: number }).at;
    return (
      point >= time.from &&
      point < time.to &&
      includes(a, point) &&
      includes(b, point)
    );
  }
  const start = Math.max(time.from, a.validity.from, b.validity.from);
  return (
    start <
      Math.min(time.to, a.validity.to ?? Infinity, b.validity.to ?? Infinity) &&
    start <= Math.min(a.snapshotAt, b.snapshotAt)
  );
}

/** Retains uncertain and conflicting assertions; never changes graph identity or priority. */
export function annotateOwnership(
  claims: BusinessClaim[],
  members: ResolvedMember[],
  time: ObservationTime,
): OwnershipAnnotation[] {
  const latest = new Map<string, number>();
  const revisions = new Map<string, number>();
  for (const claim of claims) {
    const key = JSON.stringify([claim.authority, claim.recordId]);
    latest.set(key, Math.max(latest.get(key) ?? -1, claim.revision));
    const revisionKey = JSON.stringify([
      claim.authority,
      claim.recordId,
      claim.revision,
    ]);
    revisions.set(revisionKey, (revisions.get(revisionKey) ?? 0) + 1);
  }
  const validTime =
    time.kind === "point"
      ? Number.isFinite(time.at)
      : Number.isFinite(time.from) &&
        Number.isFinite(time.to) &&
        time.from < time.to;
  const annotations: OwnershipAnnotation[] = claims
    .filter(
      (claim) =>
        claim.revision ===
        latest.get(JSON.stringify([claim.authority, claim.recordId])),
    )
    .filter((claim) =>
      members.some(
        (member) =>
          member.authority === claim.authority &&
          member.scope === claim.scope &&
          member.memberKind === claim.memberKind &&
          member.memberId === claim.memberId,
      ),
    )
    .map((claim) => {
      const duplicate =
        (revisions.get(
          JSON.stringify([claim.authority, claim.recordId, claim.revision]),
        ) ?? 0) > 1;
      if (!validTime || claim.validity.basis === "snapshot_current") {
        const covers =
          validTime &&
          time.kind === "point" &&
          claim.validity.basis === "snapshot_current" &&
          time.at === claim.validity.at;
        return {
          claim,
          coverage: covers ? ("covers" as const) : ("unknown" as const),
          conflict: duplicate,
        };
      }
      const { from, to } = claim.validity;
      const end = Math.min(to ?? Infinity, claim.snapshotAt);
      const at = (value: number) =>
        value >= from &&
        value <= claim.snapshotAt &&
        (to === undefined || value < to);
      let coverage: OwnershipAnnotation["coverage"];
      if (time.kind === "point") coverage = at(time.at) ? "covers" : "unknown";
      else if (
        time.from >= from &&
        time.to <= claim.snapshotAt &&
        (to === undefined || time.to <= to)
      )
        coverage = "covers";
      else if (
        time.from <= end &&
        time.to > from &&
        (to === undefined || time.from < to)
      )
        coverage = "partial";
      else coverage = "unknown";
      return { claim, coverage, conflict: duplicate };
    });
  for (let i = 0; i < annotations.length; i++) {
    for (let j = i + 1; j < annotations.length; j++) {
      const a = annotations[i],
        b = annotations[j];
      if (
        a.claim.authority === b.claim.authority &&
        a.claim.serviceId === b.claim.serviceId &&
        claimsOverlap(a.claim, b.claim, time) &&
        a.coverage !== "unknown" &&
        b.coverage !== "unknown" &&
        (a.claim.teamId !== b.claim.teamId ||
          a.claim.criticality !== b.claim.criticality)
      ) {
        a.conflict = true;
        b.conflict = true;
      }
    }
  }
  return annotations;
}
