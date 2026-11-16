import type { BusinessClaim } from "./import";
import {
  annotateOwnership,
  type ObservationTime,
  type ResolvedMember,
} from "./ownership";

export function OwnershipAnnotations({
  claims,
  members,
  time,
}: {
  claims: BusinessClaim[];
  members: ResolvedMember[];
  time: ObservationTime;
}) {
  const annotations = annotateOwnership(claims, members, time);
  if (!annotations.length)
    return (
      <p>
        No resolved business ownership claims are available for this selection.
      </p>
    );
  return (
    <section aria-label="Business ownership annotations">
      <h3>Business ownership</h3>
      <p>
        Imported assertions provide business context; technical priority remains
        separate. Identity and ownership are not verified by this import.
      </p>
      <ul>
        {annotations.map(({ claim, coverage, conflict }, index) => (
          <li
            key={`${claim.authority}:${claim.recordId}:${claim.revision}:${index}`}
          >
            <strong>{claim.serviceName}</strong> ({claim.serviceId}) ·{" "}
            {claim.teamName} ({claim.teamId}) · business criticality:{" "}
            {claim.criticality}
            <div>
              {coverage === "covers"
                ? "Claim covers the selected time"
                : coverage === "partial"
                  ? "Claim covers only part of the selected time"
                  : "Ownership for the selected time is unknown"}
              {claim.validity.basis === "snapshot_current"
                ? "; current snapshot only, historical ownership unavailable"
                : ""}
              {conflict
                ? "; conflicting source records, ownership, or criticality claims require review"
                : ""}
            </div>
            <div>
              Source: {claim.authority} · snapshot {claim.snapshotId} ·{" "}
              {new Date(claim.snapshotAt * 1000).toISOString()}
            </div>
          </li>
        ))}
      </ul>
    </section>
  );
}
