import type { IdentityRecord } from "./dnsAdapters";

/** A covering claim cannot hide a conflicting claim over any part of the interval. */
export function revalidatesOwner(
  identities: IdentityRecord[],
  ip: string,
  scope: string,
  owner: string | undefined,
  start: number,
  end: number,
  uncertainty: number | undefined,
): boolean {
  if (
    !owner ||
    uncertainty === undefined ||
    !Number.isFinite(uncertainty) ||
    uncertainty < 0
  )
    return false;
  const lower = start - uncertainty,
    upper = end + uncertainty;
  const overlaps = identities.filter(
    (o) =>
      o.ip === ip &&
      o.scope === scope &&
      o.valid_from <= upper &&
      (o.valid_end === undefined || o.valid_end > lower),
  );
  return (
    overlaps.length > 0 &&
    overlaps.every((o) => o.entity_id === owner && o.entity_kind === "pod") &&
    overlaps.filter(
      (o) =>
        o.valid_from <= lower &&
        (o.valid_end === undefined || o.valid_end > upper),
    ).length === 1
  );
}
