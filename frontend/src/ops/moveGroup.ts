export interface MoveCandidate {
  vm: string;
  host: string;
  source: "vmware:inv:vm" | "cisco:intersight";
}

export interface MoveGroupPlan {
  group: string;
  candidates: MoveCandidate[];
  blockers: string[];
}

/** Plan a move group from TA inventory rows. No vCenter API is called here. */
export function moveGroupPlan(
  group: string,
  candidates: MoveCandidate[],
): MoveGroupPlan {
  const name = group.trim();
  if (!name) throw new Error("Move group name is required.");
  const blockers: string[] = [];
  if (candidates.some((row) => row.source === "cisco:intersight"))
    blockers.push(
      "Intersight inventory identifies compute; it does not prove vMotion completion.",
    );
  if (candidates.length === 0)
    blockers.push(
      "No VMware or Intersight inventory rows were supplied for this group.",
    );
  return { group: name, candidates, blockers };
}
