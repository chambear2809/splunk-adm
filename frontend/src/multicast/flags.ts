import type { GroupSummary, ProfileSummary } from "./contract";

export type FlagId =
  | "interest-no-sender"
  | "sender-no-interest"
  | "new-since-previous"
  | "leave-without-query"
  | "multiple-query-senders"
  | "coverage-partial";

export interface GroupRow {
  group: string;
  summaries: GroupSummary[];
  flags: FlagId[];
}

export const FLAG_LABEL: Record<FlagId, string> = {
  "interest-no-sender": "Interest, no sender seen",
  "sender-no-interest": "Sender, no interest seen",
  "new-since-previous": "New since previous window",
  "leave-without-query": "Leave without query",
  "multiple-query-senders": "Multiple query senders",
  "coverage-partial": "Source coverage partial",
};

const FLAG_ORDER = Object.keys(FLAG_LABEL) as FlagId[];

function laterThan(value: number, other: number | undefined): boolean {
  return other === undefined || value > other;
}

function lastSeen(row: GroupRow): number {
  return Math.max(...row.summaries.map((summary) => summary.lastSeen));
}

export function deriveGroupRows(
  current: ProfileSummary[],
  previous?: ProfileSummary[] | "unavailable",
): GroupRow[] {
  const byGroup = new Map<
    string,
    { summaries: GroupSummary[]; flags: Set<FlagId> }
  >();
  const coveragePartial = current.some(
    (profile) => profile.outcome.state !== "complete",
  );

  for (const profile of current) {
    const lastGeneralQuery = profile.queries?.lastGeneralQuery;
    const multipleSenders =
      new Set(profile.queries?.querySenders.map((sender) => sender.address))
        .size > 1;
    for (const summary of profile.summaries) {
      let entry = byGroup.get(summary.group);
      if (!entry) {
        entry = { summaries: [], flags: new Set() };
        byGroup.set(summary.group, entry);
      }
      entry.summaries.push(summary);
      if (multipleSenders) entry.flags.add("multiple-query-senders");
      if (
        summary.kind === "igmp" &&
        summary.lastLeave !== undefined &&
        laterThan(summary.lastLeave, summary.lastGroupQuery) &&
        laterThan(summary.lastLeave, lastGeneralQuery)
      ) {
        entry.flags.add("leave-without-query");
      }
    }
  }

  const previousGroups = Array.isArray(previous)
    ? new Set(
        previous.flatMap((profile) =>
          profile.summaries.map((summary) => summary.group),
        ),
      )
    : undefined;

  const rows: GroupRow[] = [];
  for (const [group, { summaries, flags }] of byGroup) {
    const interest = summaries.some(
      (summary) => summary.kind === "igmp" && summary.reports > 0,
    );
    const sender = summaries.some((summary) => summary.kind === "flow");
    if (interest && !sender) flags.add("interest-no-sender");
    if (sender && !interest) flags.add("sender-no-interest");
    if (previousGroups && !previousGroups.has(group)) {
      flags.add("new-since-previous");
    }
    if (coveragePartial) flags.add("coverage-partial");
    rows.push({
      group,
      summaries,
      flags: FLAG_ORDER.filter((flag) => flags.has(flag)),
    });
  }

  return rows.sort(
    (a, b) =>
      b.flags.length - a.flags.length ||
      lastSeen(b) - lastSeen(a) ||
      (a.group < b.group ? -1 : a.group > b.group ? 1 : 0),
  );
}
