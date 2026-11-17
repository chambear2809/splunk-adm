import type { CaseEntry } from "./caseClient";

/** Return each immutable entry lineage oldest-first; reject broken or forked references. */
export function entryHistories(
  entries: CaseEntry[],
): CaseEntry[][] | undefined {
  const byId = new Map<string, CaseEntry>();
  for (const entry of entries) {
    if (byId.has(entry.id)) return undefined;
    byId.set(entry.id, entry);
  }
  const next = new Map<string, CaseEntry>();
  for (const entry of entries) {
    const parentId = entry.supersedes_entry_id;
    if (parentId === undefined) continue;
    const parent = byId.get(parentId);
    if (
      !parent ||
      parent.id === entry.id ||
      parent.type !== entry.type ||
      parent.revision >= entry.revision ||
      next.has(parentId)
    )
      return undefined;
    next.set(parentId, entry);
  }
  const histories: CaseEntry[][] = [];
  for (const root of entries.filter(
    (entry) => entry.supersedes_entry_id === undefined,
  )) {
    const history = [root];
    while (next.has(history[history.length - 1].id))
      history.push(next.get(history[history.length - 1].id)!);
    histories.push(history);
  }
  return histories.reduce((total, history) => total + history.length, 0) ===
    entries.length
    ? histories
    : undefined;
}
