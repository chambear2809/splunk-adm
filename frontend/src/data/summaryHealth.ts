import { requireNoSearchErrors, type SearchClient } from "./searchClient";

/** Qualified graph summary lag and gap probe (`adm_qualified_summary_health`). */
export const SUMMARY_HEALTH_SEARCH = "| `adm_qualified_summary_health`";

export type SummaryHealthStatus =
  "ok" | "lagging" | "gaps" | "no_summaries" | "disabled";

export interface SummaryHealth {
  status: SummaryHealthStatus;
  lateness?: number;
  newestEnd?: number;
  lagSeconds?: number;
  slices: number;
  dueSlices: number;
  missingSlices: number;
  oldestMissing?: number;
  newestMissing?: number;
  emptySlices: number;
  supersededRuns: number;
  duplicatedRuns: number;
}

const STATUSES: readonly SummaryHealthStatus[] = [
  "ok",
  "lagging",
  "gaps",
  "no_summaries",
  "disabled",
];

const num = (v: unknown): number | undefined => {
  const x = Array.isArray(v) ? v[0] : v;
  if (typeof x === "number" && Number.isFinite(x) && x >= 0) return x;
  if (typeof x === "string" && /^\d+(\.\d+)?$/.test(x.trim())) return Number(x);
  return undefined;
};

/** One untrusted probe row; anything malformed is rejected. */
export function rowsToSummaryHealth(rows: unknown): SummaryHealth {
  if (!Array.isArray(rows) || rows.length !== 1)
    throw new Error("Summary health returned an unexpected result.");
  const r = rows[0] as Record<string, unknown>;
  const status = (Array.isArray(r?.status) ? r.status[0] : r?.status) as
    SummaryHealthStatus | undefined;
  if (!status || !STATUSES.includes(status))
    throw new Error("Summary health status is invalid.");
  const health: SummaryHealth = {
    status,
    slices: num(r.slices_24h) ?? 0,
    dueSlices: num(r.due_slices_24h) ?? 0,
    missingSlices: num(r.missing_slices_24h) ?? 0,
    emptySlices: num(r.empty_slices_24h) ?? 0,
    supersededRuns: num(r.superseded_or_incomplete_runs) ?? 0,
    duplicatedRuns: num(r.duplicated_runs) ?? 0,
  };
  const optional = {
    lateness: num(r.lateness),
    newestEnd: num(r.newest_summary_end),
    lagSeconds: num(r.lag_seconds),
    oldestMissing: num(r.oldest_missing),
    newestMissing: num(r.newest_missing),
  };
  for (const [k, v] of Object.entries(optional))
    if (v !== undefined) (health as unknown as Record<string, number>)[k] = v;
  return health;
}

export async function loadSummaryHealth(
  client: SearchClient,
  signal: AbortSignal,
  asOf?: number,
): Promise<SummaryHealth> {
  const result = await client.search({
    search: SUMMARY_HEALTH_SEARCH,
    earliest: "-24h",
    latest: "now",
    ...(asOf !== undefined ? { now: asOf } : {}),
    maxRows: 1,
    signal,
  });
  return rowsToSummaryHealth(
    requireNoSearchErrors(result, "Summary health").rows,
  );
}

/** "ok · lag 4 min · 286 of 286 slices" style summary for the table. */
export function summaryHealthText(h: SummaryHealth): string {
  if (h.status === "disabled") return "Not enabled";
  if (h.status === "no_summaries") return "No summaries in the last 24 hours";
  const lag =
    h.lagSeconds !== undefined
      ? ` · lag ${Math.round(h.lagSeconds / 60)} min`
      : "";
  const gaps = h.missingSlices ? ` · ${h.missingSlices} missing` : "";
  return `${h.status === "ok" ? "OK" : h.status === "lagging" ? "Lagging" : "Gaps"}${lag} · ${h.slices} of ${h.dueSlices} slices${gaps}`;
}
