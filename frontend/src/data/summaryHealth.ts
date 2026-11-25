import { requireNoSearchErrors, type SearchClient } from "./searchClient";

/** Qualified graph summary lag and gap probe (`adm_qualified_summary_health`). */
export const SUMMARY_HEALTH_SEARCH = "| `adm_qualified_summary_health`";

export type SummaryHealthStatus =
  "ok" | "lagging" | "gaps" | "no_summaries" | "disabled";

export interface SummaryHealth {
  status: SummaryHealthStatus;
  newestEnd?: number;
  lagSeconds?: number;
  slices: number;
  dueSlices: number;
  missingSlices: number;
  oldestMissing?: number;
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

const single = (v: unknown) =>
  Array.isArray(v) ? (v.length === 1 ? v[0] : undefined) : v;

const num = (v: unknown) => {
  const x = single(v);
  return typeof x === "number" ||
    (typeof x === "string" && /^\d+(\.\d+)?$/.test(x.trim()))
    ? Number(x)
    : NaN;
};

const invalid = () => new Error("Invalid summary health result.");

/** One untrusted probe row; anything malformed is rejected. */
export function rowsToSummaryHealth(rows: unknown): SummaryHealth {
  if (!Array.isArray(rows) || rows.length !== 1) throw invalid();
  const r = rows[0] as Record<string, unknown>;
  const status = single(r?.status) as SummaryHealthStatus;
  if (!STATUSES.includes(status)) throw invalid();
  const count = (name: string) => {
    if (status === "disabled" && r[name] == null) return 0;
    const n = num(r[name]);
    if (!Number.isSafeInteger(n) || n < 0) throw invalid();
    return n;
  };
  const health: SummaryHealth = {
    status,
    slices: count("slices_24h"),
    dueSlices: count("due_slices_24h"),
    missingSlices: count("missing_slices_24h"),
    emptySlices: count("empty_slices_24h"),
    supersededRuns: count("superseded_or_incomplete_runs"),
    duplicatedRuns: count("duplicated_runs"),
  };
  const { slices, dueSlices, missingSlices, emptySlices } = health;
  if (
    missingSlices > dueSlices ||
    dueSlices - missingSlices > slices ||
    emptySlices > slices ||
    (status === "ok" && missingSlices > 0)
  )
    throw invalid();
  const optional = [
    ["newestEnd", "newest_summary_end"],
    ["lagSeconds", "lag_seconds"],
    ["oldestMissing", "oldest_missing"],
  ] as const;
  for (const [key, source] of optional) {
    if (r[source] == null) continue;
    const value = num(r[source]);
    if (!Number.isFinite(value) || value < 0 || value > 8.64e12)
      throw invalid();
    (health as unknown as Record<string, number>)[key] = value;
  }
  return health;
}

export async function loadSummaryHealth(
  client: SearchClient,
  signal: AbortSignal,
  asOf?: number,
): Promise<SummaryHealth> {
  const result = await client.search({
    search: SUMMARY_HEALTH_SEARCH,
    earliest: asOf === undefined ? "-24h" : String(asOf - 86400),
    latest: asOf === undefined ? "now" : String(asOf),
    maxRows: 1,
    signal,
  });
  const complete = requireNoSearchErrors(result, "Summary health");
  if (complete.warnings.length) throw new Error(complete.warnings[0]);
  return rowsToSummaryHealth(complete.rows);
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
  return `${h.status === "ok" ? "OK" : h.status === "lagging" ? "Lagging" : "Gaps"}${lag} · ${h.dueSlices - h.missingSlices} of ${h.dueSlices} slices${gaps}`;
}
