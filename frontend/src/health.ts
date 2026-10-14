import type { SearchClient } from "./data/searchClient";
import type { Row } from "./rows";

export const SOURCE_NAMES = [
  "NetFlow",
  "DC Networking",
  "FTD",
  "Isovalent",
  "Kubernetes",
  "Traces",
  "Hubble",
  "Summary",
] as const;
export const JOB_NAMES = [
  "Identity builder",
  "Service binding",
  "Service backends",
  "ACI policy",
  "Interface inventory",
  "Conversation rollup",
  "Identity prune",
  "Service binding prune",
  "Service backends prune",
  "Service routes prune",
  "ACI policy prune",
].map((name) => `ADM - ${name}`);
export interface SourceHealth {
  name: string;
  records?: number;
  latestEvent?: number;
  latestIndexed?: number;
  maxIngestLag?: number;
}
export interface JobHealth {
  name: string;
  disabled?: boolean;
  lastRun?: number;
  lastSuccess?: number;
  lastStatus?: string;
  failures?: number;
  skips?: number;
}
export interface HealthReport {
  sources: SourceHealth[];
  jobs: JobHealth[];
  quality: QualityHealth;
  warnings: string[];
  checkedAt: number;
}
export interface QualityHealth {
  evaluated?: number;
  excluded?: number;
  issues: { source: string; reason: string; status: string; records: number }[];
}
export const QUALITY_REASONS: Record<string, string> = {
  invalid_source_ip: "Invalid source address",
  invalid_destination_ip: "Invalid destination address",
  missing_observer: "Missing observing device or scope identifier",
  invalid_observer_ip: "Invalid exporter or firewall address",
  invalid_time: "Missing, reversed, or out-of-range flow time",
  missing_transport: "Missing network protocol",
  invalid_ports: "Missing or invalid transport ports",
  invalid_counters: "Invalid byte or packet counters",
  invalid_sampling: "Invalid sampling interval",
  missing_counters: "Byte or packet measurements are missing",
  unknown_sampling: "Sampling interval missing; assuming 1:1",
  unmapped_scope: "No observer mapping; using the default scope",
};
export function qualityRows(rows: Row[]): QualityHealth {
  const summary = rows.find(
    (r) =>
      r.kind === "quality" &&
      r.source === "all" &&
      r.status === "checked" &&
      r.reason === "evaluated",
  );
  const evaluated = numeric(summary?.records);
  const excludedRows = rows.filter(
    (r) =>
      r.kind === "quality" &&
      r.reason === "evaluated" &&
      r.status === "excluded",
  );
  const excluded =
    evaluated === undefined ||
    excludedRows.some((r) => numeric(r.records) === undefined)
      ? undefined
      : excludedRows.reduce((n, r) => n + numeric(r.records)!, 0);
  return {
    evaluated,
    excluded:
      excluded !== undefined && evaluated !== undefined && excluded <= evaluated
        ? excluded
        : undefined,
    issues: rows
      .filter(
        (r) =>
          r.kind === "quality" &&
          typeof r.reason === "string" &&
          Object.hasOwn(QUALITY_REASONS, r.reason) &&
          numeric(r.records) !== undefined,
      )
      .map((r) => ({
        source: text(r.source) ?? "Unknown",
        reason: QUALITY_REASONS[String(r.reason)],
        status: r.status === "excluded" ? "Excluded" : "Accepted with warning",
        records: numeric(r.records)!,
      })),
  };
}
const numeric = (value: unknown): number | undefined => {
  if (value === undefined || value === null || value === "") return undefined;
  const n = Number(value);
  return Number.isFinite(n) && n >= 0 ? n : undefined;
};
const timestamp = (value: unknown) => {
  const n = numeric(value);
  return n && n > 0 && n <= 8640000000000 ? n : undefined;
};
const text = (value: unknown) =>
  typeof value === "string" ? value.slice(0, 300) : undefined;
export function sourceRows(rows: Row[]): SourceHealth[] {
  return SOURCE_NAMES.map((name) => {
    const r =
      rows.find((row) => row.kind === "source" && row.name === name) ?? {};
    return {
      name,
      records: numeric(r.records),
      latestEvent: timestamp(r.latest_event),
      latestIndexed: timestamp(r.latest_indexed),
      maxIngestLag: numeric(r.max_ingest_lag),
    };
  });
}
export function jobRows(rows: Row[]): JobHealth[] {
  return JOB_NAMES.map((name) => {
    const r = rows.find((row) => row.kind === "job" && row.name === name) ?? {};
    return {
      name,
      disabled:
        r.disabled === "1" || r.disabled === 1 || r.disabled === true
          ? true
          : r.disabled === "0" || r.disabled === 0 || r.disabled === false
            ? false
            : undefined,
      lastRun: timestamp(r.last_run),
      lastSuccess: timestamp(r.last_success),
      lastStatus: text(r.last_status),
      failures: numeric(r.failures),
      skips: numeric(r.skips),
    };
  });
}
export function sourceStatus(source: SourceHealth, now: number): string {
  if (source.records === undefined) return "Unavailable";
  if (!source.latestIndexed)
    return source.records === 0
      ? "No visible data in 24 hours"
      : "Receipt time unavailable";
  if (source.latestIndexed > now + 60) return "Clock is ahead";
  return now - source.latestIndexed <= 1200
    ? "Data received within 20 minutes"
    : "No data received in 20 minutes";
}
export function jobStatus(job: JobHealth, now: number): string {
  if (job.disabled === undefined) return "Configuration unavailable";
  if (job.disabled) return "Disabled";
  if (!job.lastRun) return "No visible run in 24 hours";
  if (job.lastRun > now + 60) return "Clock is ahead";
  if (job.lastStatus !== "success")
    return job.lastStatus
      ? `Last run: ${job.lastStatus}`
      : "Run outcome unavailable";
  const threshold = job.name.endsWith("prune")
    ? 26 * 3600
    : job.name.endsWith("Interface inventory")
      ? 2 * 3600
      : 1200;
  if (!job.lastSuccess) return "Successful run not confirmed";
  return now - job.lastSuccess > threshold
    ? "Successful run is overdue"
    : "Recent successful run";
}
export async function loadHealth(
  client: SearchClient,
  signal: AbortSignal,
): Promise<HealthReport> {
  const searches = ["sources", "jobs", "quality"] as const;
  const results = await Promise.allSettled(
    searches.map((part) =>
      client.search({
        search: `| \`adm_health_${part}\``,
        earliest: "-24h",
        latest: "now",
        maxRows: part === "quality" ? 500 : 100,
        signal,
      }),
    ),
  );
  if (signal.aborted) throw new Error("Health check cancelled.");
  const warnings: string[] = [];
  const rows = results.map((result, i) => {
    if (result.status === "fulfilled") {
      warnings.push(
        ...result.value.warnings.map((w) => `${searches[i]}: ${w}`),
      );
      return result.value.rows;
    }
    warnings.push(
      `${searches[i]} health unavailable. ${result.reason instanceof Error ? result.reason.message.slice(0, 300) : "Search failed."}`,
    );
    return [];
  });
  const sources = sourceRows(rows[0]);
  const jobs = jobRows(rows[1]);
  const quality = qualityRows(rows[2]);
  if (
    sources.some((s) => s.records === undefined) ||
    jobs.some((j) => j.disabled === undefined) ||
    quality.evaluated === undefined
  )
    warnings.push(
      "Some health information is unavailable. Ask an administrator to check index access and visibility of the app's saved searches.",
    );
  return {
    sources,
    jobs,
    quality,
    warnings: [...new Set(warnings)],
    checkedAt: Date.now() / 1000,
  };
}
