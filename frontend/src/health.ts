import type { RunResult, SearchClient } from "./data/searchClient";
import type { Row } from "./rows";

import {
  SOURCE_DEFINITIONS,
  JOB_DEFINITIONS,
  applicableJobs,
  expectationFor,
  isCoreSource,
  selectedQualitySources,
  selectedHealthProbes,
  type DeploymentSnapshot,
} from "./data/deploymentHealth";

export const SOURCE_NAMES = SOURCE_DEFINITIONS.map((source) => source.label);
export const JOB_NAMES = JOB_DEFINITIONS.map((job) => job.name);
export interface SourceHealth {
  name: string;
  id?: string;
  expectation?: "active" | "staged" | "not_selected" | "unknown";
  configuration?: "configured" | "not_configured" | "unavailable";
  quiet?: boolean;
  staleAfterSeconds?: number;
  evidence?: string[];
  status?: string;
  probeLookbackSeconds?: number;
  records?: number;
  latestEvent?: number;
  latestIndexed?: number;
  maxIngestLag?: number;
  unmapped?: number;
  unresolved?: number;
  mappedRecords?: number;
  mappingKeys?: number;
  warning?: string;
}
export interface JobHealth {
  name: string;
  contractConflict?: boolean;
  disabled?: boolean;
  scheduled?: boolean;
  required?: boolean;
  staleAfterSeconds?: number;
  lastRun?: number;
  lastSuccess?: number;
  lastStatus?: string;
  failures?: number;
  skips?: number;
}
export interface HealthReport {
  deployment?: DeploymentSnapshot;
  scope?: "full" | "jobs";
  sources: SourceHealth[];
  optionalEvidence: OptionalEvidenceHealth[];
  jobs: JobHealth[];
  quality: QualityHealth;
  qualityRequired?: boolean;
  warnings: string[];
  checkedAt: number;
}
export interface OptionalEvidenceHealth {
  id: string;
  name: string;
  expectation: "active" | "staged" | "not_selected" | "unknown";
  configuration: "configured" | "not_configured" | "unavailable" | "unknown";
  receipt: "unknown";
  status:
    | "not_selected"
    | "staged"
    | "configured"
    | "not_configured"
    | "unavailable"
    | "unknown";
  diagnostic: string;
}
export interface QualityHealth {
  incomplete?: boolean;
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
  unmapped_scope: "No observer mapping; source authority remains isolated",
};
export function qualityRows(rows: Row[]): QualityHealth {
  const summaries = rows.filter(
    (r) =>
      r.kind === "quality" &&
      r.source === "all" &&
      r.status === "checked" &&
      r.reason === "evaluated",
  );
  const evaluated =
    summaries.length === 1 ? count(summaries[0].records) : undefined;
  const excludedRows = rows.filter(
    (r) =>
      r.kind === "quality" &&
      r.reason === "evaluated" &&
      (r.status === "excluded" || r.status === "excluded_uncorrelated"),
  );
  const excluded =
    evaluated === undefined ||
    excludedRows.some((r) => count(r.records) === undefined)
      ? undefined
      : excludedRows.reduce((n, r) => n + count(r.records)!, 0);
  const keys = rows.map((row) =>
    JSON.stringify([row.source, row.status, row.reason]),
  );
  return {
    incomplete:
      evaluated === undefined ||
      keys.length !== new Set(keys).size ||
      rows.some(
        (row) =>
          row.kind === "quality" &&
          (count(row.records) === undefined ||
            typeof row.reason !== "string" ||
            typeof row.status !== "string" ||
            (row.reason === "evaluated" &&
              ![
                "checked",
                "accepted",
                "accepted_with_warning",
                "excluded",
                "excluded_uncorrelated",
                "context_only",
                "mapped",
                "unmapped",
                "ambiguous",
                "unsupported",
                "incomplete",
              ].includes(String(row.status)))),
      ),
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
          count(r.records) !== undefined &&
          count(r.records)! > 0 &&
          (r.reason !== "evaluated" ||
            ["unmapped", "ambiguous", "unsupported", "incomplete"].includes(
              String(r.status),
            )) &&
          !(
            r.status === "mapped" &&
            ["profile_mapped", "history_observation_valid"].includes(r.reason)
          ),
      )
      .map((r) => ({
        source: text(r.source) ?? "Unknown",
        reason:
          r.reason === "evaluated"
            ? `Source disposition: ${String(r.status)}`
            : (QUALITY_REASONS[String(r.reason)] ??
              String(r.reason).slice(0, 300)),
        status:
          r.status === "excluded" || r.status === "excluded_uncorrelated"
            ? "Excluded"
            : r.status === "checked"
              ? "Checked"
              : r.status === "context_only"
                ? "Context only"
                : r.status === "mapped"
                  ? "Diagnostic"
                  : r.status === "accepted" ||
                      r.status === "warning" ||
                      r.status === "accepted_with_warning"
                    ? "Accepted with warning"
                    : `Disposition: ${text(r.status) ?? "unknown"}`,
        records: count(r.records)!,
      })),
  };
}
const numeric = (value: unknown): number | undefined => {
  if (value === undefined || value === null || value === "") return undefined;
  if (typeof value !== "number" && typeof value !== "string") return undefined;
  if (typeof value === "string" && !/^\d+(?:\.\d+)?$/.test(value))
    return undefined;
  const n = Number(value);
  return Number.isFinite(n) && n >= 0 ? n : undefined;
};
const count = (value: unknown) => {
  const n = numeric(value);
  return n !== undefined && Number.isSafeInteger(n) ? n : undefined;
};
const timestamp = (value: unknown) => {
  const n = numeric(value);
  return n && n > 0 && n <= 8640000000000 ? n : undefined;
};
const text = (value: unknown) =>
  typeof value === "string" ? value.slice(0, 300) : undefined;
export function sourceRows(
  rows: Row[],
  deployment?: DeploymentSnapshot,
): SourceHealth[] {
  return SOURCE_DEFINITIONS.filter(isCoreSource).map((definition) => {
    const matches = rows.filter(
      (row) =>
        ["source", "summary"].includes(String(row.kind)) &&
        definition.healthNames.includes(String(row.name)),
    );
    // Duplicate source rows cannot establish complete receipt evidence.
    const r = matches.length === 1 ? matches[0] : {};
    const settings = deployment?.settings?.sources[definition.id];
    return {
      name: definition.label,
      id: definition.id,
      ...(deployment
        ? {
            expectation: expectationFor(deployment, definition.id),
            quiet: definition.quiet,
            staleAfterSeconds:
              settings?.staleAfterSeconds ?? definition.staleAfterSeconds,
            evidence: definition.evidence,
          }
        : {}),
      ...(deployment?.sourceConfiguration
        ? {
            configuration:
              deployment.sourceConfiguration[definition.id] ?? "unavailable",
          }
        : {}),
      status: text(r.status),
      probeLookbackSeconds: numeric(r.probe_lookback_seconds),
      records: count(r.records),
      latestEvent: timestamp(r.latest_event),
      latestIndexed: timestamp(r.latest_indexed),
      maxIngestLag: numeric(r.max_ingest_lag),
      unmapped: count(r.unmapped ?? r.incomplete_records),
      unresolved: count(r.unresolved ?? r.ambiguous_records),
      mappedRecords: count(r.mapped_records),
      mappingKeys: count(r.mapping_keys),
      warning:
        matches.length > 1
          ? "Duplicate source evidence is unavailable."
          : text(r.warning),
    };
  });
}
function optionalEvidenceRows(
  deployment?: DeploymentSnapshot,
): OptionalEvidenceHealth[] {
  return SOURCE_DEFINITIONS.filter(
    (definition) => definition.readinessImpact === "optional_evidence",
  ).map((definition) => {
    const expectation = expectationFor(deployment, definition.id);
    const configuration =
      deployment?.sourceConfiguration?.[definition.id] ??
      (expectation === "active" ? "unavailable" : "unknown");
    const status =
      expectation === "not_selected" || expectation === "staged"
        ? expectation
        : expectation === "active"
          ? configuration
          : "unknown";
    return {
      id: definition.id,
      name: definition.label,
      expectation,
      configuration,
      receipt: "unknown",
      status,
      diagnostic:
        "Optional evidence is shown separately. Runtime diagnostics require an explicit scoped investigation.",
    };
  });
}
const flag = (value: unknown) =>
  value === "1" || value === 1 || value === true
    ? true
    : value === "0" || value === 0 || value === false
      ? false
      : undefined;
export function jobRows(
  rows: Row[],
  deployment?: DeploymentSnapshot,
): JobHealth[] {
  const expected = deployment ? applicableJobs(deployment) : [];
  return JOB_DEFINITIONS.map((definition) => {
    const matches = rows.filter(
      (row) => row.kind === "job" && row.name === definition.name,
    );
    const r = matches.length === 1 ? matches[0] : {};
    return {
      name: definition.name,
      ...(deployment?.state === "configured" && deployment.activeContract
        ? {
            required:
              expected.find((job) => job.id === definition.id)?.required ??
              false,
            contractConflict:
              flag(r.disabled) === false &&
              definition.stage === "active" &&
              !definition.contracts.includes(deployment.activeContract),
          }
        : {}),
      staleAfterSeconds: definition.cadenceSeconds + definition.graceSeconds,
      disabled: flag(r.disabled),
      scheduled: flag(r.is_scheduled ?? r.scheduled),
      lastRun: timestamp(r.last_run),
      lastSuccess: timestamp(r.last_success),
      lastStatus: text(r.last_status),
      failures: count(r.failures),
      skips: count(r.skips),
    };
  });
}
export interface HealthAssessment {
  reason?: "contract_conflict";
  state: "healthy" | "unknown" | "attention" | "not_required";
  label: string;
}
const assessment = (
  state: HealthAssessment["state"],
  label: string,
): HealthAssessment => ({ state, label });
export function sourceAssessment(
  source: SourceHealth,
  now: number,
): HealthAssessment {
  if (source.expectation === "not_selected")
    return assessment("not_required", "Not selected for this deployment");
  if (source.expectation === "staged")
    return assessment("not_required", "Staged; not expected to collect");
  if (source.expectation === "unknown")
    return assessment("unknown", "Deployment expectation unknown");
  if (source.configuration === "not_configured")
    return assessment("attention", "Selected; not configured");
  if (source.configuration === "unavailable")
    return assessment("unknown", "Source configuration unavailable");
  if (source.status === "unavailable" || source.records === undefined)
    return assessment("unknown", "Unavailable");
  if (source.warning) return assessment("unknown", source.warning);
  if (source.evidence?.includes("configuration")) {
    if (source.records === 0)
      return assessment("attention", "Selected; not configured");
    if (
      ["incomplete", "ambiguous", "unsupported"].includes(source.status ?? "")
    )
      return assessment("attention", "Configuration requires review");
    if (
      source.status !== "visible" ||
      source.mappedRecords === undefined ||
      source.mappingKeys === undefined ||
      source.unmapped === undefined ||
      source.unresolved === undefined
    )
      return assessment("unknown", "Configuration evidence unavailable");
    return source.mappedRecords === source.records &&
      source.mappingKeys === source.records &&
      source.unmapped === 0 &&
      source.unresolved === 0
      ? assessment("healthy", "Configuration observed")
      : assessment("attention", "Configuration requires review");
  }
  if (
    source.status &&
    !["ok", "visible", "no_visible_records"].includes(source.status)
  )
    return assessment("unknown", `Probe status: ${source.status}`);
  const threshold = source.staleAfterSeconds ?? 1200;
  if (
    source.expectation === "active" &&
    (source.probeLookbackSeconds === undefined ||
      source.probeLookbackSeconds < threshold)
  )
    return assessment(
      "unknown",
      source.probeLookbackSeconds === undefined
        ? "Receipt probe coverage unavailable"
        : "Receipt probe window is shorter than expected freshness",
    );
  if (source.latestIndexed && source.records === 0)
    return assessment(
      "unknown",
      "Receipt count and timestamp are inconsistent",
    );
  if (source.quiet && !source.latestIndexed)
    return assessment(
      "unknown",
      "No visible events; collection health unknown",
    );
  if (!source.latestIndexed)
    return source.records === 0
      ? assessment(
          "attention",
          source.probeLookbackSeconds
            ? "No visible data in receipt probe window"
            : "No visible data in 24 hours",
        )
      : assessment("unknown", "Receipt time unavailable");
  if (source.latestIndexed > now + 60)
    return assessment("attention", "Clock is ahead");
  const age = now - source.latestIndexed;
  if (
    source.probeLookbackSeconds !== undefined &&
    age > source.probeLookbackSeconds + 60
  )
    return assessment(
      "unknown",
      "Receipt timestamp is outside the reported probe window",
    );
  if (source.staleAfterSeconds !== undefined)
    return age <= threshold
      ? assessment("healthy", "Data received within expected cadence")
      : source.quiet
        ? assessment("unknown", "Quiet; collection health unknown")
        : assessment("attention", "Expected receipt is overdue");
  return age <= threshold
    ? assessment("healthy", "Data received within 20 minutes")
    : assessment("attention", "No data received in 20 minutes");
}
export const sourceStatus = (source: SourceHealth, now: number): string =>
  sourceAssessment(source, now).label;
export function jobAssessment(job: JobHealth, now: number): HealthAssessment {
  if (job.contractConflict)
    return {
      state: "attention",
      reason: "contract_conflict",
      label:
        "Enabled writer conflicts with the active data contract. Ask an administrator to disable it or complete the reviewed migration.",
    };
  if (job.required === false)
    return assessment("not_required", "Not required for this deployment");
  if (job.disabled === undefined)
    return assessment("unknown", "Configuration unavailable");
  if (job.disabled) return assessment("attention", "Disabled");
  if (job.scheduled === false) return assessment("attention", "Not scheduled");
  if (job.required !== undefined && job.scheduled === undefined)
    return assessment("unknown", "Schedule unavailable");
  return jobRunAssessment(job, now);
}
export function jobRunAssessment(
  job: JobHealth,
  now: number,
): HealthAssessment {
  if (job.required === false)
    return assessment("not_required", "Not required for this deployment");
  if (!job.lastRun) return assessment("unknown", "No visible run in 24 hours");
  if (job.lastRun > now + 60) return assessment("attention", "Clock is ahead");
  if (job.lastStatus !== "success")
    return job.lastStatus
      ? assessment("attention", `Last run: ${job.lastStatus}`)
      : assessment("unknown", "Run outcome unavailable");
  const threshold =
    job.staleAfterSeconds ??
    (job.name.endsWith("prune")
      ? 26 * 3600
      : job.name.endsWith("Interface inventory") ||
          job.name.endsWith("Application catalog") ||
          job.name.endsWith("Application catalog v2")
        ? 2 * 3600
        : 1200);
  if (!job.lastSuccess)
    return assessment("unknown", "Successful run not confirmed");
  if (job.lastSuccess > now + 60)
    return assessment("attention", "Clock is ahead");
  if (job.lastSuccess > job.lastRun)
    return assessment("unknown", "Run timestamps are inconsistent");
  return now - job.lastSuccess > threshold
    ? assessment("attention", "Successful run is overdue")
    : assessment("healthy", "Recent successful run");
}
export const jobStatus = (job: JobHealth, now: number): string =>
  jobAssessment(job, now).label;
export async function loadHealth(
  client: SearchClient,
  signal: AbortSignal,
  deployment?: DeploymentSnapshot,
  scope: "full" | "jobs" = "full",
): Promise<HealthReport> {
  const qualitySourceNames = selectedQualitySources(deployment);
  const qualityRequired =
    !deployment ||
    deployment.state !== "configured" ||
    qualitySourceNames.length > 0;
  const probes = selectedHealthProbes(deployment, scope);
  const results: PromiseSettledResult<RunResult>[] = new Array(probes.length);
  let next = 0;
  const worker = async () => {
    while (!signal.aborted) {
      const index = next++;
      if (index >= probes.length) return;
      const probe = probes[index];
      try {
        results[index] = {
          status: "fulfilled",
          value: await client.search({
            search: `| \`${probe.macro}\``,
            earliest: "-7d",
            latest: "now",
            maxRows: probe.part === "quality" ? 500 : 100,
            signal,
          }),
        };
      } catch (reason) {
        results[index] = { status: "rejected", reason };
      }
    }
  };
  await Promise.all(
    Array.from({ length: Math.min(4, probes.length) }, () => worker()),
  );
  if (signal.aborted) throw new Error("Health check cancelled.");
  const warnings: string[] = [];
  const rows: Record<"sources" | "jobs" | "quality", Row[]> = {
    sources: [],
    jobs: [],
    quality: [],
  };
  results.forEach((result, index) => {
    const probe = probes[index];
    const label = `${probe.id} ${probe.part}`;
    if (result.status === "fulfilled" && result.value.errors.length) {
      warnings.push(
        `${label} health unavailable. ${result.value.errors[0].slice(0, 300)}`,
      );
      return;
    }
    if (result.status === "rejected") {
      warnings.push(
        `${label} health unavailable. ${result.reason instanceof Error ? result.reason.message.slice(0, 300) : "Search failed."}`,
      );
      return;
    }
    warnings.push(
      ...result.value.warnings.map((warning) => `${label}: ${warning}`),
    );
    rows[probe.part].push(...result.value.rows);
  });
  const sources = scope === "jobs" ? [] : sourceRows(rows.sources, deployment);
  const jobs = jobRows(rows.jobs, deployment);
  const qualityInput = rows.quality;
  const selectedQualityRows =
    deployment?.state === "configured"
      ? qualityInput.filter((row) =>
          qualitySourceNames.includes(String(row.source)),
        )
      : qualityInput;
  const evaluations = selectedQualityRows.filter(
    (row) => row.kind === "quality" && row.reason === "evaluated",
  );
  const selectedCoverageMissing =
    deployment?.state === "configured" &&
    SOURCE_DEFINITIONS.some((source) => {
      if (
        !source.selectable ||
        !isCoreSource(source) ||
        expectationFor(deployment, source.id) !== "active"
      )
        return false;
      const names =
        source.qualitySourcesByContract?.[String(deployment.activeContract)] ??
        source.qualitySources;
      return (
        names.length > 0 &&
        !evaluations.some(
          (row) =>
            names.includes(String(row.source)) &&
            count(row.records) !== undefined,
        )
      );
    });
  const selectedEvaluated =
    evaluations.length > 0 &&
    evaluations.every((row) => count(row.records) !== undefined)
      ? evaluations.reduce((total, row) => total + count(row.records)!, 0)
      : undefined;
  const quality = qualityRows(
    deployment?.state === "configured"
      ? [
          ...selectedQualityRows,
          {
            kind: "quality",
            source: "all",
            status: "checked",
            reason: "evaluated",
            records: selectedEvaluated,
          },
        ]
      : selectedQualityRows,
  );
  if (selectedCoverageMissing) quality.incomplete = true;
  if (
    sources.some(
      (s) =>
        (s.expectation === undefined || s.expectation === "active") &&
        s.records === undefined,
    ) ||
    jobs.some(
      (j) =>
        (j.required === undefined || j.required) && j.disabled === undefined,
    ) ||
    (scope === "full" &&
      qualityRequired &&
      (quality.evaluated === undefined || quality.incomplete))
  )
    warnings.push(
      "Some health information is unavailable. Ask an administrator to check index access and visibility of the app's saved searches.",
    );
  return {
    deployment,
    scope,
    sources,
    optionalEvidence: optionalEvidenceRows(deployment),
    jobs,
    quality,
    qualityRequired,
    warnings: [...new Set(warnings)],
    checkedAt: Date.now() / 1000,
  };
}

export const loadHealthJobs = (
  client: SearchClient,
  signal: AbortSignal,
  deployment?: DeploymentSnapshot,
) => loadHealth(client, signal, deployment, "jobs");
