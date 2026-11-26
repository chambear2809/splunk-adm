import { getDefaultFetchInit } from "@splunk/splunk-utils/fetch";
import { createRESTURL } from "@splunk/splunk-utils/url";
import type { SearchClient } from "./searchClient";
import type { Row } from "../rows";

export interface ModifiedVendorTaTarget {
  app: string;
  input: string;
  official: string;
}

export const MODIFIED_VENDOR_TA_TARGETS: readonly ModifiedVendorTaTarget[] = [
  {
    app: "cisco_dc_networking_app_for_splunk",
    input: "atlas_aci_snapshot",
    official: "Cisco DC Networking 2.0.10 (Splunkbase 7777)",
  },
  {
    app: "Splunk_TA_AppDynamics",
    input: "atlas_appdynamics_inventory",
    official: "Splunk Add-on for AppDynamics 3.3.0 (Splunkbase 3471)",
  },
];

export interface ModifiedVendorTaFinding {
  app: string;
  input: string;
  official: string;
  evidence: "installed_input" | "indexed_events";
  detail?: string;
}

export interface ModifiedVendorTaReport {
  findings: ModifiedVendorTaFinding[];
  unavailable: string[];
}

type FetchLike = (
  input: string,
  init?: RequestInit,
) => Promise<{ ok: boolean; status: number }>;

export async function checkInstalledModifiedVendorTas(
  signal?: AbortSignal,
  fetcher: FetchLike = fetch,
): Promise<ModifiedVendorTaReport> {
  const findings: ModifiedVendorTaFinding[] = [];
  const unavailable: string[] = [];
  await Promise.all(
    MODIFIED_VENDOR_TA_TARGETS.map(async (target) => {
      const url = `${createRESTURL(`configs/conf-inputs/${encodeURIComponent(target.input)}`, { app: target.app, owner: "nobody" })}?output_mode=json`;
      try {
        const res = await fetcher(url, {
          ...getDefaultFetchInit(),
          method: "GET",
          signal,
        });
        if (res.ok) {
          findings.push({
            ...target,
            evidence: "installed_input",
          });
        } else if (res.status !== 404) {
          unavailable.push(`${target.app} (HTTP ${res.status})`);
        }
      } catch (err) {
        if (signal?.aborted) return;
        const msg = err instanceof Error ? err.message : "unavailable";
        unavailable.push(`${target.app} (${msg})`);
      }
    }),
  );
  return { findings, unavailable };
}

function asString(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

export function parseModifiedVendorTaSearchRows(
  rows: readonly Row[],
): ModifiedVendorTaFinding[] {
  const findings: ModifiedVendorTaFinding[] = [];
  for (const row of rows) {
    if (asString(row.kind) !== "modified_vendor_ta") continue;
    const records = Number(row.records ?? 0);
    if (!Number.isFinite(records) || records <= 0) continue;
    const app = asString(row.app);
    const input = asString(row.input);
    const official = asString(row.official_ta);
    if (!app || !input || !official) continue;
    const tag = asString(row.sourcetype) || asString(row.source);
    findings.push({
      app,
      input,
      official,
      evidence: "indexed_events",
      detail: `${records} event${records === 1 ? "" : "s"}${tag ? ` (${tag})` : ""}`,
    });
  }
  return findings;
}

export function mergeModifiedVendorTaReports(
  ...reports: readonly ModifiedVendorTaReport[]
): ModifiedVendorTaReport {
  const seen = new Set<string>();
  const findings: ModifiedVendorTaFinding[] = [];
  const unavailable = new Set<string>();
  for (const report of reports) {
    for (const finding of report.findings) {
      const key = `${finding.app}|${finding.input}|${finding.evidence}|${finding.detail ?? ""}`;
      if (seen.has(key)) continue;
      seen.add(key);
      findings.push(finding);
    }
    for (const item of report.unavailable) unavailable.add(item);
  }
  return { findings, unavailable: [...unavailable] };
}

export async function loadModifiedVendorTaReport(
  client?: SearchClient,
  signal?: AbortSignal,
  fetcher: FetchLike = fetch,
): Promise<ModifiedVendorTaReport> {
  const restPromise = checkInstalledModifiedVendorTas(signal, fetcher);
  const searchPromise: Promise<ModifiedVendorTaReport> = client
    ? client
        .search({
          search: "`adm_health_modified_vendor_tas`",
          earliest: "-7d",
          latest: "now",
          maxRows: 20,
          allowEmpty: true,
          signal: signal ?? new AbortController().signal,
        })
        .then((res) => ({
          findings: parseModifiedVendorTaSearchRows(res.rows),
          unavailable:
            res.errors.length > 0
              ? [`indexed-event probe (${res.errors[0]})`]
              : [],
        }))
        .catch(() => ({
          findings: [],
          unavailable: signal?.aborted ? [] : ["indexed-event probe"],
        }))
    : Promise.resolve({ findings: [], unavailable: [] });
  const [rest, indexed] = await Promise.all([restPromise, searchPromise]);
  return mergeModifiedVendorTaReports(rest, indexed);
}
