import type { SearchClient } from "../data/searchClient";
import {
  canonicalIp,
  evaluate,
  isScope,
  livenessCandidates,
  MAX_RUN_ASSERTIONS,
  parseObservations,
  windowErrors,
  windowIssues,
  type Assertion,
  type ChangeWindows,
  type TimeWindow,
  type Verdict,
  type WindowEvidence,
} from "./model";

/** adm_path_trace_observer_limit (200) plus at most 32 qualified NetFlow rows. */
export const TRACE_MAX_ROWS = 240;

export function traceSearch(src: string, dst: string, scope: string): string {
  if (canonicalIp(src) !== src || canonicalIp(dst) !== dst || !isScope(scope))
    throw new Error(
      "Verification needs two IP literals and a mapped routing scope.",
    );
  return `| \`adm_path_trace(${src},${dst},${scope})\` | where row_type="observation"`;
}

export function livenessSearch(device: string): string {
  if (!/^[A-Za-z0-9_.:/-]{1,128}$/.test(device))
    throw new Error("Invalid observer for liveness.");
  return `| \`adm_device_flows(${device})\` | head 1`;
}

export interface WindowRun extends WindowEvidence {
  window: TimeWindow;
  spl: string;
}

export interface AssertionResult {
  assertion: Assertion;
  verdict: Verdict;
  before: WindowRun;
  after: WindowRun;
  /** Observer keys probed for liveness in the after window and the outcome. */
  liveness: { observer: string; live: boolean | undefined }[];
}

export interface VerificationRun {
  windows: ChangeWindows;
  generated: string;
  results: AssertionResult[];
}

const bound = (w: TimeWindow) => ({
  earliest: String(Math.floor(w.start)),
  latest: String(Math.floor(w.end)),
});

async function traceWindow(
  client: SearchClient,
  a: Assertion,
  window: TimeWindow,
  now: number,
  signal: AbortSignal,
): Promise<WindowRun> {
  const spl = traceSearch(a.src, a.dst, a.scope);
  const issues = windowIssues(window, now);
  try {
    const result = await client.search({
      search: spl,
      ...bound(window),
      maxRows: TRACE_MAX_ROWS,
      overflow: "error",
      allowEmpty: true,
      signal,
    });
    const parsed = parseObservations(result.rows);
    return {
      window,
      spl,
      observations: parsed.observations,
      issues: [
        ...issues,
        ...result.errors.map((e) => `Search error: ${e}`),
        ...result.warnings.slice(0, 3).map((w) => `Search warning: ${w}`),
        ...(result.truncated ? ["Search results were truncated."] : []),
        ...parsed.issues,
      ],
    };
  } catch (error) {
    if (signal.aborted) throw error;
    return {
      window,
      spl,
      observations: [],
      issues: [
        ...issues,
        `Search did not complete: ${error instanceof Error ? error.message : "unknown error"}`,
      ],
    };
  }
}

async function isLive(
  client: SearchClient,
  device: string,
  window: TimeWindow,
  signal: AbortSignal,
): Promise<boolean | undefined> {
  try {
    const result = await client.search({
      search: livenessSearch(device),
      ...bound(window),
      maxRows: 1,
      overflow: "truncate",
      allowEmpty: true,
      signal,
    });
    if (result.errors.length) return undefined;
    return result.rows.length > 0 ? true : undefined;
  } catch (error) {
    if (signal.aborted) throw error;
    return undefined;
  }
}

/** Runs each assertion sequentially, as the caller, over both windows. */
export async function runVerification(
  client: SearchClient,
  assertions: Assertion[],
  windows: ChangeWindows,
  signal: AbortSignal,
  now = Date.now() / 1000,
  onProgress?: (done: number, total: number) => void,
): Promise<VerificationRun> {
  const errors = windowErrors(windows);
  if (errors.length) throw new Error(errors[0]);
  if (!assertions.length) throw new Error("Pick at least one assertion.");
  if (assertions.length > MAX_RUN_ASSERTIONS)
    throw new Error(`Verify at most ${MAX_RUN_ASSERTIONS} assertions per run.`);
  const traces = new Map<string, Promise<WindowRun>>();
  const probes = new Map<string, Promise<boolean | undefined>>();
  const trace = (a: Assertion, w: TimeWindow) => {
    const k = JSON.stringify([a.src, a.dst, a.scope, w.start, w.end]);
    if (!traces.has(k)) traces.set(k, traceWindow(client, a, w, now, signal));
    return traces.get(k)!;
  };
  const results: AssertionResult[] = [];
  for (const assertion of assertions) {
    const before = await trace(assertion, windows.before);
    const after = await trace(assertion, windows.after);
    const candidates = livenessCandidates(assertion, before, after) ?? [];
    const liveness: AssertionResult["liveness"] = [];
    for (const observer of candidates) {
      const device = observer.slice(observer.indexOf(":") + 1);
      if (!probes.has(device))
        probes.set(device, isLive(client, device, windows.after, signal));
      liveness.push({ observer, live: await probes.get(device)! });
    }
    const live = new Set(liveness.filter((l) => l.live).map((l) => l.observer));
    results.push({
      assertion,
      verdict: evaluate(assertion, before, after, live),
      before,
      after,
      liveness,
    });
    onProgress?.(results.length, assertions.length);
  }
  return { windows, generated: new Date(now * 1000).toISOString(), results };
}
