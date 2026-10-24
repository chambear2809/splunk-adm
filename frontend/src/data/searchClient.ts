import SearchJobExport from "@splunk/search-job/SearchJob";
import { username } from "@splunk/splunk-utils/config";
import { getDefaultFetchInit } from "@splunk/splunk-utils/fetch";
import { createRESTURL } from "@splunk/splunk-utils/url";
import { toolkitDefault } from "../app/interop";
import { splunkErrors, splunkWarnings } from "../provider";
import type { Row } from "../rows";
import { timeError } from "./timeBounds";
import { optionalJobs } from "./optionalJobs";
import type { OptionalSource } from "./evidence";
export { timeError } from "./timeBounds";

export interface SearchRequest {
  search: string;
  earliest: string;
  latest?: string;
  timezone?: string;
  maxRows: number;
  /** Catalog and Find may legitimately return zero rows. Graph callers retain strict defaults. */
  allowEmpty?: boolean;
  signal: AbortSignal;
  /** Opt-in bounded investigations; existing callers keep their 120s deadline. */
  budget?: { serverSeconds: number; clientMilliseconds: number };
  onLifecycle?: (event: {
    state:
      | "creating"
      | "created"
      | "cleanup_pending"
      | "cleanup_unverified"
      | "released";
    sid?: string;
  }) => void;
  optionalSource?: OptionalSource;
}
export interface RunResult {
  rows: Row[];
  warnings: string[];
  /** ERROR/FATAL job messages; callers that require complete results reject these. */
  errors: string[];
}
export interface SearchClient {
  search(request: SearchRequest): Promise<RunResult>;
}

/** Fail closed when Splunk reported ERROR or FATAL job messages. */
export function requireNoSearchErrors(
  result: RunResult,
  label: string,
): RunResult {
  if (result.errors.length)
    throw new Error(`${label} was incomplete: ${result.errors[0]}`);
  return result;
}

export class SearchResultLimitError extends Error {
  readonly maxRows: number;

  constructor(maxRows: number) {
    super(
      `Search returned more than ${maxRows.toLocaleString()} rows. Narrow the scope or time range and try again.`,
    );
    this.name = "SearchResultLimitError";
    this.maxRows = maxRows;
  }
}

const errorDetail = (base: string, payload: unknown) => {
  const message = splunkWarnings(payload)[0];
  return new Error(message ? `${base} Splunk reported: ${message}` : base);
};
const trueFlag = (value: unknown) =>
  value === true ||
  value === 1 ||
  value === "1" ||
  (typeof value === "string" && value.toLowerCase() === "true");
const finiteCount = (value: unknown) => {
  const n = typeof value === "number" ? value : Number(value);
  return Number.isFinite(n) && n >= 0 ? n : undefined;
};
const searchMetadata = (value: unknown): Record<string, unknown>[] => {
  if (!value || typeof value !== "object") return [];
  const root = value as Record<string, unknown>;
  const content = root.content;
  return [
    root,
    ...(content && typeof content === "object"
      ? [content as Record<string, unknown>]
      : []),
  ];
};
export const incompleteSearchError = (value: unknown) => {
  const metadata = searchMetadata(value);
  if (
    metadata.some(
      (m) => m.isDone === false || m.isDone === 0 || m.isDone === "0",
    )
  )
    return "Splunk search had not finished; results could be incomplete.";
  if (
    metadata.some(
      (m) =>
        typeof m.dispatchState === "string" &&
        !["DONE", "FAILED"].includes(m.dispatchState.toUpperCase()),
    )
  )
    return "Splunk search had not reached a complete state; results could be incomplete.";
  if (metadata.some((m) => trueFlag(m.isFinalized)))
    return "Splunk finalized this job before all results were available; results could be incomplete.";
  if (
    metadata.some(
      (m) => trueFlag(m.resultIsTruncated) || trueFlag(m.eventIsTruncated),
    )
  )
    return "Splunk truncated this search; results could be incomplete.";
  if (
    metadata.some((m) => {
      if (m.dropCount === undefined || m.dropCount === null) return false;
      const count = finiteCount(m.dropCount);
      return count === undefined || count > 0;
    })
  )
    return "Splunk dropped or could not verify search events; results could be incomplete.";
  return undefined;
};

export class ToolkitSearchClient implements SearchClient {
  search(request: SearchRequest): Promise<RunResult> {
    if (
      request.budget &&
      (!Number.isInteger(request.budget.serverSeconds) ||
        request.budget.serverSeconds < 1 ||
        request.budget.serverSeconds > 30 ||
        !Number.isInteger(request.budget.clientMilliseconds) ||
        request.budget.clientMilliseconds <
          request.budget.serverSeconds * 1000 ||
        request.budget.clientMilliseconds > 35000)
    )
      return Promise.reject(
        new Error("Invalid investigation execution budget."),
      );
    const invalid = timeError(
      request.earliest,
      request.latest,
      request.timezone,
    );
    if (invalid) return Promise.reject(new Error(invalid));
    if (request.signal.aborted)
      return Promise.reject(new Error("Search cancelled."));
    const SearchJob = toolkitDefault(SearchJobExport);
    if (!username)
      return Promise.reject(new Error("Splunk user context is unavailable."));
    SearchJob.setBaseFetchInit(getDefaultFetchInit());
    request.onLifecycle?.({ state: "creating" });
    let job: ReturnType<typeof SearchJob.create>;
    if (!request.optionalSource) optionalJobs.coreStarted();
    try {
      job = SearchJob.create(
        {
          search: request.search,
          earliest_time: request.earliest,
          latest_time: request.latest ?? "now",
          ...(request.budget
            ? {
                max_time: String(request.budget.serverSeconds),
                auto_cancel: String(request.budget.serverSeconds),
                auto_pause: "0",
                status_buckets: "0",
              }
            : {}),
        },
        { app: "splunk_adm", owner: username, cancelOnUnload: true },
      );
    } catch {
      if (!request.optionalSource) optionalJobs.coreFinished();
      // The SDK threw before a job handle or SID existed. Native creation is
      // untrackable, so report uncertainty and retain browser admission.
      request.onLifecycle?.({ state: "cleanup_unverified" });
      return Promise.reject(
        new Error("Splunk job creation could not be acknowledged."),
      );
    }
    return new Promise((resolve, reject) => {
      let settled = false;
      let subscription: { unsubscribe(): void } | undefined;
      let progressSubscription: { unsubscribe(): void } | undefined;
      let finalState: unknown;
      let sid: string | undefined;
      let released = false;
      let cleanupChecks = 0;
      let cleanupTimer: ReturnType<typeof setTimeout> | undefined;
      let cleanupCheckInFlight = false;
      let unverifiedReported = false;
      let sidGraceTimer: ReturnType<typeof setTimeout> | undefined;
      let sidSubscription: { unsubscribe(): void } | undefined;
      const release = () => {
        if (released) return;
        released = true;
        sidSubscription?.unsubscribe();
        if (cleanupTimer) clearTimeout(cleanupTimer);
        if (sidGraceTimer) clearTimeout(sidGraceTimer);
        request.onLifecycle?.({ state: "released", sid });
      };
      // Server-side cleanup could not be confirmed. Keep the native lease
      // occupied until a late cancellation or terminal status is acknowledged.
      const reportUnverified = () => {
        if (released || unverifiedReported) return;
        unverifiedReported = true;
        if (cleanupTimer) clearTimeout(cleanupTimer);
        if (sidGraceTimer) clearTimeout(sidGraceTimer);
        request.onLifecycle?.({ state: "cleanup_unverified", sid });
      };
      const verifyCleanup = async () => {
        if (cleanupTimer) {
          clearTimeout(cleanupTimer);
          cleanupTimer = undefined;
        }
        if (released || !request.budget || !sid || cleanupCheckInFlight) return;
        if (cleanupChecks >= 12) {
          reportUnverified();
          return;
        }
        cleanupCheckInFlight = true;
        cleanupChecks++;
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 3000);
        try {
          const response = await fetch(
            createRESTURL(
              `search/jobs/${encodeURIComponent(sid)}?output_mode=json`,
              { app: "splunk_adm", owner: username },
            ),
            { ...getDefaultFetchInit(), signal: controller.signal },
          );
          if (response.status === 404 || response.status === 410) {
            release();
            return;
          }
          if (response.ok) {
            const value = (await response.json()) as {
              entry?: { content?: Record<string, unknown> }[];
            };
            const native =
              value.entry?.length === 1 ? value.entry[0].content : undefined;
            if (
              trueFlag(native?.isDone) ||
              trueFlag(native?.isFailed) ||
              trueFlag(native?.isFinalized)
            ) {
              release();
              return;
            }
          }
        } catch {
          /* retain the native lease when status is unknown */
        } finally {
          clearTimeout(timeout);
          cleanupCheckInFlight = false;
        }
        if (released || cleanupTimer) return;
        if (cleanupChecks >= 12) {
          reportUnverified();
          return;
        }
        cleanupTimer = setTimeout(() => {
          cleanupTimer = undefined;
          void verifyCleanup();
        }, 5000);
      };
      const timer = setTimeout(
        () =>
          finish(
            undefined,
            new Error(
              request.budget
                ? "Investigation deadline exceeded. Cleanup is pending until Splunk confirms cancellation."
                : "Search timed out after 120 seconds. Narrow the time range or check that the ADM saved searches are enabled.",
            ),
          ),
        request.budget?.clientMilliseconds ?? 120000,
      );
      const abort = () => finish(undefined, new Error("Search cancelled."));
      const finish = (result?: RunResult, error?: Error) => {
        if (settled) return;
        settled = true;
        if (!request.optionalSource) optionalJobs.coreFinished();
        clearTimeout(timer);
        request.signal.removeEventListener("abort", abort);
        try {
          subscription?.unsubscribe();
          progressSubscription?.unsubscribe();
        } catch {
          /* toolkit versions differ */
        }
        try {
          const native = (
            finalState as { content?: Record<string, unknown> } | undefined
          )?.content;
          if (trueFlag(native?.isDone) || trueFlag(native?.isFailed)) release();
          if (!released)
            request.onLifecycle?.({ state: "cleanup_pending", sid });
          const cancellation = job.cancel();
          cancellation?.subscribe?.({
            next: () => release(),
            error: () => {
              void verifyCleanup();
            },
          });
          // Cancellation observables can remain open without emitting or failing.
          // Independently verify the known SID, retaining the lease until native
          // status is terminal, deleted, or cancellation is acknowledged.
          void verifyCleanup();
        } catch {
          void verifyCleanup();
        }
        if (!sid && !released && request.budget && !sidGraceTimer)
          sidGraceTimer = setTimeout(reportUnverified, 60000);
        if (result) resolve(result);
        else reject(error ?? new Error("Search returned no rows."));
      };
      request.signal.addEventListener("abort", abort);
      // Keep this acknowledgement subscription alive during uncertain creation.
      // A late SID still permits the already requested native cancellation.
      const subscribeSid = () => {
        sidSubscription = job.getSid?.().subscribe({
          next: (value: unknown) => {
            if (typeof value === "string" && value) {
              sid = value;
              if (sidGraceTimer) {
                clearTimeout(sidGraceTimer);
                sidGraceTimer = undefined;
              }
              request.onLifecycle?.({ state: "created", sid });
              if (settled && !released) void verifyCleanup();
            }
          },
          error: () => {
            // Native creation rejection is observed by progress/results as well.
            // Never surface it as an unhandled RxJS error or infer unknown creation cleanup.
          },
        });
        if (released) sidSubscription?.unsubscribe();
      };
      try {
        subscribeSid();
        if (settled) return;
        progressSubscription = job.getProgress().subscribe({
          next: (state: unknown) => {
            finalState = state;
            const content = (
              state as { content?: Record<string, unknown> } | undefined
            )?.content;
            const dispatchState = content?.dispatchState;
            if (
              trueFlag(content?.isFailed) ||
              (typeof dispatchState === "string" &&
                dispatchState.toUpperCase() === "FAILED")
            )
              finish(
                undefined,
                errorDetail("Splunk could not complete the search.", state),
              );
          },
          error: (error: unknown) =>
            finish(
              undefined,
              errorDetail(
                "Splunk search failed. Check index access and search permissions.",
                error,
              ),
            ),
        });
        if (settled) {
          progressSubscription.unsubscribe();
          return;
        }
        subscription = job
          .getResults({ count: request.maxRows + 1, output_mode: "json" })
          .subscribe({
            next: (payload: unknown) => {
              try {
                const results = (payload as { results?: unknown } | null)
                  ?.results;
                const incomplete =
                  incompleteSearchError(finalState) ??
                  incompleteSearchError(payload);
                if (incomplete) throw new Error(incomplete);
                if (!Array.isArray(results))
                  throw new Error("Search returned invalid results.");
                if (results.length === 0 && !request.allowEmpty)
                  throw new Error("Search returned no rows.");
                if (results.length > request.maxRows)
                  throw new SearchResultLimitError(request.maxRows);
                if (
                  !results.every(
                    (row) =>
                      row && typeof row === "object" && !Array.isArray(row),
                  )
                )
                  throw new Error("Search returned an invalid row.");
                const rows = results as Row[];
                const stateContent = (
                  finalState as
                    { content?: Record<string, unknown> } | undefined
                )?.content;
                const warnings = splunkWarnings(finalState);
                const rawCount = stateContent?.resultCount;
                const count =
                  typeof rawCount === "number"
                    ? rawCount
                    : typeof rawCount === "string" &&
                        /^\d+$/.test(rawCount.trim())
                      ? Number(rawCount)
                      : NaN;
                if (!Number.isSafeInteger(count) || count < 0)
                  throw new Error(
                    "Splunk did not report a valid final result count; results could not be verified.",
                  );
                if (count === 0 && !request.allowEmpty)
                  throw new Error("Search returned no rows.");
                if (count > request.maxRows)
                  throw new SearchResultLimitError(request.maxRows);
                if (rows.length !== count)
                  throw new Error(
                    "Splunk result count did not match returned rows; results could not be verified.",
                  );
                const errors = [
                  ...new Set([
                    ...splunkErrors(finalState),
                    ...splunkErrors(payload),
                  ]),
                ];
                finish({
                  rows,
                  warnings: [
                    ...new Set([...warnings, ...splunkWarnings(payload)]),
                  ],
                  errors,
                });
              } catch (error) {
                finish(
                  undefined,
                  error instanceof Error
                    ? error
                    : new Error("Invalid search result."),
                );
              }
            },
            error: (error: unknown) =>
              finish(
                undefined,
                errorDetail(
                  "Splunk search failed. Check index access and search permissions.",
                  error,
                ),
              ),
          });
        if (settled) subscription.unsubscribe();
      } catch (error) {
        finish(
          undefined,
          error instanceof Error ? error : new Error("Splunk search failed."),
        );
      }
    });
  }
}

export const createSearchClient = (): SearchClient => new ToolkitSearchClient();
export const jobClient: SearchClient = createSearchClient();
