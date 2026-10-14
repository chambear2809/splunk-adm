import SearchJobExport from "@splunk/search-job/SearchJob";
import { username } from "@splunk/splunk-utils/config";
import { getDefaultFetchInit } from "@splunk/splunk-utils/fetch";
import { toolkitDefault } from "../app/interop";
import { splunkWarnings } from "../provider";
import type { Row } from "../rows";

export interface SearchRequest {
  search: string;
  earliest: string;
  latest?: string;
  maxRows: number;
  signal: AbortSignal;
}
export interface RunResult {
  rows: Row[];
  warnings: string[];
}
export interface SearchClient {
  search(request: SearchRequest): Promise<RunResult>;
}

export function timeError(
  earliest: string,
  latest = "now",
): string | undefined {
  const safe = /^(?:now|[+-]\d{1,12}(?:s|m|h|d|w)(?:@[smhdw])?|\d{1,12})$/;
  if (!safe.test(earliest) || !safe.test(latest))
    return "Unsupported time window.";
  if (
    /^\d+$/.test(earliest) &&
    /^\d+$/.test(latest) &&
    Number(earliest) >= Number(latest)
  )
    return "Earliest must precede latest.";
  return undefined;
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

export class ToolkitSearchClient implements SearchClient {
  search(request: SearchRequest): Promise<RunResult> {
    const invalid = timeError(request.earliest, request.latest);
    if (invalid) return Promise.reject(new Error(invalid));
    if (request.signal.aborted)
      return Promise.reject(new Error("Search cancelled."));
    const SearchJob = toolkitDefault(SearchJobExport);
    if (!username)
      return Promise.reject(new Error("Splunk user context is unavailable."));
    SearchJob.setBaseFetchInit(getDefaultFetchInit());
    const job = SearchJob.create(
      {
        search: request.search,
        earliest_time: request.earliest,
        latest_time: request.latest ?? "now",
      },
      { app: "splunk_adm", owner: username, cancelOnUnload: true },
    );
    return new Promise((resolve, reject) => {
      let settled = false;
      let subscription: { unsubscribe(): void } | undefined;
      let progressSubscription: { unsubscribe(): void } | undefined;
      let finalState: unknown;
      const timer = setTimeout(
        () =>
          finish(
            undefined,
            new Error(
              "Search timed out after 120 seconds. Narrow the time range or check that the ADM saved searches are enabled.",
            ),
          ),
        120000,
      );
      const abort = () => finish(undefined, new Error("Search cancelled."));
      const finish = (result?: RunResult, error?: Error) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        request.signal.removeEventListener("abort", abort);
        try {
          subscription?.unsubscribe();
          progressSubscription?.unsubscribe();
        } catch {
          /* toolkit versions differ */
        }
        try {
          const cancellation = job.cancel();
          cancellation?.subscribe?.({
            error: () => {
              /* cancellation is best effort */
            },
          });
        } catch {
          /* toolkit versions differ */
        }
        if (result) resolve(result);
        else reject(error ?? new Error("Search returned no rows."));
      };
      request.signal.addEventListener("abort", abort);
      try {
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
                if (!Array.isArray(results))
                  throw new Error("Search returned invalid results.");
                if (results.length === 0)
                  throw new Error("Search returned no rows.");
                if (results.length > request.maxRows)
                  throw new Error("Search result exceeds the pilot limit.");
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
                if (trueFlag(stateContent?.isFinalized))
                  warnings.push(
                    "Splunk finalized this job before all results were available; the graph may be incomplete.",
                  );
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
                if (count === 0) throw new Error("Search returned no rows.");
                if (count > request.maxRows)
                  throw new Error("Search result exceeds the pilot limit.");
                if (rows.length !== count)
                  throw new Error(
                    "Splunk result count did not match returned rows; results could not be verified.",
                  );
                finish({
                  rows,
                  warnings: [
                    ...new Set([...warnings, ...splunkWarnings(payload)]),
                  ],
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
