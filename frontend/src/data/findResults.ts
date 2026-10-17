import type { RunResult } from "./searchClient";

export interface SettledFindResults {
  applications?: RunResult;
  networkClients?: RunResult;
  applicationError?: string;
  networkClientError?: string;
}

const reasonText = (reason: unknown) =>
  reason instanceof Error && reason.message ? reason.message : "Search failed.";

/** Preserve each Find source independently when one search fails. */
export function settledFindResults(
  application: PromiseSettledResult<RunResult>,
  networkClients?: PromiseSettledResult<RunResult>,
): SettledFindResults {
  const result: SettledFindResults =
    application.status === "fulfilled"
      ? { applications: application.value }
      : {
          applicationError: `Application Find unavailable: ${reasonText(application.reason)}`,
        };

  if (networkClients?.status === "fulfilled")
    result.networkClients = networkClients.value;
  else if (networkClients?.status === "rejected")
    result.networkClientError = `Network-client Find unavailable: ${reasonText(networkClients.reason)}`;

  return result;
}
