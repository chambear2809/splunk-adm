import { buildApprovedConnectedQuery } from "./approvedConnectedQuery";
import type {
  ConnectedQueryExecutionResult,
  ConnectedQueryTransport,
} from "./connectedServiceQueryExecutor";

export interface OwnedSplunkSearchClient {
  search(input: {
    literal: string;
    earliest: number;
    latest: number;
  }): Promise<{
    rows: Record<string, unknown>[];
    job: { sid: string; dispatchState: "DONE" };
    indexTimeBounds: { earliest: number; latest: number };
    receiptFingerprints: string[];
  }>;
}

/** Adapt an owner-verified Splunk client to the connected query contract. */
export function createSplunkConnectedQueryTransport(
  client: OwnedSplunkSearchClient,
  provenance: { executionId: string; planSha256: string },
): ConnectedQueryTransport {
  return {
    async execute(input): Promise<ConnectedQueryExecutionResult> {
      const approved = await buildApprovedConnectedQuery(input);
      if (approved.literal !== input.literal)
        throw new Error(
          "Connected query literal is not an approved factory output.",
        );
      const result = await client.search({
        literal: approved.literal,
        earliest: input.window.earliest,
        latest: input.window.latest,
      });
      if (
        !result.job ||
        typeof result.job.sid !== "string" ||
        !result.job.sid ||
        result.job.dispatchState !== "DONE" ||
        !Array.isArray(result.rows) ||
        !Array.isArray(result.receiptFingerprints) ||
        !result.receiptFingerprints.length
      )
        throw new Error("Splunk connected query did not complete cleanly.");
      return {
        rows: result.rows,
        complete: true,
        source: "splunk_rest",
        executionId: provenance.executionId,
        planSha256: provenance.planSha256,
        indexTimeBounds: result.indexTimeBounds,
        receiptFingerprints: result.receiptFingerprints,
        queryJob: result.job,
      };
    },
  };
}
