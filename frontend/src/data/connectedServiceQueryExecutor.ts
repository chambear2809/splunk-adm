import type { GraphArgs } from "../rows";
import {
  validateConnectedQueryEvidence,
  type ConnectedQueryEvidence,
  type ConnectedQueryProvenanceContext,
} from "./connectedServiceQueryEvidence";
import type { ConnectedQuerySpec } from "./connectedServiceQueryPlan";

export interface ConnectedQueryExecutionResult {
  rows: Record<string, unknown>[];
  complete: true;
  source: "splunk_rest";
  executionId: string;
  planSha256: string;
  indexTimeBounds: { earliest: number; latest: number };
  receiptFingerprints: string[];
  queryJob: Record<string, unknown>;
}

export interface ConnectedQueryTransport {
  /**
   * Execute one already-approved literal and return owned job/readback data.
   * Implementations own dispatch and receipt acquisition; this boundary never
   * accepts caller SPL or fabricates execution metadata.
   */
  execute(input: {
    application: GraphArgs;
    key: ConnectedQuerySpec["key"];
    literal: string;
    window: ConnectedQuerySpec["window"];
    findInput?: { field: "service"; value: string };
  }): Promise<ConnectedQueryExecutionResult>;
}

/** Execute a trusted plan item and validate its independently owned readback. */
export async function executeConnectedQuery(
  spec: ConnectedQuerySpec,
  provenance: ConnectedQueryProvenanceContext,
  transport: ConnectedQueryTransport,
): Promise<ConnectedQueryEvidence> {
  const result = await transport.execute({
    application: spec.application,
    key: spec.key,
    literal: spec.literal,
    window: spec.window,
    ...(spec.key === "find.service"
      ? {
          findInput: {
            field: "service" as const,
            value: spec.application.service,
          },
        }
      : {}),
  });
  const readback = {
    complete: result.complete,
    result_count: result.rows.length,
    source: result.source,
    execution_id: result.executionId,
    plan_sha256: result.planSha256,
    index_time_bounds: result.indexTimeBounds,
    receipt_fingerprints: result.receiptFingerprints,
    query_job: result.queryJob,
  };
  const evidence = {
    status: "complete" as const,
    ...(spec.key === "find.service"
      ? {
          input: {
            field: "service" as const,
            value: spec.application.service,
          },
        }
      : { args: spec.application }),
    window: { ...spec.window, basis: "source_time" as const },
    query: { literal: spec.literal, sha256: spec.sha256 },
    rows: result.rows,
    readback,
  };
  return validateConnectedQueryEvidence(spec, evidence, provenance);
}
