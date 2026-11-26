import type { GraphArgs } from "../rows";
import { sha256Hex } from "../changeCorrelation/canonicalJson";
import {
  validateConnectedQueryEvidence,
  type ConnectedQueryEvidence,
  type ConnectedQueryProvenanceContext,
} from "./connectedServiceQueryEvidence";
import {
  CONNECTED_QUERY_KEYS,
  type ConnectedQuerySpec,
} from "./connectedServiceQueryPlan";

const HASH = /^[a-f0-9]{64}$/;

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
   * Execute one literal selected by a trusted query builder and return owned
   * job/readback data. Implementations own dispatch and receipt acquisition;
   * this boundary does not authorize arbitrary SPL or fabricate metadata.
   */
  execute(input: {
    application: GraphArgs;
    key: ConnectedQuerySpec["key"];
    literal: string;
    window: ConnectedQuerySpec["window"];
    findInput?: { field: "service"; value: string };
  }): Promise<ConnectedQueryExecutionResult>;
}

async function validateExecutionInputs(
  spec: ConnectedQuerySpec,
  provenance: ConnectedQueryProvenanceContext,
) {
  if (
    !CONNECTED_QUERY_KEYS.includes(spec.key) ||
    typeof spec.literal !== "string" ||
    !spec.literal ||
    spec.literal.length > 65536 ||
    !HASH.test(spec.sha256) ||
    spec.sha256 !== (await sha256Hex(spec.literal)) ||
    !spec.window ||
    !Number.isSafeInteger(spec.window.earliest) ||
    !Number.isSafeInteger(spec.window.latest) ||
    spec.window.earliest < 0 ||
    spec.window.latest <= spec.window.earliest ||
    !provenance.executionId ||
    !HASH.test(provenance.planSha256) ||
    !Number.isSafeInteger(provenance.indexTimeBounds.earliest) ||
    !Number.isSafeInteger(provenance.indexTimeBounds.latest) ||
    provenance.indexTimeBounds.earliest >= provenance.indexTimeBounds.latest ||
    !provenance.queryJobSid ||
    !provenance.receiptFingerprints.length ||
    !provenance.receiptFingerprints.every((item) => HASH.test(item))
  )
    throw new Error("Connected query execution inputs are invalid.");
}

/** Execute a trusted plan item and validate its independently owned readback. */
export async function executeConnectedQuery(
  spec: ConnectedQuerySpec,
  provenance: ConnectedQueryProvenanceContext,
  transport: ConnectedQueryTransport,
): Promise<ConnectedQueryEvidence> {
  // Capture all caller-owned values before the first await. Hashing and
  // transport are asynchronous; subsequent validation must not observe a
  // caller mutation between those stages.
  const approvedSpec: ConnectedQuerySpec = {
    ...spec,
    application: { ...spec.application },
    window: { ...spec.window },
  };
  const approvedProvenance: ConnectedQueryProvenanceContext = {
    ...provenance,
    indexTimeBounds: { ...provenance.indexTimeBounds },
    receiptFingerprints: [...provenance.receiptFingerprints],
  };
  await validateExecutionInputs(approvedSpec, approvedProvenance);
  const result = await transport.execute({
    // Keep transport-owned mutation separate from the snapshot used below.
    application: { ...approvedSpec.application },
    key: approvedSpec.key,
    literal: approvedSpec.literal,
    window: { ...approvedSpec.window },
    ...(approvedSpec.key === "find.service"
      ? {
          findInput: {
            field: "service" as const,
            value: approvedSpec.application.service,
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
    ...(approvedSpec.key === "find.service"
      ? {
          input: {
            field: "service" as const,
            value: approvedSpec.application.service,
          },
        }
      : { args: approvedSpec.application }),
    window: { ...approvedSpec.window, basis: "source_time" as const },
    query: { literal: approvedSpec.literal, sha256: approvedSpec.sha256 },
    rows: result.rows,
    readback,
  };
  return validateConnectedQueryEvidence(
    approvedSpec,
    evidence,
    approvedProvenance,
  );
}
