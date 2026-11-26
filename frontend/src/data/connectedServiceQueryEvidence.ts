import { canonicalJson, sha256Hex } from "../changeCorrelation/canonicalJson";
import type { GraphArgs } from "../rows";
import type { ConnectedQuerySpec } from "./connectedServiceQueryPlan";

export interface ConnectedQueryEvidence {
  status: "complete";
  args?: GraphArgs;
  input?: { field: "service"; value: string };
  window: { earliest: number; latest: number; basis: "source_time" };
  query: { literal: string; sha256: string };
  rows: Record<string, unknown>[];
  readback: {
    complete: true;
    result_count: number;
    source: "splunk_rest";
    execution_id: string;
    plan_sha256: string;
    index_time_bounds: { earliest: number; latest: number };
    receipt_fingerprints: string[];
    query_job: Record<string, unknown>;
  };
}

export interface ConnectedQueryProvenanceContext {
  executionId: string;
  planSha256: string;
  indexTimeBounds: { earliest: number; latest: number };
  receiptFingerprints: readonly string[];
  queryJobSid: string;
}

const HASH = /^[a-f0-9]{64}$/;

function exactKeys(
  value: Record<string, unknown>,
  keys: readonly string[],
  label: string,
) {
  if (Object.keys(value).sort().join(",") !== [...keys].sort().join(","))
    throw new Error(`Connected query ${label} has unsupported fields.`);
}

function sameArgs(left: GraphArgs, right: GraphArgs) {
  return canonicalJson(left) === canonicalJson(right);
}

/**
 * Validate installed evidence against a plan and trusted run context. The
 * context must come from the execution owner; this validator does not
 * authenticate the caller or dispatch SPL.
 */
export async function validateConnectedQueryEvidence(
  spec: ConnectedQuerySpec,
  value: unknown,
  provenance: ConnectedQueryProvenanceContext,
): Promise<ConnectedQueryEvidence> {
  if (!value || typeof value !== "object" || Array.isArray(value))
    throw new Error("Connected query evidence is invalid.");
  if (
    !provenance.executionId ||
    !HASH.test(provenance.planSha256) ||
    !Number.isSafeInteger(provenance.indexTimeBounds.earliest) ||
    !Number.isSafeInteger(provenance.indexTimeBounds.latest) ||
    provenance.indexTimeBounds.earliest >= provenance.indexTimeBounds.latest ||
    !provenance.queryJobSid ||
    !provenance.receiptFingerprints.length ||
    !provenance.receiptFingerprints.every((item) => HASH.test(item))
  )
    throw new Error("Connected query provenance context is invalid.");
  const evidence = value as Record<string, unknown>;
  const isFind = spec.key === "find.service";
  exactKeys(
    evidence,
    [
      "status",
      ...(isFind ? ["input"] : ["args"]),
      "window",
      "query",
      "rows",
      "readback",
    ],
    "evidence",
  );
  if (
    evidence.status !== "complete" ||
    (isFind
      ? evidence.args !== undefined ||
        !evidence.input ||
        (evidence.input as Record<string, unknown>).field !== "service" ||
        (evidence.input as Record<string, unknown>).value !==
          spec.application.service
      : !sameArgs(evidence.args as GraphArgs, spec.application))
  )
    throw new Error("Connected query evidence is not complete or scope-bound.");
  const window = evidence.window as Record<string, unknown>;
  exactKeys(window, ["earliest", "latest", "basis"], "window");
  if (
    window.basis !== "source_time" ||
    window.earliest !== spec.window.earliest ||
    window.latest !== spec.window.latest
  )
    throw new Error("Connected query evidence window differs from its plan.");
  const query = evidence.query as Record<string, unknown>;
  exactKeys(query, ["literal", "sha256"], "query");
  if (
    typeof query.literal !== "string" ||
    query.sha256 !== (await sha256Hex(query.literal)) ||
    query.sha256 !== spec.sha256
  )
    throw new Error("Connected query evidence literal differs from its plan.");
  if (
    !Array.isArray(evidence.rows) ||
    !evidence.rows.every(
      (row) => row && typeof row === "object" && !Array.isArray(row),
    )
  )
    throw new Error("Connected query evidence rows are invalid.");
  const readback = evidence.readback as Record<string, unknown>;
  exactKeys(
    readback,
    [
      "complete",
      "result_count",
      "source",
      "execution_id",
      "plan_sha256",
      "index_time_bounds",
      "receipt_fingerprints",
      "query_job",
    ],
    "readback",
  );
  if (
    readback.complete !== true ||
    readback.result_count !== (evidence.rows as unknown[]).length ||
    readback.source !== "splunk_rest" ||
    readback.execution_id !== provenance.executionId ||
    readback.plan_sha256 !== provenance.planSha256 ||
    !readback.index_time_bounds ||
    typeof readback.index_time_bounds !== "object" ||
    Array.isArray(readback.index_time_bounds) ||
    !Number.isSafeInteger(
      (readback.index_time_bounds as Record<string, unknown>).earliest,
    ) ||
    !Number.isSafeInteger(
      (readback.index_time_bounds as Record<string, unknown>).latest,
    ) ||
    (readback.index_time_bounds as Record<string, number>).earliest >=
      (readback.index_time_bounds as Record<string, number>).latest ||
    (readback.index_time_bounds as Record<string, number>).earliest >
      provenance.indexTimeBounds.earliest ||
    (readback.index_time_bounds as Record<string, number>).latest <
      provenance.indexTimeBounds.latest ||
    !readback.query_job ||
    typeof readback.query_job !== "object" ||
    Array.isArray(readback.query_job) ||
    typeof (readback.query_job as Record<string, unknown>).sid !== "string" ||
    !(readback.query_job as Record<string, unknown>).sid ||
    (readback.query_job as Record<string, unknown>).sid !==
      provenance.queryJobSid ||
    !Array.isArray(readback.receipt_fingerprints) ||
    !readback.receipt_fingerprints.length ||
    !readback.receipt_fingerprints.every(
      (item) => typeof item === "string" && HASH.test(item),
    ) ||
    canonicalJson(readback.receipt_fingerprints) !==
      canonicalJson(provenance.receiptFingerprints)
  )
    throw new Error("Connected query evidence readback is incomplete.");
  return evidence as unknown as ConnectedQueryEvidence;
}
