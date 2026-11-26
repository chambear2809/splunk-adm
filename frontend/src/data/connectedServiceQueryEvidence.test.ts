import { describe, expect, it } from "vitest";
import { sha256Hex } from "../changeCorrelation/canonicalJson";
import { buildConnectedQueryPlan } from "./connectedServiceQueryPlan";
import { validateConnectedQueryEvidence } from "./connectedServiceQueryEvidence";

const application = {
  service: "inventory",
  environment: "demo",
  cluster: "c",
  namespace: "shop",
};
const windows = {
  baseline: { earliest: 100, latest: 200 },
  change: { earliest: 200, latest: 300 },
  impact: { earliest: 300, latest: 400 },
  recovery: { earliest: 400, latest: 500 },
};
const provenance = {
  executionId: "exec",
  planSha256: "a".repeat(64),
  indexTimeBounds: { earliest: 100, latest: 500 },
  receiptFingerprints: ["b".repeat(64)],
  queryJobSid: "sid",
};

describe("connected query evidence", () => {
  it("accepts exact planned evidence with independent readback proof", async () => {
    const plan = await buildConnectedQueryPlan(
      [application, { ...application, service: "pricing" }],
      windows,
      async ({ key }) => {
        const literal = `| makeresults | eval key="${key}"`;
        return { literal, sha256: await sha256Hex(literal) };
      },
    );
    const spec = plan.find(({ key }) => key === "graph.impact")!;
    const evidence = {
      status: "complete",
      args: application,
      window: { ...spec.window, basis: "source_time" },
      query: { literal: spec.literal, sha256: spec.sha256 },
      rows: [],
      readback: {
        complete: true,
        result_count: 0,
        source: "splunk_rest",
        execution_id: "exec",
        plan_sha256: "a".repeat(64),
        index_time_bounds: { earliest: 100, latest: 500 },
        receipt_fingerprints: ["b".repeat(64)],
        query_job: { sid: "sid" },
      },
    };
    await expect(
      validateConnectedQueryEvidence(spec, evidence, provenance),
    ).resolves.toEqual(evidence);
    const findSpec = plan.find(({ key }) => key === "find.service")!;
    const findEvidence = {
      ...evidence,
      input: { field: "service" as const, value: application.service },
      query: { literal: findSpec.literal, sha256: findSpec.sha256 },
    } as Record<string, unknown>;
    delete findEvidence.args;
    await expect(
      validateConnectedQueryEvidence(findSpec, findEvidence, provenance),
    ).resolves.toBeDefined();
  });

  it("rejects scope, window, query, and readback tampering", async () => {
    const plan = await buildConnectedQueryPlan(
      [application, { ...application, service: "pricing" }],
      windows,
      async ({ key }) => {
        const literal = `| makeresults | eval key="${key}"`;
        return { literal, sha256: await sha256Hex(literal) };
      },
    );
    const spec = plan[0];
    const base = {
      status: "complete",
      args: application,
      window: { ...spec.window, basis: "source_time" },
      query: { literal: spec.literal, sha256: spec.sha256 },
      rows: [],
      readback: {
        complete: true,
        result_count: 0,
        source: "splunk_rest",
        execution_id: "exec",
        plan_sha256: "a".repeat(64),
        index_time_bounds: { earliest: 100, latest: 500 },
        receipt_fingerprints: ["b".repeat(64)],
        query_job: { sid: "sid" },
      },
    };
    for (const bad of [
      { ...base, args: { ...application, service: "foreign" } },
      { ...base, window: { earliest: 0, latest: 1, basis: "source_time" } },
      { ...base, query: { ...base.query, literal: "| makeresults" } },
      { ...base, readback: { ...base.readback, query_job: undefined } },
      {
        ...base,
        readback: { ...base.readback, execution_id: "other-run" },
      },
      {
        ...base,
        readback: {
          ...base.readback,
          index_time_bounds: { earliest: 500, latest: 100 },
        },
      },
      {
        ...base,
        readback: { ...base.readback, query_job: { sid: "" } },
      },
    ])
      await expect(
        validateConnectedQueryEvidence(spec, bad, provenance),
      ).rejects.toThrow();

    const findSpec = plan.find(({ key }) => key === "find.service")!;
    const findEvidence = {
      ...base,
      input: { field: "service" as const, value: "foreign" },
      query: { literal: findSpec.literal, sha256: findSpec.sha256 },
    } as Record<string, unknown>;
    delete findEvidence.args;
    await expect(
      validateConnectedQueryEvidence(findSpec, findEvidence, provenance),
    ).rejects.toThrow();
  });
});
