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
      validateConnectedQueryEvidence(spec, evidence),
    ).resolves.toEqual(evidence);
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
    ])
      await expect(validateConnectedQueryEvidence(spec, bad)).rejects.toThrow();
  });
});
