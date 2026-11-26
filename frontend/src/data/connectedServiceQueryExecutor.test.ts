import { describe, expect, it, vi } from "vitest";
import { sha256Hex } from "../changeCorrelation/canonicalJson";
import { buildConnectedQueryPlan } from "./connectedServiceQueryPlan";
import { executeConnectedQuery } from "./connectedServiceQueryExecutor";

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

async function plan() {
  return buildConnectedQueryPlan(
    [application, { ...application, service: "pricing" }],
    windows,
    async ({ key }) => {
      const literal = `| makeresults | eval key="${key}"`;
      return { literal, sha256: await sha256Hex(literal) };
    },
  );
}

describe("executeConnectedQuery", () => {
  it("passes only the approved plan literal and returns owned evidence", async () => {
    const spec = (await plan()).find(({ key }) => key === "find.service")!;
    const transport = {
      execute: vi.fn(async (input) => {
        expect(input.literal).toBe(spec.literal);
        expect(input.window).toEqual(spec.window);
        expect(input.findInput).toEqual({
          field: "service",
          value: application.service,
        });
        return {
          rows: [{ service: application.service }],
          complete: true as const,
          source: "splunk_rest" as const,
          executionId: provenance.executionId,
          planSha256: provenance.planSha256,
          indexTimeBounds: provenance.indexTimeBounds,
          receiptFingerprints: [...provenance.receiptFingerprints],
          queryJob: { sid: provenance.queryJobSid },
        };
      }),
    };
    const evidence = await executeConnectedQuery(spec, provenance, transport);
    expect(evidence.input).toEqual({
      field: "service",
      value: application.service,
    });
    expect(transport.execute).toHaveBeenCalledOnce();
  });

  type Tamper = {
    executionId?: string;
    queryJob?: { sid: string };
    receiptFingerprints?: string[];
    indexTimeBounds?: { earliest: number; latest: number };
  };
  it.each<[string, Tamper]>([
    ["cross-run", { executionId: "other" }],
    ["wrong job", { queryJob: { sid: "other" } }],
    ["wrong receipt", { receiptFingerprints: ["c".repeat(64)] }],
    ["wider bounds", { indexTimeBounds: { earliest: 0, latest: 1000 } }],
  ])("rejects transport provenance tampering: %s", async (_label, change) => {
    const spec = (await plan()).find(({ key }) => key === "graph.impact")!;
    const transport = {
      execute: async () => ({
        rows: [],
        complete: true as const,
        source: "splunk_rest" as const,
        executionId: change.executionId ?? provenance.executionId,
        planSha256: provenance.planSha256,
        indexTimeBounds: change.indexTimeBounds ?? provenance.indexTimeBounds,
        receiptFingerprints: change.receiptFingerprints ?? [
          ...provenance.receiptFingerprints,
        ],
        queryJob: change.queryJob ?? { sid: provenance.queryJobSid },
      }),
    };
    await expect(
      executeConnectedQuery(spec, provenance, transport),
    ).rejects.toThrow();
  });
});
