import { describe, expect, it, vi } from "vitest";
import { buildApprovedConnectedQuery } from "./approvedConnectedQuery";
import { createSplunkConnectedQueryTransport } from "./splunkConnectedQueryTransport";

const application = {
  service: "inventory",
  environment: "demo",
  cluster: "c",
  namespace: "shop",
};
const window = { earliest: 100, latest: 200 };
const provenance = { executionId: "exec", planSha256: "a".repeat(64) };

describe("createSplunkConnectedQueryTransport", () => {
  it("dispatches only approved literals and retains completed job/receipts", async () => {
    const approved = await buildApprovedConnectedQuery({
      application,
      key: "find.service",
      window,
    });
    const client = {
      search: vi.fn(async () => ({
        rows: [{ service: "inventory" }],
        job: { sid: "sid", dispatchState: "DONE" as const },
        indexTimeBounds: window,
        receiptFingerprints: ["b".repeat(64)],
      })),
    };
    const transport = createSplunkConnectedQueryTransport(client, provenance);
    await expect(
      transport.execute({
        application,
        key: "find.service",
        literal: approved.literal,
        window,
        findInput: { field: "service", value: "inventory" },
      }),
    ).resolves.toMatchObject({
      executionId: "exec",
      planSha256: "a".repeat(64),
      queryJob: { sid: "sid" },
    });
    expect(client.search).toHaveBeenCalledWith({
      literal: approved.literal,
      ...window,
    });
  });

  it("rejects unapproved literals and incomplete jobs without dispatch", async () => {
    const client = { search: vi.fn() };
    const transport = createSplunkConnectedQueryTransport(client, provenance);
    await expect(
      transport.execute({
        application,
        key: "find.service",
        literal: "| makeresults",
        window,
      }),
    ).rejects.toThrow(/approved factory/);
    expect(client.search).not.toHaveBeenCalled();
  });
});
