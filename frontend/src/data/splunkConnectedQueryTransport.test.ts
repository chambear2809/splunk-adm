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
      verifyOwnership: vi.fn(async () => provenance),
      search: vi.fn(async (input) => {
        // Model the installed macro behavior: bounds are dispatch arguments;
        // a post-macro _time filter would remove projected graph rows.
        expect(input.literal).not.toContain("_time>=");
        expect(input.literal).not.toContain("adm_find(");
        expect(input.literal).toContain('service="inventory"');
        expect(input.literal).toContain('environment="demo"');
        expect(input.literal).toContain('cluster="c"');
        expect(input.literal).toContain('namespace="shop"');
        expect(input.earliest).toBe(100);
        expect(input.latest).toBe(200);
        return {
          rows: [{ service: "inventory" }],
          job: { sid: "sid", dispatchState: "DONE" as const },
          indexTimeBounds: window,
          receiptFingerprints: ["b".repeat(64)],
        };
      }),
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
    expect(client.verifyOwnership).toHaveBeenCalledOnce();
  });

  it("rejects unapproved literals and incomplete jobs without dispatch", async () => {
    const client = {
      verifyOwnership: vi.fn(async () => provenance),
      search: vi.fn(),
    };
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

  it("rejects a client bound to another run before dispatch", async () => {
    const approved = await buildApprovedConnectedQuery({
      application,
      key: "find.service",
      window,
    });
    const client = {
      verifyOwnership: vi.fn(async () => ({
        executionId: "other-run",
        planSha256: provenance.planSha256,
      })),
      search: vi.fn(),
    };
    const transport = createSplunkConnectedQueryTransport(client, provenance);
    await expect(
      transport.execute({
        application,
        key: "find.service",
        literal: approved.literal,
        window,
      }),
    ).rejects.toThrow(/ownership/);
    expect(client.search).not.toHaveBeenCalled();
  });
});
