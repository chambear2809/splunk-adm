import { describe, expect, it } from "vitest";
import { sha256Hex } from "../changeCorrelation/canonicalJson";
import { buildConnectedQueryPlan } from "./connectedServiceQueryPlan";
import type { GraphArgs } from "../rows";

const scopes: GraphArgs[] = [
  {
    service: "inventory",
    environment: "demo",
    cluster: "c",
    namespace: "shop",
  },
  { service: "pricing", environment: "demo", cluster: "c", namespace: "shop" },
];
const windows = {
  baseline: { earliest: 100, latest: 200 },
  change: { earliest: 200, latest: 300 },
  impact: { earliest: 300, latest: 400 },
  recovery: { earliest: 400, latest: 500 },
};

describe("connected query plan", () => {
  it("creates eighteen independently namespaced query specs without receipts", async () => {
    const plan = await buildConnectedQueryPlan(
      scopes,
      windows,
      async ({ queryNamespace, key }) => {
        const literal = `| makeresults | eval ns="${queryNamespace}", key="${key}"`;
        return { literal, sha256: await sha256Hex(literal) };
      },
    );
    expect(plan).toHaveLength(18);
    expect(new Set(plan.map((item) => item.queryNamespace))).toEqual(
      new Set(["connected.inventory", "connected.pricing"]),
    );
    expect(plan.every((item) => !Object.hasOwn(item, "receipt"))).toBe(true);
  });

  it("rejects bad builder hashes and scope/order drift", async () => {
    await expect(
      buildConnectedQueryPlan(scopes, windows, async () => ({
        literal: "| makeresults",
        sha256: "0".repeat(64),
      })),
    ).rejects.toThrow(/hash mismatch/);
    await expect(
      buildConnectedQueryPlan([scopes[1], scopes[0]], windows, async () => ({
        literal: "| makeresults",
        sha256: await sha256Hex("| makeresults"),
      })),
    ).rejects.toThrow(/ordered/);
    await expect(
      buildConnectedQueryPlan(
        scopes,
        { ...windows, selected: { earliest: 0, latest: 1 } } as never,
        async ({ key }) => {
          const literal = `| makeresults | eval key="${key}"`;
          return { literal, sha256: await sha256Hex(literal) };
        },
      ),
    ).rejects.toThrow(/unexpected phase/);
    await expect(
      buildConnectedQueryPlan(
        scopes,
        { ...windows, impact: { earliest: 400, latest: 300 } },
        async ({ key }) => {
          const literal = `| makeresults | eval key="${key}"`;
          return { literal, sha256: await sha256Hex(literal) };
        },
      ),
    ).rejects.toThrow(/impact window/);
  });
});
