import { describe, expect, it } from "vitest";
import { buildApprovedConnectedQuery } from "./approvedConnectedQuery";

const application = {
  service: "inventory",
  environment: "demo",
  cluster: "c",
  namespace: "shop",
};

describe("buildApprovedConnectedQuery", () => {
  it("builds fixed bounded macro queries", async () => {
    const query = await buildApprovedConnectedQuery({
      application,
      key: "graph.impact",
      window: { earliest: 100, latest: 200 },
    });
    expect(query.literal).toBe(
      '| `adm_graph("inventory","demo","c","shop")` | where _time>=100 AND _time<200',
    );
    expect(query.sha256).toMatch(/^[a-f0-9]{64}$/);
  });

  it("uses the existing catalog and Find macro contracts", async () => {
    await expect(
      buildApprovedConnectedQuery({
        application,
        key: "catalog.selected",
        window: { earliest: 100, latest: 200 },
      }),
    ).resolves.toMatchObject({
      literal:
        '| `adm_catalog_build` | search service="inventory" | where _time>=100 AND _time<200',
    });
    await expect(
      buildApprovedConnectedQuery({
        application,
        key: "find.service",
        window: { earliest: 100, latest: 200 },
      }),
    ).resolves.toMatchObject({
      literal: '| `adm_find("inventory")` | where _time>=100 AND _time<200',
    });
  });

  it("rejects SPL injection and malformed bounds", async () => {
    await expect(
      buildApprovedConnectedQuery({
        application: { ...application, service: 'x" | delete *' },
        key: "find.service",
        window: { earliest: 100, latest: 200 },
      }),
    ).rejects.toThrow();
    await expect(
      buildApprovedConnectedQuery({
        application,
        key: "find.service",
        window: { earliest: 200, latest: 100 },
      }),
    ).rejects.toThrow();
  });
});
