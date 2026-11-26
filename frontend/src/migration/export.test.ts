import { describe, expect, it } from "vitest";
import { DEFAULT_RULES, planMoveGroups } from "../ops/moveGroup";
import type { PlannerDataset } from "./data";
import { blockersCsv, groupsCsv, planJson } from "./export";

const conv = (client: string, server: string, port: number) => ({
  client,
  server,
  port,
  transport: "tcp",
  directed: true,
  records: 3,
  bytes: 90,
  first: 86500,
  last: 86600,
  observers: ["stream:leaf-101"],
  observersCapped: false,
  sources: ["stream"],
  sampled: false,
});
const dataset: PlannerDataset = {
  schemaVersion: 1,
  selection: {
    scope: "prod",
    start: 86400,
    end: 172800,
    configurationFingerprint: "a".repeat(64),
    trafficContract: 2,
  },
  capturedAt: 172900,
  conversations: [
    conv("10.0.0.1", "10.0.1.1", 8080),
    conv("10.0.1.1", "10.1.0.1", 443),
  ],
  inputCount: 2,
  capped: false,
  unprotectedRows: 0,
  coverage: { coveredBuckets: 288, expectedBuckets: 288, days: [] },
  warnings: [],
};
const seeds = [
  { label: '=HYPERLINK("x")', addresses: ["10.0.0.1"] },
  { label: "Billing", addresses: ["10.1.0.1"] },
];
const overrides = { pinnedShared: [], notShared: [], assignments: {} };
const plan = planMoveGroups({
  conversations: dataset.conversations,
  complete: true,
  seeds,
  rules: DEFAULT_RULES,
  overrides,
});

describe("move-group exports", () => {
  it("writes groups CSV with metadata and formula-safe labels", () => {
    const csv = groupsCsv(dataset, plan, [
      {
        address: "10.0.1.1",
        vmName: "orders-app-01",
        vcenter: "vc",
        reportedAt: 1,
        claims: 1,
      },
    ]);
    const lines = csv.split("\r\n");
    expect(lines[1]).toContain("metadata,prod,1970-01-02T00:00:00.000Z");
    expect(lines[1]).toContain(",complete,288/288 summary buckets");
    expect(csv).toContain("'=HYPERLINK");
    expect(csv).toContain("group_member,g1,");
    expect(csv).toContain(
      "10.0.1.1,traversal,inferred from observed conversations,1,10.0.0.1,2,expanded,,orders-app-01",
    );
  });

  it("writes blockers with direction, volume, observers and first/last seen", () => {
    const csv = blockersCsv(dataset, plan);
    expect(csv).toContain(
      "wave_blocker,g1,g2,10.0.1.1,10.1.0.1,443,tcp,observed,3,90,stream:leaf-101,false,stream,false,1970-01-02T00:01:40.000Z,1970-01-02T00:03:20.000Z",
    );
  });

  it("marks exports incomplete when coverage or the read is partial", () => {
    const partial = {
      ...dataset,
      coverage: { ...dataset.coverage, coveredBuckets: 100 },
    };
    expect(blockersCsv(partial, plan).split("\r\n")[1]).toContain(
      ",incomplete,",
    );
  });

  it("writes a draft JSON plan that labels observed and inferred evidence", () => {
    const json = JSON.parse(
      planJson(dataset, plan, seeds, DEFAULT_RULES, overrides),
    );
    expect(json).toMatchObject({
      schema: "application-atlas/move-group-plan",
      schemaVersion: 1,
      draft: true,
      selection: { scope: "prod", trafficContract: 2 },
      source: { loaded: 2, capped: false },
    });
    expect(json.evidence.conversations).toMatch(/^observed/);
    expect(json.evidence.groups).toMatch(/^inferred/);
    expect(json.plan.blockers).toHaveLength(1);
  });
});
