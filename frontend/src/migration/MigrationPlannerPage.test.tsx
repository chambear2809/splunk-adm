import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import { MigrationPlannerPage } from "./MigrationPlannerPage";
import type { PlannerDataset } from "./data";

const conv = (client: string, server: string, port: number) => ({
  client,
  server,
  port,
  transport: "tcp",
  directed: true,
  records: 4,
  bytes: 120,
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
    conv("10.0.0.1", "10.9.0.53", 53),
    conv("10.1.0.1", "10.9.0.53", 53),
  ],
  inputCount: 4,
  capped: false,
  unprotectedRows: 0,
  coverage: { coveredBuckets: 200, expectedBuckets: 288, days: [] },
  warnings: ["Coverage is partial; a missing day is a gap or a quiet period."],
};

describe("MigrationPlannerPage", () => {
  it("says live data is required instead of showing an empty plan", () => {
    const html = renderToStaticMarkup(<MigrationPlannerPage live={false} />);
    expect(html).toContain("Requires live data");
    expect(html).not.toContain("Move-group plan");
  });

  it("asks for seeds once conversations are loaded", () => {
    const html = renderToStaticMarkup(
      <MigrationPlannerPage live initialDataset={dataset} />,
    );
    expect(html).toContain("4</strong> observed conversations");
    expect(html).toContain("200 of 288 five-minute buckets");
    expect(html).toContain("a gap or a quiet period");
    expect(html).toContain("Enter seed addresses to build move groups.");
  });

  it("renders groups, shared services and blockers with move controls", () => {
    const html = renderToStaticMarkup(
      <MigrationPlannerPage
        live
        initialDataset={dataset}
        initialSeeds={"Orders = 10.0.0.1\nBilling = 10.1.0.1"}
      />,
    );
    expect(html).toContain('aria-label="Move-group plan"');
    expect(html).toContain("Orders ↔ Billing");
    expect(html).toContain('aria-label="Group Orders"');
    expect(html).toContain('aria-label="Move 10.0.1.1"');
    expect(html).toContain("10.9.0.53");
    expect(html).toContain('aria-label="Shared services table"');
    expect(html).toContain("Download groups CSV");
    expect(html).toContain("Download plan JSON");
  });

  it("reports invalid seed input instead of planning", () => {
    const html = renderToStaticMarkup(
      <MigrationPlannerPage
        live
        initialDataset={dataset}
        initialSeeds="Orders = not-an-ip"
      />,
    );
    expect(html).toContain('role="alert"');
    expect(html).not.toContain('aria-label="Move-group plan"');
  });
});
