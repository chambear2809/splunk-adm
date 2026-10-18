import { describe, expect, it } from "vitest";
import {
  defaultExpectations,
  type DeploymentSnapshot,
} from "./deploymentHealth";
import { healthIndicator, shouldPollHealth } from "./healthStatus";
import {
  JOB_NAMES,
  SOURCE_NAMES,
  jobRows,
  qualityRows,
  sourceRows,
  type HealthReport,
} from "../health";

const deployment = (id?: string): DeploymentSnapshot => {
  const settings = defaultExpectations();
  for (const [sourceId, expectation] of Object.entries(settings.sources))
    if (!id || id === sourceId) expectation.state = "active";
  return { state: "configured", activeContract: 1, settings, canWrite: true };
};
const base = (overrides: Partial<HealthReport> = {}): HealthReport => ({
  deployment: deployment(),
  sources: sourceRows(
    SOURCE_NAMES.map((name) => ({
      kind: "source",
      name,
      records: 1,
      latest_indexed: 200000,
    })),
  ),
  jobs: jobRows([
    ...JOB_NAMES.map((name) => ({
      kind: "job",
      name,
      disabled: name.endsWith("prune") ? 1 : 0,
      last_run: 200000,
      last_success: 200000,
      last_status: "success",
    })),
  ]),
  quality: qualityRows([
    {
      kind: "quality",
      source: "all",
      status: "checked",
      reason: "evaluated",
      records: 1,
    },
  ]),
  warnings: [],
  checkedAt: 200000,
  ...overrides,
});
describe("health indicator", () => {
  it("distinguishes demo, loading, unknown, attention, and healthy", () => {
    expect(healthIndicator(undefined, false, undefined, false)).toBe("unknown");
    expect(healthIndicator(undefined, true, undefined, true)).toBe("loading");
    expect(
      healthIndicator(
        base({ sources: sourceRows([]), jobs: jobRows([]) }),
        false,
        undefined,
        true,
      ),
    ).toBe("unknown");
    expect(
      healthIndicator(base({ warnings: ["partial"] }), false, undefined, true),
    ).toBe("attention");
    expect(healthIndicator(base(), false, undefined, true)).toBe("healthy");
  });
  it("does not call zero or unavailable quality evidence healthy", () => {
    for (const evaluated of [0, undefined]) {
      expect(
        healthIndicator(
          base({ quality: { evaluated, issues: [] } }),
          false,
          undefined,
          true,
        ),
      ).toBe("unknown");
    }
    expect(
      healthIndicator(
        base({ sources: sourceRows([]), warnings: ["unavailable"] }),
        false,
        undefined,
        true,
      ),
    ).toBe("unknown");
  });
  it("does not call zeros, disabled builders, failures, or stale data healthy", () => {
    expect(
      healthIndicator(
        base({
          sources: sourceRows([
            { kind: "source", name: "NetFlow", records: 0 },
          ]),
        }),
        false,
        undefined,
        true,
      ),
    ).toBe("attention");
    expect(
      healthIndicator(
        base({
          jobs: jobRows([
            { kind: "job", name: "ADM - Identity builder", disabled: 1 },
          ]),
        }),
        false,
        undefined,
        true,
      ),
    ).toBe("attention");
    expect(
      healthIndicator(
        base({
          jobs: jobRows([
            {
              kind: "job",
              name: "ADM - Identity builder",
              disabled: 0,
              last_run: 200000,
              last_status: "failed",
            },
          ]),
        }),
        false,
        undefined,
        true,
      ),
    ).toBe("attention");
  });
});

describe("health polling", () => {
  it("polls only while live and visible", () => {
    expect(shouldPollHealth(true, true)).toBe(true);
    expect(shouldPollHealth(true, false)).toBe(false);
    expect(shouldPollHealth(false, true)).toBe(false);
  });
});

it("keeps jobs-only checks and missing scheduler evidence unknown", () => {
  expect(healthIndicator(base({ scope: "jobs" }), false, undefined, true)).toBe(
    "unknown",
  );
  expect(
    healthIndicator(base({ jobs: jobRows([]) }), false, undefined, true),
  ).toBe("unknown");
  expect(
    healthIndicator(
      base({
        jobs: jobRows(
          JOB_NAMES.map((name) => ({ kind: "job", name, disabled: 0 })),
        ),
      }),
      false,
      undefined,
      true,
    ),
  ).toBe("unknown");
});

it("does not require inapplicable quality or mandatory jobs for inventory-only deployments", () => {
  const nxos = deployment("nxos");
  const report = base({
    deployment: nxos,
    sources: sourceRows(
      [
        {
          kind: "source",
          name: "NX-OS",
          records: 1,
          latest_indexed: 200000,
          probe_lookback_seconds: 604800,
        },
      ],
      nxos,
    ),
    jobs: [],
    quality: qualityRows([]),
  });
  expect(healthIndicator(report, false, undefined, true)).toBe("healthy");
  expect(
    healthIndicator({ ...report, sources: [] }, false, undefined, true),
  ).toBe("unknown");
  expect(
    healthIndicator(
      { ...report, deployment: undefined },
      false,
      undefined,
      true,
    ),
  ).toBe("unknown");
});

it("does not turn incomplete receipt metadata into an attention diagnosis", () => {
  const settings = deployment("nxos");
  const source = {
    kind: "source",
    name: "NX-OS",
    records: 1,
    latest_indexed: 200000,
  };
  for (const detail of [
    {},
    { probe_lookback_seconds: 300 },
    { probe_lookback_seconds: 604800, latest_indexed: undefined },
  ]) {
    expect(
      healthIndicator(
        base({
          deployment: settings,
          sources: sourceRows([{ ...source, ...detail }], settings),
          jobs: [],
          qualityRequired: false,
        }),
        false,
        undefined,
        true,
      ),
    ).toBe("unknown");
  }
});

it("reports selected but unconfigured sources even when their unsafe probes are omitted", () => {
  const config = deployment("nxos");
  config.sourceConfiguration = { nxos: "not_configured" };
  expect(
    healthIndicator(
      base({
        deployment: config,
        sources: sourceRows([], config),
        jobs: [],
        qualityRequired: false,
      }),
      false,
      undefined,
      true,
    ),
  ).toBe("attention");
});
