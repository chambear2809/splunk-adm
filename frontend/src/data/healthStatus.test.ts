import { describe, expect, it } from "vitest";
import { healthIndicator } from "./healthStatus";
import {
  JOB_NAMES,
  SOURCE_NAMES,
  jobRows,
  qualityRows,
  sourceRows,
  type HealthReport,
} from "../health";

const base = (overrides: Partial<HealthReport> = {}): HealthReport => ({
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
      ).toBe("attention");
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
