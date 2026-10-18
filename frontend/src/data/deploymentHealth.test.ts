import { describe, expect, it } from "vitest";
import {
  applicableJobs,
  defaultExpectations,
  expectationFor,
  validateExpectations,
  type DeploymentSnapshot,
} from "./deploymentHealth";

function deployment(
  sources: string[],
  contract: 1 | 2 = 1,
): DeploymentSnapshot {
  const settings = defaultExpectations();
  for (const id of sources) settings.sources[id].state = "active";
  return {
    state: "configured",
    settings,
    activeContract: contract,
    canWrite: false,
  };
}

describe("shared deployment expectations", () => {
  it("keeps absence and unavailable intent unknown rather than inferring from data", () => {
    expect(expectationFor(undefined, "netflow")).toBe("unknown");
    expect(
      expectationFor({ state: "unavailable", canWrite: false }, "netflow"),
    ).toBe("unknown");
    expect(expectationFor(deployment([]), "netflow")).toBe("not_selected");
    expect(applicableJobs(deployment([]))).toEqual([]);
  });
  it("requires only dependencies of partial sources and the active contract", () => {
    expect(applicableJobs(deployment(["nxos"])).map((job) => job.id)).toEqual([
      "interfaces",
    ]);
    expect(
      applicableJobs(deployment(["netflow"])).map((job) => job.id),
    ).toEqual(["rollup_v1"]);
    expect(applicableJobs(deployment(["traces"])).map((job) => job.id)).toEqual(
      ["binding", "catalog_v1"],
    );
    const v2 = deployment(["catalyst", "meraki", "netflow"], 2);
    expect(applicableJobs(v2).map((job) => job.id)).toEqual([
      "history",
      "rollup_v2",
      "traffic_v2",
    ]);
    expect(expectationFor(v2, "summary_v2")).toBe("active");
    expect(expectationFor(v2, "summary")).toBe("staged");
  });
  it("keeps Cisco integration staged on V1 without failing required production jobs", () => {
    const snapshot = deployment(["catalyst", "meraki", "sdwan"]);
    expect(expectationFor(snapshot, "catalyst")).toBe("staged");
    expect(applicableJobs(snapshot)).toEqual([]);
    snapshot.activeContract = undefined;
    expect(expectationFor(snapshot, "catalyst")).toBe("unknown");
  });
  it("rejects bad settings, unbounded cadence, derived source controls and coercion", () => {
    const settings = defaultExpectations();
    expect(validateExpectations(settings)).toEqual(settings);
    for (const bad of [true, "3600", 0, -1, Number.NaN, 604801]) {
      expect(() =>
        validateExpectations({
          ...settings,
          sources: {
            catalyst: { ...settings.sources.catalyst, cadenceSeconds: bad },
          },
        }),
      ).toThrow();
    }
    expect(() =>
      validateExpectations({
        ...settings,
        sources: { summary: settings.sources.netflow },
      }),
    ).toThrow();
    expect(() =>
      validateExpectations({ ...settings, activeContract: 2 }),
    ).toThrow();
    expect(() =>
      validateExpectations({
        ...settings,
        sources: {
          catalyst: { ...settings.sources.catalyst, state: ["active"] },
        },
      }),
    ).toThrow();
  });
});
