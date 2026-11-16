import { describe, expect, it } from "vitest";
import {
  assessMaintenance,
  compareAssessments,
  type AssessmentInput,
  type Evidence,
} from "./model";

// Synthetic assessment evidence; no production readiness or capacity claim.
const evidence = <T>(value: T): Evidence<T> => ({
  value,
  scope: "prod",
  source: "test",
  qualified: true,
  state: "complete",
  observedAt: 100,
  validUntil: 1000,
});
const input = (): AssessmentInput => ({
  id: "capture-1",
  capturedAt: 300,
  window: { start: 100, end: 200 },
  selectedElements: ["host-1"],
  services: [
    {
      id: "payments",
      name: "Payments",
      owner: "Commerce",
      scope: "prod",
      topology: evidence("exposed"),
      alternatives: [
        {
          name: "replica-2",
          reachable: evidence(true),
          healthy: evidence(true),
          ready: evidence(true),
          substitutable: evidence(true),
          independentFailureDomain: evidence(true),
          capacity: {
            ...evidence({
              sufficientPeakHeadroom: true,
              value: 100,
              unit: "requests/s",
              interval: { start: 100, end: 200 },
              direction: "inbound",
              sampling: "unsampled",
              deduplication: "request ID",
              capacitySource: "load test",
              assumptions: ["peak during window is representative"],
            }),
            observedAt: 200,
          },
        },
      ],
    },
  ],
});

describe("maintenance assessment", () => {
  it("requires qualified complete scoped evidence for every dimension", () => {
    const source = input();
    expect(assessMaintenance(source).headline).toBe(
      "No identified blockers in this evidence",
    );
    source.services[0].alternatives[0].capacity = undefined;
    expect(assessMaintenance(source).headline).toBe(
      "Readiness cannot be confirmed",
    );
    expect(assessMaintenance(source).services[0].alternatives[0].capacity).toBe(
      "unknown",
    );
    source.services[0].topology!.state = "capped";
    expect(assessMaintenance(source).services[0].topology).toBe("unknown");
  });
  it("identifies an unhealthy alternative and shared host or zone as blockers", () => {
    const source = input();
    source.services[0].alternatives[0].healthy = evidence(false);
    source.services[0].alternatives[0].independentFailureDomain =
      evidence(false);
    const result = assessMaintenance(source);
    expect(result.headline).toBe("Identified blockers");
    expect(result.services[0].alternatives[0]).toMatchObject({
      health: "blocked",
      failureDomain: "blocked",
    });
  });
  it("fails closed on stale, denied, wrong-scope and incomplete capacity evidence", () => {
    const source = input();
    source.services[0].alternatives[0].ready!.state = "stale";
    source.services[0].alternatives[0].healthy!.scope = "other";
    source.services[0].alternatives[0].reachable!.state = "denied";
    source.services[0].alternatives[0].capacity!.value.assumptions = [];
    expect(assessMaintenance(source).services[0].alternatives[0]).toMatchObject(
      {
        readiness: "unknown",
        health: "unknown",
        reachability: "unknown",
        capacity: "unknown",
      },
    );
    expect(assessMaintenance(source).headline).toBe(
      "Readiness cannot be confirmed",
    );
  });
  it("compares detached captures of the same scenario and rejects a different scope", () => {
    const source = input();
    const before = assessMaintenance(source);
    source.id = "capture-2";
    source.capturedAt = 400;
    source.services[0].alternatives[0].healthy = evidence(false);
    const after = assessMaintenance(source);
    expect(before.services[0].alternatives[0].health).toBe("confirmed");
    expect(compareAssessments(before, after)).toEqual({
      comparable: true,
      changed: ["Payments / replica-2: health confirmed → blocked"],
    });
    source.services[0].scope = "other";
    expect(
      compareAssessments(before, assessMaintenance(source)).comparable,
    ).toBe(false);
  });
});

describe("comparison boundaries", () => {
  it("rejects duplicate service identities and invalid windows", () => {
    const source = input();
    const before = assessMaintenance(source);
    source.id = "later";
    source.capturedAt = 400;
    source.services.push({ ...source.services[0] });
    expect(
      compareAssessments(before, assessMaintenance(source)).comparable,
    ).toBe(false);
    source.services.pop();
    source.window = { start: 200, end: 100 };
    expect(
      compareAssessments(before, assessMaintenance(source)).comparable,
    ).toBe(false);
  });
});

describe("measurement timing", () => {
  it("accepts a peak observed after the measured interval ends", () => {
    const source = input();
    source.services[0].alternatives[0].capacity!.observedAt = 200;
    expect(assessMaintenance(source).services[0].alternatives[0].capacity).toBe(
      "confirmed",
    );
  });
  it("rejects stale, future, invalid, premature, or incomplete peak measurements", () => {
    for (const mutate of [
      (
        e: NonNullable<
          AssessmentInput["services"][number]["alternatives"][number]["capacity"]
        >,
      ) => {
        e.validUntil = 300;
      },
      (
        e: NonNullable<
          AssessmentInput["services"][number]["alternatives"][number]["capacity"]
        >,
      ) => {
        e.observedAt = 301;
      },
      (
        e: NonNullable<
          AssessmentInput["services"][number]["alternatives"][number]["capacity"]
        >,
      ) => {
        e.observedAt = NaN;
      },
      (
        e: NonNullable<
          AssessmentInput["services"][number]["alternatives"][number]["capacity"]
        >,
      ) => {
        e.observedAt = 199;
      },
      (
        e: NonNullable<
          AssessmentInput["services"][number]["alternatives"][number]["capacity"]
        >,
      ) => {
        e.value.interval.start = 101;
      },
    ]) {
      const source = input();
      const capacity = source.services[0].alternatives[0].capacity!;
      capacity.observedAt = 200;
      mutate(capacity);
      expect(
        assessMaintenance(source).services[0].alternatives[0].capacity,
      ).toBe("unknown");
    }
  });
  it("allows a source-established effective start for operational state", () => {
    const source = input();
    const health = source.services[0].alternatives[0].healthy!;
    health.observedAt = 200;
    expect(assessMaintenance(source).services[0].alternatives[0].health).toBe(
      "unknown",
    );
    health.validFrom = 100;
    expect(assessMaintenance(source).services[0].alternatives[0].health).toBe(
      "confirmed",
    );
    health.validFrom = 201;
    expect(assessMaintenance(source).services[0].alternatives[0].health).toBe(
      "unknown",
    );
  });
});
