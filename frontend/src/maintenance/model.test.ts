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
          capacity: evidence({
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
