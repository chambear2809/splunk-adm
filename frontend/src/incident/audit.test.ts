import { describe, expect, it } from "vitest";
import { demoGraph } from "../provider";
import { projectAudit, type AuditBatch } from "./audit";
import { buildTimeline } from "./model";

const batch = (): AuditBatch => ({
  coverage: {
    start: "2026-01-01T00:00:00Z",
    end: "2026-01-01T03:00:00Z",
    gaps: ["collector gap"],
  },
  events: [
    {
      eventId: "evt-1",
      authority: "apic-1",
      scope: "fabric-1",
      objectId: "uni/tn-a/obj-1",
      action: "modified",
      actionTime: "2026-01-01T02:00:00+01:00",
      receivedTime: "2026-01-01T01:10:00Z",
    },
  ],
  bindings: [
    {
      authority: "apic-1",
      scope: "fabric-1",
      objectId: "uni/tn-a/obj-1",
      applicationId: "app-1",
      validFrom: "2026-01-01T00:00:00Z",
      validUntil: "2026-01-01T02:00:00Z",
      bindingAuthority: "inventory",
      bindingEvidenceId: "binding-1",
    },
  ],
});

describe("audit projection", () => {
  it("preserves native time, receipt, binding provenance and gaps through the timeline", () => {
    const projection = projectAudit(batch(), "app-1");
    expect(projection.coverage.gaps).toEqual(["collector gap"]);
    const graph = demoGraph();
    const before = {
      ...graph,
      window: { start: "2026-01-01T00:00:00Z", end: "2026-01-01T01:00:00Z" },
    };
    const during = {
      ...graph,
      window: { start: "2026-01-01T01:00:00Z", end: "2026-01-01T02:00:00Z" },
    };
    const item = buildTimeline(before, during, undefined, projection).find(
      (x) => x.title === "Audit action reported",
    )!;
    expect(item.start).toBe("2026-01-01T02:00:00+01:00");
    expect(item.detail).toContain("received 2026-01-01T01:10:00Z");
    expect(item.detail).toContain("inventory / binding-1");
  });
  it("withholds missing, approximate, expired, ambiguous and malformed bindings", () => {
    for (const mutate of [
      (b: AuditBatch) => {
        b.bindings = [];
      },
      (b: AuditBatch) => {
        b.bindings[0].objectId = "obj-1";
      },
      (b: AuditBatch) => {
        b.bindings[0].objectId += "/child";
      },
      (b: AuditBatch) => {
        b.bindings[0].scope = "fabric-2";
      },
      (b: AuditBatch) => {
        b.bindings[0].validUntil = "2026-01-01T01:00:00Z";
      },
      (b: AuditBatch) => {
        b.bindings.push({ ...b.bindings[0], applicationId: "app-2" });
      },
      (b: AuditBatch) => {
        b.bindings[0].bindingEvidenceId = "";
      },
      (b: AuditBatch) => {
        b.events[0].actionTime = "2026-01-01T01:00:00";
      },
      (b: AuditBatch) => {
        b.events.push({ ...b.events[0] });
      },
    ]) {
      const input = batch();
      mutate(input);
      const result = projectAudit(input, "app-1");
      expect(result.events).toEqual([]);
      expect(result.withheld).toBeGreaterThan(0);
    }
  });
  it("rejects invalid coverage and excludes events outside it", () => {
    const input = batch();
    input.coverage.end = "2026-01-01T01:00:00Z";
    expect(projectAudit(input, "app-1").withheld).toBe(1);
    input.coverage.start = "bad";
    expect(() => projectAudit(input, "app-1")).toThrow(/coverage/);
  });
});
