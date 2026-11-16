import { describe, expect, it } from "vitest";
import { demoGraph } from "../provider";
import {
  captureComparison,
  readableHandoff,
  reviseNotes,
  serializeInvestigation,
} from "./portable";

describe("portable investigation capture", () => {
  it("retains demo labeling and incomplete evidence cautions in readable handoffs", () => {
    const incident = demoGraph();
    incident.coverage.warnings = [];
    incident.coverage.unresolved_conversations = 2;
    incident.read = { coverage: 50, windowSeconds: 3600, pendingSeconds: 1800 };
    incident.truncation = {
      truncated: true,
      shown: { nodes: 1, edges: 1 },
      total: { nodes: 2, edges: 2 },
      ranking: "test",
    };
    const text = readableHandoff(
      captureComparison({ incident, baseline: incident }, "partial"),
    );
    expect(text).toContain("demo evidence");
    expect(text).toContain("ranked subset");
    expect(text).toContain("read is incomplete");
    expect(text).toContain("unresolved identity");
  });
  it("keeps fixed evidence after refresh and preserves prior note revisions", () => {
    const incident = demoGraph();
    const original = incident.snapshot_id;
    const draft = captureComparison(
      { baseline: incident, incident },
      "record-1",
    );
    incident.snapshot_id = "later-refresh";
    expect(draft.captures[1].graph.snapshot_id).toBe(original);
    const first = reviseNotes(draft, {
      notes: "Observed drops",
      hypotheses: "Policy change?",
      questions: "Check audit",
    });
    const next = reviseNotes(first, {
      notes: "Additional check",
      hypotheses: "Unconfirmed",
      questions: "Owner?",
    });
    expect(first.revisions).toHaveLength(1);
    expect(next.revisions[0].notes).toBe("Observed drops");
    const exported = JSON.parse(serializeInvestigation(next));
    expect(exported.version).toBe(1);
    expect(exported.captures[1].graph.snapshot_id).toBe(original);
    expect(readableHandoff(next)).toContain("Additional check");
    expect(readableHandoff(next)).toContain("Unconfirmed");
    expect(readableHandoff(next)).toContain("no shared case save");
  });
  it("rejects mixed scope, invalid windows and oversized notes", () => {
    const incident = demoGraph();
    expect(() =>
      captureComparison(
        {
          incident,
          baseline: {
            ...incident,
            boundary: { ...incident.boundary, cluster: "another-cluster" },
          },
        },
        "record-2",
      ),
    ).toThrow("scope");
    expect(() =>
      captureComparison(
        {
          incident,
          baseline: { ...incident, window: { start: "now", end: "later" } },
        },
        "record-2",
      ),
    ).toThrow();
    const draft = captureComparison(
      { incident, baseline: incident },
      "record-2",
    );
    expect(() =>
      reviseNotes(draft, {
        notes: "x".repeat(20001),
        hypotheses: "",
        questions: "",
      }),
    ).toThrow("20,000");
  });
});
