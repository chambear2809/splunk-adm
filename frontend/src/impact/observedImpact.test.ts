import { describe, expect, it } from "vitest";
import { compileFailure } from "./classify";
import { failsImpact } from "./model";
import {
  observedImpactClassifier,
  observedImpactData,
  observedJourneyImpact,
} from "./observedImpact";
import type {
  ObservedImpactEvidence,
  ObservedImpactTrial,
} from "./observedEvidence";

const s1 = "192.0.2.1";
const s2 = "192.0.2.2";
const form = (
  id: string,
  forward: string[],
  reverse: string[],
  journey = "Open form",
): ObservedImpactTrial => ({
  id,
  journey,
  app: "Invoice",
  actor: "browser",
  outcome: "HTTP response logged",
  src: "192.0.2.20",
  dst: "192.0.2.30",
  source_port: 32001,
  destination_port: 443,
  start: 1200,
  end: 1230,
  captures: { forward: `${id}-forward`, reverse: `${id}-reply` },
  observations: { forward, reverse },
  exports: { forward, reverse },
  traceHops: { forward: [], reverse: [] },
  linkedCaptures: [],
});
const cohort: ObservedImpactEvidence = {
  schema_version: 1,
  scope: "invoice",
  start: 1000,
  end: 2000,
  devices: [
    { id: s1, name: "Spine1", role: "spine", domain: 1 },
    { id: s2, name: "Spine2", role: "spine", domain: 1 },
  ],
  receipts: new Map(),
  native: [],
  trials: [
    form("form-s1", [s1], [s1]),
    form("form-s2", [s2], [s2]),
    form("save-s1", [s1], [s2], "Save record"),
    form("partial", [s2], []),
  ],
};

describe("observed Impact what-if", () => {
  it("retains only a bidirectional repeat of the same user action", () => {
    const data = observedImpactData(cohort, ["Spine1"]);
    expect(data.topology.links).toEqual([]);
    const journeys = observedJourneyImpact(
      cohort,
      compileFailure(data.elements),
    );
    expect(
      journeys.map((j) => [
        j.journey,
        j.exposed.length,
        j.remaining.map((t) => t.id),
      ]),
    ).toEqual([
      ["Open form", 1, ["form-s2"]],
      ["Save record", 1, []],
    ]);
    const both = observedImpactData(cohort, [s1, s2]);
    expect(
      observedJourneyImpact(cohort, compileFailure(both.elements)).map((j) => [
        j.exposed.length,
        j.remaining.length,
      ]),
    ).toEqual([
      [3, 0],
      [1, 0],
    ]);
  });

  it("checks coverage by selected tier and counts a linked Save leg once", () => {
    const leaf1 = "192.0.2.3";
    const leaf2 = "192.0.2.4";
    const border = "192.0.2.5";
    const save = form("save", [s1, border], [s2], "Save record");
    const downstream = {
      src: "192.0.2.30",
      dst: "192.0.2.40",
      source_port: 32002,
      destination_port: 5432,
      capture: "save-db",
      device: leaf2,
      segment: "routing",
      hop: "Leaf2 routed DB traffic",
    };
    const extended: ObservedImpactEvidence = {
      ...cohort,
      schema_version: 2,
      devices: [
        ...cohort.devices,
        { id: leaf1, name: "Leaf1", role: "leaf", domain: 1 },
        { id: leaf2, name: "Leaf2", role: "leaf", domain: 1 },
        { id: border, name: "Border Leaf3", role: "border", domain: 1 },
      ],
      trials: [
        form("alt-leaf", [s1, leaf1, border], [s2, leaf1]),
        form("partial-leaf", [s1, border], [s2, leaf1]),
        {
          ...save,
          linkedCaptures: [
            downstream,
            { ...downstream, capture: "save-db-retry" },
          ],
        },
      ],
    };
    const calculate = (tokens: string[]) => {
      const data = observedImpactData(extended, tokens);
      return observedJourneyImpact(extended, compileFailure(data.elements));
    };
    const [open, saveImpact] = calculate([leaf2]);
    expect(open.exposed).toHaveLength(0);
    expect(open.remaining.map((t) => t.id)).toEqual(["alt-leaf"]);
    expect([...open.remainingDevices]).toEqual([leaf1]);
    expect(open.incomplete.map((t) => t.id)).toEqual(["partial-leaf"]);
    expect(saveImpact.exposed.map((t) => t.id)).toEqual(["save"]);
    expect(saveImpact.remaining).toHaveLength(0);

    const leafData = observedImpactData(extended, [leaf2]);
    const leafResult = failsImpact(
      leafData.elements,
      leafData.conversations,
      leafData.ctx,
      {
        cls: observedImpactClassifier(leafData.ctx, extended),
      },
    );
    expect(leafResult.rows[0]).toMatchObject({
      conv: { id: "save" },
      linkedTraversal: true,
      severity: "unknown",
    });

    const [crossTier] = calculate([leaf2, s2]);
    expect(crossTier.remaining).toHaveLength(0);
    expect(crossTier.exposed).toHaveLength(2);
    const [borderImpact] = calculate([border]);
    expect(borderImpact.exposed).toHaveLength(2);
    expect(borderImpact.remaining).toHaveLength(0);
  });

  it("reports exposure without predicting an outage or inferring a failed leg", () => {
    const data = observedImpactData(cohort, [s1]);
    const cls = observedImpactClassifier(data.ctx, cohort);
    const result = failsImpact(data.elements, data.conversations, data.ctx, {
      cls,
    });
    expect(result.kpis.apps).toEqual({ unknown: 1, outage: 0, degraded: 0 });
    expect(result.rows.map((row) => row.conv.id)).toEqual([
      "form-s1",
      "save-s1",
    ]);
    expect(
      result.rows.every(
        (row) => row.traversal === "observed" && !row.alternate.length,
      ),
    ).toBe(true);
    expect(cls.path(data.conversations[0])[0].edges).toEqual([]);
  });

  it("rejects unknown selections, interfaces, and duplicate device aliases", () => {
    for (const selection of [
      ["192.0.2.3"],
      ["Spine1|Eth1/1"],
      [s1, "Spine1"],
    ]) {
      expect(() => observedImpactData(cohort, selection)).toThrow(
        /distinct devices/,
      );
    }
  });
});
