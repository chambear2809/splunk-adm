import { describe, expect, it } from "vitest";
import { correlateMulticast } from "./correlation";
import {
  MAX_EVIDENCE_ROWS,
  type ForwardingEvidence,
  type IgmpEvidence,
  type MulticastAdjacency,
  type MulticastRequest,
} from "./contract";

const request: MulticastRequest = {
  version: 1,
  scope: "site",
  group: "239.1.1.1",
  sender: "10.0.0.1",
  earliest: 100,
  latest: 200,
};
const segment = { kind: "vlan" as const, id: "10", domain: "fabric" };
const report = (overrides: Partial<IgmpEvidence> = {}): IgmpEvidence => ({
  id: "r1",
  kind: "igmp",
  source: "multicast_igmp",
  scope: "site",
  group: "239.1.1.1",
  observer: "tap",
  timestamp: 120,
  limits: [],
  operation: "report-v2",
  reporter: "10.0.0.2",
  reporterKind: "endpoint",
  segment,
  sources: [],
  ...overrides,
});
const forwarding = (
  overrides: Partial<ForwardingEvidence> = {},
): ForwardingEvidence => ({
  id: "f1",
  kind: "forwarding",
  source: "device_state",
  scope: "site",
  group: "239.1.1.1",
  observer: "router",
  timestamp: 120,
  validUntil: 210,
  sender: "10.0.0.1",
  outputs: ["eth0"],
  limits: [],
  ...overrides,
});
const link: MulticastAdjacency = {
  scope: "site",
  from: { observer: "router", interface: "eth0" },
  to: { observer: "switch", interface: "eth1" },
  validFrom: 100,
  validUntil: 210,
};

describe("multicast correlation", () => {
  it("isolates scope, group, time and segments and does not attribute queries or proxies", () => {
    const rows = [
      report(),
      report({ id: "other-segment", segment: { ...segment, domain: "other" } }),
      report({ id: "scope", scope: "other" }),
      report({ id: "group", group: "239.2.2.2" }),
      report({ id: "time", timestamp: 201 }),
      report({ id: "query", reporter: "10.0.0.3", operation: "query" }),
      report({ id: "proxy", reporter: "10.0.0.4", reporterKind: "proxy" }),
      report({ id: "leave", reporter: "10.0.0.5", operation: "leave" }),
    ];
    const result = correlateMulticast(request, rows);
    expect(result.receivers.map((receiver) => receiver.evidenceId)).toEqual([
      "r1",
      "other-segment",
    ]);
    expect(result.evidence.map((row) => row.id)).not.toContain("scope");
  });
  it("deduplicates proven replays only and preserves conflicting rows without conclusions", () => {
    const first = report({ replayKey: "packet" });
    const replay = report({ id: "replay", replayKey: "packet" });
    const independent = report({
      id: "independent",
      observer: "tap2",
      replayKey: "packet",
      reporter: "10.0.0.3",
    });
    expect(
      correlateMulticast(request, [first, replay, independent]).evidence.map(
        (row) => row.id,
      ),
    ).toEqual(["r1", "independent"]);
    const conflicting = report({
      id: "conflict",
      replayKey: "packet",
      sources: ["10.0.0.8"],
    });
    const result = correlateMulticast(request, [first, conflicting]);
    expect(result.evidence).toHaveLength(2);
    expect(result.receivers).toHaveLength(0);
  });
  it("handles source filters, positive deltas and later departures conservatively", () => {
    expect(
      correlateMulticast(request, [
        report({ operation: "include", sources: ["10.0.0.9"] }),
      ]).receivers,
    ).toHaveLength(0);
    expect(
      correlateMulticast(request, [
        report({ operation: "exclude", sources: ["10.0.0.1"] }),
      ]).receivers,
    ).toHaveLength(0);
    expect(
      correlateMulticast(request, [
        report({ operation: "allow-new-sources", sources: ["10.0.0.1"] }),
      ]).receivers[0].state,
    ).toBe("observed");
    expect(
      correlateMulticast(request, [
        report({ operation: "block-old-sources", sources: ["10.0.0.1"] }),
      ]).receivers,
    ).toHaveLength(0);
    expect(
      correlateMulticast(request, [
        report(),
        report({ id: "leave", timestamp: 130, operation: "leave" }),
      ]).receivers[0].state,
    ).toBe("uncertain");
    expect(
      correlateMulticast(request, [
        report(),
        report({
          id: "block",
          timestamp: 130,
          operation: "block-old-sources",
          sources: ["10.0.0.1"],
        }),
      ]).receivers[0].state,
    ).toBe("uncertain");
  });
  it("requires unique current adjacency and matching device state, and retains stale and unresolved branches", () => {
    const from = forwarding();
    const to = forwarding({
      id: "f2",
      observer: "switch",
      input: "eth1",
      outputs: [],
    });
    expect(
      correlateMulticast(request, [from, to], [link]).branches[0],
    ).toMatchObject({ state: "supported", to: "switch" });
    expect(correlateMulticast(request, [from], [link]).branches[0].state).toBe(
      "unresolved",
    );
    expect(
      correlateMulticast(
        request,
        [from, to],
        [link, { ...link, to: { observer: "another", interface: "eth1" } }],
      ).branches[0].state,
    ).toBe("unresolved");
    expect(
      correlateMulticast(request, [forwarding({ validUntil: 150 }), to], [link])
        .branches[0].state,
    ).toBe("stale");
  });
  it("bounds expanded output branches", () => {
    const result = correlateMulticast(request, [
      forwarding({
        outputs: Array.from(
          { length: MAX_EVIDENCE_ROWS + 1 },
          (_, i) => `port${i}`,
        ),
      }),
    ]);
    expect(result.branches).toHaveLength(MAX_EVIDENCE_ROWS);
    expect(result.capped).toBe(true);
  });
});
