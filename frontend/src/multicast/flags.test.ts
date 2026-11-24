import { describe, expect, it } from "vitest";
import type {
  FlowGroupSummary,
  IgmpGroupSummary,
  PointQueries,
  ProfileSummary,
  SourceOutcome,
} from "./contract";
import { FLAG_LABEL, deriveGroupRows } from "./flags";

function igmp(
  group: string,
  overrides: Partial<IgmpGroupSummary> = {},
): IgmpGroupSummary {
  return {
    kind: "igmp",
    profile: "p1",
    group,
    segment: { kind: "vlan", id: "10", domain: "fabric" },
    reports: 1,
    leaves: 0,
    groupQueries: 0,
    endpointReporters: ["192.0.2.10"],
    otherReporters: 0,
    firstSeen: 100,
    lastSeen: 150,
    ...overrides,
  };
}

function flow(
  group: string,
  overrides: Partial<FlowGroupSummary> = {},
): FlowGroupSummary {
  return {
    kind: "flow",
    profile: "p2",
    group,
    observer: "192.0.2.1",
    direction: "ingress",
    senders: ["198.51.100.5"],
    packets: 10,
    bytes: 1000,
    samplingInterval: 1,
    replication: "unknown",
    counters: "delta",
    firstSeen: 100,
    lastSeen: 150,
    ...overrides,
  };
}

function profile(
  id: string,
  summaries: ProfileSummary["summaries"],
  options: {
    state?: SourceOutcome["state"];
    queries?: Omit<PointQueries, "profile">;
  } = {},
): ProfileSummary {
  return {
    summaries,
    queries: options.queries ? { profile: id, ...options.queries } : undefined,
    droppedGroups: 0,
    outcome: {
      source:
        summaries[0]?.kind === "flow" ? "multicast_netflow" : "multicast_igmp",
      profile: id,
      state: options.state ?? "complete",
    },
  };
}

function flagsOf(rows: ReturnType<typeof deriveGroupRows>, group: string) {
  return rows.find((row) => row.group === group)?.flags;
}

describe("deriveGroupRows", () => {
  it("labels every flag with the spec copy", () => {
    expect(FLAG_LABEL).toEqual({
      "interest-no-sender": "Interest, no sender seen",
      "sender-no-interest": "Sender, no interest seen",
      "new-since-previous": "New since previous window",
      "leave-without-query": "Leave without query",
      "multiple-query-senders": "Multiple query senders",
      "coverage-partial": "Source coverage partial",
    });
  });

  it("interest-no-sender", () => {
    const rows = deriveGroupRows([
      profile("p1", [igmp("239.1.1.1"), igmp("239.1.1.2")]),
      profile("p2", [flow("239.1.1.2")]),
    ]);
    expect(flagsOf(rows, "239.1.1.1")).toEqual(["interest-no-sender"]);
    expect(flagsOf(rows, "239.1.1.2")).toEqual([]);
  });

  it("does not treat an IGMP row without reports as interest", () => {
    const rows = deriveGroupRows([
      profile("p1", [igmp("239.1.1.1", { reports: 0, groupQueries: 2 })]),
    ]);
    expect(flagsOf(rows, "239.1.1.1")).toEqual([]);
  });

  it("sender-no-interest", () => {
    const rows = deriveGroupRows([
      profile("p1", [igmp("239.1.1.2", { reports: 0, groupQueries: 1 })]),
      profile("p2", [flow("239.1.1.1"), flow("239.1.1.2")]),
    ]);
    expect(flagsOf(rows, "239.1.1.1")).toEqual(["sender-no-interest"]);
    expect(flagsOf(rows, "239.1.1.2")).toEqual(["sender-no-interest"]);
  });

  it("leave-without-query", () => {
    const rows = deriveGroupRows([
      profile(
        "p1",
        [
          igmp("239.1.1.1", { leaves: 1, lastLeave: 140, lastGroupQuery: 120 }),
          igmp("239.1.1.2", { leaves: 1, lastLeave: 140, lastGroupQuery: 145 }),
          igmp("239.1.1.3", { leaves: 1, lastLeave: 140 }),
          igmp("239.1.1.4"),
        ],
        {
          queries: {
            querySenders: [{ address: "192.0.2.1", first: 100, last: 130 }],
            lastGeneralQuery: 130,
          },
        },
      ),
      profile("p2", [
        flow("239.1.1.1"),
        flow("239.1.1.2"),
        flow("239.1.1.3"),
        flow("239.1.1.4"),
      ]),
    ]);
    expect(flagsOf(rows, "239.1.1.1")).toEqual(["leave-without-query"]);
    expect(flagsOf(rows, "239.1.1.2")).toEqual([]);
    expect(flagsOf(rows, "239.1.1.3")).toEqual(["leave-without-query"]);
    expect(flagsOf(rows, "239.1.1.4")).toEqual([]);
  });

  it("a general query after a leave clears the flag", () => {
    const rows = deriveGroupRows([
      profile("p1", [igmp("239.1.1.1", { leaves: 1, lastLeave: 140 })], {
        queries: {
          querySenders: [{ address: "192.0.2.1", first: 100, last: 145 }],
          lastGeneralQuery: 145,
        },
      }),
      profile("p2", [flow("239.1.1.1")]),
    ]);
    expect(flagsOf(rows, "239.1.1.1")).toEqual([]);
    expect(rows.map((row) => row.group)).not.toContain("0.0.0.0");
  });

  it("uses the leave's own profile queries", () => {
    const rows = deriveGroupRows([
      profile("p1", [igmp("239.1.1.1", { leaves: 1, lastLeave: 140 })]),
      profile("p3", [igmp("239.1.1.1", { profile: "p3", leaves: 0 })], {
        queries: {
          querySenders: [{ address: "192.0.2.1", first: 100, last: 145 }],
          lastGeneralQuery: 145,
        },
      }),
      profile("p2", [flow("239.1.1.1")]),
    ]);
    expect(flagsOf(rows, "239.1.1.1")).toEqual(["leave-without-query"]);
  });

  it("multiple-query-senders", () => {
    const rows = deriveGroupRows([
      profile("p1", [igmp("239.1.1.1"), igmp("239.1.1.2")], {
        queries: {
          querySenders: [
            { address: "192.0.2.1", first: 100, last: 110 },
            { address: "192.0.2.2", first: 120, last: 130 },
          ],
        },
      }),
      profile("p3", [igmp("239.1.1.3", { profile: "p3" })], {
        queries: {
          querySenders: [
            { address: "192.0.2.1", first: 100, last: 110 },
            { address: "192.0.2.1", first: 120, last: 130 },
          ],
        },
      }),
      profile("p2", [flow("239.1.1.1"), flow("239.1.1.2"), flow("239.1.1.3")]),
    ]);
    expect(flagsOf(rows, "239.1.1.1")).toEqual(["multiple-query-senders"]);
    expect(flagsOf(rows, "239.1.1.2")).toEqual(["multiple-query-senders"]);
    expect(flagsOf(rows, "239.1.1.3")).toEqual([]);
  });

  it("partial coverage flags every group", () => {
    const rows = deriveGroupRows([
      profile("p1", [igmp("239.1.1.1")]),
      profile("p2", [flow("239.1.1.1")], { state: "complete" }),
      profile("p3", [], { state: "blocked" }),
    ]);
    expect(flagsOf(rows, "239.1.1.1")).toEqual(["coverage-partial"]);

    const capped = deriveGroupRows([
      profile("p1", [igmp("239.1.1.1")], { state: "partial" }),
      profile("p2", [flow("239.1.1.2")]),
    ]);
    expect(flagsOf(capped, "239.1.1.1")).toEqual([
      "interest-no-sender",
      "coverage-partial",
    ]);
    expect(flagsOf(capped, "239.1.1.2")).toEqual([
      "sender-no-interest",
      "coverage-partial",
    ]);
  });

  it("new-since-previous", () => {
    const current = [
      profile("p1", [igmp("239.1.1.1"), igmp("239.1.1.2")]),
      profile("p2", [flow("239.1.1.1"), flow("239.1.1.2")]),
    ];
    expect(flagsOf(deriveGroupRows(current), "239.1.1.2")).toEqual([]);
    const unavailable = deriveGroupRows(current, "unavailable");
    expect(unavailable.map((row) => row.flags)).toEqual([[], []]);
    const rows = deriveGroupRows(current, [profile("p2", [flow("239.1.1.1")])]);
    expect(flagsOf(rows, "239.1.1.1")).toEqual([]);
    expect(flagsOf(rows, "239.1.1.2")).toEqual(["new-since-previous"]);
  });

  it("unions flags across profiles once each, in declaration order", () => {
    const queries = {
      querySenders: [
        { address: "192.0.2.1", first: 100, last: 110 },
        { address: "192.0.2.2", first: 120, last: 130 },
      ],
    };
    const rows = deriveGroupRows(
      [
        profile("p1", [igmp("239.1.1.1", { leaves: 1, lastLeave: 140 })], {
          queries,
        }),
        profile(
          "p3",
          [igmp("239.1.1.1", { profile: "p3", leaves: 1, lastLeave: 141 })],
          { queries, state: "partial" },
        ),
      ],
      [],
    );
    expect(rows).toHaveLength(1);
    expect(rows[0].summaries).toHaveLength(2);
    expect(rows[0].flags).toEqual([
      "interest-no-sender",
      "new-since-previous",
      "leave-without-query",
      "multiple-query-senders",
      "coverage-partial",
    ]);
  });

  it("rows sort problem-first", () => {
    const rows = deriveGroupRows([
      profile("p1", [
        igmp("239.1.1.4", { lastSeen: 120 }),
        igmp("239.1.1.3", { lastSeen: 190 }),
        igmp("239.1.1.2", { lastSeen: 190 }),
        igmp("239.1.1.1", { lastSeen: 110 }),
        igmp("239.1.1.5", { lastSeen: 199, leaves: 1, lastLeave: 140 }),
      ]),
      profile("p2", [
        flow("239.1.1.1", { lastSeen: 195 }),
        flow("239.1.1.6", { lastSeen: 199 }),
      ]),
    ]);
    expect(rows.map((row) => row.group)).toEqual([
      "239.1.1.5",
      "239.1.1.6",
      "239.1.1.2",
      "239.1.1.3",
      "239.1.1.4",
      "239.1.1.1",
    ]);
  });
});
