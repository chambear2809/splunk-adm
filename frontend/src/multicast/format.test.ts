import { describe, expect, it } from "vitest";
import type { FlowGroupSummary, ProfileSummary } from "./contract";
import { cappedNotice, emptyScopeNotice, flowEvidenceLine } from "./format";

function flow(overrides: Partial<FlowGroupSummary> = {}): FlowGroupSummary {
  return {
    kind: "flow",
    profile: "flow-a",
    group: "239.1.1.1",
    observer: "spine-b",
    direction: "ingress",
    senders: ["198.51.100.5"],
    packets: 1200,
    bytes: 1300000,
    samplingInterval: 100,
    replication: "before",
    counters: "delta",
    firstSeen: 100,
    lastSeen: 150,
    ...overrides,
  };
}

function profileSummary(
  overrides: Omit<Partial<ProfileSummary>, "outcome"> & {
    outcome?: Partial<ProfileSummary["outcome"]>;
  } = {},
): ProfileSummary {
  return {
    summaries: [],
    droppedGroups: 1,
    ...overrides,
    outcome: {
      source: "multicast_igmp",
      profile: "igmp-a",
      state: "partial",
      ...overrides.outcome,
    },
  };
}

describe("flowEvidenceLine", () => {
  it("keeps every exporter's counters on its own line with their meaning", () => {
    expect(flowEvidenceLine(flow())).toBe(
      "spine-b · ingress: 1,200 packets, 1,300,000 bytes · sampling 1:100 · before replication · delta counters",
    );
    expect(
      flowEvidenceLine(
        flow({
          observer: "leaf-a",
          direction: "egress",
          samplingInterval: 1,
          replication: "after",
          counters: "total",
        }),
      ),
    ).toBe(
      "leaf-a · egress: 1,200 packets, 1,300,000 bytes · sampling 1:1 · after replication · total counters",
    );
  });

  it("reports an unknown replication position and missing counts", () => {
    expect(flowEvidenceLine(flow({ replication: "unknown" }))).toContain(
      "· replication unknown ·",
    );
    expect(
      flowEvidenceLine(flow({ packets: undefined, bytes: undefined })),
    ).toBe(
      "spine-b · ingress: counts not reported · sampling 1:100 · before replication · delta counters",
    );
    expect(flowEvidenceLine(flow({ bytes: undefined }))).toContain(
      "counts not reported",
    );
  });
});

describe("cappedNotice", () => {
  it("reports the profile's own reason instead of claiming the limit", () => {
    expect(
      cappedNotice(
        profileSummary({
          droppedGroups: 12,
          outcome: { detail: "Group summary was capped. Coverage is partial." },
        }),
      ),
    ).toBe(
      "12 groups not shown for igmp-a. Group summary was capped. Coverage is partial.",
    );
    expect(cappedNotice(profileSummary({ droppedGroups: 1 }))).toBe(
      "1 group not shown for igmp-a.",
    );
    expect(
      cappedNotice(
        profileSummary({ droppedGroups: 2, outcome: { profile: undefined } }),
      ),
    ).toBe("2 groups not shown for multicast_igmp.");
  });
});

describe("emptyScopeNotice", () => {
  it("does not read as absence when no source completed", () => {
    const blocked = emptyScopeNotice([
      profileSummary({ outcome: { state: "blocked" } }),
      profileSummary({ outcome: { state: "unavailable" } }),
    ]);
    expect(blocked).toContain("No source in this scope completed its search");
    expect(blocked).not.toMatch(/no (caller-visible )?multicast groups/i);
    expect(emptyScopeNotice([])).toBe(blocked);
  });

  it("qualifies an empty result when a source did complete", () => {
    expect(
      emptyScopeNotice([
        profileSummary({ outcome: { state: "blocked" } }),
        profileSummary({ outcome: { state: "complete" } }),
      ]),
    ).toBe(
      "No caller-visible multicast groups in this window. This does not establish that none exist.",
    );
  });
});
