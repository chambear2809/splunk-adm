import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import type {
  FlowGroupSummary,
  FlowProfile,
  IgmpGroupSummary,
  IgmpProfile,
  MulticastConfiguration,
  ProfileSummary,
  SourceOutcome,
} from "./contract";
import { deriveGroupRows } from "./flags";
import { MatrixView } from "./MatrixView";
import { OverviewView } from "./OverviewView";
import type { ScopeOverviewResult } from "./scopeOverview";
import { MULTICAST_TERMS } from "./terms";

const FORBIDDEN = /deliver|member(ship)?|joined|elected/i;

const base = {
  scope: "fabric-a",
  index: "stream",
  validFrom: 0,
  validUntil: 10000,
};
const igmpProfile = (id: string, vlan: string): IgmpProfile => ({
  ...base,
  id,
  source: "multicast_igmp",
  observer: "leaf-a",
  captureInterface: "eth1",
  segment: { kind: "vlan", id: vlan, domain: "dc1" },
  placement: "endpoint",
  endpointReporters: [],
  proxyReporters: [],
  v3Encoding: "flat-counted",
});
const flowProfile: FlowProfile = {
  ...base,
  id: "flow-a",
  source: "multicast_netflow",
  observer: "spine-b",
  observationDomain: "1",
  template: "256",
  direction: "ingress",
  samplingInterval: 100,
  replication: "before",
  counters: "delta",
};
const configuration: MulticastConfiguration = {
  fingerprint: "verified",
  // Flow first: the Matrix must still put IGMP columns first.
  profiles: [
    flowProfile,
    igmpProfile("igmp-a", "10"),
    igmpProfile("igmp-b", "20"),
  ],
};

function igmp(
  group: string,
  overrides: Partial<IgmpGroupSummary> = {},
): IgmpGroupSummary {
  return {
    kind: "igmp",
    profile: "igmp-a",
    group,
    segment: { kind: "vlan", id: "10", domain: "dc1" },
    reports: 2,
    leaves: 0,
    groupQueries: 1,
    endpointReporters: ["192.0.2.10"],
    otherReporters: 3,
    firstSeen: 1100,
    lastSeen: 1900,
    ...overrides,
  };
}
function flow(
  group: string,
  overrides: Partial<FlowGroupSummary> = {},
): FlowGroupSummary {
  return {
    kind: "flow",
    profile: "flow-a",
    group,
    observer: "spine-b",
    direction: "ingress",
    senders: ["198.51.100.5"],
    packets: 10,
    bytes: 1000,
    samplingInterval: 100,
    replication: "before",
    counters: "delta",
    firstSeen: 1200,
    lastSeen: 1500,
    ...overrides,
  };
}
function profile(
  id: string,
  source: SourceOutcome["source"],
  summaries: ProfileSummary["summaries"],
  state: SourceOutcome["state"] = "complete",
  droppedGroups = 0,
): ProfileSummary {
  return {
    summaries,
    droppedGroups,
    outcome: { source, profile: id, state },
  };
}
function scope(
  profiles: ProfileSummary[],
  overrides: Partial<ScopeOverviewResult> = {},
): ScopeOverviewResult {
  return {
    version: 1,
    window: { version: 1, scope: "fabric-a", earliest: 1000, latest: 2000 },
    profiles,
    rows: deriveGroupRows(profiles),
    comparison: { state: "not-run" },
    capturedAt: 2000,
    configurationFingerprint: "verified",
    ...overrides,
  };
}

const noop = () => undefined;
const overview = (result: ScopeOverviewResult) =>
  renderToStaticMarkup(
    <OverviewView
      result={result}
      onSelectGroup={noop}
      onCompare={noop}
      comparing={false}
      timezone="UTC"
    />,
  );
const matrix = (result: ScopeOverviewResult) =>
  renderToStaticMarkup(
    <MatrixView
      result={result}
      configuration={configuration}
      onSelectCell={noop}
    />,
  );

const mixed = scope([
  profile("igmp-a", "multicast_igmp", [
    igmp("239.1.1.1"),
    igmp("239.1.1.2", { reports: 1, lastSeen: 1500 }),
  ]),
  profile("flow-a", "multicast_netflow", [
    flow("239.1.1.1", {
      senders: ["198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.100.4"],
    }),
  ]),
]);

describe("multicast views", () => {
  it("overview lists problem rows first with flag labels", () => {
    const html = overview(mixed);
    expect(html.indexOf("239.1.1.2")).toBeLessThan(html.indexOf("239.1.1.1"));
    expect(html).toContain("Interest, no sender seen");
    expect(html).toContain('aria-label="About Interest, no sender seen"');
    expect(html).toContain(MULTICAST_TERMS["interest-no-sender"]);
    expect(html).toContain("198.51.100.3");
    expect(html).not.toContain("198.51.100.4");
    expect(html).toContain("+1 more");
    expect(html).toContain("192.0.2.10");
    expect(html).toContain("+3 other reports");
    expect(html).toContain("10 packets");
    expect(html).toContain("1,000 bytes");
    expect(html).toContain("sampling 1:100");
    expect(html).toContain("before replication");
    expect(html).toContain("Compare with previous window");
  });
  it("overview reports missing counts and unavailable comparison", () => {
    const html = overview(
      scope(
        [
          profile("flow-a", "multicast_netflow", [
            flow("239.1.1.1", { packets: undefined, bytes: undefined }),
          ]),
        ],
        { comparison: { state: "unavailable", reason: "No earlier source." } },
      ),
    );
    expect(html).toContain("counts not reported");
    expect(html).toContain("Comparison unavailable: No earlier source.");
  });
  it("overview shows the cap notice", () => {
    const html = overview(
      scope([
        profile("igmp-a", "multicast_igmp", [igmp("239.1.1.1")], "partial", 12),
      ]),
    );
    expect(html).toContain(
      "12 groups not shown: the group limit was reached for igmp-a.",
    );
  });
  it("overview empty state does not claim absence", () => {
    const html = overview(scope([profile("igmp-a", "multicast_igmp", [])]));
    expect(html).toContain(
      "No caller-visible multicast groups in this window. This does not establish that none exist.",
    );
  });
  it("failed profile column reads not covered", () => {
    const html = matrix(
      scope([
        profile("igmp-a", "multicast_igmp", [igmp("239.1.1.1")]),
        profile("igmp-b", "multicast_igmp", [], "blocked"),
        profile("flow-a", "multicast_netflow", [flow("239.1.1.1")]),
      ]),
    );
    expect(html).toContain(
      'aria-label="239.1.1.1 at vlan 20 · dc1: Not covered"',
    );
    expect(html.indexOf("vlan 10 · dc1")).toBeLessThan(
      html.indexOf("spine-b · ingress"),
    );
    expect(html.indexOf("vlan 20 · dc1")).toBeLessThan(
      html.indexOf("spine-b · ingress"),
    );
  });
  it("partial profile with summaries still reads not covered", () => {
    const html = matrix(
      scope([
        profile("igmp-a", "multicast_igmp", [igmp("239.1.1.1")], "partial", 3),
      ]),
    );
    expect(html).toContain(
      'aria-label="239.1.1.1 at vlan 10 · dc1: Not covered"',
    );
  });
  it("matrix has no both state", () => {
    const html = matrix(mixed);
    expect(html).toContain(
      'aria-label="239.1.1.1 at vlan 10 · dc1: Receiver interest"',
    );
    expect(html).toContain(
      'aria-label="239.1.1.1 at spine-b · ingress: Sender traffic"',
    );
    expect(html).toContain(
      'aria-label="239.1.1.2 at spine-b · ingress: None observed"',
    );
    expect(html).not.toMatch(/both/i);
    expect(html).not.toContain("vlan 20");
    expect(html).toMatch(
      /class="[^"]*recent[^"]*"[^>]*aria-label="239\.1\.1\.1 at vlan 10/,
    );
    expect(html).toMatch(
      /class="[^"]*older[^"]*"[^>]*aria-label="239\.1\.1\.1 at spine-b/,
    );
  });
  it("no forbidden words", () => {
    const flagged = scope(
      [
        profile("igmp-a", "multicast_igmp", [
          igmp("239.1.1.3", { lastLeave: 1800 }),
        ]),
        profile("igmp-b", "multicast_igmp", [], "partial"),
        profile("flow-a", "multicast_netflow", [flow("239.1.1.4")]),
      ],
      { comparison: { state: "unavailable", reason: "x" } },
    );
    for (const html of [
      overview(mixed),
      overview(flagged),
      overview(scope([])),
      matrix(mixed),
      matrix(flagged),
    ])
      expect(html).not.toMatch(FORBIDDEN);
    for (const text of Object.values(MULTICAST_TERMS))
      expect(text).not.toMatch(FORBIDDEN);
    expect(MULTICAST_TERMS["leave-without-query"]).toBe(
      "Leave without query: a leave was observed with no later query from that capture in this window. It may be normal; it is an evidence gap, not a fault.",
    );
  });
});
