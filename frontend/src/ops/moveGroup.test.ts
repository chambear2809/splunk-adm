import { describe, expect, it } from "vitest";
import {
  DEFAULT_RULES,
  PLANNER_LIMITS,
  SHARED_PORT_CATALOG,
  UNASSIGNED,
  compareAddress,
  nearestRank,
  parseCustomPorts,
  parseSeedLines,
  planMoveGroups,
  type PlannerConversation,
  type PlannerInput,
} from "./moveGroup";

const conv = (
  client: string,
  server: string,
  port: number,
  extra: Partial<PlannerConversation> = {},
): PlannerConversation => ({
  client,
  server,
  port,
  transport: "tcp",
  directed: true,
  records: 10,
  bytes: 1000,
  first: 100,
  last: 200,
  observers: ["stream:leaf-101"],
  observersCapped: false,
  sources: ["stream"],
  sampled: false,
  ...extra,
});

// web1 → app1 → db1 (orders); web2 → app2 (billing); app1 → app2 cross-app;
// everyone uses dns1 for DNS.
const estate: PlannerConversation[] = [
  conv("10.0.0.1", "10.0.1.1", 8080),
  conv("10.0.1.1", "10.0.2.1", 5432, { records: 50, bytes: 9000 }),
  conv("10.1.0.1", "10.1.1.1", 8443),
  conv("10.0.1.1", "10.1.1.1", 8443, {
    records: 7,
    bytes: 700,
    first: 120,
    last: 180,
    observers: ["stream:leaf-101", "stream:leaf-102"],
  }),
  ...["10.0.0.1", "10.0.1.1", "10.0.2.1", "10.1.0.1", "10.1.1.1"].map((c) =>
    conv(c, "10.9.9.53", 53, { transport: "udp" }),
  ),
];

const input = (overrides: Partial<PlannerInput> = {}): PlannerInput => ({
  conversations: estate,
  complete: true,
  seeds: [
    { label: "Orders", addresses: ["10.0.0.1"] },
    { label: "Billing", addresses: ["10.1.0.1"] },
  ],
  rules: { ...DEFAULT_RULES, fanInPercentile: null },
  overrides: { pinnedShared: [], notShared: [], assignments: {} },
  ...overrides,
});

describe("move-group planner", () => {
  it("groups by observed conversations, stops at shared DNS and reports blockers", () => {
    const plan = planMoveGroups(input());
    expect(plan.groups.map((g) => [g.id, g.label])).toEqual([
      ["g1", "Orders"],
      ["g2", "Billing"],
    ]);
    expect(
      plan.groups[0].members.map((m) => [m.address, m.basis, m.depth]),
    ).toEqual([
      ["10.0.0.1", "seed", 0],
      ["10.0.1.1", "traversal", 1],
      ["10.0.2.1", "traversal", 2],
    ]);
    expect(plan.groups[1].members.map((m) => m.address)).toEqual([
      "10.1.0.1",
      "10.1.1.1",
    ]);
    expect(plan.shared).toEqual([
      {
        address: "10.9.9.53",
        reasons: [
          {
            kind: "port",
            port: 53,
            transport: "udp",
            service: "DNS",
            clients: 5,
          },
        ],
        basis: "inferred",
        peers: 5,
        dependentGroups: ["g1", "g2"],
      },
    ]);
    expect(plan.sharedDependencies).toHaveLength(5);
    expect(plan.blockers).toHaveLength(1);
    expect(plan.blockers[0]).toMatchObject({
      kind: "wave_blocker",
      client: "10.0.1.1",
      server: "10.1.1.1",
      port: 8443,
      clientGroup: "g1",
      serverGroup: "g2",
      records: 7,
      bytes: 700,
      first: 120,
      last: 180,
      observers: ["stream:leaf-101", "stream:leaf-102"],
    });
    expect(plan.blockerPairs).toEqual([
      {
        groups: ["g1", "g2"],
        conversations: 1,
        records: 7,
        bytes: 700,
        services: ["tcp/8443"],
        servicesCapped: false,
      },
    ]);
    expect(plan.totals.internal).toBe(3);
    expect(plan.complete).toBe(true);
  });

  it("is deterministic regardless of conversation order", () => {
    const shuffled = [...estate].reverse();
    expect(planMoveGroups(input({ conversations: shuffled }))).toEqual(
      planMoveGroups(input()),
    );
  });

  it("merges seeds that talk directly when asked", () => {
    const plan = planMoveGroups(
      input({ rules: { ...input().rules, mergeConnectedSeeds: true } }),
    );
    expect(plan.groups).toHaveLength(1);
    expect(plan.groups[0]).toMatchObject({
      id: "g1",
      label: "Orders + Billing",
      seeds: ["10.0.0.1", "10.1.0.1"],
    });
    expect(plan.blockers).toEqual([]);
  });

  it("updates blockers when a host is moved or unassigned", () => {
    const moved = planMoveGroups(
      input({
        overrides: {
          pinnedShared: [],
          notShared: [],
          assignments: { "10.0.2.1": "g2" },
        },
      }),
    );
    expect(
      moved.groups[1].members.find((m) => m.address === "10.0.2.1"),
    ).toMatchObject({ basis: "manual" });
    expect(moved.blockers.map((b) => [b.client, b.server, b.port])).toEqual([
      ["10.0.1.1", "10.0.2.1", 5432],
      ["10.0.1.1", "10.1.1.1", 8443],
    ]);
    expect(moved.blockerPairs[0]).toMatchObject({
      conversations: 2,
      records: 57,
      services: ["tcp/5432", "tcp/8443"],
    });
    const unassigned = planMoveGroups(
      input({
        overrides: {
          pinnedShared: [],
          notShared: [],
          assignments: { "10.0.2.1": UNASSIGNED },
        },
      }),
    );
    expect(unassigned.outsidePlan).toHaveLength(1);
    expect(unassigned.unplanned).toEqual([
      { address: "10.0.2.1", peers: 2, adjacentGroups: ["g1"] },
    ]);
    const unknown = planMoveGroups(
      input({
        overrides: {
          pinnedShared: [],
          notShared: [],
          assignments: { "10.0.2.1": "g9" },
        },
      }),
    );
    expect(unknown.notes.join(" ")).toContain("was ignored");
  });

  it("honours pinned shared services and not-shared overrides", () => {
    const pinned = planMoveGroups(
      input({
        overrides: {
          pinnedShared: ["10.0.2.1"],
          notShared: [],
          assignments: {},
        },
      }),
    );
    expect(pinned.shared.find((s) => s.address === "10.0.2.1")).toEqual({
      address: "10.0.2.1",
      reasons: [{ kind: "pinned" }],
      basis: "user",
      peers: 2,
      dependentGroups: ["g1"],
    });
    expect(pinned.groups[0].members.map((m) => m.address)).not.toContain(
      "10.0.2.1",
    );
    const unshared = planMoveGroups(
      input({
        overrides: {
          pinnedShared: [],
          notShared: ["10.9.9.53"],
          assignments: {},
        },
      }),
    );
    expect(unshared.shared).toEqual([]);
    expect(unshared.groups[0].members.map((m) => m.address)).toContain(
      "10.9.9.53",
    );
    // DNS reached from g1 first, so billing → DNS becomes a blocker.
    expect(unshared.blockers.some((b) => b.server === "10.9.9.53")).toBe(true);
  });

  it("drops pinned seeds and keeps detected-shared seeds with a note", () => {
    const pinnedSeed = planMoveGroups(
      input({
        overrides: {
          pinnedShared: ["10.1.0.1"],
          notShared: [],
          assignments: {},
        },
      }),
    );
    expect(pinnedSeed.groups[1].seeds).toEqual([]);
    expect(pinnedSeed.notes.join(" ")).toContain("pinned as a shared service");
    const dnsSeed = planMoveGroups(
      input({ seeds: [{ label: "Infra", addresses: ["10.9.9.53"] }] }),
    );
    expect(dnsSeed.groups[0].members[0]).toMatchObject({
      address: "10.9.9.53",
      basis: "seed",
      sharedMatch: [{ kind: "port", port: 53 }],
    });
    expect(dnsSeed.notes.join(" ")).toContain("chosen as a seed");
  });

  it("requires a minimum number of distinct clients and observed direction for port rules", () => {
    const few = planMoveGroups(
      input({ rules: { ...input().rules, minPortClients: 6 } }),
    );
    expect(few.shared).toEqual([]);
    const undirected = planMoveGroups(
      input({
        conversations: estate.map((c) =>
          c.port === 53 ? { ...c, directed: false } : c,
        ),
      }),
    );
    expect(undirected.shared).toEqual([]);
    expect(undirected.notes.join(" ")).toContain("no observed direction");
  });

  it("detects highly connected hosts by nearest-rank fan-in percentile", () => {
    const hub = "10.5.5.5";
    const spokes = Array.from({ length: 12 }, (_, i) =>
      conv(`10.6.0.${i + 1}`, hub, 9000),
    );
    const plan = planMoveGroups(
      input({
        conversations: [...spokes, conv("10.6.0.1", "10.6.1.1", 22)],
        seeds: [{ label: "A", addresses: ["10.6.0.1"] }],
        rules: {
          ...DEFAULT_RULES,
          sharedPorts: [],
          fanInPercentile: 95,
          minFanIn: 10,
        },
      }),
    );
    expect(plan.fanInThreshold).toBe(12);
    expect(plan.shared[0]).toMatchObject({
      address: hub,
      reasons: [{ kind: "fan_in", peers: 12, threshold: 12, percentile: 95 }],
    });
    expect(plan.groups[0].members.map((m) => m.address)).toEqual([
      "10.6.0.1",
      "10.6.1.1",
    ]);
    const guarded = planMoveGroups(
      input({
        rules: {
          ...DEFAULT_RULES,
          sharedPorts: [],
          fanInPercentile: 95,
          minFanIn: 10,
        },
      }),
    );
    expect(guarded.shared).toEqual([]);
  });

  it("flags depth, connection and size limits", () => {
    const depth = planMoveGroups(
      input({ rules: { ...input().rules, maxDepth: 1 } }),
    );
    expect(
      depth.groups[0].members.map((m) => [m.address, m.expansion]),
    ).toEqual([
      ["10.0.0.1", "expanded"],
      ["10.0.1.1", "depth_limit"],
    ]);
    const connections = planMoveGroups(
      input({ rules: { ...input().rules, maxConnections: 2 } }),
    );
    expect(
      connections.groups[0].members.find((m) => m.address === "10.0.1.1"),
    ).toMatchObject({ expansion: "connection_limit" });
    const size = planMoveGroups(
      input({ rules: { ...input().rules, maxGroupSize: 2 } }),
    );
    expect(size.groups[0].sizeCapped).toBe(true);
    expect(size.groups[0].members).toHaveLength(2);
    expect(size.notes.join(" ")).toContain("size limit");
  });

  it("labels incomplete and sampled input and caps edge lists", () => {
    const many = Array.from({ length: PLANNER_LIMITS.edgeList + 5 }, (_, i) =>
      conv("10.0.0.1", `10.2.${Math.floor(i / 250)}.${i % 250}`, 443, {
        sampled: i === 0,
      }),
    );
    const plan = planMoveGroups(
      input({
        conversations: many,
        complete: false,
        seeds: [{ label: "A", addresses: ["10.0.0.1"] }],
        rules: { ...input().rules, maxDepth: 0 },
      }),
    );
    expect(plan.notes[0]).toContain("capped or incomplete");
    expect(plan.notes.join(" ")).toContain("sampled");
    expect(plan.outsidePlan).toHaveLength(PLANNER_LIMITS.edgeList);
    expect(plan.totals.outsidePlan).toBe(PLANNER_LIMITS.edgeList + 5);
    expect(plan.truncated.outsidePlan).toBe(true);
  });

  it("rejects invalid rules and input", () => {
    expect(() =>
      planMoveGroups(input({ rules: { ...DEFAULT_RULES, maxDepth: 7 } })),
    ).toThrow("Invalid move-group rules.");
    expect(() =>
      planMoveGroups(
        input({ rules: { ...DEFAULT_RULES, fanInPercentile: 100 } }),
      ),
    ).toThrow("Invalid move-group rules.");
    expect(() => planMoveGroups(input({ seeds: [] }))).toThrow(
      "Invalid move-group input.",
    );
    expect(() =>
      planMoveGroups(input({ conversations: [conv("10.0.0.1", "x;drop", 1)] })),
    ).toThrow("Invalid move-group conversation.");
  });
});

describe("move-group parsing helpers", () => {
  const identity = (value: string) => {
    if (!/^[0-9a-f.:]+$/i.test(value)) throw new Error("bad address");
    return value.toLowerCase();
  };
  it("parses labelled and bare seed lines including IPv6", () => {
    expect(
      parseSeedLines("Orders = 10.0.0.1, 10.0.0.2\nfd00::1\n\n", identity),
    ).toEqual([
      { label: "Orders", addresses: ["10.0.0.1", "10.0.0.2"] },
      { label: "Group 2", addresses: ["fd00::1"] },
    ]);
    expect(() => parseSeedLines("", identity)).toThrow("at least one");
    expect(() => parseSeedLines("x = not-an-ip", identity)).toThrow();
    expect(() => parseSeedLines("Empty =", identity)).toThrow(
      "needs an address",
    );
  });
  it("parses custom shared ports strictly", () => {
    expect(parseCustomPorts("tcp/1556, UDP/514")).toEqual([
      { transport: "tcp", port: 1556 },
      { transport: "udp", port: 514 },
    ]);
    expect(() => parseCustomPorts("1556")).toThrow("transport/port");
    expect(() => parseCustomPorts("tcp/70000")).toThrow();
  });
  it("orders addresses and percentiles deterministically", () => {
    expect(
      ["10.0.0.10", "fd00::1", "10.0.0.9", "9.0.0.1"].sort(compareAddress),
    ).toEqual(["9.0.0.1", "10.0.0.9", "10.0.0.10", "fd00::1"]);
    expect(nearestRank([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 95)).toBe(10);
    expect(nearestRank([1, 2, 3, 4, 5, 6, 7, 8, 9, 10], 90)).toBe(9);
  });
  it("documents every catalogue port with a primary reference", () => {
    for (const rule of SHARED_PORT_CATALOG)
      expect(rule.reference).toMatch(/^https:\/\//);
    expect(DEFAULT_RULES.sharedPorts).toContainEqual({
      port: 3268,
      transport: "tcp",
    });
    expect(DEFAULT_RULES.sharedPorts).not.toContainEqual({
      port: 445,
      transport: "tcp",
    });
  });
});
