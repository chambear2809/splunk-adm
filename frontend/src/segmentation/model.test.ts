import { describe, expect, it } from "vitest";
import { demoGraph } from "../data/demoClient";
import { parseGraph } from "../graph";
import {
  conversations,
  coverageSummary,
  evaluateConversation,
  evaluationContext,
  graphCompleteness,
  matchSelector,
  MAX_RULES,
  parseCidr,
  parseRuleSet,
  parseRuleSetText,
  replay,
  replayWindowError,
  RULESET_SCHEMA,
  seedRuleSet,
  serializeRuleSet,
  TOP_BLOCKED_LIMIT,
  type Rule,
  type RuleSet,
  type Selector,
} from "./model";
import { T, testGraph } from "./testGraph";

const k8s = (namespace: string, workload?: string): Selector => ({
  kind: "k8s",
  cluster: "c1",
  namespace,
  ...(workload ? { workload } : {}),
});
const rule = (partial: Partial<Rule> & Pick<Rule, "id">): Rule => ({
  action: "allow",
  source: k8s("shop", "frontend"),
  destination: k8s("shop", "checkout"),
  protocol: "tcp",
  ports: { from: 8080, to: 8080 },
  ...partial,
});
const set = (...rules: Rule[]): RuleSet => ({ schema: RULESET_SCHEMA, rules });
const edge = (graph: ReturnType<typeof testGraph>, id: string) =>
  graph.edges.find((e) => e.id === id)!;

describe("rule-set parsing", () => {
  it("round-trips a valid rule set", () => {
    const value = set(
      rule({ id: "a" }),
      rule({
        id: "b",
        action: "deny",
        source: {
          kind: "epg",
          tenant: "shop",
          appProfile: "clients",
          epg: "win-clients",
        },
        destination: { kind: "cidr", cidr: "10.20.0.0/16" },
        ports: { from: 1024, to: 2048 },
      }),
    );
    const parsed = parseRuleSetText(serializeRuleSet(value));
    expect(parsed).toEqual({ ok: true, ruleSet: value });
  });

  it("fails closed on unknown fields, label selectors and malformed values", () => {
    const bad = parseRuleSet({
      schema: RULESET_SCHEMA,
      rules: [
        { ...rule({ id: "x" }), extra: 1 },
        {
          ...rule({ id: "y" }),
          source: {
            kind: "k8s",
            cluster: "c1",
            namespace: "shop",
            labels: { app: "a" },
          },
        },
        {
          ...rule({ id: "z" }),
          destination: { kind: "cidr", cidr: "10.0.0.1/24" },
        },
        {
          ...rule({ id: "v6" }),
          destination: { kind: "cidr", cidr: "2001:db8::/32" },
        },
        { ...rule({ id: "p" }), ports: { from: 90, to: 80 } },
        { ...rule({ id: "proto" }), protocol: "icmp" },
        { ...rule({ id: "ns" }), source: k8s("Shop_Bad") },
        {
          ...rule({ id: "nl" }),
          source: { kind: "application", service: "a\nb", environment: "prod" },
        },
        rule({ id: "dup" }),
        rule({ id: "dup" }),
      ],
    });
    expect(bad.ok).toBe(false);
    const errors = (bad as { errors: string[] }).errors.join("\n");
    expect(errors).toMatch(/unsupported field "extra"/);
    expect(errors).toMatch(/pod labels are not collected/);
    expect(errors).toMatch(/host bits set/);
    expect(errors).toMatch(/IPv6 CIDR/);
    expect(errors).toMatch(/from ≤ to/);
    expect(errors).toMatch(/tcp, udp or sctp/);
    expect(errors).toMatch(/valid Kubernetes namespace/);
    expect(errors).toMatch(/service and environment/);
    expect(errors).toMatch(/dup is duplicated/);
  });

  it("rejects wrong schema, invalid JSON, oversized sets", () => {
    expect(parseRuleSet({ schema: "v0", rules: [] }).ok).toBe(false);
    expect(parseRuleSetText("{").ok).toBe(false);
    const many = Array.from({ length: MAX_RULES + 1 }, (_, i) =>
      rule({ id: `r${i}` }),
    );
    const result = parseRuleSet(set(...many));
    expect(result.ok).toBe(false);
  });

  it("parses strict IPv4 CIDRs only", () => {
    expect(parseCidr("10.20.0.0/16")).toEqual({
      network: 0x0a140000,
      prefix: 16,
    });
    expect(typeof parseCidr("010.0.0.0/8")).toBe("string");
    expect(typeof parseCidr("10.0.0.0/33")).toBe("string");
    expect(typeof parseCidr("10.0.0.0")).toBe("string");
  });
});

describe("selector matching is three-valued", () => {
  const graph = testGraph();
  const ctx = evaluationContext(graph);
  const node = (id: string) => ctx.nodes.get(id);

  it("resolves Kubernetes namespace and controller, never Service frontends", () => {
    expect(
      matchSelector(k8s("shop", "checkout"), node(T.checkoutPod), ctx).state,
    ).toBe("match");
    expect(
      matchSelector(k8s("shop", "frontend"), node(T.checkoutPod), ctx).state,
    ).toBe("no_match");
    expect(
      matchSelector(k8s("shop", "checkout"), node(T.otherNsPod), ctx).state,
    ).toBe("no_match");
    expect(
      matchSelector(k8s("ops", "ops"), node(T.otherNsPod), ctx),
    ).toMatchObject({
      state: "unknown",
      reason: expect.stringMatching(/controller is not recorded/),
    });
    expect(matchSelector(k8s("shop"), node(T.svcFrontend), ctx).state).toBe(
      "unknown",
    );
    expect(matchSelector(k8s("shop"), node(T.unresolved), ctx).state).toBe(
      "unknown",
    );
    expect(matchSelector(k8s("shop"), node(T.db), ctx).state).toBe("no_match");
  });

  it("uses collected EPG classification and leaves ESG and missing EPG unknown", () => {
    const epg: Selector = {
      kind: "epg",
      tenant: "shop",
      appProfile: "orders",
      epg: "db",
    };
    expect(matchSelector(epg, node(T.db), ctx).state).toBe("match");
    expect(matchSelector(epg, node(T.win), ctx).state).toBe("no_match");
    expect(matchSelector(epg, node(T.checkoutPod), ctx).state).toBe("unknown");
    expect(
      matchSelector(
        { kind: "esg", tenant: "shop", esg: "pci" },
        node(T.db),
        ctx,
      ).state,
    ).toBe("unknown");
  });

  it("matches applications only through runs_on evidence", () => {
    const app: Selector = {
      kind: "application",
      service: "checkout",
      environment: "prod",
    };
    expect(matchSelector(app, node(T.checkoutPod), ctx).state).toBe("match");
    expect(matchSelector(app, node(T.frontendPod), ctx).state).toBe("unknown");
    expect(matchSelector(app, node(T.external), ctx).state).toBe("no_match");
    expect(
      matchSelector(
        { ...app, environment: "dev" } as Selector,
        node(T.checkoutPod),
        ctx,
      ).state,
    ).toBe("no_match");
  });

  it("treats CIDR membership by every recorded address", () => {
    const cidr = (c: string): Selector => ({ kind: "cidr", cidr: c });
    expect(matchSelector(cidr("10.20.30.0/24"), node(T.db), ctx).state).toBe(
      "match",
    );
    expect(matchSelector(cidr("10.21.0.0/16"), node(T.db), ctx).state).toBe(
      "no_match",
    );
    const mixed = { ...node(T.db)!, addresses: ["10.20.30.40", "10.21.0.1"] };
    expect(matchSelector(cidr("10.20.30.0/24"), mixed, ctx).state).toBe(
      "unknown",
    );
    expect(
      matchSelector(cidr("10.20.30.0/24"), { ...mixed, addresses: [] }, ctx)
        .state,
    ).toBe("unknown");
  });
});

describe("conversation verdicts", () => {
  const graph = testGraph();
  const ctx = evaluationContext(graph);

  it("allows only what an allow rule definitely matches", () => {
    const verdict = evaluateConversation(
      set(rule({ id: "a" })),
      edge(graph, "fe-co"),
      ctx,
    );
    expect(verdict).toEqual({ outcome: "allowed", rule: "a" });
  });

  it("gives deny precedence and blocks unmatched traffic by default", () => {
    const rs = set(
      rule({ id: "a" }),
      rule({ id: "d", action: "deny", source: k8s("shop") }),
    );
    expect(evaluateConversation(rs, edge(graph, "fe-co"), ctx)).toEqual({
      outcome: "blocked",
      basis: "deny_rule",
      rule: "d",
    });
    expect(
      evaluateConversation(set(rule({ id: "a" })), edge(graph, "co-ext"), ctx),
    ).toEqual({
      outcome: "blocked",
      basis: "default_deny",
    });
  });

  it("keeps uncertain matches unknown instead of allowed or blocked", () => {
    const epgRule = rule({
      id: "e",
      source: { kind: "epg", tenant: "shop", appProfile: "web", epg: "web" },
      destination: {
        kind: "epg",
        tenant: "shop",
        appProfile: "orders",
        epg: "db",
      },
      ports: { from: 5432, to: 5432 },
    });
    const verdict = evaluateConversation(
      set(epgRule),
      edge(graph, "co-db"),
      ctx,
    );
    expect(verdict.outcome).toBe("unknown");
    const noL4 = evaluateConversation(
      set(rule({ id: "a" })),
      edge(graph, "icmp"),
      ctx,
    );
    expect(noL4.outcome).toBe("unknown");
    const reversed = {
      ...edge(graph, "fe-co"),
      direction_basis: "unknown" as const,
    };
    expect(
      evaluateConversation(set(rule({ id: "a" })), reversed, ctx).outcome,
    ).toBe("unknown");
    const maybeDeny = set(
      rule({ id: "a" }),
      rule({
        id: "d",
        action: "deny",
        source: { kind: "esg", tenant: "shop", esg: "x" },
      }),
    );
    expect(
      evaluateConversation(maybeDeny, edge(graph, "fe-co"), ctx),
    ).toMatchObject({
      outcome: "unknown",
      rule: "d",
    });
  });
});

describe("coverage by collected policy", () => {
  it("separates covered, not covered and unknown and never calls unannotated traffic allowed", () => {
    const summary = coverageSummary(testGraph());
    expect(summary.covered).toEqual({ conversations: 1, connections: 30 });
    expect(summary.notCovered).toEqual({ conversations: 1, connections: 7 });
    expect(summary.unknown.conversations).toBe(6);
    expect(summary.aclDrops).toBe(1);
    const hubble = summary.items.find((i) => i.edge.id === "fe-co")!;
    expect(hubble.state).toBe("unknown");
    expect(hubble.ciliumPolicy).toBe("not_collected");
    expect(hubble.basis).toMatch(/does not collect Cilium policy/);
  });

  it("flags a logged drop on a permitted conversation as a conflict", () => {
    const graph = testGraph();
    edge(graph, "co-db").acl_action = "drop";
    expect(coverageSummary(graph).conflicts).toBe(1);
  });

  it("matches the shipped Catalyst-to-ACI demo annotations", () => {
    const graph = demoGraph("catalyst-aci");
    const summary = coverageSummary(graph);
    const conv = conversations(graph);
    expect(summary.covered.conversations).toBe(
      conv.filter(
        (e) =>
          e.contract_basis === "intent" || e.contract_basis === "intra_epg",
      ).length,
    );
    expect(summary.notCovered.conversations).toBe(
      conv.filter((e) => e.contract_basis === "none").length,
    );
    expect(
      summary.covered.conversations +
        summary.notCovered.conversations +
        summary.unknown.conversations,
    ).toBe(conv.length);
    expect(summary.completeness.notes.join(" ")).toMatch(/Synthetic demo data/);
  });
});

describe("seeding and replay", () => {
  it("seeds exact allow rules and skips drops, unresolved and port-less traffic", () => {
    const graph = testGraph();
    const seeded = seedRuleSet(graph);
    expect(parseRuleSet(seeded.ruleSet).ok).toBe(true);
    const reasons = seeded.skipped.map((s) => s.reason).join("\n");
    expect(reasons).toMatch(/ACL drop observed/);
    expect(reasons).toMatch(/unresolved or ambiguous/);
    expect(reasons).toMatch(/No valid server port/);
    expect(seeded.ruleSet.rules.every((r) => r.ports.from === r.ports.to)).toBe(
      true,
    );
    const result = replay(graph, seeded.ruleSet);
    expect(result.topBlocked.map((b) => b.edgeId)).toContain("win-db");
    expect(result.allowed.conversations).toBe(seeded.ruleSet.rules.length);
    expect(
      result.allowed.conversations +
        result.blocked.conversations +
        result.unknown.conversations,
    ).toBe(conversations(graph).length);
    expect(result.unusedRules).toEqual([]);
  });

  it("lists the top would-be-blocked conversations with rule evidence and caps the list", () => {
    const graph = testGraph();
    const rs = set(
      rule({ id: "a" }),
      rule({
        id: "d",
        action: "deny",
        source: k8s("ops"),
        ports: { from: 9090, to: 9090 },
      }),
      rule({ id: "unused", ports: { from: 1, to: 1 } }),
    );
    const result = replay(graph, rs);
    const denied = result.topBlocked.find((b) => b.edgeId === "ops-co")!;
    expect(denied).toMatchObject({
      basis: "deny_rule",
      rule: "d",
      port: 9090,
      connections: 2,
    });
    expect(result.topBlocked[0]!.connections).toBeGreaterThanOrEqual(
      result.topBlocked.at(-1)!.connections,
    );
    expect(result.unusedRules).toEqual(["unused"]);
    expect(result.ruleHits.find((h) => h.rule === "a")).toEqual({
      rule: "a",
      conversations: 1,
      connections: 40,
    });

    const big = testGraph();
    for (let i = 0; i < TOP_BLOCKED_LIMIT + 5; i++)
      big.edges.push({ ...edge(big, "co-ext"), id: `x${i}`, count: i + 1 });
    const capped = replay(big, set());
    expect(capped.topBlocked).toHaveLength(TOP_BLOCKED_LIMIT);
    expect(capped.blockedTruncated).toBe(true);
  });

  it("seeded rules from the demo allow their own conversations", () => {
    const graph = demoGraph("catalyst-aci");
    const seeded = seedRuleSet(graph);
    const result = replay(graph, seeded.ruleSet);
    expect(result.allowed.conversations).toBeGreaterThan(0);
    const drop = conversations(graph).find((e) => e.acl_action === "drop")!;
    expect(result.topBlocked.some((b) => b.edgeId === drop.id)).toBe(true);
  });
});

describe("completeness", () => {
  it("reports truncation, partial reads and caps as incomplete", () => {
    expect(graphCompleteness(testGraph()).complete).toBe(true);
    const truncated = testGraph({
      truncation: {
        truncated: true,
        shown: { nodes: 9, edges: 9 },
        total: { nodes: 20, edges: 40 },
        ranking: "bytes",
      },
    });
    expect(graphCompleteness(truncated)).toMatchObject({ complete: false });
    expect(graphCompleteness(truncated).notes[0]).toMatch(/9 of 40/);
    expect(
      graphCompleteness(
        testGraph({ read: { coverage: 60, windowSeconds: 3600 } }),
      ).complete,
    ).toBe(false);
    const capped = testGraph();
    capped.coverage.warnings = [
      "The search listed only the first 5000 connections.",
    ];
    expect(graphCompleteness(capped).complete).toBe(false);
  });

  it("test graph is a valid snapshot", () => {
    expect(() => parseGraph(structuredClone(testGraph()))).not.toThrow();
  });
});

describe("replay window", () => {
  it("validates bounds", () => {
    expect(
      replayWindowError("2026-11-20T00:00:00Z", "2026-11-20T01:00:00Z"),
    ).toBeUndefined();
    expect(replayWindowError("x", "y")).toMatch(/absolute/);
    expect(
      replayWindowError("2026-11-20T01:00:00Z", "2026-11-20T00:00:00Z"),
    ).toMatch(/after/);
    expect(
      replayWindowError("2026-11-01T00:00:00Z", "2026-11-20T00:00:00Z"),
    ).toMatch(/7 days/);
    expect(
      replayWindowError("2099-01-01T00:00:00Z", "2099-01-01T01:00:00Z"),
    ).toMatch(/future/);
  });
});
