import { describe, expect, it } from "vitest";
import {
  aciContractDraft,
  ciliumPolicyDraft,
  firewallCsvDraft,
  FIREWALL_COLUMNS,
  networkPolicyDraft,
} from "./drafts";
import {
  RULESET_SCHEMA,
  type Rule,
  type RuleSet,
  type Selector,
} from "./model";
import { T, testGraph } from "./testGraph";

const context = {
  window: { start: "2026-11-20T11:00:00Z", end: "2026-11-20T12:00:00Z" },
  scope: "prod · c1 · shop · checkout",
};
const k8s = (
  namespace: string,
  workload?: string,
  cluster = "c1",
): Selector => ({
  kind: "k8s",
  cluster,
  namespace,
  ...(workload ? { workload } : {}),
});
const epg = (ap: string, name: string, tenant = "shop"): Selector => ({
  kind: "epg",
  tenant,
  appProfile: ap,
  epg: name,
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

describe("Kubernetes NetworkPolicy draft", () => {
  it("emits ingress on the destination and egress on the source, labelled DRAFT", () => {
    const draft = networkPolicyDraft(
      set(
        rule({ id: "fe-co" }),
        rule({
          id: "co-ext",
          source: k8s("shop", "checkout"),
          destination: { kind: "cidr", cidr: "203.0.113.0/24" },
          ports: { from: 443, to: 444 },
        }),
        rule({ id: "deny", action: "deny" }),
        rule({
          id: "epg",
          source: epg("clients", "win"),
          destination: epg("orders", "db"),
        }),
        rule({ id: "xcluster", destination: k8s("shop", "checkout", "c2") }),
      ),
      context,
    );
    const text = draft.text;
    expect(text.split("\n")[0]).toMatch(/^# DRAFT Kubernetes NetworkPolicy/);
    expect(text).toContain("NOT APPLIED");
    expect(text).toContain("kind: NetworkPolicy");
    expect(text).toContain('kubernetes.io/metadata.name: "shop"');
    expect(text).toMatch(/policyTypes:\n {2}- Ingress\n {2}- Egress/);
    expect(text).toContain('cidr: "203.0.113.0/24"');
    expect(text).toContain("port: 443\n      endPort: 444");
    expect(text).toContain("# VERIFY label");
    expect(draft.included).toBe(2);
    expect(draft.skipped.map((s) => s.rule).sort()).toEqual([
      "deny",
      "epg",
      "xcluster",
    ]);
    expect(text).toMatch(/deny: Kubernetes NetworkPolicy has no deny rules/);
    expect(text).not.toMatch(/kubectl|apply -f/);
  });

  it("selects every pod in a namespace only when the selector has no workload", () => {
    const draft = networkPolicyDraft(
      set(rule({ id: "ns", destination: k8s("ops") })),
      context,
    );
    expect(draft.text).toContain(
      "podSelector: {} # every pod in the namespace",
    );
  });
});

describe("CiliumNetworkPolicy draft", () => {
  it("emits allow and deny sections and skips SCTP", () => {
    const draft = ciliumPolicyDraft(
      set(
        rule({ id: "fe-co" }),
        rule({
          id: "deny-ops",
          action: "deny",
          source: k8s("ops"),
          ports: { from: 9090, to: 9100 },
        }),
        rule({
          id: "ext",
          source: k8s("shop", "checkout"),
          destination: { kind: "cidr", cidr: "203.0.113.40/32" },
          ports: { from: 443, to: 443 },
        }),
        rule({ id: "sctp", protocol: "sctp" }),
      ),
      context,
    );
    const text = draft.text;
    expect(text).toContain("kind: CiliumNetworkPolicy");
    expect(text).toContain('"k8s:io.kubernetes.pod.namespace": "shop"');
    expect(text).toContain("ingressDeny:");
    expect(text).toContain('- port: "9090"\n        endPort: 9100');
    expect(text).toContain('- toCIDR:\n    - "203.0.113.40/32"');
    expect(text).toContain("per-endpoint PolicyAuditMode");
    expect(text).not.toContain("enable-policy-audit-mode");
    expect(draft.skipped).toEqual([
      { rule: "sctp", reason: expect.stringMatching(/SCTP is not emitted/) },
    ]);
  });
});

describe("ACI contract draft", () => {
  it("builds APIC filter, contract, subject and EPG relations inside a draft wrapper", () => {
    const draft = aciContractDraft(
      set(
        rule({
          id: "win-db",
          source: epg("clients", "win-clients"),
          destination: epg("orders", "db"),
          ports: { from: 5432, to: 5432 },
        }),
        rule({
          id: "win-db-deny",
          action: "deny",
          source: epg("clients", "win-clients"),
          destination: epg("orders", "db"),
          ports: { from: 22, to: 22 },
        }),
        rule({
          id: "conflict",
          action: "deny",
          source: epg("clients", "win-clients"),
          destination: epg("orders", "db"),
          ports: { from: 5432, to: 5432 },
        }),
        rule({
          id: "xt",
          source: epg("a", "b", "other"),
          destination: epg("orders", "db"),
        }),
        rule({
          id: "esg",
          source: { kind: "esg", tenant: "shop", esg: "pci" },
          destination: epg("orders", "db"),
        }),
        rule({ id: "k8s" }),
      ),
      context,
    );
    const doc = JSON.parse(draft.text);
    expect(doc.atlasDraft.status).toMatch(/^DRAFT/);
    expect(doc.atlasDraft.notice.join(" ")).toMatch(/never calls the APIC API/);
    const tenant = doc.apicPayload[0].fvTenant;
    expect(tenant.attributes).toEqual({ name: "shop" });
    const filters = tenant.children.filter((c: object) => "vzFilter" in c);
    expect(
      filters.map(
        (f: { vzFilter: { attributes: { name: string } } }) =>
          f.vzFilter.attributes.name,
      ),
    ).toEqual(["atlas-tcp-22", "atlas-tcp-5432"]);
    expect(filters[1].vzFilter.children[0].vzEntry.attributes).toEqual({
      name: "e-tcp-5432",
      etherT: "ip",
      prot: "tcp",
      dFromPort: "5432",
      dToPort: "5432",
    });
    const contract = tenant.children.find((c: object) => "vzBrCP" in c).vzBrCP;
    expect(contract.attributes).toEqual({
      name: "atlas-win-clients-to-db",
      scope: "context",
    });
    const subject = contract.children[0].vzSubj;
    expect(subject.attributes.revFltPorts).toBe("yes");
    expect(
      subject.children.map(
        (c: { vzRsSubjFiltAtt: { attributes: object } }) =>
          c.vzRsSubjFiltAtt.attributes,
      ),
    ).toEqual([
      { tnVzFilterName: "atlas-tcp-5432", action: "permit" },
      { tnVzFilterName: "atlas-tcp-22", action: "deny" },
    ]);
    const aps = tenant.children
      .filter((c: object) => "fvAp" in c)
      .map((c: { fvAp: unknown }) => c.fvAp);
    expect(JSON.stringify(aps)).toContain(
      '"fvRsCons":{"attributes":{"tnVzBrCPName":"atlas-win-clients-to-db"}}',
    );
    expect(JSON.stringify(aps)).toContain(
      '"fvRsProv":{"attributes":{"tnVzBrCPName":"atlas-win-clients-to-db"}}',
    );
    expect(draft.skipped.map((s) => s.rule).sort()).toEqual([
      "conflict",
      "esg",
      "k8s",
      "xt",
    ]);
  });

  it("keeps generated APIC names within 64 characters", () => {
    const long = "e".repeat(60);
    const draft = aciContractDraft(
      set(
        rule({
          id: "l",
          source: epg("ap", long),
          destination: epg("ap", long),
        }),
      ),
      context,
    );
    const name = JSON.parse(draft.text).apicPayload[0].fvTenant.children.find(
      (c: object) => "vzBrCP" in c,
    ).vzBrCP.attributes.name as string;
    expect(name.length).toBeLessThanOrEqual(64);
  });
});

describe("firewall CSV draft", () => {
  it("lists draft rows with observed addresses and neutralizes spreadsheet formulas", () => {
    const graph = testGraph();
    const draft = firewallCsvDraft(
      set(
        rule({
          id: "win-db",
          source: epg("clients", "win-clients"),
          destination: epg("orders", "db"),
          ports: { from: 5432, to: 5432 },
        }),
        rule({
          id: "cidr",
          source: { kind: "cidr", cidr: "10.0.0.0/8" },
          destination: { kind: "endpoint", nodeId: "=HYPERLINK(1)" },
        }),
        rule({
          id: "esg",
          source: { kind: "esg", tenant: "shop", esg: "pci" },
          destination: { kind: "endpoint", nodeId: T.db },
        }),
      ),
      graph,
    );
    const lines = draft.text.trim().split("\r\n");
    expect(lines[0]).toBe(FIREWALL_COLUMNS.join(","));
    expect(lines[1]).toMatch(/^DRAFT,win-db,allow,tcp,5432,5432,/);
    expect(lines[1]).toContain("10.30.40.25");
    expect(lines[1]).toContain("10.20.30.40");
    expect(lines[2]).toContain("10.0.0.0/8");
    expect(lines[2]).not.toMatch(/,=HYPERLINK/);
    expect(lines[2]).toContain("fill manually");
    expect(lines[3]).toContain("ESG membership is not evaluated");
  });
});
