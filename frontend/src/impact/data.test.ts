import { describe, expect, it } from "vitest";
import { impactCsv } from "./csv";
import {
  impactMembersSearch,
  impactSearch,
  loadLiveImpact,
  memberNameNote,
  rowsToImpact,
  windowHours,
} from "./data";
import { loadDemoImpact } from "./demo";
import { failsImpact } from "./model";
import { DEFAULT_IMPACT_WINDOW, impactURL, parseImpactParams } from "./url";

describe("impact members", () => {
  it("reads members of a validated name and notes a name it cannot read", () => {
    expect(impactMembersSearch("orders-db")).toBe(
      "| `adm_impact_members(orders-db)`",
    );
    expect(impactMembersSearch("Web Tier")).toBeUndefined();
    expect(impactMembersSearch('a",b')).toBeUndefined();
    expect(memberNameNote("EPG", "Web Tier")).toContain(
      'Members of EPG "Web Tier" were not read',
    );
  });
});

describe("impact search and rows", () => {
  it("fails closed before dispatching live impact without a qualified source", async () => {
    let called = false;
    await expect(
      loadLiveImpact({
        tokens: ["leaf101"],
        client: {
          search: async () => {
            called = true;
            return { rows: [], warnings: [], errors: [] };
          },
        },
        earliest: "1000",
        latest: "1600",
        scope: "scope-a",
        signal: new AbortController().signal,
        loadBaseTopology: async () => {
          called = true;
          throw new Error("unexpected topology query");
        },
        merge: (base) => base,
      }),
    ).rejects.toThrow("Live impact analysis is unavailable");
    expect(called).toBe(false);
  });
  it("passes only validated tokens and '-' for an empty side", () => {
    expect(
      impactSearch({
        observers: ["10.110.5.2", "pod-1/node-101", 'x" OR index=*'],
        endpoints: ["10.110.97.2", "not-an-ip"],
      }),
    ).toBe("| `adm_impact_element(10.110.5.2;pod-1/node-101,10.110.97.2)`");
    expect(impactSearch({ observers: [], endpoints: [] }, "summary")).toBe(
      "| `adm_impact_element(-,-,summary)`",
    );
  });
  it("does not promote unqualified replica node names into alternatives", () => {
    const r = rowsToImpact([
      {
        row_type: "conversation",
        source: "raw",
        src: "10.110.96.51",
        src_kinds: ["vm", "endpoint"],
        src_name: "NYC-ACI-Fabric-01-VMM-Client-01",
        dst: "10.1.12.144",
        dst_kinds: "pod",
        dst_name: "web-abc",
        dst_node: "appd-k8-3",
        dst_owner: "web",
        dst_owner_kind: "ReplicaSet",
        dst_replica_nodes: ["appd-k8-3", "appd-k8-5"],
        dest_port: "8080",
        protocol: "tcp",
        bytes: "1200",
        flows: "4",
        observers: "netflow:10.110.5.2:ifIndex 7>?",
        app: "web",
        total_conversations: "9",
        truncated: "1",
        records_capped: "0",
      },
      { row_type: "k8s_node", entity_name: "appd-k8-5", ip: "10.110.96.7" },
      { row_type: "conversation", src: "x", dst: "10.0.0.1", protocol: "tcp" },
    ]);
    expect(r.conversations).toHaveLength(1);
    const c = r.conversations[0];
    expect(c.src.kind).toBe("vm");
    expect(c.dst).toMatchObject({ kind: "pod", node: "appd-k8-3", app: "web" });
    expect(c.backends).toBeUndefined();
    expect(r.k8sNodes.get("appd-k8-5")).toBe("10.110.96.7");
    expect(r).toMatchObject({
      total: 9,
      truncated: true,
      capped: false,
      source: "raw",
    });
    expect(() => rowsToImpact({})).toThrow();
  });
  it("rejects replica lists without cluster, scope and interval evidence", () => {
    const result = rowsToImpact([
      {
        row_type: "conversation",
        src: "192.0.2.1",
        dst: "192.0.2.2",
        protocol: "tcp",
        dst_kinds: "pod",
        dst_owner: "orders",
        dst_owner_kind: "Deployment",
        dst_cluster: "cluster-a",
        dst_node: "node-a",
        // The reader does not say whether these nodes belong to another
        // cluster or to an earlier interval.
        dst_replica_nodes: ["cluster-b-node", "retired-node"],
      },
    ]);
    expect(result.conversations[0].backends).toBeUndefined();
  });
  it("derives per-hour rates from the window", () => {
    expect(windowHours("-1h")).toBe(1);
    expect(windowHours("-15m")).toBe(0.25);
    expect(windowHours("1000", "8200")).toBe(2);
    expect(windowHours("@d")).toBeUndefined();
  });
});

describe("impact URL", () => {
  it("round-trips elements, mode and window", () => {
    const href = impactURL(
      ["leaf101", "FI-B"],
      { mode: "depends", earliest: "-4h" },
      new URLSearchParams(),
    );
    const q = new URLSearchParams(href.slice(href.indexOf("?")));
    expect(q.getAll("element")).toEqual(["leaf101", "FI-B"]);
    expect(parseImpactParams(q)).toEqual({
      elements: ["leaf101", "FI-B"],
      mode: "depends",
      earliest: "-4h",
      latest: "now",
    });
  });
  it("preserves only a valid explicit scope on impact links", () => {
    const href = impactURL(
      ["leaf101"],
      { earliest: "1000", latest: "1600", scope: "scope-a" },
      new URLSearchParams(),
    );
    const state = parseImpactParams(new URLSearchParams(href.split("?")[1]));
    expect(state).toMatchObject({
      scope: "scope-a",
      earliest: "1000",
      latest: "1600",
    });
    expect(
      parseImpactParams(new URLSearchParams("scope=unmapped%3Asecret")).scope,
    ).toBeUndefined();
    expect(
      parseImpactParams(new URLSearchParams("scope=%22%20OR%20index%3D*"))
        .scope,
    ).toBeUndefined();
  });
  it("defaults to the app's -15m window", () => {
    expect(DEFAULT_IMPACT_WINDOW).toBe("-15m");
    expect(parseImpactParams(new URLSearchParams("element=leaf101"))).toEqual({
      elements: ["leaf101"],
      mode: "fails",
      earliest: "-15m",
      latest: "now",
    });
    expect(
      parseImpactParams(new URLSearchParams("element=a&window=bad window"))
        .earliest,
    ).toBe("-15m");
  });
  it("caps what-if at five valid elements", () => {
    const q = new URLSearchParams(
      "element=a,b,c&element=d&element=e&element=f&element=%3Cx%3E&mode=bogus",
    );
    const p = parseImpactParams(q);
    expect(p.elements).toEqual(["a", "b", "c", "d", "e"]);
    expect(p.mode).toBe("fails");
  });
});

describe("demo replicas and export", () => {
  it("does not infer pod alternatives from matching owner names", async () => {
    const d = await loadDemoImpact(["leaf-101"]);
    const r = failsImpact(d.elements, d.conversations, d.ctx, {
      hours: d.hours,
    });
    const rows = r.rows.filter((c) => c.conv.dst.name?.startsWith("frontend-"));
    for (const c of rows) {
      expect(c.alternate).not.toContain(c.conv.dst.name);
      expect(c.reason).not.toBe("other replica");
    }
    const csv = impactCsv(r, {
      window: "-1h to now",
      source: "demo",
      generated: "t",
    });
    const lines = csv.split("\r\n");
    expect(lines[0]).toContain("leaf-101 down:");
    expect(lines[2].split(",")).toContain("severity");
    expect(lines).toHaveLength(r.rows.length + 3);
  });
});
