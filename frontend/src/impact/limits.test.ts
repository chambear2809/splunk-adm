import { describe, expect, it } from "vitest";
import live from "../../../fixtures/path-trace-vds-fi-vpc.json";
import { indexTopology, rowsToTopology } from "../topology";
import {
  classifier,
  compileFailure,
  type ImpactConversation,
} from "./classify";
import { attributeApps, portChannelRows, rowsToImpact } from "./data";
import { resolveElement } from "./elements";
import { failsImpact } from "./model";
import { pathContext, type ImpactEndpoint } from "./paths";

// Live-shaped VDS → UCS FI pair → vPC leaf pair (fixtures/path-trace-vds-fi-vpc.json):
// FI-A reaches leaf101/leaf102 on Ethernet1/21, FI-B on Ethernet1/22.
const topology = rowsToTopology(
  live.rows.filter((r) => r.row_type === "device" || r.row_type === "link"),
);
const topo = indexTopology(topology);
const pcRow = (node: string, pc: string, policy: string, member: string) => ({
  row_type: "port_channel",
  apic_host: "192.0.2.110",
  node,
  port_channel: pc,
  policy,
  members: [member],
});
const pcs = portChannelRows(
  [
    pcRow("pod-1/node-101", "po1", "vpc-1-21-UCS-FI", "eth1/21"),
    pcRow("pod-1/node-102", "po1", "vpc-1-21-UCS-FI", "eth1/21"),
    pcRow("pod-1/node-101", "po2", "vpc-1-22-UCS-FI", "eth1/22"),
    pcRow("pod-1/node-102", "po2", "vpc-1-22-UCS-FI", "eth1/22"),
    {
      row_type: "port_channel",
      node: "bogus",
      port_channel: "po9",
      members: ["eth1/9"],
    },
  ],
  topo,
);
const el = (t: string) => resolveElement(t, topology, topo, undefined, pcs);
const vm = (ip: string, name: string): ImpactEndpoint => ({
  key: `ip:${ip}`,
  ip,
  name,
  kind: "vm",
});
const conv: ImpactConversation = {
  id: "vm-vm",
  src: vm("192.0.2.3", "k8s-vm-01"),
  dst: vm("198.51.100.2", "app-vm-02"),
  protocol: "tcp",
  port: 47001,
  flows: 1,
  observers: [],
};
const run = (tokens: string[]) =>
  classifier(pathContext(topo)).classify(conv, compileFailure(tokens.map(el)));

describe("vPC and port-channel by name", () => {
  it("maps a vPC policy group to its member ports on both leaves", () => {
    expect(pcs).toHaveLength(4);
    const v = el("vpc-1-22-UCS-FI");
    expect(v.resolved).toBe(true);
    expect(v.ports?.sort()).toEqual([
      "fab1-leaf101|eth1/22",
      "fab1-leaf102|eth1/22",
    ]);
    expect(el("leaf101|po2").ports).toEqual(["fab1-leaf101|eth1/22"]);
    expect(el("leaf101|port-channel2").ports).toEqual(["fab1-leaf101|eth1/22"]);
  });
  it("one vPC down degrades through the other FI's vPC; both vPCs down is an outage", () => {
    const one = run(["vpc-1-22-UCS-FI"]);
    expect(one.severity).toBe("degraded");
    expect(one.failedAt).toContain("eth1/22");
    expect(run(["vpc-1-22-UCS-FI", "vpc-1-21-UCS-FI"]).severity).toBe("outage");
  });
  it("one member of a vPC degrades", () => {
    expect(run(["leaf101|po2"]).severity).toBe("degraded");
  });
  it("resolves a vPC from a snapshot after the window and labels it", () => {
    // pcAggrIf/pcRsMbrIfs collection began after the selected window.
    const after = portChannelRows(
      [
        {
          ...pcRow("pod-1/node-101", "po2", "vpc-1-22-UCS-FI", "eth1/22"),
          snapshot_time: "1793814951",
          after_window: "1",
        },
        {
          ...pcRow("pod-1/node-102", "po1", "vpc-1-22-UCS-FI", "eth1/22"),
          snapshot_time: "1793814951",
          after_window: "1",
        },
      ],
      topo,
    );
    expect(after[0]).toMatchObject({
      snapshotTime: 1793814951,
      afterWindow: true,
    });
    const at = (t: string) =>
      resolveElement(t, topology, topo, undefined, after);
    for (const t of ["vpc-1-22-UCS-FI", "if:vpc-1-22-UCS-FI"]) {
      const v = at(t);
      expect(v.resolved).toBe(true);
      expect(v.membershipAfter).toBe(1793814951);
      expect(v.ports?.sort()).toEqual([
        "fab1-leaf101|eth1/22",
        "fab1-leaf102|eth1/22",
      ]);
    }
    expect(at("leaf102|po1").ports).toEqual(["fab1-leaf102|eth1/22"]);
    // In-window rows carry no label.
    expect(el("vpc-1-22-UCS-FI").membershipAfter).toBeUndefined();
  });
});

describe("merged directions", () => {
  it("keeps the per-direction detail of a merged conversation", () => {
    const r = rowsToImpact([
      {
        row_type: "conversation",
        src: "10.110.96.3",
        dst: "10.110.97.2",
        dest_port: "47001",
        protocol: "tcp",
        bytes: "1000",
        bytes_fwd: "900",
        bytes_rev: "100",
        flows: "10",
        directions: "both",
      },
    ]);
    expect(r.conversations[0]).toMatchObject({
      port: 47001,
      bytes: 1000,
      bytesFwd: 900,
      bytesRev: 100,
      directions: "both",
    });
  });
});

describe("app attribution for node-address traffic", () => {
  const node = (ip: string, name: string): ImpactEndpoint => ({
    key: `ip:${ip}`,
    ip,
    name,
    node: name,
    kind: "k8s_node",
    cluster: "lab",
  });
  const tunnel = (): ImpactConversation => ({
    id: "t",
    src: node("10.110.96.7", "appd-k8-5"),
    dst: node("10.110.96.3", "appd-k8-1"),
    protocol: "udp",
    port: 8473,
    flows: 3,
    observers: [],
    firstSeen: 100,
    lastSeen: 200,
  });
  it("Hubble pod flows on the same node pair and time name the app", () => {
    const c = tunnel();
    attributeApps(
      [c],
      [
        {
          srcNode: "appd-k8-5",
          dstNode: "appd-k8-1",
          srcApp: "webui",
          dstApp: "recommender",
          flows: 9,
          firstSeen: 150,
          lastSeen: 160,
          ports: [8080],
        },
        {
          srcNode: "appd-k8-5",
          dstNode: "appd-k8-1",
          dstApp: "old",
          flows: 99,
          firstSeen: 10,
          lastSeen: 20,
          ports: [8080],
        },
      ],
      new Map([["lab|appd-k8-1", ["hosted-x"]]]),
    );
    expect(c.apps).toEqual([{ name: "recommender", basis: "hubble" }]);
  });
  it("without a Hubble source node, the receiving node must be an end", () => {
    const c = tunnel();
    attributeApps(
      [c],
      [
        {
          dstNode: "appd-k8-9",
          dstApp: "elsewhere",
          flows: 50,
          firstSeen: 150,
          lastSeen: 160,
          ports: [8080],
        },
        {
          dstNode: "appd-k8-1",
          dstApp: "persistence",
          flows: 5,
          firstSeen: 150,
          lastSeen: 160,
          ports: [8080],
        },
      ],
      new Map(),
    );
    expect(c.apps).toEqual([{ name: "persistence", basis: "hubble" }]);
  });
  it("falls back to apps hosted on either node, marked inferred, in the same cluster only", () => {
    const c = tunnel();
    attributeApps(
      [c],
      [],
      new Map([
        ["lab|appd-k8-1", ["auth"]],
        ["other|appd-k8-5", ["nope"]],
      ]),
    );
    expect(c.apps).toEqual([{ name: "auth", basis: "hosted" }]);
  });
  it("hosted-on apps are not counted, only listed as possibly affected", () => {
    const c = tunnel();
    attributeApps([c], [], new Map([["lab|appd-k8-1", ["auth"]]]));
    const f = el("10.110.96.3");
    const r = failsImpact([f], [c], pathContext(topo));
    expect(r.apps).toEqual([]);
    expect(r.kpis.apps).toEqual({ outage: 0, degraded: 0, unknown: 0 });
    expect(r.possibleApps).toMatchObject([{ app: "auth", basis: "hosted" }]);
    expect(r.headline).toMatch(
      /^10\.110\.96\.3 down: \d+ outage · 0 workloads degraded · ~1 possibly affected · /,
    );
    expect(r.headlineMain).not.toContain("possibly");
  });
});
