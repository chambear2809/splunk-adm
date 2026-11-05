import { describe, expect, it } from "vitest";
import live from "../../../fixtures/path-trace-vds-fi-vpc.json";
import { indexTopology, rowsToTopology } from "../topology";
import {
  classifier,
  compileFailure,
  type ImpactConversation,
} from "./classify";
import { resolveElement } from "./elements";
import { dependsImpact, failsImpact } from "./model";
import { pathContext, type ImpactEndpoint } from "./paths";

// Live-shaped adm_path_trace rows (VDS → UCS FI pair → vPC leaf pair), plus the
// adm_topology fabricLink rows of the same lab and one single-homed host.
const HV9 =
  "vsphere:192.0.2.110/comp/prov-VMware/ctrlr-[vmm-dc1]-vcenter/hv-host-9";
const HV27 =
  "vsphere:192.0.2.110/comp/prov-VMware/ctrlr-[vmm-dc1]-vcenter/hv-host-27";
const VDS = "vsphere:192.0.2.110/vmm/VMware/vmm-dc1/vcenter";
const extra = [
  ...[
    ["fab1-leaf101", "Ethernet1/31", "fab1-spine202", "Ethernet1/31"],
    ["fab1-leaf101", "Ethernet1/32", "fab1-spine201", "Ethernet1/32"],
    ["fab1-leaf102", "Ethernet1/31", "fab1-spine202", "Ethernet1/32"],
    ["fab1-leaf102", "Ethernet1/32", "fab1-spine201", "Ethernet1/31"],
    ["fab1-leaf103", "Ethernet1/49", "fab1-spine201", "Ethernet1/3"],
    ["fab1-leaf103", "Ethernet1/50", "fab1-spine202", "Ethernet1/3"],
    ["fab1-leaf103", "Ethernet1/5", "bm-01", "eno1"],
  ].map(([a, ai, b, bi]) => ({
    row_type: "link",
    a_device: a,
    a_interface: ai,
    b_device: b,
    b_interface: bi,
    link_source: b.startsWith("bm-") ? "lldp" : "aci",
  })),
  {
    row_type: "device",
    device_id: "fab1-leaf103",
    name: "fab1-leaf103",
    device_kind: "switch",
    role: "leaf",
    aci_node: "pod-1/node-103",
    mgmt_ip: "192.0.2.249",
    fabric: "apic:192.0.2.110",
    sources: "aci",
  },
  // A VM attached straight to a vPC (no host uplinks collected).
  {
    row_type: "device",
    device_id: `${VDS}-b`,
    name: "vmm-b",
    device_kind: "virtual_switch",
    switch_type: "vds",
    sources: "aci_vmm",
  },
  {
    row_type: "device",
    device_id: "hv-b",
    name: "esx-b",
    device_kind: "hypervisor",
    mgmt_ip: "203.0.113.30",
    sources: "aci_vmm",
  },
  {
    row_type: "link",
    link_kind: "virtual_port",
    link_source: "aci_vmm",
    a_device: `${VDS}-b`,
    b_device: "vm:00:50:56:00:00:30",
    b_device_name: "db-vm",
    hypervisor: "hv-b",
    mac: "00:50:56:00:00:30",
    ip: "198.51.100.30",
    attach_nodes: ["pod-1/node-101", "pod-1/node-102"],
    attach_interface: "vpc-1-30-DB",
  },
];
const topology = rowsToTopology([
  ...live.rows.filter((r) => r.row_type === "device" || r.row_type === "link"),
  ...extra,
]);
const topo = indexTopology(topology);
const ctx = () => pathContext(topo);

const ep = (
  ip: string,
  name: string,
  extraFields: Partial<ImpactEndpoint> = {},
): ImpactEndpoint => ({
  key: `ip:${ip}`,
  ip,
  name,
  kind: "vm",
  ...extraFields,
});
const vm1 = ep("192.0.2.3", "k8s-vm-01", { app: "web" }); // on hv-host-9
const vm2 = ep("198.51.100.2", "app-vm-02", { app: "app" }); // on hv-host-27
const db = ep("198.51.100.30", "db-vm", { app: "db" });
const bm = ep("192.0.2.40", "bm-01", { kind: "host" });
const ext = ep("8.8.8.8", "8.8.8.8", { kind: "external" });
bm.name = "bm-01";
const conv = (
  id: string,
  src: ImpactEndpoint,
  dst: ImpactEndpoint,
  extraFields: Partial<ImpactConversation> = {},
): ImpactConversation => ({
  id,
  src,
  dst,
  protocol: "tcp",
  port: 443,
  bytes: 1_000_000,
  flows: 10,
  observers: [],
  ...extraFields,
});
const el = (t: string) => resolveElement(t, topology, topo);
const run = (tokens: string[], c: ImpactConversation) =>
  classifier(ctx()).classify(c, compileFailure(tokens.map(el)));

describe("redundancy-aware severity", () => {
  const vmToVm = conv("vm-vm", vm1, vm2);
  it("resolves an FI by name to every LLDP identity of that FI", () => {
    const fi = el("ucs-fi-b");
    expect(fi.devices.size).toBe(2);
    expect(fi.tier).toBe("fi");
  });
  it("a vPC leaf failure degrades; the peer leaf carries it", () => {
    const r = run(["leaf101"], vmToVm);
    expect(r.severity).toBe("degraded");
    expect(r.alternate).toContain("leaf102");
    expect(r.reason).toBe("vPC peer");
  });
  it("one FI failure degrades through the other FI", () => {
    const r = run(["ucs-fi-b"], vmToVm);
    expect(r.severity).toBe("degraded");
    expect(r.alternate).toContain("ucs-fi-a");
    expect(r.reason).toBe("FI pair");
  });
  it("both FIs or both vPC leaves selected → outage", () => {
    expect(run(["ucs-fi-a", "ucs-fi-b"], vmToVm).severity).toBe("outage");
    const both = run(["leaf101", "leaf102"], vmToVm);
    expect(both.severity).toBe("outage");
    expect(both.reason).toBe("all redundant members down");
  });
  it("an FI and the other side's leaf still leave one path", () => {
    expect(run(["leaf101", "ucs-fi-b"], vmToVm).severity).toBe("degraded");
  });
  it("leaf pair ↔ leaf pair is not routed via spines", () => {
    expect(run(["spine201"], vmToVm).severity).toBe("unaffected");
  });
  it("ECMP spine failure degrades fabric-crossing traffic", () => {
    const r = run(["spine201"], conv("vm-bm", vm1, bm));
    expect(r.severity).toBe("degraded");
    expect(r.alternate).toEqual(["spine202"]);
    expect(r.reason).toBe("ECMP");
  });
  it("a single-homed endpoint's leaf failure is an outage", () => {
    const r = run(["leaf103"], conv("vm-bm", vm1, bm));
    expect(r.severity).toBe("outage");
    expect(r.reason).toBe("single-homed");
  });
  it("a host failure is an outage for its VMs, not for others", () => {
    const r = run([HV27], vmToVm);
    expect(r.severity).toBe("outage");
    expect(r.reason).toBe("host down");
    expect(run([HV27], conv("vm-bm", vm1, bm)).severity).toBe("unaffected");
    expect(run(["203.0.113.14"], vmToVm).severity).toBe("outage");
  });
  it("one vPC leg degrades; the whole vPC is an outage", () => {
    const c = conv("vm-db", bm, db);
    expect(run(["leaf101|vpc-1-30-DB"], c).severity).toBe("degraded");
    const all = run(["if:vpc-1-30-DB"], c);
    expect(all.severity).toBe("outage");
  });
  it("marks observed traversal only when a collector at the element exported it", () => {
    const seen = conv("seen", vm1, vm2, {
      observers: ["netflow:192.0.2.252:ifIndex 369098753>?"],
    });
    expect(run(["leaf101"], seen).traversal).toBe("observed");
    expect(run(["leaf102"], seen).traversal).toBe("inferred");
    expect(run(["leaf102"], seen).alternateEvidence).toBe("observed");
  });
  it("external peers: the known side's redundancy decides; spines are inferred ECMP", () => {
    const c = conv("ext", vm1, ext);
    expect(run(["leaf101"], c).severity).toBe("degraded");
    expect(run(["spine201"], c).severity).toBe("degraded");
    expect(run(["spine201", "spine202"], c).severity).toBe("outage");
  });
  it("a Service survives while another backend is reachable", () => {
    const svc = conv(
      "svc",
      bm,
      ep("198.51.100.200", "api-svc", { kind: "k8s_service" }),
      {
        backends: [vm1, vm2],
      },
    );
    const r = run([HV27], svc);
    expect(r.severity).toBe("degraded");
    expect(r.reason).toBe("other backend");
    expect(r.alternate).toEqual(["k8s-vm-01"]);
    expect(run([HV27, HV9], svc).severity).toBe("outage");
  });
  it("an endpoint element takes its own conversations down", () => {
    expect(run(["198.51.100.2"], vmToVm).severity).toBe("outage");
  });
});

describe("impact summaries", () => {
  const convs = [
    conv("a", vm1, vm2, { app: "web", bytes: 3_600_000 }),
    conv("b", vm1, bm, { app: "web", bytes: 7_200_000 }),
    conv("c", bm, db, { app: "db" }),
  ];
  it("headline counts apps by severity and names where traffic shifts", () => {
    const r = failsImpact([el("leaf101")], convs, ctx(), { hours: 1 });
    expect(r.headline).toBe(
      "leaf101 down: 0 outage · 2 apps degraded · 4 peers · 11.8 MB/h shifts to leaf102",
    );
    expect(r.kpis.conversations).toEqual({
      outage: 0,
      degraded: 3,
      unknown: 0,
    });
  });
  it("an app with every conversation out is an outage", () => {
    const r = failsImpact([el("leaf103")], convs, ctx(), { hours: 1 });
    expect(r.apps.find((a) => a.app === "db")?.severity).toBe("outage");
    expect(r.apps.find((a) => a.app === "web")?.severity).toBe("degraded");
  });
  it("depends lists single points and redundant members", () => {
    const r = dependsImpact([el("198.51.100.2")], convs, ctx());
    const sev = Object.fromEntries(r.rows.map((x) => [x.label, x.severity]));
    expect(sev["203.0.113.14"]).toBe("outage");
    expect(sev["vmm-dc1"]).toBe("outage");
    expect(sev["leaf101"]).toBe("degraded");
    expect(sev["ucs-fi-a"]).toBe("degraded");
    expect(r.headline).toMatch(/^app-vm-02 depends on \d+ · 2 single points/);
  });
});
