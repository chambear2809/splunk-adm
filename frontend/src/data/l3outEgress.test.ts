import { describe, expect, it } from "vitest";
import l3outFixture from "../../../fixtures/path-trace-l3out.json";
import { endpointGraph } from "../trace/standaloneTrace";
import { assembleTrace } from "../trace/usePathTrace";
import { emptyTopology } from "../topology";
import { L3OUT_TRUNCATED_NOTE } from "./pathTrace";
import {
  cidrContains,
  l3outEgressLabel,
  l3outRows,
  matchL3Out,
  type L3OutEvidence,
} from "./l3outEgress";

// Live adm_path_trace(2) + adm_l3out_path_evidence(2) shape (see _provenance):
// VM → VDS → UCS FI pair → vPC leaf pair; only the border leaf (node-102,
// 192.0.2.253) exported the flow; the destination is the L3Out sub-interface
// address on that leaf.
const rows = l3outFixture.rows as Record<string, unknown>[];
const pair = { src: "192.0.2.3", dst: "198.51.100.6" };
const trace = (input: unknown[] = rows, dst = pair.dst) =>
  assembleTrace(
    { src: pair.src, dst },
    endpointGraph(input, [pair.src, dst]),
    emptyTopology(),
    input,
  ).trace;
/** The same records exported by another leaf. */
const exportedBy = (ip: string) =>
  rows.map((r) =>
    r.row_type === "observation" && r.observer_device === "192.0.2.253"
      ? {
          ...r,
          observer_device: ip,
          observer: String(r.observer).replace(":192.0.2.253:", `:${ip}:`),
        }
      : r,
  );
const hopView = (t: ReturnType<typeof trace>) =>
  t.hops.map((h) => [h.label, h.evidence, h.in ?? "", h.out ?? ""]);

describe("L3Out evidence rows", () => {
  it("parses live l3extRsPathL3OutAtt and l3extSubnet rows", () => {
    expect(l3outRows(rows)).toEqual({
      paths: [
        {
          apic: "192.0.2.110",
          tenant: "Tenant1",
          l3out: "L3Out1",
          l3outDn: "uni/tn-Tenant1/out-L3Out1",
          nodes: ["pod-1/node-102"],
          interface: "Ethernet1/24",
          ifType: "sub-interface",
          encap: "vlan-304",
          address: "198.51.100.6/30",
        },
      ],
      subnets: [
        {
          apic: "192.0.2.110",
          l3out: "L3Out1",
          l3outDn: "uni/tn-Tenant1/out-L3Out1",
          instp: "ExtEPG1",
          subnet: "0.0.0.0/0",
        },
      ],
    });
  });

  it("flags evidence cut at adm_l3out_path_limit and says so in the trace", () => {
    expect(l3outRows(rows).truncated).toBeUndefined();
    expect(trace().notes).not.toContain(L3OUT_TRUNCATED_NOTE);
    const cut = rows.map((r) =>
      r.row_type === "l3out_path" ? { ...r, truncated: "1" } : r,
    );
    expect(l3outRows(cut).truncated).toBe(true);
    expect(l3outRows(cut).paths).toHaveLength(1);
    expect(trace(cut).notes).toContain(L3OUT_TRUNCATED_NOTE);
    // Only l3out rows carry the marker; another row's field is ignored.
    expect(
      l3outRows([...rows, { row_type: "observation", truncated: "1" }])
        .truncated,
    ).toBeUndefined();
  });

  it("skips malformed rows and splits vPC node lists", () => {
    const ev = l3outRows([
      {
        row_type: "l3out_path",
        l3out: "x",
        l3out_dn: "bad",
        nodes: "pod-1/node-1",
      },
      { row_type: "l3out_path", l3out: "x", l3out_dn: "uni/tn-a/out-x" },
      {
        row_type: "l3out_path",
        l3out: "x",
        l3out_dn: "uni/tn-a/out-x",
        nodes: ["pod-1/node-101", "pod-1/node-102"],
        address: "not-a-cidr",
      },
      {
        row_type: "l3out_subnet",
        l3out: "x",
        l3out_dn: "uni/tn-a/out-x",
        subnet: "10.0.0.0/33",
      },
      "junk",
    ]);
    expect(ev.paths).toHaveLength(1);
    expect(ev.paths[0].nodes).toEqual(["pod-1/node-101", "pod-1/node-102"]);
    expect(ev.paths[0].address).toBeUndefined();
    expect(ev.subnets).toEqual([]);
  });
});

describe("L3Out matching", () => {
  const ev = l3outRows(rows);
  it("prefers the interface subnet, then the longest external subnet", () => {
    expect(matchL3Out("198.51.100.6", ev)?.basis).toBe("interface_address");
    expect(matchL3Out("198.51.100.5", ev)?.basis).toBe("connected");
    const ext = matchL3Out("203.0.113.99", ev);
    expect([ext?.basis, ext?.instp, ext?.subnet]).toEqual([
      "external_subnet",
      "ExtEPG1",
      "0.0.0.0/0",
    ]);
    expect(matchL3Out("203.0.113.99", ev, "192.0.2.999")).toBeUndefined();
  });

  it("refuses ties across L3Outs and uses a sole L3Out only when there is one", () => {
    const second: L3OutEvidence = {
      paths: [
        ...ev.paths,
        {
          ...ev.paths[0],
          l3out: "L3Out2",
          l3outDn: "uni/tn-Tenant1/out-L3Out2",
          address: undefined,
        },
      ],
      subnets: [
        ...ev.subnets,
        {
          ...ev.subnets[0],
          l3out: "L3Out2",
          l3outDn: "uni/tn-Tenant1/out-L3Out2",
        },
      ],
    };
    expect(matchL3Out("203.0.113.99", second)).toBeUndefined();
    expect(matchL3Out("198.51.100.6", second)?.l3out).toBe("L3Out1");
    expect(matchL3Out("203.0.113.99", { ...ev, subnets: [] })?.basis).toBe(
      "only_l3out",
    );
    expect(
      matchL3Out("203.0.113.99", { paths: second.paths, subnets: [] }),
    ).toBeUndefined();
  });

  it("matches IPv4 and IPv6 prefixes without crossing families", () => {
    expect(cidrContains("10.0.0.0/8", "10.1.2.3")).toBe(8);
    expect(cidrContains("10.0.0.0/8", "11.0.0.1")).toBeUndefined();
    expect(cidrContains("2001:db8::/32", "2001:db8:1::5")).toBe(32);
    expect(cidrContains("::/0", "10.0.0.1")).toBeUndefined();
    expect(cidrContains("0.0.0.0/0", "2001:db8::1")).toBeUndefined();
  });

  it("labels the egress inferred with the L3Out name", () => {
    expect(l3outEgressLabel(ev.paths, "L3Out1")).toBe(
      "Eth1/24 vlan-304 (inferred, L3Out L3Out1)",
    );
  });
});

describe("trace to an address behind an L3Out", () => {
  it("ends at the border leaf's L3Out sub-interface when it exported the flow", () => {
    const t = trace();
    expect(t.status).toBe("traced");
    expect(hopView(t)).toEqual([
      ["k8s-vm-01", "observed", "", ""],
      ["vmm-dc1", "observed", "", ""],
      ["One of 2 switches", "inferred", "", ""],
      [
        "fab1-leaf102",
        "observed",
        "port-channel1",
        "Ethernet1/24.15 vlan-304 (inferred, L3Out L3Out1)",
      ],
      ["198.51.100.6", "observed", "", ""],
    ]);
    expect(t.hops[3].alternatives).toBeUndefined();
    expect(t.hops[3].detail).toBe("ACI leaf · vPC peer fab1-leaf101 not seen");
    expect(t.hops[4].detail).toBe("External · L3Out L3Out1 interface address");
    expect(t.notes.join(" ")).toContain("ACI L3Out L3Out1");
  });

  it("crosses an IS-IS-adjacent spine to the border leaf from a non-border leaf", () => {
    // ACI iTraceroute from leaf101 transits a spine to border leaf102.
    const t = trace(exportedBy("192.0.2.252"));
    expect(t.status).toBe("traced");
    expect(hopView(t).slice(3)).toEqual([
      [
        "fab1-leaf101",
        "observed",
        "port-channel1 (decoded)",
        "fabric (inferred, to border leaf fab1-leaf102)",
      ],
      ["One of 2 spines", "inferred", "", ""],
      [
        "fab1-leaf102",
        "inferred",
        "",
        "Ethernet1/24.15 vlan-304 (inferred, L3Out L3Out1)",
      ],
      ["198.51.100.6", "observed", "", ""],
    ]);
    const spine = t.hops[4];
    expect(spine.support).toEqual(["ACI IS-IS adjacency"]);
    expect(spine.alternatives?.map((a) => a.label)).toEqual([
      "fab1-spine201",
      "fab1-spine202",
    ]);
    expect(spine.detail).toContain(
      "IS-IS adjacency up to fab1-leaf101 and fab1-leaf102",
    );
    expect(t.hops[5].detail).toBe("Border leaf · L3Out L3Out1");
  });

  it("keeps the vPC pair when both members exported the flow", () => {
    const leaf102 = rows.find(
      (r) =>
        r.row_type === "observation" && r.observer_device === "192.0.2.253",
    )!;
    const t = trace([
      ...rows,
      {
        ...leaf102,
        observer_device: "192.0.2.252",
        observer: String(leaf102.observer).replace(
          "192.0.2.253",
          "192.0.2.252",
        ),
      },
    ]);
    expect(t.hops.map((h) => h.label)).toEqual([
      "k8s-vm-01",
      "vmm-dc1",
      "One of 2 switches",
      "One of 2 leaves",
      "198.51.100.6",
    ]);
    expect(t.hops[3].out).toBe(
      "Ethernet1/24.15 vlan-304 (inferred, L3Out L3Out1) on fab1-leaf102",
    );
    expect(t.notes.join(" ")).toContain("would cross a spine to fab1-leaf102");
  });

  it("names no sub-interface when the border leaf reports several", () => {
    const t = trace([
      ...rows,
      {
        row_type: "interface",
        device_id: "192.0.2.253",
        ifindex: "436301840",
        interface: "Ethernet1/24.16",
        interface_source: "snmp_ifDescr",
      },
    ]);
    expect(t.hops[3].out).toBe("Eth1/24 vlan-304 (inferred, L3Out L3Out1)");
  });

  it("keeps the attachment gap without L3Out rows or with an unmatched destination", () => {
    const without = trace(
      rows.filter((r) => !String(r.row_type).startsWith("l3out_")),
    );
    expect(without.status).toBe("partial");
    expect(without.hops.map((h) => h.label)).toContain(
      "Attachment of 198.51.100.6 unknown",
    );
    const twoL3Outs = [
      ...rows.filter((r) => r.row_type !== "l3out_subnet"),
      {
        ...rows.find((r) => r.row_type === "l3out_path")!,
        l3out: "L3Out2",
        l3out_dn: "uni/tn-Tenant1/out-L3Out2",
        address: "198.51.100.10/30",
      },
    ];
    expect(trace(twoL3Outs, "203.0.113.99").status).toBe("partial");
  });
});
