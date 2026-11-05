import { describe, expect, it } from "vitest";
import type { SearchClient, SearchRequest } from "../data/searchClient";
import type { Row } from "../rows";
import { loadDevicePage } from "./DevicePage";

const signal = new AbortController().signal;

describe("loadDevicePage", () => {
  it("resolves a demo leaf by DN and loads its flows", async () => {
    const r = await loadDevicePage({
      query: "topology/pod-1/node-103",
      demo: true,
      earliest: "-24h",
      signal,
    });
    expect(r.device?.name).toBe("leaf-103");
    expect(r.flows?.conversations[0]).toMatchObject({
      src: "10.30.40.25",
      dst: "10.20.30.40",
      blocked: true,
    });
  });

  it("issues one adm_device_flows search per token in the time range", async () => {
    const requests: SearchRequest[] = [];
    const client: SearchClient = {
      async search(request) {
        requests.push(request);
        if (request.search === "`adm_topology`")
          return {
            rows: [
              {
                row_type: "device",
                device_id: "leaf-103",
                name: "leaf-103",
                device_kind: "switch",
                aci_node: "pod-1/node-103",
                sources: "aci",
              },
            ],
            warnings: [],
            errors: [],
          };
        return { rows: [], warnings: [], errors: [] };
      },
    };
    const r = await loadDevicePage({
      query: "leaf-103",
      demo: false,
      client,
      earliest: "-4h",
      latest: "now",
      signal,
    });
    expect(r.device?.id).toBe("leaf-103");
    expect(requests.map((q) => q.search)).toEqual([
      "`adm_topology`",
      "| `adm_device_inventory`",
      "| `adm_device_flows(pod-1/node-103)`",
    ]);
    expect(requests[2]).toMatchObject({ earliest: "-4h", latest: "now" });
    expect(r.flows?.conversations).toEqual([]);
  });

  it("resolves ACI leaves and ESXi exporters from device inventory and names their interfaces", async () => {
    // adm_topology returned no ACI rows; adm_device_inventory rows mirror
    // topSystem and comp:Hv (named by IP, mgmtIp 0.0.0.0) in a live lab.
    const inventory: Row[] = [
      {
        row_type: "device",
        device_id: "fab1-leaf101",
        name: "fab1-leaf101",
        mgmt_ip: "192.0.2.252",
        device_kind: "switch",
        fabric: "apic:192.0.2.110",
        aci_node: "pod-1/node-101",
        role: "leaf",
        sources: "aci",
      },
      {
        row_type: "device",
        device_id:
          "vsphere:192.0.2.110/comp/prov-VMware/ctrlr-[vmm-dc1]-vcenter/hv-host-9",
        name: "203.0.113.11",
        mgmt_ip: "203.0.113.11",
        device_kind: "hypervisor",
        platform: "VMware ESXi",
        parent_device: "vsphere:192.0.2.110/vmm/VMware/vmm-dc1/vcenter",
        sources: "aci_vmm",
      },
    ];
    const flows: Record<string, Row[]> = {
      "192.0.2.252": [
        {
          device: "192.0.2.252",
          src: "192.0.2.3",
          dst: "198.51.100.2",
          dest_port: "47001",
          protocol: "tcp",
          bytes: "5911388",
          packets: "4239",
          flows: "45",
          interfaces: "ifIndex 369098753 > ?",
          sources: "netflow",
        },
        {
          device: "192.0.2.252",
          src: "192.0.2.3",
          dst: "198.51.100.9",
          protocol: "tcp",
          flows: "1",
          interfaces: "ifIndex 436342818 > ?",
          sources: "netflow",
        },
      ],
      "203.0.113.11": [
        {
          device: "203.0.113.11",
          src: "192.0.2.3",
          dst: "198.51.100.2",
          protocol: "tcp",
          flows: "9",
          interfaces: ["ifIndex 9 > ifIndex 0", "ifIndex 7 > ifIndex 12"],
          sources: "netflow",
        },
      ],
    };
    const names: Record<string, Row[]> = {
      "192.0.2.252": [
        {
          row_type: "interface",
          device_id: "192.0.2.252",
          ifindex: "369098753",
          interface: "port-channel2",
          interface_source: "snmp_ifDescr",
        },
      ],
      "203.0.113.11": [
        {
          row_type: "interface",
          device_id: "203.0.113.11",
          ifindex: "9",
          interface: "k8s-vm-01 vNIC (port 9)",
        },
        {
          row_type: "interface",
          device_id: "203.0.113.11",
          ifindex: "7",
          interface: "vmnic7 (vmm-dc1 uplink)",
        },
      ],
    };
    const searches: string[] = [];
    const client: SearchClient = {
      async search(request) {
        searches.push(request.search);
        const arg = /\((.*)\)`$/.exec(request.search)?.[1] ?? "";
        const rows = request.search.includes("adm_device_inventory")
          ? inventory
          : request.search.includes("adm_device_flows(")
            ? (flows[arg] ?? [])
            : request.search.includes("adm_interface_names(")
              ? (names[arg] ?? [])
              : [];
        return { rows, warnings: [], errors: [] };
      },
    };
    const open = (query: string) =>
      loadDevicePage({ query, demo: false, client, earliest: "-1h", signal });
    for (const q of ["192.0.2.252", "leaf101", "101", "pod-1/node-101"])
      expect((await open(q)).device?.id).toBe("fab1-leaf101");
    const leaf = await open("leaf101");
    expect(leaf.flows?.conversations.map((c) => c.interfaces)).toEqual([
      ["port-channel2"],
      ["Ethernet1/34.34 (decoded)"],
    ]);
    expect(leaf.flows?.conversations[0].bytes).toBe(5911388);
    expect(searches).toContain("| `adm_interface_names(192.0.2.252)`");
    expect(searches).not.toContain("| `adm_interface_names(pod-1/node-101)`");
    const esxi = await open("203.0.113.11");
    expect(esxi.device?.kind).toBe("hypervisor");
    expect(esxi.flows?.conversations[0].interfaces).toEqual([
      "k8s-vm-01 vNIC (port 9)",
      "vmnic7 (vmm-dc1 uplink) > ifIndex 12",
    ]);
  });

  it("fails closed on Splunk job errors", async () => {
    const client: SearchClient = {
      async search(request) {
        return request.search === "`adm_topology`"
          ? { rows: [], warnings: [], errors: [] }
          : { rows: [], warnings: [], errors: ["boom"] };
      },
    };
    await expect(
      loadDevicePage({
        query: "192.0.2.73",
        demo: false,
        client,
        earliest: "-1h",
        signal,
      }),
    ).rejects.toThrow("Device flows was incomplete: boom");
  });
});
