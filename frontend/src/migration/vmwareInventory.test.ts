import { describe, expect, it, vi } from "vitest";
import {
  VMWARE_LABEL_LIMITS,
  buildVmwareInventorySearch,
  loadVmwareInventoryLabels,
  parseVmwareInventory,
} from "./vmwareInventory";

describe("VMware inventory labels", () => {
  it("takes each VM's latest change set before matching addresses", () => {
    const spl = buildVmwareInventorySearch(["10.0.0.1", "fd00::1"], 1000);
    expect(spl).toContain('`adm_index_vmware_inv` sourcetype="vmware:inv:vm"');
    expect(spl).toContain("spath path=changeSet.guest.ipAddress output=adm_ip");
    expect(spl.indexOf("by host adm_moid")).toBeLessThan(
      spl.indexOf('where adm_ip IN ("10.0.0.1","fd00::1")'),
    );
    expect(spl).toContain("eventstats dc(adm_moid) as claims by adm_ip");
    expect(() => buildVmwareInventorySearch([], 1000)).toThrow();
    expect(() =>
      buildVmwareInventorySearch(['10.0.0.1" OR "x'], 1000),
    ).toThrow();
    expect(() => buildVmwareInventorySearch(["FD00::1"], 1000)).toThrow(
      "canonical",
    );
  });

  it("parses labels, keeps ambiguity and rejects unrequested addresses", () => {
    const rows = [
      {
        adm_ip: "10.0.0.1",
        host: "vc-01.example.internal",
        vm_name: "orders-app-01",
        vm_id: "vm-302",
        hypervisor: "esx-01",
        cluster: "prod-cluster",
        reported: "900",
        claims: "2",
      },
    ];
    expect(parseVmwareInventory(rows, ["10.0.0.1"])).toEqual({
      labels: [
        {
          address: "10.0.0.1",
          vmName: "orders-app-01",
          vmId: "vm-302",
          hypervisor: "esx-01",
          cluster: "prod-cluster",
          vcenter: "vc-01.example.internal",
          reportedAt: 900,
          claims: 2,
        },
      ],
      capped: false,
    });
    expect(() => parseVmwareInventory(rows, ["10.0.0.2"])).toThrow();
    expect(() =>
      parseVmwareInventory([{ ...rows[0], vm_name: "" }], ["10.0.0.1"]),
    ).toThrow();
  });

  it("searches a bounded lookback ending at the plan window", async () => {
    const search = vi
      .fn()
      .mockResolvedValue({ rows: [], warnings: [], errors: [] });
    const result = await loadVmwareInventoryLabels(
      { search },
      ["10.0.0.1"],
      5_000_000,
      new AbortController().signal,
    );
    expect(result).toEqual({
      labels: [],
      capped: false,
      window: {
        start: 5_000_000 - VMWARE_LABEL_LIMITS.lookback,
        end: 5_000_000,
      },
    });
    expect(search.mock.calls[0][0]).toMatchObject({
      earliest: String(5_000_000 - VMWARE_LABEL_LIMITS.lookback),
      latest: "5000000",
      maxRows: VMWARE_LABEL_LIMITS.rows + 1,
    });
  });
});
