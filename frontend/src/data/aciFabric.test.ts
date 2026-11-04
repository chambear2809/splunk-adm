import { describe, expect, it } from "vitest";
import {
  ACI_FABRIC_SCHEMA,
  normalizeAciFabricSnapshot,
  loadAciFabricSnapshot,
} from "./aciFabric";
import type { Row } from "../rows";

const envelope = (overrides: Record<string, unknown> = {}) => ({
  schema: ACI_FABRIC_SCHEMA,
  classification: "inventory_snapshot",
  qualification: "complete_two_pass_capture",
  traversal: "not_observed",
  capture_id: "fabric-1",
  capture_started: 990,
  capture_completed: 995,
  as_of: 1000,
  authority: "apic-1",
  scope: "tenant-a/vrf-a",
  snapshot_complete: true,
  devices: [
    { id: "leaf-101", name: "leaf-101", role: "leaf" },
    { id: "spine-201", name: "spine-201", role: "spine" },
  ],
  links: [
    {
      id: "link-1",
      a_device: "leaf-101",
      b_device: "spine-201",
      a_interface: "eth1/49",
      b_interface: "eth1/1",
    },
  ],
  routed_interfaces: [
    {
      id: "routed-1",
      device: "leaf-101",
      native_id: "pod-1/node-101",
      interface: "eth1/24.100",
      parent_interface: "eth1/24",
      dn: "uni/tn-a/node-101/sys/phys-[eth1/24]/rtdif-100",
      physical_dn: "topology/pod-1/node-101/sys/phys-[eth1/24]",
      physical_source: "l1PhysIf+ethpmPhysIf",
      classification: "reported_routed_interface",
      traversal: "not_observed",
      source: "l3EncRtdIf",
      encap: "dot1q",
      admin_state: "up",
      oper_state: "up",
      connection_dn: "uni/tn-a/out-l3/lnodep-101",
    },
  ],
  provenance: { source: "atlas:aci_poll", sourcetype: "adm:aci_poll:v2" },
  ...overrides,
});
const rows = (value: unknown): Row[] => [{ _raw: JSON.stringify(value) }];

describe("ACI fabric snapshot contract", () => {
  it("accepts one complete current envelope and preserves parallel links", () => {
    const snapshot = normalizeAciFabricSnapshot(rows(envelope()), 1000);
    expect(snapshot.authority).toBe("apic-1");
    expect(snapshot.scope).toBe("tenant-a/vrf-a");
    expect(snapshot.devices).toHaveLength(2);
    expect(snapshot.links).toHaveLength(1);
    expect(snapshot.routed_interfaces[0]).toMatchObject({
      parent_interface: "eth1/24",
      interface: "eth1/24.100",
    });
  });

  it.each([
    ["not an object", "bad"],
    ["wrong schema", { schema: "other" }],
    ["incomplete", { qualification: "partial" }],
    [
      "mismatched endpoint",
      { links: [{ id: "x", a_device: "missing", b_device: "leaf-101" }] },
    ],
  ])("rejects %s", (_label, value) => {
    expect(() => normalizeAciFabricSnapshot(rows(value), 1000)).toThrow();
  });

  it("rejects empty, duplicate, or malformed search results", async () => {
    const client = {
      search: async () => ({ rows: [], warnings: [], errors: [] }),
    };
    await expect(
      loadAciFabricSnapshot(client, new AbortController().signal, "now-1h"),
    ).rejects.toThrow("missing or ambiguous");
  });

  it("uses capture completion for freshness, not the query cutoff", () => {
    expect(() =>
      normalizeAciFabricSnapshot(
        rows(
          envelope({
            capture_started: 500,
            capture_completed: 600,
            as_of: 1000,
          }),
        ),
        100000,
      ),
    ).toThrow("stale");
    expect(() =>
      normalizeAciFabricSnapshot(
        rows(
          envelope({
            capture_started: 1001,
            capture_completed: 1000,
            as_of: 1000,
          }),
        ),
        1000,
      ),
    ).toThrow("stale");
  });
});
