import { describe, expect, it } from "vitest";
import { enumerateAciFabricPaths, MAX_CANDIDATE_PATHS } from "./aciFabricPaths";
import type { AciFabricSnapshot } from "./aciFabric";

const snapshot = (): AciFabricSnapshot => ({
  schema: "application_atlas.aci_fabric_snapshot.v1",
  schema_version: 1,
  source: "atlas:aci_poll",
  snapshot_id: "capture-1",
  captured_at: 1000,
  authority: "apic-1",
  scope: "fabric-a",
  devices: [
    { id: "leaf-a", name: "leaf-a", role: "leaf" },
    { id: "leaf-b", name: "leaf-b", role: "leaf" },
    { id: "spine-1", name: "spine-1", role: "spine" },
    { id: "spine-2", name: "spine-2", role: "spine" },
    { id: "apic", name: "apic", role: "controller" },
  ],
  links: [
    {
      id: "a-1",
      source: "leaf-a",
      target: "spine-1",
      source_interface: "a1",
      target_interface: "s1",
    },
    {
      id: "a-1-recip",
      source: "spine-1",
      target: "leaf-a",
      source_interface: "s1",
      target_interface: "a1",
    },
    {
      id: "a-2",
      source: "leaf-a",
      target: "spine-2",
      source_interface: "a2",
      target_interface: "s2",
    },
    {
      id: "b-1",
      source: "leaf-b",
      target: "spine-1",
      source_interface: "b1",
      target_interface: "s3",
    },
    {
      id: "b-2",
      source: "leaf-b",
      target: "spine-2",
      source_interface: "b2",
      target_interface: "s4",
    },
    {
      id: "parallel",
      source: "leaf-a",
      target: "spine-1",
      source_interface: "a3",
      target_interface: "s5",
    },
    { id: "controller", source: "apic", target: "leaf-a" },
  ],
  routed_interfaces: [],
});

describe("ACI fabric topology candidates", () => {
  it("enumerates diamond alternatives and deduplicates reciprocal records", () => {
    const result = enumerateAciFabricPaths(snapshot(), "leaf-a", "leaf-b");
    expect(result.paths).toHaveLength(3);
    expect(result.paths.map((path) => path.links.length)).toEqual([2, 2, 2]);
    expect(
      result.paths.some((path) =>
        path.links.some((link) => link.id === "a-1-recip"),
      ),
    ).toBe(false);
    expect(
      result.paths.some((path) =>
        path.links.some((link) => link.id === "parallel"),
      ),
    ).toBe(true);
  });

  it("supports a same-leaf zero-hop candidate and excludes controllers", () => {
    const same = enumerateAciFabricPaths(snapshot(), "leaf-a", "leaf-a");
    expect(same.paths).toHaveLength(1);
    expect(same.paths[0].links).toHaveLength(0);
    expect(enumerateAciFabricPaths(snapshot(), "apic", "leaf-a").paths).toEqual(
      [],
    );
  });

  it("fails closed for unknown endpoints and caps path enumeration", () => {
    expect(
      enumerateAciFabricPaths(snapshot(), "missing", "leaf-a").paths,
    ).toEqual([]);
    const many = snapshot();
    many.links = Array.from({ length: 100 }, (_, i) => ({
      id: `link-${i}`,
      source: "leaf-a",
      target: "leaf-b",
      source_interface: `a${i}`,
      target_interface: `b${i}`,
    }));
    const result = enumerateAciFabricPaths(many, "leaf-a", "leaf-b");
    expect(result.paths).toHaveLength(MAX_CANDIDATE_PATHS);
    expect(result.truncated).toBe(true);
  });

  it("reports depth truncation for a destination beyond the hop bound", () => {
    const deep = snapshot();
    deep.devices = Array.from({ length: 9 }, (_, i) => ({
      id: `switch-${i}`,
      name: `switch-${i}`,
      role: i === 0 || i === 8 ? "leaf" : "spine",
    }));
    deep.links = deep.devices.slice(1).map((device, i) => ({
      id: `deep-${i}`,
      source: deep.devices[i].id,
      target: device.id,
      source_interface: `a${i}`,
      target_interface: `b${i}`,
    }));
    const result = enumerateAciFabricPaths(deep, "switch-0", "switch-8");
    expect(result.paths).toEqual([]);
    expect(result.truncated).toBe(true);
    expect(result.reason).toContain("depth");
  });

  it("terminates dense unreachable searches under the expansion budget", () => {
    const dense = snapshot();
    dense.devices = [
      { id: "source", name: "source", role: "leaf" },
      ...Array.from({ length: 220 }, (_, i) => ({
        id: `spine-${i}`,
        name: `spine-${i}`,
        role: "spine" as const,
      })),
      { id: "target", name: "target", role: "leaf" },
    ];
    dense.links = [];
    for (let i = 0; i < 220; i++)
      for (let j = i + 1; j < 220; j++)
        dense.links.push({
          id: `dense-${i}-${j}`,
          source: `spine-${i}`,
          target: `spine-${j}`,
        });
    dense.links.push({
      id: "source-edge",
      source: "source",
      target: "spine-0",
    });
    const result = enumerateAciFabricPaths(dense, "source", "target");
    expect(result.paths).toEqual([]);
    expect(result.truncated).toBe(true);
    expect(result.reason).toContain("budget");
  });
});
