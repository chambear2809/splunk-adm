import { describe, expect, it } from "vitest";
import { SOURCE_DEFINITIONS } from "./data/deploymentHealth";
import { impactElementSuggestions } from "./impact/ImpactPage";
import { deviceSuggestions, MAX_DEVICE_SUGGESTIONS } from "./pages/DevicePage";
import { mappingSuggestions } from "./pages/SetupPage";
import type { Device } from "./topology";

const device = (id: string, extra: Partial<Device> = {}): Device =>
  ({ id, name: id, kind: "switch", ...extra }) as Device;

describe("page-local field suggestions", () => {
  it("suggests registry and stored observer kinds and mapped scopes only", () => {
    const { kinds, scopes } = mappingSuggestions([
      { observer_kind: "APIC", scope: "fabric-a" },
      { observer_kind: "exporter", scope: "unmapped:10.0.0.1" },
      { observer_kind: "custom_kind", scope: "unknown" },
      { observer_kind: " ", scope: "fabric-a" },
      { scope: "vrf/blue" },
    ]);
    expect(kinds).toContain("apic");
    expect(kinds).toContain("custom_kind");
    expect(kinds).not.toContain("APIC");
    for (const kind of SOURCE_DEFINITIONS.flatMap((s) => s.observerKinds))
      expect(kinds).toContain(kind);
    expect(kinds).toEqual([...kinds].sort());
    expect(scopes).toEqual(["fabric-a", "vrf/blue"]);
    expect(
      mappingSuggestions(
        Array.from({ length: 300 }, (_, i) => ({ scope: `s${i}` })),
      ).scopes,
    ).toHaveLength(100);
  });

  it("suggests loaded devices by safe name, labelled by management address", () => {
    expect(
      deviceSuggestions([
        device("dev-2", { name: "spine-1", mgmt_ip: "10.0.0.2" }),
        device("dev-1", { name: "leaf 101" }),
        device("dev-3", { name: "spine-1" }),
      ]),
    ).toEqual([
      { value: "dev-1", label: "switch" },
      { value: "spine-1", label: "10.0.0.2" },
    ]);
    expect(
      deviceSuggestions(Array.from({ length: 500 }, (_, i) => device(`d${i}`))),
    ).toHaveLength(MAX_DEVICE_SUGGESTIONS);
  });

  it("suggests impact elements from observed devices, then inventory", () => {
    const options = impactElementSuggestions({
      observed: {
        devices: [{ id: "leaf-101", name: "Leaf 101" }],
      } as never,
      topology: {
        devices: [device("spine-1"), device("leaf-101"), device("bad id!")],
        links: [],
        interfaces: [],
        warnings: [],
      } as never,
    });
    expect(options).toEqual([
      { value: "leaf-101", label: "Leaf 101" },
      { value: "spine-1" },
    ]);
  });
});
