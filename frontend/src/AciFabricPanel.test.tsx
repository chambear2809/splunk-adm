import { describe, expect, it } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import {
  AciFabricPanel,
  FabricPathCandidates,
  pathHopLabel,
} from "./AciFabricPanel";
import type { AciFabricSnapshot } from "./data/aciFabric";

const snapshot: AciFabricSnapshot = {
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
    { id: "spine", name: "spine", role: "spine" },
  ],
  links: [
    {
      id: "a",
      source: "leaf-a",
      target: "spine",
      source_interface: "a1",
      target_interface: "s1",
    },
    {
      id: "b",
      source: "spine",
      target: "leaf-b",
      source_interface: "s2",
      target_interface: "b1",
    },
  ],
  routed_interfaces: [],
};

describe("AciFabricPanel", () => {
  it("does not query or present demo data as a live snapshot", () => {
    const html = renderToStaticMarkup(
      <AciFabricPanel live={false} earliest="now-1h" />,
    );
    expect(html).toContain("ACI fabric snapshot");
    expect(html).toContain("Available when running a live Splunk search");
    expect(html).not.toContain("Devices (");
  });

  it("renders selectable candidate alternatives and zero-hop selection input", () => {
    const html = renderToStaticMarkup(
      <FabricPathCandidates
        snapshot={snapshot}
        sourceId="leaf-a"
        destinationId="leaf-b"
        onSourceChange={() => {}}
        onDestinationChange={() => {}}
      />,
    );
    expect(html).toContain('aria-label="Source leaf or spine"');
    expect(html).toContain('aria-label="Destination leaf or spine"');
    expect(html).toContain('aria-pressed="false"');
    const same = renderToStaticMarkup(
      <FabricPathCandidates
        snapshot={snapshot}
        sourceId="leaf-a"
        destinationId="leaf-a"
        onSourceChange={() => {}}
        onDestinationChange={() => {}}
      />,
    );
    expect(same).toContain("0 hop");
  });

  it("orients reverse-native link interfaces from the selected path direction", () => {
    const label = pathHopLabel(
      {
        devices: snapshot.devices.slice(0, 2),
        links: [
          {
            id: "reverse",
            source: "leaf-b",
            target: "leaf-a",
            source_interface: "b-if",
            target_interface: "a-if",
          },
        ],
      },
      0,
    );
    expect(label).toContain("a-if → b-if");
    expect(label).toContain("next leaf-b (leaf-b)");
  });
});
