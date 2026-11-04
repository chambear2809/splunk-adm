import { execFileSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { normalizeAciFabricSnapshot } from "./aciFabric";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
// CI may expose a platform-specific Python launcher through this documented
// override; execFileSync still receives an executable and argv separately.
const python =
  process.env.ATLAS_PYTHON ??
  (process.platform === "win32" ? "python" : "python3");

// Exercise the real Python validator/projector and the browser contract together.
// The envelope is synthetic and includes all 23 classes and two-pass digests.
describe("native ACI reader/browser contract", () => {
  it.each(["1", "2"])(
    "accepts the qualified reader output v%s with absent optional device metadata",
    (version) => {
      const output = execFileSync(
        python,
        [
          "-c",
          `import json, sys
sys.path.insert(0, "tests")
from test_aci_fabric_snapshot import valid_envelope, FabricSnapshotTests, PROFILE, reader, schema
version = "${version}"
if version == "1":
    schema.CLASSES_V2 = schema.CLASSES_V1
envelope = valid_envelope("00000000-0000-0000-0000-000000000001", 101, routed=True)
for event in envelope:
    event["schema"] = "application_atlas.aci_poll.v" + version
    event["schema_version"] = int(version)
rows = FabricSnapshotTests().reader_rows([envelope])
for row in rows:
    row["sourcetype"] = "adm:aci_poll:v" + version
print(json.dumps(reader.read_fabric_snapshot(rows, {**PROFILE, "enabled": True, "poll_version": version}, 0, 102, 102)))`,
        ],
        { cwd: repoRoot, encoding: "utf8", timeout: 10000 },
      );
      const snapshot = normalizeAciFabricSnapshot(JSON.parse(output), 102);
      expect(snapshot.captured_at).toBe(101);
      expect(snapshot.devices).toHaveLength(2);
      expect(snapshot.links).toHaveLength(1);
      expect(snapshot.links[0].source_interface).toBe("eth1/1");
      expect(snapshot.routed_interfaces).toHaveLength(1);
      const routed = snapshot.routed_interfaces[0];
      expect(routed.device).toBe(snapshot.devices[0].id);
      expect(routed.interface).toBe("eth1/24.15");
      expect(routed.parent_interface).toBe("eth1/24");
      expect(routed.encap).toBe("vlan-304");
      expect(routed.traversal).toBe("not_observed");
      expect(routed.connection_dn).toMatch(
        /\/node-101\/stpathatt-\[eth1\/24\]\/conndef\//,
      );
      expect(
        routed.connection_dn?.startsWith(routed.routed_out_definition_dn + "/"),
      ).toBe(true);
      expect(
        snapshot.devices.every((device) => device.serial === undefined),
      ).toBe(true);
    },
  );

  it("rejects unsupported ACI poll sourcetypes", () => {
    const raw = JSON.stringify({
      schema: "application_atlas.aci_fabric_snapshot.v1",
      classification: "inventory_snapshot",
      qualification: "complete_two_pass_capture",
      traversal: "not_observed",
      provenance: {
        source: "atlas:aci_poll",
        sourcetype: "adm:aci_poll:v3",
      },
    });
    expect(() => normalizeAciFabricSnapshot([{ snapshot: raw }], 102)).toThrow(
      "Unqualified or incomplete ACI fabric snapshot",
    );
  });
});
