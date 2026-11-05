import { describe, expect, it } from "vitest";
import {
  decodeNxosIfIndex,
  ifIndexOf,
  isRawIfIndex,
  unnamedIfIndexLabel,
} from "./ifIndex";

describe("NX-OS ifIndex decoding", () => {
  // IF-MIB ifDescr polled by SC4SNMP from ACI 16.1 leaves and spines.
  it.each([
    [369098752, "port-channel1"],
    [369098753, "port-channel2"],
    [436207616, "Ethernet1/1"],
    [436211712, "Ethernet1/2"],
    [436342784, "Ethernet1/34"],
    [436342818, "Ethernet1/34.34"],
    [436330505, "Ethernet1/31.9"],
    [151060491, "Vlan11"],
    [335544321, "loopback1"],
    [335546367, "loopback2047"],
    [402718730, "Tunnel10"],
    [83886080, "mgmt0"],
  ])("decodes %i as %s", (n, name) => {
    expect(decodeNxosIfIndex(n)).toBe(name);
  });

  it("leaves unknown layouts and non-NX-OS exporters as neutral ifIndex text", () => {
    expect(decodeNxosIfIndex(7)).toBeUndefined();
    expect(decodeNxosIfIndex(0x1a080000)).toBeUndefined(); // slot 2: layout not observed
    expect(unnamedIfIndexLabel(369098753, true)).toBe(
      "port-channel2 (decoded)",
    );
    expect(unnamedIfIndexLabel(9, false)).toBe("ifIndex 9");
    expect(ifIndexOf("ifIndex 369098753")).toBe(369098753);
    expect(ifIndexOf("Eth1/5")).toBeUndefined();
    expect(isRawIfIndex("ifIndex 9 > ?")).toBe(true);
    expect(isRawIfIndex("port-channel2 > ?")).toBe(false);
  });
});
