import { describe, expect, it } from "vitest";
import { sameNatIp, strictIp, usableNatIp } from "./ip";

describe("NAT endpoint address validation", () => {
  it.each(["192.0.2.44", "2001:db8::1", "2001:db8:0:0:0:0:0:1"])(
    "accepts unicast IP %s",
    (ip) => {
      expect(strictIp(ip)).toBe(true);
      expect(usableNatIp(ip)).toBe(true);
    },
  );

  it.each([
    "0.0.0.0",
    "0.1.2.3",
    "255.255.255.255",
    "224.0.0.1",
    "239.255.255.255",
    "240.0.0.1",
    "::",
    "0:0:0:0:0:0:0:0",
    "ff02::1",
    "::ffff:192.0.2.1",
    "::1:2:3:4:5:6:7:8",
    "1:2:3:4:5:6:7:8::",
    "192.0.2.999",
  ])("rejects NAT sentinel/non-unicast IP %s", (ip) => {
    expect(usableNatIp(ip)).toBe(false);
  });

  it.each([
    ["2001:DB8::1", "2001:0db8:0:0:0:0:0:1"],
    ["192.0.2.44", "192.0.2.44"],
  ])("recognizes equivalent address spellings %s and %s", (left, right) => {
    expect(sameNatIp(left, right)).toBe(true);
  });

  it("recognizes a real IPv6 address change", () => {
    expect(sameNatIp("2001:db8::1", "2001:db8::2")).toBe(false);
  });
});
