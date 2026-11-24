import { describe, expect, it } from "vitest";
import { nativeObservationHops, nativeSourceHops } from "./nativeObservations";

const request = { src: "10.0.0.1", dst: "10.0.0.2", scope: "lab" };
const row = {
  row_type: "observation",
  flow_source: "netflow",
  source_profile: "nexus_nxos_netflow",
  profile_status: "mapped",
  scope: "lab",
  src: request.src,
  dst: request.dst,
  direction: "forward",
  observer_device: "192.0.2.1",
  observation_domain_id: "1",
  src_port: "50123",
  dest_port: "8088",
  protocol: "tcp",
  records: "1",
  first_seen: "120",
  last_seen: "120",
  interface_in: "ifIndex 100",
  interface_out: "ifIndex 200",
};

describe("nativeObservationHops", () => {
  it("separates exporters and tuples with explicit ordering gaps", () => {
    const hops = nativeObservationHops(
      [row, { ...row, observer_device: "192.0.2.2", src_port: "50124" }],
      request,
    );
    expect(hops.map((hop) => hop.kind)).toEqual([
      "gap",
      "switch",
      "gap",
      "switch",
      "gap",
    ]);
    expect(hops[1].detail).toContain("10.0.0.1:50123");
    expect(hops[3].detail).toContain("10.0.0.1:50124");
    expect(hops[1].in).toBe("ifIndex 100");
    expect(hops[1].out).toBe("ifIndex 200");
    expect(hops.filter((hop) => hop.evidence === "inferred")).toEqual([]);
  });

  it.each([
    { scope: "other" },
    { src: "10.0.0.3" },
    { profile_status: "unmapped" },
    { observation_domain_id: "" },
    { direction: "reverse" },
    { dest_port: "NaN" },
    { first_seen: "Infinity" },
    { last_seen: "119" },
    { records: "-1" },
  ])("rejects an invalid native observation %j", (change) => {
    expect(() =>
      nativeObservationHops([{ ...row, ...change }], request),
    ).toThrow("scope or tuple validation");
  });

  it("preserves reverse tuple orientation", () => {
    const hops = nativeObservationHops(
      [
        {
          ...row,
          src: request.dst,
          dst: request.src,
          src_port: "8088",
          dest_port: "50123",
          direction: "reverse",
        },
      ],
      request,
    );
    expect(hops[1].detail).toContain("10.0.0.2:8088 → 10.0.0.1:50123");
  });

  it("groups one exporter visually while retaining separate tuples", () => {
    const hops = nativeObservationHops(
      [row, { ...row, src_port: "50124" }],
      request,
    );
    expect(hops.filter((hop) => hop.kind === "switch")).toHaveLength(1);
    expect(hops[1].detail).toContain(":50123");
    expect(hops[1].detail).toContain(":50124");
  });

  it("renders a qualified firewall aggregate with explicit limitations", () => {
    const hops = nativeSourceHops(
      [
        {
          ...row,
          flow_source: "ftd",
          source_profile: "cisco_secure_firewall_estreamer",
          references: ["receipt-1"],
        },
      ],
      request,
    );
    expect(hops[1].kind).toBe("firewall");
    expect(hops[1].detail).toContain("may include separate connections");
    expect(hops[1].support).toContain("receipt-1");
    expect(hops[1].detail).not.toContain(":50123");
  });

  it.each(["1", "2"])(
    "qualifies %s point-time FTD records in an aggregate",
    (count) => {
      const hops = nativeSourceHops(
        [
          {
            ...row,
            flow_source: "ftd",
            source_profile: "cisco_secure_firewall_estreamer",
            point_time_records: count,
            records: "2",
            first_seen: "120",
            last_seen: "121",
          },
        ],
        request,
      );
      expect(hops[1].detail).toContain(
        `${count} of 2 records report only a start time`,
      );
      expect(hops[1].detail).toContain("source timestamps");
    },
  );

  it.each([
    { scope: "other" },
    { src: "10.0.0.9" },
    { first_seen: null },
    { profile_status: "unmapped" },
  ])("rejects an invalid Hubble authority or interval %j", (change) => {
    expect(() =>
      nativeSourceHops(
        [
          {
            ...row,
            flow_source: "hubble",
            source_profile: "cilium_hubble",
            observer_device: "node-1",
            ...change,
          },
        ],
        request,
      ),
    ).toThrow("scope or identity validation");
  });
});
