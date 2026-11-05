import { describe, expect, it } from "vitest";
import { DEMO_FLOW_DEVICES, demoDeviceFlows } from "./demoClient";
import {
  compactInterface,
  deviceFlowSummary,
  deviceFlowsSearch,
  interfaceSides,
  pathTraceSearch,
  rowsToDeviceFlows,
  type DeviceFlows,
} from "./deviceFlows";
import { mergeDeviceFlows } from "../trace/traceModel";

describe("device flows", () => {
  it("parses the demo VDS exporter and leaf ACL-log conversations", () => {
    expect(DEMO_FLOW_DEVICES).toEqual(["192.0.2.73", "pod-1/node-103"]);
    const vds = demoDeviceFlows("192.0.2.73");
    expect(vds.conversations).toEqual([
      expect.objectContaining({
        src: "10.30.40.25",
        srcName: "win-client-01",
        dst: "10.20.30.40",
        destPort: 5432,
        protocol: "tcp",
        bytes: 60,
        flows: 1,
        interfaces: ["ifIndex 18 > ifIndex 14"],
        blocked: false,
      }),
    ]);
    expect(vds.totals).toEqual({ conversations: 1, flows: 1, bytes: 60 });
    const leaf = demoDeviceFlows("pod-1/node-103");
    expect(leaf.conversations[0].blocked).toBe(true);
    expect(leaf.conversations[0].bytes).toBeUndefined();
    expect(deviceFlowSummary(leaf)).toEqual({
      peers: 2,
      blocked: 1,
      overlay: 0,
    });
    expect(demoDeviceFlows("unknown").conversations).toEqual([]);
  });

  it("orders by bytes, keeps totals and flags truncation", () => {
    const rows = [
      {
        src: "a",
        dst: "b",
        protocol: "tcp",
        bytes: "5",
        flows: "2",
        total_conversations: "300",
        total_flows: "900",
        truncated: "1",
        records_capped: "1",
        segments: ["5001"],
      },
      { src: "c", dst: "d", protocol: "udp", bytes: "50", flows: "1" },
    ];
    const f = rowsToDeviceFlows("10.0.0.1", rows);
    expect(f.conversations.map((c) => c.src)).toEqual(["c", "a"]);
    expect(f.totals.conversations).toBe(300);
    expect(f.truncated).toBe(true);
    expect(f.recordsCapped).toBe(true);
    expect(deviceFlowSummary(f).overlay).toBe(1);
  });

  it("keeps exactly the configured top N across exporter tokens", () => {
    const part = (prefix: string): DeviceFlows =>
      rowsToDeviceFlows(
        prefix,
        Array.from({ length: 3 }, (_, i) => ({
          src: `${prefix}${i}`,
          dst: "d",
          protocol: "tcp",
          bytes: String(10 * i + (prefix === "x" ? 1 : 0)),
          flows: "1",
          total_conversations: "5",
          flows_limit: "3",
          truncated: "1",
        })),
      );
    const one = part("x");
    expect(one.limit).toBe(3);
    const merged = mergeDeviceFlows("dev", [one, part("y")]);
    expect(merged.limit).toBe(3);
    expect(merged.conversations.map((c) => c.src)).toEqual(["x2", "y2", "x1"]);
    expect(merged.totals.conversations).toBe(10);
  });

  it("splits interface pairs into compact In and Out sides", () => {
    expect(compactInterface("port-channel2")).toBe("po2");
    expect(compactInterface("Ethernet1/49")).toBe("Eth1/49");
    expect(compactInterface("port-channel2 (vpc-1-22-UCS-FI)")).toBe(
      "po2 · vpc-1-22-UCS-FI",
    );
    const sides = interfaceSides([
      "port-channel1 > vpc-1-22-UCS-FI (inferred)",
      "port-channel1",
      "→ Ethernet1/2",
    ]);
    expect(sides.in).toEqual([
      { text: "po1", title: "port-channel1", inferred: false },
    ]);
    expect(sides.out).toEqual([
      {
        text: "vpc-1-22-UCS-FI",
        title: "vpc-1-22-UCS-FI (inferred)",
        inferred: true,
      },
      { text: "Eth1/2", title: "Ethernet1/2", inferred: false },
    ]);
    expect(interfaceSides(["?"])).toEqual({ in: [], out: [] });
  });

  it("rejects untrusted rows and other devices", () => {
    expect(() => rowsToDeviceFlows("x", {})).toThrow();
    expect(() => rowsToDeviceFlows("x", [{ src: "a" }])).toThrow();
    expect(() =>
      rowsToDeviceFlows("x", [
        { device: "y", src: "a", dst: "b", protocol: "tcp" },
      ]),
    ).toThrow(/another device/);
    expect(
      rowsToDeviceFlows("x", [
        { src: "a", dst: "b", protocol: "tcp", bytes: "-1" },
      ]).conversations[0].bytes,
    ).toBeUndefined();
  });

  it("builds bounded searches only from safe tokens", () => {
    expect(deviceFlowsSearch("pod-1/node-103")).toBe(
      "| `adm_device_flows(pod-1/node-103)`",
    );
    expect(() => deviceFlowsSearch("a) | delete")).toThrow();
    expect(pathTraceSearch("10.1.1.1", "10.1.1.2")).toBe(
      "| `adm_path_trace(10.1.1.1,10.1.1.2)`",
    );
    expect(() => pathTraceSearch("web01", "10.1.1.2")).toThrow();
  });
});
