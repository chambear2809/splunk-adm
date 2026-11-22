import { describe, expect, it } from "vitest";
import type { TraceHop } from "../data/pathTrace";
import { attachGnmiContext } from "./gnmiContext";

const hop: TraceHop = {
  kind: "switch",
  device: "198.18.131.3",
  label: "Nexus exporter 198.18.131.3",
  evidence: "observed",
  sources: ["Stream NetFlow"],
  seen: ["ifIndex 369098851"],
};
const row = (extra: Record<string, unknown> = {}) => ({
  row_type: "interface_context",
  source: "atlas:gnmi:pilot",
  sourcetype: "otel:gnmi",
  "atlas.scope": "validation-k3s-splunk",
  "atlas.interface": "Po100",
  "atlas.ifindex": "369098851",
  "server.address": "198.18.131.3:50051",
  metric_name: "openconfig.interfaces.interface.state.counters.in-discards",
  value: "2",
  _time: 100,
  ...extra,
});

describe("attachGnmiContext", () => {
  it("enriches only the exact observed exporter/interface", () => {
    const [result] = attachGnmiContext(
      [hop],
      [
        row(),
        row({
          metric_name:
            "openconfig.interfaces.interface.state.oper-status_state",
          state: "UP",
          value: 1,
        }),
      ],
      { scope: "validation-k3s-splunk", earliest: 0, latest: 120 },
    );
    expect(result.interfaceContext).toContainEqual(
      expect.objectContaining({
        interface: "Po100",
        ifIndex: "369098851",
        authority: "198.18.131.3",
        operStatus: { value: "UP", sampledAt: 100 },
        counters: { "in-discards": { value: 2, sampledAt: 100 } },
      }),
    );
  });

  it("does not turn unmatched telemetry into a hop or health", () => {
    const [result] = attachGnmiContext(
      [hop],
      [row({ "server.address": "198.18.131.4:50051" })],
      { scope: "validation-k3s-splunk", earliest: 0, latest: 120 },
    );
    expect(result.interfaceContext).toBeUndefined();
    expect(
      attachGnmiContext([], [row()], { scope: "validation-k3s-splunk" }),
    ).toEqual([]);
  });

  it("rejects wrong scope and out-of-window samples", () => {
    const [result] = attachGnmiContext(
      [hop],
      [row({ "atlas.scope": "other", _time: 300 })],
      { scope: "validation-k3s-splunk", earliest: 0, latest: 120 },
    );
    expect(result.interfaceContext).toBeUndefined();
  });

  it("keeps fresh counters while an earlier status sample expires", () => {
    const [result] = attachGnmiContext(
      [hop],
      [
        row({ _time: 185, value: 4 }),
        row({ _time: 180, value: 3 }),
        row({
          _time: 150,
          metric_name:
            "openconfig.interfaces.interface.state.oper-status_state",
          state: "UP",
          value: 1,
        }),
      ],
      { scope: "validation-k3s-splunk", earliest: 120, latest: 200 },
    );
    expect(result.interfaceContext?.[0].operStatus).toBeUndefined();
    expect(result.interfaceContext?.[0].counters).toEqual({
      "in-discards": { value: 4, sampledAt: 185 },
    });
  });
  it("never borrows a counter from a different observed interface index", () => {
    const [result] = attachGnmiContext(
      [hop],
      [row({ "atlas.ifindex": "369098852" })],
      { scope: "validation-k3s-splunk", earliest: 0, latest: 120 },
    );
    expect(result.interfaceContext).toBeUndefined();
  });
});
