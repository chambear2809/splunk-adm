import { describe, expect, it } from "vitest";
import {
  buildTrafficMixSearch,
  selectTrafficMixIndex,
  summarizeTrafficMixRows,
} from "./trafficMix";
import type { ProtocolConfiguration } from "./contract";

describe("protocol traffic mix", () => {
  const config: ProtocolConfiguration = {
    fingerprint: "fp-1",
    profiles: [
      {
        id: "qos-dc1",
        source: "protocol_qos_icmp",
        lens: "qos_icmp",
        scope: "prod:dc1",
        index: "netflow",
        observer: "stream-01",
        validFrom: 1700000000,
        validUntil: 1900000000,
        extra: { sourceKind: "stream_netflow" },
      },
      {
        id: "dns-dc1",
        source: "protocol_dns_ops",
        lens: "dns_ops",
        scope: "prod:dc1",
        index: "stream_dns",
        observer: "stream-01",
        validFrom: 1700000000,
        validUntil: 1900000000,
      },
    ],
  };

  it("selects explicit NetFlow index for the active scope and returns undefined when uncovered", () => {
    expect(selectTrafficMixIndex(config, "prod:dc1")).toBe("netflow");
    expect(selectTrafficMixIndex(config, "prod:dc2")).toBeUndefined();
  });

  it("builds bounded NetFlow traffic-mix SPL with quoted index and no _raw", () => {
    const spl = buildTrafficMixSearch({ index: "netflow", maxRows: 64 });
    expect(spl).toContain('index="netflow"');
    expect(spl).toContain('sourcetype="stream:netflow"');
    expect(spl).toContain("| head 65");
    expect(spl).toContain(
      "if(isnotnull(bytes_in) OR isnotnull(bytes_out), coalesce(tonumber(bytes_in), 0)+coalesce(tonumber(bytes_out), 0), null())",
    );
    expect(spl).toContain(
      "| table proto_num port_num ip_family total_bytes flows",
    );
    expect(spl).not.toContain("_raw");
  });

  it("computes protocol shares and IPv4/IPv6 split accurately", () => {
    const res = summarizeTrafficMixRows(
      [
        {
          proto_num: 6,
          port_num: 443,
          ip_family: "IPv4",
          total_bytes: 750000,
          flows: 120,
        },
        {
          proto_num: 6,
          port_num: 5432,
          ip_family: "IPv6",
          total_bytes: 250000,
          flows: 40,
        },
      ],
      { capped: false, index: "netflow", nowSec: 1800000000 },
    );
    expect(res.status).toBe("ok");
    expect(res.ipv4Pct).toBe(75);
    expect(res.ipv6Pct).toBe(25);
    expect(res.topProtocols[0].label).toBe("HTTPS/TLS (443)");
    expect(res.topProtocols[0].sharePct).toBe(75);
    expect(res.topProtocols[1].label).toBe("Postgres (5432)");
    expect(res.topProtocols[1].sharePct).toBe(25);
  });

  it("marks capped results as unknown rather than ok or none_observed", () => {
    const emptyCapped = summarizeTrafficMixRows([], {
      capped: true,
      index: "netflow",
      nowSec: 1800000000,
    });
    expect(emptyCapped.status).toBe("unknown");

    const nonEmptyCapped = summarizeTrafficMixRows(
      [
        {
          proto_num: 6,
          port_num: 443,
          ip_family: "IPv4",
          total_bytes: 100,
          flows: 2,
        },
      ],
      { capped: true, index: "netflow", nowSec: 1800000000 },
    );
    expect(nonEmptyCapped.status).toBe("unknown");
  });
});
