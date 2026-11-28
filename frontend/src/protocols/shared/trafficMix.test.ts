import { describe, expect, it } from "vitest";
import type { ProtocolConfiguration } from "./contract";
import {
  buildTrafficMixSearch,
  selectTrafficMixIndex,
  summarizeTrafficMixRows,
} from "./trafficMix";

describe("Hub NetFlow traffic mix", () => {
  const config: ProtocolConfiguration = {
    fingerprint: "fp-1",
    profiles: [
      {
        id: "p-qos",
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
        id: "p-routing-dme",
        source: "protocol_routing",
        lens: "routing",
        scope: "prod:dme-only",
        index: "cisco_dc",
        observer: "leaf1",
        validFrom: 1700000000,
        validUntil: 1900000000,
      },
    ],
  };

  it("selects verified NetFlow index and ignores DME-only or uncovered scopes", () => {
    expect(selectTrafficMixIndex(config, "prod:dc1")).toBe("netflow");
    expect(selectTrafficMixIndex(config, "prod:dme-only")).toBeUndefined();
    expect(selectTrafficMixIndex(config, "prod:dc2")).toBeUndefined();
  });

  it("builds bounded NetFlow traffic-mix SPL with service-port bucketing, fillnull, and eventstats grand totals", () => {
    const spl = buildTrafficMixSearch({ index: "netflow", maxRows: 64 });
    expect(spl).toContain('index="netflow"');
    expect(spl).toContain('sourcetype="stream:netflow"');
    expect(spl).toContain("service_port=case(");
    expect(spl).toContain("| fillnull value=-1 proto_num service_port");
    expect(spl).toContain(
      "if(isnotnull(bytes_in) OR isnotnull(bytes_out), coalesce(tonumber(bytes_in), 0)+coalesce(tonumber(bytes_out), 0), null())",
    );
    expect(spl).toContain("| eventstats sum(total_bytes) AS grand_bytes");
    expect(spl).toContain("| head 65");
    expect(spl).toContain(
      "| table proto_num service_port ip_family total_bytes flows grand_bytes grand_flows grand_ipv6_bytes grand_ipv6_flows",
    );
    expect(spl).not.toContain("_raw");
  });

  it("computes protocol shares, ephemeral buckets, and exact IPv4/IPv6 splits using grand totals", () => {
    const res = summarizeTrafficMixRows(
      [
        {
          proto_num: 6,
          service_port: 443,
          ip_family: "IPv4",
          total_bytes: 500000,
          flows: 120,
          grand_bytes: 1000000,
          grand_flows: 200,
          grand_ipv6_bytes: 250000,
          grand_ipv6_flows: 50,
        },
        {
          proto_num: 6,
          service_port: -1,
          ip_family: "IPv6",
          total_bytes: 250000,
          flows: 50,
          grand_bytes: 1000000,
          grand_flows: 200,
          grand_ipv6_bytes: 250000,
          grand_ipv6_flows: 50,
        },
      ],
      { capped: true, index: "netflow", nowSec: 1800000000, limit: 64 },
    );
    expect(res.status).toBe("unknown");
    expect(res.totalBytes).toBe(1000000);
    expect(res.totalFlows).toBe(200);
    expect(res.ipv4Pct).toBe(75);
    expect(res.ipv6Pct).toBe(25);
    expect(res.topProtocols[0].label).toBe("HTTPS/TLS (443)");
    expect(res.topProtocols[0].sharePct).toBe(50);
    expect(res.topProtocols[1].label).toBe("Other TCP");
    expect(res.topProtocols[1].sharePct).toBe(25);
    expect(res.summary).toContain("top 64 buckets shown");
    expect(res.statusReason).toMatch(/eventstats/i);
  });

  it("marks capped empty results as unknown rather than ok or none_observed", () => {
    const emptyCapped = summarizeTrafficMixRows([], {
      capped: true,
      index: "netflow",
      nowSec: 1800000000,
    });
    expect(emptyCapped.status).toBe("unknown");
    expect(emptyCapped.statusReason).toBeTruthy();

    const clean = summarizeTrafficMixRows(
      [
        {
          proto_num: 1,
          service_port: -1,
          ip_family: "IPv4",
          total_bytes: 1024,
          flows: 10,
        },
      ],
      { capped: false, index: "netflow", nowSec: 1800000000 },
    );
    expect(clean.status).toBe("ok");
    expect(clean.topProtocols[0].label).toBe("ICMP");
  });
});
