import { describe, expect, it } from "vitest";
import { demoGraph } from "../data/demoClient";
import { parsePathEvidenceRows } from "./pathEvidence";
import { assembleStandaloneResult } from "./usePathTrace";

describe("assembleStandaloneResult", () => {
  it("retains verified scope when resolved addresses omit it", () => {
    const request = { src: "10.0.0.1", dst: "10.0.0.2", scope: "prod" };
    const result = assembleStandaloneResult(request, {
      addresses: { src: request.src, dst: request.dst },
      graph: demoGraph("aci"),
      evidence: [],
      rows: [
        {
          row_type: "observation",
          flow_source: "netflow",
          scope: "prod",
          source_profile: "nexus_nxos_netflow",
          profile_status: "mapped",
          observer_device: "192.0.2.1",
          observation_domain_id: "1",
          src: request.dst,
          dst: request.src,
          direction: "reverse",
          src_port: "8088",
          dest_port: "50123",
          protocol: "tcp",
          records: "1",
          first_seen: "120",
          last_seen: "120",
          observers_capped: "1",
        },
      ],
    });
    expect(result.trace.hops[1].detail).toContain(
      "10.0.0.2:8088 → 10.0.0.1:50123",
    );
    expect(result.trace.hops[1].evidence).toBe("observed");
    expect(result.trace.status).toBe("partial");
    expect(result.trace.notes.join(" ")).toContain(
      "observation limit was reached",
    );
  });

  it("retains scoped source, drop, and capped notes with bounded evidence", () => {
    const request = { src: "10.0.0.1", dst: "10.0.0.2", scope: "prod" };
    const envelope = {
      schema_version: 1,
      capture_id: "cap-1",
      scope: "prod",
      src: request.src,
      dst: request.dst,
      protocol: "icmp",
      start: 120,
      end: 130,
      collected_at: 131,
      producer: "admin",
      segments: [
        {
          id: "s1",
          label: "FTD",
          source: "ftd",
          reference: "ref-1",
          observed_at: 125,
          hops: [{ kind: "firewall", label: "FTD-A", evidence: "observed" }],
        },
      ],
    };
    const evidence = parsePathEvidenceRows(
      [{ _raw: JSON.stringify(envelope) }],
      request,
      { start: 100, end: 200 },
    );
    const result = assembleStandaloneResult(request, {
      addresses: request,
      graph: demoGraph("aci"),
      evidence,
      rows: [
        {
          row_type: "observation",
          flow_source: "hubble",
          records: "4",
          drops: "2",
          observers_capped: "1",
        },
      ],
    });
    expect(result.summary.records).toBe(0);
    expect(result.trace.status).toBe("partial");
    expect(result.trace.notes.join(" ")).toContain("Hubble");
    expect(result.trace.notes.join(" ")).toContain("including 2 drops");
    expect(result.trace.notes.join(" ")).toContain(
      "observation limit was reached",
    );
  });
});
