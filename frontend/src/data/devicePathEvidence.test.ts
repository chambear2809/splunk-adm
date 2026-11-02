import { describe, expect, it } from "vitest";
import {
  resolveDevicePath,
  type DevicePathInput,
  type EvidenceRecord,
} from "./devicePathEvidence";

const record = (
  extra: Partial<EvidenceRecord> & Pick<EvidenceRecord, "kind">,
): EvidenceRecord => ({
  id: "x",
  observedAt: 95,
  receivedAt: 96,
  ...extra,
});
const input = (): DevicePathInput => {
  const base = { fabric: "f", routingDomain: "vrf" };
  const authorities = (["ownership", "attachment", "topology"] as const).map(
    (layer) => ({ ...base, source: layer, layer }),
  );
  return {
    asOf: 100,
    receiptCutoff: 105,
    maxAge: 10,
    maxReceiptDelay: 5,
    ...base,
    authorities,
    endpoints: [
      {
        address: "192.0.2.1",
        identitySource: "appdynamics",
        identityAuthority: "controller",
        identityId: "a",
      },
      {
        address: "192.0.2.2",
        identitySource: "other",
        identityAuthority: "inventory",
        identityId: "b",
      },
    ],
    snapshots: authorities.map((a) => ({
      ...a,
      snapshotId: a.source,
      producer: "other",
      complete: true,
      expectedCount: 0,
      records: [],
    })),
  };
};
const ready = () => {
  const v = input();
  v.snapshots[0].records = v.endpoints.map((e, i) =>
    record({ id: `o${i}`, kind: "owner", ...e }),
  );
  v.snapshots[1].records = v.endpoints.map((e, i) =>
    record({
      id: `a${i}`,
      kind: "attachment",
      identitySource: e.identitySource,
      identityAuthority: e.identityAuthority,
      identityId: e.identityId,
      device: `d${i}`,
      interface: "eth0",
      translation: "none",
    }),
  );
  v.snapshots[2].records = [
    record({
      id: "l",
      kind: "link",
      device: "d0",
      interface: "eth1",
      peerDevice: "d1",
      peerInterface: "eth1",
      exporter: "switch",
      translation: "none",
    }),
  ];
  v.snapshots.forEach((s) => {
    s.expectedCount = s.records.length;
  });
  return v;
};
const reason = (v: DevicePathInput) => resolveDevicePath(v).reason;

describe("device path evidence", () => {
  it("returns a provenance-bearing candidate, never an observed traversal", () => {
    const r = resolveDevicePath(ready());
    expect(r.status).toBe("candidate");
    expect(r.traversal).toBe("not_observed");
    expect(r.alternatives[0][0].provenance.recordId).toBe("l");
    expect(r.endpoints[0].owners[0].provenance.recordId).toBe("o0");
  });
  it("preserves identity namespaces and rejects competing IP owners", () => {
    const v = ready();
    v.snapshots[0].records.push(
      record({
        id: "competing",
        kind: "owner",
        ...v.endpoints[0],
        identitySource: "teastore_otel",
      }),
    );
    v.snapshots[0].expectedCount++;
    const r = resolveDevicePath(v);
    expect(r.reason).toBe("competing_owners");
    expect(r.endpoints[0].owners).toHaveLength(2);
  });
  it("requires explicit in-scope authority and complete captures", () => {
    const v = ready();
    v.snapshots[0].fabric = "other";
    expect(reason(v)).toBe("missing_snapshot");
    v.snapshots[0].fabric = "f";
    v.snapshots[0].routingDomain = "other";
    expect(reason(v)).toBe("missing_snapshot");
    v.snapshots[0].routingDomain = "vrf";
    v.snapshots[0].complete = false;
    expect(reason(v)).toBe("partial_snapshot");
    v.snapshots[0].complete = true;
    v.snapshots[0].source = "untrusted";
    expect(reason(v)).toBe("unqualified_authority");
  });
  it("rejects stale, future, late and post-cutoff records", () => {
    for (const changes of [
      { observedAt: 89 },
      { observedAt: 101 },
      { receivedAt: 102 },
      { receivedAt: 106 },
      { receivedAt: 94 },
    ]) {
      const v = ready();
      Object.assign(v.snapshots[0].records[0], changes);
      expect(reason(v)).toBe("time_window");
    }
  });
  it("rejects conflicting replays and unordered captures", () => {
    const v = ready();
    v.snapshots[0].records.push({
      ...v.snapshots[0].records[0],
      identityId: "different",
    });
    v.snapshots[0].expectedCount++;
    expect(reason(v)).toBe("replay_conflict");
    const w = ready();
    w.snapshots.push(structuredClone(w.snapshots[0]));
    expect(reason(w)).toBe("snapshot_conflict");
  });
  it("fails closed on movement, translation, missing interfaces and exporter", () => {
    const v = ready();
    v.snapshots[1].records.push({
      ...v.snapshots[1].records[0],
      id: "moved",
      device: "new",
    });
    v.snapshots[1].expectedCount++;
    expect(reason(v)).toBe("attachment_ambiguous");
    for (const translation of ["nat", "overlay", "unknown"] as const) {
      const w = ready();
      w.snapshots[1].records[0].translation = translation;
      expect(reason(w)).toBe("translation_ambiguous");
    }
    const w = ready();
    w.snapshots[2].records[0].exporter = "";
    expect(reason(w)).toBe("incomplete_record");
    w.snapshots[2].records[0].exporter = "x";
    w.snapshots[1].records[0].interface = "";
    expect(reason(w)).toBe("incomplete_record");
  });
  it("quarantines current APIC and watch-loss producers", () => {
    const v = ready();
    v.snapshots[1].producer = "apic";
    expect(reason(v)).toBe("apic_quarantined");
    v.snapshots[1].producer = "teastore_watch";
    expect(reason(v)).toBe("watch_discontinuity");
  });
  it("retains ECMP alternatives and reports disconnected topology", () => {
    const v = ready();
    v.snapshots[2].records.push({
      ...v.snapshots[2].records[0],
      id: "other",
      interface: "eth2",
      peerInterface: "eth2",
    });
    v.snapshots[2].expectedCount++;
    expect(resolveDevicePath(v).alternatives).toHaveLength(2);
    v.snapshots[2].records = [];
    v.snapshots[2].expectedCount = 0;
    expect(reason(v)).toBe("disconnected_or_unknown");
  });
  it("suppresses all paths when the path or input cap is exceeded", () => {
    const v = ready();
    v.snapshots[2].records = Array.from({ length: 17 }, (_, i) => ({
      ...v.snapshots[2].records[0],
      id: String(i),
    }));
    v.snapshots[2].expectedCount = 17;
    const r = resolveDevicePath(v);
    expect(r.reason).toBe("path_cap");
    expect(r.alternatives).toEqual([]);
    const w = ready();
    w.snapshots[2].records = Array.from({ length: 513 }, (_, i) =>
      record({ id: String(i), kind: "link" }),
    );
    expect(reason(w)).toBe("input_cap");
  });
});
