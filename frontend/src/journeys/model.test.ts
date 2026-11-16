import { describe, expect, it } from "vitest";
import fixture from "../../../fixtures/proxy/envoy-v1.40-http-access.json";
import { natJourneys, proxyJourneys } from "./model";
import {
  PROXY_SCHEMA,
  normalizeProxyEvidence,
  proxySearchWindow,
  type ProxyObservation,
} from "../data/proxyEvidence";
import type { EvidenceSelection } from "../data/evidence";
import type { SupplementalResult } from "../data/supplementalEvidence";
import type { SupplementalSourceConfiguration } from "../data/evidenceConfig";
import type { Row } from "../rows";

const selection: EvidenceSelection = {
  schemaVersion: 1,
  workflow: "endpoint",
  selectionId: "one",
  trafficContract: 1,
  window: { start: 100, end: 200 },
  scope: "prod",
  addresses: ["192.0.2.1"],
  contexts: [],
  identityBasis: "endpoint",
  configurationFingerprint: "a".repeat(64),
};
const nat = () => ({
  source_authority: "cisco:sfw:estreamer",
  event_type: "ConnectionEvent",
  scope: "prod",
  scope_mapping_verified: true,
  device_ip: "192.0.2.9",
  event_fingerprint: "b".repeat(64),
  event_time: 120,
  received_time: 125,
  protocol: "tcp",
  direction: "initiator_to_responder",
  reported_initiator_ip: "192.0.2.1",
  reported_initiator_port: 123,
  reported_responder_ip: "192.0.2.2",
  reported_responder_port: 443,
  translated_initiator_ip: "192.0.2.3",
  translated_initiator_port: 456,
  translated_responder_ip: "192.0.2.2",
  translated_responder_port: 443,
});
const proxy = (): ProxyObservation => ({
  schemaVersion: 1,
  source: "proxy_envoy",
  schema: PROXY_SCHEMA,
  scope: "prod",
  routingAuthority: "prod",
  observer: "envoy",
  index: "proxy",
  eventFingerprint: "c".repeat(64),
  eventTime: 120,
  indexedTime: 125,
  streamId: "same",
  durationBasis: "request_start_to_last_byte_out",
  downstream: {
    directPeer: { ip: "192.0.2.1", port: 123 },
    listener: { ip: "192.0.2.2", port: 443 },
  },
  upstream: {
    local: { ip: "192.0.2.3", port: 456 },
    remote: { ip: "192.0.2.4", port: 8080 },
  },
  selectedBackend: { ip: "192.0.2.4", port: 8080 },
  matchedSelectionLegs: ["downstream_direct_peer"],
  limitations: [],
});
const result = (): SupplementalResult<ProxyObservation> => ({
  schemaVersion: 1,
  source: "proxy_envoy",
  selection,
  capturedAt: 300,
  inspectedWindow: proxySearchWindow(selection),
  configurationFingerprint: selection.configurationFingerprint,
  configurationChanged: false,
  state: "complete",
  schemaQualified: true,
  inputCount: 1,
  inputCapped: false,
  outputCapped: false,
  rejected: 0,
  oversized: 0,
  records: [proxy()],
  coverage: [],
});

describe("transport journeys", () => {
  it("does not admit input counts above the source budget even with a false cap flag", () => {
    const r = result();
    r.inputCount = 10001;
    expect(proxyJourneys(r, selection).journeys[0].relation).toBe("unknown");
    r.inputCount = 1;
    r.capturedAt = Number.NaN;
    expect(proxyJourneys(r, selection).journeys[0].relation).toBe("unknown");
  });
  it("keeps each NAT event independent even when tuples are reused", () => {
    const first = nat();
    const second = { ...nat(), event_fingerprint: "d".repeat(64) };
    const built = natJourneys([first, second], "prod", selection.window);
    expect(built.journeys).toHaveLength(2);
    expect(built.journeys[0]).toMatchObject({
      relation: "same_event",
      nativeTime: 120,
      indexedTime: 125,
      legs: [{ kind: "reported" }, { kind: "translated" }],
    });
  });
  it("rejects invalid, wrong scope and out of window NAT events and reports caps", () => {
    const built = natJourneys(
      [
        nat(),
        { ...nat(), scope: "other" },
        { ...nat(), event_time: 200 },
        { ...nat(), reported_initiator_port: 0 },
      ],
      "prod",
      selection.window,
      true,
    );
    expect(built.journeys).toHaveLength(1);
    expect(built.gaps.join(" ")).toMatch(/capped/);
    expect(built.gaps).toHaveLength(4);
  });
  it("keeps concurrent requests with the same stream and tuples separate", () => {
    const r = result();
    r.records.push({ ...proxy(), eventFingerprint: "d".repeat(64) });
    r.inputCount = 2;
    const built = proxyJourneys(r, selection);
    expect(built.journeys).toHaveLength(2);
    expect(built.journeys.every((j) => j.relation === "request_reported")).toBe(
      true,
    );
    expect(built.journeys[0].legs.map((l) => l.kind)).toEqual([
      "downstream",
      "upstream",
    ]);
  });
  it("suppresses association when qualification, configuration, selection or window differ", () => {
    for (const change of [
      { inputCapped: true },
      { schemaQualified: false },
      { configurationChanged: true },
      { state: "staged" as const },
      { sourceScanCapped: true },
      { rejected: 1 },
      { oversized: 1 },
      { sourceScanInvalidCount: 1 },
      { inputCount: -1 },
      { inputCount: NaN },
      { errorCode: "configuration" as const },
      { configurationFingerprint: "d".repeat(64) },
      { inspectedWindow: { start: 0, end: 199 } },
      { selection: { ...selection, selectionId: "other" } },
    ]) {
      expect(
        proxyJourneys({ ...result(), ...change }, selection).journeys[0]
          .relation,
      ).toBe("unknown");
    }
    expect(
      proxyJourneys({ ...result(), outputCapped: true }, selection).gaps.join(
        " ",
      ),
    ).toMatch(/output was capped/);
  });
  it("deduplicates exact source identities and suppresses conflicting identity claims", () => {
    const r = result();
    r.records = [proxy(), structuredClone(proxy())];
    r.inputCount = 2;
    expect(proxyJourneys(r, selection).journeys).toHaveLength(1);
    r.records[0] = {
      ...proxy(),
      upstream: { remote: { ip: "192.0.2.8", port: 8080 } },
      selectedBackend: { ip: "192.0.2.8", port: 8080 },
    };
    r.records[1] = {
      ...proxy(),
      upstream: { remote: { ip: "192.0.2.9", port: 8080 } },
      selectedBackend: { ip: "192.0.2.9", port: 8080 },
    };
    const conflict = proxyJourneys(r, selection);
    expect(conflict.journeys).toHaveLength(1);
    expect(conflict.journeys[0].relation).toBe("unknown");
    expect(conflict.journeys[0].conflictingEvidence).toEqual(r.records);
    expect(conflict.gaps.join(" ")).toMatch(/Conflicting records/);
    const n = nat();
    expect(
      natJourneys([n, { ...n }], "prod", selection.window).journeys,
    ).toHaveLength(1);
    const natConflict = natJourneys(
      [n, { ...n, received_time: 126 }],
      "prod",
      selection.window,
    );
    expect(natConflict.journeys).toHaveLength(1);
    expect(natConflict.journeys[0].relation).toBe("unknown");
    expect(natConflict.gaps.join(" ")).toMatch(/Conflicting records/);
  });
  it("exposes missing upstream and retries without inventing legs", () => {
    const r = result();
    r.records = [
      {
        ...proxy(),
        upstream: undefined,
        selectedBackend: undefined,
        upstreamAttemptCount: 3,
        downstream: { directPeer: { ip: "192.0.2.1" } },
      },
    ];
    const journey = proxyJourneys(r, selection).journeys[0];
    expect(journey.legs).toHaveLength(1);
    expect(journey.gaps.join(" ")).toMatch(/port is missing.*socket endpoint/i);
    expect(journey.gaps.join(" ")).toMatch(/retry endpoints are unavailable/);
  });
  it("rejects invalid proxy payloads and records outside the scope and interval", () => {
    const r = result();
    r.records = [
      proxy(),
      { ...proxy(), scope: "other" },
      { ...proxy(), eventTime: 200 },
      { ...proxy(), eventFingerprint: "bad" },
      { ...proxy(), matchedSelectionLegs: [] },
      { ...proxy(), downstream: { directPeer: { ip: "192.0.2.1", port: -1 } } },
    ];
    r.inputCount = r.records.length;
    const built = proxyJourneys(r, selection);
    expect(built.journeys).toHaveLength(1);
    expect(built.journeys[0].relation).toBe("unknown");
    expect(built.gaps).toHaveLength(6);
  });
  it("preserves zero ports accepted by the source normalizer and flags socket uncertainty", () => {
    const selected = {
      ...selection,
      window: { start: 1791373400, end: 1791373600 },
      addresses: ["192.0.2.10"],
    };
    const config: SupplementalSourceConfiguration = {
      source: "proxy_envoy",
      state: "active",
      indexes: ["proxy_logs"],
      authorities: ["edge-gateway-01"],
      schemaQualified: true,
      staleAfterSeconds: 3600,
      mappings: [
        {
          observer_kind: "envoy_proxy",
          observer: "edge-gateway-01",
          scope: "prod",
          cluster: "",
          mapping_status: "verified",
        },
      ],
    };
    const row = structuredClone(fixture) as Row;
    row.event_time_epoch = Number(row._time);
    row._raw = JSON.stringify({
      ...JSON.parse(String(row._raw)),
      downstream_direct_remote_port: 0,
    });
    const normalized = normalizeProxyEvidence([row], selected, config);
    expect(normalized.rejected).toBe(0);
    const built = proxyJourneys(
      {
        ...result(),
        selection: selected,
        inspectedWindow: proxySearchWindow(selected),
        records: normalized.records,
      },
      selected,
    );
    expect(built.journeys[0].relation).toBe("request_reported");
    expect(built.journeys[0].legs[0].from?.port).toBe(0);
    expect(built.journeys[0].gaps.join(" ")).toMatch(
      /port is zero.*socket endpoint/,
    );
  });
});
