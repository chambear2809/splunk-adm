import { describe, expect, it } from "vitest";
import fixture from "../../../fixtures/proxy/envoy-v1.40-http-access.json";
import {
  buildProxySearch,
  normalizeProxyEvidence,
  proxySearchWindow,
} from "./proxyEvidence";
import type { EvidenceSelection } from "./evidence";
import type { SupplementalSourceConfiguration } from "./evidenceConfig";
import type { Row } from "../rows";

const selection: EvidenceSelection = {
  schemaVersion: 1,
  workflow: "endpoint",
  selectionId: "proxy-test",
  trafficContract: 1,
  window: { start: 1791373400, end: 1791373600 },
  scope: "prod",
  addresses: ["192.0.2.10"],
  contexts: [],
  identityBasis: "scoped endpoint",
  configurationFingerprint: "a".repeat(64),
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

const sourceRow = (): Row => {
  const row = structuredClone(fixture) as Row;
  row.event_time_epoch = Number(row._time);
  return row;
};
const raw = (row: Row): Record<string, unknown> =>
  JSON.parse(String(row._raw)) as Record<string, unknown>;
const setRaw = (row: Row, changes: Record<string, unknown>) => {
  row._raw = JSON.stringify({ ...raw(row), ...changes });
};

describe("Envoy proxy evidence contract", () => {
  it("builds bounded SPL for the exact selected scope, observer and endpoint legs", () => {
    const search = buildProxySearch(config, selection);
    expect(search).toContain('sourcetype="atlas:proxy:envoy_access"');
    expect(search).toContain('"edge-gateway-01"');
    expect(search).toContain('"routing_authority")="prod"');
    expect(search).toContain('"access_log_type")="DownstreamEnd"');
    expect(search).toContain(
      'cidrmatch("192.0.2.10/32",json_extract(_raw,"downstream_direct_remote_ip"))',
    );
    expect(search).toContain(
      'cidrmatch("192.0.2.10/32",json_extract(_raw,"upstream_remote_ip"))',
    );
    expect(search).toContain("head 10001");
    expect(search).toContain("head 64");
    expect(search).toContain("event_time_epoch=tonumber(_time)");
    expect(search).toContain("_raw _time event_time_epoch _indextime");
    expect(search).toContain('kind="supplemental_record"');
    expect(search).toContain('kind="supplemental_completion"');
    expect(search).toContain("returned_count");
    expect(search).not.toMatch(/x-forwarded-for|xff/i);
  });

  it("normalizes one DownstreamEnd event while keeping transport legs distinct", () => {
    const row = sourceRow();
    const result = normalizeProxyEvidence([row], selection, config);
    expect(result.rejected).toBe(0);
    expect(result.records).toHaveLength(1);
    expect(result.records[0]).toMatchObject({
      source: "proxy_envoy",
      schema: "application_atlas.envoy_http_access.v1",
      scope: "prod",
      observer: "edge-gateway-01",
      eventTime: 1791373500.125,
      streamId: "stream-1",
      downstream: {
        directPeer: { ip: "192.0.2.10", port: 54321 },
        listener: { ip: "198.51.100.20", port: 443 },
      },
      upstream: {
        local: { ip: "203.0.113.2", port: 45678 },
        remote: { ip: "203.0.113.8", port: 8443 },
        cluster: "payments-v2",
      },
      selectedBackend: { ip: "203.0.113.8", port: 8443 },
      durationMilliseconds: 25,
      durationBasis: "request_start_to_last_byte_out",
      responseCode: 200,
      matchedSelectionLegs: ["downstream_direct_peer"],
    });
  });

  it("matches a selected backend only from Envoy's upstream remote address", () => {
    const backendSelection = { ...selection, addresses: ["203.0.113.8"] };
    const result = normalizeProxyEvidence(
      [sourceRow()],
      backendSelection,
      config,
    );
    expect(result.rejected).toBe(0);
    expect(result.records[0].selectedBackend).toEqual({
      ip: "203.0.113.8",
      port: 8443,
    });
    expect(result.records[0].matchedSelectionLegs).toEqual([
      "upstream_selected_endpoint",
    ]);
  });

  it("does not create a backend from the cluster name when upstream address is absent", () => {
    const row = sourceRow();
    setRaw(row, {
      upstream_remote_ip: null,
      upstream_remote_port: null,
      upstream_local_ip: null,
      upstream_local_port: null,
      upstream_cluster: "payments-v2",
    });
    const result = normalizeProxyEvidence([row], selection, config);
    expect(result.rejected).toBe(0);
    expect(result.records[0].selectedBackend).toBeUndefined();
    expect(result.records[0].upstream?.cluster).toBe("payments-v2");
    expect(result.records[0].limitations.join(" ")).toMatch(
      /selected upstream remote IP/,
    );
  });

  it("allows a missing stream ID but explicitly labels it and never joins by ID", () => {
    const row = sourceRow();
    setRaw(row, { stream_id: null });
    const result = normalizeProxyEvidence([row], selection, config);
    expect(result.records).toHaveLength(1);
    expect(result.records[0].streamId).toBeUndefined();
    expect(result.records[0].limitations.join(" ")).toMatch(
      /did not provide a stream ID/,
    );
  });

  it("rejects wrong schema, log type, scope, observer and event-time parse", () => {
    for (const changes of [
      { schema: "application_atlas.envoy_http_access.v2" },
      { access_log_type: "DownstreamStart" },
      { routing_authority: "other" },
      { observer_id: "unmapped-proxy" },
      { start_time: "not-an-epoch" },
    ]) {
      const row = sourceRow();
      setRaw(row, changes);
      expect(normalizeProxyEvidence([row], selection, config)).toMatchObject({
        records: [],
        rejected: 1,
      });
    }
  });

  it("uses only the direct peer and upstream endpoint, never XFF, for selection matching", () => {
    const row = sourceRow();
    setRaw(row, {
      downstream_direct_remote_ip: "192.0.2.11",
      upstream_remote_ip: null,
      upstream_remote_port: null,
      x_forwarded_for: "192.0.2.10",
    });
    expect(normalizeProxyEvidence([row], selection, config)).toMatchObject({
      records: [],
      rejected: 1,
    });
  });

  it("requires the indexed event timestamp to agree with Envoy start time", () => {
    const row = sourceRow();
    row._time = new Date((1791373500.125 + 3.125) * 1000).toISOString();
    row.event_time_epoch = 1791373500.125 + 3.125;
    expect(normalizeProxyEvidence([row], selection, config)).toMatchObject({
      records: [],
      rejected: 1,
    });
  });

  it("uses numeric projected event time alongside native ISO _time", () => {
    const row = sourceRow();
    row._time = new Date(1791373500.125 * 1000).toISOString();
    row.event_time_epoch = "1791373500.125";
    const result = normalizeProxyEvidence([row], selection, config);
    expect(result.rejected).toBe(0);
    expect(result.records).toHaveLength(1);
    expect(result.records[0].eventTime).toBe(1791373500.125);
  });

  it("rejects an ISO string in the numeric event-time projection", () => {
    const row = sourceRow();
    row.event_time_epoch = new Date(1791373500.125 * 1000).toISOString();
    expect(normalizeProxyEvidence([row], selection, config)).toMatchObject({
      records: [],
      rejected: 1,
    });
  });

  it("tests exact request/window overlap and uses a bounded pre-window start lookback", () => {
    const overlapping = {
      ...selection,
      window: { start: 1791373500.14, end: 1791373501 },
    };
    expect(
      normalizeProxyEvidence([sourceRow()], overlapping, config).records,
    ).toHaveLength(1);
    const noOverlap = {
      ...selection,
      window: { start: 1791373500.16, end: 1791373501 },
    };
    expect(
      normalizeProxyEvidence([sourceRow()], noOverlap, config).records,
    ).toHaveLength(0);
    expect(proxySearchWindow(selection)).toEqual({
      start: selection.window.start - 86400,
      end: selection.window.end,
    });
  });

  it("fails closed for unselected, unqualified, invalid-index or ambiguous-scope sources", () => {
    expect(() =>
      buildProxySearch({ ...config, state: "not_selected" }, selection),
    ).toThrow();
    expect(() =>
      buildProxySearch({ ...config, schemaQualified: false }, selection),
    ).toThrow();
    expect(() =>
      buildProxySearch(
        { ...config, indexes: ["proxy_logs OR index=*"] },
        selection,
      ),
    ).toThrow();
    expect(() =>
      buildProxySearch(
        { ...config, mappings: [...config.mappings, config.mappings[0]] },
        selection,
      ),
    ).toThrow();
  });
});
