import { describe, expect, it, vi } from "vitest";
import stream from "../../../fixtures/dns/stream-transaction.json";
import { loadDnsEvidence } from "./dnsEvidence";
import { inspectDnsRecord } from "./dnsDrilldown";
import type { EvidenceSelection } from "./evidence";
import type {
  EvidenceConfigClient,
  EvidenceConfiguration,
} from "./evidenceConfig";
import type { SearchClient } from "./searchClient";

const selection: EvidenceSelection = {
  schemaVersion: 1,
  workflow: "endpoint",
  selectionId: "test",
  trafficContract: 1,
  window: { start: 1791373400, end: 1791373600 },
  scope: "prod",
  addresses: ["192.0.2.10"],
  contexts: [],
  identityBasis: "scoped address",
  configurationFingerprint: "a".repeat(64),
};
const config: EvidenceConfiguration = {
  fingerprint: selection.configurationFingerprint,
  trafficContract: 1,
  summaryIndexes: ["adm_summary"],
  mappings: [],
  identities: [],
  identityAvailable: true,
  maxAgeSeconds: 3600,
  dns: [
    {
      source: "dns_stream",
      state: "active",
      indexes: [stream.index],
      authorities: [stream.host],
      schemaQualified: false,
    },
    {
      source: "dns_hubble",
      state: "not_selected",
      indexes: [],
      authorities: [],
      schemaQualified: false,
    },
  ],
};
const envelope = (rows: Record<string, unknown>[]) => ({
  rows: [
    ...rows.map((r) => ({ ...r, kind: "dns_record" })),
    {
      kind: "dns_completion",
      schema_version: "1",
      input_count: String(rows.length),
      returned_count: String(rows.length),
      input_capped: "0",
      oversized: "0",
    },
  ],
  warnings: [],
  errors: [],
});
const configClient: EvidenceConfigClient = {
  read: async () => structuredClone(config),
};
describe("DNS record drilldown window", () => {
  it("windows on Stream response endtime rather than request start or delayed indexing", async () => {
    const loader: SearchClient = { search: async () => envelope([stream]) };
    const result = await loadDnsEvidence(
      loader,
      selection,
      new AbortController().signal,
      configClient,
    );
    const record = result.records[0];
    expect(record.eventTime).toBe(1791373500.125);
    expect(record.requestStart).toBe(1791373500.1);
    expect(record.rowTime).toBe(record.eventTime);
    expect(record.indexedTime).toBeGreaterThan(record.eventTime);
    const search = vi.fn(async () => envelope([stream]));
    await inspectDnsRecord(
      { search },
      selection,
      record,
      new AbortController().signal,
      configClient,
    );
    const request = (
      search.mock.calls[0] as unknown as [{ earliest: string; latest: string }]
    )[0];
    expect(Number(request.earliest)).toBe(Math.floor(record.rowTime!) - 1);
    expect(Number(request.latest)).toBe(Math.ceil(record.rowTime!) + 1);
    expect(Number(request.latest)).toBeLessThan(record.indexedTime);
  });
  it("falls back to the event time when the record carries no _time", async () => {
    const loader: SearchClient = { search: async () => envelope([stream]) };
    const result = await loadDnsEvidence(
      loader,
      selection,
      new AbortController().signal,
      configClient,
    );
    const { rowTime: _omitted, ...record } = result.records[0];
    void _omitted;
    const search = vi.fn(async () => envelope([]));
    await inspectDnsRecord(
      { search },
      selection,
      record,
      new AbortController().signal,
      configClient,
    );
    const request = (
      search.mock.calls[0] as unknown as [{ earliest: string; latest: string }]
    )[0];
    expect(Number(request.earliest)).toBe(Math.floor(record.eventTime) - 1);
    expect(Number(request.latest)).toBe(Math.ceil(record.eventTime) + 1);
  });
});
