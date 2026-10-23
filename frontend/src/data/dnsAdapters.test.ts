import { describe, expect, it } from "vitest";
import hubbleFixture from "../../../fixtures/dns/hubble-response.json";
import streamFixture from "../../../fixtures/dns/stream-transaction.json";
import type { EvidenceSelection } from "./evidence";
import {
  normalizeDns,
  type DnsAdapterConfig,
  type IdentityRecord,
  type Row,
} from "./dnsAdapters";

it("recognizes response proto3 defaults only for a qualified Hubble schema", async () => {
  const raw = JSON.parse(hubbleFixture._raw);
  delete raw.flow.l7.dns.rcode;
  delete raw.flow.l7.dns.ttl;
  const sourceRow = { ...hubbleFixture, _raw: JSON.stringify(raw) };
  const qualified = await normalizeDns(
    "dns_hubble",
    [sourceRow],
    config(),
    { ...selection(), addresses: ["192.0.2.11"] },
    [],
  );
  const unknown = await normalizeDns(
    "dns_hubble",
    [sourceRow],
    config({ schemaQualified: false }),
    { ...selection(), addresses: ["192.0.2.11"] },
    [],
  );
  expect(qualified.records[0].responseCode).toBe("0");
  expect(qualified.records[0].ttlSeconds).toBe(0);
  expect(qualified.records[0].limitations).toContain(
    "qualified_proto3_default_rcode",
  );
  expect(unknown.records[0].responseCode).toBeUndefined();
  expect(unknown.records[0].ttlSeconds).toBeUndefined();
});

const selection = (
  contexts: EvidenceSelection["contexts"] = [],
): EvidenceSelection => ({
  schemaVersion: 1,
  workflow: "endpoint",
  selectionId: "endpoint/192.0.2.10",
  trafficContract: 2,
  window: { start: 1791373400, end: 1791373600 },
  scope: "vpc-east",
  addresses: ["192.0.2.10"],
  contexts,
  identityBasis: "scoped_address",
  configurationFingerprint: "a".repeat(64),
});
const config = (
  overrides: Partial<DnsAdapterConfig> = {},
): DnsAdapterConfig => ({
  scope: "vpc-east",
  authorities: ["sensor-east", "worker-a"],
  maxAgeSeconds: 3600,
  clockUncertaintySeconds: 0,
  schemaQualified: true,
  ...overrides,
});
const row = (raw: Row, fields: Partial<Row> = {}): Row => ({
  host: "sensor-east",
  index: "dns",
  _time: "1791373500",
  _indextime: "1791373501",
  event_fingerprint: "c".repeat(64),
  _raw: JSON.stringify(raw),
  ...fields,
});
const flow = (
  client: string,
  server: string,
  first = 1791373510,
  additions: Partial<EvidenceSelection["contexts"][number]> = {},
): EvidenceSelection["contexts"][number] => ({
  client,
  server,
  scope: "vpc-east",
  first,
  last: first + 2,
  timeBasis: "flow_observation",
  capped: false,
  ...additions,
});
const owner = (
  ip: string,
  id: string,
  valid_from = 1791373400,
  valid_end?: number,
): IdentityRecord => ({
  ip,
  scope: "vpc-east",
  entity_id: id,
  entity_kind: "pod",
  valid_from,
  ...(valid_end === undefined ? {} : { valid_end }),
  scope_mapping_verified: 1,
});

describe("normalizeDns", () => {
  it("preserves real Stream list fields and does not guess host_addr/TTL array relationships", async () => {
    const result = await normalizeDns(
      "dns_stream",
      [streamFixture as Row],
      config(),
      selection([flow("192.0.2.10", "198.51.100.20")]),
      [],
    );
    expect(result.rejected).toBe(0);
    expect(result.records[0]).toMatchObject({
      query: "api.example.test.",
      comparisonName: "api.example.test",
      shape: "transaction",
      eventTime: 1791373500.125,
      rowTime: 1791373500.125,
      requestStart: 1791373500.1,
      responseInterval: {
        start: 1791373500.1,
        end: 1791373500.125,
      },
      latencySeconds: 0.025,
      attribution: "scoped_client",
    });
    expect(result.records[0].answers).toEqual([]);
    expect(result.records[0].reportedAddresses).toEqual(["198.51.100.20"]);
    expect(result.records[0].reportedTtls).toEqual([120]);
    expect(result.records[0].limitations).toContain(
      "ttl_unqualified_or_missing",
    );
  });

  it("keeps Hubble direction, aliases, UUID and scalar TTL without assigning it per answer", async () => {
    const result = await normalizeDns(
      "dns_hubble",
      [hubbleFixture as Row],
      config(),
      selection([flow("192.0.2.11", "2001:db8::20", 1791390310)]),
      [],
    );
    expect(result.records[0]).toMatchObject({
      shape: "response",
      responseCode: "0",
      duplicateId: "flow-7",
      attribution: "scoped_client",
      authority: "worker-a",
      ttlSeconds: 90,
      ttlBasis: "rrset_scalar",
      eventTime: 1791390300.25,
      client: "192.0.2.11",
      resolver: "192.0.2.53",
    });
    expect(result.records[0].answers).toEqual([]);
    expect(result.records[0].aliases).toEqual(["edge.example.test."]);
    expect(result.records[0].answers.every((a) => a.ttl === undefined)).toBe(
      true,
    );
  });

  it("preserves requests, failures, missing TTL and unqualified schemas as context only", async () => {
    const rows = [
      row({
        query: "api.test",
        src: "192.0.2.10",
        reply_code: 0,
        ttl: 60,
        answer_records: [{ address: "198.51.100.2", type: "A", ttl: 60 }],
        message_type: "request",
      }),
      row({
        query: "bad.test",
        src: "192.0.2.10",
        reply_code: 2,
        ttl: 60,
        answer_records: [{ address: "198.51.100.2", type: "A", ttl: 60 }],
      }),
      row({
        query: "unknown.test",
        src: "192.0.2.10",
        reply_code: 0,
        answer_records: [{ address: "198.51.100.2", type: "A" }],
      }),
    ];
    const result = await normalizeDns(
      "dns_stream",
      rows,
      config({ schemaQualified: false }),
      selection([flow("192.0.2.10", "198.51.100.2")]),
      [],
    );
    expect(result.records).toHaveLength(3);
    expect(
      result.records.every((r) => r.attribution !== "compatible_observations"),
    ).toBe(true);
    expect(result.records.map((r) => r.limitations)).toEqual(
      expect.arrayContaining([
        expect.arrayContaining(["producer_schema_unqualified"]),
        expect.arrayContaining(["response_not_successful"]),
      ]),
    );
  });

  it("does not correlate across scope, unknown clocks, capped contexts, or connection-open timestamps", async () => {
    const r = row({
      query: "api.test",
      src: "192.0.2.10",
      reply_code: 0,
      answer_records: [{ address: "198.51.100.2", type: "A", ttl: 60 }],
    });
    const result = await normalizeDns(
      "dns_stream",
      [r],
      config({ clockUncertaintySeconds: undefined }),
      selection([
        { ...flow("192.0.2.10", "198.51.100.2"), scope: "other" },
        { ...flow("192.0.2.10", "198.51.100.2"), timeBasis: "connection_open" },
        { ...flow("192.0.2.10", "198.51.100.2"), capped: true },
      ]),
      [],
    );
    expect(result.records[0].attribution).toBe("scoped_client");
    expect(result.records[0].limitations).toContain("clock_basis_unknown");
  });

  it("does not associate an address after a reused client ownership interval", async () => {
    const r = row({
      query: "api.test",
      src: "192.0.2.10",
      reply_code: 0,
      answer_records: [{ address: "198.51.100.2", type: "A", ttl: 60 }],
    });
    const result = await normalizeDns(
      "dns_stream",
      [r],
      config(),
      selection([flow("192.0.2.10", "198.51.100.2")]),
      [owner("192.0.2.10", "old", 1791373400, 1791373505)],
    );
    expect(result.records[0].attribution).toBe("scoped_client");
    expect(result.records[0].limitations).toContain(
      "no_qualified_address_answer",
    );
  });

  it("keeps Hubble direction unknown and ISO nanosecond time context-only", async () => {
    const raw = JSON.parse(hubbleFixture._raw);
    delete raw.flow.traffic_direction;
    raw.flow.l7.type = "UNKNOWN";
    const input = { ...hubbleFixture, _raw: JSON.stringify(raw) } as Row;
    const result = await normalizeDns(
      "dns_hubble",
      [input],
      config(),
      { ...selection(), addresses: ["192.0.2.11"] },
      [],
    );
    expect(result.records[0].eventTime).toBe(1791390300.25);
    expect(result.records[0].attribution).toBe("context_only");
    expect(result.records[0].limitations).toContain("hubble_direction_unknown");
    expect(result.records[0].limitations).toContain(
      "hubble_flow_direction_unknown",
    );
  });

  it("parses Hubble request direction using the source as client and destination as resolver", async () => {
    const raw = JSON.parse(hubbleFixture._raw);
    raw.flow.l7.type = "REQUEST";
    raw.flow.IP = { source: "192.0.2.11", destination: "192.0.2.53" };
    raw.flow.is_reply = false;
    raw.flow.l7.dns = { query: "api.example.test.", qtypes: ["A"] };
    const result = await normalizeDns(
      "dns_hubble",
      [{ ...hubbleFixture, _raw: JSON.stringify(raw) } as Row],
      config(),
      { ...selection(), addresses: ["192.0.2.11"] },
      [],
    );
    expect(result.records[0]).toMatchObject({
      shape: "request",
      client: "192.0.2.11",
      resolver: "192.0.2.53",
      attribution: "scoped_client",
    });
    expect(result.records[0].limitations).toContain("request_only");
  });

  it("retains non-address Hubble record types without producing address answers", async () => {
    const raw = JSON.parse(hubbleFixture._raw);
    raw.flow.l7.dns.qtypes = ["SRV", "MX"];
    const result = await normalizeDns(
      "dns_hubble",
      [{ ...hubbleFixture, _raw: JSON.stringify(raw) } as Row],
      config(),
      selection([flow("192.0.2.11", "198.51.100.20", 1791390310)]),
      [],
    );
    expect(result.records[0].queryType).toBe("SRV,MX");
    expect(result.records[0].answers).toEqual([]);
    expect(result.records[0].reportedAddresses).toEqual([
      "198.51.100.20",
      "2001:db8::20",
    ]);
    expect(result.records[0].attribution).toBe("scoped_client");
  });

  it("keeps invalid names as inspectable context and does not pair independent Stream arrays", async () => {
    const rows = [
      row(
        { query: "bad name.test", src: "192.0.2.10", reply_code: 0, ttl: 60 },
        { event_fingerprint: "d".repeat(64) },
      ),
      row(
        {
          query: "ok.test",
          src: "192.0.2.10",
          reply_code: 0,
          ttl: 60,
          host_addr: ["198.51.100.2"],
          ttl_values: [60],
        },
        { event_fingerprint: "e".repeat(64) },
      ),
    ];
    const result = await normalizeDns(
      "dns_stream",
      rows,
      config(),
      selection([flow("192.0.2.10", "198.51.100.2")]),
      [],
    );
    expect(result.rejected).toBe(0);
    expect(result.records[0].query).toBe("bad name.test");
    expect(result.records[0].limitations).toContain("invalid_query_name");
    expect(result.records[0].attribution).toBe("scoped_client");
    expect(result.records[1].answers).toEqual([]);
  });

  it("requires answer-section owner membership and complete per-answer TTLs", async () => {
    const base = {
      query: "api.test",
      src_ip: "192.0.2.10",
      reply_code: 0,
      answer_records: [
        {
          owner: "unrelated.test",
          section: "additional",
          type: "A",
          address: "198.51.100.2",
          ttl: 60,
        },
      ],
    };
    const unrelated = row(base);
    const mixed = row(
      {
        ...base,
        answer_records: [
          {
            owner: "api.test",
            section: "answer",
            type: "A",
            address: "198.51.100.2",
            ttl: 60,
          },
          {
            owner: "api.test",
            section: "answer",
            type: "A",
            address: "198.51.100.3",
          },
        ],
      },
      { event_fingerprint: "d".repeat(64) },
    );
    const result = await normalizeDns(
      "dns_stream",
      [unrelated, mixed],
      config(),
      selection([flow("192.0.2.10", "198.51.100.2")]),
      [],
    );
    expect(result.records[0].answers).toEqual([]);
    expect(result.records[1].answers).toHaveLength(2);
    expect(result.records[1].limitations).toContain("answer_ttl_missing");
    expect(result.records[1].attribution).toBe("scoped_client");
  });

  it("keeps Stream RR answers contextual when response end time is absent", async () => {
    const result = await normalizeDns(
      "dns_stream",
      [
        row(
          {
            query: "api.test",
            query_type: "A",
            message_type: "RESPONSE",
            src_ip: "192.0.2.10",
            reply_code: 0,
            timestamp: 1791373490,
            answer_records: [
              {
                owner: "api.test",
                section: "answer",
                type: "A",
                address: "198.51.100.2",
                ttl: 60,
              },
            ],
          },
          { event_fingerprint: "b".repeat(64) },
        ),
      ],
      config(),
      selection([flow("192.0.2.10", "198.51.100.2")]),
      [],
    );
    expect(result.records[0].answers).toHaveLength(1);
    expect(result.records[0].eventTime).toBe(1791373500);
    expect(result.records[0].requestStart).toBe(1791373490);
    expect(result.records[0].limitations).toContain(
      "stream_response_time_basis_unknown",
    );
    expect(result.records[0].attribution).toBe("scoped_client");
  });

  it("keeps malformed and reversed Stream timestamp/endtime intervals context-only", async () => {
    const answer = {
      owner: "api.test",
      section: "answer",
      type: "A",
      address: "198.51.100.2",
      ttl: 60,
    };
    const result = await normalizeDns(
      "dns_stream",
      [
        row({
          query: "api.test",
          query_type: "A",
          message_type: "RESPONSE",
          src_ip: "192.0.2.10",
          reply_code: 0,
          timestamp: 1791373500.2,
          endtime: 1791373500.1,
          answer_records: [answer],
        }),
        row(
          {
            query: "api.test",
            query_type: "A",
            message_type: "RESPONSE",
            src_ip: "192.0.2.10",
            reply_code: 0,
            timestamp: "invalid timestamp",
            endtime: 1791373500.1,
            answer_records: [answer],
          },
          { event_fingerprint: "d".repeat(64) },
        ),
      ],
      config(),
      selection([flow("192.0.2.10", "198.51.100.2")]),
      [],
    );
    expect(result.records).toHaveLength(2);
    expect(result.records[0].responseInterval).toBeUndefined();
    expect(result.records[0].limitations).toContain(
      "stream_response_interval_invalid",
    );
    expect(result.records[1].limitations).toContain(
      "stream_response_interval_invalid",
    );
    expect(
      result.records.every((record) =>
        record.attributionReason.includes("stream_response_interval_invalid"),
      ),
    ).toBe(true);
  });

  it("caps oversized reported address lists and rejects nonfinite TTL entries for association", async () => {
    const raw = {
      query: "api.test",
      query_type: "A",
      message_type: "RESPONSE",
      src_ip: "192.0.2.10",
      reply_code: 0,
      end: 1791373500,
      host_addr: Array.from({ length: 65 }, (_, i) => `198.51.100.${i + 1}`),
      ttl: [60, "Infinity"],
      answer_records: [
        {
          owner: "api.test",
          section: "answer",
          type: "A",
          address: "198.51.100.2",
          ttl: 60,
        },
      ],
    };
    const result = await normalizeDns(
      "dns_stream",
      [row(raw)],
      config(),
      selection([flow("192.0.2.10", "198.51.100.2")]),
      [],
    );
    expect(result.expansionCapped).toBe(1);
    expect(result.records[0].reportedAddresses).toHaveLength(64);
    expect(result.records[0].limitations).toContain(
      "reported_address_list_cap",
    );
    expect(result.records[0].limitations).toContain("invalid_ttl_value");
    expect(result.records[0].attribution).toBe("scoped_client");
  });

  it("keeps CNAME records as context and does not infer alias chains", async () => {
    const result = await normalizeDns(
      "dns_stream",
      [
        row({
          query: "api.test",
          src_ip: "192.0.2.10",
          reply_code: 0,
          answer_records: [
            {
              owner: "api.test",
              section: "answer",
              type: "CNAME",
              target: "edge.test",
              ttl: 20,
            },
            {
              owner: "edge.test",
              section: "answer",
              type: "A",
              address: "198.51.100.2",
              ttl: 90,
            },
          ],
        }),
      ],
      config(),
      selection([flow("192.0.2.10", "198.51.100.2")]),
      [],
    );
    expect(result.records[0].aliases).toEqual(["edge.test"]);
    expect(result.records[0].answers).toEqual([]);
    expect(result.records[0].limitations).toContain(
      "alias_relationship_unqualified",
    );
    expect(result.records[0].attribution).toBe("scoped_client");
  });

  it("enforces the raw byte cap for multibyte JSON strings", async () => {
    const raw = JSON.stringify({
      query: "☃".repeat(400_000),
      src_ip: "192.0.2.10",
    });
    expect(new TextEncoder().encode(raw).byteLength).toBeGreaterThan(1_048_576);
    const result = await normalizeDns(
      "dns_stream",
      [row({}, { _raw: raw })],
      config(),
      selection(),
      [],
    );
    expect(result.rejected).toBe(1);
    expect(result.records).toEqual([]);
  });

  it("preserves explicit Hubble drop verdicts as policy context and suppresses association", async () => {
    const raw = JSON.parse(hubbleFixture._raw);
    raw.flow.verdict = "DROPPED";
    const result = await normalizeDns(
      "dns_hubble",
      [{ ...hubbleFixture, _raw: JSON.stringify(raw) } as Row],
      config(),
      selection([flow("192.0.2.11", "198.51.100.20", 1791390310)]),
      [],
    );
    expect(result.records[0].policy).toBe("hubble_dropped");
    expect(result.records[0].limitations).toContain("source_policy_outcome");
    expect(result.records[0].attribution).toBe("scoped_client");
  });

  it("deduplicates only identical UUID exports from one source authority", async () => {
    const first = row(
      {
        node_name: "worker-a",
        source_ip: "192.0.2.10",
        uuid: "u1",
        l7: {
          type: "RESPONSE",
          dns: { query: "api.test", rcode: 0, ips: ["198.51.100.2"], ttl: 30 },
        },
      },
      { host: "worker-a" },
    );
    const dup = { ...first };
    const retry = row(
      {
        node_name: "worker-a",
        source_ip: "192.0.2.10",
        uuid: "u2",
        l7: {
          type: "RESPONSE",
          dns: { query: "api.test", rcode: 0, ips: ["198.51.100.2"], ttl: 30 },
        },
      },
      { host: "worker-a", event_fingerprint: "f".repeat(64) },
    );
    const otherRaw = JSON.parse(first._raw as string);
    otherRaw.node_name = "sensor-east";
    const otherSensor = row(otherRaw, {
      host: "sensor-east",
      event_fingerprint: "1".repeat(64),
    });
    const result = await normalizeDns(
      "dns_hubble",
      [first, dup, retry, otherSensor],
      config(),
      selection(),
      [],
    );
    expect(result.records).toHaveLength(3);
    expect(result.records.map((r) => r.authority)).toEqual([
      "worker-a",
      "worker-a",
      "sensor-east",
    ]);
  });

  it("throws when the adapter receives an oversized input instead of silently implying completeness", async () => {
    await expect(
      normalizeDns(
        "dns_stream",
        Array(10001).fill({}),
        config(),
        selection(),
        [],
      ),
    ).rejects.toThrow(/bounded row limit/);
  });
});

it("retains genuine retries and search-suffix queries without a proven export identity", async () => {
  const raw = JSON.parse(streamFixture._raw);
  const retry = {
    ...streamFixture,
    _raw: JSON.stringify({ ...raw, transaction_id: 43 }),
  };
  const suffix = {
    ...streamFixture,
    _raw: JSON.stringify({
      ...raw,
      query: "api.example.test.prod.internal.",
      transaction_id: 44,
    }),
  };
  const result = await normalizeDns(
    "dns_stream",
    [streamFixture, streamFixture, retry, suffix],
    config(),
    selection(),
    [],
  );
  expect(result.rejected).toBe(0);
  expect(result.records).toHaveLength(4);
  expect(
    result.records.filter((r) => r.query === "api.example.test."),
  ).toHaveLength(3);
  expect(
    result.records.some((r) => r.query === "api.example.test.prod.internal."),
  ).toBe(true);
});
