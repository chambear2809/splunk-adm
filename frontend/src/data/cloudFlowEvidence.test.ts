import { readFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import fixture from "../../../fixtures/cloud-flow/records-v5.json";
import {
  CLOUD_FLOW_FIELDS,
  CLOUD_FLOW_LOG_FORMAT,
  CLOUD_FLOW_PROJECTION,
  CLOUD_FLOW_SOURCE,
  buildCloudFlowSearch,
  cloudFlowSearchWindow,
  loadCloudFlowEvidence,
  normalizeCloudFlowEvidence,
  parseCloudFlowLine,
  type CloudFlowObservation,
} from "./cloudFlowEvidence";
import type { EvidenceSelection } from "./evidence";
import type {
  EvidenceConfigClient,
  EvidenceConfiguration,
  SupplementalSourceConfiguration,
} from "./evidenceConfig";
import type { SearchClient } from "./searchClient";

const selection: EvidenceSelection = {
  schemaVersion: 1,
  workflow: "endpoint",
  selectionId: "cloud-flow-test",
  trafficContract: 1,
  window: { start: 1791373400, end: 1791373600 },
  scope: "prod",
  addresses: ["10.0.1.25"],
  contexts: [],
  identityBasis: "scoped address",
  configurationFingerprint: "a".repeat(64),
};

const source: SupplementalSourceConfiguration = {
  source: CLOUD_FLOW_SOURCE,
  state: "active",
  indexes: ["aws_flow"],
  authorities: ["collector-a"],
  schemaQualified: true,
  staleAfterSeconds: 3600,
  mappings: [
    {
      observer_kind: "aws_vpc_flow",
      observer: "collector-a",
      scope: "prod",
      cluster: "",
      mapping_status: "verified",
      account_id: "123456789012",
      region: "us-east-1",
      vpc_id: "vpc-0abc1234",
    },
  ],
};

function raw(id: string): string {
  const item = fixture.records.find((record) => record.id === id);
  if (!item) throw new Error("Missing cloud-flow fixture " + id);
  return item.raw;
}

function projectedRow(
  line: string,
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  const fields = parseCloudFlowLine(line);
  const projection = Object.fromEntries(
    CLOUD_FLOW_PROJECTION.map(([field, column]) => [column, fields[field]]),
  );
  return {
    ...projection,
    kind: "supplemental_record",
    flow_field_count: 29,
    host: "collector-a",
    index: "aws_flow",
    event_fingerprint: "b".repeat(64),
    _time: Number(fields.start),
    event_time_epoch: Number(fields.start),
    _indextime: "1791373500",
    ...overrides,
  };
}

function completion(rows: Record<string, unknown>[]) {
  return {
    rows: [
      ...rows.map((row) => ({ ...row, kind: "supplemental_record" })),
      {
        kind: "supplemental_completion",
        schema_version: "1",
        input_count: String(rows.length),
        returned_count: String(rows.length),
        input_capped: "0",
        oversized: "0",
      },
    ],
    warnings: [],
    errors: [],
  };
}

const evidenceConfiguration = (): EvidenceConfiguration => ({
  fingerprint: selection.configurationFingerprint,
  trafficContract: 1,
  summaryIndexes: ["adm_summary"],
  mappings: [],
  identities: [],
  identityAvailable: true,
  dns: [],
  supplemental: [structuredClone(source)],
  maxAgeSeconds: 3600,
});

const configurationClient: EvidenceConfigClient = {
  read: async () => evidenceConfiguration(),
};

describe("AWS VPC Flow Logs v5 contract", () => {
  it("documents the exact 29-field AWS format and preserves its token order", () => {
    expect(CLOUD_FLOW_FIELDS).toHaveLength(29);
    const expectedFields = [
      "version",
      "srcaddr",
      "dstaddr",
      "srcport",
      "dstport",
      "protocol",
      "start",
      "end",
      "type",
      "packets",
      "bytes",
      "account-id",
      "vpc-id",
      "subnet-id",
      "instance-id",
      "interface-id",
      "region",
      "az-id",
      "sublocation-type",
      "sublocation-id",
      "action",
      "tcp-flags",
      "pkt-srcaddr",
      "pkt-dstaddr",
      "pkt-src-aws-service",
      "pkt-dst-aws-service",
      "traffic-path",
      "flow-direction",
      "log-status",
    ];
    expect(CLOUD_FLOW_FIELDS).toEqual(expectedFields);
    expect(CLOUD_FLOW_LOG_FORMAT).toBe(
      expectedFields.map((field) => "$" + "{" + field + "}").join(" "),
    );
    expect(parseCloudFlowLine(raw("accepted-flow"))).toMatchObject({
      version: "5",
      srcaddr: "203.0.113.25",
      "pkt-dstaddr": "10.0.1.25",
      "account-id": "123456789012",
      "log-status": "OK",
    });
  });

  it.each([
    ["28 fields", raw("accepted-flow").split(" ").slice(0, 28).join(" ")],
    ["wrong version", raw("accepted-flow").replace(/^5 /, "2 ")],
    ["control character", raw("accepted-flow").replace(" ", "\t")],
  ])("rejects %s", (_label, line) => {
    expect(() => parseCloudFlowLine(line)).toThrow();
  });

  it("builds a bounded fixed-schema search across interface and packet addresses", () => {
    const search = buildCloudFlowSearch(source, selection);
    expect(search).toContain('sourcetype="aws:vpcflow:v5"');
    expect(search).toContain('host IN ("collector-a")');
    expect(search).toContain("event_time_epoch=tonumber(_time)");
    for (const [, column] of CLOUD_FLOW_PROJECTION.slice(1, 3)) {
      expect(search).toContain(column + "=mvindex(_cloud_fields");
    }
    expect(search).toContain("flow_pkt_srcaddr");
    expect(search).toContain("flow_pkt_dstaddr");
    expect(search).toContain('flow_log_status IN ("NODATA","SKIPDATA")');
    expect(search).toContain("flow_start<=1791373660 AND flow_end>=1791373340");
    expect(search).toContain("| head 10001");
    expect(search).toContain("| head 64");
    expect(search).toContain('kind="supplemental_completion"');
    expect(search.includes(String.fromCharCode(96))).toBe(false);
    expect(search).not.toMatch(/\blookup\b|\bjoin\b|\bmap\b/);
    expect(search).not.toMatch(/\|\s*fields[^\n]*\b_raw\b/);
    expect(cloudFlowSearchWindow(selection)).toEqual({
      start: 1791372740,
      end: 1791373660,
    });
  });

  it("requires active, unique, verified host/account/Region/VPC mappings", () => {
    expect(() =>
      buildCloudFlowSearch({ ...source, state: "staged" }, selection),
    ).toThrow(/active and verified/);
    expect(() =>
      buildCloudFlowSearch(
        { ...source, indexes: ["aws_flow OR index=*"] },
        selection,
      ),
    ).toThrow(/index configuration/);
    expect(() =>
      buildCloudFlowSearch(
        {
          ...source,
          mappings: source.mappings.map((mapping) => ({
            ...mapping,
            mapping_status: "mapped",
          })),
        },
        selection,
      ),
    ).toThrow(/verified/);
    expect(() =>
      buildCloudFlowSearch(
        {
          ...source,
          mappings: [
            ...source.mappings,
            { ...source.mappings[0], scope: "other" },
          ],
        },
        selection,
      ),
    ).toThrow(/ambiguous/);
    expect(() =>
      buildCloudFlowSearch(
        {
          ...source,
          authorities: ["collector-a", "collector-b"],
        },
        selection,
      ),
    ).toThrow(/ambiguous/);
    expect(() =>
      buildCloudFlowSearch({ ...source, schemaQualified: false }, selection),
    ).toThrow(/active and verified/);
    expect(() =>
      buildCloudFlowSearch({ ...source, state: "staged" }, selection),
    ).toThrow(/active and verified/);
  });

  it("keeps interface and packet addresses distinct and counters per record", () => {
    const line =
      "5 10.0.1.25 10.0.1.99 49152 443 6 1791373400 1791373460 IPv4 4 1500 123456789012 vpc-0abc1234 subnet-0def1234 i-0abc1234 eni-0def1234 us-east-1 use1-az1 - - ACCEPT 19 203.0.113.25 10.0.1.25 - - 1 ingress OK";
    const normalized = normalizeCloudFlowEvidence(
      [projectedRow(line)],
      selection,
      source,
    );
    expect(normalized.rejected).toBe(0);
    expect(normalized.records).toHaveLength(1);
    expect(normalized.records[0]).toMatchObject({
      source: CLOUD_FLOW_SOURCE,
      authority: "collector-a",
      scope: "prod",
      interfaceAddresses: {
        source: "10.0.1.25",
        destination: "10.0.1.99",
      },
      packetAddresses: {
        source: "203.0.113.25",
        destination: "10.0.1.25",
      },
      matchedAddressFields: ["srcaddr", "pkt-dstaddr"],
      packets: 4,
      bytes: 1500,
      action: "ACCEPT",
      attribution: "context_only",
    } satisfies Partial<CloudFlowObservation>);
    expect(normalized.records[0]).not.toHaveProperty("success");
    expect(normalized.records[0].limitations).toContain(
      "per_record_counters_not_aggregated",
    );
  });

  it("requires event time to match producer start within one second", () => {
    const line = raw("accepted-flow");
    const start = Number(parseCloudFlowLine(line).start);
    const valid = projectedRow(line, {
      _time: "2026-10-23T23:44:34.000+00:00",
      event_time_epoch: start + 1,
    });
    const missing = projectedRow(line);
    delete missing.event_time_epoch;
    const mismatch = projectedRow(line, { event_time_epoch: start + 2 });
    const invalid = projectedRow(line, { event_time_epoch: "now" });
    const result = normalizeCloudFlowEvidence(
      [valid, missing, mismatch, invalid],
      selection,
      source,
    );
    expect(result.records).toHaveLength(1);
    expect(result.records[0].rowTime).toBe(start + 1);
    expect(result.rejected).toBe(3);
  });

  it("treats NODATA and SKIPDATA as capture status, never endpoint absence", () => {
    const rows = [
      projectedRow(raw("skipped-capture-interval")),
      projectedRow(raw("no-data-capture-interval")),
    ];
    const result = normalizeCloudFlowEvidence(rows, selection, source);
    expect(result.rejected).toBe(0);
    expect(result.records.map((record) => record.recordClass)).toEqual([
      "capture_status",
      "capture_status",
    ]);
    expect(result.records.map((record) => record.logStatus)).toEqual([
      "SKIPDATA",
      "NODATA",
    ]);
    expect(
      result.records.every((record) => !record.matchedAddressFields.length),
    ).toBe(true);
    expect(
      result.records.every((record) => record.attribution === "context_only"),
    ).toBe(true);
    expect(
      result.records.every((record) =>
        record.limitations.includes("capture_status_not_endpoint_absence"),
      ),
    ).toBe(true);
  });

  it("includes only flow intervals within the exact ±60-second uncertainty", () => {
    const at = (start: number, end: number) => {
      const values = raw("accepted-flow").split(" ");
      values[6] = String(start);
      values[7] = String(end);
      return projectedRow(values.join(" "));
    };
    const result = normalizeCloudFlowEvidence(
      [
        at(selection.window.start - 60, selection.window.start - 60),
        at(selection.window.end + 60, selection.window.end + 60),
        at(selection.window.start - 61, selection.window.start - 61),
        at(selection.window.end + 61, selection.window.end + 61),
      ],
      selection,
      source,
    );
    expect(result.records.map((record) => record.interval)).toEqual([
      {
        start: selection.window.start - 60,
        end: selection.window.start - 60,
      },
      {
        start: selection.window.end + 60,
        end: selection.window.end + 60,
      },
    ]);
    expect(result.rejected).toBe(2);
  });

  it("requires the installed v5 timestamp configuration for captured event time", () => {
    const file = readFileSync(
      new URL(
        "../../../splunk_app/splunk_adm/default/props.conf",
        import.meta.url,
      ),
      "utf8",
    );
    const lines = file.split(/\r?\n/);
    const header = lines.indexOf("[aws:vpcflow:v5]");
    const nextHeader = lines.findIndex(
      (line, index) => index > header && line.startsWith("["),
    );
    const stanza = lines
      .slice(header + 1, nextHeader < 0 ? lines.length : nextHeader)
      .join("\n");
    expect(header).toBeGreaterThanOrEqual(0);
    expect(stanza).toContain("SHOULD_LINEMERGE = false");
    expect(stanza).toContain("TIME_PREFIX = ^(?:\\S+\\s+){6}");
    expect(stanza).toContain("TIME_FORMAT = %s");
    expect(stanza).toContain("MAX_TIMESTAMP_LOOKAHEAD = 10");
  });

  it("rejects wrong source scope, wrong address, malformed field count and oversized rows", () => {
    const wrongScope = projectedRow(raw("accepted-flow"), {
      flow_region: "us-west-2",
    });
    const wrongAddress = projectedRow(raw("accepted-flow"), {
      flow_dstaddr: "10.0.1.99",
      flow_pkt_dstaddr: "10.0.1.99",
    });
    const malformed = projectedRow(raw("accepted-flow"), {
      flow_field_count: 30,
    });
    const oversized = projectedRow(raw("accepted-flow"), { oversized: "1" });
    const result = normalizeCloudFlowEvidence(
      [wrongScope, wrongAddress, malformed, oversized],
      selection,
      source,
    );
    expect(result.records).toEqual([]);
    expect(result.rejected).toBe(4);
  });

  it("delegates bounded execution and exact completion to the shared loader", async () => {
    const record = projectedRow(raw("accepted-flow"));
    const client: SearchClient = {
      search: vi.fn(async () => completion([record])),
    };
    const result = await loadCloudFlowEvidence(
      client,
      selection,
      new AbortController().signal,
      configurationClient,
    );
    expect(client.search).toHaveBeenCalledTimes(1);
    const request = vi.mocked(client.search).mock.calls[0][0];
    expect(request.optionalSource).toBe("aws_vpc_flow");
    expect(request.earliest).toBe("1791372740");
    expect(request.latest).toBe("1791373660");
    expect(request.maxRows).toBe(65);
    expect(result.state).toBe("complete");
    expect(result.inputCount).toBe(1);
    expect(result.records).toHaveLength(1);
    expect(result.records[0].attribution).toBe("context_only");
  });

  it("does not dispatch staged or active-but-unqualified sources", async () => {
    const client: SearchClient = { search: vi.fn(async () => completion([])) };
    const stagedClient: EvidenceConfigClient = {
      read: async () => ({
        ...evidenceConfiguration(),
        supplemental: [{ ...source, state: "staged", schemaQualified: false }],
      }),
    };
    const staged = await loadCloudFlowEvidence(
      client,
      selection,
      new AbortController().signal,
      stagedClient,
    );
    expect(staged.state).toBe("staged");
    expect(client.search).not.toHaveBeenCalled();

    const unqualifiedClient: EvidenceConfigClient = {
      read: async () => ({
        ...evidenceConfiguration(),
        supplemental: [{ ...source, schemaQualified: false }],
      }),
    };
    const unqualified = await loadCloudFlowEvidence(
      client,
      selection,
      new AbortController().signal,
      unqualifiedClient,
    );
    expect(unqualified.state).toBe("unavailable");
    expect(unqualified.records).toEqual([]);
    expect(client.search).not.toHaveBeenCalled();
  });
});
