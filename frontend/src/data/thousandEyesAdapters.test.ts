import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import type { Row } from "../rows";
import type { EvidenceSelection } from "./evidence";
import type { SupplementalSourceConfiguration } from "./evidenceConfig";
import { normalizeThousandEyesRows } from "./thousandEyesAdapters";

const selection: EvidenceSelection = {
  schemaVersion: 1,
  workflow: "endpoint",
  selectionId: "endpoint:192.0.2.8",
  trafficContract: 1,
  window: { start: 1_700_000_000, end: 1_700_000_400 },
  scope: "site-a",
  addresses: ["192.0.2.8"],
  identityAddresses: ["192.0.2.8"],
  contexts: [],
  identityBasis: "scoped endpoint",
  configurationFingerprint: "a".repeat(64),
};

const nativeBinding = {
  id: "test-17-agent-9-cea",
  authority: "te-example",
  accountGroupId: "1234",
  scope: "site-a",
  testId: "17",
  agentId: "9",
  testDomain: "cea" as const,
  target: { ip: "198.51.100.20", protocol: "tcp", port: 443 },
  endpointAddresses: ["192.0.2.8"],
  validFrom: 1_700_000_000,
  validTo: 1_700_000_400,
  configurationId: "test-config-1",
  agentLocation: "East office",
};

const configuration = (): SupplementalSourceConfiguration => ({
  source: "thousandeyes",
  state: "active",
  indexes: ["te_metrics", "te_traces", "te_activity", "te_events", "te_paths"],
  authorities: ["te-example"],
  schemaQualified: true,
  staleAfterSeconds: 1_200,
  mappings: [
    {
      observer_kind: "thousandeyes_account_group",
      observer: "te-example",
      scope: "site-a",
      cluster: "",
      mapping_status: "verified",
      te_account_group_id: "1234",
      te_stream_account_id: "5678",
      te_alert_account_id: "6789",
      te_organization_id: "org-1",
      te_families: JSON.stringify([
        "metric",
        "path",
        "trace",
        "event",
        "alert",
        "activity",
      ]),
      te_bindings: JSON.stringify([nativeBinding]),
      te_path_sources: JSON.stringify([
        { index: "te_paths", source: "test_metrics_stream://site-a" },
        { index: "te_paths", source: "atlas:thousandeyes:path" },
      ]),
      thousandeyes_origin: "https://app.thousandeyes.com",
    },
  ],
});

function fixture(name: string): string {
  return readFileSync(
    fileURLToPath(
      new URL(`../../../fixtures/thousandeyes/${name}`, import.meta.url),
    ),
    "utf8",
  );
}

function row(
  raw: string,
  index: string,
  source: string,
  sourcetype: string,
  overrides: Partial<Row> = {},
): Row {
  return {
    kind: "supplemental_record",
    _raw: raw,
    index,
    source,
    sourcetype,
    event_fingerprint: createHash("sha256").update(raw).digest("hex"),
    row_time_epoch: "1700000200",
    indexed_time_epoch: "1700000201",
    record_truncated: "0",
    ...overrides,
  };
}

const sourceRows = () => [
  row(
    fixture("metric-v2.json"),
    "te_metrics",
    "cisco:thousandeyes:stream",
    "cisco:thousandeyes:metric",
  ),
  row(
    fixture("trace-v2.json"),
    "te_traces",
    "cisco:thousandeyes:stream",
    "cisco:thousandeyes:trace",
  ),
  row(
    fixture("activity-v2.json"),
    "te_activity",
    "cisco:thousandeyes:stream",
    "cisco:thousandeyes:activity",
  ),
  row(
    fixture("event.json"),
    "te_events",
    "events-writer://site-a",
    "cisco:thousandeyes:event",
  ),
  row(
    fixture("alert.json"),
    "te_events",
    "cisco:thousandeyes:webhook",
    "cisco:thousandeyes:alerts",
  ),
  row(
    fixture("path-export-wrapper.json"),
    "te_paths",
    "atlas:thousandeyes:path",
    "atlas:thousandeyes:path",
  ),
];

describe("strict ThousandEyes producer adapters", () => {
  it("normalizes all six families while keeping native measurement and Splunk row times distinct", () => {
    const normalized = normalizeThousandEyesRows(
      sourceRows(),
      selection,
      configuration(),
    );
    expect(normalized.rejected).toBe(0);
    expect(normalized.records.map((record) => record.family).sort()).toEqual([
      "activity",
      "alert",
      "event",
      "metric",
      "path",
      "trace",
    ]);
    const metric = normalized.records.find(
      (record) => record.family === "metric",
    )!;
    expect(metric.eventTime).toBe(1_700_000_010);
    expect(metric.rowTime).toBe(1_700_000_200);
    expect(metric.receiptTime).toBeUndefined();
    expect(metric.indexedTime).toBe(1_700_000_201);
    expect(metric).toMatchObject({
      adapterVersion: "0.9.0",
      producerVersion: "not_reported",
      dataModelVersion: "v2",
    });
    expect(metric.limitations.join(" ")).toContain(
      "raw OpenTelemetry resource declares data-model v2",
    );
    expect(metric.sourceTimes).toContainEqual({
      field: "time_unix_nano",
      value: "1700000010000000000",
      unit: "ns",
    });
    expect(metric.measurements[0]).toMatchObject({
      name: "network.latency",
      value: 0.025,
      unit: "s",
      sourceUnit: "s",
      aggregation: "gauge",
    });
    const span = normalized.records.find((record) => record.family === "trace")!
      .spans[0];
    expect(span.startTimeUnixNano).toBe("1700000010000000000");
    expect(span.endTimeUnixNano).toBe("1700000010100000000");
    const event = normalized.records.find(
      (record) => record.family === "event",
    )!;
    expect(event).toMatchObject({
      relatedTestIds: ["17", "18"],
      relatedAgentIds: ["9"],
    });
    expect(event.testId).toBeUndefined();
    expect(event.agentId).toBeUndefined();
    expect(
      normalized.records.find((record) => record.family === "activity"),
    ).toMatchObject({
      streamId: "activity-stream-1",
      activity: { action: "test.updated", actor: "operator@example.test" },
    });
    const path = normalized.records.find((record) => record.family === "path")!;
    expect(path).toMatchObject({
      adapterVersion: "0.9.0",
      producerVersion: "not_reported",
      dataModelVersion: "api-v7",
      testDomain: "cea",
      collectionTime: 1_700_000_015,
      hops: [
        { pathId: "path-1", number: 1, missing: false },
        { pathId: "path-1", number: 2, missing: true },
        { pathId: "path-1", number: 3, missing: false },
      ],
      quality: { complete: false },
    });
    expect(path.limitations.join(" ")).toContain(
      "schema_version is a separate envelope contract",
    );
    expect(path.limitations.join(" ")).toContain(
      "deployed Cisco app/package version",
    );
  });

  it("preserves summary RTT and count without inventing intermediate hops", () => {
    const summary = JSON.parse(fixture("path-export-wrapper.json")) as {
      result: { pathTraces: Record<string, unknown>[] };
    };
    summary.result.pathTraces = [
      { pathId: "summary-path", numberOfHops: 15, responseTime: 25 },
    ];
    const normalized = normalizeThousandEyesRows(
      [
        row(
          JSON.stringify(summary),
          "te_paths",
          "atlas:thousandeyes:path",
          "atlas:thousandeyes:path",
        ),
      ],
      selection,
      configuration(),
    );
    expect(normalized.rejected).toBe(0);
    expect(normalized.records[0].hops).toEqual([]);
    expect(normalized.records[0].quality.complete).toBe(false);
    expect(normalized.records[0].measurements).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          name: "path.round_trip_time",
          value: 25,
          unit: "ms",
        }),
        expect.objectContaining({
          name: "path.hop_count",
          value: 15,
          unit: "{count}",
        }),
      ]),
    );
  });

  it("does not bind a CEA path wrapper unless its versioned test domain is explicit", () => {
    const wrapper = JSON.parse(fixture("path-export-wrapper.json")) as Record<
      string,
      unknown
    >;
    delete wrapper.test_domain;
    const normalized = normalizeThousandEyesRows(
      [
        row(
          JSON.stringify(wrapper),
          "te_paths",
          "atlas:thousandeyes:path",
          "atlas:thousandeyes:path",
        ),
      ],
      selection,
      configuration(),
    );
    expect(normalized.records).toEqual([]);
    expect(normalized.rejected).toBe(1);
  });

  it("rejects anonymous CEA results, malformed JSON, duplicate keys and unsupported units", () => {
    const anonymousPath = row(
      fixture("path-cea-anonymous.json"),
      "te_paths",
      "test_metrics_stream://site-a",
      "cisco:thousandeyes:path-vis",
    );
    const duplicateKey = row(
      '{"aid":"1234","aid":"9999","id":"e-1","startDate":"2023-11-14T22:13:30Z"}',
      "te_events",
      "events-writer://site-a",
      "cisco:thousandeyes:event",
    );
    const invalidUnit = JSON.parse(fixture("metric-v2.json")) as {
      resource_metrics: { scope_metrics: { metrics: { unit: string }[] }[] }[];
    };
    invalidUnit.resource_metrics[0].scope_metrics[0].metrics[0].unit = "ms";
    const malformed = row(
      "{",
      "te_metrics",
      "cisco:thousandeyes:stream",
      "cisco:thousandeyes:metric",
    );
    const normalized = normalizeThousandEyesRows(
      [
        anonymousPath,
        duplicateKey,
        row(
          JSON.stringify(invalidUnit),
          "te_metrics",
          "cisco:thousandeyes:stream",
          "cisco:thousandeyes:metric",
        ),
        malformed,
      ],
      selection,
      configuration(),
    );
    expect(normalized.records).toEqual([]);
    expect(normalized.rejected).toBe(4);
  });

  it("retains conflicting native duplicate measurements only as flagged records", () => {
    const original = JSON.parse(fixture("metric-v2.json")) as {
      resource_metrics: {
        scope_metrics: {
          metrics: { gauge: { data_points: { as_double: number }[] } }[];
        }[];
      }[];
    };
    const conflicting = structuredClone(original);
    conflicting.resource_metrics[0].scope_metrics[0].metrics[0].gauge.data_points[0].as_double = 0.05;
    const rows = [original, conflicting].map((payload) =>
      row(
        JSON.stringify(payload),
        "te_metrics",
        "cisco:thousandeyes:stream",
        "cisco:thousandeyes:metric",
      ),
    );
    const normalized = normalizeThousandEyesRows(
      rows,
      selection,
      configuration(),
    );
    expect(normalized.rejected).toBe(2);
    expect(normalized.records).toHaveLength(2);
    expect(
      normalized.records.every((record) => record.quality.conflicting),
    ).toBe(true);
  });

  it("retains exact replay once, rejects out-of-order native intervals and rejects numeric64bit IDs", () => {
    const replay = row(
      fixture("metric-v2.json"),
      "te_metrics",
      "cisco:thousandeyes:stream",
      "cisco:thousandeyes:metric",
    );
    const pointOrder = JSON.parse(fixture("metric-v2.json")) as {
      resource_metrics: {
        scope_metrics: {
          metrics: {
            gauge: {
              data_points: {
                start_time_unix_nano?: string;
                time_unix_nano: string;
              }[];
            };
          }[];
        }[];
      }[];
    };
    pointOrder.resource_metrics[0].scope_metrics[0].metrics[0].gauge.data_points[0] =
      {
        start_time_unix_nano: "1700000020000000000",
        time_unix_nano: "1700000010000000000",
      };
    const unsafeId = JSON.parse(fixture("event.json")) as Record<
      string,
      unknown
    >;
    unsafeId.id = 9_007_199_254_740_992;
    const normalized = normalizeThousandEyesRows(
      [
        replay,
        replay,
        row(
          JSON.stringify(pointOrder),
          "te_metrics",
          "cisco:thousandeyes:stream",
          "cisco:thousandeyes:metric",
        ),
        row(
          JSON.stringify(unsafeId),
          "te_events",
          "events-writer://site-a",
          "cisco:thousandeyes:event",
        ),
      ],
      selection,
      configuration(),
    );
    expect(normalized.records).toHaveLength(1);
    expect(normalized.records[0].family).toBe("metric");
    expect(normalized.rejected).toBe(2);
  });

  it("retains BGP monitor evidence without fabricating a source agent", () => {
    const normalized = normalizeThousandEyesRows(
      [
        row(
          fixture("bgp-monitor-v2.json"),
          "te_metrics",
          "cisco:thousandeyes:stream",
          "cisco:thousandeyes:metric",
        ),
      ],
      selection,
      configuration(),
    );
    expect(normalized.rejected).toBe(0);
    expect(normalized.records[0]).toMatchObject({
      family: "metric",
      monitorId: "monitor-4",
    });
    expect(normalized.records[0].agentId).toBeUndefined();
  });
});
