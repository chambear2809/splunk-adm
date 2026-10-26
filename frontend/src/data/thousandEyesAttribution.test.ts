import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import type { Row } from "../rows";
import type { EvidenceSelection } from "./evidence";
import type { SupplementalSourceConfiguration } from "./evidenceConfig";
import { normalizeThousandEyesRows } from "./thousandEyesAdapters";
import {
  attributeThousandEyesRecords,
  compareThousandEyesMeasurements,
} from "./thousandEyesAttribution";
import type {
  ThousandEyesAttributedObservation,
  ThousandEyesBinding,
  ThousandEyesObservation,
} from "./thousandEyesTypes";

const selection = (
  overrides: Partial<EvidenceSelection> = {},
): EvidenceSelection => ({
  schemaVersion: 1,
  workflow: "application",
  selectionId: "app/checkout",
  trafficContract: 2,
  window: { start: 100, end: 300 },
  scope: "vpc-east",
  addresses: ["192.0.2.10"],
  identityAddresses: ["192.0.2.10", "192.0.2.11"],
  contexts: [],
  identityBasis: "revalidated workload and selected peer addresses",
  configurationFingerprint: "a".repeat(64),
  application: {
    service: "checkout",
    environment: "prod",
    cluster: "east-1",
    namespace: "payments",
  },
  ...overrides,
});

const record = (
  overrides: Partial<ThousandEyesObservation> = {},
): ThousandEyesObservation => ({
  schemaVersion: 1,
  family: "metric",
  authority: "te-east",
  authorityBasis: "producer_account",
  accountGroupId: "12345",
  adapterVersion: "0.9.0",
  producerVersion: "10.0",
  dataModelVersion: "1",
  testId: "test-7",
  agentId: "agent-2",
  testDomain: "cea",
  testName: "checkout availability",
  agentName: "east probe",
  agentLocation: "East office",
  configurationId: "config-a",
  target: {
    ip: "198.51.100.20",
    protocol: "https",
    port: 443,
  },
  interval: { start: 120, end: 130 },
  intervalBasis: "measurement",
  eventTime: 125,
  indexedTime: 131,
  index: "te_metrics",
  source: "adm:te_metric",
  sourcetype: "adm:te:metric",
  fingerprint: "b".repeat(64),
  outcome: "success",
  quality: {
    stale: false,
    complete: true,
    conflicting: false,
    truncated: false,
  },
  measurements: [
    {
      name: "latency",
      value: 25,
      unit: "ms",
      sourceUnit: "ms",
      aggregation: "mean",
      direction: "round_trip",
      denominator: "samples",
      timeBasis: "measurement_interval",
    },
  ],
  hops: [],
  spans: [],
  limitations: [],
  ...overrides,
});

const binding = (
  overrides: Partial<ThousandEyesBinding> = {},
): ThousandEyesBinding => ({
  id: "binding-a",
  authority: "te-east",
  accountGroupId: "12345",
  scope: "vpc-east",
  testId: "test-7",
  agentId: "agent-2",
  testDomain: "cea",
  target: { ip: "198.51.100.20", protocol: "https", port: 443 },
  endpointAddresses: ["192.0.2.10"],
  application: {
    service: "checkout",
    environment: "prod",
    cluster: "east-1",
    namespace: "payments",
  },
  validFrom: 100,
  validTo: 200,
  configurationId: "config-a",
  agentLocation: "East office",
  ...overrides,
});

const attribute = (
  value: ThousandEyesObservation = record(),
  selected: EvidenceSelection = selection(),
  bindings: ThousandEyesBinding[] = [binding()],
) => attributeThousandEyesRecords([value], selected, bindings)[0];

const adapterSelection = (): EvidenceSelection =>
  selection({ window: { start: 1_700_000_000, end: 1_700_000_050 } });

const adapterBinding = (): ThousandEyesBinding =>
  binding({
    testId: "17",
    agentId: "9",
    target: { ip: "198.51.100.20", protocol: "tcp", port: 443 },
    validFrom: 1_700_000_000,
    validTo: 1_700_000_050,
  });

const adapterConfiguration = (): SupplementalSourceConfiguration => ({
  source: "thousandeyes",
  state: "active",
  indexes: ["te_metrics"],
  authorities: ["te-east"],
  schemaQualified: true,
  staleAfterSeconds: 1_200,
  mappings: [
    {
      observer_kind: "thousandeyes_account_group",
      observer: "te-east",
      scope: "vpc-east",
      cluster: "",
      mapping_status: "verified",
      te_account_group_id: "12345",
      te_stream_account_id: "5678",
      te_families: JSON.stringify(["metric"]),
      te_bindings: JSON.stringify([adapterBinding()]),
    },
  ],
});

function metricFixture(timestamp: number, latency: number, loss: number): Row {
  const fixturePath = fileURLToPath(
    new URL("../../../fixtures/thousandeyes/metric-v2.json", import.meta.url),
  );
  const document = JSON.parse(readFileSync(fixturePath, "utf8")) as {
    resource_metrics: {
      scope_metrics: {
        metrics: {
          name: string;
          unit: string;
          gauge: { data_points: Record<string, unknown>[] };
        }[];
      }[];
    }[];
  };
  const metrics = document.resource_metrics[0].scope_metrics[0].metrics;
  const latencyMetric = metrics[0];
  const sourcePoint = latencyMetric.gauge.data_points[0];
  const point = {
    ...sourcePoint,
    attributes: [
      ...((sourcePoint.attributes as Record<string, unknown>[]) ?? []),
      { key: "network.io.direction", value: { string_value: "round_trip" } },
    ],
    time_unix_nano: `${timestamp}000000000`,
    as_double: latency,
  };
  latencyMetric.gauge.data_points = [point];
  metrics.push({
    name: "network.loss",
    unit: "%",
    gauge: {
      data_points: [{ ...point, as_double: loss }],
    },
  });

  const raw = JSON.stringify(document);
  return {
    kind: "supplemental_record",
    _raw: raw,
    index: "te_metrics",
    source: "cisco:thousandeyes:stream",
    sourcetype: "cisco:thousandeyes:metric",
    event_fingerprint: createHash("sha256").update(raw).digest("hex"),
    row_time_epoch: "1700000300",
    indexed_time_epoch: "1700000301",
    record_truncated: "0",
  };
}

function normalizeMetricFixture(
  timestamp: number,
  latency: number,
  loss: number,
) {
  return normalizeThousandEyesRows(
    [metricFixture(timestamp, latency, loss)],
    adapterSelection(),
    adapterConfiguration(),
  );
}

describe("attributeThousandEyesRecords", () => {
  it("binds only the exact native identity, selected scope/application/address, target and interval", () => {
    const attributed = attribute();
    expect(attributed.attribution.state).toBe("bound");
    expect(attributed.attribution.bindingIds).toEqual(["binding-a"]);
    expect(attributed.attribution.configurationId).toBe("config-a");

    expect(attribute(record({ authority: "te-west" })).attribution.state).toBe(
      "unmatched",
    );
    expect(
      attribute(record({ accountGroupId: "54321" })).attribution.state,
    ).toBe("unmatched");
    expect(
      attribute(record({ testId: "renamed-test" })).attribution.state,
    ).toBe("unmatched");
    expect(attribute(record({ agentId: "agent-3" })).attribution.state).toBe(
      "unmatched",
    );
    expect(
      attribute(record(), selection({ scope: "vpc-west" })).attribution.state,
    ).toBe("unmatched");
    for (const [field, value] of [
      ["service", "catalog"],
      ["environment", "stage"],
      ["cluster", "west-1"],
      ["namespace", "commerce"],
    ] as const) {
      expect(
        attribute(
          record(),
          selection({
            application: {
              service: "checkout",
              environment: "prod",
              cluster: "east-1",
              namespace: "payments",
              [field]: value,
            },
          }),
        ).attribution.state,
      ).toBe("unmatched");
    }
    expect(
      attribute(record(), selection({ identityAddresses: ["192.0.2.99"] }))
        .attribution.state,
    ).toBe("unmatched");
  });

  it("uses exact configured target fields and never resolves a hostname", () => {
    expect(
      attribute(
        record({
          target: { ip: "198.51.100.21", protocol: "https", port: 443 },
        }),
      ).attribution.state,
    ).toBe("unmatched");
    expect(
      attribute(
        record({
          target: { ip: "198.51.100.20", protocol: "http", port: 443 },
        }),
      ).attribution.state,
    ).toBe("unmatched");
    expect(
      attribute(
        record({
          target: { ip: "198.51.100.20", protocol: "https", port: 8443 },
        }),
      ).attribution.state,
    ).toBe("unmatched");
    expect(
      attribute(
        record({
          target: { hostname: "service.example", protocol: "https", port: 443 },
        }),
        selection(),
        [
          binding({
            target: {
              hostname: "service.example",
              protocol: "https",
              port: 443,
            },
          }),
        ],
      ).attribution.state,
    ).toBe("bound");
    expect(
      attribute(
        record({
          target: { ip: "198.51.100.20", protocol: "https", port: 443 },
        }),
        selection(),
        [
          binding({
            target: {
              hostname: "service.example",
              protocol: "https",
              port: 443,
            },
          }),
        ],
      ).attribution.state,
    ).toBe("unmatched");
  });

  it("requires the complete observation interval inside a half-open binding", () => {
    expect(
      attribute(record({ interval: { start: 100, end: 200 } }), selection(), [
        binding({ validFrom: 100, validTo: 200 }),
      ]).attribution.state,
    ).toBe("bound");
    expect(
      attribute(record({ interval: { start: 199, end: 200 } }), selection(), [
        binding({ validFrom: 100, validTo: 200 }),
      ]).attribution.state,
    ).toBe("bound");
    expect(
      attribute(
        record({ interval: { start: 200, end: 200 }, intervalBasis: "point" }),
        selection(),
        [binding({ validFrom: 100, validTo: 200 })],
      ).attribution.state,
    ).toBe("unmatched");
    expect(
      attribute(record({ interval: { start: 99, end: 101 } }), selection(), [
        binding({ validFrom: 100, validTo: 200 }),
      ]).attribution.state,
    ).toBe("unmatched");
  });

  it("retains overlapping binding ambiguity and honors an exact observed configuration ID", () => {
    const duplicate = binding({ id: "binding-b" });
    const ambiguous = attribute(record(), selection(), [binding(), duplicate]);
    expect(ambiguous.attribution.state).toBe("ambiguous");
    expect(ambiguous.attribution.bindingIds).toEqual([
      "binding-a",
      "binding-b",
    ]);

    const configurations = [
      binding(),
      binding({ id: "binding-b", configurationId: "config-b" }),
    ];
    expect(
      attribute(record(), selection(), configurations).attribution.state,
    ).toBe("bound");
    expect(
      attribute(
        record({ configurationId: "config-missing" }),
        selection(),
        configurations,
      ).attribution.state,
    ).toBe("ambiguous");
  });

  it("uses historical half-open ranges when an endpoint address is reused", () => {
    const old = binding({
      id: "old-address-owner",
      validFrom: 50,
      validTo: 150,
      configurationId: "config-old",
    });
    const current = binding({
      id: "new-address-owner",
      validFrom: 150,
      validTo: 250,
      configurationId: "config-new",
    });
    const beforeBoundary = attribute(
      record({
        interval: { start: 140, end: 150 },
        configurationId: "config-old",
      }),
      selection(),
      [old, current],
    );
    const atBoundary = attribute(
      record({
        interval: { start: 150, end: 150 },
        intervalBasis: "point",
        configurationId: "config-new",
      }),
      selection(),
      [old, current],
    );
    expect(beforeBoundary.attribution).toMatchObject({
      state: "bound",
      bindingIds: ["old-address-owner"],
    });
    expect(atBoundary.attribution).toMatchObject({
      state: "bound",
      bindingIds: ["new-address-owner"],
    });
  });

  it("requires an explicit matching CEA or Endpoint test domain", () => {
    const missing = attribute(record({ testDomain: undefined }));
    expect(missing.attribution.state).toBe("context_only");
    expect(missing.attribution.reason).toContain("test domain is missing");

    const mismatched = attribute(record(), selection(), [
      binding({ testDomain: "endpoint" }),
    ]);
    expect(mismatched.attribution.state).toBe("unmatched");
    expect(mismatched.attribution.reason).toContain(
      "different ThousandEyes test domain",
    );
  });

  it("keeps producer-marked proxy targets context only without target-role proof", () => {
    const target = { ip: "198.51.100.20", protocol: "tcp", port: 443 };
    const proxy = attribute(
      record({ target, targetIsProxy: true }),
      selection({
        contexts: [
          {
            client: "192.0.2.10",
            server: "198.51.100.20",
            serverPort: 443,
            transport: "tcp",
            scope: "vpc-east",
            first: 123,
            last: 128,
            timeBasis: "flow_observation",
            capped: false,
          },
        ],
      }),
      [binding({ target })],
    );
    expect(proxy.attribution.state).toBe("context_only");
    expect(proxy.attribution.bindingIds).toEqual([]);
    expect(proxy.attribution.observedDependency).toBe(false);
    expect(proxy.attribution.reason).toContain("proxy coverage");
    expect(proxy.attribution.reason).toContain("does not prove target role");
  });

  it("does not use names or tags when native test or agent IDs are absent", () => {
    const attributed = attribute(
      record({ testId: undefined, agentId: undefined }),
    );
    expect(attributed.attribution.state).toBe("unmatched");
    expect(attributed.attribution.reason).toContain(
      "test names and tags are not used",
    );
  });

  it("requires an explicitly configured agent location and keeps relocation context only", () => {
    const relocated = attribute(record({ agentLocation: "West office" }));
    expect(relocated.attribution.state).toBe("context_only");
    expect(relocated.attribution.bindingIds).toEqual([]);
    expect(relocated.attribution.reason).toContain("possible agent relocation");

    const notLocationScoped = attribute(
      record({ agentLocation: "West office" }),
      selection(),
      [binding({ agentLocation: undefined })],
    );
    expect(notLocationScoped.attribution.state).toBe("bound");
  });

  it("keeps stale, incomplete, conflicting or truncated records context only", () => {
    const defects = [
      { stale: true, complete: true, conflicting: false, truncated: false },
      { stale: false, complete: false, conflicting: false, truncated: false },
      { stale: false, complete: true, conflicting: true, truncated: false },
      { stale: false, complete: true, conflicting: false, truncated: true },
    ];
    for (const quality of defects) {
      const attributed = attribute(record({ quality }));
      expect(attributed.attribution.state).toBe("context_only");
      expect(attributed.attribution.bindingIds).toEqual([]);
      expect(attributed.attribution.observedDependency).toBe(false);
    }
    const staleButTupleMatched = attribute(
      record({ quality: defects[0] }),
      selection({
        contexts: [
          {
            client: "192.0.2.10",
            server: "198.51.100.20",
            serverPort: 443,
            transport: "https",
            scope: "vpc-east",
            first: 123,
            last: 128,
            timeBasis: "flow_observation",
            capped: false,
          },
        ],
      }),
    );
    expect(staleButTupleMatched.attribution.observedDependency).toBe(false);
  });

  it("marks only uncapped actual selected contexts and says they do not prove the same route", () => {
    const contextSelection = selection({
      contexts: [
        {
          client: "192.0.2.10",
          server: "198.51.100.20",
          scope: "vpc-east",
          first: 123,
          last: 128,
          timeBasis: "flow_observation",
          capped: false,
          serverPort: 443,
          transport: "tcp",
        },
      ],
    });
    const target = { ip: "198.51.100.20", protocol: "tcp", port: 443 };
    const tupleRecord = record({ target });
    const tupleBinding = binding({ target });
    const observed = attribute(tupleRecord, contextSelection, [tupleBinding]);
    expect(observed.attribution.observedDependency).toBe(true);
    expect(observed.attribution.reason).toContain(
      "does not prove the same route",
    );

    expect(
      attribute(tupleRecord, selection()).attribution.observedDependency,
    ).toBe(false);
    expect(
      attribute(
        tupleRecord,
        selection({
          contexts: [
            {
              ...contextSelection.contexts[0],
              capped: true,
            },
          ],
        }),
        [tupleBinding],
      ).attribution.observedDependency,
    ).toBe(false);
    expect(
      attribute(record({ ...tupleRecord, family: "trace" }), contextSelection, [
        tupleBinding,
      ]).attribution.observedDependency,
    ).toBe(false);
    expect(
      attribute(
        record({ target: { hostname: "service.example" } }),
        contextSelection,
        [tupleBinding],
      ).attribution.observedDependency,
    ).toBe(false);
    expect(
      attribute(
        record({ ...tupleRecord, interval: { start: 150, end: 160 } }),
        contextSelection,
        [tupleBinding],
      ).attribution.observedDependency,
    ).toBe(false);

    expect(
      attribute(
        record({ target: { ...target, port: 444 } }),
        contextSelection,
        [binding({ target: { ...target, port: 444 } })],
      ).attribution.observedDependency,
    ).toBe(false);
    expect(
      attribute(
        record({ target: { ...target, protocol: "udp" } }),
        contextSelection,
        [binding({ target: { ...target, protocol: "udp" } })],
      ).attribution.observedDependency,
    ).toBe(false);
    expect(
      attribute(
        tupleRecord,
        selection({
          contexts: [
            {
              ...contextSelection.contexts[0],
              client: "198.51.100.20",
              server: "192.0.2.10",
            },
          ],
        }),
        [tupleBinding],
      ).attribution.observedDependency,
    ).toBe(false);
    expect(
      attribute(
        record({ target: { ...target, protocol: "unknown" } }),
        selection({
          contexts: [
            {
              ...contextSelection.contexts[0],
              transport: "unknown",
            },
          ],
        }),
        [binding({ target: { ...target, protocol: "unknown" } })],
      ).attribution.observedDependency,
    ).toBe(false);
    const boundWithoutTuple = attribute(
      record({ target: { ip: "198.51.100.20" } }),
      contextSelection,
      [binding({ target: { ip: "198.51.100.20" } })],
    );
    expect(boundWithoutTuple.attribution.state).toBe("bound");
    expect(boundWithoutTuple.attribution.observedDependency).toBe(false);
    const missingContextTuple = attribute(
      tupleRecord,
      selection({
        contexts: [
          {
            ...contextSelection.contexts[0],
            serverPort: undefined,
            transport: undefined,
          },
        ],
      }),
      [tupleBinding],
    );
    expect(missingContextTuple.attribution.observedDependency).toBe(false);
  });
});

describe("compareThousandEyesMeasurements", () => {
  const attributed = (
    overrides: Partial<ThousandEyesObservation>,
    bindings: ThousandEyesBinding[] = [
      binding({ validFrom: 50, validTo: 350 }),
    ],
  ): ThousandEyesAttributedObservation =>
    attributeThousandEyesRecords([record(overrides)], selection(), bindings)[0];

  const before = { start: 100, end: 200 };
  const after = { start: 200, end: 300 };

  it("groups adapter-emitted OTLP metric datapoints into metric-specific rounds", () => {
    const beforeNormalized = normalizeMetricFixture(1_700_000_010, 0.025, 1);
    const afterNormalized = normalizeMetricFixture(1_700_000_020, 0.05, 2);
    expect(beforeNormalized.rejected).toBe(0);
    expect(afterNormalized.rejected).toBe(0);
    expect(beforeNormalized.records).toHaveLength(2);
    expect(afterNormalized.records).toHaveLength(2);
    expect(
      new Set(beforeNormalized.records.map((item) => item.fingerprint)).size,
    ).toBe(1);

    const selected = adapterSelection();
    const attributedRecords = [
      ...beforeNormalized.records,
      ...afterNormalized.records,
    ].map(
      (item) =>
        attributeThousandEyesRecords([item], selected, [adapterBinding()])[0],
    );
    expect(attributedRecords.map((item) => item.attribution.state)).toEqual([
      "bound",
      "bound",
      "bound",
      "bound",
    ]);

    const comparisons = compareThousandEyesMeasurements(
      attributedRecords,
      { start: 1_700_000_000, end: 1_700_000_015 },
      { start: 1_700_000_015, end: 1_700_000_030 },
    );
    expect(comparisons).toHaveLength(2);
    expect(
      comparisons.map(({ metric, beforeCount, afterCount, comparable }) => ({
        metric,
        beforeCount,
        afterCount,
        comparable,
      })),
    ).toEqual([
      {
        metric: "network.latency",
        beforeCount: 1,
        afterCount: 1,
        comparable: true,
      },
      {
        metric: "network.loss",
        beforeCount: 1,
        afterCount: 1,
        comparable: true,
      },
    ]);
    for (const comparison of comparisons) {
      expect(comparison.reasons.join(" ")).not.toContain(
        "successful-sample coverage may be biased",
      );
    }
  });

  it("returns means and deltas only for compatible bound scalar samples", () => {
    const samples = [
      attributed({
        interval: { start: 110, end: 120 },
        measurements: [{ ...record().measurements[0], value: 10 }],
      }),
      attributed({
        interval: { start: 130, end: 140 },
        measurements: [{ ...record().measurements[0], value: 20 }],
      }),
      attributed({
        interval: { start: 210, end: 220 },
        measurements: [{ ...record().measurements[0], value: 30 }],
      }),
    ];
    const [comparison] = compareThousandEyesMeasurements(
      samples,
      before,
      after,
    );
    expect(comparison).toMatchObject({
      metric: "latency",
      unit: "ms",
      beforeCount: 2,
      afterCount: 1,
      beforeMean: 15,
      afterMean: 30,
      delta: 15,
      comparable: true,
    });
  });

  it("uses native test IDs across renamed tests and reports missing window coverage", () => {
    const samples = [
      attributed({
        interval: { start: 110, end: 120 },
        testName: "old display label",
      }),
      attributed({
        interval: { start: 210, end: 220 },
        testName: "new display label",
      }),
    ];
    const [comparison] = compareThousandEyesMeasurements(
      samples,
      before,
      after,
    );
    expect(comparison.testId).toBe("test-7");
    expect(comparison.beforeCount).toBe(1);
    expect(comparison.afterCount).toBe(1);
    expect(comparison.comparable).toBe(true);

    const [missing] = compareThousandEyesMeasurements(
      [samples[0]],
      before,
      after,
    );
    expect(missing.afterCount).toBe(0);
    expect(missing.comparable).toBe(false);
    expect(missing.beforeMean).toBeUndefined();
    expect(missing.reasons.join(" ")).toContain("No finite scalar measurement");
  });

  it("keeps identical native test IDs in separate test-domain comparisons", () => {
    const ceaSample = attributed({ interval: { start: 110, end: 120 } });
    const endpointSample = attributed(
      { interval: { start: 210, end: 220 }, testDomain: "endpoint" },
      [
        binding({
          testDomain: "endpoint",
          validFrom: 50,
          validTo: 350,
        }),
      ],
    );
    const comparisons = compareThousandEyesMeasurements(
      [ceaSample, endpointSample],
      before,
      after,
    );
    expect(comparisons).toHaveLength(2);
    expect(new Set(comparisons.map((item) => item.key)).size).toBe(2);
    expect(comparisons.every((item) => !item.comparable)).toBe(true);
    expect(comparisons.map((item) => item.testDomain).sort()).toEqual([
      "cea",
      "endpoint",
    ]);
    expect(
      comparisons
        .map((item) => [item.beforeCount, item.afterCount].join(":"))
        .sort(),
    ).toEqual(["0:1", "1:0"]);
  });

  it("exposes configuration, location, target and unit changes as incomparable", () => {
    const beforeBinding = binding({
      id: "old-config",
      configurationId: "config-a",
      validFrom: 50,
      validTo: 200,
    });
    const afterBinding = binding({
      id: "new-config",
      configurationId: "config-b",
      target: { ip: "198.51.100.21", protocol: "https", port: 443 },
      agentLocation: "West office",
      validFrom: 200,
      validTo: 350,
    });
    const oldSample = attributed(
      {
        interval: { start: 110, end: 120 },
        configurationId: "config-a",
        agentLocation: "East office",
      },
      [beforeBinding],
    );
    const newSample = attributed(
      {
        interval: { start: 210, end: 220 },
        target: { ip: "198.51.100.21", protocol: "https", port: 443 },
        configurationId: "config-b",
        agentLocation: "West office",
        measurements: [{ ...record().measurements[0], unit: "s", value: 0.03 }],
      },
      [afterBinding],
    );
    const [comparison] = compareThousandEyesMeasurements(
      [oldSample, newSample],
      before,
      after,
    );
    expect(comparison.comparable).toBe(false);
    expect(comparison.beforeMean).toBeUndefined();
    expect(comparison.afterMean).toBeUndefined();
    expect(comparison.delta).toBeUndefined();
    expect(comparison.unit).toBe("mixed");
    expect(comparison.reasons.join(" ")).toContain(
      "Test configuration changed",
    );
    expect(comparison.reasons.join(" ")).toContain("Agent location changed");
    expect(comparison.reasons.join(" ")).toContain("Target identity changed");
    expect(comparison.reasons.join(" ")).toContain("Measurement unit changed");
  });

  it("rejects unknown measurement semantics and changed adapter or model versions", () => {
    const fields = [
      ["aggregation", "Measurement aggregation"],
      ["direction", "Measurement direction"],
      ["denominator", "Measurement denominator"],
      ["timeBasis", "Measurement time basis"],
    ] as const;
    for (const [field, label] of fields) {
      const measurement = { ...record().measurements[0], [field]: "unknown" };
      const [comparison] = compareThousandEyesMeasurements(
        [
          attributed({
            interval: { start: 110, end: 120 },
            measurements: [measurement],
          }),
          attributed({
            interval: { start: 210, end: 220 },
            measurements: [measurement],
          }),
        ],
        before,
        after,
      );
      expect(comparison.comparable).toBe(false);
      expect(comparison.reasons.join(" ")).toContain(
        `${label} is unknown or unreported`,
      );
    }

    for (const [field, label] of [
      ["adapterVersion", "Atlas adapter version"],
      ["dataModelVersion", "ThousandEyes data-model version"],
    ] as const) {
      const [comparison] = compareThousandEyesMeasurements(
        [
          attributed({ interval: { start: 110, end: 120 } }),
          attributed({
            interval: { start: 210, end: 220 },
            [field]: "changed-version",
          }),
        ],
        before,
        after,
      );
      expect(comparison.comparable).toBe(false);
      expect(comparison.reasons.join(" ")).toContain(
        `${label} changed between windows`,
      );
      const [unknown] = compareThousandEyesMeasurements(
        [
          attributed({
            interval: { start: 110, end: 120 },
            [field]: "unknown",
          }),
          attributed({
            interval: { start: 210, end: 220 },
            [field]: "unknown",
          }),
        ],
        before,
        after,
      );
      expect(unknown.comparable).toBe(false);
      expect(unknown.reasons.join(" ")).toContain(
        `${label} is unknown or unreported`,
      );
    }
  });

  it("requires a stable known probe path direction for path comparisons", () => {
    const [changed] = compareThousandEyesMeasurements(
      [
        attributed({
          family: "path",
          interval: { start: 110, end: 120 },
          pathDirection: "to-target",
        }),
        attributed({
          family: "path",
          interval: { start: 210, end: 220 },
          pathDirection: "from-target",
        }),
      ],
      before,
      after,
    );
    expect(changed.comparable).toBe(false);
    expect(changed.reasons.join(" ")).toContain(
      "Probe path direction changed between windows",
    );

    const [missing] = compareThousandEyesMeasurements(
      [
        attributed({ family: "path", interval: { start: 110, end: 120 } }),
        attributed({ family: "path", interval: { start: 210, end: 220 } }),
      ],
      before,
      after,
    );
    expect(missing.comparable).toBe(false);
    expect(missing.reasons.join(" ")).toContain(
      "Probe path direction is missing or varies",
    );
  });

  it("discloses unreported producer versions and rejects version changes", () => {
    const noProducerVersion = [
      attributed({
        interval: { start: 110, end: 120 },
        producerVersion: undefined,
      }),
      attributed({
        interval: { start: 210, end: 220 },
        producerVersion: "not_reported",
      }),
    ];
    const [unreported] = compareThousandEyesMeasurements(
      noProducerVersion,
      before,
      after,
    );
    expect(unreported.comparable).toBe(true);
    expect(unreported.reasons.join(" ")).toContain(
      "Producer version was not reported in either window",
    );

    const [changed] = compareThousandEyesMeasurements(
      [
        attributed({
          interval: { start: 110, end: 120 },
          producerVersion: "10.0",
        }),
        attributed({
          interval: { start: 210, end: 220 },
          producerVersion: "11.0",
        }),
      ],
      before,
      after,
    );
    expect(changed.comparable).toBe(false);
    expect(changed.reasons.join(" ")).toContain(
      "Producer version changed between windows",
    );

    const [unknown] = compareThousandEyesMeasurements(
      [
        attributed({
          interval: { start: 110, end: 120 },
          producerVersion: "unknown",
        }),
        attributed({
          interval: { start: 210, end: 220 },
          producerVersion: "unknown",
        }),
      ],
      before,
      after,
    );
    expect(unknown.comparable).toBe(false);
    expect(unknown.reasons.join(" ")).toContain(
      "Producer version is unknown or invalid",
    );
  });

  it("counts failed rounds missing a finite metric and blocks a survivor-only comparison", () => {
    const [comparison] = compareThousandEyesMeasurements(
      [
        attributed({
          interval: { start: 110, end: 120 },
          outcome: "success",
          measurements: [{ ...record().measurements[0], value: 100 }],
        }),
        attributed({
          interval: { start: 130, end: 140 },
          outcome: "failure",
          measurements: [],
        }),
        attributed({
          interval: { start: 210, end: 220 },
          outcome: "success",
          measurements: [{ ...record().measurements[0], value: 10 }],
        }),
        attributed({
          interval: { start: 230, end: 240 },
          outcome: "failure",
          measurements: [],
        }),
      ],
      before,
      after,
    );
    expect(comparison.beforeCount).toBe(1);
    expect(comparison.afterCount).toBe(1);
    expect(comparison.comparable).toBe(false);
    expect(comparison.beforeMean).toBeUndefined();
    expect(comparison.afterMean).toBeUndefined();
    expect(comparison.reasons.join(" ")).toContain(
      "across 2 latency-eligible native interval round(s); 1 failed round(s), 1 round(s) without a finite bound latency reading",
    );
    expect(comparison.reasons.join(" ")).toContain(
      "successful-sample coverage may be biased",
    );
  });

  it("does not count finite but unbound or quality-limited readings as complete rounds", () => {
    const changedTarget = attributed({
      interval: { start: 130, end: 140 },
      target: { ip: "198.51.100.21", protocol: "https", port: 443 },
      measurements: [{ ...record().measurements[0], value: 999 }],
    });
    const relocated = attributed({
      interval: { start: 140, end: 150 },
      agentLocation: "West office",
      measurements: [{ ...record().measurements[0], value: 998 }],
    });
    const changedConfiguration = attributed({
      interval: { start: 150, end: 160 },
      configurationId: "config-b",
      measurements: [{ ...record().measurements[0], value: 997 }],
    });
    const qualityLimited = attributed({
      interval: { start: 160, end: 170 },
      quality: {
        stale: true,
        complete: true,
        conflicting: false,
        truncated: false,
      },
      measurements: [{ ...record().measurements[0], value: 996 }],
    });
    expect(
      [changedTarget, relocated, changedConfiguration, qualityLimited].map(
        (item) => item.attribution.state,
      ),
    ).not.toContain("bound");

    const [comparison] = compareThousandEyesMeasurements(
      [
        attributed({
          interval: { start: 110, end: 120 },
          measurements: [{ ...record().measurements[0], value: 10 }],
        }),
        changedTarget,
        relocated,
        changedConfiguration,
        qualityLimited,
        attributed({
          interval: { start: 210, end: 220 },
          measurements: [{ ...record().measurements[0], value: 20 }],
        }),
      ],
      before,
      after,
    );
    expect(comparison.beforeCount).toBe(1);
    expect(comparison.afterCount).toBe(1);
    expect(comparison.comparable).toBe(false);
    expect(comparison.beforeMean).toBeUndefined();
    expect(comparison.afterMean).toBeUndefined();
    expect(comparison.reasons.join(" ")).toContain(
      "across 5 latency-eligible native interval round(s)",
    );
    expect(comparison.reasons.join(" ")).toContain(
      "4 round(s) without a finite bound latency reading",
    );
  });

  it("rejects partial window intervals, unbound rows and out-of-order windows", () => {
    const partial = attributed({ interval: { start: 190, end: 210 } });
    const comparison = compareThousandEyesMeasurements(
      [
        partial,
        {
          ...attributed({ interval: { start: 110, end: 120 } }),
          attribution: {
            state: "context_only",
            bindingIds: [],
            reason: "context only",
            observedDependency: true,
          },
        },
      ],
      before,
      after,
    );
    expect(comparison).toEqual([]);

    const contextOnly = {
      ...attributed({ interval: { start: 110, end: 120 } }),
      attribution: {
        state: "context_only" as const,
        bindingIds: [],
        reason: "context only",
        observedDependency: true,
      },
    };
    expect(
      compareThousandEyesMeasurements([contextOnly], before, after),
    ).toEqual([]);

    const [boundary] = compareThousandEyesMeasurements(
      [
        attributed({
          interval: { start: 200, end: 200 },
          intervalBasis: "point",
        }),
      ],
      before,
      after,
    );
    expect(boundary.beforeCount).toBe(0);
    expect(boundary.afterCount).toBe(1);

    const ordered = compareThousandEyesMeasurements(
      [attributed({ interval: { start: 110, end: 120 } })],
      after,
      before,
    );
    expect(ordered[0].comparable).toBe(false);
    expect(ordered[0].reasons.join(" ")).toContain(
      "overlap or are out of order",
    );
    expect(ordered[0].beforeMean).toBeUndefined();
  });

  it("excludes quality-limited records from comparisons even if marked bound", () => {
    const qualityLimited = {
      ...attributed({ interval: { start: 110, end: 120 } }),
      quality: {
        stale: false,
        complete: true,
        conflicting: false,
        truncated: true,
      },
    };
    expect(
      compareThousandEyesMeasurements([qualityLimited], before, after),
    ).toEqual([]);
  });
});
