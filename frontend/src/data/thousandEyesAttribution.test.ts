import { describe, expect, it } from "vitest";
import type { EvidenceSelection } from "./evidence";
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

  it("does not use names or tags when native test or agent IDs are absent", () => {
    const attributed = attribute(
      record({ testId: undefined, agentId: undefined }),
    );
    expect(attributed.attribution.state).toBe("unmatched");
    expect(attributed.attribution.reason).toContain(
      "test names and tags are not used",
    );
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
        },
      ],
    });
    const observed = attribute(record(), contextSelection);
    expect(observed.attribution.observedDependency).toBe(true);
    expect(observed.attribution.reason).toContain(
      "does not prove the same route",
    );

    expect(
      attribute(record(), selection()).attribution.observedDependency,
    ).toBe(false);
    expect(
      attribute(
        record(),
        selection({
          contexts: [
            {
              ...contextSelection.contexts[0],
              capped: true,
            },
          ],
        }),
      ).attribution.observedDependency,
    ).toBe(false);
    expect(
      attribute(record({ family: "trace" }), contextSelection).attribution
        .observedDependency,
    ).toBe(false);
    expect(
      attribute(
        record({ target: { hostname: "service.example" } }),
        contextSelection,
      ).attribution.observedDependency,
    ).toBe(false);
    expect(
      attribute(
        record({ interval: { start: 150, end: 160 } }),
        contextSelection,
      ).attribution.observedDependency,
    ).toBe(false);
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
    expect(comparison[0].beforeCount).toBe(0);
    expect(comparison[0].afterCount).toBe(0);

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
