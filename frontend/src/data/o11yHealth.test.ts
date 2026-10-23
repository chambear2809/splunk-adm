import { describe, expect, it, vi } from "vitest";
import fixture from "../../../fixtures/o11y/complete.json";
import {
  buildO11yHealthSearch,
  loadO11yHealthEvidence,
  normalizeO11yHealthEvidence,
} from "./o11yHealth";
import type { ServiceHealthSelection } from "./evidence";
import type {
  EvidenceConfiguration,
  SupplementalSourceConfiguration,
} from "./evidenceConfig";
import type { SearchClient } from "./searchClient";
import type { Row } from "../rows";

const observer = "o11y-observer-prod";
const selection: ServiceHealthSelection = {
  schemaVersion: 1,
  workflow: "service",
  selectionId: "service-test",
  scope: "prod-east",
  window: { start: 1792763000, end: 1792763990 },
  service: {
    name: "checkout-api",
    environment: "production",
    cluster: "eks-prod-east",
    namespace: "commerce",
  },
  identityBasis: "exact graph-boundary service dimensions",
  configurationFingerprint: "a".repeat(64),
};

const config: SupplementalSourceConfiguration = {
  source: "o11y_health",
  state: "active",
  indexes: ["atlas_o11y"],
  authorities: [observer],
  schemaQualified: true,
  staleAfterSeconds: 3600,
  mappings: [
    {
      observer_kind: "o11y_export",
      observer,
      scope: "prod-east",
      cluster: "eks-prod-east",
      mapping_status: "verified",
      organization_id: "org-demo-01",
      realm: "us0",
      apm_mms_id: "checkout_service_mms_v1",
    },
  ],
};

interface TestEnvelope {
  time: number;
  host: string;
  source: string;
  sourcetype: string;
  event: Record<string, unknown>;
}

type FixtureEvent = Record<string, unknown>;

function indexedRows(events: readonly TestEnvelope[] = fixture.events): Row[] {
  return events.map((envelope, index) => ({
    _raw: JSON.stringify(envelope.event),
    _time: String(envelope.time),
    _indextime: String(envelope.time + 1),
    host: envelope.host,
    index: "atlas_o11y",
    event_fingerprint: String(index + 1).padStart(64, "0"),
  }));
}

function withEventChanges(
  index: number,
  changes: Partial<FixtureEvent>,
): Row[] {
  const events = structuredClone(fixture.events) as TestEnvelope[];
  events[index] = {
    ...events[index],
    event: { ...events[index].event, ...changes },
  };
  return indexedRows(events);
}

describe("Observability Cloud health evidence", () => {
  it("builds an exact, projected and bounded search for one verified org and realm", () => {
    const search = buildO11yHealthSearch(config, selection);
    expect(search).toContain('index=atlas_o11y sourcetype="atlas:o11y_health"');
    expect(search).toContain(`host="${observer}"`);
    expect(search).toContain('"organization_id")="org-demo-01"');
    expect(search).toContain('"realm")="us0"');
    expect(search).toContain('"service_name")="checkout-api"');
    expect(search).toContain('"environment")="production"');
    expect(search).toContain('"cluster")="eks-prod-east"');
    expect(search).toContain('"kubernetes_namespace")="commerce"');
    expect(search).toContain('"apm_mms_id")="checkout_service_mms_v1"');
    expect(search).toContain('"sf_mms_id")="checkout_service_mms_v1"');
    expect(search).toContain('"sf_dimensionalized")="true"');
    expect(search).toContain("head 10001");
    expect(search).toContain("head 64");
    expect(search).toContain('kind="supplemental_completion"');
    expect(search).toContain('"service_namespace"');
    expect(search).not.toMatch(/\|\s*(join|map|lookup)\b/i);
  });

  it("normalizes measured RED, container CPU and JVM samples plus completion", () => {
    const result = normalizeO11yHealthEvidence(
      indexedRows(),
      selection,
      config,
    );
    expect(result.rejected).toBe(0);
    expect(result.records).toHaveLength(6);
    expect(result.records.at(-1)).toMatchObject({
      kind: "export_completion",
      expectedRecordCount: 5,
      signalsWithData: 5,
      organizationId: "org-demo-01",
      realm: "us0",
      detectorAlerts: "not_queried",
    });
    expect(
      result.records
        .filter((record) => record.kind === "metric")
        .map((record) => [record.signalLabel, record.value, record.unit]),
    ).toEqual([
      ["request_count", 18, "count"],
      ["request_errors", 2, "count"],
      ["request_latency_p90", 25000000, "ns"],
      ["container_cpu_utilization", 0.42, "1"],
      ["jvm_memory_used", 134217728, "By"],
    ]);
    expect(result.records[0].sourceDimensions?.serviceNamespace).toBe(
      "payments",
    );
    expect(result.records[0].apmMmsId).toBe("checkout_service_mms_v1");
    expect(result.records[3].apmMmsId).toBeUndefined();
    expect(result.records[3].sourceDimensions?.sfMmsId).toBeUndefined();
    expect(result.records[0].limitations.join(" ")).toMatch(
      /do not establish a network cause/i,
    );
  });

  it("rejects a wrong org, realm, observer, routing scope or graph dimension", () => {
    for (const [index, changes] of [
      [0, { organization_id: "other-org" }],
      [0, { realm: "eu0" }],
      [0, { observer_id: "other-observer" }],
      [0, { routing_scope: "other-scope" }],
      [0, { kubernetes_namespace: "other-namespace" }],
      [0, { cluster: "other-cluster" }],
      [0, { environment: "staging" }],
      [0, { service_name: "same-display-name-other-identity" }],
      [0, { apm_mms_id: "other_mms" }],
      [0, { sf_mms_id: "other_mms" }],
      [0, { sf_dimensionalized: "false" }],
      [5, { sf_mms_id: "other_mms" }],
    ] as const) {
      expect(
        normalizeO11yHealthEvidence(
          withEventChanges(index, changes),
          selection,
          config,
        ),
      ).toMatchObject({ records: [], rejected: 1 });
    }
  });

  it("fails closed when source service.namespace is ambiguous", () => {
    const events = structuredClone(fixture.events) as TestEnvelope[];
    events[5].event.expected_record_count = 6;
    events.splice(5, 0, {
      ...events[0],
      event: {
        ...events[0].event,
        service_namespace: "other-otel-namespace",
        value: 19,
      },
    });
    expect(
      normalizeO11yHealthEvidence(indexedRows(events), selection, config),
    ).toMatchObject({
      records: [],
      rejected: 1,
    });
  });

  it("treats a missing indexed metric as an unavailable partial capture", async () => {
    const rows = indexedRows().slice(1);
    expect(normalizeO11yHealthEvidence(rows, selection, config)).toMatchObject({
      records: [],
      rejected: 1,
    });
    const configuration: EvidenceConfiguration = {
      fingerprint: selection.configurationFingerprint,
      trafficContract: 1,
      summaryIndexes: ["adm_summary"],
      mappings: config.mappings,
      identities: [],
      identityAvailable: true,
      dns: [],
      maxAgeSeconds: 3600,
      supplemental: [config],
    };
    const client: SearchClient = {
      search: vi.fn(async () => ({
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
        errors: [],
        warnings: [],
      })),
    };
    const result = await loadO11yHealthEvidence(
      client,
      selection,
      new AbortController().signal,
      { read: async () => configuration },
    );
    expect(result.state).toBe("unavailable");
    expect(result.errorCode).toBe("normalization");
    expect(result.records).toEqual([]);
  });

  it("supports an explicitly selected independent OTel service namespace", () => {
    const qualified = {
      ...selection,
      service: { ...selection.service, serviceNamespace: "payments" },
    };
    expect(buildO11yHealthSearch(config, qualified)).toContain(
      '"service_namespace")="payments"',
    );
    expect(
      normalizeO11yHealthEvidence(indexedRows(), qualified, config).rejected,
    ).toBe(0);
  });

  it("rejects unqualified or multiply mapped Observability Cloud authorities", () => {
    expect(() => buildO11yHealthSearch(config, selection)).not.toThrow();
    expect(() =>
      buildO11yHealthSearch({ ...config, schemaQualified: false }, selection),
    ).toThrow(/active and schema-qualified/i);
    expect(() =>
      buildO11yHealthSearch(
        {
          ...config,
          mappings: [
            ...config.mappings,
            {
              ...config.mappings[0],
              observer: "o11y-observer-secondary",
              organization_id: "org-demo-02",
              realm: "eu0",
            },
          ],
          authorities: [...config.authorities, "o11y-observer-secondary"],
        },
        selection,
      ),
    ).toThrow(/multiple verified/i);
    expect(() =>
      buildO11yHealthSearch(
        {
          ...config,
          mappings: [{ ...config.mappings[0], apm_mms_id: "unsafe value" }],
        },
        selection,
      ),
    ).toThrow(/APM MMS ID is invalid/i);
  });
});
