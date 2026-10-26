import { describe, expect, it } from "vitest";
import {
  parseThousandEyesBindings,
  parseThousandEyesFamilies,
  parseThousandEyesPathSources,
  thousandEyesMappings,
  thousandEyesTarget,
} from "./thousandEyesConfiguration";
import type { SupplementalSourceConfiguration } from "./evidenceConfig";
import type { EvidenceSelection } from "./evidence";

const binding = {
  id: "test-17-agent-9-v1",
  authority: "te-example",
  accountGroupId: "1234",
  scope: "site-a",
  testId: "17",
  agentId: "9",
  target: { ip: "192.0.2.8", protocol: "tcp", port: 443 },
  endpointAddresses: ["192.0.2.8"],
  validFrom: 100,
  validTo: 200,
  configurationId: "test-config-1",
};
const selection: EvidenceSelection = {
  schemaVersion: 1,
  workflow: "endpoint",
  selectionId: "endpoint-1",
  trafficContract: 1,
  window: { start: 110, end: 120 },
  scope: "site-a",
  addresses: ["192.0.2.8"],
  contexts: [],
  identityBasis: "scoped endpoint",
  configurationFingerprint: "a".repeat(64),
};
const configuration = (): SupplementalSourceConfiguration => ({
  source: "thousandeyes",
  state: "active",
  indexes: ["te_metrics", "te_events"],
  authorities: ["te-example"],
  schemaQualified: true,
  staleAfterSeconds: 1200,
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
      te_bindings: JSON.stringify([binding]),
      te_path_sources: JSON.stringify([
        { index: "te_events", source: "test_metrics_stream://site-a" },
      ]),
      thousandeyes_origin: "https://app.thousandeyes.com",
    },
  ],
});

describe("ThousandEyes administrator configuration boundary", () => {
  it("retains explicit native-account bindings without assuming equality with aid", () => {
    const [mapping] = thousandEyesMappings(configuration(), selection);
    expect(mapping.accountGroupId).toBe("1234");
    expect(mapping.streamAccountId).toBe("5678");
    expect(mapping.alertAccountId).toBe("6789");
    expect(mapping.organizationId).toBe("org-1");
    expect(mapping.bindings).toEqual([binding]);
  });

  it("requires a selected family and bounds configuration expansion", () => {
    expect(() => parseThousandEyesFamilies("[]")).toThrow();
    expect(() => parseThousandEyesFamilies('["metric","metric"]')).toThrow();
    expect(() => parseThousandEyesFamilies('["unknown"]')).toThrow();
    expect(() =>
      parseThousandEyesBindings(
        JSON.stringify(Array(65).fill(binding)),
        "te-example",
        "1234",
        "site-a",
      ),
    ).toThrow();
    expect(() =>
      parseThousandEyesBindings(
        " ".repeat(65537),
        "te-example",
        "1234",
        "site-a",
      ),
    ).toThrow();
  });

  it.each([
    { authority: "other-account" },
    { accountGroupId: "9999" },
    { scope: "other-scope" },
    { validTo: 100 },
    { validFrom: -1 },
    { testId: '17" | delete' },
    { endpointAddresses: ["192.0.2.8", "::ffff:c000:208"] },
    { target: { hostname: "*.example.com" } },
    {
      application: {
        service: 123,
        environment: "prod",
        cluster: "c",
        namespace: "ns",
      },
    },
    { credential: "forbidden-extra-field" },
  ])("refuses unqualified, conflicting or malformed binding %j", (change) => {
    expect(() =>
      parseThousandEyesBindings(
        JSON.stringify([{ ...binding, ...change }]),
        "te-example",
        "1234",
        "site-a",
      ),
    ).toThrow();
  });

  it("preserves distinct historical revisions and rejects reused binding IDs", () => {
    const successor = {
      ...binding,
      id: "v2",
      validFrom: 200,
      validTo: 300,
      configurationId: "config-2",
    };
    expect(
      parseThousandEyesBindings(
        JSON.stringify([binding, successor]),
        "te-example",
        "1234",
        "site-a",
      ),
    ).toHaveLength(2);
    expect(() =>
      parseThousandEyesBindings(
        JSON.stringify([binding, binding]),
        "te-example",
        "1234",
        "site-a",
      ),
    ).toThrow();
  });

  it("requires exact configured index and input source for paths", () => {
    expect(() =>
      parseThousandEyesPathSources(
        '[{"index":"*","source":"test_metrics_stream://a"}]',
      ),
    ).toThrow();
    expect(() =>
      parseThousandEyesPathSources('[{"index":"te_events","source":"*"}]'),
    ).toThrow();
    const config = configuration();
    config.mappings[0].te_path_sources =
      '[{"index":"forbidden","source":"test_metrics_stream://a"}]';
    expect(() => thousandEyesMappings(config, selection)).toThrow();
    const duplicated = configuration();
    duplicated.authorities.push("te-other");
    duplicated.mappings.push({
      ...duplicated.mappings[0],
      observer: "te-other",
      te_account_group_id: "2345",
      te_bindings: "[]",
    });
    expect(() => thousandEyesMappings(duplicated, selection)).toThrow();
  });

  it.each([
    "http://app.thousandeyes.com",
    "https://user:credential@app.thousandeyes.com",
    "https://app.thousandeyes.com/tests/17",
    "https://app.thousandeyes.com?test=17",
    "https://app.thousandeyes.com#test-17",
  ])("rejects unsafe or non-origin navigation configuration %s", (origin) => {
    const config = configuration();
    config.mappings[0].thousandeyes_origin = origin;
    expect(() => thousandEyesMappings(config, selection)).toThrow();
  });

  it("does not require unrelated stream/webhook fields for native event-only inputs", () => {
    const config = configuration();
    config.mappings[0].te_families = '["event"]';
    delete config.mappings[0].te_stream_account_id;
    delete config.mappings[0].te_alert_account_id;
    delete config.mappings[0].te_organization_id;
    expect(thousandEyesMappings(config, selection)[0].families).toEqual([
      "event",
    ]);
  });

  it("normalizes target literals without DNS lookup or URL interpretation", () => {
    expect(
      thousandEyesTarget({
        ip: "::ffff:c000:208",
        hostname: "API.EXAMPLE.COM",
        protocol: "tcp",
        port: 443,
      }),
    ).toEqual({
      ip: "192.0.2.8",
      hostname: "api.example.com",
      protocol: "tcp",
      port: 443,
    });
    expect(() =>
      thousandEyesTarget({ hostname: "https://api.example.com" }),
    ).toThrow();
  });
});
