import { describe, expect, it } from "vitest";
import type { EvidenceSelection } from "./evidence";
import type { SupplementalSourceConfiguration } from "./evidenceConfig";
import {
  buildThousandEyesSearch,
  THOUSANDEYES_COVERAGE,
} from "./thousandEyesEvidence";

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

const binding = {
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
      te_bindings: JSON.stringify([binding]),
      te_path_sources: JSON.stringify([
        { index: "te_paths", source: "test_metrics_stream://site-a" },
        { index: "te_paths", source: "atlas:thousandeyes:path" },
      ]),
      thousandeyes_origin: "https://app.thousandeyes.com",
    },
  ],
});

describe("ThousandEyes selected evidence search", () => {
  it("filters recognized native measurement time before the retained input cap", () => {
    const query = buildThousandEyesSearch(configuration(), selection);
    const coarseFilter = query.indexOf("| where case(");
    const cap = query.indexOf("| head 10001");
    expect(coarseFilter).toBeGreaterThan(-1);
    expect(coarseFilter).toBeLessThan(cap);
    expect(query).toContain("time_unix_nano");
    expect(query).toContain("start_time_unix_nano");
    expect(query).toContain("startDate");
    expect(query).toContain("alert.triggered.epochMilli");
    expect(query).toContain("result.date");
    expect(query).toContain("_te_m_first<=1700000401");
    expect(query).toContain("_te_m_last>=1699999999");
    expect(query).toContain("_te_m_unknown=1 OR");
    expect(query).toContain("_te_t_unknown=1 OR");
    expect(query).toContain("_te_a_unknown=1 OR");
    expect(query).toContain("_te_e_unknown=1 OR");
    expect(query).toContain("_te_l_unknown=1 OR");
    expect(query).toContain("_te_p_unknown=1 OR");
    expect(query).toContain("%:z");
    expect(query).toContain('replace(_te_e_start,"Z$","+0000")');
    expect(query).toContain("min(_te_m_start_s)");
    expect(query).not.toContain("mvmin(");
    expect(query).not.toContain("mvmax(");
  });

  it("uses retained-index capture bounds, never Splunk _time as native time or receipt filter", () => {
    const query = buildThousandEyesSearch(configuration(), selection);
    expect(query).not.toMatch(/\b_time\s*(?:>=|<=|>|<|=)/);
    expect(query).not.toMatch(/\b_indextime\s*(?:>=|<=|>|<|=)/);
    expect(query).toContain("row_time_epoch=tonumber(_time)");
    expect(query).toContain("indexed_time_epoch=tonumber(_indextime)");
    expect(THOUSANDEYES_COVERAGE.join(" ")).toContain(
      "Late-indexed evidence remains visible",
    );
    expect(THOUSANDEYES_COVERAGE.join(" ")).toContain(
      "Splunk _time is preserved separately as rowTime",
    );
  });

  it("extracts OTel attribute arrays and nested path identity before literal admission", () => {
    const query = buildThousandEyesSearch(configuration(), selection);
    expect(query).toContain('sourcetype="cisco:thousandeyes:metric"');
    expect(query).toContain('sourcetype="cisco:thousandeyes:trace"');
    expect(query).toContain('sourcetype="cisco:thousandeyes:activity"');
    expect(query).toContain('sourcetype="cisco:thousandeyes:event"');
    expect(query).toContain('sourcetype="cisco:thousandeyes:alerts"');
    expect(query).toContain('sourcetype="atlas:thousandeyes:path"');
    expect(query).toContain('source="cisco:thousandeyes:stream"');
    expect(query).toContain('source="cisco:thousandeyes:webhook"');
    expect(query).toContain(
      "path=resource_metrics{}.resource.attributes{}.key output=_te_m_keys",
    );
    expect(query).toContain(
      "path=resource_metrics{}.resource.attributes{}.value.string_value output=_te_m_string_values",
    );
    expect(query).toContain(
      "path=resource_spans{}.resource.attributes{}.key output=_te_t_keys",
    );
    expect(query).toContain(
      "path=resource_logs{}.resource.attributes{}.key output=_te_a_keys",
    );
    expect(query).toContain('mvfilter(_te_m_keys="thousandeyes.account.id")');
    expect(query).toContain('mvfilter(_te_m_values="5678")');
    expect(query).toContain('mvfilter(_te_m_values="17")');
    expect(query).toContain('mvfilter(_te_m_values="9")');
    expect(query).toContain('like(_te_m_metric_names,"bgp.%")');
    expect(query).toContain("thousandeyes.monitor.id");
    expect(query).toContain("'aid'=\"1234\"");
    expect(query).toContain("'accountId'=\"6789\"");
    expect(query).toContain("'orgId'=\"org-1\"");
    expect(query).toContain('schema="application_atlas.thousandeyes_path.v1"');
    expect(query).toContain(
      "path=result.agent.agentId output=_te_p_wrapper_agent",
    );
    expect(query).toContain('_te_p_wrapper_agent="9"');
    expect(query).not.toContain("'agent_id'=\"9\"");
    expect(query).not.toContain("'thousandeyes.account.id'=\"5678\"");
    expect(query).toContain("_te_m_identity_unknown=1 OR");
  });

  it("rejects inactive, unqualified, invalid-index, and injection-shaped config", () => {
    const inactive = configuration();
    inactive.state = "staged";
    expect(() => buildThousandEyesSearch(inactive, selection)).toThrow();

    const unqualified = configuration();
    unqualified.schemaQualified = false;
    expect(() => buildThousandEyesSearch(unqualified, selection)).toThrow();

    const badIndex = configuration();
    badIndex.indexes[0] = "te_metrics OR index=*";
    expect(() => buildThousandEyesSearch(badIndex, selection)).toThrow();

    const badIdentity = configuration();
    badIdentity.mappings[0].te_stream_account_id = '5678" OR *';
    expect(() => buildThousandEyesSearch(badIdentity, selection)).toThrow();
  });

  it("keeps the scan limit and completion counters explicit", () => {
    const query = buildThousandEyesSearch(configuration(), selection);
    expect(query).toContain("| head 10001");
    expect(query).toContain(
      "source_scan_capped=if(source_scan_count>10000,1,0)",
    );
    expect(query).toContain("| head 64");
    expect(query).toContain('kind="supplemental_completion"');
  });
});
