import { describe, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import {
  RECEIPT_LOOKBACK_SECONDS,
  buildEcosystemReceiptSearch,
  checkEcosystemReceipt,
  parseEcosystemReceipt,
} from "./ecosystemReceipt";
import type {
  EvidenceConfigClient,
  EvidenceConfiguration,
  SupplementalSourceConfiguration,
} from "../data/evidenceConfig";
import type { SearchClient } from "../data/searchClient";
import { EcosystemReceiptPanel, receiptText } from "./EcosystemReceiptPanel";
import { EndpointEvidencePanels } from "../EndpointEvidencePanels";

const pan: SupplementalSourceConfiguration = {
  source: "pan_traffic",
  state: "active",
  indexes: ["pan"],
  authorities: ["pa-fw-01"],
  schemaQualified: false,
  staleAfterSeconds: 1800,
  mappings: [
    {
      observer_kind: "pan_firewall",
      observer: "pa-fw-01",
      scope: "prod",
      cluster: "",
      mapping_status: "verified",
    },
  ],
};

const configuration = (
  supplemental: SupplementalSourceConfiguration[],
): EvidenceConfiguration => ({
  fingerprint: "a".repeat(64),
  trafficContract: 1,
  summaryIndexes: ["adm_summary"],
  mappings: [],
  identities: [],
  identityAvailable: true,
  dns: [],
  supplemental,
  maxAgeSeconds: 3600,
});

const receiptRow = (overrides: Record<string, unknown> = {}) => ({
  kind: "ecosystem_receipt",
  schema_version: "1",
  records: "10",
  valid_records: "10",
  mapped_records: "10",
  hosts: "1",
  latest_event: "1000",
  latest_indexed: "1002",
  max_ingest_lag: "2",
  input_capped: "0",
  probe_lookback_seconds: String(RECEIPT_LOOKBACK_SECONDS),
  ...overrides,
});

describe("ecosystem receipt probe", () => {
  it("bounds the indexed-receipt window before projecting fields", () => {
    const search = buildEcosystemReceiptSearch("pan_traffic", pan);
    const lines = search.split("\n");
    expect(lines[0]).toBe(
      'search index=pan sourcetype IN ("pan:traffic") earliest=0 latest=+10y _index_earliest=-604800s _index_latest=now',
    );
    expect(lines[1]).toBe("| head 10001");
    expect(lines[2]).toContain("fw_action=vendor_action");
    expect(search).toContain('in(host,"pa-fw-01")');
    expect(search).toContain('in(fw_action,"allow","deny","drop"');
    expect(search).not.toContain("_raw\n");
  });

  it("uses the same FortiOS extraction and both add-on sourcetypes", () => {
    const search = buildEcosystemReceiptSearch("fortigate_traffic", {
      ...pan,
      source: "fortigate_traffic",
      authorities: ["fgt-edge-01"],
      mappings: [
        {
          ...pan.mappings[0],
          observer_kind: "fortigate_firewall",
          observer: "fgt-edge-01",
        },
      ],
    });
    expect(search).toContain(
      'sourcetype IN ("fgt_traffic","fortigate_traffic")',
    );
    expect(search).toContain("(?<fw_log_time>");
    expect(search).toContain('"client-rst"');
  });

  it("probes load balancer and flow log sources with their own extraction, never expanding Azure tuples", () => {
    const sourceConfig = (
      source: SupplementalSourceConfiguration["source"],
      kind: string,
    ): SupplementalSourceConfiguration => ({
      ...pan,
      source,
      indexes: ["edge"],
      authorities: ["edge-01"],
      mappings: [
        { ...pan.mappings[0], observer_kind: kind, observer: "edge-01" },
      ],
    });
    const f5 = buildEcosystemReceiptSearch(
      "f5_ltm_http",
      sourceConfig("f5_ltm_http", "f5_bigip"),
    );
    expect(f5).toContain('"f5:bigip:ltm:http:irule"');
    expect(f5).toContain("atlas_valid=if(isnotnull(f5_irule) AND f5_quotes=8");
    const aws = buildEcosystemReceiptSearch(
      "aws_elb_access",
      sourceConfig("aws_elb_access", "aws_elb"),
    );
    expect(aws).toContain("(?<nlb_verify>");
    const azure = buildEcosystemReceiptSearch(
      "azure_vnet_flow",
      sourceConfig("azure_vnet_flow", "azure_vnet_flow"),
    );
    expect(azure).toContain('in(az_version,"4","5")');
    expect(azure).not.toContain("mvexpand");
    const gcp = buildEcosystemReceiptSearch(
      "gcp_vpc_flow",
      sourceConfig("gcp_vpc_flow", "gcp_vpc_flow"),
    );
    expect(gcp).toContain("atlas_valid=if(flow_parse_ok=1,1,0)");
    expect(() =>
      buildEcosystemReceiptSearch(
        "gcp_vpc_flow",
        sourceConfig("gcp_vpc_flow", "aws_elb"),
      ),
    ).toThrow();
  });

  it("refuses unmapped or unconfigured sources", () => {
    expect(() =>
      buildEcosystemReceiptSearch("pan_traffic", {
        ...pan,
        indexes: ["unconfigured_optional"],
      }),
    ).toThrow();
    expect(() =>
      buildEcosystemReceiptSearch("pan_traffic", { ...pan, mappings: [] }),
    ).toThrow();
    expect(() =>
      buildEcosystemReceiptSearch("pan_traffic", { ...pan, error: "x" }),
    ).toThrow();
  });

  it("classifies receipt without treating silence as an outage", () => {
    expect(parseEcosystemReceipt([receiptRow()], 1800, 1100).status).toBe(
      "receipt_observed",
    );
    expect(parseEcosystemReceipt([receiptRow()], 1800, 9000).status).toBe(
      "stale",
    );
    expect(
      parseEcosystemReceipt([receiptRow({ valid_records: "7" })], 1800, 1100)
        .status,
    ).toBe("quality_gaps");
    expect(
      parseEcosystemReceipt([receiptRow({ mapped_records: "3" })], 1800, 1100)
        .status,
    ).toBe("unmapped_hosts");
    const empty = parseEcosystemReceipt(
      [
        receiptRow({
          records: "0",
          valid_records: "0",
          mapped_records: "0",
          hosts: "0",
          latest_event: "",
          latest_indexed: "",
          max_ingest_lag: "",
        }),
      ],
      1800,
      1100,
    );
    expect(empty.status).toBe("no_visible_records");
    expect(
      receiptText({
        ...empty,
        source: "pan_traffic",
        state: "complete",
        schemaQualified: false,
        checkedAt: 1100,
      }),
    ).toContain("not proof of a collection outage");
  });

  it("rejects inconsistent or duplicated receipt rows", () => {
    for (const rows of [
      [],
      [receiptRow(), receiptRow()],
      [receiptRow({ valid_records: "11" })],
      [receiptRow({ records: "10001", input_capped: "0" })],
      [receiptRow({ probe_lookback_seconds: "86400" })],
      [receiptRow({ latest_indexed: "" })],
    ])
      expect(() => parseEcosystemReceipt(rows, 1800, 1100)).toThrow();
  });

  it("runs only for selected sources, with the caller's search client", async () => {
    const search = vi.fn().mockResolvedValue({
      rows: [receiptRow()],
      warnings: [],
      errors: [],
    });
    const client: SearchClient = { search };
    const read: EvidenceConfigClient["read"] = async () =>
      configuration([
        pan,
        { ...pan, source: "fortigate_traffic", state: "not_selected" },
      ]);
    const signal = new AbortController().signal;
    const notSelected = await checkEcosystemReceipt(
      client,
      "fortigate_traffic",
      signal,
      { read },
      () => 1100,
    );
    expect(notSelected.state).toBe("not_selected");
    expect(search).not.toHaveBeenCalled();
    const observed = await checkEcosystemReceipt(
      client,
      "pan_traffic",
      signal,
      { read },
      () => 1100,
    );
    expect(observed).toMatchObject({
      state: "complete",
      status: "receipt_observed",
      schemaQualified: false,
      records: 10,
    });
    expect(search.mock.calls[0][0]).toMatchObject({
      optionalSource: "pan_traffic",
      maxRows: 2,
    });
    const unreadable = await checkEcosystemReceipt(
      client,
      "pan_traffic",
      signal,
      {
        read: async () => {
          throw new Error("denied");
        },
      },
    );
    expect(unreadable.state).toBe("unavailable");
  });
});

describe("ecosystem evidence presentation", () => {
  it("renders an explicit, unqualified receipt check that dispatches nothing on render", () => {
    const search = vi.fn();
    const html = renderToStaticMarkup(
      <EcosystemReceiptPanel client={{ search }} />,
    );
    expect(html).toContain("Check ecosystem receipt");
    expect(html).toContain("unqualified until validated");
    expect(search).not.toHaveBeenCalled();
  });

  it("adds every ecosystem panel to the scoped endpoint investigation as a lazily loaded asset", () => {
    const search = vi.fn();
    const html = renderToStaticMarkup(
      <EndpointEvidencePanels
        selection={{
          schemaVersion: 1,
          workflow: "endpoint",
          selectionId: "endpoint-1",
          trafficContract: 2,
          window: { start: 100, end: 200 },
          scope: "prod",
          addresses: ["10.0.0.1"],
          contexts: [],
          identityBasis: "Scoped endpoint investigation",
          configurationFingerprint: "a".repeat(64),
        }}
        client={{ search }}
      />,
    );
    for (const label of [
      "Palo Alto Networks traffic",
      "FortiGate traffic",
      "F5 BIG-IP LTM request legs",
      "AWS ALB/NLB access legs",
      "Azure VNet flow logs",
      "GCP VPC flow logs",
    ])
      expect(html).toContain(label);
    expect(html).toContain("Loading optional ecosystem evidence");
    expect(search).not.toHaveBeenCalled();
  });
});
