import { readFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import {
  AZURE_VNET_FLOW,
  FLOW_LATE_LOG_SECONDS,
  GCP_PATHS,
  GCP_VPC_FLOW,
  azureTupleSeconds,
  buildCloudFlowSearch,
  cloudFlowSearchWindow,
  loadCloudFlowEvidence,
  normalizeCloudFlowEvidence,
  type CloudFlowContract,
} from "./cloudFlowLogEvidence";
import type { EvidenceSelection } from "../data/evidence";
import type {
  EvidenceConfigClient,
  SupplementalSourceConfiguration,
} from "../data/evidenceConfig";
import type { SearchClient } from "../data/searchClient";
import type { Row } from "../rows";
import { CloudFlowResultView } from "./CloudFlowEvidencePanel";

interface Envelope {
  time: number;
  host: string;
  index: string;
  sourcetype: string;
  event: string;
}
function envelopes(name: string): Envelope[] {
  return readFileSync(
    new URL(`../../../fixtures/raw-ecosystem/${name}`, import.meta.url),
    "utf8",
  )
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line) as Envelope);
}

type Json = Record<string, unknown>;
/** `spath` on a dotted path; scalars become strings as Splunk returns them. */
function path(value: unknown, dotted: string): string | undefined {
  let current = value;
  for (const key of dotted.split(".")) {
    if (!current || typeof current !== "object") return undefined;
    current = (current as Json)[key];
  }
  if (current === undefined || current === null) return undefined;
  return typeof current === "object"
    ? JSON.stringify(current)
    : String(current);
}

function envelopeRow(envelope: Envelope, index: number): Row {
  return {
    host: envelope.host,
    index: envelope.index,
    sourcetype: envelope.sourcetype,
    event_fingerprint: ((Math.round(envelope.time * 1000) % 65536) + index)
      .toString(16)
      .padStart(64, "0"),
    event_time_epoch: String(envelope.time),
    _time: String(envelope.time),
    _indextime: String(Math.floor(envelope.time) + 5),
    kind: "supplemental_record",
  };
}

/** The GCP SPL projection: one shape, then each LogEntry path. */
function gcpRows(envelope: Envelope): Row[] {
  const body = JSON.parse(envelope.event) as Json;
  const shape =
    path(body, "data.jsonPayload.connection.src_ip") && !("jsonPayload" in body)
      ? "pubsub_data"
      : path(body, "jsonPayload.connection.src_ip") && !("data" in body)
        ? "log_entry"
        : undefined;
  const row: Row = { ...envelopeRow(envelope, 0) };
  if (shape) {
    row.gcp_shape = shape;
    const entry = shape === "pubsub_data" ? body.data : body;
    for (const [column, dotted] of GCP_PATHS) {
      const item = path(entry, dotted);
      if (item !== undefined) row[column] = item;
    }
  }
  row.flow_parse_ok =
    shape &&
    /\/logs\/compute\.googleapis\.com%2Fvpc_flows$/.test(
      String(row.gcp_log_name),
    )
      ? "1"
      : "0";
  return [row];
}

/** The Azure SPL projection: one record per event, then flows × groups × tuples. */
function azureRows(envelope: Envelope): Row[] {
  const body = JSON.parse(envelope.event) as Json;
  const records = Array.isArray(body.records)
    ? (body.records as Json[])
    : undefined;
  const shape =
    !records && body.flowRecords
      ? "single_record"
      : records?.length === 1
        ? "records_array"
        : undefined;
  const record =
    shape === "single_record" ? body : shape ? records![0] : undefined;
  const base: Row = {
    ...envelopeRow(envelope, 0),
    ...(shape ? { az_shape: shape } : {}),
    ...(record
      ? {
          az_time: path(record, "time"),
          az_version: path(record, "flowLogVersion"),
          az_category: path(record, "category"),
          az_mac: path(record, "macAddress"),
          az_target: path(record, "targetResourceID"),
        }
      : {}),
  };
  const flows = ((record?.flowRecords as Json | undefined)?.flows ?? [
    {},
  ]) as Json[];
  const rows: Row[] = [];
  let ordinal = 0;
  for (const flow of flows)
    for (const group of (flow.flowGroups ?? [{}]) as Json[])
      for (const tuple of (group.flowTuples ?? ["-"]) as string[]) {
        const parts = tuple.split(",");
        const row: Row = {
          ...base,
          ...envelopeRow(envelope, ordinal++),
          ...(flow.aclID ? { az_acl: String(flow.aclID) } : {}),
          ...(group.rule ? { az_rule: String(group.rule) } : {}),
          az_tuple: tuple,
          az_src_ip: parts[1],
          az_dest_ip: parts[2],
          az_nat_ip: parts[14],
        };
        row.flow_parse_ok =
          row.az_shape &&
          row.az_category === "FlowLogFlowEvent" &&
          row.az_time &&
          row.az_acl &&
          row.az_rule &&
          tuple !== "-"
            ? "1"
            : "0";
        rows.push(row);
      }
  return rows;
}

function scoped(
  contract: CloudFlowContract,
  rows: Row[],
  addresses: string[],
): Row[] {
  return rows.filter(
    (row) =>
      row.flow_parse_ok === "0" ||
      contract.addressColumns.some((column) =>
        addresses.includes(String(row[column])),
      ),
  );
}

const BASE = Date.UTC(2026, 10, 26, 15, 0, 0) / 1000;
const selection = (addresses: string[]): EvidenceSelection => ({
  schemaVersion: 1,
  workflow: "endpoint",
  selectionId: "flow-test",
  trafficContract: 1,
  window: { start: BASE, end: BASE + 300 },
  scope: "prod",
  addresses,
  contexts: [],
  identityBasis: "scoped address",
  configurationFingerprint: "a".repeat(64),
});

function config(
  contract: CloudFlowContract,
  host: string,
  index: string,
): SupplementalSourceConfiguration {
  return {
    source: contract.source,
    state: "active",
    indexes: [index],
    authorities: [host],
    schemaQualified: true,
    staleAfterSeconds: 1800,
    mappings: [
      {
        observer_kind: contract.observerKind,
        observer: host,
        scope: "prod",
        cluster: "",
        mapping_status: "verified",
      },
    ],
  };
}
const GCP_CONFIG = config(GCP_VPC_FLOW, "gcp-ta-hf", "gcp");
const AZURE_CONFIG = config(AZURE_VNET_FLOW, "mscs-hf", "azure");

describe("cloud flow log search contract", () => {
  it("reads GCP LogEntry paths from exactly one event shape", () => {
    const search = buildCloudFlowSearch(
      GCP_VPC_FLOW,
      GCP_CONFIG,
      selection(["10.40.1.15"]),
    );
    expect(search).toContain(
      'search index=gcp sourcetype IN ("google:gcp:compute:vpc_flows") host IN ("gcp-ta-hf")',
    );
    expect(search).toContain(
      'gcp_src_ip=case(gcp_shape="pubsub_data",spath(_raw,"data.jsonPayload.connection.src_ip"),gcp_shape="log_entry",spath(_raw,"jsonPayload.connection.src_ip"))',
    );
    expect(search).toContain('cidrmatch("10.40.1.15/32",gcp_nat_ip)');
    expect(search).toContain("| head 10001");
    expect(search).toContain("| fields - _raw");
  });

  it("expands Azure tuples after dropping _raw and fingerprints each tuple", () => {
    const search = buildCloudFlowSearch(
      AZURE_VNET_FLOW,
      AZURE_CONFIG,
      selection(["10.40.1.15"]),
    );
    const lines = search.split("\n");
    const dropRaw = lines.indexOf("| fields - _raw az_records az_record");
    const expand = lines.indexOf("| mvexpand az_flows");
    expect(dropRaw).toBeGreaterThan(0);
    expect(expand).toBeGreaterThan(dropRaw);
    expect(search).toContain("mvcount(az_records)=1");
    expect(search).toContain(
      "sha256(json_array(index,_bkt,_cd,az_acl,az_rule,az_tuple))",
    );
    expect(search).toContain("oversized=if(atlas_oversized=1,1,0)");
    expect(search).toContain('cidrmatch("10.40.1.15/32",az_nat_ip)');
  });

  it("extends dispatch for exported flow logs", () => {
    expect(cloudFlowSearchWindow(selection(["10.40.1.15"]))).toEqual({
      start: BASE,
      end: BASE + 300 + FLOW_LATE_LOG_SECONDS,
    });
  });
});

describe("GCP VPC Flow Logs normalization", () => {
  const rows = envelopes("gcp_vpc_flow.ndjson").flatMap(gcpRows);

  it("keeps Cloud NAT as translation evidence and a drop as the only stated decision", () => {
    const { records, rejected } = normalizeCloudFlowEvidence(
      GCP_VPC_FLOW,
      scoped(GCP_VPC_FLOW, rows, ["10.40.1.15"]),
      selection(["10.40.1.15"]),
      GCP_CONFIG,
    );
    expect(rejected).toBe(0);
    const [nat, drop] = records;
    expect(nat).toMatchObject({
      recordShape: "pubsub_data",
      vantage: "Reporter SRC",
      protocol: "tcp",
      original: {
        source: { ip: "10.40.1.15", port: 44114 },
        destination: { ip: "198.51.100.20", port: 443 },
      },
      translated: {
        source: { ip: "203.0.113.7", port: 40321 },
        kind: "cloud_nat",
      },
      policyDecision: "not_reported",
      counters: { bytesSent: 5300, packetsSent: 40 },
      intervalBasis: "aggregation_interval",
    });
    expect(nat.limitations).toContain("no_allow_decision_reported");
    expect(nat.context).toContainEqual({
      label: "Source VM",
      value: "atlas-orders-1",
    });
    expect(drop).toMatchObject({
      recordShape: "log_entry",
      vantage: "Reporter DEST",
      policyDecision: "deny",
      actionMeaning: "Dropped (FIREWALL_DENY).",
      counters: { bytesDropped: 120, packetsDropped: 2 },
    });
  });

  it("matches the NAT address as translated, never as the endpoint", () => {
    const { records } = normalizeCloudFlowEvidence(
      GCP_VPC_FLOW,
      scoped(GCP_VPC_FLOW, rows, ["203.0.113.7"]),
      selection(["203.0.113.7"]),
      GCP_CONFIG,
    );
    expect(records).toHaveLength(1);
    expect(records[0].matchedAddressFields).toEqual(["translated_source"]);
    expect(records[0].limitations).toContain(
      "selected_address_matched_translated_field",
    );
  });

  it("rejects NAT from a destination reporter, unknown dispositions and other logs", () => {
    const [nat, drop] = rows;
    for (const bad of [
      { ...drop, gcp_nat_ip: "203.0.113.9" },
      { ...drop, gcp_disposition: "ALLOWED" },
      {
        ...nat,
        gcp_log_name: "projects/p/logs/cloudaudit.googleapis.com%2Factivity",
      },
      { ...nat, gcp_start: "2026-11-26T15:01:00" },
      { ...nat, event_time_epoch: String(BASE + 30) },
    ])
      expect(
        normalizeCloudFlowEvidence(
          GCP_VPC_FLOW,
          [bad],
          selection(["10.40.1.15"]),
          GCP_CONFIG,
        ).rejected,
      ).toBe(1);
  });
});

describe("Azure VNet flow log normalization", () => {
  const rows = envelopes("azure_vnet_flow.ndjson").flatMap(azureRows);

  it("states permit, deny and Private Link SNAT per tuple from single-record events", () => {
    const { records, rejected } = normalizeCloudFlowEvidence(
      AZURE_VNET_FLOW,
      scoped(AZURE_VNET_FLOW, rows, ["10.40.1.15"]),
      selection(["10.40.1.15"]),
      AZURE_CONFIG,
    );
    expect(rejected).toBe(1);
    expect(
      records.map((record) => [record.flowState, record.policyDecision]),
    ).toEqual([
      ["Begin", "allow"],
      ["End", "allow"],
      ["Deny", "deny"],
      ["End", "allow"],
    ]);
    const [, end, deny, pls] = records;
    expect(end).toMatchObject({
      recordShape: "single_record",
      rule: "DefaultRule_AllowInternetOutBound",
      vantage: "Outbound at the captured interface",
      original: {
        source: { ip: "10.40.1.15", port: 23956 },
        destination: { ip: "198.51.100.20", port: 443 },
      },
      counters: {
        packetsSent: 22,
        bytesSent: 2217,
        packetsReceived: 33,
        bytesReceived: 32466,
      },
      interval: { start: BASE + 75, end: BASE + 75 },
    });
    expect(deny.actionMeaning).toBe(
      "Denied by rule BlockHighRiskTCPPortsFromInternet.",
    );
    expect(pls).toMatchObject({
      recordShape: "records_array",
      translated: {
        source: { ip: "10.26.252.5", port: 4890 },
        kind: "private_link_snat",
      },
    });
  });

  it("rejects multi-record events, wrong tuple widths and encryption drops as deny", () => {
    const multi = rows.filter((row) => row.az_shape === undefined);
    expect(multi.length).toBeGreaterThan(0);
    expect(multi.every((row) => row.flow_parse_ok === "0")).toBe(true);
    const [begin] = rows;
    const v5Width = { ...begin, az_version: "5" };
    const dropped = {
      ...begin,
      az_tuple: String(begin.az_tuple).replace(",NX,", ",NX_NOT_ACCEPTED,"),
    };
    const result = normalizeCloudFlowEvidence(
      AZURE_VNET_FLOW,
      [v5Width, dropped],
      selection(["10.40.1.15"]),
      AZURE_CONFIG,
    );
    expect(result.rejected).toBe(1);
    expect(result.records[0]).toMatchObject({
      policyDecision: "deny",
      encryption: "NX_NOT_ACCEPTED",
    });
  });

  it("reads tuple time in seconds or milliseconds only", () => {
    expect(azureTupleSeconds("1708978215")).toBe(1708978215);
    expect(azureTupleSeconds("1663146003599")).toBe(1663146003.599);
    expect(() => azureTupleSeconds("17089782")).toThrow();
  });
});

describe("cloud flow log loader and presentation", () => {
  it("runs through the shared loader and renders translation and decisions honestly", async () => {
    const rows = scoped(
      AZURE_VNET_FLOW,
      envelopes("azure_vnet_flow.ndjson").flatMap(azureRows),
      ["10.40.1.15"],
    );
    const client: SearchClient = {
      search: vi.fn().mockResolvedValue({
        rows: [
          ...rows,
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
      }),
    };
    const configurationClient: EvidenceConfigClient = {
      read: async () => ({
        fingerprint: "a".repeat(64),
        trafficContract: 1,
        summaryIndexes: ["adm_summary"],
        mappings: [],
        identities: [],
        identityAvailable: true,
        dns: [],
        supplemental: [structuredClone(AZURE_CONFIG)],
        maxAgeSeconds: 3600,
      }),
    };
    const result = await loadCloudFlowEvidence(
      client,
      "azure_vnet_flow",
      selection(["10.40.1.15"]),
      new AbortController().signal,
      configurationClient,
    );
    expect(vi.mocked(client.search).mock.calls[0][0].optionalSource).toBe(
      "azure_vnet_flow",
    );
    expect(result.state).toBe("complete");
    expect(result.records).toHaveLength(4);
    const html = renderToStaticMarkup(
      <CloudFlowResultView
        label="Azure VNet flow logs"
        result={{ ...result, schemaQualified: false }}
      />,
    );
    expect(html).toContain("producer schema is not qualified");
    expect(html).toContain("Private Link SNAT");
    expect(html).toContain("Translation evidence, not endpoint identity");
    expect(html).toContain("Denied or dropped at this capture point");
    expect(html).toContain("not added to the map&#x27;s blocked-flow edges");
  });
});
