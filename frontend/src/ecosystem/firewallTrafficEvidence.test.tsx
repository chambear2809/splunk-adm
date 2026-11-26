import { readFileSync } from "node:fs";
import { describe, expect, it, vi } from "vitest";
import { renderToStaticMarkup } from "react-dom/server";
import {
  FIREWALL_LATE_LOG_SECONDS,
  FORTIGATE_TRAFFIC,
  PAN_TRAFFIC,
  buildFirewallSearch,
  firewallDecisionSummary,
  firewallSearchWindow,
  fortiEventSeconds,
  loadFirewallTrafficEvidence,
  normalizeFirewallEvidence,
  panNaiveSeconds,
  type FirewallSourceContract,
} from "./firewallTrafficEvidence";
import type { EvidenceSelection } from "../data/evidence";
import type {
  EvidenceConfigClient,
  SupplementalSourceConfiguration,
} from "../data/evidenceConfig";
import type { SearchClient } from "../data/searchClient";
import type { Row } from "../rows";
import { FirewallTrafficResultView } from "./FirewallTrafficEvidencePanel";

/** Splunk_TA_paloalto 6.2.0 transforms.conf [extract_traffic] FIELDS. */
const PAN_TA_FIELDS =
  "future_use1,receive_time,serial_number,type,log_subtype,version,generated_time,src_ip,dest_ip,src_translated_ip,dest_translated_ip,rule,src_user,dest_user,app,vsys,src_zone,dest_zone,src_interface,dest_interface,log_forwarding_profile,future_use3,session_id,repeat_count,src_port,dest_port,src_translated_port,dest_translated_port,session_flags,transport,action,bytes,bytes_out,bytes_in,packets,start_time,duration,http_category,future_use4,sequence_number,action_flags,src_location,dest_location,future_use5,packets_out,packets_in,session_end_reason,devicegroup_level1,devicegroup_level2,devicegroup_level3,devicegroup_level4,vsys_name,dvc_name,action_source,src_vm,dest_vm,tunnel_id,tunnel_monitor_tag,tunnel_session_id,tunnel_start_time,tunnel_type".split(
    ",",
  );

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

/** DELIMS extraction plus EVAL-vendor_action = action, as the PAN TA does. */
function panFields(raw: string): Record<string, string> {
  const values = raw.split(",");
  const fields: Record<string, string> = {};
  PAN_TA_FIELDS.forEach((field, index) => {
    if (values[index]) fields[field] = values[index];
  });
  if (fields.action) fields.vendor_action = fields.action;
  return fields;
}

/** The SPL `rex` projection for FortiOS keys, including duplicate detection. */
function fortiFields(raw: string): Record<string, string | string[]> {
  const fields: Record<string, string | string[]> = {};
  for (const key of Object.values(FORTIGATE_TRAFFIC.fields)) {
    const pattern = new RegExp(
      `(?:^|[ ,])${key}="?([^" ,]{1,255})"?(?=[ ,]|$)`,
      "g",
    );
    const matches = [...raw.matchAll(pattern)].map((match) => match[1]);
    if (matches.length)
      fields[key] = matches.length === 1 ? matches[0] : matches;
  }
  return fields;
}

function project(
  contract: FirewallSourceContract,
  envelope: Envelope,
  overrides: Row = {},
  rawOverride?: string,
): Row {
  const raw = rawOverride ?? envelope.event;
  const fields = contract === PAN_TRAFFIC ? panFields(raw) : fortiFields(raw);
  const row: Row = {};
  for (const [column, field] of Object.entries(contract.fields))
    if (fields[field] !== undefined) row[column] = fields[field];
  const parseOk = contract.required.every(
    (column) => row[column] !== undefined,
  );
  return {
    ...row,
    fw_parse_ok: parseOk ? "1" : "0",
    host: envelope.host,
    index: envelope.index,
    sourcetype: envelope.sourcetype,
    event_fingerprint: (envelope.time % 4096).toString(16).padStart(64, "0"),
    event_time_epoch: String(envelope.time),
    _time: String(envelope.time),
    _indextime: String(envelope.time + 2),
    kind: "supplemental_record",
    ...overrides,
  };
}

const BASE = Date.UTC(2026, 10, 26, 15, 0, 0) / 1000;
const selection = (addresses: string[]): EvidenceSelection => ({
  schemaVersion: 1,
  workflow: "endpoint",
  selectionId: "firewall-test",
  trafficContract: 1,
  window: { start: BASE, end: BASE + 300 },
  scope: "prod",
  addresses,
  contexts: [],
  identityBasis: "scoped address",
  configurationFingerprint: "a".repeat(64),
});
const PAN_SELECTION = selection(["10.20.1.15"]);
const FORTI_SELECTION = selection(["10.30.1.25"]);

function config(
  contract: FirewallSourceContract,
  host: string,
  index: string,
  overrides: Partial<SupplementalSourceConfiguration> = {},
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
    ...overrides,
  };
}
const PAN_CONFIG = config(PAN_TRAFFIC, "pa-fw-01", "pan");
const FORTI_CONFIG = config(FORTIGATE_TRAFFIC, "fgt-edge-01", "fortigate");

describe("firewall traffic search contract", () => {
  it("projects only allowlisted TA fields, keeps unparsed rows and never returns _raw", () => {
    const search = buildFirewallSearch(PAN_TRAFFIC, PAN_CONFIG, PAN_SELECTION);
    expect(search).toContain(
      'search index=pan sourcetype IN ("pan:traffic") host IN ("pa-fw-01")',
    );
    expect(search).toContain("fw_action=vendor_action");
    expect(search).toContain("fw_nat_src_ip=src_translated_ip");
    expect(search).toContain("fw_log_time=generated_time");
    expect(search).toContain('cidrmatch("10.20.1.15/32",fw_nat_dest_ip)');
    expect(search).toContain("where fw_parse_ok=0 OR (");
    expect(search).toContain("| head 10001");
    expect(search).toContain("| head 64");
    expect(search).toContain("| fields - _raw");
    const fieldsLine = search
      .split("\n")
      .find((line) => line.startsWith("| fields fw_"))!;
    expect(fieldsLine).not.toMatch(/\b_raw\b|src_user|dest_user/);
    expect(search).toContain('kind="supplemental_completion"');
  });

  it("extracts FortiOS keys itself across both add-on sourcetypes", () => {
    const search = buildFirewallSearch(
      FORTIGATE_TRAFFIC,
      FORTI_CONFIG,
      FORTI_SELECTION,
    );
    expect(search).toContain(
      'sourcetype IN ("fgt_traffic","fortigate_traffic")',
    );
    expect(search).toContain(
      '| rex field=_raw max_match=2 "(?:^|[ ,])action=\\"?(?<fw_action>[^\\" ,]{1,255})\\"?(?=[ ,]|$)"',
    );
    expect(search).toContain("(?<fw_nat_src_port>");
    expect(search).not.toContain("utmaction");
  });

  it("refuses inactive, unqualified, unverified or out-of-scope sources", () => {
    for (const bad of [
      { state: "staged" as const },
      { schemaQualified: false },
      { error: "unavailable" },
      { indexes: ["unconfigured optional"] },
      {
        mappings: [{ ...PAN_CONFIG.mappings[0], mapping_status: "proposed" }],
      },
      { mappings: [{ ...PAN_CONFIG.mappings[0], scope: "lab" }] },
      { mappings: [{ ...PAN_CONFIG.mappings[0], observer_kind: "envoy" }] },
      { authorities: ["PA-FW-01"] },
    ])
      expect(() =>
        buildFirewallSearch(
          PAN_TRAFFIC,
          { ...PAN_CONFIG, ...bad },
          PAN_SELECTION,
        ),
      ).toThrow();
  });

  it("extends dispatch past the selection for late session logs only", () => {
    expect(firewallSearchWindow(PAN_SELECTION)).toEqual({
      start: BASE,
      end: BASE + 300 + FIREWALL_LATE_LOG_SECONDS,
    });
  });
});

describe("Palo Alto Networks pan:traffic normalization", () => {
  const rows = envelopes("pan_traffic.ndjson").map((envelope) =>
    project(PAN_TRAFFIC, envelope),
  );

  it("maps allow, deny and drop faithfully and keeps NAT as translation evidence", () => {
    const result = normalizeFirewallEvidence(
      PAN_TRAFFIC,
      rows,
      PAN_SELECTION,
      PAN_CONFIG,
    );
    expect(result.rejected).toBe(0);
    expect(result.records.map((record) => record.vendorAction)).toEqual([
      "allow",
      "deny",
      "drop",
      "allow",
    ]);
    expect(result.records.map((record) => record.policyDecision)).toEqual([
      "allow",
      "deny",
      "deny",
      "allow",
    ]);
    const [snat, deny, , dnat] = result.records;
    expect(snat.original).toEqual({
      source: { ip: "10.20.1.15", port: 51514 },
      destination: { ip: "198.51.100.20", port: 443 },
    });
    expect(snat.translated).toEqual({
      source: { ip: "203.0.113.5", port: 40123 },
      destination: { ip: "198.51.100.20", port: 443 },
      natFlag: true,
    });
    expect(snat.interval).toEqual({ start: BASE + 50, end: BASE + 65 });
    expect(snat.intervalBasis).toBe("reported_session_start_and_elapsed");
    expect(snat.inferredZoneOffsetSeconds).toBe(0);
    expect(snat.counters).toMatchObject({
      bytes: 5200,
      bytesSent: 1200,
      bytesReceived: 4000,
    });
    expect(snat.sessionEndReason).toBe("tcp-fin");
    expect(deny.translated).toEqual({ natFlag: false });
    expect(deny.rule).toBe("block-rdp");
    expect(dnat.matchedAddressFields).toEqual(["translated_destination"]);
    expect(dnat.original.destination.ip).toBe("203.0.113.80");
    expect(dnat.limitations).toContain(
      "selected_address_matched_translated_field",
    );
    expect(result.records.every((r) => r.attribution === "context_only")).toBe(
      true,
    );
  });

  it("infers a whole quarter-hour zone offset and rejects unrelated _time", () => {
    const local = project(PAN_TRAFFIC, envelopes("pan_traffic.ndjson")[0], {
      event_time_epoch: String(BASE + 65 + 18000),
      _time: String(BASE + 65 + 18000),
    });
    const shifted = normalizeFirewallEvidence(
      PAN_TRAFFIC,
      [local],
      { ...PAN_SELECTION, window: { start: BASE, end: BASE + 86400 } },
      PAN_CONFIG,
    );
    expect(shifted.records[0].inferredZoneOffsetSeconds).toBe(18000);
    expect(shifted.records[0].interval.start).toBe(BASE + 50 + 18000);
    const receipt = project(PAN_TRAFFIC, envelopes("pan_traffic.ndjson")[0], {
      event_time_epoch: String(BASE + 82),
    });
    expect(
      normalizeFirewallEvidence(
        PAN_TRAFFIC,
        [receipt],
        PAN_SELECTION,
        PAN_CONFIG,
      ).rejected,
    ).toBe(1);
  });

  it("rejects unparsed, unmapped, unknown-action, multivalue and out-of-window rows", () => {
    const [first] = envelopes("pan_traffic.ndjson");
    const bad = [
      project(PAN_TRAFFIC, first, { fw_parse_ok: "0" }),
      project(PAN_TRAFFIC, first, { host: "pa-fw-02" }),
      project(PAN_TRAFFIC, first, { fw_action: "alert" }),
      project(PAN_TRAFFIC, first, { fw_src_ip: ["10.20.1.15", "10.20.1.16"] }),
      project(PAN_TRAFFIC, first, { fw_type: "THREAT" }),
      project(PAN_TRAFFIC, first, { sourcetype: "pan:threat" }),
      project(PAN_TRAFFIC, first, { index: "other" }),
      project(PAN_TRAFFIC, first, { fw_src_ip: "10.20.1.99" }),
      project(PAN_TRAFFIC, first, { oversized: "1" }),
    ];
    const result = normalizeFirewallEvidence(
      PAN_TRAFFIC,
      bad,
      PAN_SELECTION,
      PAN_CONFIG,
    );
    expect(result.records).toEqual([]);
    expect(result.rejected).toBe(bad.length);
    const late = normalizeFirewallEvidence(
      PAN_TRAFFIC,
      [first].map((envelope) => project(PAN_TRAFFIC, envelope)),
      { ...PAN_SELECTION, window: { start: BASE + 66, end: BASE + 300 } },
      PAN_CONFIG,
    );
    expect(late.rejected).toBe(1);
  });

  it("parses PAN-OS clock values strictly", () => {
    expect(panNaiveSeconds("2026/11/26 15:00:00")).toBe(BASE);
    expect(() => panNaiveSeconds("2026/02/30 00:00:00")).toThrow();
    expect(() => panNaiveSeconds("2026-11-26 15:00:00")).toThrow();
  });
});

describe("FortiGate traffic normalization", () => {
  const rows = envelopes("fortigate_traffic.ndjson").map((envelope) =>
    project(FORTIGATE_TRAFFIC, envelope),
  );

  it("maps accept/close/deny faithfully and keeps endpoint resets undecided", () => {
    const result = normalizeFirewallEvidence(
      FORTIGATE_TRAFFIC,
      rows,
      FORTI_SELECTION,
      FORTI_CONFIG,
    );
    expect(result.rejected).toBe(0);
    expect(
      result.records.map((record) => [
        record.vendorAction,
        record.policyDecision,
        record.sourcetype,
      ]),
    ).toEqual([
      ["close", "allow", "fortigate_traffic"],
      ["deny", "deny", "fortigate_traffic"],
      ["accept", "allow", "fortigate_traffic"],
      ["client-rst", "not_reported", "fgt_traffic"],
    ]);
    const [snat, deny, dnat] = result.records;
    expect(snat.translated).toEqual({
      source: { ip: "203.0.113.6", port: 40772 },
      disposition: "snat",
    });
    expect(snat.interval).toEqual({ start: BASE + 55, end: BASE + 70 });
    expect(snat.intervalBasis).toBe("log_time_minus_duration");
    expect(snat.protocol).toBe("tcp");
    expect(snat.rule).toBe("1");
    expect(snat.device).toEqual({
      serial: "FGVM02TM00000001",
      name: "fgt-edge-01",
      virtualSystem: "root",
    });
    expect(deny.translated).toEqual({ disposition: "noop" });
    expect(dnat.matchedAddressFields).toEqual(["translated_destination"]);
    expect(dnat.translated?.destination).toEqual({
      ip: "10.30.1.25",
      port: 8443,
    });
    expect(
      firewallDecisionSummary({ ...completeResult(result.records) }),
    ).toEqual({ allow: 2, deny: 1, notReported: 1, lowerBound: false });
  });

  it("requires Splunk _time to agree with FortiOS eventtime and rejects duplicated keys", () => {
    const [first] = envelopes("fortigate_traffic.ndjson");
    const skewed = project(FORTIGATE_TRAFFIC, first, {
      event_time_epoch: String(first.time + 3600),
    });
    const duplicated = project(
      FORTIGATE_TRAFFIC,
      first,
      {},
      first.event + " action=deny",
    );
    const unknown = project(FORTIGATE_TRAFFIC, first, { fw_action: "pass" });
    const sniffer = project(FORTIGATE_TRAFFIC, first, {
      fw_subtype: "sniffer",
    });
    const result = normalizeFirewallEvidence(
      FORTIGATE_TRAFFIC,
      [skewed, duplicated, unknown, sniffer],
      FORTI_SELECTION,
      FORTI_CONFIG,
    );
    expect(result.records).toEqual([]);
    expect(result.rejected).toBe(4);
  });

  it("accepts documented eventtime precisions only", () => {
    expect(fortiEventSeconds("1795705270")).toBe(1795705270);
    expect(fortiEventSeconds("1795705270500000000")).toBe(1795705270.5);
    expect(() => fortiEventSeconds("1795705270500")).toThrow();
  });
});

function completeResult(
  records: ReturnType<typeof normalizeFirewallEvidence>["records"],
) {
  return {
    schemaVersion: 1 as const,
    source: "fortigate_traffic" as const,
    selection: FORTI_SELECTION,
    capturedAt: BASE + 400,
    inspectedWindow: firewallSearchWindow(FORTI_SELECTION),
    configurationFingerprint: "a".repeat(64),
    configurationChanged: false,
    state: "complete" as const,
    schemaQualified: false,
    inputCount: records.length,
    inputCapped: false,
    outputCapped: false,
    rejected: 0,
    oversized: 0,
    records,
    coverage: ["coverage note"],
  };
}

describe("firewall traffic loader and presentation", () => {
  it("runs through the shared bounded loader with the late-log window", async () => {
    const rows = envelopes("pan_traffic.ndjson").map((envelope) =>
      project(PAN_TRAFFIC, envelope),
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
        supplemental: [structuredClone(PAN_CONFIG)],
        maxAgeSeconds: 3600,
      }),
    };
    const result = await loadFirewallTrafficEvidence(
      client,
      "pan_traffic",
      PAN_SELECTION,
      new AbortController().signal,
      configurationClient,
    );
    const [request] = vi.mocked(client.search).mock.calls[0];
    expect(request.optionalSource).toBe("pan_traffic");
    expect(request.earliest).toBe(String(BASE));
    expect(request.latest).toBe(String(BASE + 300 + FIREWALL_LATE_LOG_SECONDS));
    expect(result.state).toBe("complete");
    expect(result.records).toHaveLength(4);
    expect(firewallDecisionSummary(result)).toEqual({
      allow: 2,
      deny: 2,
      notReported: 0,
      lowerBound: false,
    });
  });

  it("renders denies, NAT evidence and unqualified status honestly", () => {
    const records = normalizeFirewallEvidence(
      FORTIGATE_TRAFFIC,
      envelopes("fortigate_traffic.ndjson").map((envelope) =>
        project(FORTIGATE_TRAFFIC, envelope),
      ),
      FORTI_SELECTION,
      FORTI_CONFIG,
    ).records;
    const html = renderToStaticMarkup(
      <FirewallTrafficResultView
        label="FortiGate traffic"
        result={{ ...completeResult(records), rejected: 2 }}
      />,
    );
    expect(html).toContain("producer schema is not qualified");
    expect(html).toContain("Denied or dropped at this firewall");
    expect(html).toContain("not added to the map&#x27;s blocked-flow edges");
    expect(html).toContain("lower bounds");
    expect(html).toContain("203.0.113.6:40772");
    expect(html).toContain("Translation evidence, not endpoint identity");
    expect(html).toContain("Session reset by the client endpoint");
  });
});
