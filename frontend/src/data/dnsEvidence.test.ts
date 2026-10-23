import { describe, expect, it, vi } from "vitest";
import stream from "../../../fixtures/dns/stream-transaction.json";
import { buildDnsSearch, loadDnsEvidence } from "./dnsEvidence";
import { inspectDnsRecord } from "./dnsDrilldown";
import { validateDnsResult, type EvidenceSelection } from "./evidence";
import type {
  EvidenceConfigClient,
  EvidenceConfiguration,
} from "./evidenceConfig";
import type { SearchClient } from "./searchClient";
import { dnsEvidenceCSV, dnsEvidenceJSON } from "../dnsExport";

const selection: EvidenceSelection = {
  schemaVersion: 1,
  workflow: "endpoint",
  selectionId: "test",
  trafficContract: 1,
  window: { start: 1791373400, end: 1791373600 },
  scope: "prod",
  addresses: ["192.0.2.10"],
  contexts: [],
  identityBasis: "scoped address",
  configurationFingerprint: "a".repeat(64),
};
const config: EvidenceConfiguration = {
  fingerprint: selection.configurationFingerprint,
  trafficContract: 1,
  summaryIndexes: ["adm_summary"],
  mappings: [],
  identities: [],
  identityAvailable: true,
  maxAgeSeconds: 3600,
  dns: [
    {
      source: "dns_stream",
      state: "active",
      indexes: [stream.index],
      authorities: [stream.host],
      schemaQualified: false,
    },
    {
      source: "dns_hubble",
      state: "not_selected",
      indexes: [],
      authorities: [],
      schemaQualified: false,
    },
  ],
};
const envelope = (rows: Record<string, unknown>[]) => ({
  rows: [
    ...rows.map((r) => ({ ...r, kind: "dns_record" })),
    {
      kind: "dns_completion",
      schema_version: "1",
      input_count: String(rows.length),
      returned_count: String(rows.length),
      input_capped: "0",
      oversized: "0",
    },
  ],
  warnings: [],
  errors: [],
});
const configClient: EvidenceConfigClient = {
  read: async () => structuredClone(config),
};
describe("DNS inspection isolation and explicit exports", () => {
  it("projects Stream 8.1.6 transaction start and response end fields", () => {
    const search = buildDnsSearch(config.dns[0], selection);
    expect(search).toContain('"timestamp",json_extract(_raw,"timestamp")');
    expect(search).toContain('"endtime",json_extract(_raw,"endtime")');
  });

  it("dispatches no jobs when sources are unselected or staged", async () => {
    const client: SearchClient = { search: vi.fn() };
    const cfg = {
      ...config,
      dns: config.dns.map((s) => ({ ...s, state: "staged" as const })),
    };
    const result = await loadDnsEvidence(
      client,
      selection,
      new AbortController().signal,
      { read: async () => cfg },
    );
    expect(client.search).not.toHaveBeenCalled();
    expect(result.records).toEqual([]);
  });
  it("retains successful source observations when another adapter fails", async () => {
    const cfg = {
      ...config,
      dns: config.dns.map((s) => ({
        ...s,
        state: "active" as const,
        indexes: [stream.index],
        authorities: ["sensor-east"],
      })),
    };
    const client: SearchClient = {
      search: vi.fn(async (r) => {
        if (r.search.includes("cilium:hubble")) throw Error("denied");
        return envelope([stream]);
      }),
    };
    const result = await loadDnsEvidence(
      client,
      selection,
      new AbortController().signal,
      { read: async () => cfg },
    );
    expect(result.sources.map((s) => s.state)).toEqual([
      "complete",
      "unavailable",
    ]);
    expect(result.records).toHaveLength(1);
    expect(result.coverage.join(" ")).toMatch(/Caller-visible/);
  });
  it("dispatches staged sources only for explicit scoped diagnostics and suppresses association", async () => {
    const staged = {
      ...config,
      dns: config.dns.map((s) => ({
        ...s,
        state: "staged" as const,
        indexes: [stream.index],
        authorities: [stream.host],
      })),
    };
    const client: SearchClient = {
      search: vi.fn(async () => envelope([stream])),
    };
    const result = await loadDnsEvidence(
      client,
      selection,
      new AbortController().signal,
      { read: async () => staged },
      ["dns_stream"],
    );
    expect(client.search).toHaveBeenCalledTimes(1);
    expect(result.sources[0].intent).toBe("staged");
    expect(result.records.every((r) => r.attribution === "context_only")).toBe(
      true,
    );
  });
  it("invalidates association when configuration changes during execution", async () => {
    let reads = 0;
    const client: SearchClient = { search: async () => envelope([stream]) };
    const result = await loadDnsEvidence(
      client,
      selection,
      new AbortController().signal,
      {
        read: async () => ({
          ...config,
          fingerprint: ++reads === 1 ? config.fingerprint : "b".repeat(64),
        }),
      },
    );
    expect(result.configurationChanged).toBe(true);
    expect(result.records.every((r) => r.attribution === "context_only")).toBe(
      true,
    );
  });
  it("fails incomplete execution closed, while retaining source-specific diagnostics", async () => {
    const client: SearchClient = {
      search: async () => ({
        ...envelope([stream]),
        warnings: ["peer truncated"],
      }),
    };
    const result = await loadDnsEvidence(
      client,
      selection,
      new AbortController().signal,
      configClient,
    );
    expect(result.sources[0].state).toBe("unavailable");
    expect(result.records).toEqual([]);
  });
  it("exports only loaded data with CSV formula protection and metadata even when empty", async () => {
    const client: SearchClient = { search: async () => envelope([stream]) };
    const result = await loadDnsEvidence(
      client,
      selection,
      new AbortController().signal,
      configClient,
    );
    result.records[0].query = "=DANGEROUS()";
    expect(dnsEvidenceCSV(result)).toContain("'=DANGEROUS()");
    expect(JSON.parse(dnsEvidenceJSON(result)).selection).toEqual(selection);
    expect(dnsEvidenceCSV({ ...result, records: [] })).toContain(
      "configurationFingerprint",
    );
  });
  it("reconstructs exact source references and never broadens expired or invalid references", async () => {
    const client: SearchClient = {
      search: vi.fn(async () => envelope([stream])),
    };
    const result = await loadDnsEvidence(
      client,
      selection,
      new AbortController().signal,
      configClient,
    );
    const record = result.records[0];
    const noRecord: SearchClient = { search: vi.fn(async () => envelope([])) };
    await expect(
      inspectDnsRecord(
        noRecord,
        selection,
        record,
        new AbortController().signal,
        configClient,
      ),
    ).resolves.toBeUndefined();
    expect(noRecord.search).toHaveBeenCalledTimes(1);
    await expect(
      inspectDnsRecord(
        noRecord,
        selection,
        { ...record, eventFingerprint: '" | delete' },
        new AbortController().signal,
        configClient,
      ),
    ).rejects.toThrow(/reference/);
    expect(noRecord.search).toHaveBeenCalledTimes(1);
  });
  it("rejects malformed public completeness, scope and observation metadata", async () => {
    const result = await loadDnsEvidence(
      { search: async () => envelope([stream]) },
      selection,
      new AbortController().signal,
      configClient,
    );
    const mutations = [
      (r: typeof result) => {
        r.sources[0].source = "arbitrary" as never;
      },
      (r: typeof result) => {
        r.sources[0].inputCount = -1;
      },
      (r: typeof result) => {
        r.inspectedWindow.start = 0;
      },
      (r: typeof result) => {
        r.records[0].client = "not an IP";
      },
      (r: typeof result) => {
        r.records[0].responseInterval = { start: 20, end: 1 };
      },
      (r: typeof result) => {
        r.records[0].answers = [{ address: "10.0.0.1", type: "AAAA" }];
      },
    ];
    for (const mutate of mutations) {
      const copy = structuredClone(result);
      mutate(copy);
      expect(() => validateDnsResult(copy)).toThrow();
    }
  });
});
