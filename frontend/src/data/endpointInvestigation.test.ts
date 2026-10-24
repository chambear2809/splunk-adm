import { describe, expect, it, vi } from "vitest";
import {
  buildEndpointObservationSearch,
  buildEndpointSearch,
  endpointEvidenceSelection,
  endpointUrl,
  parseEndpointUrl,
  runEndpointInvestigation,
  validateEndpointInput,
  validateEndpointResult,
  type EndpointSelection,
} from "./endpointInvestigation";
import type { EvidenceConfigClient } from "./evidenceConfig";
import type { SearchClient } from "./searchClient";

const selection: EndpointSelection = {
  schemaVersion: 1,
  id: "x",
  address: "10.0.0.1",
  scope: "prod",
  start: 100,
  end: 200,
  trafficContract: 2,
  configurationFingerprint: "a".repeat(64),
};
const config = {
  fingerprint: "a".repeat(64),
  trafficContract: 2 as const,
  summaryIndexes: ["adm_summary_v2"],
  mappings: [
    {
      observer_kind: "sensor",
      observer: "s1",
      scope: "prod",
      cluster: "",
      mapping_status: "verified",
    },
  ],
  identities: [],
  identityAvailable: true,
  dns: [],
  maxAgeSeconds: 3600,
};

describe("endpoint investigation contracts", () => {
  it("preserves proxy and locale prefixes when opening an endpoint", () => {
    vi.stubGlobal("location", {
      pathname: "/splunk/en-US/app/splunk_adm/map",
    });
    try {
      expect(endpointUrl(selection)).toBe(
        "/splunk/en-US/app/splunk_adm/endpoints?endpoint_ip=10.0.0.1&endpoint_scope=prod&endpoint_start=100&endpoint_end=200",
      );
    } finally {
      vi.unstubAllGlobals();
    }
  });
  it.each([
    "accepted",
    "accepted_with_warning",
    "excluded",
    "unknown",
    undefined,
  ])(
    "validates V2 observation quality %s while retaining core traffic",
    async (quality) => {
      const completion = {
        row_type: "completion",
        schema_version: 1,
        input_count: 1,
        output_count: 1,
        input_capped: 0,
        output_capped: 0,
        unprotected_count: 0,
      };
      const search: SearchClient = {
        search: vi
          .fn()
          .mockResolvedValueOnce({
            rows: [
              {
                row_type: "conversation",
                scope: "prod",
                adm_root: "10.0.0.1",
                adm_client: "10.0.0.1",
                adm_server: "10.0.0.2",
                adm_peer: "10.0.0.2",
                adm_port: 443,
                adm_transport: "tcp",
                adm_first: 110,
                adm_last: 120,
                adm_records: 1,
                adm_conns: "50000@110@120",
              },
              completion,
            ],
            warnings: [],
            errors: [],
          })
          .mockResolvedValueOnce({
            rows: [
              {
                row_type: "traffic_observation",
                scope: "prod",
                source: "stream_ipfix",
                adm_scope_authority: "router-a",
                source_ip: "10.0.0.1",
                destination_ip: "10.0.0.3",
                source_port: 50001,
                destination_port: 443,
                transport: "tcp",
                adm_first: 110,
                adm_last: 120,
                records: 1,
                metrics_authoritative: 0,
                counter_semantics: "unknown",
                adm_quality_status: quality,
              },
              completion,
            ],
            warnings: [],
            errors: [],
          }),
      };
      const result = await runEndpointInvestigation(
        search,
        { read: vi.fn().mockResolvedValue(config) },
        selection,
        new AbortController().signal,
      );
      expect(result.conversations).toHaveLength(1);
      const accepted =
        quality === "accepted" || quality === "accepted_with_warning";
      expect(result.observationState).toBe(
        accepted ? "complete" : "unavailable",
      );
      expect(result.observations).toHaveLength(accepted ? 1 : 0);
    },
  );
  it("validates deep links containing only endpoint inputs", () => {
    const url = endpointUrl({
      address: "10.0.0.1",
      scope: "prod",
      start: 100,
      end: 200,
    });
    expect(
      parseEndpointUrl(new URL(url, "https://example.test").searchParams),
    ).toEqual({ address: "10.0.0.1", scope: "prod", start: 100, end: 200 });
    expect(url).not.toMatch(/evidence|fingerprint|contract/i);
    expect(() =>
      parseEndpointUrl(
        new URLSearchParams(
          "endpoint_ip=10.0.0.1&endpoint_scope=prod&endpoint_start=100&endpoint_end=200&dns=1",
        ),
      ),
    ).toThrow();
    expect(() =>
      parseEndpointUrl(
        new URLSearchParams(
          "endpoint_ip=10.0.0.1&endpoint_scope=prod&endpoint_start=100&endpoint_start=101&endpoint_end=200",
        ),
      ),
    ).toThrow();
  });
  it("rejects invalid scope and oversized windows", () => {
    expect(() =>
      validateEndpointInput({
        address: "10.0.0.1",
        scope: "unmapped:legacy-default",
        start: 0,
        end: 10,
      }),
    ).toThrow();
    expect(() =>
      validateEndpointInput({
        address: "10.0.0.1",
        scope: "prod",
        start: 0,
        end: 86401,
      }),
    ).toThrow();
  });
  it("uses explicit replay dedup and legacy-default quarantine", () => {
    const query = buildEndpointSearch(
      { ...selection, trafficContract: 1 },
      "index=adm_summary_v2",
    );
    expect(query).toContain("dedup rollup_id keepempty=true");
    expect(query).toContain('"unmapped:legacy-default"');
    expect(query).toContain('row_type="completion"');
    expect(query).toContain(
      "isnull(contract_version) OR tonumber(contract_version)=1",
    );
    expect(query).not.toContain("coalesce(tonumber(contract_version),1)");
    expect(query).toContain("stats max(input_count)");
    expect(query).toContain("eval input_count=coalesce(input_count,0)");
    expect(query).not.toContain("adm_summary_dedup");
    expect(buildEndpointSearch(selection, "index=adm_summary_v2")).toContain(
      "tonumber(contract_version)=2",
    );
    expect(() =>
      buildEndpointSearch(selection, "index=bad OR index=foo; delete"),
    ).toThrow();
  });
  it("keeps V2 observations on their own non-authoritative query", () => {
    const query = buildEndpointObservationSearch(
      selection,
      "index=adm_summary_v2",
    );
    expect(query).toContain('source="adm:traffic_observation"');
    expect(query).toContain("dedup adm_observation_dedup_key");
    expect(query).toContain("metrics_authoritative=0");
    expect(query).toContain(
      'adm_quality_status IN ("accepted","accepted_with_warning")',
    );
    expect(query).toContain("| where ((cidrmatch(");
    expect(query).not.toMatch(/contract_version=2\s+\(cidrmatch/);
    expect(query).not.toContain('source="adm:conversation"');
    expect(() =>
      buildEndpointObservationSearch(
        { ...selection, trafficContract: 1 },
        "index=adm_summary",
      ),
    ).toThrow();
  });
  it("rejects completion envelopes with missing or inconsistent counts", async () => {
    const search: SearchClient = {
      search: vi.fn().mockResolvedValue({
        rows: [
          {
            row_type: "completion",
            schema_version: 1,
            input_count: null,
            output_count: 0,
            input_capped: 0,
            output_capped: 0,
            unprotected_count: 0,
          },
        ],
        warnings: [],
        errors: [],
      }),
    };
    await expect(
      runEndpointInvestigation(
        search,
        { read: vi.fn().mockResolvedValue(config) },
        { address: "10.0.0.1", scope: "prod", start: 100, end: 200 },
        new AbortController().signal,
      ),
    ).rejects.toThrow("completion envelope");
  });
  it("marks retained DNS contexts incomplete after caps", () => {
    const result = {
      schemaVersion: 1 as const,
      selection: { ...selection, address: "2001:db8::1" },
      capturedAt: 200,
      conversations: [
        {
          scope: "prod",
          root: "2001:db8::1",
          client: "2001:db8::1",
          server: "2001:db8::2",
          peer: "2001:db8::2",
          port: 443,
          transport: "tcp",
          directionBasis: "observed",
          source: "s",
          observer: "o",
          first: 110,
          last: 120,
          records: 1,
          conversations: 1,
          contextCapped: false,
        },
      ],
      observations: [],
      observationState: "not_applicable" as const,
      observationCapped: false,
      identityAvailable: false,
      identityHistory: [],
      identityHistoryCapped: false,
      peerCapped: false,
      relationshipCapped: true,
      warnings: [],
    };
    const evidence = endpointEvidenceSelection(result);
    expect(evidence.contexts[0].capped).toBe(true);
  });
  it("rejects result timestamps beyond the supported date range", () => {
    const result = {
      schemaVersion: 1 as const,
      selection: { ...selection, trafficContract: 1 as const },
      capturedAt: 253402300800,
      conversations: [],
      observations: [],
      observationState: "not_applicable" as const,
      observationCapped: false,
      identityAvailable: false,
      identityHistory: [],
      identityHistoryCapped: false,
      peerCapped: false,
      relationshipCapped: false,
      warnings: [],
    };
    expect(() => validateEndpointResult(result)).toThrow(
      "Invalid endpoint investigation result",
    );
  });
  it("normalizes expanded IPv6 tuples returned by the summary index", async () => {
    const search: SearchClient = {
      search: vi.fn().mockResolvedValue({
        rows: [
          {
            row_type: "conversation",
            scope: "prod",
            adm_root: "2001:db8::1",
            adm_client: "2001:0db8:0:0:0:0:0:1",
            adm_server: "2001:0db8:0:0:0:0:0:2",
            adm_peer: "2001:0db8:0:0:0:0:0:2",
            adm_port: 443,
            adm_first: 110,
            adm_last: 120,
            adm_records: 1,
            adm_conns: "",
            adm_sampled: 0,
          },
          {
            row_type: "completion",
            schema_version: 1,
            input_count: 1,
            output_count: 1,
            input_capped: 0,
            output_capped: 0,
            unprotected_count: 0,
          },
        ],
        warnings: [],
        errors: [],
      }),
    };
    const ipv6Config = {
      ...config,
      trafficContract: 1 as const,
      summaryIndexes: ["adm_summary"],
    };
    const result = await runEndpointInvestigation(
      search,
      { read: vi.fn().mockResolvedValue(ipv6Config) },
      { address: "2001:db8::1", scope: "prod", start: 100, end: 200 },
      new AbortController().signal,
    );
    expect(result.conversations[0]).toMatchObject({
      client: "2001:db8::1",
      server: "2001:db8::2",
      peer: "2001:db8::2",
    });
  });
  it("retains supported portless ICMP conversations without inventing port zero", async () => {
    const summary = (transport: string) => ({
      rows: [
        {
          row_type: "conversation",
          scope: "prod",
          adm_root: "10.0.0.1",
          adm_client: "10.0.0.1",
          adm_server: "10.0.0.2",
          adm_peer: "10.0.0.2",
          adm_port: null,
          adm_transport: transport,
          adm_first: 110,
          adm_last: 120,
          adm_records: 1,
          adm_conns: "",
          adm_sampled: 0,
        },
        {
          row_type: "completion",
          schema_version: 1,
          input_count: 1,
          output_count: 1,
          input_capped: 0,
          output_capped: 0,
          unprotected_count: 0,
        },
      ],
      warnings: [],
      errors: [],
    });
    const legacyConfig = {
      ...config,
      trafficContract: 1 as const,
      summaryIndexes: ["adm_summary"],
    };
    const icmp = await runEndpointInvestigation(
      { search: vi.fn().mockResolvedValue(summary("icmp")) },
      { read: vi.fn().mockResolvedValue(legacyConfig) },
      { address: "10.0.0.1", scope: "prod", start: 100, end: 200 },
      new AbortController().signal,
    );
    expect(icmp.conversations[0]).toMatchObject({
      peer: "10.0.0.2",
      transport: "icmp",
    });
    expect(icmp.conversations[0].port).toBeUndefined();
    await expect(
      runEndpointInvestigation(
        { search: vi.fn().mockResolvedValue(summary("tcp")) },
        { read: vi.fn().mockResolvedValue(legacyConfig) },
        { address: "10.0.0.1", scope: "prod", start: 100, end: 200 },
        new AbortController().signal,
      ),
    ).rejects.toThrow("invalid conversation port");
  });
  describe("conversation interval validation", () => {
    const legacyConfig = {
      ...config,
      trafficContract: 1 as const,
      summaryIndexes: ["adm_summary"],
    };
    const bucket = (first: unknown, last: unknown) => ({
      rows: [
        {
          row_type: "conversation",
          scope: "prod",
          adm_root: "10.0.0.1",
          adm_client: "10.0.0.1",
          adm_server: "10.0.0.2",
          adm_peer: "10.0.0.2",
          adm_port: 443,
          adm_transport: "tcp",
          adm_first: first,
          adm_last: last,
          adm_records: 1,
          adm_conns: "",
          adm_sampled: 0,
        },
        {
          row_type: "completion",
          schema_version: 1,
          input_count: 1,
          output_count: 1,
          input_capped: 0,
          output_capped: 0,
          unprotected_count: 0,
        },
      ],
      warnings: [],
      errors: [],
    });
    const run = (first: unknown, last: unknown) =>
      runEndpointInvestigation(
        { search: vi.fn().mockResolvedValue(bucket(first, last)) },
        { read: vi.fn().mockResolvedValue(legacyConfig) },
        { address: "10.0.0.1", scope: "prod", start: 100, end: 200 },
        new AbortController().signal,
      );
    it("returns buckets that straddle an unaligned window edge", async () => {
      const after = await run(250, 290);
      expect(after.conversations[0]).toMatchObject({ first: 250, last: 290 });
      const before = await run(10, 20);
      expect(before.conversations[0]).toMatchObject({ first: 10, last: 20 });
    });
    it.each([
      ["non-finite first", "x", 120],
      ["non-finite last", 110, "x"],
      ["negative first", -1, 120],
      ["last before first", 120, 110],
    ])("still rejects %s", async (_name, first, last) => {
      await expect(run(first, last)).rejects.toThrow(
        "invalid conversation interval",
      );
    });
  });
  it("requires exactly one valid completion row and rechecks configuration", async () => {
    const search: SearchClient = {
      search: vi
        .fn()
        .mockResolvedValueOnce({
          rows: [
            {
              row_type: "conversation",
              scope: "prod",
              adm_root: "10.0.0.1",
              adm_client: "10.0.0.1",
              adm_server: "10.0.0.2",
              adm_peer: "10.0.0.2",
              adm_port: 443,
              adm_transport: "tcp",
              adm_first: 110,
              adm_last: 120,
              adm_records: 2,
              adm_conns: "1000@110@120",
              adm_sampled: 0,
            },
            {
              row_type: "completion",
              schema_version: 1,
              input_count: 1,
              output_count: 1,
              input_capped: 0,
              output_capped: 0,
              unprotected_count: 0,
            },
          ],
          warnings: [],
          errors: [],
        })
        .mockResolvedValueOnce({
          rows: [
            {
              row_type: "traffic_observation",
              adm_quality_status: "accepted",
              scope: "prod",
              source: "stream_ipfix",
              adm_scope_authority: "router-a",
              source_ip: "10.0.0.1",
              destination_ip: "10.0.0.2",
              source_port: 50000,
              destination_port: 443,
              transport: "tcp",
              adm_first: 110,
              adm_last: 120,
              records: 1,
              counter_semantics: "unknown",
              metrics_authoritative: 0,
            },
            {
              row_type: "completion",
              schema_version: 1,
              input_count: 1,
              output_count: 1,
              input_capped: 0,
              output_capped: 0,
              unprotected_count: 0,
            },
          ],
          warnings: [],
          errors: [],
        }),
    };
    const configClient: EvidenceConfigClient = {
      read: vi.fn().mockResolvedValue(config),
    };
    const result = await runEndpointInvestigation(
      search,
      configClient,
      { address: "10.0.0.1", scope: "prod", start: 100, end: 200 },
      new AbortController().signal,
    );
    expect(result.conversations[0].peer).toBe("10.0.0.2");
    expect(result.observations).toHaveLength(1);
    expect(result.observations[0].metricsAuthoritative).toBe(false);
    expect(search.search).toHaveBeenCalledTimes(2);
    expect(
      (search.search as ReturnType<typeof vi.fn>).mock.calls[0][0].budget,
    ).toEqual({ serverSeconds: 30, clientMilliseconds: 35000 });
  });
  it("retains core conversations when the optional V2 observation query fails", async () => {
    const search: SearchClient = {
      search: vi
        .fn()
        .mockResolvedValueOnce({
          rows: [
            {
              row_type: "conversation",
              scope: "prod",
              adm_root: "10.0.0.1",
              adm_client: "10.0.0.1",
              adm_server: "10.0.0.2",
              adm_peer: "10.0.0.2",
              adm_port: 443,
              adm_transport: "tcp",
              adm_first: 110,
              adm_last: 120,
              adm_records: 1,
              adm_conns: "",
              adm_sampled: 0,
            },
            {
              row_type: "completion",
              schema_version: 1,
              input_count: 1,
              output_count: 1,
              input_capped: 0,
              output_capped: 0,
              unprotected_count: 0,
            },
          ],
          warnings: [],
          errors: [],
        })
        .mockRejectedValueOnce(new Error("observation index unavailable")),
    };
    const configClient: EvidenceConfigClient = {
      read: vi.fn().mockResolvedValue(config),
    };
    const result = await runEndpointInvestigation(
      search,
      configClient,
      { address: "10.0.0.1", scope: "prod", start: 100, end: 200 },
      new AbortController().signal,
    );
    expect(result.conversations).toHaveLength(1);
    expect(result.observationState).toBe("unavailable");
    expect(result.observations).toEqual([]);
    expect(result.warnings.join(" ")).toContain(
      "observation index unavailable",
    );
  });
  it("rejects publishing results after the configuration fingerprint changes", async () => {
    const legacy = {
      ...config,
      trafficContract: 1 as const,
      summaryIndexes: ["adm_summary"],
    };
    const changed = { ...legacy, fingerprint: "b".repeat(64) };
    const search: SearchClient = {
      search: vi.fn().mockResolvedValue({
        rows: [
          {
            row_type: "completion",
            schema_version: 1,
            input_count: 0,
            output_count: 0,
            input_capped: 0,
            output_capped: 0,
            unprotected_count: 0,
          },
        ],
        warnings: [],
        errors: [],
      }),
    };
    const configClient: EvidenceConfigClient = {
      read: vi
        .fn()
        .mockResolvedValueOnce(legacy)
        .mockResolvedValueOnce(changed),
    };
    await expect(
      runEndpointInvestigation(
        search,
        configClient,
        { address: "10.0.0.1", scope: "prod", start: 100, end: 200 },
        new AbortController().signal,
      ),
    ).rejects.toThrow("configuration changed");
  });
});
