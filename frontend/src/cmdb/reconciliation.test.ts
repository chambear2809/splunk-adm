import { describe, expect, it } from "vitest";
import type { Row } from "../rows";
import type { SupplementalSourceConfiguration } from "../data/evidenceConfig";
import {
  CMDB_LIMITS,
  ENDPOINT_STATUS_LABEL,
  RELATIONSHIP_STATUS_LABEL,
  assetAuthorities,
  buildCmdbAssetSearch,
  buildCmdbRelationshipSearch,
  buildObservedRelationshipSearch,
  endpointFindingsCsv,
  parseCmdbAssets,
  parseCmdbRelationships,
  parseObservedRelationships,
  reconcileCmdb,
  relationshipFindingsCsv,
  type Parsed,
  type CmdbAssetRecord,
  type CmdbRelationshipRecord,
  type ObservedRelationship,
} from "./reconciliation";

const scope = "east";
const window = { start: 1_700_000_000, end: 1_700_086_400 };
const config = (
  overrides: Partial<SupplementalSourceConfiguration> = {},
): SupplementalSourceConfiguration => ({
  source: "asset_history",
  state: "active",
  indexes: ["adm_assets"],
  authorities: ["cmdb-east"],
  schemaQualified: true,
  staleAfterSeconds: 86400,
  mappings: [
    {
      observer_kind: "asset_authority",
      observer: "cmdb-east",
      scope,
      cluster: "",
      mapping_status: "verified",
    },
  ],
  ...overrides,
});

const rel = (overrides: Row = {}): Row => ({
  kind: "relationship",
  scope,
  client_ip: "10.0.0.1",
  server_ip: "10.0.0.2",
  server_port: "443",
  transport: "tcp",
  first_seen: String(window.start + 10),
  last_seen: String(window.start + 20),
  blocked: "0",
  client_service: JSON.stringify(["web", "prod", "c1", "shop"]),
  client_service_state: "bound",
  client_kind: "pod",
  client_identity_state: "resolved",
  client_name: "web-1",
  server_service_state: "not_workload",
  server_kind: "vm",
  server_endpoint_kind: "vm",
  server_identity_state: "resolved",
  server_name: "db-01",
  ...overrides,
});
const completion = (n: number, overrides: Row = {}): Row => ({
  kind: "completion",
  input_count: String(n),
  returned_count: String(n),
  capped: "0",
  identity_invalid: "0",
  ...overrides,
});
const asset = (ip: string, overrides: Row = {}): Row => ({
  kind: "asset_record",
  asset_authority: "cmdb-east",
  scope,
  ip,
  record_id: `r-${ip}`,
  revision: "1",
  revision_conflict: "0",
  asset_id: `a-${ip}`,
  validity_basis: "source_interval",
  valid_from: String(window.start - 100),
  snapshot_at: String(window.start + 50),
  ...overrides,
});
const assetCompletion = (n: number, overrides: Row = {}): Row => ({
  kind: "completion",
  input_count: String(n),
  returned_count: String(n),
  capped: "0",
  source_scan_count: String(n),
  source_scan_invalid_count: "0",
  source_scan_capped: "0",
  ...overrides,
});
const cmdbRel = (overrides: Row = {}): Row => ({
  kind: "cmdb_relationship",
  authority: "cmdb-east",
  relationship_id: "rel-1",
  scope,
  client_ip: "10.0.0.1",
  server_ip: "10.0.0.2",
  server_port: "443",
  transport: "tcp",
  relationship_type: "Depends on::Used by",
  ...overrides,
});
const relCompletion = (n: number, overrides: Row = {}): Row => ({
  kind: "completion",
  qualified: "1",
  input_count: String(n),
  source_scan_count: String(n),
  source_scan_capped: "0",
  ...overrides,
});
const notConfigured = parseCmdbRelationships(
  [relCompletion(0, { qualified: "0" })],
  scope,
);

describe("search builders", () => {
  it("bounds the observed search and rejects injected scopes", () => {
    const spl = buildObservedRelationshipSearch(scope);
    expect(spl).toContain('`adm_cmdb_observed_relationships("east")`');
    expect(spl).toContain(`kind_rank<=${CMDB_LIMITS.relationships}`);
    expect(spl).toContain('kind="completion"');
    for (const bad of ['east" OR 1=1', "east`x`", "unmapped:x", "", "a b"])
      expect(() => buildObservedRelationshipSearch(bad)).toThrow();
  });

  it("reads only verified, configured authorities from qualified asset history", () => {
    expect(assetAuthorities(config(), scope)).toEqual(["cmdb-east"]);
    expect(() =>
      assetAuthorities(config({ schemaQualified: false }), scope),
    ).toThrow();
    expect(() =>
      assetAuthorities(config({ state: "staged" }), scope),
    ).toThrow();
    expect(() => assetAuthorities(config(), "west")).toThrow();
    expect(() =>
      assetAuthorities(config({ authorities: ["cmdb-east", "other"] }), scope),
    ).toThrow();
    const spl = buildCmdbAssetSearch(config(), scope, window);
    expect(spl).toContain(
      'search (index=adm_assets) sourcetype="adm:asset_history"',
    );
    expect(spl).toContain(`head ${CMDB_LIMITS.assetScan + 1}`);
    expect(spl).toContain('asset_authority="cmdb-east"');
    expect(spl).toContain(`valid_from_number<${window.end}`);
    expect(() =>
      buildCmdbAssetSearch(config({ indexes: ["bad index"] }), scope, window),
    ).toThrow();
    expect(() =>
      buildCmdbAssetSearch(config(), scope, { start: 5, end: 5 }),
    ).toThrow();
  });

  it("keeps the CMDB relationship source behind its qualification macro", () => {
    const spl = buildCmdbRelationshipSearch(scope);
    expect(spl.startsWith("| `adm_cmdb_relationship_rows`")).toBe(true);
    expect(spl).toContain(
      "qualified=`adm_cmdb_relationships_schema_qualified`",
    );
    expect(spl).toContain(`head ${CMDB_LIMITS.cmdbRelationships + 1}`);
  });
});

describe("parsers fail closed", () => {
  it("marks observed traffic incomplete without a completion row or when capped", () => {
    expect(parseObservedRelationships([rel()], scope).completeness.state).toBe(
      "incomplete",
    );
    const capped = parseObservedRelationships(
      [rel(), completion(9000, { returned_count: "1", capped: "1" })],
      scope,
    );
    expect(capped.completeness.state).toBe("incomplete");
    expect(capped.completeness.reasons.join(" ")).toContain("5,000");
  });

  it("rejects malformed rows and treats multivalue service bindings as ambiguous", () => {
    const parsed = parseObservedRelationships(
      [
        rel(),
        rel({ client_ip: "not-an-ip" }),
        rel({ scope: "west" }),
        rel({
          client_ip: "10.0.0.9",
          client_service: [
            JSON.stringify(["a", "prod", "c1", "shop"]),
            JSON.stringify(["b", "prod", "c1", "shop"]),
          ],
          client_service_state: "bound",
        }),
        completion(4),
      ],
      scope,
    );
    expect(parsed.records).toHaveLength(2);
    expect(parsed.completeness.rejected).toBe(2);
    expect(parsed.completeness.state).toBe("incomplete");
    expect(parsed.records[0].client.serviceState).toBe("bound");
    expect(parsed.records[0].client.service?.service).toBe("web");
    expect(parsed.records[1].client.serviceState).toBe("ambiguous");
    expect(parsed.records[1].client.service).toBeUndefined();
  });

  it("reports identity invalidation from the completion row", () => {
    const parsed = parseObservedRelationships(
      [rel(), completion(1, { identity_invalid: "1" })],
      scope,
    );
    expect(parsed.identityIncomplete).toBe(true);
    expect(parsed.completeness.state).toBe("complete");
  });

  it("rejects assets from unconfigured authorities and reports scan caps", () => {
    const parsed = parseCmdbAssets(
      [
        asset("10.0.0.2"),
        asset("10.0.0.3", { asset_authority: "other" }),
        asset("10.0.0.4", { valid_to: String(window.start - 200) }),
        assetCompletion(3, { source_scan_capped: "1" }),
      ],
      scope,
      ["cmdb-east"],
    );
    expect(parsed.records.map((r) => r.ip)).toEqual(["10.0.0.2"]);
    expect(parsed.completeness.rejected).toBe(2);
    expect(parsed.completeness.reasons.join(" ")).toContain("scan cap");
  });

  it("reports an unqualified relationship lookup as not configured", () => {
    expect(notConfigured.completeness.state).toBe("not_configured");
    expect(parseCmdbRelationships([cmdbRel()], scope).completeness.state).toBe(
      "incomplete",
    );
    const dup = parseCmdbRelationships(
      [cmdbRel(), cmdbRel(), relCompletion(2)],
      scope,
    );
    expect(dup.records).toHaveLength(1);
    expect(dup.completeness.state).toBe("incomplete");
  });
});

const observed = (rows: Row[]) => parseObservedRelationships(rows, scope);
const assets = (rows: Row[]): Parsed<CmdbAssetRecord> =>
  parseCmdbAssets(rows, scope, ["cmdb-east"]);
const relationships = (rows: Row[]): Parsed<CmdbRelationshipRecord> =>
  parseCmdbRelationships(rows, scope);
const run = (
  o: Parsed<ObservedRelationship>,
  a: Parsed<CmdbAssetRecord>,
  r: Parsed<CmdbRelationshipRecord> = notConfigured,
) => reconcileCmdb({ scope, window, observed: o, assets: a, relationships: r });

describe("reconcileCmdb", () => {
  it("classifies matched, not-in-CMDB, external and conflicting endpoints", () => {
    const result = run(
      observed([
        rel(),
        rel({
          client_ip: "10.0.0.7",
          server_ip: "8.8.8.8",
          server_kind: [],
          server_endpoint_kind: "external",
          server_identity_state: "none",
          server_name: [],
        }),
        rel({ client_ip: "10.0.0.8" }),
        completion(3),
      ]),
      assets([
        asset("10.0.0.2"),
        asset("10.0.0.1"),
        asset("10.0.0.8"),
        asset("10.0.0.8", { record_id: "other", asset_id: "different" }),
        assetCompletion(4),
      ]),
    );
    const status = Object.fromEntries(
      result.endpoints.map((e) => [e.ip, e.status]),
    );
    expect(status).toEqual({
      "10.0.0.1": "matched",
      "10.0.0.2": "matched",
      "10.0.0.7": "not_in_cmdb",
      "10.0.0.8": "ambiguous",
      "8.8.8.8": "external",
    });
    expect(result.endpointCounts.not_in_cmdb).toBe(1);
  });

  it("never claims not-in-CMDB when asset history is incomplete or not configured", () => {
    const o = observed([rel(), completion(1)]);
    const incomplete = run(o, assets([asset("10.0.0.1")]));
    expect(incomplete.endpoints.every((e) => e.status !== "not_in_cmdb")).toBe(
      true,
    );
    expect(incomplete.endpointCounts.matched).toBe(1);
    const missing: Parsed<CmdbAssetRecord> = {
      records: [],
      completeness: {
        state: "not_configured",
        reasons: [],
        inputCount: 0,
        returnedCount: 0,
        rejected: 0,
      },
    };
    const none = run(
      o,
      missing,
      relationships([cmdbRel({ client_ip: "10.0.0.5" }), relCompletion(1)]),
    );
    expect(none.endpoints.find((e) => e.ip === "10.0.0.1")!.status).toBe(
      "coverage_unknown",
    );
  });

  it("reports unseen CMDB relationships as not observed in window, never removed", () => {
    const result = run(
      observed([rel(), completion(1)]),
      assets([assetCompletion(0)]),
      relationships([
        cmdbRel(),
        cmdbRel({ relationship_id: "rel-2", server_ip: "10.0.0.3" }),
        cmdbRel({
          relationship_id: "rel-3",
          client_ip: "10.9.0.1",
          server_ip: "10.9.0.2",
        }),
        relCompletion(3),
      ]),
    );
    const byServer = Object.fromEntries(
      result.relationships.map((r) => [r.serverIp, r]),
    );
    expect(byServer["10.0.0.2"].status).toBe("matched");
    expect(byServer["10.0.0.3"].status).toBe("not_observed_in_window");
    expect(byServer["10.0.0.3"].endpointCoverage).toBe("client_only");
    expect(byServer["10.9.0.2"].endpointCoverage).toBe("neither");
    expect(byServer["10.9.0.2"].note).toContain("outside collection coverage");
    const findings = result.relationships
      .map((r) => `${r.status} ${r.note}`)
      .join(" ");
    expect(findings).not.toMatch(/removed|absent/i);
    expect(relationshipFindingsCsv(result.relationships)).toContain(
      "Not observed in window",
    );
    expect(Object.values(RELATIONSHIP_STATUS_LABEL).join(" ")).not.toMatch(
      /removed|absent/i,
    );
  });

  it("downgrades unseen relationships to coverage unknown when traffic is incomplete", () => {
    const result = run(
      observed([rel()]),
      assets([assetCompletion(0)]),
      relationships([cmdbRel({ server_ip: "10.0.0.3" }), relCompletion(1)]),
    );
    const unseen = result.relationships.find((r) => r.serverIp === "10.0.0.3")!;
    expect(unseen.status).toBe("coverage_unknown");
    expect(result.relationshipCounts.not_observed_in_window).toBe(0);
  });

  it("lists observed relationships missing from a complete CMDB lookup", () => {
    const result = run(
      observed([rel(), rel({ server_port: "5432" }), completion(2)]),
      assets([assetCompletion(0)]),
      relationships([cmdbRel(), relCompletion(1)]),
    );
    expect(result.relationshipCounts).toEqual({
      matched: 1,
      not_observed_in_window: 0,
      observed_not_in_cmdb: 1,
      coverage_unknown: 0,
    });
    expect(
      run(
        observed([rel(), completion(1)]),
        assets([assetCompletion(0)]),
      ).caveats.join(" "),
    ).toContain("relationship lookup is configured and qualified");
  });

  it("exports findings as CSV with human labels", () => {
    const result = run(
      observed([rel(), completion(1)]),
      assets([asset("10.0.0.1"), assetCompletion(1)]),
    );
    const csv = endpointFindingsCsv(result.endpoints).split("\r\n");
    expect(csv[0]).toContain("status,scope,ip,basis,asset_ids");
    expect(csv[1].startsWith(ENDPOINT_STATUS_LABEL.matched)).toBe(true);
    expect(csv).toHaveLength(3);
  });
});
