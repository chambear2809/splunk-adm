import { describe, expect, it } from "vitest";
import {
  normalizeIp,
  validateSelection,
  validateWindow,
  type EvidenceSelection,
} from "./evidence";
import { buildDnsSearch, parseDnsEnvelope } from "./dnsEvidence";

export const selection: EvidenceSelection = {
  schemaVersion: 1,
  workflow: "endpoint",
  selectionId: "scope:ip",
  trafficContract: 1,
  window: { start: 100, end: 200 },
  scope: "lab",
  addresses: ["10.0.0.1"],
  contexts: [],
  identityBasis: "scoped address",
  configurationFingerprint: "a".repeat(64),
};
describe("evidence contracts and completion", () => {
  it("canonicalizes IPv6 and mapped IPs", () => {
    expect(normalizeIp("::ffff:c000:201")).toBe("192.0.2.1");
    expect(normalizeIp("2001:0DB8:0:0::1")).toBe("2001:db8::1");
  });
  it.each(["10.0.0.1\n|delete", "1.2.3.*", "example.com", "fe80::1%en0"])(
    "rejects hostile or nonliteral addresses %s",
    (value) => expect(() => normalizeIp(value)).toThrow(),
  );
  it("requires one bounded verified context and strict contracts", () => {
    expect(validateSelection(selection)).toBe(selection);
    expect(() =>
      validateSelection({ ...selection, scope: "unmapped:x" }),
    ).toThrow();
    expect(() => validateWindow({ start: 1, end: 86402 })).toThrow();
    expect(() =>
      validateSelection({ ...selection, addresses: Array(9).fill("10.0.0.1") }),
    ).toThrow();
  });
  it("compiles literal source predicates without shadowable knowledge objects", () => {
    const search = buildDnsSearch(
      {
        source: "dns_stream",
        state: "active",
        indexes: ["dns"],
        authorities: ["sensor-1"],
        schemaQualified: false,
      },
      selection,
    );
    expect(search).toContain('sourcetype="stream:dns" host IN ("sensor-1")');
    expect(search).not.toMatch(/`|\blookup\b|\bjoin\b|\bmap\b/);
    expect(() =>
      buildDnsSearch(
        {
          source: "dns_hubble",
          state: "active",
          indexes: ["dns OR index=*"],
          authorities: ["c"],
          schemaQualified: false,
        },
        selection,
      ),
    ).toThrow();
    expect(() =>
      buildDnsSearch(
        {
          source: "dns_stream",
          state: "staged",
          indexes: ["dns"],
          authorities: ["s"],
          schemaQualified: false,
        },
        selection,
      ),
    ).toThrow();
  });
  it("projects only bounded allowlisted DNS RR fields for each source", () => {
    const streamSearch = buildDnsSearch(
      {
        source: "dns_stream",
        state: "active",
        indexes: ["dns"],
        authorities: ["sensor-1"],
        schemaQualified: false,
      },
      selection,
    );
    const hubbleSearch = buildDnsSearch(
      {
        source: "dns_hubble",
        state: "active",
        indexes: ["dns"],
        authorities: ["sensor-1"],
        schemaQualified: false,
      },
      selection,
    );
    for (const [search, path, prefix] of [
      [streamSearch, '"answer_records"', "_dns_stream"],
      [hubbleSearch, '"flow.l7.dns.answer_records"', "_dns_hubble"],
    ]) {
      expect(search).toContain(`json_array_to_mv(json_extract(_raw,${path}))`);
      expect(search).toContain(`mvmap(${prefix}_answer_records_mv`);
      expect(search).toContain('"address"');
      expect(search).toContain('"target"');
      expect(search).toContain("substr(tostring(");
      expect(search).toContain("1,1025");
      expect(search).toContain("mv_to_json_array(");
      expect(search).toContain("true())");
      expect(search).toContain("if(oversized=1,null(),json_array_to_mv(");
      expect(search).toContain(`json_extract(${prefix}_answer_records)`);
      expect(search).toContain("upper(tostring(");
      expect(search).toContain('IN ("A","AAAA","1","28")');
      expect(search).not.toContain(
        `coalesce(json_extract(${prefix}_answer_records_mv,"ttl"))`,
      );
    }
    expect(streamSearch).not.toContain('json_extract(_raw,"txt")');
    expect(hubbleSearch).not.toContain('json_extract(_raw,"flow.l7.dns.txt")');
  });
  const meta = (n: number) => ({
    kind: "dns_completion",
    schema_version: "1",
    input_count: String(n),
    returned_count: String(Math.min(n, 64)),
    input_capped: n > 10000 ? "1" : "0",
    oversized: "0",
  });
  it.each([0, 64, 65, 10001])("distinguishes deliberate caps at %i", (n) => {
    const rows = [
      ...Array.from({ length: Math.min(n, 64) }, () => ({
        kind: "dns_record",
      })),
      meta(n),
    ];
    expect(parseDnsEnvelope(rows)).toMatchObject({
      inputCapped: n > 10000,
      outputCapped: n > 64,
      inputCount: n,
    });
  });
  it("rejects missing/duplicate/invalid metadata and count mismatches", () => {
    expect(() => parseDnsEnvelope([])).toThrow();
    expect(() => parseDnsEnvelope([meta(0), meta(0)])).toThrow();
    expect(() => parseDnsEnvelope([meta(2)])).toThrow();
    expect(() => parseDnsEnvelope([{ ...meta(0), input_count: "" }])).toThrow();
  });
});
