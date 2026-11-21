import { describe, expect, it } from "vitest";
import { hopIcon } from "./traceModel";
import { demoGraph } from "../data/demoClient";
import { hopEvidenceText } from "../data/pathTrace";
import {
  assemblePathEvidence,
  parsePathEvidenceRows,
  type PathEvidence,
} from "./pathEvidence";

const request = { src: "10.0.0.1", dst: "10.0.0.2", scope: "prod" };
const bounds = { start: 100, end: 200 };
const envelope = (overrides: Partial<PathEvidence> = {}): PathEvidence => ({
  schema_version: 1,
  capture_id: "cap-1",
  scope: "prod",
  src: request.src,
  dst: request.dst,
  protocol: "tcp",
  source_port: 40000,
  destination_port: 443,
  start: 120,
  end: 140,
  collected_at: 141,
  producer: "admin-source",
  segments: [
    {
      id: "seg-1",
      label: "FTD forward",
      source: "ftd",
      reference: "atlas:path:1",
      observed_at: 130,
      hops: [
        {
          kind: "firewall",
          label: "FTD-A",
          device: "ftd-a",
          in: "inside",
          out: "outside",
          evidence: "observed",
        },
      ],
    },
  ],
  ...overrides,
});
const row = (value: unknown) => ({ _raw: JSON.stringify(value) });
const parse = (value: unknown, req = request, window = bounds) =>
  parsePathEvidenceRows([row(value)], req, window);

describe("path evidence contract", () => {
  it("labels an endpoint with an observed capture and provenance as observed", () => {
    const e = envelope();
    e.segments[0].source = "ESXi captures and PostgreSQL primary readback";
    e.segments[0].hops = [
      {
        kind: "endpoint",
        label: "PostgreSQL committed the Invoice Save",
        evidence: "observed",
      },
    ];
    const [hop] = assemblePathEvidence(
      request,
      demoGraph("aci"),
      parse(e),
    ).hops;
    expect(hop.support).toEqual(["atlas:path:1"]);
    expect(hopEvidenceText(hop)).toBe(
      "Observed by ESXi captures and PostgreSQL primary readback",
    );
    expect(hopEvidenceText({ ...hop, evidence: "inferred" })).toBe(
      "Inferred; supported by atlas:path:1",
    );
    expect(hopEvidenceText({ ...hop, sources: [], support: undefined })).toBe(
      "Endpoint",
    );
  });
  it("does not classify a leaf by a spine receipt filename", () => {
    expect(
      hopIcon({
        kind: "switch",
        label: "border-leaf4",
        detail: "leaf attachment; atlas-spine-repeat.json",
        evidence: "inferred",
        sources: [],
        seen: [],
      }).kind,
    ).toBe("Leaf");
  });
  it("counts producer-declared gaps within a segment", () => {
    const e = envelope();
    e.segments[0].hops.push({
      kind: "gap",
      label: "Missing translation",
      evidence: "gap",
    });
    expect(
      assemblePathEvidence(request, demoGraph("aci"), parse(e)).gaps,
    ).toEqual(["Missing translation"]);
  });
  it("rejects malformed rows and overflow", () => {
    expect(() => parsePathEvidenceRows([{}], request, bounds)).toThrow(/_raw/);
    expect(() =>
      parsePathEvidenceRows([{ _raw: "{" }], request, bounds),
    ).toThrow(/JSON/);
    expect(() =>
      parsePathEvidenceRows(Array(33).fill(row(envelope())), request, bounds),
    ).toThrow(/row limit/);
  });
  it("accepts forward and reverse ordered pairs", () => {
    expect(parse(envelope())[0].src).toBe("10.0.0.1");
    const reverse = { ...envelope(), src: request.dst, dst: request.src };
    expect(
      parse(reverse, { ...request, src: request.dst, dst: request.src })[0],
    ).toMatchObject({ src: request.dst, dst: request.src });
  });

  it("rejects scope or ordered pair mismatches", () => {
    expect(() => parse({ ...envelope(), scope: "dev" })).toThrow(/mismatch/);
    expect(() =>
      parse({ ...envelope(), src: request.dst, dst: request.src }),
    ).toThrow(/mismatch/);
  });

  it("rejects intervals outside bounds and over 300 seconds", () => {
    expect(() => parse({ ...envelope(), start: 99 })).toThrow(/interval/);
    expect(() => parse({ ...envelope(), end: 201 })).toThrow(/interval/);
    expect(() =>
      parse({ ...envelope(), start: 100, end: 401 }, request, {
        start: 0,
        end: 500,
      }),
    ).toThrow(/interval/);
    expect(() => parse({ ...envelope(), collected_at: 139 })).toThrow(
      /interval/,
    );
  });

  it("enforces protocol and port rules", () => {
    expect(() => parse({ ...envelope(), protocol: "sctp" as never })).toThrow(
      /protocol/,
    );
    expect(() => parse({ ...envelope(), source_port: 0 })).toThrow(
      /source_port/,
    );
    expect(() => parse({ ...envelope(), destination_port: 65536 })).toThrow(
      /destination_port/,
    );
    expect(() => parse({ ...envelope(), source_port: undefined })).toThrow(
      /required/,
    );
    expect(
      parse({
        ...envelope(),
        protocol: "icmp",
        source_port: undefined,
        destination_port: undefined,
      }),
    ).toHaveLength(1);
  });

  it("enforces observed_at and segment/hop caps", () => {
    expect(() =>
      parse({
        ...envelope(),
        segments: [{ ...envelope().segments[0], observed_at: 99 }],
      }),
    ).toThrow(/segment hops/);
    const manySegments = Array.from({ length: 33 }, (_, i) => ({
      ...envelope().segments[0],
      id: `s-${i}`,
    }));
    expect(() => parse({ ...envelope(), segments: manySegments })).toThrow(
      /segments/,
    );
    const manyHops = Array.from(
      { length: 17 },
      () => envelope().segments[0].hops[0],
    );
    expect(() =>
      parse({
        ...envelope(),
        segments: [{ ...envelope().segments[0], hops: manyHops }],
      }),
    ).toThrow(/segment hops/);
  });

  it("deduplicates identical captures and rejects collisions or multiple captures", () => {
    expect(
      parsePathEvidenceRows(
        [row(envelope()), row(envelope())],
        request,
        bounds,
      ),
    ).toHaveLength(1);
    expect(() =>
      parsePathEvidenceRows(
        [row(envelope()), row({ ...envelope(), producer: "other" })],
        request,
        bounds,
      ),
    ).toThrow(/conflicting/);
    expect(() =>
      parsePathEvidenceRows(
        [row(envelope()), row({ ...envelope(), capture_id: "cap-2" })],
        request,
        bounds,
      ),
    ).toThrow(/narrow/);
  });

  it("preserves inferred hops, segment provenance, explicit gaps, and partial status", () => {
    const second = {
      id: "seg-2",
      label: "Hubble reply",
      source: "hubble",
      reference: "atlas:path:2",
      observed_at: 135,
      hops: [
        {
          kind: "host",
          label: "k3s-node-2",
          evidence: "inferred",
          detail: "node attachment",
        },
      ],
    };
    const evidence = parse({
      ...envelope(),
      segments: [envelope().segments[0], second],
    });
    const trace = assemblePathEvidence(request, demoGraph("aci"), evidence);
    expect(trace.status).toBe("partial");
    expect(trace.gaps).toContain(
      "Ordering between evidence segments is unverified",
    );
    expect(trace.hops.map((h) => h.label)).toContain("k3s-node-2");
    expect(trace.hops.find((h) => h.label === "FTD-A")).toMatchObject({
      sources: ["ftd"],
      support: ["atlas:path:1"],
      in: "inside",
      out: "outside",
      seen: [],
    });
    expect(trace.notes[0]).toMatch(/do not establish a complete route/);
  });
});
