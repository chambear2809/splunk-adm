import {
  resolveTraceEndpoint,
  type PathTrace,
  type TraceHop,
} from "../data/pathTrace";
import type { Graph } from "../graph";
import { emptyTopology, indexTopology } from "../topology";

const MAX_TEXT = 512;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/;
const KINDS = new Set([
  "endpoint",
  "host",
  "virtual_switch",
  "switch",
  "firewall",
  "handoff",
  "gap",
]);
const EVIDENCE = new Set(["observed", "inferred", "gap"]);
type Hop = {
  kind: string;
  label: string;
  device?: string;
  detail?: string;
  in?: string;
  out?: string;
  evidence: string;
};
type Segment = {
  id: string;
  label: string;
  source: string;
  reference: string;
  observed_at: number;
  hops: Hop[];
};
export interface PathEvidence {
  schema_version: 1;
  capture_id: string;
  scope: string;
  src: string;
  dst: string;
  protocol: "tcp" | "udp" | "icmp";
  source_port?: number;
  destination_port?: number;
  start: number;
  end: number;
  collected_at: number;
  producer: string;
  segments: Segment[];
  notes?: string[];
}
const invalid = (s: string): never => {
  throw new Error(`Invalid path evidence: ${s}`);
};
const str = (v: unknown, n: string, optional = false): string | undefined => {
  if (v === undefined && optional) return undefined;
  if (typeof v !== "string" || !v.trim() || v.length > MAX_TEXT) invalid(n);
  return v as string;
};
const num = (v: unknown, n: string): number =>
  typeof v === "number" && Number.isFinite(v) ? v : invalid(n);
const pnum = (v: unknown, n: string): number | undefined => {
  if (v === undefined) return undefined;
  const x = num(v, n);
  if (!Number.isInteger(x) || x < 1 || x > 65535) invalid(n);
  return x;
};

export function parsePathEvidenceRows(
  rows: readonly unknown[],
  request: { src: string; dst: string; scope: string },
  bounds: { start: number; end: number },
): PathEvidence[] {
  if (rows.length > 32)
    throw new Error("Path evidence exceeded its row limit; narrow the window.");
  const captures = new Map<string, PathEvidence>();
  for (const row of rows) {
    if (
      !row ||
      typeof row !== "object" ||
      typeof (row as Record<string, unknown>)._raw !== "string"
    )
      invalid("row must contain _raw JSON");
    let parsed: unknown;
    try {
      parsed = JSON.parse((row as Record<string, unknown>)._raw as string);
    } catch {
      invalid("envelope is not valid JSON");
    }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed))
      invalid("envelope");
    const e = parsed as Record<string, unknown>;
    if (e.schema_version !== 1) invalid("schema_version");
    const capture_id = str(e.capture_id, "capture_id")!,
      scope = str(e.scope, "scope")!,
      src = str(e.src, "src")!,
      dst = str(e.dst, "dst")!;
    if (!ID.test(capture_id)) invalid("capture_id");
    if (scope !== request.scope || src !== request.src || dst !== request.dst)
      invalid("scope or endpoint pair mismatch");
    if (e.protocol !== "tcp" && e.protocol !== "udp" && e.protocol !== "icmp")
      invalid("protocol");
    const source_port = pnum(e.source_port, "source_port"),
      destination_port = pnum(e.destination_port, "destination_port");
    if (
      (e.protocol === "tcp" || e.protocol === "udp") &&
      (source_port === undefined || destination_port === undefined)
    )
      invalid("TCP/UDP ports required");
    const start = num(e.start, "start"),
      end = num(e.end, "end"),
      collected_at = num(e.collected_at, "collected_at");
    if (
      end <= start ||
      end - start > 300 ||
      start < bounds.start ||
      end > bounds.end ||
      collected_at < end
    )
      invalid("capture interval");
    const producer = str(e.producer, "producer")!;
    if (
      !Array.isArray(e.segments) ||
      e.segments.length < 1 ||
      e.segments.length > 32
    )
      invalid("segments");
    const segments = (e.segments as unknown[]).map(
      (raw: unknown, si: number): Segment => {
        if (!raw || typeof raw !== "object") invalid(`segment ${si}`);
        const s = raw as Record<string, unknown>;
        const id = str(s.id, "segment id")!,
          label = str(s.label, "segment label")!,
          source = str(s.source, "segment source")!,
          reference = str(s.reference, "segment reference")!;
        if (!ID.test(id)) invalid("segment id");
        const observed_at = num(s.observed_at, "observed_at");
        if (
          observed_at < start ||
          observed_at > end ||
          !Array.isArray(s.hops) ||
          s.hops.length < 1 ||
          s.hops.length > 16
        )
          invalid("segment hops");
        const hops = (s.hops as unknown[]).map(
          (rawHop: unknown, hi: number): Hop => {
            if (!rawHop || typeof rawHop !== "object")
              invalid(`hop ${si}/${hi}`);
            const h = rawHop as Record<string, unknown>;
            const kind = str(h.kind, "hop kind")!,
              evidence = str(h.evidence, "hop evidence")!,
              device = str(h.device, "hop device", true);
            if (
              !KINDS.has(kind) ||
              !EVIDENCE.has(evidence) ||
              (device !== undefined && !ID.test(device))
            )
              invalid("hop kind/evidence/device");
            return {
              kind,
              label: str(h.label, "hop label")!,
              ...(device ? { device } : {}),
              ...(str(h.detail, "hop detail", true)
                ? { detail: str(h.detail, "hop detail", true) }
                : {}),
              ...(str(h.in, "hop in", true)
                ? { in: str(h.in, "hop in", true) }
                : {}),
              ...(str(h.out, "hop out", true)
                ? { out: str(h.out, "hop out", true) }
                : {}),
              evidence,
            };
          },
        );
        return { id, label, source, reference, observed_at, hops };
      },
    );
    const notes =
      e.notes === undefined
        ? undefined
        : !Array.isArray(e.notes) || e.notes.length > 32
          ? invalid("notes")
          : e.notes.map((n) => str(n, "note")!);
    const envelope = {
      schema_version: 1 as const,
      capture_id,
      scope,
      src,
      dst,
      protocol: e.protocol,
      ...(source_port === undefined ? {} : { source_port }),
      ...(destination_port === undefined ? {} : { destination_port }),
      start,
      end,
      collected_at,
      producer,
      segments,
      ...(notes ? { notes } : {}),
    } as PathEvidence;
    const prior = captures.get(capture_id);
    if (prior && JSON.stringify(prior) !== JSON.stringify(envelope))
      invalid("conflicting capture_id");
    captures.set(capture_id, envelope);
  }
  if (captures.size > 1)
    throw new Error("Multiple path captures returned; narrow the window.");
  return [...captures.values()];
}

export function assemblePathEvidence(
  request: { src: string; dst: string; scope?: string },
  graph: Graph,
  evidence: readonly PathEvidence[],
): PathTrace {
  const topo = indexTopology(emptyTopology()),
    capture = evidence[0],
    hops: TraceHop[] = [];
  for (const [i, segment] of (capture?.segments ?? []).entries()) {
    if (i) {
      const gap = "Ordering between evidence segments is unverified";
      hops.push({
        kind: "gap",
        label: gap,
        evidence: "gap",
        sources: [],
        seen: [],
      });
    }
    for (const h of segment.hops)
      hops.push({
        kind: h.kind as TraceHop["kind"],
        label: h.label,
        ...(h.device ? { device: h.device } : {}),
        detail: `${h.detail ? `${h.detail} ` : ""}(${segment.label}; ${segment.source}; ${segment.reference}; observed ${new Date(segment.observed_at * 1000).toISOString()})`,
        ...(h.in ? { in: h.in } : {}),
        ...(h.out ? { out: h.out } : {}),
        seen: [],
        evidence: h.evidence as TraceHop["evidence"],
        sources: h.evidence === "observed" ? [segment.source] : [],
        support: [segment.reference],
      });
  }
  return {
    status: "partial",
    src: resolveTraceEndpoint(request.src, graph, topo),
    dst: resolveTraceEndpoint(request.dst, graph, topo),
    hops,
    gaps: hops
      .filter((hop) => hop.kind === "gap" || hop.evidence === "gap")
      .map((hop) => hop.label),
    conversations: [],
    drops: [],
    notes: [
      "Bounded source observations and attachments do not establish a complete route.",
      ...(capture
        ? [
            `Capture ${capture.capture_id}: ${capture.protocol.toUpperCase()} ${capture.src}${capture.source_port ? `:${capture.source_port}` : ""} → ${capture.dst}${capture.destination_port ? `:${capture.destination_port}` : ""}; ${new Date(capture.start * 1000).toISOString()}–${new Date(capture.end * 1000).toISOString()}; scope ${capture.scope}.`,
          ]
        : []),
      ...(capture?.notes ?? []),
    ],
  };
}
