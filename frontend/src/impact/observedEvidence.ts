import type { SearchClient, RunResult } from "../data/searchClient";
import {
  parsePathEvidenceRows,
  type PathEvidence,
} from "../trace/pathEvidence";

import { isImpactScope } from "./url";

const MAX_WINDOW = 24 * 60 * 60;
const IP = /^(?:\d{1,3}\.){3}\d{1,3}$/;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/;

interface TraceHopReference {
  device: string;
  segment: string;
  hop: string;
}

interface CaptureReference {
  src: string;
  dst: string;
  source_port: number;
  destination_port: number;
  capture: string;
}

export interface ObservedImpactDevice {
  id: string;
  name: string;
  role: "spine" | "leaf" | "border";
  domain: number;
}

export interface ObservedImpactTrial {
  id: string;
  journey: string;
  app: string;
  actor: "browser" | "operator";
  outcome: string;
  src: string;
  dst: string;
  source_port: number;
  destination_port: number;
  start: number;
  end: number;
  captures: { forward: string; reverse?: string };
  /** Devices proven by native exports and checked trace references. */
  observations: { forward: string[]; reverse: string[] };
  /** Exporter identities declared by the qualified source. */
  exports: { forward: string[]; reverse: string[] };
  traceHops: Record<"forward" | "reverse", TraceHopReference[]>;
  linkedCaptures: (CaptureReference & TraceHopReference)[];
}

export interface ObservedImpactCohort {
  schema_version: 1 | 2;
  scope: string;
  start: number;
  end: number;
  devices: ObservedImpactDevice[];
  trials: ObservedImpactTrial[];
}

export interface ObservedImpactNativeRecord {
  trial: string;
  direction: "forward" | "reverse";
  device: string;
  scope: string;
  src: string;
  dst: string;
  source_port: number;
  destination_port: number;
  start: number;
  end: number;
  domain: number;
  reference?: string;
}

export interface ObservedImpactEvidence extends ObservedImpactCohort {
  receipts: Map<string, PathEvidence[]>;
  native: ObservedImpactNativeRecord[];
}

type Options = {
  client: SearchClient;
  earliest: string;
  latest?: string;
  scope?: string;
  timezone?: string;
  signal: AbortSignal;
};

const text = (v: unknown, label: string): string => {
  if (typeof v !== "string" || !v || v.length > 512)
    throw new Error(`Invalid ${label}.`);
  return v;
};
const integer = (
  v: unknown,
  label: string,
  min = 0,
  max = 253402300799,
): number => {
  const n =
    typeof v === "number" || (typeof v === "string" && /^\d+$/.test(v))
      ? Number(v)
      : NaN;
  if (!Number.isSafeInteger(n) || n < min || n > max)
    throw new Error(`Invalid ${label}.`);
  return n;
};
const port = (v: unknown, label: string) => integer(v, label, 1, 65535);
const ipv4 = (v: unknown, label: string): string => {
  const value = text(v, label);
  if (
    !IP.test(value) ||
    value
      .split(".")
      .some((part) => Number(part) > 255 || String(Number(part)) !== part)
  )
    throw new Error(`Invalid ${label}.`);
  return value;
};
const json = (row: unknown, label: string): Record<string, unknown> => {
  if (!row || typeof row !== "object" || Array.isArray(row))
    throw new Error(`Invalid ${label} row.`);
  const raw = (row as Record<string, unknown>)._raw;
  if (typeof raw !== "string") throw new Error(`Invalid ${label} row.`);
  try {
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed))
      throw new Error();
    return parsed as Record<string, unknown>;
  } catch {
    throw new Error(`Invalid ${label} JSON.`);
  }
};

function windowBounds(
  earliest: string,
  latest?: string,
): { start: number; end: number } {
  const start = integer(earliest, "earliest");
  const end = integer(latest ?? "", "latest");
  if (end <= start || end - start > MAX_WINDOW)
    throw new Error(
      "Impact evidence requires an absolute window of at most 24 hours.",
    );
  return { start, end };
}

function search(
  client: SearchClient,
  searchText: string,
  options: Options,
  maxRows: number,
): Promise<RunResult> {
  return client
    .search({
      search: searchText,
      earliest: options.earliest,
      latest: options.latest,
      timezone: options.timezone,
      maxRows,
      overflow: "error",
      allowEmpty: true,
      signal: options.signal,
    })
    .then((result) => {
      if (result.errors.length)
        throw new Error(
          `Impact evidence search was incomplete: ${result.errors[0]}`,
        );
      if (result.warnings.length)
        throw new Error(
          `Impact evidence search returned warnings: ${result.warnings[0]}`,
        );
      if (result.truncated)
        throw new Error("Impact evidence search was truncated.");
      return result;
    });
}

function scopedSearch(
  client: SearchClient,
  searchText: string,
  options: Options,
  start: number,
  end: number,
  maxRows: number,
) {
  return search(
    client,
    searchText,
    { ...options, earliest: String(start), latest: String(end) },
    maxRows,
  );
}

function parseCohort(
  row: unknown,
  scope: string,
  bounds: { start: number; end: number },
): ObservedImpactCohort {
  const e = json(row, "journey cohort");
  const version = e.schema_version === 2 ? 2 : e.schema_version === 1 ? 1 : 0;
  if (
    !version ||
    e.scope !== scope ||
    integer(e.start, "cohort start") !== bounds.start ||
    integer(e.end, "cohort end") !== bounds.end
  )
    throw new Error("Journey cohort scope or window mismatch.");
  if (
    !Array.isArray(e.devices) ||
    !Array.isArray(e.trials) ||
    !e.devices.length ||
    !e.trials.length ||
    e.devices.length > 8 ||
    e.trials.length > 8
  )
    throw new Error("Journey cohort is empty or exceeds its limit.");
  const devices = e.devices.map<ObservedImpactDevice>((raw, i) => {
    if (!raw || typeof raw !== "object" || Array.isArray(raw))
      throw new Error(`Invalid cohort device ${i}.`);
    const d = raw as Record<string, unknown>;
    const id = text(d.id, `device ${i} id`),
      name = text(d.name, `device ${i} name`);
    ipv4(id, `device ${i} id`);
    const { role } = d;
    if (
      role !== "spine" &&
      (version === 1 || (role !== "leaf" && role !== "border"))
    )
      throw new Error(`Invalid cohort device ${i}.`);
    return {
      id,
      name,
      role,
      domain: integer(d.domain, `device ${i} domain`, 0, 0xffffffff),
    };
  });
  const ids = new Set(devices.map((d) => d.id));
  if (
    ids.size !== devices.length ||
    new Set(devices.map((device) => device.name.trim().toLowerCase())).size !==
      devices.length
  )
    throw new Error("Journey cohort has duplicate devices.");
  const trialIds = new Set<string>();
  const trials: ObservedImpactTrial[] = e.trials.map((raw, i) => {
    if (!raw || typeof raw !== "object" || Array.isArray(raw))
      throw new Error(`Invalid cohort trial ${i}.`);
    const t = raw as Record<string, unknown>;
    const id = text(t.id, `trial ${i} id`);
    if (!ID.test(id) || trialIds.has(id))
      throw new Error(`Invalid or duplicate cohort trial ${i}.`);
    trialIds.add(id);
    const src = text(t.src, `trial ${i} source`),
      dst = text(t.dst, `trial ${i} destination`);
    ipv4(src, `trial ${i} source`);
    ipv4(dst, `trial ${i} destination`);
    if (src === dst || (t.actor !== "browser" && t.actor !== "operator"))
      throw new Error(`Invalid cohort trial ${i}.`);
    const actor: "browser" | "operator" = t.actor;
    const start = integer(t.start, `trial ${i} start`),
      end = integer(t.end, `trial ${i} end`);
    if (start < bounds.start || end > bounds.end || end <= start)
      throw new Error(`Trial ${id} is outside the cohort window.`);
    const c = t.captures;
    const s = version === 1 ? t.spines : undefined;
    const ex = version === 2 ? t.exports : undefined;
    if (
      !c ||
      typeof c !== "object" ||
      Array.isArray(c) ||
      (version === 1 && (!s || typeof s !== "object" || Array.isArray(s))) ||
      (version === 2 && (!ex || typeof ex !== "object" || Array.isArray(ex)))
    )
      throw new Error(`Invalid trial ${id} evidence.`);
    const captures = c as Record<string, unknown>;
    const sourceSets = (version === 1 ? s : ex) as Record<string, unknown>;
    const forward = text(captures.forward, `trial ${id} forward capture`);
    const reverse =
      captures.reverse === undefined
        ? undefined
        : text(captures.reverse, `trial ${id} reverse capture`);
    const deviceSet = (value: unknown, label: string, allowEmpty = false) => {
      if (
        !Array.isArray(value) ||
        (!allowEmpty && !value.length) ||
        value.some((x) => typeof x !== "string" || !ids.has(x))
      )
        throw new Error(`Invalid ${label} device set.`);
      const out = [...new Set(value as string[])];
      if (out.length !== value.length)
        throw new Error(`Duplicate ${label} device.`);
      return out;
    };
    const forwardExports = deviceSet(
      sourceSets.forward,
      `trial ${id} forward`,
      version === 2,
    );
    const reverseExports =
      sourceSets.reverse === undefined
        ? []
        : deviceSet(sourceSets.reverse, `trial ${id} reverse`, version === 2);
    if (version === 1 && !forwardExports.length && !reverseExports.length)
      throw new Error(`Trial ${id} has no checked spine.`);
    if (reverseExports.length && !reverse)
      throw new Error(`Trial ${id} is missing its reverse receipt.`);
    if (version === 1 && reverse && !reverseExports.length)
      throw new Error(
        `Trial ${id} has a reverse receipt without reverse spine evidence.`,
      );
    const traceHops = version === 2 ? t.trace_hops : undefined;
    if (
      traceHops !== undefined &&
      (!traceHops || typeof traceHops !== "object" || Array.isArray(traceHops))
    )
      throw new Error(`Invalid Trace hops for trial ${id}.`);
    const resolvedHopDevices = (
      direction: "forward" | "reverse",
    ): TraceHopReference[] => {
      const raw = (traceHops as Record<string, unknown> | undefined)?.[
        direction
      ];
      if (raw === undefined) return [];
      if (!Array.isArray(raw) || raw.length > 16)
        throw new Error(`Invalid ${direction} trace hops for trial ${id}.`);
      const seen = new Set<string>();
      return raw.map((item, index) => {
        if (!item || typeof item !== "object" || Array.isArray(item))
          throw new Error(`Invalid ${direction} trace hop ${index}.`);
        const hop = item as Record<string, unknown>;
        const device = ipv4(hop.device, `trace hop ${id} device`);
        if (!ids.has(device))
          throw new Error(`Trace hop ${id} names an undeclared device.`);
        const segment = text(hop.segment, `trace hop ${id} segment`);
        const label = text(hop.hop, `trace hop ${id} label`);
        const key = JSON.stringify([segment, label]);
        if (seen.has(key))
          throw new Error(`Duplicate trace hop ${id}/${index}.`);
        seen.add(key);
        if (!captures[direction] && direction === "reverse")
          throw new Error(`Trace hop ${id} requires a reverse receipt.`);
        return { device, segment, hop: label };
      });
    };
    const forwardHops = resolvedHopDevices("forward");
    const reverseHops = resolvedHopDevices("reverse");
    const linkedCaptures: ObservedImpactTrial["linkedCaptures"] = (() => {
      if (version === 1 || t.linked_captures === undefined) return [];
      if (!Array.isArray(t.linked_captures) || t.linked_captures.length > 4)
        throw new Error(`Invalid linked captures for trial ${id}.`);
      const seen = new Set<string>();
      return t.linked_captures.map((raw, index) => {
        if (!raw || typeof raw !== "object" || Array.isArray(raw))
          throw new Error(`Invalid linked capture ${id}/${index}.`);
        const l = raw as Record<string, unknown>;
        const device = ipv4(l.device, `linked capture ${id} device`);
        if (!ids.has(device))
          throw new Error(`Linked capture ${id} names an undeclared device.`);
        const capture = text(l.capture, `linked capture ${id} receipt`);
        if (seen.has(capture) || capture === forward || capture === reverse)
          throw new Error(`Duplicate linked capture ${id}/${index}.`);
        seen.add(capture);
        const linkedSrc = ipv4(l.src, `linked capture ${id} source`);
        const linkedDst = ipv4(l.dst, `linked capture ${id} destination`);
        if (linkedSrc === linkedDst)
          throw new Error(`Linked capture ${id} requires distinct endpoints.`);
        return {
          src: linkedSrc,
          dst: linkedDst,
          source_port: port(l.source_port, `linked capture ${id} source port`),
          destination_port: port(
            l.destination_port,
            `linked capture ${id} destination port`,
          ),
          capture,
          device,
          segment: text(l.segment, `linked capture ${id} segment`),
          hop: text(l.hop, `linked capture ${id} hop`),
        };
      });
    })();
    const observations = {
      forward: [
        ...new Set([
          ...forwardExports,
          ...forwardHops.map((hop) => hop.device),
        ]),
      ],
      reverse: [
        ...new Set([
          ...reverseExports,
          ...reverseHops.map((hop) => hop.device),
        ]),
      ],
    };
    if (!observations.forward.length && !observations.reverse.length)
      throw new Error(`Trial ${id} has no checked device observation.`);
    return {
      id,
      journey: text(t.journey, `trial ${id} journey`),
      app: text(t.app, `trial ${id} app`),
      actor,
      outcome: text(t.outcome, `trial ${id} outcome`),
      src,
      dst,
      source_port: port(t.source_port, `trial ${id} source port`),
      destination_port: port(
        t.destination_port,
        `trial ${id} destination port`,
      ),
      start,
      end,
      captures: reverse ? { forward, reverse } : { forward },
      observations,
      exports: { forward: forwardExports, reverse: reverseExports },
      traceHops: { forward: forwardHops, reverse: reverseHops },
      linkedCaptures,
    };
  });
  devices.sort((a, b) => a.id.localeCompare(b.id));
  trials.sort((a, b) => a.start - b.start || a.id.localeCompare(b.id));
  return {
    schema_version: version,
    scope,
    start: bounds.start,
    end: bounds.end,
    devices,
    trials,
  };
}

function parseNative(
  rows: readonly unknown[],
  trial: ObservedImpactTrial,
  scope: string,
  expected: { forward: string[]; reverse: string[] },
  devices: ObservedImpactDevice[],
): ObservedImpactNativeRecord[] {
  if (rows.length > 32)
    throw new Error(
      `Native tuple results exceeded their limit for trial ${trial.id}.`,
    );
  const out = rows
    .map((row) => {
      if (!row || typeof row !== "object" || Array.isArray(row))
        throw new Error("Invalid native tuple row.");
      const e = row as Record<string, unknown>;
      const { direction } = e;
      if (direction !== "forward" && direction !== "reverse")
        throw new Error(`Invalid native direction for trial ${trial.id}.`);
      const device = ipv4(e.observer_device, "native exporter");
      const deviceInfo = devices.find((d) => d.id === device);
      const start = Number(e.first_seen),
        end = Number(e.last_seen);
      if (!Number.isFinite(start) || !Number.isFinite(end))
        throw new Error("Invalid native interval.");
      const record: ObservedImpactNativeRecord = {
        trial: trial.id,
        direction,
        device,
        scope: e.scope === undefined ? scope : text(e.scope, "native scope"),
        src: text(e.src, "native source"),
        dst: text(e.dst, "native destination"),
        source_port: port(e.src_port, "native source port"),
        destination_port: port(e.dest_port, "native destination port"),
        start,
        end,
        domain: integer(
          e.observation_domain_id,
          "native observation domain",
          0,
          0xffffffff,
        ),
        reference: text(e.reference, "native reference"),
      };
      const expectedSpines = expected[direction];
      if (
        (deviceInfo && record.domain !== deviceInfo.domain) ||
        e.row_type !== "observation" ||
        e.flow_source !== "netflow" ||
        e.protocol !== "tcp" ||
        e.profile_status !== "tuple-candidate" ||
        e.source_profile !== "nexus_nxos_netflow" ||
        record.scope !== scope ||
        record.start < trial.start ||
        record.end > trial.end ||
        record.end < record.start ||
        record.src !== (direction === "forward" ? trial.src : trial.dst) ||
        record.dst !== (direction === "forward" ? trial.dst : trial.src) ||
        record.source_port !==
          (direction === "forward"
            ? trial.source_port
            : trial.destination_port) ||
        record.destination_port !==
          (direction === "forward" ? trial.destination_port : trial.source_port)
      )
        throw new Error(`Native tuple mismatch for trial ${trial.id}.`);
      if (deviceInfo && !expectedSpines.includes(device))
        throw new Error(`Unexpected cohort device for trial ${trial.id}.`);
      return record;
    })
    .filter((r) => expected[r.direction].includes(r.device));
  for (const direction of ["forward", "reverse"] as const) {
    const wanted = expected[direction];
    if (
      wanted.length &&
      !wanted.every((spine) =>
        out.some((r) => r.direction === direction && r.device === spine),
      )
    )
      throw new Error(
        `Native tuple coverage is incomplete for trial ${trial.id}.`,
      );
  }
  return out;
}

async function verifyReceipt(
  options: Options,
  scope: string,
  trial: ObservedImpactTrial,
  ref: CaptureReference,
  hops: readonly TraceHopReference[],
): Promise<PathEvidence[]> {
  const { src, dst, capture } = ref;
  const result = await scopedSearch(
    options.client,
    `| \`adm_path_evidence(${src},${dst},${scope})\``,
    options,
    trial.start,
    trial.end,
    64,
  );
  const matching = parsePathEvidenceRows(
    result.rows,
    { src, dst, scope },
    trial,
  ).filter(
    (entry) =>
      entry.capture_id === capture &&
      entry.protocol === "tcp" &&
      entry.source_port === ref.source_port &&
      entry.destination_port === ref.destination_port,
  );
  if (matching.length !== 1)
    throw new Error(`Receipt ${capture} is missing or ambiguous.`);
  for (const expected of hops) {
    const segments = matching[0].segments.filter(
      (segment) => segment.id === expected.segment,
    );
    const found =
      segments[0]?.hops.filter((hop) => hop.label === expected.hop) ?? [];
    const hop = found[0];
    if (
      segments.length !== 1 ||
      found.length !== 1 ||
      hop.evidence !== "observed" ||
      !["switch", "handoff"].includes(hop.kind) ||
      (hop.device && hop.device !== expected.device)
    )
      throw new Error(
        `Trace hop ${expected.hop} is not an exact observed device reference.`,
      );
  }
  return matching;
}

export async function loadObservedImpactEvidence(
  options: Options,
): Promise<ObservedImpactEvidence> {
  const scope = options.scope;
  if (!scope || !isImpactScope(scope))
    throw new Error("Select a verified routing scope.");
  const bounds = windowBounds(options.earliest, options.latest);
  const cohortResult = await search(
    options.client,
    `| \`adm_impact_journeys(${scope})\``,
    options,
    1,
  );
  if (!cohortResult.rows.length)
    throw new Error(
      "No verified Impact data for this scope and exact time window.",
    );
  if (cohortResult.rows.length !== 1)
    throw new Error(
      "Multiple Impact cohorts match this scope and time window.",
    );
  const cohort = parseCohort(cohortResult.rows[0], scope, bounds);
  const receipts = new Map<string, PathEvidence[]>();
  const native: ObservedImpactNativeRecord[] = [];
  const sockets: {
    src: string;
    dst: string;
    source_port: number;
    destination_port: number;
    start: number;
    end: number;
  }[] = [];
  const captureIds = new Set<string>();
  for (const trial of cohort.trials) {
    const directional: (CaptureReference & {
      direction: "forward" | "reverse";
    })[] = [
      {
        direction: "forward",
        src: trial.src,
        dst: trial.dst,
        source_port: trial.source_port,
        destination_port: trial.destination_port,
        capture: trial.captures.forward,
      },
    ];
    if (trial.captures.reverse) {
      directional.push({
        direction: "reverse",
        src: trial.dst,
        dst: trial.src,
        source_port: trial.destination_port,
        destination_port: trial.source_port,
        capture: trial.captures.reverse,
      });
    }
    for (const { capture } of [...directional, ...trial.linkedCaptures]) {
      if (captureIds.has(capture))
        throw new Error(`Duplicate capture ${capture}.`);
      captureIds.add(capture);
    }
    await Promise.all(
      directional.map(async (entry) => {
        const checked = await verifyReceipt(
          options,
          scope,
          trial,
          entry,
          trial.traceHops[entry.direction],
        );
        receipts.set(entry.capture, checked);
      }),
    );
    const tupleResult = await scopedSearch(
      options.client,
      `| \`adm_impact_stream_tuple(${trial.src},${trial.dst},${scope},${trial.source_port},${trial.destination_port})\``,
      options,
      trial.start,
      trial.end,
      64,
    );
    native.push(
      ...parseNative(
        tupleResult.rows,
        trial,
        scope,
        trial.exports,
        cohort.devices,
      ),
    );
    for (const linked of trial.linkedCaptures) {
      receipts.set(
        linked.capture,
        await verifyReceipt(options, scope, trial, linked, [linked]),
      );
    }
    const socket = `${trial.src}|${trial.dst}|${trial.source_port}|${trial.destination_port}`;
    if (
      sockets.some(
        (previous) =>
          `${previous.src}|${previous.dst}|${previous.source_port}|${previous.destination_port}` ===
            socket &&
          previous.start < trial.end &&
          trial.start < previous.end,
      )
    )
      throw new Error(`Overlapping duplicate socket for trial ${trial.id}.`);
    sockets.push({
      src: trial.src,
      dst: trial.dst,
      source_port: trial.source_port,
      destination_port: trial.destination_port,
      start: trial.start,
      end: trial.end,
    });
  }
  native.sort(
    (a, b) =>
      a.trial.localeCompare(b.trial) ||
      a.direction.localeCompare(b.direction) ||
      a.device.localeCompare(b.device),
  );
  return { ...cohort, receipts, native };
}
