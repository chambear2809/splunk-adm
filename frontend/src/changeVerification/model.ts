/**
 * Change verification: saved dependency assertions evaluated over a before and
 * an after window from scoped Trace observations. Missing, truncated or
 * ambiguous evidence is always "unknown"; nothing passes on incomplete data.
 */

export type AssertionKind = "reaches" | "redundant" | "no_new_blocked";
export type Transport = "tcp" | "udp" | "sctp";

export interface Assertion {
  id: string;
  name: string;
  owner?: string;
  kind: AssertionKind;
  scope: string;
  src: string;
  dst: string;
  transport?: Transport;
  port?: number;
  minObservers?: number;
  team?: string;
  note?: string;
}

export const MAX_ASSERTIONS = 100;
export const MAX_RUN_ASSERTIONS = 10;
export const MIN_OBSERVERS = 2;
export const MAX_OBSERVERS = 8;
/** Before-window observers whose liveness is checked when the pair goes quiet. */
export const MAX_LIVENESS_CHECKS = 4;
/** A window must close this long before "now" so late events have arrived. */
export const SETTLE_SECONDS = 600;
export const MAX_WINDOW_SECONDS = 24 * 3600;

export const KIND_LABEL: Record<AssertionKind, string> = {
  reaches: "Reaches",
  redundant: "Redundant paths",
  no_new_blocked: "No new blocked flows",
};

/** One line without C0 controls or DEL, at most `max` code points (server rule). */
const line = (value: string, min: number, max: number) => {
  const chars = [...value];
  return (
    chars.length >= min &&
    chars.length <= max &&
    chars.every((c) => c.charCodeAt(0) > 0x1f && c !== "\x7f")
  );
};
const NAME = { test: (value: string) => line(value, 1, 80) };
const TOKEN = /^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}$/;
const PRINCIPAL = /^[A-Za-z0-9][A-Za-z0-9._\\@-]{0,127}$/;
const NOTE = { test: (value: string) => line(value, 0, 280) };
const TRANSPORTS: readonly Transport[] = ["tcp", "udp", "sctp"];

export const isScope = (value: string) =>
  TOKEN.test(value) && !/^unmapped:/i.test(value);

const V4 =
  /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

/** RFC 5952 text for an IP literal (the server's canonical form), else undefined. */
export function canonicalIp(input: string): string | undefined {
  const value = input.trim();
  if (V4.test(value)) return value;
  if (!/^[0-9A-Fa-f:]{2,39}$/.test(value)) return undefined;
  const halves = value.split("::");
  if (halves.length > 2) return undefined;
  const part = (text: string) => (text ? text.split(":") : []);
  const head = part(halves[0]);
  const tail = halves.length === 2 ? part(halves[1]) : [];
  const missing = 8 - head.length - tail.length;
  if (halves.length === 2 ? missing < 1 : missing !== 0) return undefined;
  const groups = [...head, ...Array<string>(missing).fill("0"), ...tail];
  if (groups.some((g) => !/^[0-9A-Fa-f]{1,4}$/.test(g))) return undefined;
  const words = groups.map((g) => parseInt(g, 16));
  if (words.slice(0, 5).every((w) => w === 0) && words[5] === 0xffff)
    return undefined;
  let best = -1,
    bestLen = 0;
  for (let i = 0; i < 8;) {
    if (words[i] !== 0) {
      i++;
      continue;
    }
    let j = i;
    while (j < 8 && words[j] === 0) j++;
    if (j - i > bestLen) [best, bestLen] = [i, j - i];
    i = j;
  }
  const hex = words.map((w) => w.toString(16));
  if (bestLen < 2) return hex.join(":");
  return `${hex.slice(0, best).join(":")}::${hex.slice(best + bestLen).join(":")}`;
}

export class AssertionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AssertionError";
  }
}

const object = (value: unknown): value is Record<string, unknown> =>
  !!value && typeof value === "object" && !Array.isArray(value);

const FIELDS = new Set([
  "id",
  "name",
  "owner",
  "kind",
  "scope",
  "src",
  "dst",
  "transport",
  "port",
  "minObservers",
  "team",
  "note",
]);

/** Mirrors adm_collaboration_lib/assertions.py; the server stays authoritative. */
export function validateAssertion(raw: unknown): Assertion {
  if (!object(raw) || Object.keys(raw).some((key) => !FIELDS.has(key)))
    throw new AssertionError("Invalid dependency assertion.");
  const { id, owner, kind, scope, src, dst, transport, port, team, note } = raw;
  const name = typeof raw.name === "string" ? raw.name.trim() : "";
  if (typeof id !== "string" || !TOKEN.test(id))
    throw new AssertionError("Invalid assertion id.");
  if (!NAME.test(name)) throw new AssertionError("Name the assertion.");
  if (
    owner !== undefined &&
    (typeof owner !== "string" || !PRINCIPAL.test(owner))
  )
    throw new AssertionError("Invalid assertion owner.");
  if (kind !== "reaches" && kind !== "redundant" && kind !== "no_new_blocked")
    throw new AssertionError("Unsupported assertion kind.");
  if (typeof scope !== "string" || !isScope(scope))
    throw new AssertionError("Assertions require a mapped routing scope.");
  if (typeof src !== "string" || canonicalIp(src) !== src)
    throw new AssertionError("Enter the source as a canonical IP address.");
  if (typeof dst !== "string" || canonicalIp(dst) !== dst)
    throw new AssertionError(
      "Enter the destination as a canonical IP address.",
    );
  if (src === dst)
    throw new AssertionError("Source and destination must differ.");
  const out: Assertion = { id, name, kind, scope, src, dst };
  if (owner !== undefined) out.owner = owner as string;
  if (kind === "no_new_blocked") {
    if (transport !== undefined || port !== undefined)
      throw new AssertionError(
        "No-new-blocked assertions cover every service.",
      );
  } else {
    if (!TRANSPORTS.includes(transport as Transport))
      throw new AssertionError("Choose tcp, udp or sctp.");
    if (
      !Number.isInteger(port) ||
      (port as number) < 1 ||
      (port as number) > 65535
    )
      throw new AssertionError("Enter a port from 1 to 65535.");
    out.transport = transport as Transport;
    out.port = port as number;
  }
  if (kind === "redundant") {
    const min = raw.minObservers;
    if (
      !Number.isInteger(min) ||
      (min as number) < MIN_OBSERVERS ||
      (min as number) > MAX_OBSERVERS
    )
      throw new AssertionError("Redundancy needs 2 to 8 observers.");
    out.minObservers = min as number;
  } else if (raw.minObservers !== undefined) {
    throw new AssertionError("Only redundancy assertions set a minimum.");
  }
  if (team !== undefined) {
    if (typeof team !== "string" || !TOKEN.test(team))
      throw new AssertionError("Invalid team.");
    out.team = team;
  }
  if (note !== undefined) {
    if (typeof note !== "string" || !NOTE.test(note))
      throw new AssertionError("Notes are one line of at most 280 characters.");
    out.note = note;
  }
  return out;
}

export const serviceOf = (a: Assertion) =>
  a.transport && a.port !== undefined ? `${a.transport}/${a.port}` : undefined;

export function describeAssertion(a: Assertion): string {
  const service = serviceOf(a);
  if (a.kind === "reaches") return `${a.src} reaches ${a.dst} on ${service}`;
  if (a.kind === "redundant")
    return `${a.src} reaches ${a.dst} on ${service} through at least ${a.minObservers} observers`;
  return `No new blocked or dropped flows between ${a.src} and ${a.dst}`;
}

/* ---------------------------------------------------------------- windows */

export interface TimeWindow {
  /** Epoch seconds, inclusive start. */
  start: number;
  /** Epoch seconds, exclusive end. */
  end: number;
}

export type WindowBasis = "manual" | "servicenow_actual" | "servicenow_planned";

export interface ChangeWindows {
  before: TimeWindow;
  after: TimeWindow;
  basis: WindowBasis;
  change?: { number: string; sysId: string; state?: string };
}

export const BASIS_LABEL: Record<WindowBasis, string> = {
  manual: "Manual window",
  servicenow_actual: "ServiceNow actual work start/end",
  servicenow_planned: "ServiceNow planned start/end (work times not recorded)",
};

/** Before = [start-span, start), after = [end, end+span). */
export function windowsAround(
  start: number,
  end: number,
  span: number,
): { before: TimeWindow; after: TimeWindow } {
  return {
    before: { start: start - span, end: start },
    after: { start: end, end: end + span },
  };
}

/** Errors that block a run (the windows cannot be compared at all). */
export function windowErrors(
  w: Pick<ChangeWindows, "before" | "after">,
): string[] {
  const errors: string[] = [];
  for (const [label, win] of [
    ["Before", w.before],
    ["After", w.after],
  ] as const) {
    if (
      !Number.isFinite(win.start) ||
      !Number.isFinite(win.end) ||
      win.start < 0
    )
      errors.push(`${label} window is not an absolute time range.`);
    else if (win.end <= win.start)
      errors.push(`${label} window ends before it starts.`);
    else if (win.end - win.start > MAX_WINDOW_SECONDS)
      errors.push(`${label} window is longer than 24 hours.`);
  }
  if (w.before.end > w.after.start)
    errors.push("The before window must end before the after window starts.");
  return errors;
}

/** Issues that keep a window's evidence incomplete (verdicts become unknown). */
export function windowIssues(win: TimeWindow, now: number): string[] {
  return win.end > now - SETTLE_SECONDS
    ? [
        `Window closes less than ${SETTLE_SECONDS / 60} minutes before now; late events may still arrive.`,
      ]
    : [];
}

/* ------------------------------------------------------------ observations */

export type FlowSource = "aci_acllog" | "hubble" | "nd" | "ftd" | "netflow";
const FLOW_SOURCES = new Set<FlowSource>([
  "aci_acllog",
  "hubble",
  "nd",
  "ftd",
  "netflow",
]);
/** Readers that map a forwarding verdict (ACI ACL permit/drop, Hubble verdicts). */
export const VERDICT_SOURCES = new Set<FlowSource>(["aci_acllog", "hubble"]);

export interface Observation {
  source: FlowSource;
  device: string;
  observer: string;
  direction: "forward" | "reverse";
  records: number;
  drops: number;
  services: string[];
  dropServices: string[];
  references: string[];
}

export interface WindowEvidence {
  observations: Observation[];
  /** Reasons the window's evidence is incomplete; empty when complete. */
  issues: string[];
}

const values = (value: unknown): string[] =>
  Array.isArray(value)
    ? value.filter((v): v is string => typeof v === "string")
    : typeof value === "string" && value !== ""
      ? [value]
      : [];
const count = (value: unknown): number | undefined => {
  const n =
    typeof value === "number"
      ? value
      : typeof value === "string" && value.trim() !== ""
        ? Number(value)
        : NaN;
  return Number.isSafeInteger(n) && n >= 0 ? n : undefined;
};
const DEVICE = /^[A-Za-z0-9_.:/-]{1,128}$/;

/** Parse adm_path_trace(3) observation rows. Rows are untrusted; malformed rows mark the window incomplete. */
export function parseObservations(rows: unknown[]): WindowEvidence {
  const observations: Observation[] = [];
  const issues = new Set<string>();
  for (const raw of rows) {
    if (!object(raw) || raw.row_type !== "observation") continue;
    if (raw.observers_capped === "1" || raw.observers_capped === 1)
      issues.add("Observer rows were capped; not every observer is shown.");
    if (raw.records_capped === "1" || raw.records_capped === 1)
      issues.add("Flow records were capped.");
    const source = raw.flow_source as FlowSource;
    const device =
      typeof raw.observer_device === "string" ? raw.observer_device : "";
    const direction = raw.direction;
    const records = count(raw.records);
    if (
      !FLOW_SOURCES.has(source) ||
      !DEVICE.test(device) ||
      (direction !== "forward" && direction !== "reverse") ||
      !records
    ) {
      issues.add("A Trace observation row was malformed.");
      continue;
    }
    let services = values(raw.services);
    if (source === "netflow") {
      const port = count(raw.dest_port);
      const srcPort = count(raw.src_port);
      const proto = typeof raw.protocol === "string" ? raw.protocol : "";
      if (!proto) {
        issues.add("A NetFlow observation had no transport.");
        continue;
      }
      // Forward records carry the listener port as dest_port, replies as src_port.
      const listener = direction === "forward" ? port : srcPort;
      services = listener !== undefined ? [`${proto}/${listener}`] : [proto];
    }
    const drops = count(raw.drops ?? "0");
    if (drops === undefined || drops > records) {
      issues.add("A Trace observation row had inconsistent drop counts.");
      continue;
    }
    observations.push({
      source,
      device,
      observer: typeof raw.observer === "string" ? raw.observer : device,
      direction,
      records,
      drops,
      services,
      dropServices: values(raw.drop_services),
      references: values(raw.references ?? raw.reference).slice(0, 8),
    });
  }
  return { observations, issues: [...issues] };
}

/* ---------------------------------------------------------------- verdicts */

export type Status = "pass" | "fail" | "unknown";
/** observed: drawn from records in the window; inferred: drawn from absence at live observers. */
export type Basis = "observed" | "inferred" | "none";

export interface WindowSummary {
  complete: boolean;
  issues: string[];
  /** Observer devices with established forwarding of the asserted service. */
  forwarded: string[];
  /** Observer devices that dropped the asserted service (or any service for no_new_blocked). */
  blocked: string[];
  /** Observer devices with traffic whose outcome this reader cannot establish. */
  unresolved: string[];
  records: number;
  dropKeys: string[];
}

export interface Verdict {
  status: Status;
  basis: Basis;
  reason: string;
  before: WindowSummary;
  after: WindowSummary;
}

const key = (o: Observation) => `${o.source}:${o.device}`;
const uniq = (items: Iterable<string>) => [...new Set(items)].sort();

interface ServiceView {
  forwarded: Set<string>;
  blocked: Set<string>;
  unresolved: Set<string>;
}

function serviceView(obs: Observation[], service: string): ServiceView {
  const forwarded = new Set<string>();
  const blocked = new Set<string>();
  const unresolved = new Set<string>();
  const presence = new Map<string, { fwd: boolean; rev: boolean }>();
  for (const o of obs) {
    if (!o.services.includes(service)) continue;
    const k = key(o);
    if (VERDICT_SOURCES.has(o.source)) {
      const dropped = o.dropServices.includes(service);
      if (dropped) blocked.add(k);
      if (o.direction !== "forward") continue;
      if (!dropped) forwarded.add(k);
      else if (o.services.length === 1 && o.records > o.drops) forwarded.add(k);
      else if (o.records > o.drops) unresolved.add(k);
    } else {
      // NetFlow, Nexus Dashboard and FTD rows show traffic, not a verdict:
      // forwarding needs the listener's replies at the same observer too.
      const p = presence.get(k) ?? { fwd: false, rev: false };
      if (o.direction === "forward") p.fwd = true;
      else p.rev = true;
      presence.set(k, p);
    }
  }
  for (const [k, p] of presence) {
    if (p.fwd && p.rev) forwarded.add(k);
    else unresolved.add(k);
  }
  for (const k of forwarded) unresolved.delete(k);
  return { forwarded, blocked, unresolved };
}

function dropKeys(obs: Observation[]): Map<string, Set<string>> {
  const keys = new Map<string, Set<string>>();
  for (const o of obs) {
    if (!VERDICT_SOURCES.has(o.source) || !o.drops) continue;
    const services = o.dropServices.length ? o.dropServices : ["unclassified"];
    for (const s of services) {
      const k = `${o.direction}:${s}`;
      if (!keys.has(k)) keys.set(k, new Set());
      keys.get(k)!.add(key(o));
    }
  }
  return keys;
}

export function summarize(a: Assertion, w: WindowEvidence): WindowSummary {
  const service = serviceOf(a);
  const view = service ? serviceView(w.observations, service) : undefined;
  const drops = dropKeys(w.observations);
  return {
    complete: w.issues.length === 0,
    issues: w.issues,
    forwarded: view ? uniq(view.forwarded) : [],
    blocked: view
      ? uniq(view.blocked)
      : uniq([...drops.values()].flatMap((s) => [...s])),
    unresolved: view ? uniq(view.unresolved) : [],
    records: w.observations.reduce((n, o) => n + o.records, 0),
    dropKeys: uniq(drops.keys()),
  };
}

/** Observer device tokens (source:device) to probe for liveness in the after window. */
export function livenessCandidates(
  a: Assertion,
  before: WindowEvidence,
  after: WindowEvidence,
): string[] | undefined {
  if (
    a.kind === "no_new_blocked" ||
    before.issues.length ||
    after.issues.length
  )
    return undefined;
  const b = summarize(a, before);
  const f = summarize(a, after);
  if (a.kind === "reaches") {
    if (f.forwarded.length || f.blocked.length || f.unresolved.length)
      return undefined;
    return b.forwarded.length && b.forwarded.length <= MAX_LIVENESS_CHECKS
      ? b.forwarded
      : undefined;
  }
  const min = a.minObservers ?? MIN_OBSERVERS;
  if (f.forwarded.length >= min || b.forwarded.length < min) return undefined;
  const seen = new Set([...f.forwarded, ...f.blocked, ...f.unresolved]);
  const missing = b.forwarded.filter((d) => !seen.has(d));
  return missing.length <= MAX_LIVENESS_CHECKS ? missing : undefined;
}

const names = (items: string[], max = 3) =>
  items.length <= max
    ? items.join(", ")
    : `${items.slice(0, max).join(", ")} +${items.length - max}`;

/**
 * Verdict for one assertion. `live` holds observer keys proven to export
 * records in the after window (see livenessCandidates); absent keys are unproven.
 */
export function evaluate(
  a: Assertion,
  before: WindowEvidence,
  after: WindowEvidence,
  live: ReadonlySet<string> = new Set(),
): Verdict {
  const b = summarize(a, before);
  const f = summarize(a, after);
  const verdict = (status: Status, basis: Basis, reason: string): Verdict => ({
    status,
    basis,
    reason,
    before: b,
    after: f,
  });
  if (!f.complete)
    return verdict(
      "unknown",
      "none",
      `After window incomplete: ${f.issues[0]}`,
    );
  const service = serviceOf(a);

  if (a.kind === "reaches") {
    if (f.forwarded.length)
      return verdict(
        "pass",
        "observed",
        `Forwarded ${service} observed at ${names(f.forwarded)}${f.blocked.length ? `; drops also at ${names(f.blocked)}` : ""}.`,
      );
    if (f.blocked.length && !f.unresolved.length)
      return verdict(
        "fail",
        "observed",
        `${service} dropped at ${names(f.blocked)}.`,
      );
    if (f.blocked.length || f.unresolved.length)
      return verdict(
        "unknown",
        "none",
        `${service} traffic seen at ${names([...f.blocked, ...f.unresolved])}, but forwarding is not established by these sources.`,
      );
    return quiet(a, b, live, verdict);
  }

  if (a.kind === "redundant") {
    const min = a.minObservers ?? MIN_OBSERVERS;
    if (f.forwarded.length >= min)
      return verdict(
        "pass",
        "observed",
        `Forwarded ${service} observed at ${f.forwarded.length} observers (${names(f.forwarded)}).`,
      );
    const have = `${f.forwarded.length} of ${min} observers forwarded ${service}`;
    if (!b.complete)
      return verdict(
        "unknown",
        "none",
        `${have}; before window incomplete, so no baseline.`,
      );
    if (b.forwarded.length < min)
      return verdict(
        "unknown",
        "none",
        `${have}; the before window also showed fewer than ${min}, so a missing path is not established.`,
      );
    const seen = new Set([...f.forwarded, ...f.blocked, ...f.unresolved]);
    const missing = b.forwarded.filter((d) => !seen.has(d));
    const droppedNow = b.forwarded.filter(
      (d) => f.blocked.includes(d) && !f.forwarded.includes(d),
    );
    if (droppedNow.length && !f.unresolved.length)
      return verdict(
        "fail",
        "observed",
        `${have}; now dropped at ${names(droppedNow)}.`,
      );
    if (
      !f.unresolved.length &&
      missing.length &&
      missing.every((d) => live.has(d))
    )
      return verdict(
        "fail",
        "inferred",
        `${have}; ${names(missing)} still reported other traffic but no longer saw this service.`,
      );
    return verdict(
      "unknown",
      "none",
      `${have}; the missing observers were not proven to be reporting.`,
    );
  }

  const beforeKeys = new Set(b.dropKeys);
  if (f.dropKeys.length) {
    if (!b.complete)
      return verdict(
        "unknown",
        "none",
        `Drops after the change (${names(f.dropKeys)}), but the before window is incomplete.`,
      );
    const fresh = f.dropKeys.filter((k) => !beforeKeys.has(k));
    if (fresh.length)
      return verdict(
        "fail",
        "observed",
        `New drops after the change: ${names(fresh)} at ${names(f.blocked)}.`,
      );
    return verdict(
      "pass",
      "observed",
      `Only drops already present before the change (${names(f.dropKeys)}).`,
    );
  }
  const verdictSeen = after.observations.some((o) =>
    VERDICT_SOURCES.has(o.source),
  );
  if (verdictSeen)
    return verdict(
      "pass",
      "observed",
      "ACI ACL-log or Hubble records for the pair show no drops after the change.",
    );
  return verdict(
    "unknown",
    "none",
    "No source that reports drops (ACI ACL log, Hubble) observed this pair after the change.",
  );
}

function quiet(
  a: Assertion,
  b: WindowSummary,
  live: ReadonlySet<string>,
  verdict: (s: Status, basis: Basis, reason: string) => Verdict,
): Verdict {
  const service = serviceOf(a);
  if (!b.complete)
    return verdict(
      "unknown",
      "none",
      `No ${service} observed after; before window incomplete.`,
    );
  if (!b.forwarded.length)
    return verdict(
      "unknown",
      "none",
      `No ${service} observed in either window; nothing to compare.`,
    );
  if (b.forwarded.length > MAX_LIVENESS_CHECKS)
    return verdict(
      "unknown",
      "none",
      `No ${service} observed after; too many baseline observers to prove.`,
    );
  if (b.forwarded.every((d) => live.has(d)))
    return verdict(
      "fail",
      "inferred",
      `No ${service} after the change; ${names(b.forwarded)} carried it before and still reported other traffic.`,
    );
  return verdict(
    "unknown",
    "none",
    `No ${service} observed after; baseline observers ${names(b.forwarded)} were not proven to be reporting.`,
  );
}

export function tally(statuses: Status[]) {
  return {
    pass: statuses.filter((s) => s === "pass").length,
    fail: statuses.filter((s) => s === "fail").length,
    unknown: statuses.filter((s) => s === "unknown").length,
  };
}
