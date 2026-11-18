import type { Graph } from "../graph";
import type { Window } from "./model";

/**
 * A projection contract, not an authentication or source-qualification boundary.
 * Only a trusted producer may supply records after independently verifying the
 * native event, authorization, source scope and historical binding provenance.
 */
export type AuditEvent = {
  eventId: string;
  authority: string;
  scope: string;
  objectId: string;
  action: string;
  actionTime: string;
  receivedTime: string;
};
export type AuditBinding = {
  authority: string;
  scope: string;
  objectId: string;
  applicationId: string;
  validFrom: string;
  validUntil: string;
  bindingAuthority: string;
  bindingEvidenceId: string;
};
export type AuditBatch = {
  events: AuditEvent[];
  bindings: AuditBinding[];
  coverage: { start: string; end: string; gaps: string[] };
};
export type AuditProducer = {
  /** Producer verifies this selection and application identity under caller authorization. */
  load: (
    request: { boundary: Graph["boundary"]; window: Window },
    signal: AbortSignal,
  ) => Promise<{
    producerId: string;
    applicationId: string;
    batch: AuditBatch;
  }>;
};
export type WithheldReason =
  | "invalid event"
  | "duplicate event identity"
  | "outside source coverage"
  | "outside requested window"
  | "invalid binding"
  | "no active binding"
  | "ambiguous binding"
  | "different application";
export type AuditProjection = {
  events: { event: AuditEvent; binding: AuditBinding }[];
  withheld: number;
  withheldReasons: Partial<Record<WithheldReason, number>>;
  coverage: AuditBatch["coverage"];
};

const text = (value: unknown): value is string =>
  typeof value === "string" &&
  value.trim().length > 0 &&
  value === value.trim();
const instant = (value: unknown): value is string => {
  if (!text(value)) return false;
  const match =
    /^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.\d{1,3})?(Z|[+-]\d\d:\d\d)$/.exec(
      value,
    );
  if (!match) return false;
  const [, year, month, day, hour, minute, second, zone] = match;
  const y = Number(year),
    m = Number(month),
    d = Number(day);
  const days = [
    31,
    y % 4 === 0 && (y % 100 !== 0 || y % 400 === 0) ? 29 : 28,
    31,
    30,
    31,
    30,
    31,
    31,
    30,
    31,
    30,
    31,
  ];
  return (
    m >= 1 &&
    m <= 12 &&
    d >= 1 &&
    d <= days[m - 1] &&
    Number(hour) <= 23 &&
    Number(minute) <= 59 &&
    Number(second) <= 59 &&
    (zone === "Z" ||
      (Number(zone.slice(1, 3)) <= 23 && Number(zone.slice(4, 6)) <= 59)) &&
    Number.isFinite(Date.parse(value))
  );
};
const validEvent = (e: AuditEvent) =>
  !!e &&
  [e.eventId, e.authority, e.scope, e.objectId, e.action].every(text) &&
  instant(e.actionTime) &&
  instant(e.receivedTime);
const validBinding = (b: AuditBinding) =>
  !!b &&
  [
    b.authority,
    b.scope,
    b.objectId,
    b.applicationId,
    b.bindingAuthority,
    b.bindingEvidenceId,
  ].every(text) &&
  instant(b.validFrom) &&
  instant(b.validUntil) &&
  Date.parse(b.validFrom) < Date.parse(b.validUntil);

/** Half-open validity intervals; exact native tuples only. */
export function projectAudit(
  batch: AuditBatch,
  applicationId: string,
  window?: Window,
): AuditProjection {
  if (
    !batch ||
    !Array.isArray(batch.events) ||
    !Array.isArray(batch.bindings) ||
    !batch.coverage ||
    !instant(batch.coverage.start) ||
    !instant(batch.coverage.end) ||
    Date.parse(batch.coverage.start) >= Date.parse(batch.coverage.end) ||
    !Array.isArray(batch.coverage.gaps) ||
    !batch.coverage.gaps.every(text) ||
    !text(applicationId) ||
    (window !== undefined &&
      (!instant(window.start) ||
        !instant(window.end) ||
        Date.parse(window.start) >= Date.parse(window.end)))
  )
    throw new Error("Invalid audit source coverage or application identity.");

  const events: AuditProjection["events"] = [];
  const withheldReasons: AuditProjection["withheldReasons"] = {};
  const withhold = (reason: WithheldReason) => {
    withheldReasons[reason] = (withheldReasons[reason] ?? 0) + 1;
  };

  for (const event of batch.events) {
    if (!validEvent(event)) {
      withhold("invalid event");
      continue;
    }
    // A repeated native identity is ambiguous, even if the payloads agree.
    if (
      batch.events.filter(
        (other) =>
          other &&
          other.eventId === event.eventId &&
          other.authority === event.authority &&
          other.scope === event.scope,
      ).length !== 1
    ) {
      withhold("duplicate event identity");
      continue;
    }
    const time = Date.parse(event.actionTime);
    if (
      time < Date.parse(batch.coverage.start) ||
      time >= Date.parse(batch.coverage.end)
    ) {
      withhold("outside source coverage");
      continue;
    }
    if (
      window &&
      (time < Date.parse(window.start) || time >= Date.parse(window.end))
    ) {
      withhold("outside requested window");
      continue;
    }
    // Malformed records for this exact tuple must not hide a conflicting binding.
    const candidates = batch.bindings.filter(
      (binding) =>
        binding &&
        binding.authority === event.authority &&
        binding.scope === event.scope &&
        binding.objectId === event.objectId,
    );
    if (candidates.some((binding) => !validBinding(binding))) {
      withhold("invalid binding");
      continue;
    }
    const active = candidates.filter(
      (binding) =>
        Date.parse(binding.validFrom) <= time &&
        time < Date.parse(binding.validUntil),
    );
    const apps = new Set(active.map((binding) => binding.applicationId));
    if (active.length === 0) {
      withhold("no active binding");
      continue;
    }
    if (apps.size !== 1 || active.length !== 1) {
      withhold("ambiguous binding");
      continue;
    }
    if (!apps.has(applicationId)) {
      withhold("different application");
      continue;
    }
    const binding = active[0];
    events.push({
      event: {
        eventId: event.eventId,
        authority: event.authority,
        scope: event.scope,
        objectId: event.objectId,
        action: event.action,
        actionTime: event.actionTime,
        receivedTime: event.receivedTime,
      },
      binding: {
        authority: binding.authority,
        scope: binding.scope,
        objectId: binding.objectId,
        applicationId: binding.applicationId,
        validFrom: binding.validFrom,
        validUntil: binding.validUntil,
        bindingAuthority: binding.bindingAuthority,
        bindingEvidenceId: binding.bindingEvidenceId,
      },
    });
  }
  return {
    events,
    withheld: Object.values(withheldReasons).reduce(
      (sum, count) => sum + count,
      0,
    ),
    withheldReasons,
    coverage: {
      start: batch.coverage.start,
      end: batch.coverage.end,
      gaps: [...batch.coverage.gaps],
    },
  };
}

/** An optional source cannot hold the comparison indefinitely. */
export const AUDIT_TIMEOUT_MS = 10_000;
export async function loadAudit(
  producer: AuditProducer,
  request: { boundary: Graph["boundary"]; window: Window },
  signal: AbortSignal,
) {
  if (signal.aborted) throw new Error("Audit request cancelled.");
  const source = new AbortController();
  let timer: ReturnType<typeof setTimeout> | undefined;
  let abort: (() => void) | undefined;
  const interrupted = new Promise<never>((_, reject) => {
    abort = () => {
      source.abort();
      reject(new Error("Audit request cancelled."));
    };
    signal.addEventListener("abort", abort, { once: true });
    timer = setTimeout(() => {
      source.abort();
      reject(new Error("Audit request timed out."));
    }, AUDIT_TIMEOUT_MS);
  });
  try {
    const response = await Promise.race([
      Promise.resolve().then(() => {
        if (source.signal.aborted) throw new Error("Audit request cancelled.");
        return producer.load(request, source.signal);
      }),
      interrupted,
    ]);
    if (signal.aborted) throw new Error("Audit request cancelled.");
    if (!response || !text(response.producerId))
      throw new Error("Invalid audit producer identity.");
    return {
      producerId: response.producerId,
      applicationId: response.applicationId,
      projection: projectAudit(
        response.batch,
        response.applicationId,
        request.window,
      ),
    };
  } finally {
    if (timer !== undefined) clearTimeout(timer);
    if (abort) signal.removeEventListener("abort", abort);
    source.abort();
  }
}
export type AuditResult = Awaited<ReturnType<typeof loadAudit>>;
