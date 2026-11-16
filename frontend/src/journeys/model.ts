import { validNatObservation } from "../graph";
import {
  EVIDENCE_LIMITS,
  normalizeIp,
  validateSelection,
  type EvidenceSelection,
  type EvidenceWindow,
} from "../data/evidence";
import {
  PROXY_SCHEMA,
  proxySearchWindow,
  type ProxyAddress,
  type ProxyObservation,
} from "../data/proxyEvidence";
import type { SupplementalResult } from "../data/supplementalEvidence";

export interface JourneyLeg {
  kind: "reported" | "translated" | "downstream" | "upstream";
  from?: ProxyAddress;
  to?: ProxyAddress;
  protocol?: string;
}
export interface Journey {
  source: "cisco:sfw:estreamer" | "proxy_envoy";
  relation: "same_event" | "request_reported" | "unknown";
  scope: string;
  observer: string;
  fingerprint: string;
  nativeTime: number;
  indexedTime: number;
  legs: JourneyLeg[];
  gaps: string[];
  limitations?: string[];
  evidence: unknown;
  /** All distinct payloads for a conflicting source identity, including evidence. */
  conflictingEvidence?: unknown[];
}
export interface JourneyResult {
  journeys: Journey[];
  gaps: string[];
}

/** One validated FTD connection event per journey. Never infer an association to another event. */
export function natJourneys(
  observations: readonly unknown[],
  scope: string,
  window: EvidenceWindow,
  truncated = false,
): JourneyResult {
  const gaps: string[] = [];
  if (truncated || observations.length > 32)
    gaps.push("NAT observations are capped; additional events may be absent.");
  if (
    !scope ||
    !Number.isFinite(window.start) ||
    !Number.isFinite(window.end) ||
    window.start < 0 ||
    window.end <= window.start
  )
    return {
      journeys: [],
      gaps: [...gaps, "Invalid NAT scope or event window."],
    };
  const journeys: Journey[] = [];
  const identities = new Map<string, Journey>();
  for (const value of observations.slice(0, 32)) {
    if (
      !validNatObservation(value) ||
      value.scope !== scope ||
      value.event_time < window.start ||
      value.event_time >= window.end
    ) {
      gaps.push(
        "Invalid, out-of-scope or out-of-window NAT observation omitted.",
      );
      continue;
    }
    addJourney(journeys, identities, gaps, {
      source: value.source_authority,
      relation: "same_event",
      scope: value.scope,
      observer: value.device_ip,
      fingerprint: value.event_fingerprint,
      nativeTime: value.event_time,
      indexedTime: value.received_time,
      legs: [
        {
          kind: "reported",
          from: {
            ip: value.reported_initiator_ip,
            port: value.reported_initiator_port,
          },
          to: {
            ip: value.reported_responder_ip,
            port: value.reported_responder_port,
          },
          protocol: value.protocol,
        },
        {
          kind: "translated",
          from: {
            ip: value.translated_initiator_ip,
            port: value.translated_initiator_port,
          },
          to: {
            ip: value.translated_responder_ip,
            port: value.translated_responder_port,
          },
          protocol: value.protocol,
        },
      ],
      gaps: [],
      evidence: value,
    });
  }
  return { journeys, gaps };
}

const validAddress = (value: unknown): value is ProxyAddress => {
  if (!value || typeof value !== "object") return false;
  const a = value as ProxyAddress;
  try {
    return (
      typeof a.ip === "string" &&
      normalizeIp(a.ip) === a.ip &&
      (a.port === undefined ||
        (Number.isInteger(a.port) && a.port >= 0 && a.port <= 65535))
    );
  } catch {
    return false;
  }
};
const text = (value: unknown, max: number): value is string =>
  typeof value === "string" && value.trim().length > 0 && value.length <= max;
const finiteEpoch = (n: unknown): n is number =>
  typeof n === "number" && Number.isFinite(n) && n >= 0 && n <= 253402300799;
function validProxy(
  value: unknown,
  selection: EvidenceSelection,
): value is ProxyObservation {
  if (!value || typeof value !== "object") return false;
  const v = value as ProxyObservation;
  if (
    v.schemaVersion !== 1 ||
    v.source !== "proxy_envoy" ||
    v.schema !== PROXY_SCHEMA ||
    v.scope !== selection.scope ||
    v.routingAuthority !== selection.scope ||
    !text(v.observer, 255) ||
    !text(v.index, 128) ||
    !/^[a-f0-9]{64}$/.test(v.eventFingerprint) ||
    !finiteEpoch(v.eventTime) ||
    !finiteEpoch(v.indexedTime) ||
    v.durationBasis !== "request_start_to_last_byte_out" ||
    !v.downstream ||
    !validAddress(v.downstream.directPeer) ||
    (v.downstream.listener !== undefined &&
      !validAddress(v.downstream.listener)) ||
    (v.upstream !== undefined &&
      (!v.upstream ||
        typeof v.upstream !== "object" ||
        (v.upstream.local !== undefined && !validAddress(v.upstream.local)) ||
        (v.upstream.remote !== undefined &&
          !validAddress(v.upstream.remote)))) ||
    (v.selectedBackend !== undefined &&
      (!validAddress(v.selectedBackend) ||
        JSON.stringify(v.selectedBackend) !==
          JSON.stringify(v.upstream?.remote))) ||
    (v.upstream?.remote !== undefined && v.selectedBackend === undefined) ||
    (v.durationMilliseconds !== undefined &&
      (!Number.isFinite(v.durationMilliseconds) ||
        v.durationMilliseconds < 0 ||
        v.durationMilliseconds > 31536000000)) ||
    (v.upstreamAttemptCount !== undefined &&
      (!Number.isInteger(v.upstreamAttemptCount) ||
        v.upstreamAttemptCount < 0 ||
        v.upstreamAttemptCount > 10000)) ||
    !Array.isArray(v.limitations) ||
    !v.limitations.every((x) => typeof x === "string")
  )
    return false;
  const match = [];
  if (selection.addresses.includes(v.downstream.directPeer.ip))
    match.push("downstream_direct_peer");
  if (v.upstream?.remote && selection.addresses.includes(v.upstream.remote.ip))
    match.push("upstream_selected_endpoint");
  return (
    match.length > 0 &&
    Array.isArray(v.matchedSelectionLegs) &&
    JSON.stringify(match) === JSON.stringify(v.matchedSelectionLegs) &&
    v.eventTime >= proxySearchWindow(selection).start &&
    v.eventTime < selection.window.end &&
    v.eventTime + (v.durationMilliseconds ?? 0) / 1000 >= selection.window.start
  );
}
const stable = (value: unknown): string =>
  JSON.stringify(value, (_key, item: unknown) =>
    item && typeof item === "object" && !Array.isArray(item)
      ? Object.fromEntries(
          Object.entries(item).sort(([a], [b]) => a.localeCompare(b)),
        )
      : item,
  );

function addJourney(
  journeys: Journey[],
  identities: Map<string, Journey>,
  gaps: string[],
  journey: Journey,
) {
  const key = JSON.stringify([
    journey.source,
    journey.scope,
    journey.observer,
    journey.fingerprint,
  ]);
  const previous = identities.get(key);
  if (!previous) {
    identities.set(key, journey);
    journeys.push(journey);
  } else if (stable(previous.evidence) !== stable(journey.evidence)) {
    previous.relation = "unknown";
    previous.conflictingEvidence ??= [previous.evidence];
    if (
      !previous.conflictingEvidence.some(
        (item) => stable(item) === stable(journey.evidence),
      )
    )
      previous.conflictingEvidence.push(journey.evidence);
    const message =
      "Conflicting records share the same source, scope, observer and fingerprint; association is unknown.";
    if (!previous.gaps.includes(message)) {
      previous.gaps.push(message);
      gaps.push(message);
    }
  }
}

/** Results from the qualified proxy adapter are source context unless all admission gates pass. */
export function proxyJourneys(
  result: SupplementalResult<ProxyObservation>,
  selection: EvidenceSelection,
): JourneyResult {
  const gaps: string[] = [];
  try {
    validateSelection(selection);
    validateSelection(result.selection);
  } catch {
    return { journeys: [], gaps: ["Invalid evidence selection."] };
  }
  const expectedWindow = proxySearchWindow(selection);
  const count = (value: unknown) =>
    typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
  const optionalCount = (value: unknown) => value === undefined || count(value);
  const qualified =
    result.schemaVersion === 1 &&
    result.source === "proxy_envoy" &&
    result.state === "complete" &&
    result.schemaQualified === true &&
    result.configurationChanged === false &&
    result.inputCapped === false &&
    (result.sourceScanCapped === undefined ||
      result.sourceScanCapped === false) &&
    typeof result.outputCapped === "boolean" &&
    count(result.inputCount) &&
    result.inputCount <= EVIDENCE_LIMITS.input &&
    finiteEpoch(result.capturedAt) &&
    result.rejected === 0 &&
    result.oversized === 0 &&
    optionalCount(result.sourceScanCount) &&
    (result.sourceScanCount === undefined ||
      result.sourceScanCount <= EVIDENCE_LIMITS.input) &&
    (result.sourceScanInvalidCount === undefined ||
      result.sourceScanInvalidCount === 0) &&
    result.errorCode === undefined &&
    result.error === undefined &&
    Array.isArray(result.records) &&
    result.records.length <= 64 &&
    result.inputCount >= result.records.length &&
    result.records.every((record) => validProxy(record, selection)) &&
    result.configurationFingerprint === selection.configurationFingerprint &&
    stable(result.selection) === stable(selection) &&
    result.inspectedWindow?.start === expectedWindow.start &&
    result.inspectedWindow?.end === expectedWindow.end;
  if (!qualified)
    gaps.push(
      "Proxy association is unknown: source, selection, configuration, window or input qualification failed.",
    );
  if (result.inputCapped || result.sourceScanCapped)
    gaps.push("Proxy input was capped; associations are suppressed.");
  if (result.outputCapped)
    gaps.push("Proxy output was capped; additional requests may be absent.");
  if (result.rejected || result.oversized || result.sourceScanInvalidCount)
    gaps.push(
      "Proxy records were rejected, oversized or invalid; associations are suppressed.",
    );
  if (!Array.isArray(result.records))
    return { journeys: [], gaps: [...gaps, "Invalid proxy records."] };
  const journeys: Journey[] = [];
  const identities = new Map<string, Journey>();
  for (const value of result.records.slice(0, 64)) {
    if (!validProxy(value, selection)) {
      gaps.push(
        "Invalid, out-of-scope or out-of-window proxy observation omitted.",
      );
      continue;
    }
    const legGaps: string[] = [];
    if (!value.downstream.directPeer.port || !value.downstream.listener?.port)
      legGaps.push(
        "A downstream address or port is missing or a port is zero; a complete socket endpoint cannot be established.",
      );
    if (!value.upstream?.remote)
      legGaps.push("Selected upstream endpoint was not reported.");
    else if (!value.upstream.local?.port || !value.upstream.remote.port)
      legGaps.push(
        "An upstream address or port is missing or a port is zero; a complete socket endpoint cannot be established.",
      );
    if ((value.upstreamAttemptCount ?? 0) > 1)
      legGaps.push(
        `${value.upstreamAttemptCount} upstream attempts reported; individual retry endpoints are unavailable.`,
      );
    addJourney(journeys, identities, gaps, {
      source: "proxy_envoy",
      relation: qualified ? "request_reported" : "unknown",
      scope: value.scope,
      observer: value.observer,
      fingerprint: value.eventFingerprint,
      nativeTime: value.eventTime,
      indexedTime: value.indexedTime,
      legs: [
        {
          kind: "downstream",
          from: value.downstream.directPeer,
          to: value.downstream.listener,
        },
        ...(value.upstream?.remote || value.upstream?.local
          ? [
              {
                kind: "upstream" as const,
                from: value.upstream.local,
                to: value.upstream.remote,
              },
            ]
          : []),
      ],
      gaps: legGaps,
      limitations: [...value.limitations],
      evidence: value,
    });
  }
  if (result.records.length > 64)
    gaps.push(
      "Proxy records exceed the output limit; additional requests omitted.",
    );
  return { journeys, gaps };
}
