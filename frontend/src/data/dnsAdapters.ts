import {
  EVIDENCE_LIMITS,
  isObject,
  normalizeIp,
  type DnsObservation,
  type DnsSource,
  type EvidenceSelection,
} from "./evidence";

export type Row = Record<string, unknown>;
export interface IdentityRecord {
  ip: string;
  scope: string;
  entity_id: string;
  entity_kind: string;
  valid_from: number;
  valid_end?: number;
  scope_mapping_verified?: number;
}
export interface DnsAdapterConfig {
  scope: string;
  authorities: string[];
  maxAgeSeconds: number;
  clockUncertaintySeconds?: number;
  schemaQualified: boolean;
}

const hasControl = (value: string): boolean => {
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if (c <= 31 || c === 127) return true;
  }
  return false;
};
const text = (v: unknown, max: number): v is string =>
  typeof v === "string" && v.length > 0 && v.length <= max && !hasControl(v);
const scalar = (v: unknown): string | undefined =>
  typeof v === "string" || typeof v === "number" ? String(v) : undefined;
const finite = (v: unknown): number | undefined => {
  if (typeof v === "number" && Number.isFinite(v)) return v;
  if (typeof v === "string" && v.trim() && Number.isFinite(Number(v)))
    return Number(v);
  return undefined;
};
function epoch(v: unknown): number | undefined {
  const numeric = finite(v);
  if (numeric !== undefined) return numeric;
  if (typeof v !== "string") return;
  const iso =
    /^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.(\d+))?(Z|[+-]\d\d:\d\d)$/.exec(v);
  if (!iso) return;
  const whole = Date.parse(`${iso[1]}${iso[3]}`);
  if (!Number.isFinite(whole)) return;
  return whole / 1000 + (iso[2] ? Number(`0.${iso[2]}`) : 0);
}
const pick = (o: Row, ...keys: string[]): unknown => {
  for (const k of keys) if (o[k] !== undefined && o[k] !== null) return o[k];
  return undefined;
};
function parseRaw(row: Row): Row | undefined {
  const raw = row._raw;
  if (isObject(raw)) {
    try {
      if (
        new TextEncoder().encode(JSON.stringify(raw)).byteLength >
        EVIDENCE_LIMITS.recordBytes
      )
        return;
    } catch {
      return;
    }
    return raw;
  }
  if (
    typeof raw !== "string" ||
    new TextEncoder().encode(raw).byteLength > EVIDENCE_LIMITS.recordBytes
  )
    return;
  try {
    const parsed: unknown = JSON.parse(raw);
    return isObject(parsed) ? parsed : undefined;
  } catch {
    return;
  }
}
function list(v: unknown): unknown[] {
  if (Array.isArray(v)) return v;
  if (typeof v === "string") return [v];
  return [];
}
const first = (v: unknown): unknown => (Array.isArray(v) ? v[0] : v);
function recordType(v: unknown): string | undefined {
  const s = scalar(v)?.toUpperCase();
  if (s === "1") return "A";
  if (s === "28") return "AAAA";
  return s;
}
function name(
  value: unknown,
): { original: string; comparison?: string; valid: boolean } | undefined {
  if (typeof value !== "string" || !value.length) return;
  const sanitized = [...value]
    .map((c) => (hasControl(c) ? "�" : c))
    .join("")
    .slice(0, 1024)
    .trim();
  if (!sanitized) return;
  const valid =
    value.length <= 253 &&
    !hasControl(value) &&
    !/\s/.test(value) &&
    /^[A-Za-z0-9_*-](?:[A-Za-z0-9_.*-]*[A-Za-z0-9_*.-])?\.?$/.test(value);
  return {
    original: sanitized,
    ...(valid
      ? { comparison: sanitized.replace(/\.$/, "").toLowerCase() }
      : {}),
    valid,
  };
}
function code(v: unknown): string | undefined {
  const s = scalar(v);
  if (!s || s.length > 32 || hasControl(s)) return;
  return /^\d+$/.test(s) ? String(Number(s)) : s.toUpperCase();
}
function canonicalIp(v: unknown): string | undefined {
  if (typeof v !== "string" || v.length > 64) return;
  try {
    return normalizeIp(v);
  } catch {
    return;
  }
}
function fingerprint(row: Row): string | undefined {
  const supplied = row.event_fingerprint;
  if (typeof supplied === "string" && /^[a-f0-9]{64}$/.test(supplied))
    return supplied;
  return undefined;
}
function eventTime(row: Row, raw: Row): number | undefined {
  return epoch(
    pick(raw, "event_time", "timestamp", "end", "time", "_time") ?? row._time,
  );
}
function ownerFor(
  client: string | undefined,
  scope: string,
  t: number,
  owners: readonly IdentityRecord[],
): IdentityRecord | undefined {
  if (!client) return;
  const matches = owners.filter(
    (o) =>
      canonicalIp(o.ip) === client &&
      o.scope === scope &&
      (o.scope !== "default" || o.scope_mapping_verified === 1) &&
      Number.isFinite(o.valid_from) &&
      o.valid_from <= t &&
      (o.valid_end === undefined || t < o.valid_end),
  );
  const ids = new Set(matches.map((o) => `${o.entity_kind}/${o.entity_id}`));
  return ids.size === 1 ? matches[0] : undefined;
}
function ownerIdsDuring(
  client: string | undefined,
  scope: string,
  start: number,
  end: number,
  owners: readonly IdentityRecord[],
): Set<string> {
  if (!client) return new Set();
  return new Set(
    owners
      .filter(
        (o) =>
          canonicalIp(o.ip) === client &&
          o.scope === scope &&
          (o.scope !== "default" || o.scope_mapping_verified === 1) &&
          Number.isFinite(o.valid_from) &&
          o.valid_from <= end &&
          (o.valid_end === undefined || o.valid_end > start),
      )
      .map((o) => `${o.entity_kind}/${o.entity_id}`),
  );
}
function answerPairs(
  raw: Row,
  source: DnsSource,
  requestedTypes: readonly string[],
  queryName?: string,
): {
  answers: DnsObservation["answers"];
  aliases: string[];
  capped: boolean;
  invalidTtl: boolean;
} {
  const answers: DnsObservation["answers"] = [];
  const aliases: string[] = [];
  let capped = false;
  let invalidTtl = false;
  // Only an explicitly associated RR object is safe for Stream. Independent arrays are ambiguous.
  const structured = pick(raw, "answer_records", "answers");
  if (Array.isArray(structured)) {
    for (const item of structured) {
      if (!isObject(item)) continue;
      const ip = canonicalIp(pick(item, "address", "answer", "ip"));
      const type = recordType(pick(item, "type", "record_type"));
      const ttl = finite(item.ttl);
      const ownerName = name(pick(item, "owner", "name", "rr_name"));
      const section = scalar(
        pick(item, "section", "record_section"),
      )?.toLowerCase();
      if (
        item.ttl !== undefined &&
        (ttl === undefined || ttl < 0 || ttl > 4294967295)
      )
        invalidTtl = true;
      if (type === "CNAME") {
        const n = name(pick(item, "target", "value"));
        if (n) aliases.push(n.original);
      } else if (
        ip &&
        (type === "A" || type === "AAAA") &&
        ownerName?.comparison === queryName &&
        section === "answer" &&
        (requestedTypes.length === 0 || requestedTypes.includes(type)) &&
        (type !== "A" || !ip.includes(":")) &&
        (type !== "AAAA" || ip.includes(":"))
      ) {
        answers.push({
          address: ip,
          type,
          ...(ttl !== undefined && ttl >= 0 && ttl <= 4294967295
            ? { ttl }
            : {}),
        });
      }
    }
  } else if (source === "dns_hubble") {
    // Hubble's unordered IP/CNAME arrays lack RR owner and section data.
    // Preserve as reported context; do not infer that they answer the query.
    for (const v of list(pick(raw, "cnames", "cname"))) {
      const n = name(v);
      if (n) aliases.push(n.original);
    }
  }
  if (answers.length > EVIDENCE_LIMITS.answers) {
    answers.length = EVIDENCE_LIMITS.answers;
    capped = true;
  }
  if (aliases.length > EVIDENCE_LIMITS.aliases) {
    aliases.length = EVIDENCE_LIMITS.aliases;
    capped = true;
  }
  return { answers, aliases, capped, invalidTtl };
}
interface Parsed {
  observation: DnsObservation;
  ttlQualified: boolean;
  ttlSeconds?: number;
  duplicatePayload: string;
  associationSuppressed: boolean;
}
function parseOne(
  source: DnsSource,
  row: Row,
  config: DnsAdapterConfig,
  selection: EvidenceSelection,
  owners: readonly IdentityRecord[],
): Parsed | undefined {
  const raw = parseRaw(row);
  if (!raw) return;
  const stream = source === "dns_stream";
  const flow = !stream && isObject(raw.flow) ? raw.flow : raw;
  const l7 = isObject(flow.l7) ? flow.l7 : {};
  const hubDns = isObject(l7.dns) ? l7.dns : isObject(raw.dns) ? raw.dns : raw;
  const ipData = isObject(flow.IP) ? flow.IP : isObject(flow.ip) ? flow.ip : {};
  const authorityValue = stream
    ? row.host
    : (pick(raw, "cluster_name") ??
      scalar(pick(raw, "node_name") ?? pick(flow, "node_name"))?.split(
        "/",
      )[0] ??
      pick(raw, "observer", "host") ??
      row.host);
  const authority = scalar(authorityValue);
  if (!authority || !config.authorities.includes(authority)) return;
  const queryValue =
    pick(hubDns, "query", "query_name", "question") ??
    (stream ? raw.query : undefined);
  const q = name(first(queryValue));
  if (!q) return;
  const queryTypeValues = list(
    pick(hubDns, "qtypes", "query_type", "qtype", "record_type") ??
      (stream ? raw.query_type : undefined),
  );
  const queryTypes = queryTypeValues
    .map(recordType)
    .filter((t): t is string => t !== undefined);
  const supportedAddressTypes = queryTypes.filter(
    (t) => t === "A" || t === "AAAA",
  );
  const eventTimeValue = eventTime(row, stream ? raw : { ...raw, ...flow });
  const indexedTime = finite(row._indextime);
  const rowTime = epoch(row._time);
  if (
    eventTimeValue === undefined ||
    eventTimeValue < 0 ||
    indexedTime === undefined ||
    indexedTime < 0
  )
    return;
  if (typeof row.index !== "string" || !/^[a-z0-9_.-]{1,80}$/.test(row.index))
    return;
  const dir = scalar(
    first(pick(raw, "message_type", "event_type", "type", "flow_type")) ??
      pick(l7, "type", "message_type") ??
      pick(hubDns, "message_type", "type"),
  )?.toLowerCase();
  let shape: DnsObservation["shape"] = "transaction";
  const hubbleDirectionKnown =
    stream || /request|query|response|answer/.test(dir ?? "");
  if (!stream && /request|query/.test(dir ?? "")) shape = "request";
  if (!stream && /response|answer/.test(dir ?? "")) shape = "response";
  const suppliedCode =
    pick(hubDns, "reply_code", "rcode", "response_code") ??
    (stream ? pick(raw, "reply_code", "reply_code_id") : undefined);
  const defaultCode =
    !stream &&
    config.schemaQualified &&
    shape === "response" &&
    suppliedCode === undefined;
  const responseCode = code(suppliedCode ?? (defaultCode ? 0 : undefined));
  const success = responseCode === "0" || responseCode === "NOERROR";
  const rawVerdict =
    !stream && config.schemaQualified
      ? scalar(pick(flow, "verdict"))?.toUpperCase()
      : undefined;
  const policy =
    rawVerdict && ["DROPPED", "ERROR"].includes(rawVerdict)
      ? `hubble_${rawVerdict.toLowerCase()}`
      : undefined;
  const {
    answers,
    aliases,
    capped,
    invalidTtl: answerInvalidTtl,
  } = answerPairs(hubDns, source, supportedAddressTypes, q.comparison);
  const hubbleEgress =
    stream ||
    scalar(pick(flow, "traffic_direction"))?.toUpperCase() === "EGRESS";
  const clientEndpoint =
    shape === "response"
      ? (pick(ipData, "destination", "dst") ??
        pick(flow, "destination_ip", "dst", "client_ip"))
      : (pick(ipData, "source", "src") ??
        pick(flow, "source_ip", "src", "client_ip"));
  const resolverEndpoint =
    shape === "response"
      ? (pick(ipData, "source", "src") ??
        pick(flow, "source_ip", "src", "resolver_ip"))
      : (pick(ipData, "destination", "dst") ??
        pick(flow, "destination_ip", "dst", "resolver_ip"));
  const replyFlag = pick(flow, "is_reply");
  const hubbleReplyConflict =
    !stream &&
    typeof replyFlag === "boolean" &&
    ((shape === "response" && !replyFlag) ||
      (shape === "request" && replyFlag));
  const client = canonicalIp(
    stream
      ? pick(raw, "src_ip", "src", "client")
      : hubbleEgress
        ? clientEndpoint
        : undefined,
  );
  const selectedClients = new Set([
    ...selection.addresses,
    ...selection.contexts.map((c) => c.client),
  ]);
  if (client && !selectedClients.has(client)) return;
  const resolver = canonicalIp(
    stream ? pick(raw, "dest_ip", "dest", "resolver") : resolverEndpoint,
  );
  const identifier = scalar(
    pick(hubDns, "transaction_id", "id") ??
      (stream ? raw.transaction_id : undefined),
  );
  const uuid = !stream ? scalar(pick(flow, "uuid", "flow_uuid")) : undefined;
  const ttlValue =
    pick(hubDns, "ttl", "time_to_live") ??
    (stream
      ? raw.ttl
      : config.schemaQualified && shape === "response"
        ? 0
        : undefined);
  const ttlScalar =
    stream && Array.isArray(ttlValue) ? undefined : finite(ttlValue);
  const allReportedTtls = list(ttlValue)
    .map(finite)
    .filter((v): v is number => v !== undefined);
  const reportedTtls = allReportedTtls
    .filter((v) => v >= 0 && v <= 4294967295)
    .slice(0, EVIDENCE_LIMITS.answers);
  const invalidTtl =
    answerInvalidTtl ||
    (ttlValue !== undefined &&
      ttlScalar === undefined &&
      !Array.isArray(ttlValue)) ||
    list(ttlValue).some(
      (v) => finite(v) === undefined || (finite(v) ?? 0) < 0,
    ) ||
    allReportedTtls.some((v) => v < 0 || v > 4294967295);
  const ttlArrayCapped = list(ttlValue).length > EVIDENCE_LIMITS.answers;
  const reportedAddressValues = list(pick(hubDns, "ips", "answer_ips"));
  const streamAddressValues = list(raw.host_addr);
  const reportedAddressCapped =
    (stream ? streamAddressValues : reportedAddressValues).length >
    EVIDENCE_LIMITS.answers;
  const cappedExpansion = capped || reportedAddressCapped;
  const ttlQualified = config.schemaQualified;
  // A scalar Hubble TTL never gets copied onto unordered IP answers.
  // `response_time` is a latency field in Stream (microseconds), never an epoch.
  const responseStart = epoch(
    pick(raw, "start", "response_start", "interval_start"),
  );
  const responseEnd = epoch(
    pick(raw, "end", "response_end", "event_end", "interval_end"),
  );
  const latencyRaw = finite(pick(raw, "response_time", "duration", "latency"));
  const latencySeconds =
    latencyRaw !== undefined && latencyRaw >= 0
      ? stream
        ? latencyRaw / 1_000_000
        : latencyRaw
      : undefined;
  const interval =
    responseStart !== undefined &&
    responseEnd !== undefined &&
    responseEnd >= responseStart
      ? { start: responseStart, end: responseEnd }
      : undefined;
  const actualResponseTime =
    stream && shape === "transaction"
      ? (responseEnd ?? eventTimeValue)
      : eventTimeValue;
  const owner = ownerFor(client, config.scope, actualResponseTime, owners);
  const limitations: string[] = [];
  if (defaultCode) limitations.push("qualified_proto3_default_rcode");
  let associationSuppressed = false;
  if (
    actualResponseTime > selection.window.end ||
    actualResponseTime < selection.window.start - config.maxAgeSeconds
  ) {
    limitations.push("source_time_outside_inspected_window");
    associationSuppressed = true;
  }
  if (!q.valid) {
    limitations.push("invalid_query_name");
    associationSuppressed = true;
  }
  if (!config.schemaQualified) {
    limitations.push("producer_schema_unqualified");
    associationSuppressed = true;
  }
  if (cappedExpansion) {
    limitations.push("answer_or_alias_cap");
    associationSuppressed = true;
  }
  if (!answers.length) limitations.push("no_qualified_address_answer");
  if (aliases.length) {
    limitations.push("alias_relationship_unqualified");
    associationSuppressed = true;
  }
  if (shape !== "response" && shape !== "transaction") {
    limitations.push("request_only");
    associationSuppressed = true;
  }
  if (!hubbleDirectionKnown) {
    limitations.push("hubble_direction_unknown");
    associationSuppressed = true;
  }
  if (!hubbleEgress) {
    limitations.push("hubble_flow_direction_unknown");
    associationSuppressed = true;
  }
  if (hubbleReplyConflict) {
    limitations.push("hubble_reply_direction_conflict");
    associationSuppressed = true;
  }
  if (invalidTtl) {
    limitations.push("invalid_ttl_value");
    associationSuppressed = true;
  }
  if (ttlArrayCapped) {
    limitations.push("ttl_list_cap");
    associationSuppressed = true;
  }
  if (
    queryTypes.length === 0 ||
    supportedAddressTypes.length !== queryTypes.length
  ) {
    limitations.push("query_type_not_qualified_for_address_association");
    associationSuppressed = true;
  }
  if (list(queryValue).length > 1) {
    limitations.push("multiple_questions_not_expanded");
    associationSuppressed = true;
  }
  if (!success) {
    limitations.push("response_not_successful");
    associationSuppressed = true;
  }
  if (policy) {
    limitations.push("source_policy_outcome");
    associationSuppressed = true;
  }
  if (!client) {
    limitations.push("client_unknown");
    associationSuppressed = true;
  }
  const structuredTtl = answers.some((a) => a.ttl !== undefined);
  if (answers.some((a) => a.ttl === undefined)) {
    limitations.push("answer_ttl_missing");
    associationSuppressed = true;
  }
  if (stream && reportedTtls.length > 0 && !structuredTtl) {
    limitations.push("stream_ttl_answer_relationship_ambiguous");
    associationSuppressed = true;
  }
  if (stream && responseEnd === undefined) {
    limitations.push("stream_response_time_basis_unknown");
    associationSuppressed = true;
  }
  if (reportedAddressCapped) {
    limitations.push("reported_address_list_cap");
    associationSuppressed = true;
  }
  if (
    !ttlQualified ||
    (ttlScalar === undefined && !structuredTtl) ||
    (stream && reportedTtls.length > 0 && !structuredTtl)
  ) {
    limitations.push("ttl_unqualified_or_missing");
    associationSuppressed = true;
  } else if (
    (ttlScalar !== undefined && ttlScalar <= 0) ||
    answers.some((a) => a.ttl === 0)
  ) {
    limitations.push("ttl_zero_or_negative");
    associationSuppressed = true;
  }
  if (!config.schemaQualified) associationSuppressed = true;
  if (
    config.clockUncertaintySeconds === undefined ||
    !Number.isFinite(config.clockUncertaintySeconds) ||
    config.clockUncertaintySeconds < 0
  ) {
    limitations.push("clock_basis_unknown");
    associationSuppressed = true;
  }
  const answerTtl = answers.reduce<number | undefined>(
    (min, a) => (a.ttl === undefined ? min : Math.min(min ?? a.ttl, a.ttl)),
    undefined,
  );
  const effectiveTtl = answerTtl ?? ttlScalar;
  if (
    owner &&
    owner.valid_end !== undefined &&
    effectiveTtl !== undefined &&
    owner.valid_end < actualResponseTime + Math.max(0, effectiveTtl)
  ) {
    limitations.push("ownership_interval_ends_before_answer_expiry");
    associationSuppressed = true;
  }
  const eventFingerprint = fingerprint(row);
  if (!eventFingerprint) return;
  const attribution: DnsObservation["attribution"] = !client
    ? "context_only"
    : "scoped_client";
  const obs: DnsObservation = {
    schemaVersion: 1,
    source,
    authority,
    scope: config.scope,
    ...(client ? { client } : {}),
    ...(resolver ? { resolver } : {}),
    query: q.original,
    ...(q.comparison ? { comparisonName: q.comparison } : {}),
    queryType: (queryTypes.length ? queryTypes.join(",") : "UNKNOWN").slice(
      0,
      64,
    ),
    shape,
    ...(responseCode ? { responseCode } : {}),
    answers,
    aliases,
    ...(source === "dns_stream"
      ? {
          reportedAddresses: streamAddressValues
            .map(canonicalIp)
            .filter((v): v is string => v !== undefined)
            .slice(0, EVIDENCE_LIMITS.answers),
          ...(reportedTtls.length ? { reportedTtls } : {}),
          ...(ttlScalar !== undefined &&
          ttlScalar >= 0 &&
          ttlScalar <= 4294967295
            ? { ttlSeconds: ttlScalar }
            : {}),
          ...(structuredTtl ? { ttlBasis: "record" as const } : {}),
          ...(responseStart !== undefined && responseStart >= 0
            ? { requestStart: responseStart }
            : {}),
          sourceTimeBasis: interval ? "stream_start_end" : "stream_event_time",
        }
      : {
          reportedAddresses: reportedAddressValues
            .map(canonicalIp)
            .filter((v): v is string => v !== undefined)
            .slice(0, EVIDENCE_LIMITS.answers),
          ...(ttlScalar !== undefined &&
          ttlScalar >= 0 &&
          ttlScalar <= 4294967295
            ? { ttlSeconds: ttlScalar }
            : {}),
          ...(ttlScalar !== undefined &&
          ttlScalar >= 0 &&
          ttlScalar <= 4294967295
            ? { ttlBasis: "rrset_scalar" as const }
            : {}),
          authorityNode: scalar(
            pick(raw, "node_name") ?? pick(flow, "node_name"),
          ),
          sourceTimeBasis: "hubble_flow_time",
        }),
    eventTime: eventTimeValue,
    ...(rowTime !== undefined && rowTime >= 0 ? { rowTime } : {}),
    indexedTime,
    ...(interval && interval.start >= 0 ? { responseInterval: interval } : {}),
    ...(latencySeconds !== undefined ? { latencySeconds } : {}),
    ...(identifier && text(identifier, 255)
      ? { transactionId: identifier }
      : {}),
    ...(uuid && text(uuid, 255) ? { duplicateId: uuid } : {}),
    ...(policy ? { policy } : {}),
    eventFingerprint,
    index: row.index,
    ...(owner &&
    (!stream || responseEnd !== undefined) &&
    config.schemaQualified &&
    config.clockUncertaintySeconds !== undefined &&
    Number.isFinite(config.clockUncertaintySeconds) &&
    owner.valid_from <=
      (interval?.start ?? actualResponseTime) -
        config.clockUncertaintySeconds &&
    (owner.valid_end === undefined ||
      owner.valid_end >
        (interval?.end ?? actualResponseTime) +
          config.clockUncertaintySeconds) &&
    ownerIdsDuring(
      client,
      config.scope,
      (interval?.start ?? actualResponseTime) - config.clockUncertaintySeconds,
      (interval?.end ?? actualResponseTime) + config.clockUncertaintySeconds,
      owners,
    ).size === 1
      ? { clientOwner: owner.entity_id }
      : {}),
    limitations,
    attribution,
    attributionReason: associationSuppressed
      ? limitations.join(", ") || "context_only"
      : "awaiting_compatible_observation",
  };
  // Keep malformed TTL metadata from entering the contract; answers with missing TTL remain visible.
  if (source === "dns_hubble" && ttlScalar !== undefined && ttlScalar < 0)
    limitations.push("invalid_scalar_ttl");
  return {
    observation: obs,
    ttlQualified:
      ttlQualified &&
      ((ttlScalar !== undefined && ttlScalar > 0) || structuredTtl),
    ttlSeconds:
      source === "dns_hubble" || answers.length === 1 ? ttlScalar : undefined,
    duplicatePayload: JSON.stringify(raw),
    associationSuppressed,
  };
}

/** Normalize one explicitly selected DNS source. This is an adapter, not an SPL/query builder. */
export async function normalizeDns(
  source: DnsSource,
  rows: readonly Row[],
  config: DnsAdapterConfig,
  selection: EvidenceSelection,
  owners: readonly IdentityRecord[],
): Promise<{
  records: DnsObservation[];
  rejected: number;
  expansionCapped: number;
}> {
  if (
    !config.scope ||
    config.scope !== selection.scope ||
    !Array.isArray(config.authorities) ||
    !config.authorities.length ||
    !Number.isFinite(config.maxAgeSeconds) ||
    config.maxAgeSeconds < 60 ||
    config.maxAgeSeconds > 86400
  )
    throw new Error("Invalid DNS adapter configuration.");
  if (rows.length > EVIDENCE_LIMITS.input)
    throw new Error("DNS adapter input exceeds its bounded row limit.");
  const seen = new Map<string, Set<string>>();
  const parsed: Parsed[] = [];
  let rejected = 0;
  let expansionCapped = 0;
  for (const row of rows) {
    const item = parseOne(source, row, config, selection, owners);
    if (!item) {
      rejected++;
      continue;
    }
    if (item.observation.limitations.includes("answer_or_alias_cap"))
      expansionCapped++;
    const id = item.observation.duplicateId;
    // UUID duplicates are suppressed only for identical payloads under the same authority/source.
    if (id && config.schemaQualified) {
      const key = `${source}\0${item.observation.authority}\0${id}`;
      const payload = item.duplicatePayload;
      const prior = seen.get(key) ?? new Set<string>();
      if (prior.has(payload)) continue;
      prior.add(payload);
      seen.set(key, prior);
    }
    parsed.push(item);
  }
  const out = parsed.map((p) => p.observation);
  const uncertainty = config.clockUncertaintySeconds ?? Infinity;
  for (const dns of parsed) {
    const d = dns.observation;
    if (dns.associationSuppressed || !dns.ttlQualified) continue;
    const earliestResponse = d.responseInterval?.start ?? d.eventTime;
    const latestResponse = d.responseInterval?.end ?? d.eventTime;
    const ttl = d.answers.reduce<number | undefined>(
      (min, a) => (a.ttl === undefined ? min : Math.min(min ?? a.ttl, a.ttl)),
      undefined,
    );
    // A qualified source TTL is an RRset bound, never an invented per-answer TTL.
    const rowTtl = ttl ?? dns.ttlSeconds;
    if (rowTtl === undefined || rowTtl <= 0) continue;
    const boundedTtl = Math.min(rowTtl, config.maxAgeSeconds);
    const earliestExpiry = earliestResponse + boundedTtl;
    for (const answer of d.answers) {
      const flows = selection.contexts.filter(
        (c) =>
          c.scope === config.scope &&
          c.client === d.client &&
          c.server === answer.address &&
          !c.capped &&
          c.first >= latestResponse + uncertainty &&
          c.first < earliestExpiry - uncertainty &&
          c.last >= c.first,
      );
      for (const context of flows) {
        const identityStart = Math.min(
          earliestResponse - uncertainty,
          context.first - uncertainty,
        );
        const identityEnd = Math.max(
          latestResponse + uncertainty,
          context.last + uncertainty,
        );
        const identities = ownerIdsDuring(
          d.client,
          config.scope,
          identityStart,
          identityEnd,
          owners,
        );
        const dnsOwners = ownerIdsDuring(
          d.client,
          config.scope,
          earliestResponse - uncertainty,
          latestResponse + uncertainty,
          owners,
        );
        const flowOwners = ownerIdsDuring(
          d.client,
          config.scope,
          context.first - uncertainty,
          context.last + uncertainty,
          owners,
        );
        const selectedOwner = context.clientOwner;
        const selectedDnsOwner =
          dnsOwners.size === 1 &&
          [...dnsOwners][0].slice([...dnsOwners][0].indexOf("/") + 1) ===
            selectedOwner;
        const selectedFlowOwner =
          flowOwners.size === 1 &&
          [...flowOwners][0].slice([...flowOwners][0].indexOf("/") + 1) ===
            selectedOwner;
        const ownershipConflict =
          identities.size > 1 ||
          (selectedOwner !== undefined &&
            (dnsOwners.size !== 1 ||
              flowOwners.size !== 1 ||
              !selectedDnsOwner ||
              !selectedFlowOwner));
        if (ownershipConflict) {
          if (!d.limitations.includes("client_ownership_ambiguous"))
            d.limitations.push("client_ownership_ambiguous");
          d.attribution = "context_only";
          d.attributionReason = "client_ownership_ambiguous";
          continue;
        }
        d.attribution = "compatible_observations";
        d.attributionReason =
          context.timeBasis === "connection_open"
            ? "compatible_connection_open_observation"
            : "compatible_flow_observation";
        break;
      }
      if (d.attribution === "compatible_observations") break;
    }
  }
  return { records: out, rejected, expansionCapped };
}
