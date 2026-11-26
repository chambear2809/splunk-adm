import type { Row } from "../rows";
import type { SupplementalSourceConfiguration } from "../data/evidenceConfig";
import {
  EVIDENCE_LIMITS,
  literal,
  normalizeIp,
  routingScope,
  type EvidenceSelection,
  type EvidenceWindow,
} from "../data/evidence";
import type { SupplementalResult } from "../data/supplementalEvidence";

export const MAX_EPOCH = 253402300799;
const INPUT_LIMIT = EVIDENCE_LIMITS.input;
const OUTPUT_LIMIT = EVIDENCE_LIMITS.records;
export const RECORD_BYTES = EVIDENCE_LIMITS.recordBytes;

/** What every ecosystem adapter pins before it searches or normalizes. */
export interface SourceIdentity {
  source: string;
  label: string;
  observerKind: string;
  sourcetypes: readonly string[];
}

export function indexSelector(
  indexes: readonly string[],
  rejectPlaceholder = false,
): string {
  if (
    !indexes.length ||
    indexes.length > 16 ||
    indexes.some((index) => !/^[a-z][a-z0-9_-]{0,79}$/.test(index)) ||
    new Set(indexes).size !== indexes.length ||
    (rejectPlaceholder && indexes.includes("unconfigured_optional"))
  )
    throw new Error("Invalid ecosystem index configuration.");
  const terms = indexes.map((index) => "index=" + index).join(" OR ");
  return indexes.length === 1 ? terms : "(" + terms + ")";
}

/** Exactly one verified mapping of the source's observer kind per authority, in scope. */
export function verifiedAuthorities(
  identity: SourceIdentity,
  config: SupplementalSourceConfiguration,
  scope?: string,
): string[] {
  if (
    config.source !== identity.source ||
    !Array.isArray(config.authorities) ||
    !config.authorities.length ||
    config.authorities.length > 32 ||
    new Set(config.authorities).size !== config.authorities.length ||
    !Array.isArray(config.mappings)
  )
    throw new Error("Observer mapping is unavailable.");
  for (const authority of config.authorities) {
    literal(authority);
    const mappings = config.mappings.filter(
      (mapping) =>
        mapping.observer_kind === identity.observerKind &&
        mapping.observer === authority,
    );
    if (
      authority !== authority.toLowerCase() ||
      mappings.length !== 1 ||
      mappings[0].mapping_status !== "verified" ||
      (scope !== undefined && mappings[0].scope !== scope)
    )
      throw new Error("Observer scope is not uniquely verified.");
    routingScope(mappings[0].scope);
  }
  return [...config.authorities];
}

export function assertActiveSource(
  identity: SourceIdentity,
  config: SupplementalSourceConfiguration,
  selection: EvidenceSelection,
): string[] {
  if (
    config.source !== identity.source ||
    config.state !== "active" ||
    config.error ||
    config.schemaQualified !== true
  )
    throw new Error(
      identity.label + " evidence is not active and schema-qualified.",
    );
  indexSelector(config.indexes);
  return verifiedAuthorities(identity, config, selection.scope);
}

export function quotedList(values: readonly string[]): string {
  return values.map((value) => '"' + literal(value) + '"').join(",");
}

/** Index, sourcetype and verified-host restriction shared by every adapter. */
export function baseSearch(
  identity: SourceIdentity,
  config: SupplementalSourceConfiguration,
  authorities: readonly string[],
): string {
  return (
    "search " +
    indexSelector(config.indexes) +
    " sourcetype IN (" +
    quotedList(identity.sourcetypes) +
    ") host IN (" +
    quotedList(authorities) +
    ")"
  );
}

/** A JavaScript-compatible PCRE subset, emitted as an SPL `rex` string. */
export function splRex(pattern: string, field = "_raw"): string {
  if (!/^[a-z_]{1,32}$/.test(field) || pattern.includes("\\\\"))
    throw new Error("Invalid extraction pattern.");
  return "| rex field=" + field + ' "' + pattern.replace(/"/g, '\\"') + '"';
}

export function lateWindow(
  selection: EvidenceSelection,
  seconds: number,
): EvidenceWindow {
  return {
    start: selection.window.start,
    end: Math.min(MAX_EPOCH, selection.window.end + seconds),
  };
}

/** Exact-address match on any listed column, with IPv4-mapped IPv6 forms. */
export function cidrPredicate(
  addresses: readonly string[],
  columns: readonly string[],
): string {
  if (!addresses.length || addresses.length > EVIDENCE_LIMITS.addresses)
    throw new Error("Narrow the selected addresses.");
  if (
    !columns.length ||
    columns.some((column) => !/^[a-z][a-z0-9_]{1,39}$/.test(column))
  )
    throw new Error("Invalid address columns.");
  return [...new Set(addresses.map(normalizeIp))]
    .flatMap((address) => {
      const candidates = address.includes(":")
        ? [address]
        : [address, "::ffff:" + address];
      return columns.map(
        (column) =>
          "(" +
          candidates
            .map(
              (candidate) =>
                'cidrmatch("' +
                candidate +
                "/" +
                (candidate.includes(":") ? 128 : 32) +
                '",' +
                column +
                ")",
            )
            .join(" OR ") +
          ")",
      );
    })
    .join(" OR ");
}

const DEFAULT_FINGERPRINT =
  "if(isnotnull(_bkt) AND isnotnull(_cd),sha256(json_array(index,_bkt,_cd)),null())";

/**
 * Bounded tail: newest 10,001 inputs, at most 64 returned, allowlisted
 * columns only and a completion row that accounts for every transported row.
 */
export function supplementalTail(
  columns: readonly string[],
  oversized = "len(_raw)>" + RECORD_BYTES,
  fingerprintExpression = DEFAULT_FINGERPRINT,
): string[] {
  return [
    "| head " + (INPUT_LIMIT + 1),
    "| eval event_time_epoch=tonumber(_time), event_fingerprint=" +
      fingerprintExpression +
      ", oversized=if(" +
      oversized +
      ",1,0)",
    "| eventstats count AS input_count sum(oversized) AS oversized_count",
    "| sort 0 - _time index host event_fingerprint",
    "| head " + OUTPUT_LIMIT,
    "| fields " +
      [
        ...columns,
        "host",
        "index",
        "sourcetype",
        "event_fingerprint",
        "event_time_epoch",
        "_time",
        "_indextime",
        "input_count",
        "oversized_count",
        "oversized",
      ].join(" "),
    "| fields - _raw",
    '| eval kind="supplemental_record"',
    '| appendpipe [| stats count AS returned_count max(input_count) AS input_count max(oversized_count) AS oversized | eval kind="supplemental_completion",schema_version=1,input_count=coalesce(input_count,0),input_capped=if(coalesce(input_count,0)>' +
      INPUT_LIMIT +
      ",1,0),oversized=coalesce(oversized,0)]",
  ];
}

/** One printable value of at most `maximum` characters, or undefined. */
export function first(
  row: Row,
  column: string,
  maximum = 255,
): string | undefined {
  const value = row[column];
  const item = Array.isArray(value)
    ? value.length === 1
      ? value[0]
      : Symbol.for("multivalue")
    : value;
  if (item === undefined || item === null || item === "") return undefined;
  if (typeof item === "number" && Number.isFinite(item)) return String(item);
  if (
    typeof item !== "string" ||
    item.length > maximum ||
    Array.from(item).some((character) => {
      const code = character.charCodeAt(0);
      return code < 32 || code === 127;
    })
  )
    throw new Error("Projected field is invalid or multivalued.");
  return item;
}

/** Like `first`, with the producer's "-" placeholder read as not reported. */
export function reported(row: Row, column: string): string | undefined {
  const value = first(row, column);
  return value === undefined || value === "-" ? undefined : value;
}

export function parseInteger(
  value: string | undefined,
  maximum: number,
): number | undefined {
  if (value === undefined) return undefined;
  if (!/^\d{1,19}$/.test(value)) throw new Error("Invalid number.");
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed > maximum)
    throw new Error("Number exceeds its supported range.");
  return parsed;
}

export function epoch(value: unknown): number | undefined {
  const item = Array.isArray(value) && value.length === 1 ? value[0] : value;
  if (
    (typeof item !== "number" && typeof item !== "string") ||
    !/^\d{1,12}(?:\.\d{1,9})?$/.test(String(item))
  )
    return undefined;
  const parsed = Number(item);
  return parsed >= 0 && parsed <= MAX_EPOCH ? parsed : undefined;
}

export interface Endpoint {
  ip: string;
  port?: number;
}

/** `ip:port`, `[ipv6]:port` or bare `ipv6:port` (the last colon separates the port). */
export function socketValue(value: string): Endpoint {
  const bracket = /^\[([0-9A-Fa-f:.]{2,45})\]:(\d{1,5})$/.exec(value);
  const split = value.lastIndexOf(":");
  const [ip, port] = bracket
    ? [bracket[1], bracket[2]]
    : split > 0
      ? [value.slice(0, split), value.slice(split + 1)]
      : ["", ""];
  if (!/^\d{1,5}$/.test(port)) throw new Error("Invalid socket.");
  return { ip: normalizeIp(ip), port: parseInteger(port, 65535)! };
}

function civil(
  year: number,
  month: number,
  day: number,
  hour: number,
  minute: number,
  second: number,
): number {
  const parsed = Date.UTC(year, month - 1, day, hour, minute, second) / 1000;
  const check = new Date(parsed * 1000);
  if (
    check.getUTCFullYear() !== year ||
    check.getUTCMonth() !== month - 1 ||
    check.getUTCDate() !== day ||
    hour > 23 ||
    minute > 59 ||
    second > 59
  )
    throw new Error("Invalid calendar time.");
  return parsed;
}

/** "YYYY/MM/DD HH:MM:SS" with no zone, read as a naive clock value. */
export function slashNaiveSeconds(value: string): number {
  const match = /^(\d{4})\/(\d{2})\/(\d{2}) (\d{2}):(\d{2}):(\d{2})$/.exec(
    value,
  );
  if (!match) throw new Error("Unsupported naive time format.");
  const [year, month, day, hour, minute, second] = match.slice(1).map(Number);
  return civil(year, month, day, hour, minute, second);
}

/**
 * ISO 8601 / RFC 3339 in UTC: `Z` is required unless `zoneOptional`, in which
 * case a missing designator is read as UTC (stated per source).
 */
export function isoSeconds(value: string, zoneOptional = false): number {
  const match =
    /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z?)$/.exec(
      value,
    );
  if (!match || (!zoneOptional && match[8] !== "Z"))
    throw new Error("Unsupported ISO 8601 time.");
  const [year, month, day, hour, minute, second] = match
    .slice(1, 7)
    .map(Number);
  return (
    civil(year, month, day, hour, minute, second) +
    (match[7] ? Number("0." + match[7]) : 0)
  );
}

export interface RecordOrigin {
  authority: string;
  sourcetype: string;
  scope: string;
  index: string;
  eventFingerprint: string;
  rowTime: number;
  indexedTime: number;
}

/** Host, sourcetype, index, fingerprint and times every returned row must carry. */
export function recordOrigin(
  identity: SourceIdentity,
  config: SupplementalSourceConfiguration,
  authorities: readonly string[],
  row: Row,
): RecordOrigin {
  if (Number(row.oversized) === 1) throw new Error("Oversized record.");
  const authority = typeof row.host === "string" ? row.host : "";
  if (!authorities.includes(authority))
    throw new Error("Record authority is outside source configuration.");
  const sourcetype = typeof row.sourcetype === "string" ? row.sourcetype : "";
  if (!identity.sourcetypes.includes(sourcetype))
    throw new Error("Unexpected sourcetype.");
  if (
    typeof row.index !== "string" ||
    !config.indexes.includes(row.index) ||
    typeof row.event_fingerprint !== "string" ||
    !/^[a-f0-9]{64}$/.test(row.event_fingerprint)
  )
    throw new Error("Record origin fingerprint is invalid.");
  const rowTime = epoch(row.event_time_epoch);
  const indexedTime = epoch(row._indextime);
  if (rowTime === undefined || indexedTime === undefined)
    throw new Error("Record event or index time is missing.");
  const scope = config.mappings.find(
    (mapping) =>
      mapping.observer_kind === identity.observerKind &&
      mapping.observer === authority,
  )!.scope;
  return {
    authority,
    sourcetype,
    scope,
    index: row.index,
    eventFingerprint: row.event_fingerprint,
    rowTime,
    indexedTime,
  };
}

/** Names of the candidate endpoints whose address is one of the selected ones. */
export function matchedFields<T extends string>(
  selected: ReadonlySet<string>,
  candidates: readonly (readonly [T, Endpoint | undefined])[],
): T[] {
  return candidates
    .filter(([, value]) => value && selected.has(value.ip))
    .map(([name]) => name);
}

/** Visible-only summaries are lower bounds whenever any input was not shown. */
export function isLowerBound<T>(result: SupplementalResult<T>): boolean {
  return (
    result.state !== "complete" ||
    result.inputCapped ||
    result.outputCapped ||
    result.rejected > 0 ||
    result.oversized > 0 ||
    result.configurationChanged
  );
}

export const PROTOCOL_NAMES: Record<number, string> = {
  1: "icmp",
  6: "tcp",
  17: "udp",
  47: "gre",
  50: "esp",
  58: "ipv6-icmp",
};

export function ianaProtocol(value: string | undefined): string {
  const number = parseInteger(value, 255);
  if (number === undefined) throw new Error("Protocol is missing.");
  return PROTOCOL_NAMES[number] ?? "ip-" + number;
}
