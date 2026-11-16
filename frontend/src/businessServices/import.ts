/** Imported business claims are supplemental assertions, not traffic identity. */
export type Criticality = "critical" | "high" | "medium" | "low" | "unknown";
export type Validity =
  | { basis: "source_interval"; from: number; to?: number }
  | { basis: "snapshot_current"; at: number };
export interface Reference {
  label: string;
  url: string;
}
export interface BusinessClaim {
  recordId: string;
  revision: number;
  authority: string;
  snapshotId: string;
  snapshotAt: number;
  serviceId: string;
  serviceName: string;
  memberKind: "service" | "workload" | "asset";
  memberId: string;
  scope: string;
  teamId: string;
  teamName: string;
  criticality: Criticality;
  validity: Validity;
  runbook?: Reference;
  escalation?: Reference;
}
export interface ImportIssue {
  row?: number;
  message: string;
}
export interface ImportPreview {
  claims: BusinessClaim[];
  errors: ImportIssue[];
  conflicts: { rows: [number, number]; reason: string }[];
  conflictCount: number;
}
const ROOT_KEYS = [
  "schema_version",
  "authority",
  "snapshot_id",
  "snapshot_at",
  "records",
];
const ROW_KEYS = [
  "record_id",
  "revision",
  "service_id",
  "service_name",
  "member_kind",
  "member_id",
  "scope",
  "team_id",
  "team_name",
  "criticality",
  "validity_basis",
  "valid_from",
  "valid_to",
  "runbook",
  "escalation",
];
const ID = /^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,254}$/;
const object = (v: unknown): v is Record<string, unknown> =>
  !!v && typeof v === "object" && !Array.isArray(v);
function fields(v: Record<string, unknown>, allowed: string[]) {
  const unknown = Object.keys(v).filter((key) => !allowed.includes(key));
  if (unknown.length) throw new Error(`Unknown field: ${unknown.join(", ")}.`);
}
function text(value: unknown, name: string, id = false): string {
  if (
    typeof value !== "string" ||
    !value.trim() ||
    value !== value.trim() ||
    value.length > 512 ||
    [...value].some(
      (char) => char.charCodeAt(0) < 32 || char.charCodeAt(0) === 127,
    ) ||
    (id && !ID.test(value))
  )
    throw new Error(
      `${name} must be ${id ? "a stable identifier" : "printable text"}.`,
    );
  return value;
}
function timestamp(value: unknown, name: string): number {
  if (typeof value !== "string")
    throw new Error(`${name} must be an ISO timestamp with a timezone.`);
  const match =
    /^(\d{4})-(\d\d)-(\d\d)T(\d\d):(\d\d):(\d\d)(?:\.\d{1,3})?(Z|[+-]\d\d:\d\d)$/.exec(
      value,
    );
  if (!match)
    throw new Error(`${name} must be an ISO timestamp with a timezone.`);
  const [, y, mo, d, h, mi, s, zone] = match;
  const parts = [y, mo, d, h, mi, s].map(Number);
  const [year, month, day, hour, minute, second] = parts;
  const days = new Date(Date.UTC(year, month, 0)).getUTCDate();
  if (
    year < 1970 ||
    month < 1 ||
    month > 12 ||
    day < 1 ||
    day > days ||
    hour > 23 ||
    minute > 59 ||
    second > 59 ||
    (zone !== "Z" &&
      (Number(zone.slice(1, 3)) > 23 || Number(zone.slice(4)) > 59))
  )
    throw new Error(`${name} is not a valid timestamp.`);
  const time = Date.parse(value);
  if (!Number.isFinite(time) || time < 0)
    throw new Error(`${name} is not a valid timestamp.`);
  return time / 1000;
}
function reference(value: unknown, name: string): Reference | undefined {
  if (value === undefined || value === null) return undefined;
  if (!object(value))
    throw new Error(`${name} must contain a label and HTTPS URL.`);
  fields(value, ["label", "url"]);
  const label = text(value.label, `${name}.label`);
  const input = text(value.url, `${name}.url`);
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    throw new Error(`${name}.url must be a valid HTTPS URL.`);
  }
  if (
    url.protocol !== "https:" ||
    !url.hostname ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    input.includes("\\")
  )
    throw new Error(
      `${name}.url must be HTTPS without credentials, query, or fragment.`,
    );
  return { label, url: url.href };
}

/** Detect repeated keys before JSON.parse can silently discard a conflicting value. */
function rejectDuplicateKeys(input: string) {
  let i = 0;
  const ws = () => {
    while (/\s/.test(input[i] ?? "") && i < input.length) i++;
  };
  const string = (): string => {
    const start = i++;
    while (i < input.length) {
      if (input[i] === "\\") {
        i += 2;
        continue;
      }
      if (input[i++] === '"')
        return JSON.parse(input.slice(start, i)) as string;
    }
    throw new Error("Invalid JSON.");
  };
  const value = (depth: number): void => {
    if (depth > 20) throw new Error("JSON nesting is too deep.");
    ws();
    if (input[i] === '"') {
      string();
      return;
    }
    if (input[i] === "{") {
      i++;
      ws();
      const keys = new Set<string>();
      if (input[i] === "}") {
        i++;
        return;
      }
      while (i < input.length) {
        ws();
        if (input[i] !== '"') throw new Error("Invalid JSON.");
        const key = string();
        if (keys.has(key)) throw new Error(`Duplicate JSON field: ${key}.`);
        keys.add(key);
        ws();
        if (input[i++] !== ":") throw new Error("Invalid JSON.");
        value(depth + 1);
        ws();
        if (input[i] === "}") {
          i++;
          return;
        }
        if (input[i++] !== ",") throw new Error("Invalid JSON.");
      }
      throw new Error("Invalid JSON.");
    }
    if (input[i] === "[") {
      i++;
      ws();
      if (input[i] === "]") {
        i++;
        return;
      }
      while (i < input.length) {
        value(depth + 1);
        ws();
        if (input[i] === "]") {
          i++;
          return;
        }
        if (input[i++] !== ",") throw new Error("Invalid JSON.");
      }
      throw new Error("Invalid JSON.");
    }
    const match =
      /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(
        input.slice(i),
      );
    if (!match) throw new Error("Invalid JSON.");
    i += match[0].length;
  };
  value(0);
  ws();
  if (i !== input.length) throw new Error("Invalid JSON.");
}

function overlaps(a: BusinessClaim, b: BusinessClaim): boolean {
  if (
    a.validity.basis === "snapshot_current" ||
    b.validity.basis === "snapshot_current"
  ) {
    const point =
      a.validity.basis === "snapshot_current"
        ? a.validity.at
        : (b.validity as { at: number }).at;
    const interval = a.validity.basis === "source_interval" ? a : b;
    return interval.validity.basis === "snapshot_current"
      ? a.snapshotAt === b.snapshotAt
      : point >= interval.validity.from &&
          point <
            Math.min(
              interval.validity.to ?? Infinity,
              interval.snapshotAt + 0.001,
            );
  }
  return (
    Math.max(a.validity.from, b.validity.from) <
    Math.min(
      a.validity.to ?? Infinity,
      b.validity.to ?? Infinity,
      a.snapshotAt + 0.001,
      b.snapshotAt + 0.001,
    )
  );
}

/** Validate the entire batch. Invalid rows do not produce an applicable partial import. */
export function previewBusinessServiceImport(input: string): ImportPreview {
  const fail = (message: string): ImportPreview => ({
    claims: [],
    errors: [{ message }],
    conflicts: [],
    conflictCount: 0,
  });
  if (new TextEncoder().encode(input).length > 2_000_000)
    return fail("Import exceeds 2 MB.");
  let root: unknown;
  try {
    rejectDuplicateKeys(input);
    root = JSON.parse(input);
  } catch (e) {
    return fail(e instanceof Error ? e.message : "Invalid JSON.");
  }
  if (!object(root)) return fail("Import must be a JSON object.");
  try {
    fields(root, ROOT_KEYS);
    if (root.schema_version !== 1) throw new Error("schema_version must be 1.");
    const authority = text(root.authority, "authority", true);
    const snapshotId = text(root.snapshot_id, "snapshot_id", true);
    const snapshotAt = timestamp(root.snapshot_at, "snapshot_at");
    if (
      !Array.isArray(root.records) ||
      root.records.length === 0 ||
      root.records.length > 1000
    )
      throw new Error("records must contain 1–1,000 rows.");
    const claims: BusinessClaim[] = [];
    const errors: ImportIssue[] = [];
    root.records.forEach((row, index) => {
      try {
        if (!object(row)) throw new Error("Record must be an object.");
        fields(row, ROW_KEYS);
        const basis = row.validity_basis;
        let validity: Validity;
        if (basis === "snapshot_current") {
          if (row.valid_from != null || row.valid_to != null)
            throw new Error(
              "Current-only records cannot include interval dates.",
            );
          validity = { basis, at: snapshotAt };
        } else if (basis === "source_interval") {
          const from = timestamp(row.valid_from, "valid_from");
          const to =
            row.valid_to == null
              ? undefined
              : timestamp(row.valid_to, "valid_to");
          if (from > snapshotAt || (to !== undefined && to <= from))
            throw new Error(
              "Validity interval must start by the snapshot and end after its start.",
            );
          validity = { basis, from, ...(to !== undefined ? { to } : {}) };
        } else
          throw new Error(
            "validity_basis must be source_interval or snapshot_current.",
          );
        if (!Number.isSafeInteger(row.revision) || (row.revision as number) < 0)
          throw new Error("revision must be a nonnegative integer.");
        if (!["service", "workload", "asset"].includes(String(row.member_kind)))
          throw new Error("member_kind must be service, workload, or asset.");
        if (
          !["critical", "high", "medium", "low", "unknown"].includes(
            String(row.criticality),
          )
        )
          throw new Error(
            "criticality must be critical, high, medium, low, or unknown.",
          );
        claims.push({
          recordId: text(row.record_id, "record_id", true),
          revision: row.revision as number,
          authority,
          snapshotId,
          snapshotAt,
          serviceId: text(row.service_id, "service_id", true),
          serviceName: text(row.service_name, "service_name"),
          memberKind: row.member_kind as BusinessClaim["memberKind"],
          memberId: text(row.member_id, "member_id", true),
          scope: text(row.scope, "scope", true),
          teamId: text(row.team_id, "team_id", true),
          teamName: text(row.team_name, "team_name"),
          criticality: row.criticality as Criticality,
          validity,
          runbook: reference(row.runbook, "runbook"),
          escalation: reference(row.escalation, "escalation"),
        });
      } catch (e) {
        errors.push({
          row: index + 1,
          message: e instanceof Error ? e.message : "Invalid record.",
        });
      }
    });
    if (errors.length)
      return { claims: [], errors, conflicts: [], conflictCount: 0 };
    const conflicts: ImportPreview["conflicts"] = [];
    let conflictCount = 0;
    const latest = new Map<string, number>();
    for (const claim of claims)
      latest.set(
        claim.recordId,
        Math.max(latest.get(claim.recordId) ?? -1, claim.revision),
      );
    const conflict = (i: number, j: number, reason: string) => {
      conflictCount++;
      if (conflicts.length < 500)
        conflicts.push({ rows: [i + 1, j + 1], reason });
    };
    for (let i = 0; i < claims.length; i++)
      for (let j = i + 1; j < claims.length; j++) {
        const a = claims[i],
          b = claims[j];
        if (a.recordId === b.recordId && a.revision === b.revision) {
          conflict(i, j, "The same record revision appears more than once.");
        } else if (
          a.revision === latest.get(a.recordId) &&
          b.revision === latest.get(b.recordId) &&
          a.serviceId === b.serviceId &&
          overlaps(a, b) &&
          (a.teamId !== b.teamId || a.criticality !== b.criticality)
        ) {
          conflict(
            i,
            j,
            "Overlapping service ownership or criticality claims disagree.",
          );
        }
      }
    return { claims, errors, conflicts, conflictCount };
  } catch (e) {
    return fail(e instanceof Error ? e.message : "Invalid import.");
  }
}
