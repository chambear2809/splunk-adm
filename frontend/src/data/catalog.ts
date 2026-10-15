import { argError } from "../provider";
import type { GraphArgs } from "../rows";

export interface CatalogRow extends GraphArgs {
  _key: string;
  scopeError?: string;
  pods?: number;
  peers?: number;
  conversations_1h?: number;
  blocked_1h?: number;
  unknown_peers_1h?: number;
  first_seen?: number;
  last_seen?: number;
  updated?: number;
  window_start?: number;
  window_end?: number;
}
export type FindRow = Pick<
  CatalogRow,
  "_key" | "service" | "environment" | "cluster" | "namespace"
> & { scopeError?: string };

const fields = ["service", "environment", "cluster", "namespace"] as const;
const metricFields = [
  "pods",
  "peers",
  "conversations_1h",
  "blocked_1h",
  "unknown_peers_1h",
  "first_seen",
  "last_seen",
  "updated",
  "window_start",
  "window_end",
] as const;
const timestampFields = new Set([
  "first_seen",
  "last_seen",
  "updated",
  "window_start",
  "window_end",
]);
const keyPattern = /^[a-f0-9]{64}$/;
const validKey = (value: unknown): value is string =>
  typeof value === "string" && keyPattern.exec(value)?.[0] === value;
const MAX_EPOCH = 253402300799;

const integer = (value: unknown, name: string): number | undefined => {
  if (value === undefined || value === null) return undefined;
  if (typeof value === "string" && value.trim() === "")
    throw new Error(`Catalog field ${name} must be a nonnegative integer.`);
  if (
    (typeof value !== "number" && typeof value !== "string") ||
    (typeof value === "string" && /^\d+$/.exec(value)?.[0] !== value)
  )
    throw new Error(`Catalog field ${name} must be a nonnegative integer.`);
  const parsed = typeof value === "number" ? value : Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0)
    throw new Error(`Catalog field ${name} must be a nonnegative integer.`);
  if (timestampFields.has(name) && parsed > MAX_EPOCH)
    throw new Error(`Catalog field ${name} is outside the epoch range.`);
  return parsed;
};
const text = (value: unknown, name: string): string => {
  if (typeof value !== "string")
    throw new Error(`Catalog field ${name} is invalid.`);
  return value;
};
function scope(row: Record<string, unknown>): GraphArgs {
  return Object.fromEntries(
    fields.map((field) => [field, text(row[field], field)]),
  ) as unknown as GraphArgs;
}
function scopeError(result: GraphArgs): string | undefined {
  for (const field of fields) {
    if (!result[field] || argError(field, result[field]))
      return (
        argError(field, result[field]) ?? `${field} is missing from this scope.`
      );
  }
  return undefined;
}
function validateRelations(result: CatalogRow): CatalogRow {
  if (
    result.first_seen !== undefined &&
    result.last_seen !== undefined &&
    result.first_seen > result.last_seen
  )
    throw new Error("Catalog timestamps are out of order.");
  if (
    result.window_start !== undefined &&
    result.window_end !== undefined &&
    result.window_start > result.window_end
  )
    throw new Error("Catalog observation window is out of order.");
  if (
    result.blocked_1h !== undefined &&
    result.conversations_1h !== undefined &&
    result.blocked_1h > result.conversations_1h
  )
    throw new Error("Blocked conversations exceed conversations.");
  if (
    result.unknown_peers_1h !== undefined &&
    result.peers !== undefined &&
    result.unknown_peers_1h > result.peers
  )
    throw new Error("Unknown peers exceed peers.");
  return result;
}

export function parseCatalogRows(
  rows: readonly Record<string, unknown>[],
): CatalogRow[] {
  return rows.map((row) => {
    if (!validKey(row._key)) throw new Error("Catalog field _key is invalid.");
    const dimensions = scope(row);
    const invalidScope = scopeError(dimensions);
    const result = {
      _key: row._key,
      ...dimensions,
      ...(invalidScope ? { scopeError: invalidScope } : {}),
    } as CatalogRow;
    for (const field of metricFields)
      result[field] = integer(row[field], field);
    return validateRelations(result);
  });
}

export function createScopeCatalogRows(
  rows: readonly Record<string, unknown>[],
): CatalogRow[] {
  return rows.map((row) => {
    const dimensions = scope(row);
    const key = JSON.stringify(fields.map((field) => dimensions[field]));
    const invalidScope = scopeError(dimensions);
    return {
      _key: `scope:${key}`,
      ...dimensions,
      ...(invalidScope ? { scopeError: invalidScope } : {}),
    };
  });
}

export function parseFindRows(
  rows: readonly Record<string, unknown>[],
): FindRow[] {
  return rows.map((row) => {
    if (typeof row.warnings === "string" && row.warnings)
      throw new Error(row.warnings);
    if (!validKey(row._key)) throw new Error("Find field _key is invalid.");
    const dimensions = scope(row);
    const invalidScope = scopeError(dimensions);
    return {
      _key: row._key,
      ...dimensions,
      ...(invalidScope ? { scopeError: invalidScope } : {}),
    };
  });
}

export function validatedBuildFindSearch(value: string): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > 255 ||
    !/^[A-Za-z0-9:.][A-Za-z0-9._:/@-]{0,254}$/.test(value) ||
    value.match(/^[A-Za-z0-9:.][A-Za-z0-9._:/@-]{0,254}$/)?.[0] !== value
  )
    throw new Error("Find value contains unsupported characters.");
  return `| \`adm_find("${value}")\``;
}
