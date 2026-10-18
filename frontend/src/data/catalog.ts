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
export interface NetworkClientFindRow {
  _key: string;
  native_id?: string;
  client_mac?: string;
  client_ip?: string;
  source: string;
  contract_version?: string;
  access_platform?: string;
  source_authority?: string;
  routing_domain?: string;
  scope?: string;
  cluster?: string;
  source_time?: number;
  source_time_status?: string;
  history_coverage?: string;
  received_time?: number;
  latest_received_time?: number;
  event_type?: string;
  attachment_event_time?: number;
  attachment_received_time?: number;
  attachment_collected_time?: number;
  attachment_status: string;
  mapping_status?: string;
  attachment_basis?: string;
  attachment_device_id?: string;
  attachment_device_name?: string;
  attachment_device_mac?: string;
  device_serial?: string;
  ssid_number?: string;
  quality_reason?: string;
  diagnostic_status?: string;
  diagnostic_reason?: string;
  history_rows?: number;
  simultaneous_claims?: number;
  warning?: string;
}

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
  return rows
    .filter((row) => row._key !== "adm-catalog-empty")
    .map((row) => {
      if (!validKey(row._key))
        throw new Error("Catalog field _key is invalid.");
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
  const byKey = new Map<string, FindRow>();
  for (const row of rows) {
    if (typeof row.warnings === "string" && row.warnings)
      throw new Error(row.warnings);
    if (!validKey(row._key)) throw new Error("Find field _key is invalid.");
    const dimensions = scope(row);
    const invalidScope = scopeError(dimensions);
    const parsed = {
      _key: row._key,
      ...dimensions,
      ...(invalidScope ? { scopeError: invalidScope } : {}),
    };
    const existing = byKey.get(parsed._key);
    if (existing) {
      if (
        fields.some((field) => existing[field] !== parsed[field]) ||
        existing.scopeError !== parsed.scopeError
      )
        throw new Error(
          "Find returned conflicting scope dimensions for one key.",
        );
      continue;
    }
    byKey.set(parsed._key, parsed);
  }
  return [...byKey.values()];
}

export function parseNetworkClientFindRows(
  rows: readonly Record<string, unknown>[],
): NetworkClientFindRow[] {
  const textFields = [
    "contract_version",
    "native_id",
    "client_mac",
    "client_ip",
    "access_platform",
    "source_authority",
    "routing_domain",
    "scope",
    "cluster",
    "event_type",
    "mapping_status",
    "attachment_basis",
    "attachment_device_id",
    "attachment_device_name",
    "attachment_device_mac",
    "device_serial",
    "ssid_number",
    "quality_reason",
    "diagnostic_status",
    "diagnostic_reason",
    "source_time_status",
    "history_coverage",
    "warning",
  ] as const;
  const numericFields = [
    "source_time",
    "received_time",
    "latest_received_time",
    "attachment_event_time",
    "attachment_received_time",
    "attachment_collected_time",
    "history_rows",
    "simultaneous_claims",
  ] as const;
  return rows.map((row) => {
    if (
      row.row_type !== "network_client" ||
      typeof row._key !== "string" ||
      !row._key ||
      typeof row.source !== "string" ||
      typeof row.attachment_status !== "string"
    )
      throw new Error(
        "Network client Find row has invalid identity or status.",
      );
    const result: NetworkClientFindRow = {
      _key: row._key,
      source: row.source,
      attachment_status: row.attachment_status,
    };
    for (const field of textFields) {
      if (row[field] === undefined || row[field] === null || row[field] === "")
        continue;
      if (typeof row[field] !== "string")
        throw new Error(`Network client Find field ${field} is invalid.`);
      result[field] = row[field] as never;
    }
    for (const field of numericFields) {
      if (row[field] === undefined || row[field] === null || row[field] === "")
        continue;
      const value =
        typeof row[field] === "number"
          ? row[field]
          : typeof row[field] === "string" && /^\d+(?:\.\d+)?$/.test(row[field])
            ? Number(row[field])
            : NaN;
      if (!Number.isFinite(value) || value < 0)
        throw new Error(`Network client Find field ${field} is invalid.`);
      if (value > MAX_EPOCH)
        throw new Error(
          `Network client Find field ${field} is outside the epoch range.`,
        );
      result[field] = value as never;
    }
    return result;
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

export function validatedBuildNetworkClientFindSearch(value: string): string {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    !(
      /^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$/.test(value) ||
      /^(?:\d{1,3}\.){3}\d{1,3}$/.test(value)
    )
  )
    throw new Error(
      "Enter an exact IPv4 address or colon-separated MAC address for network client evidence.",
    );
  return `| \`adm_find_network_client("${value}")\``;
}

export const catalogLimitMessage = (maxRows = 5000) =>
  `The application catalog contains more than ${maxRows.toLocaleString()} rows. Narrow the service scope and try again.`;

/** Build a lookup search with an optional exact service prefilter. */
export function validatedBuildCatalogSearch(service?: string): string {
  if (service === undefined) return "| inputlookup adm_app_catalog";
  const invalid = argError("service", service);
  const exact = /^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,254}$/;
  if (invalid || exact.exec(service)?.[0] !== service)
    throw new Error(invalid ?? "Service contains unsupported characters.");
  return `| inputlookup adm_app_catalog WHERE service="${service}"`;
}
