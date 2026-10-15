import { argError } from "../provider";
import type { GraphArgs, Row } from "../rows";
export const SCOPE_FIELDS = [
  "environment",
  "cluster",
  "namespace",
  "service",
] as const;
export interface ScopeOption extends GraphArgs {
  last_seen: number;
  pods: number;
}
export function parseScopes(rows: readonly Row[]): ScopeOption[] {
  return rows.map((row) => {
    const dimensions = Object.fromEntries(
      SCOPE_FIELDS.map((key) => {
        if (typeof row[key] !== "string")
          throw new Error("Scope options have missing dimensions.");
        return [key, row[key]];
      }),
    ) as unknown as GraphArgs;
    const last_seen = Number(row.last_seen),
      pods = Number(row.pods);
    if (
      (typeof row.last_seen !== "string" &&
        typeof row.last_seen !== "number") ||
      (typeof row.pods !== "string" && typeof row.pods !== "number") ||
      row.last_seen === "" ||
      row.pods === "" ||
      !Number.isFinite(last_seen) ||
      last_seen < 0 ||
      !Number.isSafeInteger(pods) ||
      pods < 0
    )
      throw new Error("Scope options have invalid counts or timestamps.");
    return { ...dimensions, last_seen, pods };
  });
}
export function scopeValues(
  rows: readonly ScopeOption[],
  args: GraphArgs,
  key: keyof GraphArgs,
): string[] {
  const index = SCOPE_FIELDS.indexOf(key);
  return [
    ...new Set(
      rows
        .filter((row) =>
          SCOPE_FIELDS.slice(0, index).every(
            (parent) => row[parent] === args[parent],
          ),
        )
        .map((row) => row[key]),
    ),
  ].sort();
}
export function cascadeScope(
  args: GraphArgs,
  key: keyof GraphArgs,
  value: string,
): GraphArgs {
  const next = { ...args, [key]: value };
  for (const child of SCOPE_FIELDS.slice(SCOPE_FIELDS.indexOf(key) + 1))
    next[child] = "";
  return next;
}
export const scopeError = (args: GraphArgs) =>
  SCOPE_FIELDS.map((key) => argError(key, args[key])).find(Boolean);
