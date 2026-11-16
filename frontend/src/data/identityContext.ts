import { rejectDuplicateKeys } from "./strictJson";
/** Source identity provenance describes observations; it never grants access. */
export interface IdentityContext {
  schemaVersion: 1;
  contract: "qualified_v2";
  authority: string;
  scope: string;
  configRevision: string;
  observedWindow: { start: number; end: number };
}
const object = (value: unknown): value is Record<string, unknown> =>
  !!value && typeof value === "object" && !Array.isArray(value);
const keys = (value: Record<string, unknown>, expected: string[]) =>
  Object.keys(value).sort().join(",") === expected.sort().join(",");
const token = (value: unknown): value is string =>
  typeof value === "string" &&
  /^[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,254}$/.test(value);

export function checkedIdentityContext(
  value: unknown,
  window: { start: number; end: number },
): IdentityContext {
  if (
    !object(value) ||
    !keys(value, [
      "schemaVersion",
      "contract",
      "authority",
      "scope",
      "configRevision",
      "observedWindow",
    ]) ||
    value.schemaVersion !== 1 ||
    value.contract !== "qualified_v2" ||
    !token(value.authority) ||
    !token(value.scope) ||
    typeof value.configRevision !== "string" ||
    !/^[a-f0-9]{64}$/.test(value.configRevision) ||
    !object(value.observedWindow) ||
    !keys(value.observedWindow, ["start", "end"]) ||
    !Number.isSafeInteger(value.observedWindow.start) ||
    !Number.isSafeInteger(value.observedWindow.end) ||
    (value.observedWindow.start as number) < 0 ||
    (value.observedWindow.end as number) <=
      (value.observedWindow.start as number) ||
    value.observedWindow.start !== window.start ||
    value.observedWindow.end !== window.end
  )
    throw new Error(
      "Qualified identity provenance is invalid or belongs to another window.",
    );
  return value as unknown as IdentityContext;
}

export function identityContextFromRow(
  value: unknown,
  window: { start: number; end: number },
): IdentityContext | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  if (typeof value !== "string" || value.length > 4096)
    throw new Error("Qualified identity provenance is malformed.");
  rejectDuplicateKeys(value);
  return checkedIdentityContext(JSON.parse(value) as unknown, window);
}
