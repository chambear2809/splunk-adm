/** Splunk Observability Cloud realm identifiers used in product origins. */
export const OBSERVABILITY_REALM_PATTERN = /^[a-z][a-z0-9]{0,7}$/;

/** True only for documented realm tokens such as us0, eu1 or au0. */
export function isObservabilityRealm(
  value: string | undefined | null,
): boolean {
  return typeof value === "string" && OBSERVABILITY_REALM_PATTERN.test(value);
}

/** Product UI origin for a verified realm; never follows event-provided URLs. */
export function observabilityRealmOrigin(realm: string): string | undefined {
  if (!isObservabilityRealm(realm)) return undefined;
  return `https://app.${realm}.observability.splunkcloud.com`;
}
