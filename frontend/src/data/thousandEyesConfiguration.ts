import {
  isObject,
  literal,
  normalizeIp,
  routingScope,
  validText,
  type EvidenceSelection,
} from "./evidence";
import type { SupplementalSourceConfiguration } from "./evidenceConfig";
import type {
  ThousandEyesBinding,
  ThousandEyesFamily,
  ThousandEyesTarget,
} from "./thousandEyesTypes";

export const THOUSANDEYES_SOURCE = "thousandeyes" as const;
export const THOUSANDEYES_OBSERVER_KIND = "thousandeyes_account_group";
export const THOUSANDEYES_ADAPTER_VERSION = "0.9.0";

export interface ThousandEyesSourceMapping {
  authority: string;
  accountGroupId: string;
  scope: string;
  families: ThousandEyesFamily[];
  streamAccountId?: string;
  alertAccountId?: string;
  organizationId?: string;
  bindings: ThousandEyesBinding[];
  pathSources: { index: string; source: string }[];
  origin?: string;
}

export function parseThousandEyesFamilies(json: string): ThousandEyesFamily[] {
  if (typeof json !== "string" || json.length > 256)
    throw new Error("Invalid ThousandEyes family selection.");
  const value: unknown = JSON.parse(json);
  if (
    !Array.isArray(value) ||
    !value.length ||
    value.length > 6 ||
    !value.every((item) =>
      ["metric", "path", "trace", "event", "alert", "activity"].includes(item),
    ) ||
    new Set(value).size !== value.length
  )
    throw new Error("Select the exact qualified ThousandEyes input families.");
  return [...value].sort() as ThousandEyesFamily[];
}

export function thousandEyesNativeId(value: unknown): string {
  if (
    typeof value !== "string" ||
    !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value)
  )
    throw new Error("Configure one literal ThousandEyes native ID.");
  return value;
}

export function thousandEyesAccountGroupId(value: unknown): string {
  if (typeof value !== "string" || !/^[1-9][0-9]{0,19}$/.test(value))
    throw new Error("Configure the native ThousandEyes account-group ID.");
  return value;
}

export function thousandEyesTarget(value: unknown): ThousandEyesTarget {
  if (!isObject(value)) throw new Error("Invalid ThousandEyes target.");
  if (
    Object.keys(value).some(
      (key) => !["ip", "hostname", "protocol", "port"].includes(key),
    )
  )
    throw new Error("Unknown ThousandEyes target field.");
  const target: ThousandEyesTarget = {};
  if (value.ip !== undefined) {
    if (typeof value.ip !== "string")
      throw new Error("Invalid target address.");
    target.ip = normalizeIp(value.ip);
  }
  if (value.hostname !== undefined) {
    if (
      typeof value.hostname !== "string" ||
      value.hostname.length > 253 ||
      !/^(?=.{1,253}$)[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/i.test(
        value.hostname,
      ) ||
      value.hostname.includes("..")
    )
      throw new Error("Invalid target hostname.");
    target.hostname = value.hostname.toLowerCase();
  }
  if (!target.ip && !target.hostname)
    throw new Error("Configure a literal target address or hostname.");
  if (value.protocol !== undefined) {
    if (
      typeof value.protocol !== "string" ||
      !/^[a-z][a-z0-9-]{0,31}$/.test(value.protocol)
    )
      throw new Error("Invalid target protocol.");
    target.protocol = value.protocol;
  }
  if (value.port !== undefined) {
    if (
      typeof value.port !== "number" ||
      !Number.isInteger(value.port) ||
      value.port < 1 ||
      value.port > 65535
    )
      throw new Error("Invalid target port.");
    target.port = value.port;
  }
  return target;
}

export function parseThousandEyesBindings(
  json: string,
  authority: string,
  accountGroupId: string,
  scope: string,
): ThousandEyesBinding[] {
  if (typeof json !== "string" || json.length > 65536)
    throw new Error("ThousandEyes bindings exceed the configuration budget.");
  const values: unknown = JSON.parse(json);
  if (!Array.isArray(values) || values.length > 64)
    throw new Error(
      "Configure at most 64 ThousandEyes bindings per authority.",
    );
  const ids = new Set<string>();
  return values.map((value): ThousandEyesBinding => {
    if (
      !isObject(value) ||
      Object.keys(value).some(
        (key) =>
          ![
            "id",
            "authority",
            "accountGroupId",
            "scope",
            "testId",
            "agentId",
            "target",
            "endpointAddresses",
            "application",
            "validFrom",
            "validTo",
            "configurationId",
            "agentLocation",
          ].includes(key),
      ) ||
      value.authority !== authority ||
      value.accountGroupId !== accountGroupId ||
      value.scope !== scope ||
      typeof value.validFrom !== "number" ||
      typeof value.validTo !== "number" ||
      !Number.isFinite(value.validFrom) ||
      !Number.isFinite(value.validTo) ||
      value.validFrom < 0 ||
      value.validTo <= value.validFrom ||
      value.validTo > 253402300799 ||
      !Array.isArray(value.endpointAddresses) ||
      !value.endpointAddresses.length ||
      value.endpointAddresses.length > 8 ||
      !value.endpointAddresses.every((ip) => typeof ip === "string")
    )
      throw new Error("Invalid time-qualified ThousandEyes binding.");
    const id = thousandEyesNativeId(value.id);
    if (ids.has(id)) throw new Error("Conflicting ThousandEyes binding IDs.");
    ids.add(id);
    const addresses = value.endpointAddresses.map(normalizeIp);
    if (new Set(addresses).size !== addresses.length)
      throw new Error("Duplicate ThousandEyes binding addresses.");
    let application: ThousandEyesBinding["application"];
    if (value.application !== undefined) {
      if (
        !isObject(value.application) ||
        Object.keys(value.application).length !== 4
      )
        throw new Error("Invalid ThousandEyes application binding.");
      const fields = [
        "service",
        "environment",
        "cluster",
        "namespace",
      ] as const;
      const configuredApplication = value.application;
      application = Object.fromEntries(
        fields.map((field) => [
          field,
          literal(configuredApplication[field] as string),
        ]),
      ) as unknown as NonNullable<ThousandEyesBinding["application"]>;
    }
    if (
      value.agentLocation !== undefined &&
      !validText(value.agentLocation, 255)
    )
      throw new Error("Invalid configured agent location.");
    return {
      id,
      authority: literal(authority),
      accountGroupId: thousandEyesAccountGroupId(accountGroupId),
      scope: routingScope(scope),
      testId: thousandEyesNativeId(value.testId),
      agentId: thousandEyesNativeId(value.agentId),
      target: thousandEyesTarget(value.target),
      endpointAddresses: addresses,
      ...(application ? { application } : {}),
      validFrom: value.validFrom,
      validTo: value.validTo,
      configurationId: thousandEyesNativeId(value.configurationId),
      ...(typeof value.agentLocation === "string"
        ? { agentLocation: value.agentLocation }
        : {}),
    };
  });
}

export function parseThousandEyesPathSources(
  json: string,
): { index: string; source: string }[] {
  if (typeof json !== "string" || json.length > 8192)
    throw new Error("Invalid ThousandEyes path-source configuration.");
  const values: unknown = JSON.parse(json);
  if (!Array.isArray(values) || values.length > 16)
    throw new Error("Configure at most 16 exact path input sources.");
  const keys = new Set<string>();
  return values.map((value) => {
    if (
      !isObject(value) ||
      Object.keys(value).length !== 2 ||
      typeof value.index !== "string" ||
      !/^[a-z][a-z0-9_-]{0,79}$/.test(value.index) ||
      typeof value.source !== "string"
    )
      throw new Error("Invalid exact path input source.");
    const source = literal(value.source, 255);
    const key = `${value.index}\u0000${source}`;
    if (keys.has(key)) throw new Error("Duplicate path input source.");
    keys.add(key);
    return { index: value.index, source };
  });
}

export function thousandEyesMappings(
  config: SupplementalSourceConfiguration,
  selection: EvidenceSelection,
): ThousandEyesSourceMapping[] {
  if (
    config.source !== THOUSANDEYES_SOURCE ||
    !config.indexes.length ||
    config.indexes.length > 16 ||
    config.indexes.some(
      (index) =>
        !/^[a-z][a-z0-9_-]{0,79}$/.test(index) ||
        index === "unconfigured_optional",
    ) ||
    !config.mappings.length ||
    config.mappings.length > 32 ||
    config.authorities.length !== config.mappings.length
  )
    throw new Error("ThousandEyes source configuration is unavailable.");
  const identities = new Set<string>();
  const pathIdentities = new Set<string>();
  return config.mappings.map((mapping) => {
    const authority = literal(mapping.observer);
    const group = thousandEyesAccountGroupId(mapping.te_account_group_id);
    const families = parseThousandEyesFamilies(mapping.te_families ?? "[]");
    const streamAccountId = families.some((family) =>
      ["metric", "trace", "activity"].includes(family),
    )
      ? thousandEyesAccountGroupId(mapping.te_stream_account_id)
      : undefined;
    const alertAccountId = families.includes("alert")
      ? thousandEyesAccountGroupId(mapping.te_alert_account_id)
      : undefined;
    const organizationId = families.includes("alert")
      ? thousandEyesNativeId(mapping.te_organization_id)
      : undefined;
    if (
      mapping.observer_kind !== THOUSANDEYES_OBSERVER_KIND ||
      mapping.mapping_status !== "verified" ||
      mapping.scope !== routingScope(selection.scope) ||
      authority !== authority.toLowerCase() ||
      !config.authorities.includes(authority) ||
      identities.has(authority) ||
      identities.has(`group:${group}`)
    )
      throw new Error("ThousandEyes authority is missing or ambiguous.");
    identities.add(authority);
    identities.add(`group:${group}`);
    const pathSources = parseThousandEyesPathSources(
      mapping.te_path_sources ?? "[]",
    );
    for (const entry of pathSources) {
      const key = `${entry.index}\u0000${entry.source}`;
      if (!config.indexes.includes(entry.index) || pathIdentities.has(key))
        throw new Error("ThousandEyes path input scope is ambiguous.");
      pathIdentities.add(key);
    }
    let origin: string | undefined;
    if (mapping.thousandeyes_origin !== undefined) {
      const url = new URL(mapping.thousandeyes_origin);
      if (
        url.protocol !== "https:" ||
        url.username ||
        url.password ||
        url.search ||
        url.hash ||
        (mapping.thousandeyes_origin !== url.origin &&
          mapping.thousandeyes_origin !== `${url.origin}/`)
      )
        throw new Error(
          "Configure one credential-free ThousandEyes HTTPS origin.",
        );
      origin = url.origin;
    }
    return {
      authority,
      accountGroupId: group,
      scope: mapping.scope,
      families,
      ...(streamAccountId ? { streamAccountId } : {}),
      ...(alertAccountId ? { alertAccountId } : {}),
      ...(organizationId ? { organizationId } : {}),
      bindings: parseThousandEyesBindings(
        mapping.te_bindings ?? "[]",
        authority,
        group,
        mapping.scope,
      ),
      pathSources,
      ...(origin ? { origin } : {}),
    };
  });
}
