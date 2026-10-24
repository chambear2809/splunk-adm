import { getDefaultFetchInit } from "@splunk/splunk-utils/fetch";
import { createRESTURL } from "@splunk/splunk-utils/url";
import { deploymentClient } from "./deploymentClient";
import {
  expectationFor,
  indexNames,
  UNCONFIGURED_DNS_INDEX,
  type DeploymentClient,
} from "./deploymentHealth";
import {
  fingerprint,
  isObject,
  literal,
  normalizeIp,
  routingScope,
  type DnsSource,
} from "./evidence";
import type { IdentityRecord } from "./dnsAdapters";

export interface ObserverMapping {
  observer_kind: string;
  observer: string;
  scope: string;
  cluster: string;
  mapping_status?: string;
}
export interface DnsConfiguration {
  source: DnsSource;
  state: "active" | "staged" | "not_selected";
  indexes: string[];
  authorities: string[];
  schemaQualified: boolean;
  error?: string;
}
export interface EvidenceConfiguration {
  fingerprint: string;
  trafficContract: 1 | 2;
  summaryIndexes: string[];
  mappings: ObserverMapping[];
  identities: IdentityRecord[];
  identityAvailable: boolean;
  dns: DnsConfiguration[];
  maxAgeSeconds: number;
  clockUncertaintySeconds?: number;
}
export interface EvidenceConfigClient {
  read(
    signal?: AbortSignal,
    addresses?: string[],
    scope?: string,
  ): Promise<EvidenceConfiguration>;
}
/** Reads explicit app/shared objects with the caller's session, never private lookups. */
export class ToolkitEvidenceConfigClient implements EvidenceConfigClient {
  constructor(
    private readonly fetcher: typeof fetch = (...args) => fetch(...args),
    private readonly deployment: DeploymentClient = deploymentClient,
  ) {}
  private async get(
    path: string,
    signal?: AbortSignal,
    body?: { stanza: string },
  ): Promise<unknown> {
    const controller = new AbortController();
    const abort = () => controller.abort();
    signal?.addEventListener("abort", abort, { once: true });
    if (signal?.aborted) controller.abort();
    const timer = setTimeout(abort, 10000);
    try {
      const defaults = getDefaultFetchInit();
      const headers = new Headers(defaults.headers);
      if (body) headers.set("Content-Type", "application/json");
      const response = await this.fetcher(
        createRESTURL(path, { app: "splunk_adm", owner: "nobody" }),
        {
          ...defaults,
          signal: controller.signal,
          ...(body
            ? {
                method: "POST",
                headers,
                body: JSON.stringify(body),
              }
            : {}),
        },
      );
      if (!response.ok)
        throw new Error(
          "Shared evidence configuration is unavailable to this caller.",
        );
      let text: string;
      if (response.body) {
        const reader = response.body.getReader(),
          decoder = new TextDecoder();
        let bytes = 0;
        const parts: string[] = [];
        try {
          for (;;) {
            const part = await reader.read();
            if (part.done) break;
            bytes += part.value.byteLength;
            if (bytes > 8 * 1048576) {
              controller.abort();
              await reader.cancel();
              throw new Error(
                "Shared evidence configuration exceeds its read budget.",
              );
            }
            parts.push(decoder.decode(part.value, { stream: true }));
          }
          parts.push(decoder.decode());
          text = parts.join("");
        } finally {
          reader.releaseLock();
        }
      } else {
        text = await response.text();
        if (new TextEncoder().encode(text).byteLength > 8 * 1048576)
          throw new Error(
            "Shared evidence configuration exceeds its read budget.",
          );
      }
      return JSON.parse(text) as unknown;
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener("abort", abort);
    }
  }
  private async definition(
    name: string,
    signal?: AbortSignal,
  ): Promise<string> {
    if (!/^adm_[a-z0-9_]+$/.test(name))
      throw new Error("Invalid shared selector name.");
    // Splunk's app-merged config view combines app default/local settings for
    // the explicit nobody namespace. User-private shadows are excluded. The
    // caller needs list_conf_objects; this route never elevates search access.
    const value = await this.get(
      "configs/v1/conftypes/macros/stanzas:get?output_mode=json&view=app-merged",
      signal,
      { stanza: name },
    );
    if (
      !isObject(value) ||
      !Array.isArray(value.settings) ||
      !value.settings.every(
        (item) => isObject(item) && typeof item.setting === "string",
      )
    )
      throw new Error("Shared selector unavailable.");
    const definitions = value.settings.filter(
      (item) => item.setting === "definition",
    );
    if (definitions.length !== 1 || typeof definitions[0].value !== "string")
      throw new Error("Shared selector unavailable.");
    return definitions[0].value;
  }
  private async collection(
    name: "adm_observer_scope" | "adm_ip_identity",
    query: object,
    cap: number,
    signal?: AbortSignal,
  ): Promise<Record<string, unknown>[]> {
    const params = new URLSearchParams({
      query: JSON.stringify(query),
      limit: String(cap + 1),
      sort: "_key:1",
      fields:
        name === "adm_observer_scope"
          ? "_key,observer_kind,observer,scope,cluster,mapping_status"
          : "_key,ip,scope,scope_mapping_verified,entity_kind,entity_id,valid_from,valid_end",
    });
    const value = await this.get(
      `storage/collections/data/${name}?${params}`,
      signal,
    );
    if (
      !Array.isArray(value) ||
      value.length > cap ||
      !value.every((v) => isObject(v) && typeof v._key === "string")
    )
      throw new Error("Shared collection is capped or invalid.");
    // Detect a lower server row cap. This is a bounded read, not an atomic KV snapshot.
    params.set("skip", "1");
    const probe = await this.get(
      `storage/collections/data/${name}?${params}`,
      signal,
    );
    if (
      !Array.isArray(probe) ||
      JSON.stringify(value.slice(1)) !== JSON.stringify(probe)
    )
      throw new Error(
        "Shared collection completeness or stability could not be verified.",
      );
    return value as Record<string, unknown>[];
  }
  async read(
    signal?: AbortSignal,
    addresses: string[] = [],
    scope?: string,
  ): Promise<EvidenceConfiguration> {
    if (addresses.length > 16)
      throw new Error("Narrow the evidence addresses.");
    const ips = addresses.map(normalizeIp);
    if (scope !== undefined) routingScope(scope);
    const deployment = await this.deployment.read(signal);
    if (!deployment.activeContract)
      throw new Error("The active traffic contract is unavailable.");
    const mappingRows = await this.collection(
      "adm_observer_scope",
      {},
      2000,
      signal,
    );
    const mappings: ObserverMapping[] = mappingRows.map((r) => {
      if (
        !["observer_kind", "observer", "scope"].every(
          (k) => typeof r[k] === "string",
        )
      )
        throw new Error("Invalid observer mapping.");
      return {
        observer_kind: String(r.observer_kind),
        observer: String(r.observer),
        scope: String(r.scope),
        cluster: typeof r.cluster === "string" ? r.cluster : "",
        ...(typeof r.mapping_status === "string"
          ? { mapping_status: r.mapping_status }
          : {}),
      };
    });
    const sharedSummary =
      deployment.activeContract === 2
        ? "adm_index_summary_v2"
        : "adm_index_summary";
    const summary = await this.definition(sharedSummary, signal);
    const summaryIndexes = indexNames({
      name: sharedSummary,
      definition: summary,
    });
    if (!summaryIndexes.length || summaryIndexes.length > 16)
      throw new Error(
        "Configure the active summary index with validated literal index selectors.",
      );
    const writer = await this.definition(
      deployment.activeContract === 2
        ? "adm_summary_index_v2_name"
        : "adm_summary_index_name",
      signal,
    );
    if (summaryIndexes.length !== 1 || summaryIndexes[0] !== writer)
      throw new Error(
        "The active summary reader and writer selectors disagree.",
      );
    const selected = ["dns_stream", "dns_hubble"].some((id) =>
      ["active", "staged"].includes(expectationFor(deployment, id)),
    );
    let maxAge = "3600",
      clock = "unknown",
      optionalError: string | undefined;
    if (selected) {
      try {
        maxAge = await this.definition("adm_dns_max_age_seconds", signal);
        clock = await this.definition(
          "adm_dns_clock_uncertainty_seconds",
          signal,
        );
        if (
          !/^\d+$/.test(maxAge) ||
          Number(maxAge) < 60 ||
          Number(maxAge) > 86400 ||
          !(
            clock === "unknown" ||
            (/^\d+(?:\.\d+)?$/.test(clock) && Number(clock) <= 60)
          )
        )
          throw new Error("Invalid optional bounds.");
      } catch {
        maxAge = "3600";
        clock = "unknown";
        optionalError = "Optional DNS bounds could not be verified.";
      }
    }
    const clockUncertaintySeconds =
      /^\d+(?:\.\d+)?$/.test(clock) && Number(clock) <= 60
        ? Number(clock)
        : undefined;
    return this.finish(
      deployment,
      mappings,
      summaryIndexes,
      Number(maxAge),
      clockUncertaintySeconds,
      ips,
      scope,
      signal,
      optionalError,
    );
  }
  private async finish(
    deployment: Awaited<ReturnType<DeploymentClient["read"]>>,
    mappings: ObserverMapping[],
    summaryIndexes: string[],
    maxAgeSeconds: number,
    clockUncertaintySeconds: number | undefined,
    ips: string[],
    scope?: string,
    signal?: AbortSignal,
    optionalError?: string,
  ): Promise<EvidenceConfiguration> {
    const dns: DnsConfiguration[] = await Promise.all(
      (["dns_stream", "dns_hubble"] as const).map(async (source) => {
        const intent = expectationFor(deployment, source);
        const state =
          intent === "active" || intent === "staged" ? intent : "not_selected";
        const base: DnsConfiguration = {
          source,
          state,
          indexes: [],
          authorities: [],
          schemaQualified: false,
        };
        if (state === "not_selected") return base;
        if (optionalError) return { ...base, error: optionalError };
        try {
          const name =
            source === "dns_stream"
              ? "adm_index_dns_stream"
              : "adm_index_dns_hubble";
          const definition = await this.definition(name, signal);
          const indexes = indexNames({ name, definition });
          if (
            !indexes.length ||
            indexes.length > 16 ||
            indexes.includes(UNCONFIGURED_DNS_INDEX)
          )
            throw new Error(
              "DNS index selector must contain reviewed literal indexes.",
            );
          const schemaQualified =
            (await this.definition(
              source === "dns_stream"
                ? "adm_dns_stream_schema_qualified"
                : "adm_dns_hubble_schema_qualified",
              signal,
            )) === "1";
          const kind = source === "dns_stream" ? "dns_sensor" : "cluster";
          const relevant = mappings.filter(
            (r) => r.observer_kind === kind && (!scope || r.scope === scope),
          );
          const authorities = relevant
            .filter((r) => {
              try {
                routingScope(r.scope);
                literal(r.observer);
              } catch {
                return false;
              }
              return (
                r.observer === r.observer.toLowerCase() &&
                r.mapping_status === "verified" &&
                (kind !== "cluster" ||
                  r.cluster.toLowerCase() === r.observer) &&
                mappings.filter(
                  (m) => m.observer_kind === kind && m.observer === r.observer,
                ).length === 1
              );
            })
            .map((r) => r.observer)
            .sort();
          if (!authorities.length || authorities.length > 32)
            throw new Error(
              "DNS needs one to 32 unique verified source authorities in the selected scope.",
            );
          return { ...base, indexes, authorities, schemaQualified };
        } catch {
          return {
            ...base,
            error:
              "DNS source configuration is unavailable, unverified or conflicting.",
          };
        }
      }),
    );
    let identityAvailable = true;
    let identities: IdentityRecord[] = [];
    if (ips.length && scope) {
      try {
        const rows = await this.collection(
          "adm_ip_identity",
          // Legacy identity writers did not compress ordinary IPv6. A bounded
          // scope read avoids omitting equivalent known ownership/conflict rows.
          ips.some((ip) => ip.includes(":"))
            ? { scope }
            : { scope, ip: { $in: ips } },
          999,
          signal,
        );
        identities = rows
          .filter((r) => {
            if (typeof r.ip !== "string")
              throw new Error("Invalid identity address.");
            try {
              return ips.includes(normalizeIp(r.ip));
            } catch {
              return false;
            }
          })
          .filter(
            (r) =>
              r.scope !== "default" || Number(r.scope_mapping_verified) === 1,
          )
          .map((r) => {
            if (
              typeof r.ip !== "string" ||
              r.scope !== scope ||
              !ips.includes(normalizeIp(r.ip)) ||
              typeof r.entity_id !== "string" ||
              !r.entity_id ||
              typeof r.entity_kind !== "string" ||
              !["string", "number"].includes(typeof r.valid_from) ||
              !Number.isFinite(Number(r.valid_from)) ||
              Number(r.valid_from) < 0 ||
              Number(r.valid_from) > 253402300799 ||
              r.valid_from === "" ||
              (r.valid_end !== undefined &&
                r.valid_end !== null &&
                r.valid_end !== "" &&
                (!Number.isFinite(Number(r.valid_end)) ||
                  Number(r.valid_end) > 253402300799 ||
                  Number(r.valid_end) <= Number(r.valid_from)))
            )
              throw new Error("Invalid identity history.");
            return {
              ip: normalizeIp(r.ip),
              scope: String(r.scope),
              entity_id: r.entity_id,
              entity_kind: r.entity_kind,
              valid_from: Number(r.valid_from),
              ...(r.valid_end !== undefined &&
              r.valid_end !== null &&
              r.valid_end !== ""
                ? { valid_end: Number(r.valid_end) }
                : {}),
              scope_mapping_verified:
                Number(r.scope_mapping_verified) === 1 ? 1 : 0,
            };
          });
      } catch {
        identityAvailable = false;
      }
    }
    const config = {
      trafficContract: deployment.activeContract!,
      summaryIndexes,
      mappings,
      identities,
      identityAvailable,
      dns,
      maxAgeSeconds,
      ...(clockUncertaintySeconds !== undefined
        ? { clockUncertaintySeconds }
        : {}),
    };
    return {
      ...config,
      fingerprint: await fingerprint([
        config,
        deployment.settings?.revision ?? deployment.state,
      ]),
    };
  }
}
export const evidenceConfigClient: EvidenceConfigClient =
  new ToolkitEvidenceConfigClient();
