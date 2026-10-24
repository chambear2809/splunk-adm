import { getDefaultFetchInit } from "@splunk/splunk-utils/fetch";
import { createRESTURL } from "@splunk/splunk-utils/url";
import {
  SOURCE_DEFINITIONS,
  DATA_CONTRACT_SELECTORS,
  normalizeDefinition,
  JOB_DEFINITIONS,
  applicableJobs,
  expectationFor,
  isCoreSource,
  validateIndexName,
  indexNames,
  indexName,
  type DeploymentClient,
  type DeploymentSnapshot,
} from "./deploymentHealth";
import { ToolkitDeploymentClient } from "./deploymentClient";

export const INDEX_MACROS = [
  "adm_index_netflow",
  "adm_index_dcn",
  "adm_index_ftd",
  "adm_index_isovalent",
  "adm_index_k8s",
  "adm_index_traces",
  "adm_index_hubble",
  "adm_index_dns_stream",
  "adm_index_dns_hubble",
  "adm_index_summary",
  "adm_index_catalyst",
  "adm_index_meraki",
  "adm_summary_index_name",
] as const;
export const BUILDER_SEARCHES = [
  "ADM - Identity builder",
  "ADM - Service binding",
  "ADM - Service backends",
  "ADM - ACI policy",
  "ADM - Interface inventory",
  "ADM - Conversation rollup",
  "ADM - Application catalog",
] as const;
export { CISCO_V2_SELECTORS } from "./deploymentHealth";
export const CISCO_READ_MACROS = [
  "adm_data_contract_version",
  "adm_graph(4)",
  "adm_graph_v2(4)",
  "adm_index_summary_v2",
  "adm_summary_index_v2_name",
  "adm_network_client_history_observations",
  "adm_network_client_history_build",
  "adm_catalog_build",
  "adm_find(1)",
  "adm_health_sources",
  "adm_flow_evidence(4)",
  "adm_health_quality",
  "adm_topology",
] as const;
export const CISCO_STAGED_SEARCHES = [
  "ADM - Network client history builder",
  "ADM - Conversation rollup v2",
  "ADM - Traffic observation rollup v2",
  "ADM - Application catalog v2",
] as const;
export type IndexMacro = (typeof INDEX_MACROS)[number];
export type BuilderSearch = (typeof BUILDER_SEARCHES)[number];
export type CiscoStagedSearch = (typeof CISCO_STAGED_SEARCHES)[number];
export interface SetupMacro {
  name: IndexMacro;
  definition?: string;
  error?: string;
  canWrite: boolean;
}
export interface SummaryIndex {
  name?: string;
  exists?: boolean;
  error?: string;
}
export interface ObserverScope {
  _key: string;
  observer_kind: string;
  observer: string;
  scope: string;
  cluster: string;
}
export interface SavedSearchStatus {
  name: string;
  disabled?: boolean;
  scheduled?: boolean;
  canWrite: boolean;
  error?: string;
}
export interface SetupSnapshot {
  authorized: boolean;
  macros: SetupMacro[];
  summaryIndex: SummaryIndex;
  observerScopes: { rows: ObserverScope[]; complete: boolean; error?: string };
  savedSearches: SavedSearchStatus[];
  ciscoIntegration: CiscoIntegrationStatus;
  warnings: string[];
}
export interface ReadonlyMacroStatus {
  name: string;
  definition?: string;
  error?: string;
  canWrite: boolean;
}
export interface NetworkSourceProfile {
  _key: string;
  mapping_key: string;
  duplicate_count: number;
  source: string;
  source_authority: string;
  domain_kind: string;
  observation_domain_present: string;
  observation_domain_id: string;
  vpn_id: string;
  routing_domain: string;
  scope: string;
  cluster: string;
  mapping_status: string;
  profile: string;
}
export interface CiliumClusterSetting {
  _key: string;
  cluster: string;
  lb_mode: string;
  ingress_mode: string;
  l2announcements_enabled: string;
  mapping_status: string;
}
export interface ReadonlyCollection<T> {
  rows: T[];
  complete: boolean;
  error?: string;
}
export interface CiscoIntegrationStatus {
  macros: ReadonlyMacroStatus[];
  searches: SavedSearchStatus[];
  summaryIndex: SummaryIndex;
  sourceProfiles: ReadonlyCollection<NetworkSourceProfile>;
  clusterSettings: ReadonlyCollection<CiliumClusterSetting>;
  state: "unavailable" | "incomplete" | "staged" | "active";
  reasons: string[];
}
export interface SetupReadiness {
  ready: boolean;
  missingRequired: string[];
  optionalWarnings: string[];
}
export interface SetupClient {
  read(signal?: AbortSignal): Promise<SetupSnapshot>;
  setIndexMacro(
    name: string,
    indexName: string,
    signal?: AbortSignal,
  ): Promise<void>;
  setBuilderEnabled(
    name: string,
    enabled: boolean,
    signal?: AbortSignal,
  ): Promise<void>;
}
const object = (value: unknown): value is Record<string, unknown> =>
  !!value && typeof value === "object" && !Array.isArray(value);
const message = (error: unknown) =>
  error instanceof Error ? error.message : "Setup information unavailable.";
const text = (value: unknown): string | undefined =>
  typeof value === "string" ? value : undefined;
const flag = (value: unknown): boolean | undefined =>
  value === true || value === 1 || value === "1"
    ? true
    : value === false || value === 0 || value === "0"
      ? false
      : undefined;
function entry(payload: unknown): {
  content: Record<string, unknown>;
  writable: boolean;
} {
  if (
    !object(payload) ||
    !Array.isArray(payload.entry) ||
    payload.entry.length !== 1 ||
    !object(payload.entry[0]) ||
    !object(payload.entry[0].content)
  )
    throw new Error("Splunk returned an incomplete setup record.");
  const row = payload.entry[0];
  const content = row.content;
  if (!object(content))
    throw new Error("Splunk returned an incomplete setup record.");
  const acl = object(row.acl)
    ? row.acl
    : object(content["eai:acl"])
      ? content["eai:acl"]
      : {};
  return { content, writable: flag(acl.can_write) === true };
}
export { validateIndexName, indexNames, indexName } from "./deploymentHealth";
const REQUIRED_MACROS: readonly IndexMacro[] = [
  "adm_index_dcn",
  "adm_index_netflow",
  "adm_index_k8s",
  "adm_index_traces",
  "adm_index_summary",
  "adm_summary_index_name",
];
const OPTIONAL_MACROS: readonly [IndexMacro, string][] = [
  ["adm_index_ftd", "FTD"],
  ["adm_index_isovalent", "Isovalent"],
  ["adm_index_hubble", "Hubble"],
  ["adm_index_catalyst", "Catalyst Center and SD-WAN"],
  ["adm_index_meraki", "Meraki wireless"],
];
const EXPECTED_SOURCE_PROFILES: Record<string, ReadonlySet<string>> = {
  stream_ipfix: new Set([
    "standard_netflow",
    "catalyst_campus_fnf",
    "catalyst_sdwan_ipfix",
    "meraki_ms390_ipfix",
  ]),
  catalyst_client_snapshot: new Set(["catalyst_client_snapshot"]),
  meraki_association: new Set(["meraki_association"]),
};
const SOURCE_PROFILE_FIELDS = [
  "source",
  "source_authority",
  "domain_kind",
  "observation_domain_present",
  "observation_domain_id",
  "vpn_id",
  "routing_domain",
  "scope",
  "cluster",
  "mapping_status",
  "profile",
] as const;
const CLUSTER_SETTING_FIELDS = [
  "cluster",
  "lb_mode",
  "ingress_mode",
  "l2announcements_enabled",
  "mapping_status",
] as const;
export function setupReadiness(
  snapshot: SetupSnapshot,
  deployment?: DeploymentSnapshot,
  jobName?: string,
): SetupReadiness {
  const definition = JOB_DEFINITIONS.find((job) => job.name === jobName);
  const applicable = applicableJobs(deployment);
  const jobsToCheck = definition
    ? [definition]
    : applicable.filter((job) => job.required);
  const selected =
    deployment?.state === "configured" && deployment.activeContract
      ? SOURCE_DEFINITIONS.filter(
          (source) =>
            source.selectable &&
            expectationFor(deployment, source.id) === "active" &&
            (!definition || definition.sourceIds.includes(source.id)),
        )
      : [];
  const summaryContract =
    deployment === undefined
      ? 1
      : jobsToCheck.some((job) =>
            ["rollup_v2", "traffic_v2"].includes(job.id),
          ) && deployment.activeContract === 2
        ? 2
        : jobsToCheck.some((job) => job.id === "rollup_v1") &&
            deployment.activeContract === 1
          ? 1
          : undefined;
  const summaryNames =
    summaryContract === 2
      ? ["adm_index_summary_v2", "adm_summary_index_v2_name"]
      : summaryContract === 1
        ? ["adm_index_summary", "adm_summary_index_name"]
        : [];
  const coreSelected = selected.filter(isCoreSource);
  const requiredMacros: readonly string[] = deployment
    ? [
        ...new Set([
          ...coreSelected.flatMap((source) => source.indexMacros),
          ...summaryNames,
        ]),
      ]
    : REQUIRED_MACROS;
  const macroRecords = [
    ...snapshot.macros,
    ...snapshot.ciscoIntegration.macros,
  ];
  const namesFor = (name: string): string[] => {
    const macro = macroRecords.find((row) => row.name === name);
    if (!macro || macro.error) return [];
    if (name === "adm_summary_index_v2_name")
      return macro.definition && !validateIndexName(macro.definition)
        ? [macro.definition]
        : [];
    return indexNames({ ...macro, name: name as IndexMacro });
  };
  const missingRequired: string[] = requiredMacros.filter(
    (name) => namesFor(name).length === 0,
  );
  if (
    deployment &&
    (deployment.state !== "configured" || !deployment.activeContract)
  )
    missingRequired.push("deployment expectations and active contract");
  if (
    !jobName &&
    deployment?.state === "configured" &&
    deployment.activeContract &&
    coreSelected.length === 0
  )
    missingRequired.push(
      "at least one core source for traffic or inventory readiness",
    );
  if (jobName !== undefined && !definition)
    missingRequired.push("saved search is not registered");
  if (
    deployment &&
    definition &&
    !applicable.some((job) => job.name === definition.name)
  )
    missingRequired.push("job is not required by the active deployment");
  if (summaryContract !== undefined) {
    const [reader, writer] = summaryNames.map(namesFor);
    if (reader.length !== 1 || writer.length !== 1 || reader[0] !== writer[0])
      missingRequired.push("summary reader/writer match");
    const summaryIndex =
      summaryContract === 2
        ? snapshot.ciscoIntegration.summaryIndex
        : snapshot.summaryIndex;
    if (summaryIndex.exists !== true) missingRequired.push("summary index");
  }
  const scopes = snapshot.observerScopes;
  const mappingRequirements = deployment
    ? jobsToCheck.flatMap((job) =>
        selected
          .filter((source) => job.sourceIds.includes(source.id))
          .map((source) => ({
            source,
            kinds: source.observerKindsByJob?.[job.id] ?? source.observerKinds,
          })),
      )
    : selected.map((source) => ({ source, kinds: source.observerKinds }));
  const requiredKinds = mappingRequirements.flatMap(
    (requirement) => requirement.kinds,
  );
  const relevantRows = deployment
    ? scopes.rows.filter((row) =>
        requiredKinds.includes(row.observer_kind.toLowerCase()),
      )
    : scopes.rows;
  if (
    (deployment === undefined || requiredKinds.length > 0) &&
    (!scopes.complete ||
      !relevantRows.length ||
      relevantRows.some(
        (row) =>
          !row.observer.trim() ||
          !row.observer_kind.trim() ||
          !row.scope.trim() ||
          row.observer !== row.observer.toLowerCase() ||
          row.observer_kind !== row.observer_kind.toLowerCase(),
      ))
  )
    missingRequired.push("observer mappings");
  if (deployment && scopes.complete)
    for (const { source, kinds } of mappingRequirements) {
      if (
        kinds.length &&
        !relevantRows.some(
          (row) =>
            kinds.some((kind) => kind === row.observer_kind) &&
            !!row.observer.trim() &&
            !!row.scope.trim(),
        )
      )
        missingRequired.push(`observer mapping for ${source.label}`);
    }
  if (deployment)
    for (const id of new Set(
      jobsToCheck.flatMap((job) => job.prerequisiteIds),
    )) {
      const prerequisite = JOB_DEFINITIONS.find((job) => job.id === id);
      if (
        prerequisite &&
        applicableJobs(deployment).some((job) => job.id === id)
      ) {
        const state = snapshot.savedSearches.find(
          (job) => job.name === prerequisite.name,
        );
        if (
          !state ||
          state.error ||
          state.disabled !== false ||
          state.scheduled !== true
        )
          missingRequired.push(`enable prerequisite ${prerequisite.name}`);
      }
    }
  const optionalWarnings = OPTIONAL_MACROS.filter(([name]) => {
    const macro = snapshot.macros.find((row) => row.name === name);
    return !macro || !!macro.error || indexNames(macro).length === 0;
  }).map(([, label]) => `${label} source is optional and not configured.`);
  return {
    ready: snapshot.authorized && missingRequired.length === 0,
    missingRequired,
    optionalWarnings,
  };
}
const parseBareIndex = (value: string | undefined): string | undefined =>
  value && /^[a-z][a-z0-9_-]{0,79}$/.test(value) ? value : undefined;
const parseIndexMacro = (value: string | undefined): string | undefined => {
  if (!value) return undefined;
  const match = /^index=([a-z][a-z0-9_-]{0,79})$/.exec(value);
  return match?.[1];
};
class SetupHTTPError extends Error {
  constructor(readonly status: number) {
    super(`Splunk setup request failed (HTTP ${status}).`);
  }
}
export class ToolkitSetupClient implements SetupClient {
  private readonly deploymentClient: DeploymentClient;
  constructor(
    // Native fetch throws "Illegal invocation" when called as another object's method.
    private readonly fetcher: typeof fetch = (...args) => fetch(...args),
    deploymentClient?: DeploymentClient,
  ) {
    this.deploymentClient =
      deploymentClient ?? new ToolkitDeploymentClient(fetcher);
  }
  private async request(
    path: string,
    signal?: AbortSignal,
    app = true,
    data?: Record<string, string>,
  ): Promise<unknown> {
    if (signal?.aborted) throw new Error("Setup request cancelled.");
    const timeout = new AbortController();
    const abort = () => timeout.abort();
    signal?.addEventListener("abort", abort, { once: true });
    const deadline = setTimeout(abort, 30000);
    try {
      const isKV = path.startsWith("storage/collections/data/");
      const endpoint =
        path +
        (isKV
          ? ""
          : path.includes("?")
            ? "&output_mode=json"
            : "?output_mode=json");
      const defaults = getDefaultFetchInit();
      const headers = new Headers(defaults.headers);
      if (data)
        headers.set("Content-Type", "application/x-www-form-urlencoded");
      const response = await this.fetcher(
        createRESTURL(
          endpoint,
          app ? { app: "splunk_adm", owner: "nobody" } : undefined,
        ),
        {
          ...defaults,
          headers,
          signal: timeout.signal,
          method: data ? "POST" : "GET",
          ...(data ? { body: new URLSearchParams(data).toString() } : {}),
        },
      );
      if (!response.ok) throw new SetupHTTPError(response.status);
      if (data) return undefined;
      return await response.json();
    } catch (error) {
      if (timeout.signal.aborted && !signal?.aborted)
        throw new Error(
          "Setup request timed out. Refresh the checklist before retrying a change.",
          { cause: error },
        );
      throw error;
    } finally {
      clearTimeout(deadline);
      signal?.removeEventListener("abort", abort);
    }
  }
  private async authorized(signal?: AbortSignal): Promise<boolean> {
    const context = entry(
      await this.request("authentication/current-context", signal, false),
    ).content;
    if (
      !Array.isArray(context.capabilities) ||
      !context.capabilities.every(
        (capability) => typeof capability === "string",
      )
    )
      throw new Error("Administrator capability information is unavailable.");
    return context.capabilities.includes("admin_all_objects");
  }
  private async scopes(
    signal?: AbortSignal,
  ): Promise<SetupSnapshot["observerScopes"]> {
    const rows: ObserverScope[] = [];
    const seen = new Set<string>();
    const size = 1000;
    for (let page = 0; page <= 20; page++) {
      const query = new URLSearchParams({
        limit: String(page === 20 ? 1 : size),
        skip: String(page * size),
        sort: "_key:1",
      });
      const payload = await this.request(
        `storage/collections/data/adm_observer_scope?${query}`,
        signal,
      );
      if (!Array.isArray(payload) || payload.length > (page === 20 ? 1 : size))
        throw new Error("Observer lookup returned an invalid or partial page.");
      if (page === 20)
        return {
          rows,
          complete: payload.length === 0,
          ...(payload.length
            ? {
                error:
                  "Observer mappings exceed the 20,000-row checklist limit; review them through Splunk administration.",
              }
            : {}),
        };
      for (const row of payload) {
        if (
          !object(row) ||
          typeof row._key !== "string" ||
          !row._key.trim() ||
          seen.has(row._key) ||
          ["observer_kind", "observer", "scope"].some(
            (key) =>
              typeof row[key] !== "string" || !(row[key] as string).trim(),
          ) ||
          (row.cluster !== undefined && typeof row.cluster !== "string")
        )
          throw new Error(
            "Observer mappings are malformed or changed during paging. Check again.",
          );
        seen.add(row._key);
        rows.push({
          _key: row._key,
          observer_kind: row.observer_kind as string,
          observer: row.observer as string,
          scope: row.scope as string,
          cluster: (row.cluster as string) ?? "",
        });
      }
      if (payload.length < size) return { rows, complete: true };
    }
    return { rows, complete: false };
  }
  private async readonlyMacro(
    name: string,
    signal?: AbortSignal,
  ): Promise<ReadonlyMacroStatus> {
    try {
      const record = entry(
        await this.request(
          `configs/conf-macros/${encodeURIComponent(name)}`,
          signal,
        ),
      );
      const definition = text(record.content.definition);
      if (definition === undefined)
        throw new Error("Macro definition is unavailable.");
      return { name, definition, canWrite: record.writable };
    } catch (error) {
      return { name, canWrite: false, error: message(error) };
    }
  }
  private async readonlySearch(
    name: string,
    signal?: AbortSignal,
  ): Promise<SavedSearchStatus> {
    try {
      const record = entry(
        await this.request(
          `saved/searches/${encodeURIComponent(name)}`,
          signal,
        ),
      );
      const disabled = flag(record.content.disabled);
      if (disabled === undefined)
        throw new Error("Saved-search enabled state is unavailable.");
      const scheduled = flag(record.content.is_scheduled);
      if (scheduled === undefined)
        throw new Error("Saved-search schedule state is unavailable.");
      return { name, disabled, scheduled, canWrite: record.writable };
    } catch (error) {
      return { name, canWrite: false, error: message(error) };
    }
  }
  private async readonlyCollection<T>(
    collection: string,
    parseRow: (value: unknown) => T,
    signal?: AbortSignal,
  ): Promise<ReadonlyCollection<T>> {
    const rows: T[] = [];
    const seenKeys = new Set<string>();
    const pageSize = 250;
    const maximum = 1000;
    try {
      for (let skip = 0; skip <= maximum; skip += pageSize) {
        const limit = skip === maximum ? 1 : pageSize;
        const query = new URLSearchParams({
          limit: String(limit),
          skip: String(skip),
          sort: "_key:1",
        });
        const payload = await this.request(
          `storage/collections/data/${collection}?${query}`,
          signal,
        );
        if (!Array.isArray(payload) || payload.length > limit)
          throw new Error("Collection returned an invalid or partial page.");
        if (skip === maximum)
          return {
            rows,
            complete: payload.length === 0,
            ...(payload.length
              ? {
                  error: `Collection exceeds the ${maximum}-row setup review limit.`,
                }
              : {}),
          };
        const page = payload.map(parseRow);
        for (const row of page) {
          const key = (row as { _key: string })._key;
          if (seenKeys.has(key))
            throw new Error(
              "Collection has duplicate keys or changed during paging.",
            );
          seenKeys.add(key);
          rows.push(row);
        }
        if (payload.length < pageSize) return { rows, complete: true };
      }
      return {
        rows,
        complete: false,
        error: "Collection read was incomplete.",
      };
    } catch (error) {
      return { rows, complete: false, error: message(error) };
    }
  }
  private sourceProfileRows(signal?: AbortSignal) {
    return this.readonlyCollection(
      "adm_network_source_scope",
      (value): NetworkSourceProfile => {
        if (
          !object(value) ||
          typeof value._key !== "string" ||
          !/^[a-f0-9]{64}$/.test(value._key) ||
          typeof value.mapping_key !== "string" ||
          !/^[a-f0-9]{64}$/.test(value.mapping_key) ||
          typeof value.duplicate_count !== "number" ||
          !Number.isSafeInteger(value.duplicate_count) ||
          value.duplicate_count < 1 ||
          SOURCE_PROFILE_FIELDS.some(
            (field) => typeof value[field] !== "string",
          ) ||
          SOURCE_PROFILE_FIELDS.some(
            (field) =>
              field !== "observation_domain_id" &&
              field !== "vpn_id" &&
              field !== "routing_domain" &&
              field !== "cluster" &&
              !(value[field] as string).trim(),
          ) ||
          !["0", "1"].includes(value.observation_domain_present as string) ||
          !["mapped", "unmapped", "ambiguous", "unsupported"].includes(
            value.mapping_status as string,
          )
        )
          throw new Error("Source-scope records are malformed or incomplete.");
        return value as unknown as NetworkSourceProfile;
      },
      signal,
    ).then((collection) => {
      const keys = new Set<string>();
      const mappingKeys = new Set<string>();
      for (const row of collection.rows) {
        const key = JSON.stringify([
          row.source,
          row.source_authority,
          row.domain_kind,
          row.observation_domain_present,
          row.observation_domain_id,
          row.vpn_id,
          row.routing_domain,
        ]);
        if (keys.has(key))
          return {
            ...collection,
            complete: false,
            error:
              "Duplicate seven-key source profiles make mapping ambiguous.",
          };
        keys.add(key);
        if (mappingKeys.has(row.mapping_key))
          return {
            ...collection,
            complete: false,
            error:
              "Duplicate source mapping keys make the seven-key mapping ambiguous.",
          };
        mappingKeys.add(row.mapping_key);
      }
      return collection;
    });
  }
  private clusterSettingRows(signal?: AbortSignal) {
    return this.readonlyCollection(
      "adm_cilium_cluster_settings",
      (value): CiliumClusterSetting => {
        if (
          !object(value) ||
          typeof value._key !== "string" ||
          !/^[a-f0-9]{64}$/.test(value._key) ||
          CLUSTER_SETTING_FIELDS.some(
            (field) =>
              field !== "l2announcements_enabled" &&
              typeof value[field] !== "string",
          ) ||
          CLUSTER_SETTING_FIELDS.some(
            (field) =>
              field !== "l2announcements_enabled" &&
              !(value[field] as string).trim(),
          ) ||
          ![0, 1, "0", "1", "true", "false"].includes(
            value.l2announcements_enabled as number | string,
          ) ||
          !["mapped", "unmapped", "ambiguous"].includes(
            value.mapping_status as string,
          )
        )
          throw new Error("Cluster settings are malformed or incomplete.");
        return {
          ...(value as unknown as CiliumClusterSetting),
          l2announcements_enabled: String(value.l2announcements_enabled),
        };
      },
      signal,
    );
  }
  private async ciscoIntegration(
    signal: AbortSignal | undefined,
    authorized: boolean,
  ): Promise<CiscoIntegrationStatus> {
    const [macros, searches, sourceProfiles, clusterSettings] =
      await Promise.all([
        Promise.all(
          CISCO_READ_MACROS.map((name) => this.readonlyMacro(name, signal)),
        ),
        Promise.all(
          CISCO_STAGED_SEARCHES.map((name) =>
            this.readonlySearch(name, signal),
          ),
        ),
        this.sourceProfileRows(signal),
        this.clusterSettingRows(signal),
      ]);
    const v2ReaderIndex = macros.find(
      (row) => row.name === "adm_index_summary_v2",
    );
    const v2WriterIndex = macros.find(
      (row) => row.name === "adm_summary_index_v2_name",
    );
    const readerIndex = parseIndexMacro(v2ReaderIndex?.definition);
    const writerIndex = parseBareIndex(v2WriterIndex?.definition);
    let summaryIndex: SummaryIndex =
      readerIndex && writerIndex && readerIndex === writerIndex
        ? { name: readerIndex }
        : {
            error: "Version-2 summary reader and writer indexes do not match.",
          };
    if (summaryIndex.name) {
      try {
        const record = entry(
          await this.request(
            `data/indexes/${summaryIndex.name}`,
            signal,
            false,
          ),
        );
        const disabled = flag(record.content.disabled);
        if (disabled === undefined)
          throw new Error("Version-2 summary index state is unavailable.");
        summaryIndex = {
          name: summaryIndex.name,
          exists: !disabled,
          ...(disabled
            ? { error: "The version-2 summary index is disabled." }
            : {}),
        };
      } catch (error) {
        summaryIndex = {
          name: summaryIndex.name,
          error: message(error),
        };
      }
    }
    const reasons: string[] = [];
    if (!authorized)
      reasons.push("Administrator capabilities are unavailable.");
    if (macros.some((row) => row.error))
      reasons.push("One or more integration macros could not be read.");

    if (!sourceProfiles.complete)
      reasons.push(sourceProfiles.error ?? "Source profiles are incomplete.");
    if (!clusterSettings.complete)
      reasons.push(clusterSettings.error ?? "Cluster settings are incomplete.");
    if (
      sourceProfiles.rows.some(
        (row) => !EXPECTED_SOURCE_PROFILES[row.source]?.has(row.profile),
      )
    )
      reasons.push("Unknown source profiles require operator review.");
    if (sourceProfiles.rows.some((row) => row.mapping_status !== "mapped"))
      reasons.push(
        "Unmapped or ambiguous source profiles cannot support correlation.",
      );
    if (sourceProfiles.rows.some((row) => row.duplicate_count !== 1))
      reasons.push(
        "Duplicate source-profile candidates make the seven-key mapping ambiguous.",
      );
    if (clusterSettings.rows.some((row) => row.mapping_status !== "mapped"))
      reasons.push(
        "Unmapped or ambiguous cluster settings cannot support cluster joins.",
      );
    const clusters = new Set<string>();
    if (
      clusterSettings.rows.some((row) => {
        if (clusters.has(row.cluster)) return true;
        clusters.add(row.cluster);
        return false;
      })
    )
      reasons.push(
        "Duplicate cluster settings make cluster configuration ambiguous.",
      );
    if (summaryIndex.exists !== true)
      reasons.push(
        summaryIndex.error ?? "Version-2 summary index is unavailable.",
      );
    const contract = macros.find(
      (row) => row.name === "adm_data_contract_version",
    );
    const version =
      contract?.definition === undefined
        ? undefined
        : normalizeDefinition(contract.definition);
    const activeV2 = version === "2";
    if (!activeV2 && version !== "1")
      reasons.push("The active data contract could not be verified.");
    for (const selector of DATA_CONTRACT_SELECTORS.filter(
      (item) => item.name !== "adm_data_contract_version",
    )) {
      const actual = macros.find((macro) => macro.name === selector.name);
      const expected = activeV2 ? selector.after : selector.before;
      if (
        actual?.definition === undefined ||
        normalizeDefinition(actual.definition) !== normalizeDefinition(expected)
      )
        reasons.push(
          `${selector.name} does not match the data-contract marker.`,
        );
    }
    if (activeV2) {
      const deployment = await this.deploymentClient
        .read(signal)
        .catch(() => ({ state: "unavailable" as const, canWrite: false }));
      if (deployment.state !== "configured" || deployment.activeContract !== 2)
        reasons.push(
          "Version-2 deployment expectations and selectors could not be verified.",
        );
      const requiredWriters = applicableJobs(deployment).filter(
        (job) =>
          job.required &&
          job.contracts.includes(2) &&
          !job.contracts.includes(1),
      );
      if (
        requiredWriters.some((definition) => {
          const job = searches.find((row) => row.name === definition.name);
          return (
            !job ||
            !!job.error ||
            job.disabled !== false ||
            job.scheduled !== true
          );
        })
      )
        reasons.push(
          "Required version-2 builder and catalog schedules are not confirmed enabled and scheduled.",
        );
      const legacyNames = [
        ...(requiredWriters.some((job) =>
          ["rollup_v2", "traffic_v2"].includes(job.id),
        )
          ? ["ADM - Conversation rollup"]
          : []),
        ...(requiredWriters.some((job) => job.id === "catalog_v2")
          ? ["ADM - Application catalog"]
          : []),
      ];
      const legacy = await Promise.all(
        legacyNames.map((name) => this.readonlySearch(name, signal)),
      );
      if (legacy.some((job) => job.error || job.disabled !== true))
        reasons.push(
          "Applicable legacy version-1 writers must be confirmed disabled for version 2.",
        );
    } else {
      if (searches.some((row) => row.error))
        reasons.push("One or more staged builder states could not be read.");
      const historySearch = searches.find(
        (row) => row.name === "ADM - Network client history builder",
      );
      if (historySearch?.disabled !== true || historySearch.scheduled !== true)
        reasons.push(
          "Client history builder is not in the expected disabled staged state.",
        );
      const v2Writers = searches.filter(
        (row) => row.name !== "ADM - Network client history builder",
      );
      if (
        v2Writers.some((row) => row.disabled !== true || row.scheduled !== true)
      )
        reasons.push(
          "Version-2 writers are not in the expected disabled staged state.",
        );
    }
    const allUnreadable = !authorized || macros.every((row) => !!row.error);
    return {
      macros,
      searches,
      summaryIndex,
      sourceProfiles,
      clusterSettings,
      state: allUnreadable
        ? "unavailable"
        : reasons.length > 0
          ? "incomplete"
          : activeV2
            ? "active"
            : "staged",
      reasons,
    };
  }
  async read(signal?: AbortSignal): Promise<SetupSnapshot> {
    const warnings: string[] = [];
    let authorized = false;
    try {
      authorized = await this.authorized(signal);
    } catch (error) {
      warnings.push(message(error));
    }
    const macros = await Promise.all(
      INDEX_MACROS.map(async (name): Promise<SetupMacro> => {
        try {
          const record = entry(
            await this.request(`configs/conf-macros/${name}`, signal),
          );
          const definition = text(record.content.definition);
          if (definition === undefined)
            throw new Error("Macro definition is unavailable.");
          return { name, definition, canWrite: authorized && record.writable };
        } catch (error) {
          return { name, canWrite: false, error: message(error) };
        }
      }),
    );
    const savedSearches = await Promise.all(
      BUILDER_SEARCHES.map(async (name): Promise<SavedSearchStatus> => {
        try {
          const record = entry(
            await this.request(
              `saved/searches/${encodeURIComponent(name)}`,
              signal,
            ),
          );
          const disabled = flag(record.content.disabled);
          if (disabled === undefined)
            throw new Error("Saved-search enabled state is unavailable.");
          return {
            name,
            disabled,
            scheduled: flag(record.content.is_scheduled),
            canWrite: authorized && record.writable,
          };
        } catch (error) {
          return { name, canWrite: false, error: message(error) };
        }
      }),
    );
    let observerScopes: SetupSnapshot["observerScopes"];
    try {
      observerScopes = await this.scopes(signal);
    } catch (error) {
      observerScopes = { rows: [], complete: false, error: message(error) };
    }
    const ciscoIntegration = await this.ciscoIntegration(signal, authorized);
    const writer = macros.find(
      (macro) => macro.name === "adm_summary_index_name",
    )!;
    const name = indexName(writer);
    let summaryIndex: SummaryIndex = name
      ? { name }
      : { error: "The summary writer must name one valid index." };
    if (name) {
      try {
        const record = entry(
          await this.request(`data/indexes/${name}`, signal, false),
        );
        const disabled = flag(record.content.disabled);
        if (disabled === undefined)
          throw new Error("Summary index state is unavailable.");
        summaryIndex = {
          name,
          exists: !disabled,
          ...(disabled ? { error: "The summary index is disabled." } : {}),
        };
      } catch (error) {
        summaryIndex =
          error instanceof SetupHTTPError && error.status === 404
            ? {
                name,
                error:
                  "The summary index was not returned. It may be absent or hidden by permissions.",
              }
            : { name, error: message(error) };
      }
    }
    if (signal?.aborted) throw new Error("Setup request cancelled.");
    return {
      authorized,
      macros,
      summaryIndex,
      observerScopes,
      savedSearches,
      ciscoIntegration,
      warnings,
    };
  }
  async setIndexMacro(
    name: string,
    value: string,
    signal?: AbortSignal,
  ): Promise<void> {
    if (!(INDEX_MACROS as readonly string[]).includes(name))
      throw new Error("Only approved index macros may be changed.");
    const invalid = validateIndexName(value);
    if (invalid) throw new Error(invalid);
    if (!(await this.authorized(signal)))
      throw new Error("Administrator access is required.");
    const path = `configs/conf-macros/${name}`;
    if (!entry(await this.request(path, signal)).writable)
      throw new Error("This macro is not writable by your role.");
    await this.request(path, signal, true, {
      definition: name === "adm_summary_index_name" ? value : `index=${value}`,
    });
  }
  async setBuilderEnabled(
    name: string,
    enabled: boolean,
    signal?: AbortSignal,
  ): Promise<void> {
    if (
      !(BUILDER_SEARCHES as readonly string[]).includes(name) ||
      enabled !== true
    )
      throw new Error("Only enabling approved builder searches is supported.");
    if (!(await this.authorized(signal)))
      throw new Error("Administrator access is required.");
    const [configuration, deployment] = await Promise.all([
      this.read(signal),
      this.deploymentClient.read(signal),
    ]);
    const readiness = setupReadiness(configuration, deployment, name);
    if (!readiness.ready)
      throw new Error(
        `Builder prerequisites are not ready: ${readiness.missingRequired.join(", ")}.`,
      );
    const path = `saved/searches/${encodeURIComponent(name)}`;
    if (!entry(await this.request(path, signal)).writable)
      throw new Error("This saved search is not writable by your role.");
    await this.request(path, signal, true, {
      disabled: "0",
      is_scheduled: "1",
    });
  }
}
export const setupClient: SetupClient = new ToolkitSetupClient();
