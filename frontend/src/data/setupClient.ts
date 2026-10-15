import { getDefaultFetchInit } from "@splunk/splunk-utils/fetch";
import { createRESTURL } from "@splunk/splunk-utils/url";

export const INDEX_MACROS = [
  "adm_index_netflow",
  "adm_index_dcn",
  "adm_index_ftd",
  "adm_index_isovalent",
  "adm_index_k8s",
  "adm_index_traces",
  "adm_index_hubble",
  "adm_index_summary",
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
export type IndexMacro = (typeof INDEX_MACROS)[number];
export type BuilderSearch = (typeof BUILDER_SEARCHES)[number];
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
  name: BuilderSearch;
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
  warnings: string[];
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
export function validateIndexName(value: string): string | undefined {
  return typeof value === "string" &&
    value.length <= 80 &&
    /^[a-z][a-z0-9_-]*$/.exec(value)?.[0] === value
    ? undefined
    : "Use a lowercase index name beginning with a letter (up to 80 letters, numbers, underscores or hyphens).";
}
export function indexName(macro: SetupMacro): string | undefined {
  const value =
    macro.name === "adm_summary_index_name"
      ? macro.definition
      : macro.definition?.startsWith("index=")
        ? macro.definition.slice(6)
        : undefined;
  return value && !validateIndexName(value) ? value : undefined;
}
class SetupHTTPError extends Error {
  constructor(readonly status: number) {
    super(`Splunk setup request failed (HTTP ${status}).`);
  }
}
export class ToolkitSetupClient implements SetupClient {
  constructor(private readonly fetcher: typeof fetch = fetch) {}
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
      !Array.isArray(context.roles) ||
      !context.roles.every((role) => typeof role === "string")
    )
      throw new Error("Administrator role information is unavailable.");
    return context.roles.some(
      (role) => role === "admin" || role === "sc_admin",
    );
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
