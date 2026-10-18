import { getDefaultFetchInit } from "@splunk/splunk-utils/fetch";
import { createRESTURL } from "@splunk/splunk-utils/url";
import {
  validateExpectations,
  DATA_CONTRACT_SELECTORS,
  normalizeDefinition,
  SOURCE_DEFINITIONS,
  expectationFor,
  indexNames,
  type DeploymentClient,
  type DeploymentExpectations,
  type DeploymentSnapshot,
} from "./deploymentHealth";

const COLLECTION = "storage/collections/data/adm_deployment_settings";
const KEY = "deployment";
const object = (value: unknown): value is Record<string, unknown> =>
  !!value && typeof value === "object" && !Array.isArray(value);
class HTTPError extends Error {
  constructor(readonly status: number) {
    super(`Deployment settings request failed (HTTP ${status}).`);
  }
}
function entry(payload: unknown) {
  if (
    !object(payload) ||
    !Array.isArray(payload.entry) ||
    payload.entry.length !== 1 ||
    !object(payload.entry[0]) ||
    !object(payload.entry[0].content)
  )
    throw new Error("Deployment configuration evidence is incomplete.");
  return payload.entry[0] as {
    content: Record<string, unknown>;
    acl?: Record<string, unknown>;
  };
}

export class ToolkitDeploymentClient implements DeploymentClient {
  constructor(private readonly fetcher: typeof fetch = fetch) {}
  private async request(
    path: string,
    signal?: AbortSignal,
    body?: unknown,
    global = false,
  ): Promise<unknown> {
    if (signal?.aborted)
      throw new Error("Deployment settings request cancelled.");
    const controller = new AbortController();
    const abort = () => controller.abort();
    signal?.addEventListener("abort", abort, { once: true });
    const timeout = setTimeout(abort, 30000);
    try {
      const defaults = getDefaultFetchInit();
      const headers = new Headers(defaults.headers);
      if (body !== undefined) headers.set("Content-Type", "application/json");
      const endpoint = path.startsWith(COLLECTION)
        ? path
        : `${path}?output_mode=json`;
      const response = await this.fetcher(
        createRESTURL(
          endpoint,
          global ? undefined : { app: "splunk_adm", owner: "nobody" },
        ),
        {
          ...defaults,
          headers,
          signal: controller.signal,
          method: body === undefined ? "GET" : "POST",
          ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        },
      );
      if (!response.ok) throw new HTTPError(response.status);
      return body === undefined ? await response.json() : undefined;
    } finally {
      clearTimeout(timeout);
      signal?.removeEventListener("abort", abort);
    }
  }

  async read(signal?: AbortSignal): Promise<DeploymentSnapshot> {
    const results = await Promise.allSettled([
      this.request(`${COLLECTION}/${KEY}`, signal),
      Promise.all(
        DATA_CONTRACT_SELECTORS.map((selector) =>
          this.request(
            `configs/conf-macros/${encodeURIComponent(selector.name)}`,
            signal,
          ),
        ),
      ),
      this.request("authentication/current-context", signal, undefined, true),
      this.request(
        "storage/collections/config/adm_deployment_settings",
        signal,
      ),
    ]);
    if (signal?.aborted)
      throw new Error("Deployment settings request cancelled.");
    let activeContract: 1 | 2 | undefined;
    let canWrite = false;
    const [record, contract, context, acl] = results;
    try {
      if (contract.status === "fulfilled") {
        const definitions = contract.value.map(
          (value) => entry(value).content.definition,
        );
        const matches = (version: 1 | 2) =>
          definitions.every(
            (value, index) =>
              typeof value === "string" &&
              normalizeDefinition(value) ===
                normalizeDefinition(
                  DATA_CONTRACT_SELECTORS[index][
                    version === 1 ? "before" : "after"
                  ],
                ),
          );
        activeContract = matches(1) ? 1 : matches(2) ? 2 : undefined;
      }
    } catch {
      /* Missing selector evidence stays unknown. */
    }
    try {
      if (context.status === "fulfilled" && acl.status === "fulfilled") {
        const capabilities = entry(context.value).content.capabilities;
        const permissions = entry(acl.value);
        const writable =
          permissions.acl?.can_write ??
          (object(permissions.content["eai:acl"])
            ? permissions.content["eai:acl"].can_write
            : undefined);
        canWrite =
          Array.isArray(capabilities) &&
          capabilities.includes("admin_all_objects") &&
          [true, 1, "1"].includes(writable as boolean | number | string);
      }
    } catch {
      /* A failed authorization check never enables writes. */
    }
    if (record.status === "rejected") {
      const absent =
        record.reason instanceof HTTPError && record.reason.status === 404;
      return {
        state: absent ? "absent" : "unavailable",
        activeContract,
        canWrite,
        error: absent
          ? "Deployment expectations have not been configured."
          : "Deployment expectations are unavailable; check permissions and KV Store availability.",
      };
    }
    try {
      if (
        !object(record.value) ||
        record.value._key !== KEY ||
        typeof record.value.settings_json !== "string"
      )
        throw new Error("Malformed deployment settings record.");
      const settings = validateExpectations(
        JSON.parse(record.value.settings_json),
      );
      if (record.value.revision !== settings.revision)
        throw new Error("Deployment settings revision is inconsistent.");
      const preliminary: DeploymentSnapshot = {
        state: "configured",
        settings,
        activeContract,
        canWrite,
      };
      const selected = SOURCE_DEFINITIONS.filter(
        (source) => expectationFor(preliminary, source.id) === "active",
      );
      const names = [
        ...new Set(selected.flatMap((source) => source.indexMacros)),
      ];
      const definitions = await Promise.allSettled(
        names.map((name) =>
          this.request(
            `configs/conf-macros/${encodeURIComponent(name)}`,
            signal,
          ),
        ),
      );
      if (signal?.aborted)
        throw new Error("Deployment settings request cancelled.");
      const sourceConfiguration: NonNullable<
        DeploymentSnapshot["sourceConfiguration"]
      > = {};
      for (const source of selected) {
        const indexes: string[][] = [];
        let state: "configured" | "not_configured" | "unavailable" =
          "configured";
        for (const name of source.indexMacros) {
          const result = definitions[names.indexOf(name)];
          try {
            if (result.status !== "fulfilled")
              throw new Error("Macro unavailable");
            const definition = entry(result.value).content.definition;
            if (typeof definition !== "string")
              throw new Error("Macro definition unavailable");
            const parsed = indexNames({ name, definition });
            indexes.push(parsed);
            if (!parsed.length && state !== "unavailable")
              state = "not_configured";
          } catch {
            state = "unavailable";
          }
        }
        if (
          source.evidence.includes("derived_traffic") &&
          indexes.length > 1 &&
          indexes.some(
            (values) => values.length !== 1 || values[0] !== indexes[0][0],
          ) &&
          state !== "unavailable"
        )
          state = "not_configured";
        sourceConfiguration[source.id] = state;
      }
      return {
        state: "configured",
        settings,
        activeContract,
        canWrite,
        sourceConfiguration,
        ...(activeContract === undefined
          ? {
              error:
                "Active data contract could not be verified: public selectors are unavailable or inconsistent.",
            }
          : {}),
      };
    } catch (reason) {
      return {
        state: "unavailable",
        activeContract,
        canWrite: false,
        error:
          reason instanceof Error
            ? reason.message
            : "Deployment settings are invalid.",
      };
    }
  }

  async write(
    settings: DeploymentExpectations,
    expectedRevision?: string,
    signal?: AbortSignal,
  ): Promise<DeploymentSnapshot> {
    const validated = validateExpectations(settings);
    const before = await this.read(signal);
    if (!before.canWrite)
      throw new Error(
        "Administrator capability and collection write permission are required.",
      );
    if (before.state === "unavailable")
      throw new Error(
        "Read deployment expectations successfully before changing them.",
      );
    if (before.settings?.revision !== expectedRevision)
      throw new Error(
        "Deployment expectations changed. Refresh before saving.",
      );
    const next = { ...validated, revision: crypto.randomUUID() };
    const document = {
      _key: KEY,
      revision: next.revision,
      settings_json: JSON.stringify(next),
    };
    await this.request(
      before.state === "absent" ? COLLECTION : `${COLLECTION}/${KEY}`,
      signal,
      document,
    );
    const after = await this.read(signal);
    if (
      after.state !== "configured" ||
      JSON.stringify(after.settings) !== JSON.stringify(next)
    )
      throw new Error(
        "Deployment settings readback did not match. Refresh and verify the saved values before retrying.",
      );
    return after;
  }
}

export const deploymentClient: DeploymentClient = new ToolkitDeploymentClient();
