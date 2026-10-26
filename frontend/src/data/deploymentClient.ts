import { getDefaultFetchInit } from "@splunk/splunk-utils/fetch";
import { createRESTURL } from "@splunk/splunk-utils/url";
import {
  validateExpectations,
  DATA_CONTRACT_SELECTORS,
  normalizeDefinition,
  SOURCE_DEFINITIONS,
  expectationFor,
  indexNames,
  UNCONFIGURED_DNS_INDEX,
  UNCONFIGURED_OPTIONAL_INDEX,
  type DeploymentClient,
  type DeploymentExpectations,
  type DeploymentSnapshot,
} from "./deploymentHealth";

const ENDPOINT = "adm/deployment-settings";
const UNCERTAIN =
  "Save outcome is uncertain. Your draft is preserved; retry the same save to verify it.";
const object = (value: unknown): value is Record<string, unknown> =>
  !!value && typeof value === "object" && !Array.isArray(value);
const validCapacity = (value: unknown): value is number =>
  typeof value === "number" && Number.isInteger(value) && value >= 0;
export class DeploymentWriteError extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message);
  }
}
class HTTPError extends DeploymentWriteError {
  constructor(
    readonly status: number,
    payload?: unknown,
  ) {
    super(
      object(payload) && typeof payload.code === "string"
        ? payload.code
        : "unavailable",
      object(payload) && typeof payload.error === "string"
        ? payload.error
        : `Deployment settings request failed (HTTP ${status}).`,
    );
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
  private pending = new Map<string, string>();
  private observedRevision?: string;
  private namespace?: string;
  // Native fetch throws "Illegal invocation" when called as another object's method.
  constructor(
    private readonly fetcher: typeof fetch = (...args) => fetch(...args),
  ) {}
  private async request(
    path: string,
    signal?: AbortSignal,
    body?: unknown,
    global = false,
    readOnlyPost = false,
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
      const endpoint = `${path}${path.includes("?") ? "&" : "?"}output_mode=json`;
      const mayWrite = body !== undefined && !readOnlyPost;
      let response: Response;
      try {
        response = await this.fetcher(
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
      } catch (reason) {
        // A timed-out, cancelled or dropped write may still have committed.
        if (mayWrite) throw new DeploymentWriteError("uncertain", UNCERTAIN);
        throw reason;
      }
      const payload: unknown = await response.json().catch(() => undefined);
      const coded = object(payload) && typeof payload.code === "string";
      // A proxy/gateway failure on a write says nothing about whether the insert landed.
      if (mayWrite && (response.ok ? payload === undefined : !coded))
        throw new DeploymentWriteError("uncertain", UNCERTAIN);
      if (!response.ok) throw new HTTPError(response.status, payload);
      if (payload === undefined)
        throw new Error("Deployment settings response is not JSON.");
      return payload;
    } finally {
      clearTimeout(timeout);
      signal?.removeEventListener("abort", abort);
    }
  }

  /** A denied legacy read may use the caller-authorized app-merged view. */
  private async macro(name: string, signal?: AbortSignal): Promise<unknown> {
    if (!/^adm_[a-z0-9_]+(?:\([1-9][0-9]*\))?$/.test(name))
      throw new Error("Invalid shared selector name.");
    try {
      return await this.request(
        `configs/conf-macros/${encodeURIComponent(name)}`,
        signal,
      );
    } catch (error) {
      if (!(error instanceof HTTPError) || error.status !== 403) throw error;
    }
    // This POST reads a fixed app/nobody stanza; it neither writes nor elevates.
    const payload = await this.request(
      "configs/v1/conftypes/macros/stanzas:get?view=app-merged",
      signal,
      { stanza: name },
      false,
      true,
    );
    if (
      !object(payload) ||
      !Array.isArray(payload.settings) ||
      !payload.settings.every(
        (item) => object(item) && typeof item.setting === "string",
      )
    )
      throw new Error("Shared selector unavailable.");
    const definitions = payload.settings.filter(
      (item) => item.setting === "definition",
    );
    if (
      definitions.length !== 1 ||
      typeof definitions[0].value !== "string" ||
      definitions[0].value.length > 1048576
    )
      throw new Error("Shared selector unavailable.");
    return { entry: [{ content: { definition: definitions[0].value } }] };
  }

  async read(signal?: AbortSignal): Promise<DeploymentSnapshot> {
    const results = await Promise.allSettled([
      this.request(ENDPOINT, signal),
      Promise.all(
        DATA_CONTRACT_SELECTORS.map((selector) =>
          this.macro(selector.name, signal),
        ),
      ),
    ]);
    if (signal?.aborted)
      throw new Error("Deployment settings request cancelled.");
    let activeContract: 1 | 2 | undefined;
    const [record, contract] = results;
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
    if (record.status === "rejected") {
      return {
        state: "unavailable",
        activeContract,
        canWrite: false,
        error:
          "Deployment expectations are unavailable; check permissions and the supported settings endpoint. No direct KV write fallback is enabled.",
      };
    }

    try {
      if (
        !object(record.value) ||
        !["configured", "absent"].includes(String(record.value.state)) ||
        !Array.isArray(record.value.observedRevisions) ||
        !record.value.observedRevisions.every(
          (value) => typeof value === "string",
        )
      )
        throw new Error("Malformed deployment settings response.");
      const backend = record.value;
      const recordCount = backend.recordCount;
      const maxRecords = backend.maxRecords;
      const remainingRecords = backend.remainingRecords;
      const capacityValues = [recordCount, maxRecords, remainingRecords];
      if (
        capacityValues.some((value) => value !== undefined) &&
        (!capacityValues.every(validCapacity) ||
          !validCapacity(recordCount) ||
          !validCapacity(maxRecords) ||
          !validCapacity(remainingRecords) ||
          recordCount > maxRecords ||
          remainingRecords !== maxRecords - recordCount)
      )
        throw new Error("Malformed deployment settings capacity metadata.");
      const observedRevisions = backend.observedRevisions as string[];
      const namespace =
        typeof backend.namespace === "string" ? backend.namespace : undefined;
      const assertFresh = () => {
        if (this.namespace && namespace && this.namespace !== namespace)
          throw new Error(
            "Deployment settings namespace changed. Reload this page after verifying the deployment routing.",
          );
        if (
          this.observedRevision &&
          !observedRevisions.includes(this.observedRevision)
        )
          throw new Error(
            "Deployment settings refresh has not reached the previously observed revision. Retry after replication catches up.",
          );
      };
      assertFresh();
      const persistence = {
        namespace,
        observedRevisions,
        recordCount: validCapacity(recordCount) ? recordCount : undefined,
        maxRecords: validCapacity(maxRecords) ? maxRecords : undefined,
        remainingRecords: validCapacity(remainingRecords)
          ? remainingRecords
          : undefined,
        capacityWarning:
          typeof backend.capacityWarning === "string"
            ? backend.capacityWarning
            : undefined,
        canRetry: backend.canRetry === true,
        writeUnavailableReason:
          typeof backend.writeUnavailableReason === "string"
            ? backend.writeUnavailableReason
            : undefined,
      };
      const canWrite = backend.canWrite === true && namespace !== undefined;
      this.namespace = namespace ?? this.namespace;
      if (backend.state === "absent")
        return {
          state: "absent",
          activeContract,
          canWrite,
          ...persistence,
          error: "Deployment expectations have not been configured.",
        };
      const settings = validateExpectations(backend.settings);
      if (!observedRevisions.includes(settings.revision))
        throw new Error(
          "Deployment settings history does not verify its revision.",
        );
      this.observedRevision = settings.revision;
      this.namespace = namespace ?? this.namespace;
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
        names.map((name) => this.macro(name, signal)),
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
            const listed = indexNames({ name, definition });
            const parsed =
              listed.length === 1 &&
              [UNCONFIGURED_DNS_INDEX, UNCONFIGURED_OPTIONAL_INDEX].includes(
                listed[0],
              )
                ? []
                : listed;
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
      // Another read/save can observe a successor while index macros are in
      // flight. Recheck at publication so this snapshot cannot move it back.
      assertFresh();
      return {
        state: "configured",
        settings,
        activeContract,
        canWrite,
        ...persistence,
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
    const signature = JSON.stringify([
      expectedRevision ?? null,
      validated.sources,
    ]);
    const before = await this.read(signal);
    if (before.state === "unavailable")
      throw new DeploymentWriteError(
        "unavailable",
        before.error ??
          "Read deployment expectations successfully before changing them.",
      );
    const canRetryFinalSlot =
      this.pending.has(signature) && before.canRetry === true;
    if ((!before.canWrite && !canRetryFinalSlot) || !before.namespace)
      throw new DeploymentWriteError(
        "forbidden",
        before.writeUnavailableReason ??
          "Administrator capability and collection write permission are required.",
      );
    // Keep the operation identity on response loss/cancellation. A retry must
    // resolve that immutable operation even if another administrator advanced.
    const requestId = this.pending.get(signature) ?? crypto.randomUUID();
    this.pending.set(signature, requestId);
    const result = await this.request(ENDPOINT, signal, {
      settings: validated,
      expectedRevision: expectedRevision ?? null,
      requestId,
      namespace: before.namespace,
    });
    if (
      !object(result) ||
      typeof result.committedRevision !== "string" ||
      result.requestId !== requestId
    )
      throw new DeploymentWriteError("uncertain", UNCERTAIN);
    const after = await this.read(signal);
    if (
      after.state !== "configured" ||
      !after.observedRevisions?.includes(result.committedRevision)
    )
      throw new DeploymentWriteError(
        "uncertain",
        "Saved revision has not been verified by refresh. Your draft is preserved; retry the same save.",
      );
    this.pending.delete(signature);
    if (after.settings?.revision !== result.committedRevision)
      throw new DeploymentWriteError(
        "conflict",
        "Your save was committed, but newer expectations are now present. Your draft is preserved; reload before saving.",
      );
    return after;
  }
}

export const deploymentClient: DeploymentClient = new ToolkitDeploymentClient();
