import { getDefaultFetchInit } from "@splunk/splunk-utils/fetch";
import { createRESTURL } from "@splunk/splunk-utils/url";
import { validateIndexName } from "../data/deploymentHealth";
import type {
  ChangeTimelineConfiguration,
  ChangeTimelineConfigurationClient,
} from "./types";

const ENABLED_MACRO = "adm_configuration_history_enabled";
const INDEX_MACRO = "adm_index_configuration_changes";
const ACTIVATION_MACRO = "adm_configuration_activation";
const MACRO_PATH =
  "configs/v1/conftypes/macros/stanzas:get?output_mode=json&view=app-merged";
const MAX_MACRO_RESPONSE_BYTES = 64 * 1024;

function isObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

async function readLimitedText(response: Response): Promise<string> {
  if (!response.body) {
    const text = await response.text();
    if (new TextEncoder().encode(text).byteLength > MAX_MACRO_RESPONSE_BYTES)
      throw new Error("Shared configuration is unavailable.");
    return text;
  }
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  const parts: string[] = [];
  let bytes = 0;
  try {
    for (;;) {
      const part = await reader.read();
      if (part.done) break;
      bytes += part.value.byteLength;
      if (bytes > MAX_MACRO_RESPONSE_BYTES) {
        await reader.cancel();
        throw new Error("Shared configuration is unavailable.");
      }
      parts.push(decoder.decode(part.value, { stream: true }));
    }
    parts.push(decoder.decode());
    return parts.join("");
  } finally {
    reader.releaseLock();
  }
}

/** Reads one fixed shared macro through the caller's app-merged configuration view. */
export class ToolkitChangeTimelineConfigurationClient implements ChangeTimelineConfigurationClient {
  constructor(
    private readonly fetcher: typeof fetch = (...args) => fetch(...args),
  ) {}

  private async definition(
    name: string,
    signal?: AbortSignal,
  ): Promise<string> {
    if (![ENABLED_MACRO, INDEX_MACRO, ACTIVATION_MACRO].includes(name))
      throw new Error("Shared configuration is unavailable.");
    const controller = new AbortController();
    const abort = () => controller.abort();
    signal?.addEventListener("abort", abort, { once: true });
    if (signal?.aborted) controller.abort();
    const timeout = setTimeout(abort, 10_000);
    try {
      const defaults = getDefaultFetchInit();
      const headers = new Headers(defaults.headers);
      headers.set("Content-Type", "application/json");
      const response = await this.fetcher(
        createRESTURL(MACRO_PATH, { app: "splunk_adm", owner: "nobody" }),
        {
          ...defaults,
          method: "POST",
          headers,
          signal: controller.signal,
          body: JSON.stringify({ stanza: name }),
        },
      );
      if (!response.ok) throw new Error("Shared configuration is unavailable.");
      const payload: unknown = JSON.parse(await readLimitedText(response));
      if (
        !isObject(payload) ||
        !Array.isArray(payload.settings) ||
        !payload.settings.every(
          (item) => isObject(item) && typeof item.setting === "string",
        )
      )
        throw new Error("Shared configuration is unavailable.");
      const definitions = payload.settings.filter(
        (item) => isObject(item) && item.setting === "definition",
      );
      if (
        definitions.length !== 1 ||
        !isObject(definitions[0]) ||
        typeof definitions[0].value !== "string" ||
        definitions[0].value.length > 256
      )
        throw new Error("Shared configuration is unavailable.");
      return definitions[0].value;
    } catch {
      throw new Error("Shared configuration is unavailable.");
    } finally {
      clearTimeout(timeout);
      signal?.removeEventListener("abort", abort);
    }
  }

  async read(signal?: AbortSignal): Promise<ChangeTimelineConfiguration> {
    const enabled = await this.definition(ENABLED_MACRO, signal);
    if (signal?.aborted)
      throw new Error("Shared configuration read cancelled.");
    if (enabled === "0") return { state: "not_selected" };
    if (enabled !== "1")
      throw new Error("Shared configuration is unavailable.");

    const indexDefinition = await this.definition(INDEX_MACRO, signal);
    if (signal?.aborted)
      throw new Error("Shared configuration read cancelled.");
    const activationId = await this.definition(ACTIVATION_MACRO, signal);
    if (signal?.aborted)
      throw new Error("Shared configuration read cancelled.");
    const indexMatch = /^index=([a-z][a-z0-9_-]{0,79})$/.exec(indexDefinition);
    const index = indexMatch?.[1];
    if (
      !index ||
      index === "unconfigured_optional" ||
      validateIndexName(index) ||
      !/^[a-f0-9]{64}$/.test(activationId)
    )
      throw new Error("Shared configuration is unavailable.");
    return { state: "selected", index, activation_id: activationId };
  }
}

export const changeTimelineConfigurationClient: ChangeTimelineConfigurationClient =
  new ToolkitChangeTimelineConfigurationClient();

export function loadChangeTimelineConfiguration(
  client: ChangeTimelineConfigurationClient = changeTimelineConfigurationClient,
  signal?: AbortSignal,
): Promise<ChangeTimelineConfiguration> {
  return client.read(signal);
}
