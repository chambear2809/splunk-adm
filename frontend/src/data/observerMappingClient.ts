import { getDefaultFetchInit } from "@splunk/splunk-utils/fetch";
import { createRESTURL } from "@splunk/splunk-utils/url";

const object = (value: unknown): value is Record<string, unknown> =>
  !!value && typeof value === "object" && !Array.isArray(value);

export interface ObserverMapping {
  _key?: string;
  observer_kind: string;
  observer: string;
  scope: string;
  cluster?: string;
  mapping_status?: string;
}

function unwrap(payload: unknown): Record<string, unknown> {
  if (
    object(payload) &&
    Array.isArray(payload.entry) &&
    payload.entry.length === 1 &&
    object(payload.entry[0]) &&
    object(payload.entry[0].content)
  )
    return payload.entry[0].content;
  if (object(payload)) return payload;
  throw new Error("Observer mapping evidence is incomplete.");
}

function mapping(row: unknown): ObserverMapping | undefined {
  if (
    !object(row) ||
    typeof row.observer_kind !== "string" ||
    typeof row.observer !== "string" ||
    typeof row.scope !== "string"
  )
    return undefined;
  return {
    ...(typeof row._key === "string" ? { _key: row._key } : {}),
    observer_kind: row.observer_kind,
    observer: row.observer,
    scope: row.scope,
    ...(typeof row.cluster === "string" ? { cluster: row.cluster } : {}),
    ...(typeof row.mapping_status === "string"
      ? { mapping_status: row.mapping_status }
      : {}),
  };
}

const REQUEST_TIMEOUT_MS = 30_000;

function withTimeout(signal?: AbortSignal) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  const onAbort = () => controller.abort();
  signal?.addEventListener("abort", onAbort, { once: true });
  return {
    signal: controller.signal,
    done: () => {
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
    },
  };
}

export class ObserverMappingClient {
  constructor(
    private readonly fetcher: typeof fetch = (...args) => fetch(...args),
  ) {}

  private async request(body?: unknown, signal?: AbortSignal) {
    const defaults = getDefaultFetchInit();
    const headers = new Headers(defaults.headers);
    if (body !== undefined) headers.set("Content-Type", "application/json");
    const timed = withTimeout(signal);
    try {
      const response = await this.fetcher(
        createRESTURL("adm/observer-mapping?output_mode=json", {
          app: "splunk_adm",
          owner: "nobody",
        }),
        {
          ...defaults,
          headers,
          signal: timed.signal,
          method: body === undefined ? "GET" : "POST",
          ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
        },
      );
      const payload: unknown = await response.json().catch(() => undefined);
      if (!response.ok)
        throw new Error(
          object(payload) && typeof payload.error === "string"
            ? payload.error
            : `Observer mapping request failed (HTTP ${response.status}).`,
        );
      return unwrap(payload);
    } finally {
      timed.done();
    }
  }

  async list(signal?: AbortSignal): Promise<ObserverMapping[]> {
    const content = await this.request(undefined, signal);
    const rows = Array.isArray(content.mappings) ? content.mappings : [];
    return rows.flatMap((row) => {
      const item = mapping(row);
      return item ? [item] : [];
    });
  }

  async map(
    document: ObserverMapping,
    signal?: AbortSignal,
  ): Promise<ObserverMapping> {
    const content = await this.request(document, signal);
    return mapping(content.mapping) ?? document;
  }
}

export const observerMappingClient = new ObserverMappingClient();
