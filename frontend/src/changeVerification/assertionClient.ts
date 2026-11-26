import { getDefaultFetchInit } from "@splunk/splunk-utils/fetch";
import { createRESTURL } from "@splunk/splunk-utils/url";
import { validateAssertion, type Assertion } from "./model";

const object = (value: unknown): value is Record<string, unknown> =>
  !!value && typeof value === "object" && !Array.isArray(value);

export interface AssertionsDocument {
  revision: string | null;
  assertions: Assertion[];
}

export class AssertionStoreError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = "AssertionStoreError";
  }
}

const REQUEST_TIMEOUT_MS = 30_000;

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
  throw new AssertionStoreError("Saved assertions are incomplete.", 502);
}

/** Every stored row must validate; one bad row rejects the document (fail closed). */
export function assertionsOf(payload: unknown): Assertion[] {
  if (payload === null || payload === undefined) return [];
  if (!object(payload) || !Array.isArray(payload.assertions))
    throw new AssertionStoreError("Saved assertions are malformed.", 502);
  try {
    return payload.assertions.map(validateAssertion);
  } catch {
    throw new AssertionStoreError("A saved assertion is malformed.", 502);
  }
}

export function storeMessage(error: unknown): string {
  if (error instanceof AssertionStoreError) {
    if (error.status === 403 && /owned by another user/.test(error.message))
      return `${error.message} Only the owner can change or remove it.`;
    if (error.status === 403)
      return "Saving needs write access to the adm_change_assertions collection (admin or sc_admin by default). Drafts still run.";
    if (error.status === 409)
      return "Someone else saved assertions first. Reload and reapply your drafts.";
    return error.message;
  }
  return error instanceof Error
    ? error.message
    : "Saved assertions are unavailable.";
}

/** Shared assertions in the collaboration ledger (kind=assertions). */
export class AssertionClient {
  constructor(
    private readonly fetcher: typeof fetch = (...args) => fetch(...args),
  ) {}

  private async request(body?: unknown, signal?: AbortSignal) {
    const defaults = getDefaultFetchInit();
    const headers = new Headers(defaults.headers);
    if (body !== undefined) headers.set("Content-Type", "application/json");
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    const onAbort = () => controller.abort();
    signal?.addEventListener("abort", onAbort, { once: true });
    try {
      const response = await this.fetcher(
        createRESTURL("adm/collaboration?kind=assertions&output_mode=json", {
          app: "splunk_adm",
          owner: "nobody",
        }),
        {
          ...defaults,
          headers,
          signal: controller.signal,
          method: body === undefined ? "GET" : "POST",
          ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
        },
      );
      const payload: unknown = await response.json().catch(() => undefined);
      if (!response.ok)
        throw new AssertionStoreError(
          object(payload) && typeof payload.error === "string"
            ? payload.error
            : `Saved assertions request failed (HTTP ${response.status}).`,
          response.status,
        );
      return unwrap(payload);
    } finally {
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
    }
  }

  async load(signal?: AbortSignal): Promise<AssertionsDocument> {
    const content = await this.request(undefined, signal);
    return {
      revision: typeof content.revision === "string" ? content.revision : null,
      assertions: assertionsOf(content.payload),
    };
  }

  async save(
    assertions: Assertion[],
    expectedRevision: string | null,
    requestId: string,
    signal?: AbortSignal,
  ): Promise<AssertionsDocument> {
    const content = await this.request(
      { expectedRevision, requestId, payload: { assertions } },
      signal,
    );
    const revision =
      typeof content.committedRevision === "string"
        ? content.committedRevision
        : typeof content.revision === "string"
          ? content.revision
          : null;
    if (!revision)
      throw new AssertionStoreError(
        "The save was not confirmed; reload before retrying.",
        502,
      );
    return { revision, assertions: assertionsOf(content.payload) };
  }
}
