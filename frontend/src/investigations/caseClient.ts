import { createFetchInit } from "@splunk/splunk-utils/fetch";
import { createRESTURL } from "@splunk/splunk-utils/url";

export type CaseWindow = { start: string; end: string };
export type CaseEntry = {
  id: string;
  revision: number;
  author: string;
  created_at: string;
  type: "note" | "hypothesis" | "question";
  text: string;
};
export type CaseCapture = {
  id: string;
  revision: number;
  author: string;
  created_at: string;
  label: string;
  captured_at: string;
  data: Record<string, unknown>;
};
export type CaseRecord = {
  schema_version: 1;
  id: string;
  revision: number;
  title: string;
  window: CaseWindow;
  entries: CaseEntry[];
  captures: CaseCapture[];
  capture_ids?: string[];
  redactions?: { captures: number; attachments: number };
  attachments: Record<string, unknown>[];
};
export type CaseList = { items: CaseRecord[]; next: string | null };
export type CaseReceipt =
  | { id: string; revision: number; revoked: true }
  | { id: string; deleted: true };
export type CaseMutation<T> = {
  readonly requestId: string;
  execute(): Promise<T>;
};
export type CaseTransport = (
  url: string,
  init: RequestInit,
) => Promise<Response>;

export class CaseError extends Error {
  constructor(
    message: string,
    readonly status?: number,
    readonly uncertain = false,
  ) {
    super(message);
    this.name = "CaseError";
  }
}
const object = (v: unknown): v is Record<string, unknown> =>
  !!v && typeof v === "object" && !Array.isArray(v);
const str = (v: unknown): v is string => typeof v === "string" && v.length > 0;
const uuid = (v: unknown): v is string =>
  typeof v === "string" &&
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(v);
const revision = (v: unknown): v is number =>
  Number.isSafeInteger(v) && (v as number) > 0;
const time = (v: unknown): v is string =>
  str(v) && Number.isFinite(Date.parse(v));
const metadata = (v: unknown): v is Record<string, unknown> =>
  object(v) &&
  str(v.id) &&
  revision(v.revision) &&
  str(v.author) &&
  time(v.created_at);
function record(v: unknown): v is CaseRecord {
  return (
    object(v) &&
    v.schema_version === 1 &&
    str(v.id) &&
    revision(v.revision) &&
    str(v.title) &&
    object(v.window) &&
    time(v.window.start) &&
    time(v.window.end) &&
    Date.parse(v.window.start) < Date.parse(v.window.end) &&
    Array.isArray(v.entries) &&
    v.entries.every(
      (e: unknown) =>
        metadata(e) &&
        (e.type === "note" ||
          e.type === "hypothesis" ||
          e.type === "question") &&
        typeof e.text === "string",
    ) &&
    Array.isArray(v.captures) &&
    v.captures.every(
      (e: unknown) =>
        metadata(e) && str(e.label) && time(e.captured_at) && object(e.data),
    ) &&
    (v.capture_ids === undefined ||
      (Array.isArray(v.capture_ids) &&
        v.capture_ids.every(uuid) &&
        new Set(v.capture_ids).size === v.capture_ids.length)) &&
    (v.redactions === undefined ||
      (object(v.redactions) &&
        Number.isSafeInteger(v.redactions.captures) &&
        (v.redactions.captures as number) >= 0 &&
        Number.isSafeInteger(v.redactions.attachments) &&
        (v.redactions.attachments as number) >= 0)) &&
    Array.isArray(v.attachments) &&
    v.attachments.every(
      (e: unknown) =>
        metadata(e) &&
        str(e.label) &&
        str(e.media_type) &&
        typeof e.content === "string",
    )
  );
}
const receipt = (v: unknown): v is CaseReceipt =>
  object(v) &&
  str(v.id) &&
  (v.deleted === true || (v.revoked === true && revision(v.revision)));
const listing = (v: unknown): v is CaseList =>
  object(v) &&
  Array.isArray(v.items) &&
  v.items.every(record) &&
  (v.next === null || str(v.next));

type Guard<T> = (v: unknown) => v is T;
export interface CaseClient {
  list(signal?: AbortSignal, after?: string): Promise<CaseList>;
  get(
    id: string,
    signal?: AbortSignal,
    captureId?: string,
  ): Promise<CaseRecord>;
  export(
    id: string,
    signal?: AbortSignal,
    captureId?: string,
  ): Promise<CaseRecord>;
  create(title: string, window: CaseWindow): CaseMutation<CaseRecord>;
  append(
    id: string,
    expectedRevision: number,
    type: CaseEntry["type"],
    text: string,
  ): CaseMutation<CaseRecord>;
  capture(
    id: string,
    expectedRevision: number,
    reference: string,
    label?: string,
  ): CaseMutation<CaseRecord>;
  share(
    id: string,
    expectedRevision: number,
    member: string,
    grant: boolean,
  ): CaseMutation<CaseRecord | CaseReceipt>;
  delete(id: string, expectedRevision: number): CaseMutation<CaseReceipt>;
}

/** The transport owns authentication; no identity is accepted from callers. */
export function createCaseClient(options: {
  transport: CaseTransport;
  baseUrl: string;
  requestId?: () => string;
}): CaseClient {
  const { transport, baseUrl } = options;
  const url = (path: string) => `${baseUrl.replace(/\/$/, "")}${path}`;
  async function request<T>(
    path: string,
    init: RequestInit,
    guard: Guard<T>,
    mutation = false,
  ): Promise<T> {
    let response: Response;
    try {
      response = await transport(url(path), init);
    } catch {
      throw new CaseError(
        mutation
          ? "The result is unknown. Retry the same request."
          : "Unable to reach the shared case store.",
        undefined,
        mutation,
      );
    }
    if (!response.ok) {
      if (mutation && [401, 403, 404].includes(response.status))
        throw new CaseError(
          "Access or permission is unavailable and the write outcome is unconfirmed. Restore access and retry the same request.",
          response.status,
          true,
        );
      if (response.status >= 500)
        throw new CaseError(
          mutation
            ? "The result is unknown. Retry the same request."
            : "The shared case store is unavailable.",
          response.status,
          mutation,
        );
      const message =
        response.status === 401 || response.status === 403
          ? "You do not have permission to access this case."
          : response.status === 409
            ? "This case changed. Reload it before making another change."
            : response.status === 422
              ? "Evidence cannot currently be revalidated. Your notes remain available."
              : `The case request failed (${response.status}).`;
      throw new CaseError(message, response.status);
    }
    let value: unknown;
    try {
      value = await response.json();
    } catch {
      throw new CaseError(
        "The case store returned an invalid response.",
        response.status,
        mutation,
      );
    }
    if (!guard(value))
      throw new CaseError(
        "The case store returned an invalid response.",
        response.status,
        mutation,
      );
    return value;
  }
  const read = <T>(path: string, guard: Guard<T>, signal?: AbortSignal) =>
    request(path, { method: "GET", signal }, guard);
  const mutate = <T>(
    path: string,
    method: string,
    body: object,
    guard: Guard<T>,
  ): CaseMutation<T> => {
    const requestId = (options.requestId ?? (() => crypto.randomUUID()))();
    const payload = JSON.stringify(body);
    let inFlight: Promise<T> | undefined;
    let resolved: T | undefined;
    let settled = false;
    return {
      requestId,
      execute() {
        if (settled) return Promise.resolve(resolved as T);
        if (inFlight) return inFlight;
        inFlight = request(
          path,
          {
            method,
            headers: {
              "Content-Type": "application/json",
              "Idempotency-Key": requestId,
            },
            body: payload,
          },
          guard,
          true,
        )
          .then((value) => {
            settled = true;
            resolved = value;
            return value;
          })
          .finally(() => {
            inFlight = undefined;
          });
        return inFlight;
      },
    };
  };
  const itemPath = (id: string) => `/cases/${encodeURIComponent(id)}`;
  const captureQuery = (captureId?: string) => {
    if (captureId === undefined) return "";
    if (!uuid(captureId)) throw new CaseError("Invalid capture selector.");
    return `?capture_id=${encodeURIComponent(captureId)}`;
  };
  return {
    list: (signal, after) =>
      read(
        `/cases${after ? `?after=${encodeURIComponent(after)}` : ""}`,
        listing,
        signal,
      ),
    get: async (id, signal, captureId) =>
      read(`${itemPath(id)}${captureQuery(captureId)}`, record, signal),
    export: async (id, signal, captureId) =>
      read(`${itemPath(id)}/export${captureQuery(captureId)}`, record, signal),
    create: (title, window) =>
      mutate("/cases", "POST", { schema_version: 1, title, window }, record),
    append: (id, expectedRevision, type, text) =>
      mutate(
        `${itemPath(id)}/entries`,
        "POST",
        { expected_revision: expectedRevision, item: { type, text } },
        record,
      ),
    capture: (id, expectedRevision, reference, label) =>
      mutate(
        `${itemPath(id)}/captures`,
        "POST",
        {
          expected_revision: expectedRevision,
          reference,
          ...(label ? { label } : {}),
        },
        (v): v is CaseRecord => record(v) && v.id === id,
      ),
    share: (id, expectedRevision, member, grant) =>
      mutate(
        `${itemPath(id)}/share`,
        "POST",
        { expected_revision: expectedRevision, member, grant },
        (v): v is CaseRecord | CaseReceipt =>
          (record(v) && v.id === id) ||
          (receipt(v) && v.id === id && "revoked" in v),
      ),
    delete: (id, expectedRevision) =>
      mutate(
        itemPath(id),
        "DELETE",
        { expected_revision: expectedRevision },
        (v): v is CaseReceipt => receipt(v) && v.id === id && "deleted" in v,
      ),
  };
}

/** Uses Splunk's authenticated browser transport and app namespace. */
export function splunkCaseClient(): CaseClient {
  return createCaseClient({
    baseUrl: createRESTURL("adm/investigations", {
      app: "splunk_adm",
      owner: "nobody",
    }),
    transport: (url, init) => fetch(url, createFetchInit(init)),
  });
}
