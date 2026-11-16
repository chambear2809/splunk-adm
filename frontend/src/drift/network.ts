import { createFetchInit } from "@splunk/splunk-utils/fetch";
import { createRESTURL } from "@splunk/splunk-utils/url";
import {
  BaselineWriteError,
  checkedCapture,
  type BaselineMetadata,
  type BaselineReceipt,
  type BaselineRecord,
  type BaselineRepository,
  type CaptureReference,
  type DependencySource,
  type Occurrence,
  type WatchWithVersion,
  type WatchStatus,
} from "./client";
import type { WatchDefinition } from "./model";

export type DependencySelection = {
  service: string;
  environment: string;
  cluster: string;
  namespace: string;
};
export type MonitorCapabilities = {
  available: boolean;
  sourceAvailable: boolean;
  qualificationReasons: string[];
};
type Transport = (url: string, init: RequestInit) => Promise<Response>;
const object = (v: unknown): v is Record<string, unknown> =>
  !!v && typeof v === "object" && !Array.isArray(v);
const str = (v: unknown): v is string =>
  typeof v === "string" && v.length > 0 && v.length <= 4096;
const integer = (v: unknown): v is number =>
  Number.isSafeInteger(v) && (v as number) >= 1;
const finite = (v: unknown): v is number =>
  typeof v === "number" && Number.isFinite(v) && v >= 0 && v <= 8640000000000;
const metadata = (v: unknown): v is BaselineMetadata =>
  object(v) &&
  str(v.id) &&
  str(v.name) &&
  integer(v.revision) &&
  integer(v.version);
const receipt = (v: unknown): v is BaselineReceipt =>
  object(v) &&
  str(v.id) &&
  integer(v.revision) &&
  (v.version === undefined || integer(v.version)) &&
  (v.inserted === undefined ||
    (Number.isSafeInteger(v.inserted) && (v.inserted as number) >= 0)) &&
  (v.surfaced === undefined ||
    (Number.isSafeInteger(v.surfaced) && (v.surfaced as number) >= 0)) &&
  (v.resultWithheld === undefined || v.resultWithheld === true);
const watch = (v: unknown): v is WatchWithVersion =>
  object(v) &&
  str(v.id) &&
  integer(v.threshold) &&
  finite(v.cooldownSeconds) &&
  integer(v.baselineVersion) &&
  Array.isArray(v.expectedWindows) &&
  v.expectedWindows.every(
    (w: unknown) =>
      object(w) && finite(w.start) && finite(w.end) && w.start < w.end,
  );
const occurrence = (v: unknown): v is Occurrence =>
  object(v) &&
  integer(v.seq) &&
  str(v.signature) &&
  object(v.window) &&
  finite(v.window.start) &&
  finite(v.window.end) &&
  v.window.start < v.window.end &&
  finite(v.observedAt);
const page = <T>(
  v: unknown,
  guard: (item: unknown) => item is T,
  cursor: (x: unknown) => boolean,
): v is {
  items: T[];
  next: T extends never ? never : string | number | null;
} =>
  object(v) &&
  Array.isArray(v.items) &&
  v.items.length <= 100 &&
  v.items.every(guard) &&
  (v.next === null || cursor(v.next));

/** All source qualification and access checks belong to the server. */
export function createDependencyClient(options: {
  transport: Transport;
  baseUrl: string;
  selection: DependencySelection;
}) {
  const url = (path: string) => `${options.baseUrl.replace(/\/$/, "")}${path}`;
  async function request(
    path: string,
    init: RequestInit,
    mutation = false,
  ): Promise<unknown> {
    let response: Response;
    try {
      response = await options.transport(url(path), init);
    } catch {
      if (mutation)
        throw new BaselineWriteError(
          "The write outcome is unknown. Retry the same request.",
          true,
        );
      throw new Error("Dependency service is unavailable.");
    }
    if (!response.ok) {
      const uncertain =
        mutation &&
        ([401, 403, 404].includes(response.status) || response.status >= 500);
      if (mutation)
        throw new BaselineWriteError(
          response.status === 422
            ? "Dependency evidence is unavailable or cannot be revalidated."
            : uncertain
              ? "The write outcome is unknown. Retry the same request."
              : `The baseline request failed (${response.status}).`,
          uncertain,
        );
      throw new Error(
        response.status === 422
          ? "Qualified dependency evidence is unavailable."
          : response.status === 401 ||
              response.status === 403 ||
              response.status === 404
            ? "Dependency access could not be confirmed."
            : "Dependency service is unavailable.",
      );
    }
    try {
      return await response.json();
    } catch {
      if (mutation)
        throw new BaselineWriteError(
          "The write outcome is unknown. Retry the same request.",
          true,
        );
      throw new Error("Dependency service returned an invalid response.");
    }
  }
  const read = (path: string, signal: AbortSignal) =>
    request(path, { method: "GET", signal });
  const write = async (
    path: string,
    body: object,
    key: string,
    expectedId?: string,
    evaluation = false,
  ): Promise<BaselineReceipt> => {
    const value = await request(
      path,
      {
        method: "POST",
        headers: { "Content-Type": "application/json", "Idempotency-Key": key },
        body: JSON.stringify(body),
      },
      true,
    );
    if (
      !receipt(value) ||
      (expectedId !== undefined && value.id !== expectedId) ||
      (evaluation &&
        !(
          value.resultWithheld === true ||
          (value.resultWithheld === undefined &&
            value.inserted !== undefined &&
            value.surfaced !== undefined)
        ))
    )
      throw new BaselineWriteError(
        "The write outcome is unknown. Retry the same request.",
        true,
      );
    return value;
  };
  const path = (id: string) => `/baselines/${encodeURIComponent(id)}`;
  const capabilities = async (
    signal: AbortSignal,
  ): Promise<MonitorCapabilities> => {
    const v = await read("/capabilities", signal);
    if (
      !object(v) ||
      typeof v.available !== "boolean" ||
      typeof v.sourceAvailable !== "boolean" ||
      (v.sourceAvailable && !v.available) ||
      !Array.isArray(v.qualificationReasons) ||
      !v.qualificationReasons.every(
        (reason: unknown) => typeof reason === "string",
      )
    )
      throw new Error("Dependency service returned invalid availability.");
    return v as MonitorCapabilities;
  };
  const source: DependencySource = {
    async capture(window, signal): Promise<CaptureReference> {
      const query = new URLSearchParams({
        ...options.selection,
        start: String(window.start),
        end: String(window.end),
      });
      const value = await read(`/capture?${query}`, signal);
      if (!object(value) || !str(value.reference))
        throw new Error("Dependency capture response is invalid.");
      return {
        reference: value.reference,
        capture: checkedCapture(value.capture),
      };
    },
  };
  const repository: BaselineRepository = {
    async list(signal, after) {
      const v = await read(
        `/baselines${after ? `?after=${encodeURIComponent(after)}` : ""}`,
        signal,
      );
      if (!page(v, metadata, str)) throw new Error("Baseline list is invalid.");
      return { items: v.items, next: v.next as string | null };
    },
    async get(id, signal, version) {
      const v = await read(
        `${path(id)}${version ? `/versions/${version}` : ""}`,
        signal,
      );
      if (!metadata(v) || !object(v))
        throw new Error("Baseline response is invalid.");
      return {
        ...v,
        capture: checkedCapture(
          (v as unknown as Record<string, unknown>).capture,
        ),
      } as BaselineRecord;
    },
    create: (name, reference, key) =>
      write("/baselines", { name, reference }, key),
    version: (id, expected_revision, reference, key) =>
      write(`${path(id)}/versions`, { expected_revision, reference }, key, id),
    setWatch: (id, expected_revision, definition: WatchDefinition, key) =>
      write(`${path(id)}/watches`, { expected_revision, definition }, key, id),
    async watches(id, signal) {
      const v = await read(`${path(id)}/watches`, signal);
      if (!page(v, watch, str))
        throw new Error("Watch definitions are invalid.");
      return v.items;
    },
    async watchPage(id, signal, after) {
      const v = await read(
        `${path(id)}/watches${after ? `?after=${encodeURIComponent(after)}` : ""}`,
        signal,
      );
      if (!page(v, watch, str))
        throw new Error("Watch definitions are invalid.");
      return { items: v.items, next: v.next as string | null };
    },
    async versions(id, signal, after) {
      const v = await read(
        `${path(id)}/versions${after ? `?after=${after}` : ""}`,
        signal,
      );
      if (
        !page(
          v,
          (x): x is { version: number } => object(x) && integer(x.version),
          integer,
        )
      )
        throw new Error("Version history is invalid.");
      return { items: v.items, next: v.next as number | null };
    },
    async occurrences(id, watchId, signal, after) {
      const v = await read(
        `${path(id)}/watches/${encodeURIComponent(watchId)}/occurrences${after ? `?after=${after}` : ""}`,
        signal,
      );
      if (!page(v, occurrence, integer))
        throw new Error("Watch history is invalid.");
      return { items: v.items, next: v.next as number | null };
    },
    async watchStatus(
      id,
      watchId,
      signature,
      now,
      signal,
    ): Promise<WatchStatus> {
      const query = new URLSearchParams({ signature, now: String(now) });
      const value = await read(
        `${path(id)}/watches/${encodeURIComponent(watchId)}/evaluate?${query}`,
        signal,
      );
      if (
        !object(value) ||
        !Number.isSafeInteger(value.count) ||
        (value.count as number) < 0 ||
        typeof value.thresholdMet !== "boolean" ||
        typeof value.expected !== "boolean" ||
        typeof value.coolingDown !== "boolean"
      )
        throw new Error("Watch status is invalid.");
      return value as WatchStatus;
    },
    evaluate: (
      id,
      watchId,
      expected_revision,
      baseline_version,
      reference,
      key,
    ) =>
      write(
        `${path(id)}/watches/${encodeURIComponent(watchId)}/evaluate`,
        { expected_revision, baseline_version, reference },
        key,
        id,
        true,
      ),
  };
  return { capabilities, source, repository };
}
export function splunkDependencyClient(selection: DependencySelection) {
  return createDependencyClient({
    baseUrl: createRESTURL("adm/dependency-monitoring", {
      app: "splunk_adm",
      owner: "nobody",
    }),
    transport: (url, init) => fetch(url, createFetchInit(init)),
    selection,
  });
}
