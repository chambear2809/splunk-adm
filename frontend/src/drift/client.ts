import { eligibility, type Capture, type WatchDefinition } from "./model";

export type CaptureReference = { reference: string; capture: Capture };
export interface DependencySource {
  capture(
    window: { start: number; end: number },
    signal: AbortSignal,
  ): Promise<CaptureReference>;
}
export type BaselineMetadata = {
  id: string;
  name: string;
  revision: number;
  version: number;
};
export type BaselineReceipt = Pick<
  BaselineMetadata,
  "id" | "revision" | "version"
>;
export type BaselineRecord = BaselineMetadata & { capture: Capture };
export interface BaselineRepository {
  list(
    signal: AbortSignal,
    after?: string,
  ): Promise<{ items: BaselineMetadata[]; next: string | null }>;
  get(
    id: string,
    signal: AbortSignal,
    version?: number,
  ): Promise<BaselineRecord>;
  create(
    name: string,
    reference: string,
    requestId: string,
  ): Promise<BaselineReceipt>;
  version(
    id: string,
    expectedRevision: number,
    reference: string,
    requestId: string,
  ): Promise<BaselineReceipt>;
  setWatch(
    id: string,
    expectedRevision: number,
    definition: WatchDefinition,
    requestId: string,
  ): Promise<BaselineReceipt>;
  watches(id: string, signal: AbortSignal): Promise<WatchDefinition[]>;
}

const object = (value: unknown): value is Record<string, unknown> =>
  !!value && typeof value === "object" && !Array.isArray(value);
const text = (value: unknown): value is string =>
  typeof value === "string" &&
  value.trim().length > 0 &&
  value.length <= 1024 &&
  !/[\uD800-\uDFFF]/u.test(value);
const number = (value: unknown): value is number =>
  typeof value === "number" && Number.isFinite(value) && value >= 0;
const window = (value: unknown) =>
  object(value) &&
  number(value.start) &&
  number(value.end) &&
  value.end > value.start &&
  value.end <= 8640000000000;

/** Transport validation never grants permission or establishes stable source identity. */
export function checkedCapture(value: unknown): Capture {
  if (
    !object(value) ||
    !text(value.id) ||
    !object(value.coverage) ||
    !Array.isArray(value.dependencies) ||
    value.dependencies.length > 10000
  )
    throw new Error(
      "Dependency capture is malformed or exceeds the record limit.",
    );
  const c = value.coverage;
  if (
    !window(c.requested) ||
    !window(c.returned) ||
    ![
      c.authority,
      c.scope,
      c.sourceRevision,
      c.configRevision,
      c.normalizationRevision,
    ].every(text) ||
    c.signatureVersion !== 1 ||
    !["allowed", "denied", "unknown"].includes(String(c.permission)) ||
    ![c.complete, c.capped, c.progressive, c.sampled, c.stale].every(
      (flag) => typeof flag === "boolean",
    ) ||
    !number(c.knowledgeHorizon) ||
    !number(c.requiredLatenessSeconds)
  )
    throw new Error("Dependency capture coverage is malformed.");
  for (const d of value.dependencies) {
    if (
      !object(d) ||
      ![
        d.authority,
        d.scope,
        d.source,
        d.destination,
        d.protocol,
        d.relation,
        d.direction,
      ].every(text) ||
      !Number.isInteger(d.port) ||
      (d.port as number) < 1 ||
      (d.port as number) > 65535 ||
      (d.blocked !== null && typeof d.blocked !== "boolean") ||
      (d.redundancyDomains !== undefined &&
        (!Array.isArray(d.redundancyDomains) ||
          d.redundancyDomains.length > 64 ||
          !d.redundancyDomains.every(text)))
    )
      throw new Error("Dependency record identity or protocol is malformed.");
  }
  const capture = structuredClone(value) as unknown as Capture;
  eligibility(capture); // Structural checks above make domain admission safe to evaluate.
  return capture;
}

export class BaselineWriteError extends Error {
  constructor(
    message: string,
    readonly uncertain: boolean,
  ) {
    super(message);
  }
}
