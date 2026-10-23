import registry from "../../../config/deployment-health.json";
import { activation } from "../../../research/cisco-pipeline-interface.json";

/** Shared with the read-only Python readiness tool. Never infer intent from events. */
export interface SourceDefinition {
  id: string;
  readinessImpact?: "core" | "optional_evidence";
  label: string;
  healthNames: string[];
  probeMacro: string;
  indexMacros: string[];
  qualitySources: string[];
  qualitySourcesByContract?: Record<string, string[]>;
  evidence: string[];
  cadenceSeconds: number;
  staleAfterSeconds: number;
  quiet: boolean;
  minimumContract: number;
  selectable: boolean;
  derivedFrom: string[];
  contract: number | null;
  observerKinds: string[];
  observerKindsByJob?: Record<string, string[]>;
  requiredFields: string[];
}
export interface JobDefinition {
  id: string;
  name: string;
  sourceIds: string[];
  contracts: number[];
  cadenceSeconds: number;
  graceSeconds: number;
  required: boolean;
  stage: string;
  prerequisiteIds: string[];
}
export const SOURCE_DEFINITIONS = registry.sources as SourceDefinition[];
export const JOB_DEFINITIONS: JobDefinition[] = registry.jobs;
export const HEALTH_LOOKBACK_SECONDS = registry.probeLookbackSeconds;
export interface HealthProbe {
  id: string;
  macro: string;
  part: "sources" | "quality" | "jobs";
}
/** Reviewed public selector contract, shared with migration's read-only inventory. */
export const DATA_CONTRACT_SELECTORS = activation.cutover_selectors;
export const CISCO_V2_SELECTORS: Record<string, string> = Object.fromEntries(
  DATA_CONTRACT_SELECTORS.filter(
    (selector) => selector.name !== "adm_data_contract_version",
  ).map((selector) => [selector.name, selector.after]),
);
export const normalizeDefinition = (value: string) =>
  value
    .replace(/\\\r?\n\s*/g, " ")
    .replace(/\s+/g, " ")
    .trim();
export type ExpectationState = "active" | "staged" | "not_selected";
export interface SourceExpectation {
  state: ExpectationState;
  cadenceSeconds: number;
  staleAfterSeconds: number;
}
export interface DeploymentExpectations {
  schemaVersion: 1;
  revision: string;
  sources: Record<string, SourceExpectation>;
}
export interface DeploymentSnapshot {
  state: "configured" | "absent" | "unavailable";
  settings?: DeploymentExpectations;
  /** Actual read-only selector; saving expectations cannot activate a contract. */
  activeContract?: 1 | 2;
  sourceConfiguration?: Record<
    string,
    "configured" | "not_configured" | "unavailable"
  >;
  canWrite: boolean;
  namespace?: string;
  observedRevisions?: string[];
  writeUnavailableReason?: string;
  error?: string;
}
export interface DeploymentClient {
  read(signal?: AbortSignal): Promise<DeploymentSnapshot>;
  write(
    settings: DeploymentExpectations,
    expectedRevision?: string,
    signal?: AbortSignal,
  ): Promise<DeploymentSnapshot>;
}

export function validateIndexName(value: string): string | undefined {
  return typeof value === "string" &&
    value.length <= 80 &&
    /^[a-z][a-z0-9_-]*$/.exec(value)?.[0] === value
    ? undefined
    : "Use a lowercase index name beginning with a letter (up to 80 letters, numbers, underscores or hyphens).";
}
export const isCoreSource = (source: SourceDefinition) =>
  source.readinessImpact !== "optional_evidence";
export const UNCONFIGURED_DNS_INDEX = "unconfigured_dns";
export const UNCONFIGURED_OPTIONAL_INDEX = "unconfigured_optional";
const indexTerm = /^index=([a-z][a-z0-9_-]{0,79})$/;
type IndexDefinition = { name: string; definition?: string };
export function indexNames(macro: IndexDefinition): string[] {
  const definition = macro.definition;
  if (!definition) return [];
  if (
    ["adm_summary_index_name", "adm_summary_index_v2_name"].includes(macro.name)
  )
    return !validateIndexName(definition) ? [definition] : [];
  const single = indexTerm.exec(definition);
  if (single && single[0] === definition) return [single[1]];
  const group =
    /^\((index=[a-z][a-z0-9_-]*(?:\s+OR\s+index=[a-z][a-z0-9_-]*)+)\)$/.exec(
      definition,
    );
  if (!group || group[0] !== definition) return [];
  const terms = group[1].split(/\s+OR\s+/);
  return terms.every((term) => indexTerm.test(term))
    ? terms.map((term) => term.slice("index=".length))
    : [];
}
export function indexName(macro: IndexDefinition): string | undefined {
  const names = indexNames(macro);
  return names.length === 1 ? names[0] : undefined;
}

const object = (value: unknown): value is Record<string, unknown> =>
  !!value && typeof value === "object" && !Array.isArray(value);
const keysAre = (value: Record<string, unknown>, allowed: string[]) =>
  Object.keys(value).every((key) => allowed.includes(key));

export function defaultExpectations(): DeploymentExpectations {
  return {
    schemaVersion: 1,
    revision: "draft",
    sources: Object.fromEntries(
      SOURCE_DEFINITIONS.filter((source) => source.selectable).map((source) => [
        source.id,
        {
          state: "not_selected",
          cadenceSeconds: source.cadenceSeconds,
          staleAfterSeconds: source.staleAfterSeconds,
        },
      ]),
    ),
  };
}

export function validateExpectations(value: unknown): DeploymentExpectations {
  if (
    !object(value) ||
    !keysAre(value, ["schemaVersion", "revision", "sources"]) ||
    value.schemaVersion !== 1 ||
    typeof value.revision !== "string" ||
    !/^[A-Za-z0-9_-]{1,80}$/.test(value.revision) ||
    !object(value.sources)
  )
    throw new Error(
      "Deployment expectations are invalid or use an unsupported schema.",
    );
  const sources: Record<string, SourceExpectation> = {};
  for (const [id, expectation] of Object.entries(value.sources)) {
    const definition = SOURCE_DEFINITIONS.find((source) => source.id === id);
    if (
      !definition?.selectable ||
      !object(expectation) ||
      !keysAre(expectation, ["state", "cadenceSeconds", "staleAfterSeconds"]) ||
      typeof expectation.state !== "string" ||
      !["active", "staged", "not_selected"].includes(expectation.state) ||
      !Number.isSafeInteger(expectation.cadenceSeconds) ||
      !Number.isSafeInteger(expectation.staleAfterSeconds) ||
      (expectation.cadenceSeconds as number) < 60 ||
      (expectation.staleAfterSeconds as number) <
        (expectation.cadenceSeconds as number) ||
      (expectation.staleAfterSeconds as number) > HEALTH_LOOKBACK_SECONDS
    )
      throw new Error(
        `Invalid expectations for ${id}: use whole seconds, cadence at least 60, and freshness between cadence and ${HEALTH_LOOKBACK_SECONDS} seconds.`,
      );
    sources[id] = {
      state: expectation.state as ExpectationState,
      cadenceSeconds: expectation.cadenceSeconds as number,
      staleAfterSeconds: expectation.staleAfterSeconds as number,
    };
  }
  return { schemaVersion: 1, revision: value.revision, sources };
}

/** Staged/inactive sources never make production jobs required. */
export function expectationFor(
  snapshot: DeploymentSnapshot | undefined,
  id: string,
): ExpectationState | "unknown" {
  if (snapshot?.state !== "configured" || !snapshot.settings) return "unknown";
  const definition = SOURCE_DEFINITIONS.find((source) => source.id === id);
  if (!definition) return "unknown";
  if (definition.selectable) {
    const expectation = snapshot.settings.sources[id];
    if (!expectation || expectation.state === "not_selected")
      return "not_selected";
    if (expectation.state === "staged") return "staged";
    if (snapshot.activeContract === undefined) return "unknown";
    return definition.minimumContract > snapshot.activeContract
      ? "staged"
      : "active";
  }
  if (snapshot.activeContract === undefined) return "unknown";
  if (definition.contract && definition.contract !== snapshot.activeContract)
    return "staged";
  return definition.derivedFrom.some(
    (source) => expectationFor(snapshot, source) === "active",
  )
    ? "active"
    : "not_selected";
}

export function applicableJobs(
  snapshot: DeploymentSnapshot | undefined,
): JobDefinition[] {
  if (snapshot?.activeContract === undefined) return [];
  return JOB_DEFINITIONS.filter(
    (job) =>
      job.stage === "active" &&
      job.contracts.includes(snapshot.activeContract!) &&
      job.sourceIds.some((id) => expectationFor(snapshot, id) === "active"),
  );
}

export function selectedQualitySources(
  snapshot: DeploymentSnapshot | undefined,
): string[] {
  return [
    ...new Set(
      SOURCE_DEFINITIONS.filter(
        (source) => expectationFor(snapshot, source.id) === "active",
      ).flatMap(
        (source) =>
          source.qualitySourcesByContract?.[String(snapshot?.activeContract)] ??
          source.qualitySources,
      ),
    ),
  ];
}

/** Registry-approved macro identifiers only; never interpolate user source values into SPL. */
export function selectedHealthProbes(
  snapshot: DeploymentSnapshot | undefined,
  scope: "full" | "jobs" = "full",
): HealthProbe[] {
  if (scope === "jobs")
    return [{ id: "jobs", macro: "adm_health_jobs", part: "jobs" }];
  if (snapshot?.state !== "configured" || !snapshot.activeContract) return [];
  const configuredSources = SOURCE_DEFINITIONS.filter(
    (source) =>
      isCoreSource(source) &&
      expectationFor(snapshot, source.id) === "active" &&
      (!snapshot.sourceConfiguration ||
        snapshot.sourceConfiguration[source.id] === "configured"),
  );
  const result: HealthProbe[] = configuredSources.map((source) => ({
    id: source.id,
    macro: source.probeMacro,
    part: "sources",
  }));
  if (applicableJobs(snapshot).some((job) => job.required))
    result.push({ id: "jobs", macro: "adm_health_jobs", part: "jobs" });
  const quality: Record<string, string> = registry.qualityProbes;
  const eligibleQuality = new Set(
    configuredSources.flatMap(
      (source) =>
        source.qualitySourcesByContract?.[String(snapshot.activeContract)] ??
        source.qualitySources,
    ),
  );
  for (const id of selectedQualitySources(snapshot).filter((id) =>
    eligibleQuality.has(id),
  )) {
    if (quality[id]) result.push({ id, macro: quality[id], part: "quality" });
  }
  const seen = new Set<string>();
  return result.filter((probe) => {
    const key = `${probe.part}:${probe.macro}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
