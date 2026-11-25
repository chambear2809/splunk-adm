import { createStaticURL } from "@splunk/splunk-utils/url";
import { canonicalJson, sha256Hex } from "../changeCorrelation/canonicalJson";
import {
  DEMO_PHASES,
  demoTrack,
  requireDemoScenario,
  type DemoPhase,
  type DemoScenario,
} from "./demoRegistry";
import type { GraphArgs } from "../rows";

const TEMPLATE_REVISION = 2;
const MAX_CAPTURE_BYTES = 20 * 1024 * 1024;
const MAX_RESULT_ROWS = 10_000;
const HASH = /^[a-f0-9]{64}$/;
export const DEMO_CAPTURE_KEYS = [
  "graph.baseline",
  "graph.change",
  "graph.impact",
  "graph.recovery",
  "topology.baseline",
  "topology.impact",
  "topology.recovery",
  "catalog.selected",
  "find.service",
  "find.network_client",
  "scopes.selected",
  "timeline.selected",
  "endpoint.primary.baseline",
  "endpoint.primary.change",
  "endpoint.primary.impact",
  "endpoint.primary.recovery",
  "endpoint.control.impact",
  "monitoring.appdynamics",
  "monitoring.thousandeyes",
] as const;
const CAPTURE_KEYS = DEMO_CAPTURE_KEYS;
export type DemoCaptureKey = (typeof DEMO_CAPTURE_KEYS)[number];
export type DemoResultStatus =
  "complete" | "partial" | "failed" | "blocked" | "unavailable";

export interface DemoCaptureWindow {
  earliest: number;
  latest: number;
  basis: "source_time" | "index_time";
}

export interface DemoCaptureReadback {
  complete: boolean;
  result_count: number;
  index_time_bounds: { earliest: number; latest: number } | null;
  receipt_fingerprints: string[];
  source: "splunk_rest";
  execution_id: string;
  plan_sha256: string;
  query_job?: Record<string, unknown>;
  query_input_coverage?: Record<string, unknown>;
}

export interface DemoCaptureQuery {
  literal: string;
  sha256: string;
  earliest: string | number;
  latest: string | number;
  max_rows: number;
  rows: Record<string, unknown>[];
  readback: DemoCaptureReadback;
}
export interface NotApplicableDemoCaptureQuery {
  status: "not_applicable";
  reason: string;
}
export type DemoCaptureQueryResult =
  DemoCaptureQuery | NotApplicableDemoCaptureQuery;

export interface DemoCaptureResult {
  status: DemoResultStatus;
  reason?: string;
  args?: GraphArgs;
  input?: { field: string; value: string };
  window?: DemoCaptureWindow;
  query?: { literal: string; sha256: string };
  rows: Record<string, unknown>[];
  readback?: DemoCaptureReadback;
  selection?: Record<string, unknown> & {
    scope?: string;
    window?: { start?: number; end?: number };
    change_ids?: string[];
  };
  selectors?: Record<string, unknown>;
  queries?: Record<string, DemoCaptureQueryResult>;
  config_snapshot?: Record<string, unknown>;
  generation_validation?: {
    generation_id: string;
    manifest: Record<string, unknown>;
    complete_row_count: number;
    rows_sha256: string;
    ingest_bounds: { earliest: number; latest: number };
    validated_before_filter: true;
  };
  generation_rows?: Record<string, unknown>[];
}

export interface CompleteDemoCaptureResult extends DemoCaptureResult {
  status: "complete";
  window: DemoCaptureWindow;
  query: { literal: string; sha256: string };
  readback: DemoCaptureReadback;
}

export interface DemoCaptureManifest {
  scenario_id: DemoScenario;
  template_revision: number;
  template_sha256: string;
  application: GraphArgs;
  selection: Record<string, unknown> & {
    change_scope: string;
    client_ip: string;
  };
  phase_windows: Record<DemoPhase, { earliest: number; latest: number }>;
  anchor_utc: string;
  anchor_epoch: number;
  actual_run_started_epoch: number | null;
  actual_run_ended_epoch: number | null;
  execution_id: string;
  plan_sha256: string;
  source_time_bounds: { earliest: number; latest: number };
  index_time_bounds: { earliest: number; latest: number };
  package_sha256: string;
  execution_inventory_sha256: string;
  fixture_sha256: string;
  fixture_file_sha256: Record<string, string>;
  query_sha256: Record<string, string>;
  contract_sha256: string;
  configuration_sha256: string;
  active_traffic_contract_sha256: string;
  change_generation_id: string | null;
  change_generation_sha256: string | null;
  captured_dependencies: unknown[];
  capture_status: "complete" | "partial";
  services_contacted: boolean;
  capture_sha256: string;
}

export interface DemoCapture {
  schema_version: 1;
  manifest: DemoCaptureManifest;
  results: Record<DemoCaptureKey, DemoCaptureResult>;
  bundle_sha256: string;
}

interface DemoTemplate {
  scenario_id: DemoScenario;
  template_revision: number;
  application: GraphArgs;
  selection: Record<string, unknown> & {
    change_scope: string;
    client_ip: string;
    client_mac?: string;
    control_scope?: string;
    control_client_ip?: string;
    control_client_mac?: string;
  };
  clock: {
    phases: {
      id: DemoPhase;
      start_offset_seconds: number;
      end_offset_seconds: number;
    }[];
  };
}

export class DemoCaptureUnavailableError extends Error {
  constructor(readonly scenario: DemoScenario) {
    super(
      `${demoTrack(scenario).label} is prepared, but its installed capture has not been accepted yet.`,
    );
    this.name = "DemoCaptureUnavailableError";
  }
}

const object = (value: unknown): value is Record<string, unknown> =>
  !!value && typeof value === "object" && !Array.isArray(value);

function exactKeys(
  value: Record<string, unknown>,
  allowed: readonly string[],
  label: string,
) {
  if (Object.keys(value).some((key) => !allowed.includes(key)))
    throw new Error(`Demo capture ${label} has unsupported fields.`);
}

function requiredText(value: unknown, label: string, max = 512): string {
  if (
    typeof value !== "string" ||
    !value ||
    value.length > max ||
    Array.from(value).some(
      (character) =>
        character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127,
    )
  )
    throw new Error(`Demo capture ${label} is invalid.`);
  return value;
}

function hash(value: unknown, label: string): string {
  const result = requiredText(value, label, 64);
  if (!HASH.test(result)) throw new Error(`Demo capture ${label} is invalid.`);
  return result;
}

async function parseCapturedDependencies(
  value: unknown,
  scenario: DemoScenario,
  executionId: string,
): Promise<Record<string, unknown>[]> {
  if (!Array.isArray(value) || value.length > 500 || !value.every(object))
    throw new Error("Demo capture dependency bindings are invalid.");
  const track = demoTrack(scenario);
  const dependencies: Record<string, unknown>[] = [];
  for (const candidate of value) {
    exactKeys(candidate, ["authority", "type", "id", "binding"], "dependency");
    if (
      candidate.authority !== "atlas:observed_dependency" ||
      candidate.type !== "captured_dependency" ||
      !object(candidate.binding)
    )
      throw new Error("Demo capture dependency authority is invalid.");
    const binding = candidate.binding;
    exactKeys(
      binding,
      [
        "authority",
        "identity_type",
        "scenario_id",
        "execution_id",
        "graph_result_key",
        "graph_result_sha256",
        "edge_id",
        "scope",
        "window",
        "query_sha256",
        "receipt_basis",
        "query_input_coverage_sha256",
        "active_traffic_contract_sha256",
        "receipt_fingerprints",
      ],
      "dependency binding",
    );
    if (
      binding.authority !== candidate.authority ||
      binding.identity_type !== candidate.type ||
      binding.scenario_id !== scenario ||
      binding.execution_id !== executionId ||
      binding.scope !== track.scope ||
      ![
        "graph.baseline",
        "graph.change",
        "graph.impact",
        "graph.recovery",
      ].includes(String(binding.graph_result_key)) ||
      binding.receipt_basis !== "query_input_coverage_v1"
    )
      throw new Error("Demo capture dependency binding is foreign.");
    hash(binding.graph_result_sha256, "dependency graph hash");
    hash(binding.query_sha256, "dependency query hash");
    hash(binding.query_input_coverage_sha256, "dependency input coverage hash");
    hash(binding.active_traffic_contract_sha256, "dependency traffic hash");
    if (
      !Array.isArray(binding.receipt_fingerprints) ||
      binding.receipt_fingerprints.length === 0 ||
      !binding.receipt_fingerprints.every((item) => HASH.test(String(item)))
    )
      throw new Error("Demo capture dependency receipts are invalid.");
    if (!object(binding.window))
      throw new Error("Dependency window is invalid.");
    bounds(binding.window, "dependency window");
    const expectedId = `captured_dependency:${await sha256Hex(canonicalJson(binding))}`;
    if (candidate.id !== expectedId)
      throw new Error(
        "Demo capture dependency identity is not bound to its body.",
      );
    dependencies.push(candidate);
  }
  return dependencies;
}

async function validateDependencyEvidence(
  dependencies: unknown[],
  rawResults: Record<string, unknown>,
  manifest: DemoCaptureManifest,
): Promise<void> {
  for (const candidate of dependencies) {
    const binding = (candidate as Record<string, unknown>).binding as Record<
      string,
      unknown
    >;
    const graphKey = String(binding.graph_result_key);
    const graph = rawResults[graphKey];
    if (!object(graph) || graph.status !== "complete")
      throw new Error("Demo capture dependency graph evidence is incomplete.");
    if (
      binding.execution_id !== manifest.execution_id ||
      binding.scope !== manifest.selection.change_scope ||
      binding.active_traffic_contract_sha256 !==
        manifest.active_traffic_contract_sha256 ||
      binding.query_sha256 !== (graph.query as Record<string, unknown>)?.sha256
    )
      throw new Error(
        "Demo capture dependency binding is not tied to its graph.",
      );
    const graphWindow = graph.window;
    if (!object(graphWindow) || graphWindow.basis !== "source_time")
      throw new Error("Demo capture dependency graph window is invalid.");
    const expectedWindow = {
      earliest: graphWindow.earliest,
      latest: graphWindow.latest,
    };
    if (canonicalJson(binding.window) !== canonicalJson(expectedWindow))
      throw new Error("Demo capture dependency window differs from graph.");
    const graphHash = await sha256Hex(canonicalJson(graph));
    if (binding.graph_result_sha256 !== graphHash)
      throw new Error("Demo capture dependency graph hash differs from graph.");
    const readback = graph.readback;
    const coverage = object(readback)
      ? readback.query_input_coverage
      : undefined;
    if (
      !object(readback) ||
      !object(readback.query_job) ||
      !object(coverage) ||
      !object(coverage.summary_readback)
    )
      throw new Error("Demo capture dependency lacks input coverage.");
    const summary = coverage.summary_readback;
    if (
      coverage.schema_version !== 1 ||
      coverage.basis !== "query_level_input_coverage" ||
      coverage.qualification !==
        "eligible_input_superset_not_per_edge_lineage" ||
      coverage.execution_id !== manifest.execution_id ||
      coverage.query_sha256 !== binding.query_sha256 ||
      coverage.scope !== binding.scope ||
      canonicalJson(coverage.graph_window) !== canonicalJson(expectedWindow) ||
      canonicalJson(summary.receipt_fingerprints) !==
        canonicalJson(
          (readback as Record<string, unknown>).receipt_fingerprints,
        ) ||
      canonicalJson((readback as Record<string, unknown>).index_time_bounds) !==
        canonicalJson(summary.index_window)
    )
      throw new Error(
        "Demo capture dependency input coverage differs from graph.",
      );
    const coverageHash = await sha256Hex(canonicalJson(coverage));
    if (binding.query_input_coverage_sha256 !== coverageHash)
      throw new Error(
        "Demo capture dependency coverage hash differs from graph.",
      );
    const rows = Array.isArray(graph.rows) ? graph.rows : [];
    if (
      !rows.some(
        (row) =>
          object(row) && row.id === binding.edge_id && row.row_type === "edge",
      )
    )
      throw new Error("Demo capture dependency edge is absent from graph.");
    if (
      !Array.isArray(binding.receipt_fingerprints) ||
      canonicalJson(binding.receipt_fingerprints) !==
        canonicalJson(
          (readback as Record<string, unknown>).receipt_fingerprints,
        )
    )
      throw new Error("Demo capture dependency receipts differ from graph.");
  }
}

function validEpoch(value: unknown): value is number {
  return (
    typeof value === "number" &&
    Number.isFinite(value) &&
    value >= 0 &&
    value <= 253402300799 &&
    Number.isSafeInteger(value)
  );
}

function validTimestamp(value: unknown): value is number {
  return (
    typeof value === "number" &&
    Number.isFinite(value) &&
    value >= 0 &&
    value <= 253402300799 &&
    Number.isSafeInteger(value * 1000)
  );
}

function bounds(value: unknown, label: string) {
  if (
    !object(value) ||
    !validTimestamp(value.earliest) ||
    !validTimestamp(value.latest)
  )
    throw new Error(`Demo capture ${label} is invalid.`);
  exactKeys(value, ["earliest", "latest"], label);
  if (value.earliest >= value.latest)
    throw new Error(`Demo capture ${label} is reversed.`);
  return { earliest: value.earliest, latest: value.latest };
}

function boundsAllowEmpty(value: unknown, label: string) {
  if (
    !object(value) ||
    !validTimestamp(value.earliest) ||
    !validTimestamp(value.latest)
  )
    throw new Error(`Demo capture ${label} is invalid.`);
  exactKeys(value, ["earliest", "latest"], label);
  if (value.earliest > value.latest)
    throw new Error(`Demo capture ${label} is reversed.`);
  return { earliest: value.earliest, latest: value.latest };
}

function boundedSelection(value: unknown, label: string) {
  if (!object(value) || Object.keys(value).length > 64)
    throw new Error(`Demo capture ${label} is invalid.`);
  for (const [key, selected] of Object.entries(value)) {
    if (!/^[a-z][a-z0-9_]{0,63}$/.test(key))
      throw new Error(`Demo capture ${label} has an invalid field name.`);
    if (typeof selected === "string") requiredText(selected, key, 512);
    else if (
      typeof selected === "number" &&
      (!Number.isSafeInteger(selected) || selected < 0)
    )
      throw new Error(`Demo capture ${label} has an invalid numeric field.`);
    else if (typeof selected !== "boolean" && typeof selected !== "number")
      throw new Error(`Demo capture ${label} has an invalid field value.`);
  }
  return value;
}

function exactArgs(
  value: unknown,
  expected: GraphArgs,
  label: string,
): GraphArgs {
  if (!object(value))
    throw new Error(`Demo capture ${label} is missing scope.`);
  exactKeys(value, ["service", "environment", "cluster", "namespace"], label);
  const actual: GraphArgs = {
    service: requiredText(value.service, `${label} service`),
    environment: requiredText(value.environment, `${label} environment`),
    cluster: requiredText(value.cluster, `${label} cluster`),
    namespace: requiredText(value.namespace, `${label} namespace`),
  };
  if (canonicalJson(actual) !== canonicalJson(expected))
    throw new Error(
      `Demo capture ${label} uses a different application scope.`,
    );
  return actual;
}

function phaseWindow(anchor: number, phase: DemoPhase) {
  const offsets: Record<DemoPhase, [number, number]> = {
    baseline: [0, 300],
    change: [300, 420],
    impact: [420, 900],
    recovery: [900, 1200],
  };
  const [start, end] = offsets[phase];
  return { earliest: anchor + start, latest: anchor + end };
}

function validateTemplate(
  value: unknown,
  scenario: DemoScenario,
): DemoTemplate {
  if (!object(value)) throw new Error("Demo track template is invalid.");
  const track = demoTrack(scenario);
  if (
    value.scenario_id !== scenario ||
    value.template_revision !== TEMPLATE_REVISION
  )
    throw new Error(
      "Demo track template is stale or belongs to another track.",
    );
  const application = exactArgs(value.application, track.args, "template");
  const selection = boundedSelection(value.selection, "template selection");
  if (
    selection.change_scope !== track.scope ||
    selection.client_ip !== track.clientIp
  )
    throw new Error("Demo track template selects another change or client.");
  const textSelections = [
    "client_mac",
    "control_scope",
    "control_client_ip",
    "control_client_mac",
  ] as const;
  for (const [name, selected] of [
    ["client MAC", selection.client_mac],
    ["control scope", selection.control_scope],
    ["control client address", selection.control_client_ip],
    ["control client MAC", selection.control_client_mac],
  ] as const)
    if (selected !== undefined) requiredText(selected, name, 255);
  for (const name of textSelections) {
    if (selection[name] !== undefined && typeof selection[name] !== "string")
      throw new Error("Demo track template has an invalid text selection.");
  }
  if (
    (selection.control_scope === undefined) !==
      (selection.control_client_ip === undefined) ||
    (scenario === "track-b-fabric" &&
      (selection.control_scope !== undefined ||
        selection.control_client_ip !== undefined))
  )
    throw new Error("Demo track template has an invalid control selection.");
  if (!object(value.clock) || !Array.isArray(value.clock.phases))
    throw new Error("Demo track template has no phase plan.");
  const expected: Record<DemoPhase, [number, number]> = {
    baseline: [0, 300],
    change: [300, 420],
    impact: [420, 900],
    recovery: [900, 1200],
  };
  const phases = value.clock.phases.map((raw) => {
    if (!object(raw)) throw new Error("Demo track template phase is invalid.");
    exactKeys(
      raw,
      ["id", "start_offset_seconds", "end_offset_seconds"],
      "template phase",
    );
    const id = raw.id;
    if (
      id !== "baseline" &&
      id !== "change" &&
      id !== "impact" &&
      id !== "recovery"
    )
      throw new Error("Demo track template has an unsupported phase.");
    if (
      typeof raw.start_offset_seconds !== "number" ||
      typeof raw.end_offset_seconds !== "number"
    )
      throw new Error("Demo track template phase offsets are invalid.");
    const phaseId = id as DemoPhase;
    return {
      id: phaseId,
      start_offset_seconds: raw.start_offset_seconds,
      end_offset_seconds: raw.end_offset_seconds,
    };
  });
  if (
    phases.length !== 4 ||
    phases.some(({ id, start_offset_seconds, end_offset_seconds }) => {
      const pair = expected[id];
      return start_offset_seconds !== pair[0] || end_offset_seconds !== pair[1];
    })
  )
    throw new Error("Demo track template has stale phase windows.");
  return {
    scenario_id: scenario,
    template_revision: TEMPLATE_REVISION,
    application,
    selection: selection as DemoTemplate["selection"],
    clock: { phases },
  };
}

function parseReadback(
  value: unknown,
  status: DemoResultStatus,
  rows: unknown[],
  manifest: DemoCaptureManifest,
): DemoCaptureReadback | undefined {
  if (value === undefined && status !== "complete") return undefined;
  if (!object(value)) throw new Error("Demo capture readback is missing.");
  exactKeys(
    value,
    [
      "complete",
      "result_count",
      "index_time_bounds",
      "receipt_fingerprints",
      "source",
      "execution_id",
      "plan_sha256",
      "query_job",
      "query_input_coverage",
    ],
    "readback",
  );
  if (
    typeof value.complete !== "boolean" ||
    !Number.isSafeInteger(value.result_count) ||
    (value.result_count as number) < 0 ||
    value.result_count !== rows.length ||
    !Array.isArray(value.receipt_fingerprints) ||
    !value.receipt_fingerprints.every(
      (fingerprint) =>
        typeof fingerprint === "string" && HASH.test(fingerprint),
    ) ||
    value.receipt_fingerprints.some(
      (fingerprint: string, index: number, all: string[]) =>
        index > 0 && all[index - 1] >= fingerprint,
    ) ||
    value.source !== "splunk_rest" ||
    value.execution_id !== manifest.execution_id ||
    value.plan_sha256 !== manifest.plan_sha256
  )
    throw new Error("Demo capture readback is invalid.");
  const indexBounds =
    value.index_time_bounds === null
      ? null
      : bounds(value.index_time_bounds, "readback index bounds");
  if (status === "complete" && (!value.complete || !indexBounds))
    throw new Error(
      "Demo capture claims complete results without index readback.",
    );
  if (status !== "complete" && value.complete)
    throw new Error("Demo capture readback contradicts its result status.");
  if (status === "complete" && value.receipt_fingerprints.length === 0)
    throw new Error("Demo capture has no indexed receipt fingerprints.");
  const queryJob = value.query_job;
  const queryInputCoverage = value.query_input_coverage;
  if (queryJob !== undefined && !object(queryJob))
    throw new Error("Demo capture query job is invalid.");
  if (queryInputCoverage !== undefined && !object(queryInputCoverage))
    throw new Error("Demo capture query-input coverage is invalid.");
  return {
    complete: value.complete,
    result_count: value.result_count as number,
    index_time_bounds: indexBounds,
    receipt_fingerprints: [...value.receipt_fingerprints] as string[],
    source: "splunk_rest" as const,
    execution_id: manifest.execution_id,
    plan_sha256: manifest.plan_sha256,
    ...(queryJob ? { query_job: queryJob } : {}),
    ...(queryInputCoverage ? { query_input_coverage: queryInputCoverage } : {}),
  };
}

function parseEndpointQuery(
  value: unknown,
  key: string,
  manifest: DemoCaptureManifest,
): DemoCaptureQueryResult {
  if (!object(value)) throw new Error(`Demo endpoint query ${key} is invalid.`);
  if (value.status === "not_applicable") {
    exactKeys(value, ["status", "reason"], `${key} unavailable query`);
    return {
      status: "not_applicable",
      reason: requiredText(value.reason, `${key} reason`, 512),
    };
  }
  exactKeys(
    value,
    ["literal", "sha256", "earliest", "latest", "max_rows", "rows", "readback"],
    `${key} query`,
  );
  const literal = requiredText(value.literal, `${key} search`, 65_536);
  const sha256 = hash(value.sha256, `${key} query hash`);
  const parseBound = (raw: unknown, label: string) => {
    if (
      (typeof raw !== "string" && typeof raw !== "number") ||
      (typeof raw === "string" && !/^\d+(?:\.\d{1,3})?$/.test(raw))
    )
      throw new Error(`Demo endpoint query ${key} ${label} is invalid.`);
    const value = Number(raw);
    if (!validTimestamp(value))
      throw new Error(`Demo endpoint query ${key} ${label} is invalid.`);
    return value;
  };
  const earliest = parseBound(value.earliest, "start");
  const latest = parseBound(value.latest, "end");
  if (
    earliest >= latest ||
    typeof value.max_rows !== "number" ||
    !Number.isSafeInteger(value.max_rows) ||
    value.max_rows < 1 ||
    value.max_rows > MAX_RESULT_ROWS ||
    !Array.isArray(value.rows) ||
    value.rows.length > value.max_rows ||
    !value.rows.every(object)
  )
    throw new Error(`Demo endpoint query ${key} readback is invalid.`);
  const readback = parseReadback(
    value.readback,
    "complete",
    value.rows,
    manifest,
  );
  return {
    literal,
    sha256,
    earliest: value.earliest as string | number,
    latest: value.latest as string | number,
    max_rows: value.max_rows as number,
    rows: value.rows as Record<string, unknown>[],
    readback: readback!,
  };
}

function parseEndpointResult(
  value: Record<string, unknown>,
  key: DemoCaptureKey,
  scenario: DemoScenario,
  manifest: DemoCaptureManifest,
  template: DemoTemplate,
): DemoCaptureResult {
  if (value.status !== "complete")
    throw new Error(`Demo endpoint result ${key} has an invalid status.`);
  if (
    !object(value.selection) ||
    !object(value.selectors) ||
    !object(value.config_snapshot) ||
    !object(value.queries)
  )
    throw new Error(
      `Demo endpoint result ${key} is missing its capture context.`,
    );
  const selection = value.selection;
  const selectors = value.selectors;
  const config = value.config_snapshot;
  exactKeys(
    selection,
    [
      "schemaVersion",
      "id",
      "address",
      "scope",
      "start",
      "end",
      "configurationFingerprint",
      "trafficContract",
    ],
    `${key} selection`,
  );
  exactKeys(
    selectors,
    ["summary_selector", "query_earliest", "query_latest"],
    `${key} selectors`,
  );
  exactKeys(
    config,
    [
      "fingerprint",
      "trafficContract",
      "summaryIndexes",
      "mappings",
      "identities",
      "identityAvailable",
      "dns",
      "supplemental",
      "maxAgeSeconds",
      "clockUncertaintySeconds",
      "caller_acl",
      "readback",
    ],
    `${key} configuration snapshot`,
  );
  const start = selection.start;
  const end = selection.end;
  const address = requiredText(
    selection.address,
    `${key} selected address`,
    255,
  );
  const scope = requiredText(selection.scope, `${key} selected scope`, 255);
  if (!validEpoch(start) || !validEpoch(end) || start >= end)
    throw new Error(`Demo endpoint result ${key} uses an invalid selection.`);
  const match =
    /^endpoint\.(?:primary|control)\.(baseline|change|impact|recovery)$/.exec(
      key,
    );
  const phase = key === "endpoint.control.impact" ? "impact" : match?.[1];
  if (!phase)
    throw new Error(`Demo endpoint result ${key} has an unknown phase.`);
  const expected = manifest.phase_windows[phase as DemoPhase];
  const control = key === "endpoint.control.impact";
  const expectedScope = control
    ? template.selection.control_scope
    : template.selection.change_scope;
  const expectedAddress = control
    ? template.selection.control_client_ip
    : template.selection.client_ip;
  if (
    !expectedScope ||
    !expectedAddress ||
    scope !== expectedScope ||
    address !== expectedAddress ||
    start !== expected.earliest ||
    end !== expected.latest
  )
    throw new Error(
      `Demo endpoint result ${key} does not match its phase window.`,
    );
  if (selection.id !== `${scope}:${address}:${start}:${end}`)
    throw new Error(
      `Demo endpoint result ${key} has a stale selection identity.`,
    );
  const fingerprint = hash(
    config.fingerprint,
    `${key} configuration fingerprint`,
  );
  const trafficContract = config.trafficContract;
  if (
    selection.configurationFingerprint !== fingerprint ||
    (trafficContract !== 1 && trafficContract !== 2) ||
    selection.trafficContract !== trafficContract
  )
    throw new Error(
      `Demo endpoint result ${key} does not match its configuration.`,
    );
  requiredText(selectors.summary_selector, `${key} summary selector`, 256);
  const summaryIndexes = config.summaryIndexes;
  if (
    !Array.isArray(summaryIndexes) ||
    summaryIndexes.length < 1 ||
    summaryIndexes.length > 16 ||
    !summaryIndexes.every(
      (name) =>
        typeof name === "string" && /^[a-z][a-z0-9_-]{0,79}$/.test(name),
    ) ||
    new Set(summaryIndexes).size !== summaryIndexes.length
  )
    throw new Error(`Demo endpoint result ${key} has invalid summary indexes.`);
  if (
    !Array.isArray(config.mappings) ||
    !config.mappings.some(
      (mapping) =>
        object(mapping) &&
        mapping.scope === scope &&
        mapping.mapping_status === "verified",
    )
  )
    throw new Error(
      `Demo endpoint result ${key} has no verified scope mapping.`,
    );
  if (
    config.identityAvailable !== true ||
    !Array.isArray(config.identities) ||
    !config.identities.some(
      (identity) =>
        object(identity) && identity.ip === address && identity.scope === scope,
    )
  )
    throw new Error(
      `Demo endpoint result ${key} has no exact address identity.`,
    );
  if (!object(config.readback) || !object(config.caller_acl))
    throw new Error(
      `Demo endpoint result ${key} is missing configuration authority.`,
    );
  exactKeys(
    config.readback,
    [
      "complete",
      "source",
      "captured_at",
      "config_sha256",
      "configuration_fingerprint",
      "settings_revision",
    ],
    `${key} configuration readback`,
  );
  if (
    config.readback.complete !== true ||
    config.readback.source !== "ToolkitEvidenceConfigClient.read" ||
    !validTimestamp(config.readback.captured_at) ||
    config.readback.configuration_fingerprint !== fingerprint ||
    (typeof config.readback.settings_revision !== "string" &&
      !Number.isSafeInteger(config.readback.settings_revision))
  )
    throw new Error(
      `Demo endpoint result ${key} has invalid configuration readback.`,
    );
  hash(config.readback.config_sha256, `${key} configuration readback hash`);
  if (config.readback.config_sha256 !== manifest.configuration_sha256)
    throw new Error(
      `Demo endpoint result ${key} differs from the captured configuration.`,
    );
  exactKeys(
    config.caller_acl,
    [
      "status",
      "principal",
      "checked_at",
      "admin_all_objects",
      "target_identity_sha256",
    ],
    `${key} caller permission attestation`,
  );
  if (
    config.caller_acl.status !== "owned_local_lab_admin" ||
    !requiredText(config.caller_acl.principal, `${key} ACL principal`, 256) ||
    !validTimestamp(config.caller_acl.checked_at) ||
    config.caller_acl.admin_all_objects !== true
  )
    throw new Error(
      `Demo endpoint result ${key} has invalid caller permission evidence.`,
    );
  hash(config.caller_acl.target_identity_sha256, `${key} target identity hash`);
  const summarySelector = summaryIndexes
    .map((name) => `index=${name}`)
    .join(" OR ");
  const queryStart = Math.floor(start / 300) * 300;
  const queryEnd = Math.floor(end / 300) * 300 + 300;
  const selectorBound = (value: unknown, label: string) => {
    if (
      (typeof value !== "string" && typeof value !== "number") ||
      (typeof value === "string" && !/^\d+(?:\.\d{1,3})?$/.test(value))
    )
      throw new Error(`Demo endpoint result ${key} has invalid ${label}.`);
    const result = Number(value);
    if (!validTimestamp(result))
      throw new Error(`Demo endpoint result ${key} has invalid ${label}.`);
    return result;
  };
  if (
    selectors.summary_selector !== summarySelector ||
    selectorBound(selectors.query_earliest, "query start") !== queryStart ||
    selectorBound(selectors.query_latest, "query end") !== queryEnd
  )
    throw new Error(`Demo endpoint result ${key} has stale query selectors.`);
  const parsedQueries: Record<string, DemoCaptureQueryResult> = {};
  const queryKeys = Object.keys(value.queries);
  if (
    !queryKeys.includes("conversations") ||
    queryKeys.some(
      (name) => name !== "conversations" && name !== "observations",
    )
  )
    throw new Error(`Demo endpoint result ${key} has unexpected query types.`);
  for (const name of queryKeys)
    parsedQueries[name] = parseEndpointQuery(
      value.queries[name],
      `${key}.${name}`,
      manifest,
    );
  const queryBounds = (name: string, query: DemoCaptureQueryResult) => {
    if (!("literal" in query)) return;
    const start = Number(query.earliest);
    const end = Number(query.latest);
    if (!validTimestamp(start) || !validTimestamp(end) || start >= end)
      throw new Error(`Demo endpoint query ${key}.${name} has invalid bounds.`);
    const indexed = query.readback.index_time_bounds;
    if (
      !indexed ||
      indexed.earliest < manifest.index_time_bounds.earliest ||
      indexed.latest > manifest.index_time_bounds.latest
    )
      throw new Error(
        `Demo endpoint query ${key}.${name} readback is outside capture bounds.`,
      );
  };
  for (const [name, query] of Object.entries(parsedQueries))
    queryBounds(name, query);
  if (
    Object.values(parsedQueries).some(
      (query) =>
        "literal" in query &&
        (Number(query.earliest) !== queryStart ||
          Number(query.latest) !== queryEnd),
    )
  )
    throw new Error(`Demo endpoint result ${key} has mismatched query bounds.`);
  const expectedMac = control
    ? template.selection.control_client_mac
    : template.selection.client_mac;
  if (expectedMac) {
    for (const query of Object.values(parsedQueries)) {
      if (
        "literal" in query &&
        query.rows.some(
          (row) =>
            row.client_mac !== undefined && row.client_mac !== expectedMac,
        )
      )
        throw new Error(
          `Demo endpoint result ${key} contains another client MAC.`,
        );
    }
  }
  return {
    status: "complete",
    rows: [],
    selection: selection as DemoCaptureResult["selection"],
    selectors,
    queries: parsedQueries,
    config_snapshot: config,
  };
}

function parseResult(
  value: unknown,
  key: DemoCaptureKey,
  expectedArgs: GraphArgs,
  scenario: DemoScenario,
  manifest: DemoCaptureManifest,
  template: DemoTemplate,
): DemoCaptureResult {
  if (!object(value)) throw new Error(`Demo capture result ${key} is invalid.`);
  const status = value.status;
  if (
    status !== "complete" &&
    status !== "partial" &&
    status !== "failed" &&
    status !== "blocked" &&
    status !== "unavailable"
  )
    throw new Error(`Demo capture result ${key} has an unknown status.`);
  if (key.startsWith("endpoint.")) {
    if (status === "blocked" || status === "unavailable") {
      exactKeys(value, ["status", "reason"], `${key} unavailable result`);
      return {
        status,
        reason: requiredText(value.reason, `${key} unavailable reason`, 512),
        rows: [],
      };
    }
    exactKeys(
      value,
      ["status", "selection", "selectors", "config_snapshot", "queries"],
      `${key} result`,
    );
    return parseEndpointResult(value, key, scenario, manifest, template);
  }
  if (status === "blocked" || status === "unavailable") {
    exactKeys(value, ["status", "reason"], `${key} unavailable result`);
    return {
      status,
      reason: requiredText(value.reason, `${key} unavailable reason`, 512),
      rows: [],
    };
  }
  exactKeys(
    value,
    [
      "status",
      "reason",
      "args",
      "input",
      "window",
      "query",
      "rows",
      "readback",
      "selection",
      "generation_validation",
      "generation_rows",
    ],
    `${key} result`,
  );
  if (!Array.isArray(value.rows) || value.rows.length > MAX_RESULT_ROWS)
    throw new Error(`Demo capture result ${key} has invalid rows.`);
  const rows = value.rows as unknown[];
  if (!rows.every(object))
    throw new Error(`Demo capture result ${key} has a non-object row.`);
  if (!object(value.window))
    throw new Error(`Demo capture result ${key} has no selected window.`);
  exactKeys(value.window, ["earliest", "latest", "basis"], `${key} window`);
  const earliest = value.window.earliest;
  const latest = value.window.latest;
  if (
    !validTimestamp(earliest) ||
    !validTimestamp(latest) ||
    earliest >= latest
  )
    throw new Error(`Demo capture result ${key} has invalid time bounds.`);
  if (
    value.window.basis !== "source_time" &&
    value.window.basis !== "index_time"
  )
    throw new Error(`Demo capture result ${key} has an unknown time basis.`);
  if (!object(value.query))
    throw new Error(`Demo capture result ${key} has no exact query reference.`);
  exactKeys(value.query, ["literal", "sha256"], `${key} query`);
  const literal = requiredText(value.query.literal, `${key} query`, 65_536);
  const queryHash = hash(value.query.sha256, `${key} query hash`);
  const readback = parseReadback(value.readback, status, rows, manifest);
  const isFindResult = key === "find.service" || key === "find.network_client";
  const args = isFindResult
    ? undefined
    : exactArgs(value.args, expectedArgs, key);
  if (isFindResult && value.args !== undefined)
    throw new Error(`Demo capture ${key} must use input metadata.`);
  let input: DemoCaptureResult["input"];
  if (value.input !== undefined) {
    if (!object(value.input))
      throw new Error(`Demo capture result ${key} has invalid input metadata.`);
    exactKeys(value.input, ["field", "value"], `${key} input`);
    if (
      typeof value.input.field !== "string" ||
      typeof value.input.value !== "string" ||
      !value.input.value ||
      value.input.value.length > 512
    )
      throw new Error(`Demo capture result ${key} has invalid input metadata.`);
    input = { field: value.input.field, value: value.input.value };
  }
  if (isFindResult !== (input !== undefined))
    throw new Error(`Demo capture ${key} is missing its exact query input.`);
  let selection: DemoCaptureResult["selection"];
  let generation_validation: DemoCaptureResult["generation_validation"];
  if (key === "timeline.selected" && status === "complete") {
    if (!object(value.selection) || !Array.isArray(value.selection.change_ids))
      throw new Error("Demo timeline capture has no selection metadata.");
    exactKeys(
      value.selection,
      ["scope", "window", "change_ids"],
      "timeline selection",
    );
    if (!object(value.selection.window))
      throw new Error("Demo timeline selection window is invalid.");
    exactKeys(
      value.selection.window,
      ["start", "end"],
      "timeline selection window",
    );
    const selectedWindow = bounds(
      {
        earliest:
          value.selection.window &&
          (value.selection.window as Record<string, unknown>).start,
        latest:
          value.selection.window &&
          (value.selection.window as Record<string, unknown>).end,
      },
      "timeline selection window",
    );
    const track = demoTrack(scenario);
    const incidentWindow = {
      start: manifest.anchor_epoch,
      end: manifest.anchor_epoch + 1200,
    };
    if (
      value.selection.scope !== track.scope ||
      selectedWindow.earliest !== incidentWindow.start ||
      selectedWindow.latest !== incidentWindow.end ||
      !value.selection.change_ids.every(
        (id) => typeof id === "string" && id.length > 0 && id.length <= 256,
      ) ||
      new Set(value.selection.change_ids).size !==
        value.selection.change_ids.length
    )
      throw new Error("Demo timeline selection is bound to another scope.");
    selection = {
      scope: track.scope,
      window: { start: selectedWindow.earliest, end: selectedWindow.latest },
      change_ids: [...value.selection.change_ids] as string[],
    };
    if (!object(value.generation_validation))
      throw new Error("Demo timeline has no full-generation validation.");
    const validation = value.generation_validation;
    exactKeys(
      validation,
      [
        "generation_id",
        "manifest",
        "complete_row_count",
        "rows_sha256",
        "ingest_bounds",
        "validated_before_filter",
      ],
      "timeline generation validation",
    );
    const generationId = hash(
      validation.generation_id,
      "timeline generation ID",
    );
    const generationManifest = validation.manifest;
    if (
      !object(generationManifest) ||
      generationManifest.record_type !== "generation_manifest" ||
      generationManifest.generation_id !== generationId ||
      !Number.isSafeInteger(validation.complete_row_count) ||
      validation.complete_row_count !== generationManifest.row_count ||
      validation.rows_sha256 !== generationManifest.rows_sha256 ||
      !object(validation.ingest_bounds) ||
      validation.validated_before_filter !== true
    )
      throw new Error("Demo timeline generation validation is inconsistent.");
    const ingestBounds = bounds(
      validation.ingest_bounds,
      "timeline ingest bounds",
    );
    generation_validation = {
      generation_id: generationId,
      manifest: generationManifest,
      complete_row_count: validation.complete_row_count as number,
      rows_sha256: hash(validation.rows_sha256, "timeline row hash"),
      ingest_bounds: ingestBounds,
      validated_before_filter: true,
    };
    if (
      !Array.isArray(value.generation_rows) ||
      value.generation_rows.length > MAX_RESULT_ROWS ||
      !value.generation_rows.every(object)
    )
      throw new Error("Demo timeline omits its full generation rows.");
  } else if (
    key !== "timeline.selected" &&
    (value.selection !== undefined || value.generation_validation !== undefined)
  ) {
    throw new Error(
      "Only the timeline result may include generation metadata.",
    );
  }
  return {
    status,
    ...(typeof value.reason === "string"
      ? { reason: requiredText(value.reason, `${key} reason`, 512) }
      : {}),
    ...(args ? { args } : {}),
    ...(input ? { input } : {}),
    window: { earliest, latest, basis: value.window.basis },
    query: { literal, sha256: queryHash },
    rows: rows as Record<string, unknown>[],
    ...(readback ? { readback } : {}),
    ...(selection ? { selection } : {}),
    ...(generation_validation ? { generation_validation } : {}),
    ...(key === "timeline.selected" && Array.isArray(value.generation_rows)
      ? { generation_rows: value.generation_rows as Record<string, unknown>[] }
      : {}),
  };
}

async function parseManifest(
  value: unknown,
  scenario: DemoScenario,
  template: DemoTemplate,
): Promise<DemoCaptureManifest> {
  if (!object(value)) throw new Error("Demo capture manifest is invalid.");
  if (new TextEncoder().encode(canonicalJson(value)).byteLength > 512 * 1024)
    throw new Error("Demo capture manifest exceeds its readback limit.");
  exactKeys(
    value,
    [
      "scenario_id",
      "template_revision",
      "template_sha256",
      "application",
      "selection",
      "phase_windows",
      "anchor_utc",
      "anchor_epoch",
      "actual_run_started_epoch",
      "actual_run_ended_epoch",
      "source_time_bounds",
      "index_time_bounds",
      "execution_id",
      "plan_sha256",
      "package_sha256",
      "execution_inventory_sha256",
      "fixture_sha256",
      "fixture_file_sha256",
      "query_sha256",
      "contract_sha256",
      "configuration_sha256",
      "active_traffic_contract_sha256",
      "change_generation_id",
      "change_generation_sha256",
      "captured_dependencies",
      "capture_status",
      "services_contacted",
      "capture_sha256",
    ],
    "manifest",
  );
  const track = demoTrack(scenario);
  if (
    value.scenario_id !== scenario ||
    value.template_revision !== TEMPLATE_REVISION
  )
    throw new Error("Demo capture belongs to a stale or different track.");
  const anchor = requiredText(value.anchor_utc, "UTC anchor", 40);
  const anchorMs = Date.parse(anchor);
  const canonicalAnchor = Number.isFinite(anchorMs)
    ? new Date(anchorMs).toISOString()
    : "";
  if (
    !Number.isFinite(anchorMs) ||
    anchorMs % 1000 !== 0 ||
    (canonicalAnchor !== anchor &&
      canonicalAnchor.replace(".000Z", "Z") !== anchor)
  )
    throw new Error("Demo capture has an invalid run anchor.");
  const anchorSeconds = anchorMs / 1000;
  const actualRunStarted =
    value.actual_run_started_epoch === null
      ? null
      : value.actual_run_started_epoch;
  const actualRunEnded =
    value.actual_run_ended_epoch === null ? null : value.actual_run_ended_epoch;
  if (
    !validEpoch(value.anchor_epoch) ||
    value.anchor_epoch !== anchorSeconds ||
    (actualRunStarted !== null && !validTimestamp(actualRunStarted)) ||
    (actualRunEnded !== null && !validTimestamp(actualRunEnded)) ||
    (actualRunStarted !== null &&
      actualRunEnded !== null &&
      actualRunStarted > actualRunEnded)
  )
    throw new Error("Demo capture run clock fields are inconsistent.");
  const source = boundsAllowEmpty(
    value.source_time_bounds,
    "source-time bounds",
  );
  const index = boundsAllowEmpty(value.index_time_bounds, "index-time bounds");
  const application = exactArgs(
    value.application,
    template.application,
    "manifest",
  );
  const selection = boundedSelection(value.selection, "manifest selection");
  if (canonicalJson(selection) !== canonicalJson(template.selection))
    throw new Error(
      "Demo capture manifest selection differs from its template.",
    );
  const rawPhaseWindows = value.phase_windows;
  if (!object(rawPhaseWindows))
    throw new Error("Demo capture manifest phase windows are invalid.");
  const phaseWindows = Object.fromEntries(
    DEMO_PHASES.map(({ id }) => {
      const actual = bounds(rawPhaseWindows[id], `manifest ${id} phase`);
      const expected = phaseWindow(anchorSeconds, id);
      if (
        actual.earliest !== expected.earliest ||
        actual.latest !== expected.latest
      )
        throw new Error(
          `Demo capture manifest ${id} phase is not anchor-bound.`,
        );
      return [id, actual];
    }),
  ) as Record<DemoPhase, { earliest: number; latest: number }>;
  if (
    Object.keys(rawPhaseWindows).length !== DEMO_PHASES.length ||
    DEMO_PHASES.some(({ id }) => !Object.hasOwn(rawPhaseWindows, id))
  )
    throw new Error(
      "Demo capture manifest has missing or extra phase windows.",
    );
  const expectedSourceStart = anchorMs / 1000 - 120;
  const expectedSourceEnd = anchorMs / 1000 + 1200;
  if (value.capture_status !== "complete" && value.capture_status !== "partial")
    throw new Error("Demo capture has an unknown completion status.");
  if (typeof value.services_contacted !== "boolean")
    throw new Error("Demo capture service-contact status is invalid.");
  if (
    value.capture_status === "complete" &&
    (source.earliest > expectedSourceStart ||
      source.latest < expectedSourceEnd ||
      index.earliest > expectedSourceStart ||
      index.latest < expectedSourceEnd ||
      actualRunStarted === null ||
      actualRunEnded === null ||
      actualRunStarted > anchorSeconds ||
      actualRunEnded < anchorSeconds ||
      !value.services_contacted)
  )
    throw new Error("Demo capture bounds do not cover the complete run.");

  if (!object(value.fixture_file_sha256))
    throw new Error("Demo capture fixture hash map is invalid.");
  const fixtureFiles = Object.fromEntries(
    Object.entries(value.fixture_file_sha256).map(([name, digest]) => {
      if (
        name.length > 512 ||
        name.startsWith("/") ||
        name.includes("\\") ||
        name
          .split("/")
          .some((part) => part === "" || part === "." || part === "..")
      )
        throw new Error("Demo capture fixture name is invalid.");
      return [name, hash(digest, `fixture ${name} hash`)];
    }),
  );
  const fixtureHash = hash(value.fixture_sha256, "fixture hash");
  if ((await sha256Hex(canonicalJson(fixtureFiles))) !== fixtureHash)
    throw new Error("Demo capture aggregate fixture hash is invalid.");
  const capturedDependencies = await parseCapturedDependencies(
    value.captured_dependencies,
    scenario,
    requiredText(value.execution_id, "execution ID", 128),
  );
  const changeGenerationId =
    value.change_generation_id === null
      ? null
      : hash(value.change_generation_id, "change generation ID");
  const changeGenerationHash =
    value.change_generation_sha256 === null
      ? null
      : hash(value.change_generation_sha256, "change generation hash");
  if (
    (changeGenerationId === null) !== (changeGenerationHash === null) ||
    (changeGenerationId !== null && changeGenerationId !== changeGenerationHash)
  )
    throw new Error("Demo capture generation hashes are inconsistent.");
  const manifest: DemoCaptureManifest = {
    scenario_id: scenario,
    template_revision: TEMPLATE_REVISION,
    template_sha256: hash(value.template_sha256, "template hash"),
    application,
    selection: selection as DemoCaptureManifest["selection"],
    phase_windows: phaseWindows,
    anchor_utc: anchor,
    anchor_epoch: anchorSeconds,
    actual_run_started_epoch: actualRunStarted,
    actual_run_ended_epoch: actualRunEnded,
    execution_id: requiredText(value.execution_id, "execution ID", 128),
    plan_sha256: hash(value.plan_sha256, "plan hash"),
    source_time_bounds: source,
    index_time_bounds: index,
    package_sha256: hash(value.package_sha256, "package hash"),
    execution_inventory_sha256: hash(
      value.execution_inventory_sha256,
      "execution inventory hash",
    ),
    fixture_sha256: fixtureHash,
    fixture_file_sha256: fixtureFiles,
    query_sha256: {},
    contract_sha256: hash(value.contract_sha256, "contract hash"),
    configuration_sha256: hash(
      value.configuration_sha256,
      "configuration hash",
    ),
    active_traffic_contract_sha256: hash(
      value.active_traffic_contract_sha256,
      "active traffic contract hash",
    ),
    change_generation_id: changeGenerationId,
    change_generation_sha256: changeGenerationHash,
    captured_dependencies: capturedDependencies,
    capture_status: value.capture_status,
    services_contacted: value.services_contacted,
    capture_sha256: hash(value.capture_sha256, "capture hash"),
  };
  if (
    manifest.template_sha256.length !== 64 ||
    manifest.scenario_id !== track.id
  )
    throw new Error("Demo capture manifest hashes are inconsistent.");
  if (!object(value.query_sha256))
    throw new Error("Demo capture query hash registry is invalid.");
  manifest.query_sha256 = Object.fromEntries(
    Object.entries(value.query_sha256).map(([key, digest]) => [
      key,
      hash(digest, `${key} query hash`),
    ]),
  );
  return manifest;
}

export async function validateDemoCapture(
  value: unknown,
  scenarioValue: unknown,
  templateValue: unknown,
): Promise<DemoCapture> {
  const scenario = requireDemoScenario(scenarioValue);
  const template = validateTemplate(templateValue, scenario);
  if (!object(value) || value.schema_version !== 1 || !object(value.results))
    throw new Error("Demo capture bundle has an unsupported shape.");
  const rawResults = value.results;
  exactKeys(
    value,
    ["schema_version", "manifest", "results", "bundle_sha256"],
    "bundle",
  );
  const manifest = await parseManifest(value.manifest, scenario, template);
  const expectedTemplateHash = await sha256Hex(canonicalJson(templateValue));
  if (manifest.template_sha256 !== expectedTemplateHash)
    throw new Error("Demo capture references a different track template.");
  const keys = Object.keys(rawResults);
  if (
    keys.length !== CAPTURE_KEYS.length ||
    keys.some((key) => !(CAPTURE_KEYS as readonly string[]).includes(key))
  )
    throw new Error("Demo capture has missing or unexpected results.");
  const captureHash = await sha256Hex(canonicalJson(rawResults));
  if (captureHash !== manifest.capture_sha256)
    throw new Error("Demo capture result hash does not match its manifest.");
  const bundleHash = hash(value.bundle_sha256, "bundle hash");
  const partialBundle = {
    manifest: value.manifest,
    results: rawResults,
  };
  if ((await sha256Hex(canonicalJson(partialBundle))) !== bundleHash)
    throw new Error("Demo capture bundle hash is invalid.");
  if (manifest.capture_status === "partial") {
    await validateDependencyEvidence(
      manifest.captured_dependencies,
      rawResults,
      manifest,
    );
    for (const key of CAPTURE_KEYS) {
      const result = rawResults[key];
      if (!object(result))
        throw new Error(`Demo capture result ${key} is invalid.`);
      const status = result.status;
      if (
        status !== "complete" &&
        status !== "partial" &&
        status !== "failed" &&
        status !== "blocked" &&
        status !== "unavailable"
      )
        throw new Error(`Demo capture result ${key} has an unknown status.`);
    }
    throw new DemoCaptureUnavailableError(scenario);
  }
  if (manifest.change_generation_id === null)
    throw new Error("A complete demo capture has no validated generation.");
  const results = Object.fromEntries(
    CAPTURE_KEYS.map((key) => [
      key,
      parseResult(
        rawResults[key],
        key,
        template.application,
        scenario,
        manifest,
        template,
      ),
    ]),
  ) as Record<DemoCaptureKey, DemoCaptureResult>;
  await validateDependencyEvidence(
    manifest.captured_dependencies,
    rawResults,
    manifest,
  );
  const requiredKeys = [
    "graph.baseline",
    "graph.change",
    "graph.impact",
    "graph.recovery",
    "topology.baseline",
    "topology.impact",
    "topology.recovery",
    "catalog.selected",
    "find.service",
    "find.network_client",
    "scopes.selected",
    "timeline.selected",
    "endpoint.primary.baseline",
    "endpoint.primary.change",
    "endpoint.primary.impact",
    "endpoint.primary.recovery",
    ...(scenario === "track-a-firewall" ? ["endpoint.control.impact"] : []),
  ] as readonly DemoCaptureKey[];
  for (const key of requiredKeys) {
    if (results[key].status !== "complete")
      throw new DemoCaptureUnavailableError(scenario);
  }
  if (
    scenario === "track-b-fabric" &&
    results["endpoint.control.impact"].status !== "blocked" &&
    results["endpoint.control.impact"].status !== "unavailable"
  )
    throw new Error("Track B has an unsupported control endpoint result.");
  for (const key of [
    "monitoring.appdynamics",
    "monitoring.thousandeyes",
  ] as const) {
    if (
      results[key].status !== "complete" &&
      results[key].status !== "blocked" &&
      results[key].status !== "unavailable"
    )
      throw new Error(`Demo capture ${key} has an unsupported status.`);
  }
  for (const key of CAPTURE_KEYS) {
    const result = results[key];
    if (!key.startsWith("endpoint.") || result.status !== "complete") continue;
    const config = result.config_snapshot!;
    const configFields = Object.fromEntries(
      Object.entries(config).filter(
        ([field]) => field !== "caller_acl" && field !== "readback",
      ),
    );
    const readback = config.readback as Record<string, unknown>;
    if (
      (await sha256Hex(canonicalJson(configFields))) !== readback.config_sha256
    )
      throw new Error(
        `Demo endpoint result ${key} configuration hash is invalid.`,
      );
  }
  for (const key of CAPTURE_KEYS) {
    const result = results[key];
    if (key.startsWith("endpoint.")) continue;
    if (
      result.args &&
      canonicalJson(result.args) !== canonicalJson(template.application)
    )
      throw new Error(
        `Demo capture ${key} is outside the template application.`,
      );
  }
  const anchor = Date.parse(manifest.anchor_utc) / 1000;
  if (manifest.anchor_epoch !== anchor)
    throw new Error("Demo capture anchor epoch is inconsistent.");
  for (const phase of ["baseline", "change", "impact", "recovery"] as const) {
    const key = `graph.${phase}` as DemoCaptureKey;
    const result = results[key];
    if (result.status !== "complete") continue;
    const expected = phaseWindow(anchor, phase);
    if (
      !result.window ||
      result.window.basis !== "source_time" ||
      result.window.earliest !== expected.earliest ||
      result.window.latest !== expected.latest
    )
      throw new Error(`Demo capture ${key} does not match its phase window.`);
    if (canonicalJson(result.args) !== canonicalJson(template.application))
      throw new Error(
        `Demo capture ${key} is outside the template application.`,
      );
  }
  for (const phase of ["baseline", "impact", "recovery"] as const) {
    const key = `topology.${phase}` as DemoCaptureKey;
    const result = results[key];
    if (result.status !== "complete") continue;
    const expected = phaseWindow(anchor, phase);
    if (
      !result.window ||
      result.window.basis !== "source_time" ||
      result.window.earliest !== expected.earliest ||
      result.window.latest !== expected.latest
    )
      throw new Error(`Demo capture ${key} does not match its phase window.`);
  }
  if (
    (results["find.service"].status === "complete" &&
      (results["find.service"].input?.field !== "service" ||
        results["find.service"].input?.value !==
          template.application.service)) ||
    (results["find.network_client"].status === "complete" &&
      (results["find.network_client"].input?.field !== "client_ip" ||
        results["find.network_client"].input?.value !==
          demoTrack(scenario).clientIp))
  )
    throw new Error(
      "Demo capture Find values do not match the selected track.",
    );
  const timeline = results["timeline.selected"];
  if (timeline.status === "complete") {
    if (
      !timeline.window ||
      timeline.window.basis !== "source_time" ||
      timeline.window.earliest !== manifest.anchor_epoch ||
      timeline.window.latest !== manifest.anchor_epoch + 1200
    )
      throw new Error("Demo timeline does not cover the full incident window.");
    const validation = timeline.generation_validation;
    const generationRows = timeline.generation_rows;
    if (
      !validation ||
      !generationRows ||
      validation.generation_id !== manifest.change_generation_id ||
      validation.rows_sha256 !== validation.manifest.rows_sha256
    )
      throw new Error("Demo capture timeline is not bound to its generation.");
    const generationManifest = validation.manifest;
    const generationId = await sha256Hex(
      canonicalJson(
        Object.fromEntries(
          Object.entries(generationManifest).filter(
            ([key]) => key !== "generation_id",
          ),
        ),
      ),
    );
    if (generationId !== validation.generation_id)
      throw new Error("Demo capture timeline manifest hash is invalid.");
    if (
      generationRows.length !== validation.complete_row_count ||
      generationRows.some(
        (row) =>
          row.generation_id !== validation.generation_id ||
          typeof row.record_id !== "string" ||
          !HASH.test(row.record_id),
      )
    )
      throw new Error("Demo capture timeline full generation is incomplete.");
    const orderedGenerationRows = [...generationRows].sort((left, right) =>
      String(left.record_id).localeCompare(String(right.record_id)),
    );
    if (
      orderedGenerationRows.some(
        (row, index) => row.record_id !== generationRows[index].record_id,
      )
    )
      throw new Error("Demo capture timeline generation rows are not ordered.");
    const computedRowsHash = await sha256Hex(
      orderedGenerationRows
        .map((row) =>
          canonicalJson(
            Object.fromEntries(
              Object.entries(row).filter(([key]) => key !== "generation_id"),
            ),
          ),
        )
        .join("\n"),
    );
    if (computedRowsHash !== validation.rows_sha256)
      throw new Error(
        "Demo capture timeline rows do not match their generation.",
      );
    for (const row of generationRows) {
      const recordId = await sha256Hex(
        canonicalJson(
          Object.fromEntries(
            Object.entries(row).filter(
              ([key]) => key !== "record_id" && key !== "generation_id",
            ),
          ),
        ),
      );
      if (recordId !== row.record_id)
        throw new Error("Demo capture timeline row identity is invalid.");
    }
    const selectedRows = timeline.rows;
    const selectedIds = selectedRows.map((row) => String(row.record_id)).sort();
    if (
      !timeline.selection ||
      timeline.selection.scope !== manifest.selection.change_scope ||
      canonicalJson(selectedIds) !==
        canonicalJson([...(timeline.selection.change_ids ?? [])].sort())
    )
      throw new Error(
        "Demo capture timeline selection is not bound to its rows.",
      );
    const generationById = new Map(
      generationRows.map((row) => [String(row.record_id), row]),
    );
    for (const row of selectedRows) {
      const retained = generationById.get(String(row.record_id));
      if (!retained || canonicalJson(row) !== canonicalJson(retained))
        throw new Error("Demo capture timeline selected row is not retained.");
      if (row.scope !== timeline.selection.scope)
        throw new Error(
          "Demo capture timeline selected row has a foreign scope.",
        );
      const hasInterval =
        (row.earliest_at !== null && row.earliest_at !== undefined) ||
        (row.latest_at !== null && row.latest_at !== undefined);
      const start = hasInterval
        ? row.earliest_at
        : (row.event_at ??
          row.effective_at ??
          row.observed_at ??
          row.received_at);
      const end = hasInterval ? row.latest_at : undefined;
      if (start !== null && start !== undefined && !validTimestamp(start))
        throw new Error(
          "Demo capture timeline selected row has an invalid start.",
        );
      if (end !== null && end !== undefined && !validTimestamp(end))
        throw new Error(
          "Demo capture timeline selected row has an invalid end.",
        );
      if (hasInterval) {
        if (
          (start !== null &&
            start !== undefined &&
            end !== null &&
            end !== undefined &&
            start > end) ||
          (end !== null && end !== undefined && end < manifest.anchor_epoch) ||
          (start !== null &&
            start !== undefined &&
            start >= manifest.anchor_epoch + 1200)
        )
          throw new Error(
            "Demo capture timeline selected row is outside its window.",
          );
      } else if (
        start === null ||
        start === undefined ||
        start < manifest.anchor_epoch ||
        start >= manifest.anchor_epoch + 1200
      ) {
        throw new Error("Demo capture timeline point is outside its window.");
      }
    }
  }
  const queryLiterals = new Map<string, string>();
  for (const key of CAPTURE_KEYS) {
    const result = results[key];
    if (result.query) queryLiterals.set(key, result.query.literal);
    if (result.queries) {
      for (const [name, nested] of Object.entries(result.queries)) {
        if ("literal" in nested)
          queryLiterals.set(`${key}.${name}`, nested.literal);
      }
    }
  }
  const queryHashes = Object.fromEntries(
    [...queryLiterals.keys()].map((key) => [key, manifest.query_sha256[key]]),
  );
  if (
    Object.keys(manifest.query_sha256).length !== queryLiterals.size ||
    Object.values(manifest.query_sha256).some((digest) => !HASH.test(digest))
  )
    throw new Error("Demo capture query hash registry has unexpected entries.");
  if (canonicalJson(manifest.query_sha256) !== canonicalJson(queryHashes))
    throw new Error("Demo capture query hashes do not match their searches.");
  for (const [key, literal] of queryLiterals) {
    const expectedHash = manifest.query_sha256[key];
    if ((await sha256Hex(literal)) !== expectedHash)
      throw new Error(
        `Demo capture ${key} query hash does not match its search.`,
      );
  }
  for (const [key, digest] of Object.entries(manifest.query_sha256)) {
    const resultKey = CAPTURE_KEYS.find(
      (candidate) => key === candidate || key.startsWith(`${candidate}.`),
    );
    if (!resultKey) throw new Error(`Demo capture query ${key} has no result.`);
    const result = results[resultKey];
    const nestedName = key.startsWith("endpoint.")
      ? key.slice(resultKey.length + 1)
      : undefined;
    const nested = nestedName ? result.queries?.[nestedName] : undefined;
    const resultDigest =
      nested && "literal" in nested
        ? nested.sha256
        : !nestedName
          ? result.query?.sha256
          : undefined;
    if (digest !== resultDigest)
      throw new Error(
        `Demo capture ${key} query digest does not match its result.`,
      );
  }
  for (const key of CAPTURE_KEYS) {
    const result = results[key];
    if (key.startsWith("endpoint.")) continue;
    const match = /^\w+\.(baseline|change|impact|recovery)$/.exec(key);
    if (match && result.status === "complete") {
      const expected = phaseWindow(anchor, match[1] as DemoPhase);
      if (
        !result.window ||
        result.window.basis !== "source_time" ||
        result.window.earliest !== expected.earliest ||
        result.window.latest !== expected.latest
      )
        throw new Error(`Demo capture ${key} does not match its phase window.`);
    }
    if (result.status !== "complete") continue;
    if (!result.window || !result.query)
      throw new Error(`Demo capture ${key} has no accepted query window.`);
    const timeBounds =
      result.window.basis === "source_time"
        ? manifest.source_time_bounds
        : manifest.index_time_bounds;
    if (
      result.window.earliest < timeBounds.earliest ||
      result.window.latest > timeBounds.latest
    )
      throw new Error(`Demo capture ${key} exceeds its manifest time bounds.`);
    if (result.readback?.index_time_bounds) {
      const readbackBounds = result.readback.index_time_bounds;
      if (
        readbackBounds.earliest < manifest.index_time_bounds.earliest ||
        readbackBounds.latest > manifest.index_time_bounds.latest
      )
        throw new Error(`Demo capture ${key} receipt is outside index bounds.`);
    }
  }
  const expectedCaptureHash = await sha256Hex(canonicalJson(value.results));
  if (expectedCaptureHash !== manifest.capture_sha256)
    throw new Error("Demo capture result hash does not match its manifest.");
  return {
    schema_version: 1,
    manifest,
    results,
    bundle_sha256: bundleHash,
  };
}

function assetPath(scenario: DemoScenario, capture = false) {
  const suffix = `${capture ? "captures/" : ""}${scenario}.json`;
  const path = `change-correlation/scenarios/${suffix}`;
  return typeof __ADM_SPLUNK_BUILD__ !== "undefined" && __ADM_SPLUNK_BUILD__
    ? createStaticURL(`app/splunk_adm/demo/${path}`)
    : `/fixtures/${path}`;
}

async function fetchJson(
  url: string,
  scenario: DemoScenario,
  signal?: AbortSignal,
): Promise<unknown> {
  if (signal?.aborted) throw new Error("Demo capture load cancelled.");
  const controller = new AbortController();
  const abort = () => controller.abort();
  signal?.addEventListener("abort", abort, { once: true });
  const timer = setTimeout(abort, 10_000);
  try {
    const response = await fetch(url, { signal: controller.signal });
    if (!response.ok) {
      if (response.status === 404 && url === assetPath(scenario, true))
        throw new DemoCaptureUnavailableError(scenario);
      throw new Error(`Demo asset request failed (${response.status}).`);
    }
    const payload = await response.text();
    if (new TextEncoder().encode(payload).byteLength > MAX_CAPTURE_BYTES)
      throw new Error("Demo capture exceeds its readback limit.");
    try {
      return JSON.parse(payload) as unknown;
    } catch {
      throw new Error("Demo capture asset is not valid JSON.");
    }
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener("abort", abort);
  }
}

const acceptedCaptures = new Map<DemoScenario, DemoCapture>();

export function cachedDemoCapture(scenarioValue: unknown) {
  const scenario = requireDemoScenario(scenarioValue);
  return acceptedCaptures.get(scenario);
}

export function clearDemoCaptureCache() {
  acceptedCaptures.clear();
}

export async function loadDemoCapture(
  scenarioValue: unknown,
  signal?: AbortSignal,
): Promise<DemoCapture> {
  const scenario = requireDemoScenario(scenarioValue);
  if (signal?.aborted) throw new Error("Demo capture load cancelled.");
  const accepted = acceptedCaptures.get(scenario);
  if (accepted) return accepted;
  const templateValue = await fetchJson(assetPath(scenario), scenario, signal);
  validateTemplate(templateValue, scenario);
  const bundleValue = await fetchJson(
    assetPath(scenario, true),
    scenario,
    signal,
  );
  const capture = await validateDemoCapture(
    bundleValue,
    scenario,
    templateValue,
  );
  if (
    capture.manifest.template_sha256 !==
    (await sha256Hex(canonicalJson(templateValue)))
  )
    throw new Error("Demo capture template changed during loading.");
  if (signal?.aborted) throw new Error("Demo capture load cancelled.");
  acceptedCaptures.set(scenario, capture);
  return capture;
}

export function completeCaptureResult(
  capture: DemoCapture,
  key: DemoCaptureKey,
): CompleteDemoCaptureResult {
  const result = capture.results[key];
  if (
    result.status !== "complete" ||
    !result.window ||
    !result.query ||
    !result.readback
  ) {
    const trackLabel = demoTrack(capture.manifest.scenario_id).label;
    const label = key.startsWith("graph.")
      ? key.endsWith("baseline")
        ? "Before-change map"
        : key.endsWith("change")
          ? "Change-window map"
          : key.endsWith("impact")
            ? "Impact map"
            : "After-change map"
      : key.startsWith("topology.")
        ? "Device inventory"
        : key === "catalog.selected"
          ? "Application catalog"
          : key.startsWith("find.")
            ? "Find results"
            : key === "timeline.selected"
              ? "Change history"
              : key.startsWith("endpoint.")
                ? "Endpoint evidence"
                : "Captured evidence";
    throw new Error(
      result.reason ?? `${label} is ${result.status} for ${trackLabel}.`,
    );
  }
  return result as CompleteDemoCaptureResult;
}

export const demoCaptureAssets = {
  template: assetPath,
  capture: (scenario: DemoScenario) => assetPath(scenario, true),
};
