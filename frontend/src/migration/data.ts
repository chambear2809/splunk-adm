import {
  literal,
  normalizeIp,
  routingScope,
  validText,
} from "../data/evidence";
import type { EvidenceConfigClient } from "../data/evidenceConfig";
import { requireNoSearchErrors, type SearchClient } from "../data/searchClient";
import { PLANNER_LIMITS, type PlannerConversation } from "../ops/moveGroup";

export const PLANNER_DATA_SCHEMA_VERSION = 1 as const;
export const PLANNER_WINDOW = {
  minimum: 300,
  maximum: 30 * 86400,
  bucket: 300,
} as const;
export const PLANNER_WINDOW_PRESETS = [
  { id: "24h", label: "Last 24 hours", seconds: 86400 },
  { id: "7d", label: "Last 7 days", seconds: 7 * 86400 },
  { id: "14d", label: "Last 14 days", seconds: 14 * 86400 },
  { id: "30d", label: "Last 30 days", seconds: 30 * 86400 },
] as const;

export interface PlannerSelection {
  scope: string;
  start: number;
  end: number;
}
export interface PlannerCoverageDay {
  day: number;
  buckets: number;
  expected: number;
}
export interface PlannerCoverage {
  coveredBuckets: number;
  expectedBuckets: number;
  days: PlannerCoverageDay[];
}
export interface PlannerDataset {
  schemaVersion: typeof PLANNER_DATA_SCHEMA_VERSION;
  selection: PlannerSelection & {
    configurationFingerprint: string;
    trafficContract: 1 | 2;
  };
  capturedAt: number;
  conversations: PlannerConversation[];
  /** Distinct conversations that matched before the row cap. */
  inputCount: number;
  capped: boolean;
  unprotectedRows: number;
  coverage: PlannerCoverage;
  warnings: string[];
}

const EPOCH_MAX = 253402300799;
const bucketStart = (t: number) =>
  Math.floor(t / PLANNER_WINDOW.bucket) * PLANNER_WINDOW.bucket;
const bucketEnd = (t: number) => bucketStart(t) + PLANNER_WINDOW.bucket;

export function validatePlannerSelection(
  selection: PlannerSelection,
): PlannerSelection {
  const scope = routingScope(String(selection.scope ?? "").trim());
  const { start, end } = selection;
  if (
    ![start, end].every(
      (n) => Number.isInteger(n) && n >= 0 && n <= EPOCH_MAX,
    ) ||
    end - start < PLANNER_WINDOW.minimum ||
    end - start > PLANNER_WINDOW.maximum
  )
    throw new Error(
      "Choose a whole-second window between 5 minutes and 30 days.",
    );
  return { scope, start, end };
}

/** Preset windows end at the last closed 5-minute bucket. */
export function presetSelection(
  scope: string,
  seconds: number,
  now = Math.floor(Date.now() / 1000),
): PlannerSelection {
  const end = bucketStart(now);
  return validatePlannerSelection({ scope, start: end - seconds, end });
}

function validIndexSelector(indexes: string[]): string {
  if (!indexes.length)
    throw new Error("No active summary index is configured.");
  return indexes
    .map((name) => {
      if (!/^[a-z][a-z0-9_-]{0,79}$/.test(name))
        throw new Error("Invalid configured summary index.");
      return `index=${name}`;
    })
    .join(" OR ");
}

const contractFilter = (contract: 1 | 2) =>
  contract === 1
    ? "(isnull(contract_version) OR tonumber(contract_version)=1)"
    : "(tonumber(contract_version)=2)";

const scopePrefix = (
  selection: PlannerSelection,
  summaryIndex: string,
  contract: 1 | 2,
) => {
  const scope = literal(selection.scope, 253);
  return `search (${summaryIndex}) source="adm:conversation" adm_record="conversation" _time>=${bucketStart(selection.start)} AND _time<${bucketEnd(selection.end)} | where ${contractFilter(contract)} | eval adm_unprotected=if(isnull(rollup_id),1,0) | dedup rollup_id keepempty=true | eval scope=if(scope="default" AND coalesce(tostring(scope_mapping_verified),"0")!="1","unmapped:legacy-default",scope) | where scope="${scope}"`;
};

/**
 * One row per (client, server, server port, transport) over the window.
 * Counters are aggregated per observer first; the planner keeps the largest
 * single-observer total so overlapping observers are never double counted.
 */
export function buildPlannerConversationSearch(
  selection: PlannerSelection,
  summaryIndex: string,
  contract: 1 | 2,
): string {
  const valid = validatePlannerSelection(selection);
  if (
    valid.scope !== selection.scope ||
    !/^(?:index=[a-z][a-z0-9_-]{0,79})(?: OR index=[a-z][a-z0-9_-]{0,79})*$/.test(
      summaryIndex,
    )
  )
    throw new Error("Invalid planner search selection.");
  const cap = PLANNER_LIMITS.conversations;
  const observers = PLANNER_LIMITS.observers;
  return `${scopePrefix(valid, summaryIndex, contract)} | eval adm_first=tonumber(first_seen), adm_last=tonumber(last_seen), adm_port=if(isnull(tonumber(server_port)),"",tostring(tonumber(server_port))), adm_transport=lower(coalesce(transport,"unknown")), adm_directed=if(direction_basis="initiator" OR direction_basis="port_rule",1,0), adm_rec=tonumber(records), adm_bytes=if(isnull(tonumber(bytes_c2s)) AND isnull(tonumber(bytes_s2c)),null(),coalesce(tonumber(bytes_c2s),0)+coalesce(tonumber(bytes_s2c),0)), adm_sampled=if(tostring(sampled)="1",1,0), adm_observer=coalesce(observer,"unknown"), adm_source=coalesce(flow_source,"unknown") | where isnotnull(client_ip) AND isnotnull(server_ip) AND isnotnull(adm_first) AND isnotnull(adm_last) AND adm_last>=${valid.start} AND adm_first<${valid.end} | stats sum(adm_rec) as adm_rec sum(adm_bytes) as adm_bytes min(adm_first) as adm_first max(adm_last) as adm_last max(adm_sampled) as adm_sampled min(adm_directed) as adm_directed sum(adm_unprotected) as adm_unprotected by client_ip server_ip adm_port adm_transport adm_observer adm_source | stats max(adm_rec) as records max(adm_bytes) as bytes min(adm_first) as first max(adm_last) as last max(adm_sampled) as sampled min(adm_directed) as directed dc(adm_observer) as observer_count values(adm_observer) as observers values(adm_source) as sources sum(adm_unprotected) as unprotected by client_ip server_ip adm_port adm_transport | eval observers_capped=if(observer_count>${observers},1,0), observers=mvjoin(mvindex(observers,0,${observers - 1}),"|"), sources=mvjoin(mvindex(sources,0,${observers - 1}),"|") | eventstats count as input_count sum(unprotected) as unprotected_count | sort 0 - records client_ip server_ip adm_port adm_transport | head ${cap + 1} | eval row_type="conversation" | appendpipe [ stats max(input_count) as input_count max(unprotected_count) as unprotected_count count as output_count | eval input_count=coalesce(input_count,0), unprotected_count=coalesce(unprotected_count,0), row_type="completion", schema_version=1, output_capped=if(input_count>${cap},1,0) | fields row_type schema_version input_count output_count output_capped unprotected_count ] | fields row_type schema_version input_count output_count output_capped unprotected_count client_ip server_ip adm_port adm_transport records bytes first last sampled directed observers observers_capped sources`;
}

/** Count summary buckets with any conversation row in the scope, per UTC day. */
export function buildPlannerCoverageSearch(
  selection: PlannerSelection,
  summaryIndex: string,
  contract: 1 | 2,
): string {
  const valid = validatePlannerSelection(selection);
  if (valid.scope !== selection.scope)
    throw new Error("Invalid planner search selection.");
  return `${scopePrefix(valid, summaryIndex, contract)} | stats count by _time | eval adm_day=floor(_time/86400)*86400 | stats count as buckets by adm_day | eval row_type="coverage_day" | appendpipe [ stats count as output_count sum(buckets) as covered_buckets | eval row_type="completion", schema_version=1, covered_buckets=coalesce(covered_buckets,0) ] | fields row_type schema_version adm_day buckets output_count covered_buckets`;
}

const integer = (value: unknown): number | undefined => {
  const text = typeof value === "number" ? String(value) : value;
  return typeof text === "string" && /^\d{1,15}$/.test(text)
    ? Number(text)
    : undefined;
};
const finite = (value: unknown): number | undefined => {
  if (value === undefined || value === null || value === "") return undefined;
  const n = Number(value);
  return Number.isFinite(n) && n >= 0 ? n : NaN;
};
const invalid = (what: string) =>
  new Error(`Planner search returned an invalid ${what}.`);

function completion(rows: Record<string, unknown>[], dataType: string) {
  const meta = rows.filter((row) => row.row_type === "completion");
  if (
    meta.length !== 1 ||
    rows.some(
      (row) => row.row_type !== dataType && row.row_type !== "completion",
    ) ||
    integer(meta[0].schema_version) !== 1
  )
    throw invalid("completion envelope");
  return meta[0];
}

function splitList(value: unknown): string[] {
  if (value === undefined || value === null || value === "") return [];
  const items = String(value).split("|");
  if (
    items.length > PLANNER_LIMITS.observers ||
    !items.every((item) => validText(item, 255))
  )
    throw invalid("observer list");
  return items;
}

export function parsePlannerConversations(
  rows: Record<string, unknown>[],
  selection: PlannerSelection,
): {
  conversations: PlannerConversation[];
  inputCount: number;
  capped: boolean;
  unprotectedRows: number;
} {
  const meta = completion(rows, "conversation");
  const cap = PLANNER_LIMITS.conversations;
  const inputCount = integer(meta.input_count);
  const outputCount = integer(meta.output_count);
  const unprotectedRows = integer(meta.unprotected_count);
  const outputCapped = integer(meta.output_capped);
  const data = rows.filter((row) => row.row_type === "conversation");
  if (
    inputCount === undefined ||
    outputCount === undefined ||
    unprotectedRows === undefined ||
    outputCount !== Math.min(inputCount, cap + 1) ||
    outputCapped !== Number(inputCount > cap) ||
    data.length !== outputCount
  )
    throw invalid("completion envelope");
  const conversations = data.slice(0, cap).map((row) => {
    const client = normalizeIp(String(row.client_ip ?? ""));
    const server = normalizeIp(String(row.server_ip ?? ""));
    const transport = String(row.adm_transport ?? "");
    const portText = String(row.adm_port ?? "");
    const port = portText === "" ? undefined : integer(portText);
    const records = finite(row.records);
    const bytes = finite(row.bytes);
    const first = Number(row.first),
      last = Number(row.last);
    if (
      !validText(transport, 32) ||
      (portText !== "" && (port === undefined || port > 65535)) ||
      (port === undefined && ["tcp", "udp", "sctp"].includes(transport)) ||
      records === undefined ||
      Number.isNaN(records) ||
      Number.isNaN(bytes) ||
      !Number.isFinite(first) ||
      !Number.isFinite(last) ||
      first < 0 ||
      last < first ||
      last < selection.start ||
      first >= selection.end ||
      last > EPOCH_MAX
    )
      throw invalid("conversation row");
    const flag = (value: unknown) => {
      if (value === 1 || value === "1") return true;
      if (value === 0 || value === "0") return false;
      throw invalid("conversation flag");
    };
    return {
      client,
      server,
      ...(port === undefined ? {} : { port }),
      transport,
      directed: flag(row.directed),
      records: records as number,
      ...(bytes === undefined ? {} : { bytes }),
      first,
      last,
      observers: splitList(row.observers),
      observersCapped: flag(row.observers_capped),
      sources: splitList(row.sources),
      sampled: flag(row.sampled),
    };
  });
  return {
    conversations,
    inputCount,
    capped: inputCount > cap,
    unprotectedRows,
  };
}

export function expectedCoverage(
  selection: PlannerSelection,
): PlannerCoverageDay[] {
  const days = new Map<number, number>();
  for (
    let t = bucketStart(selection.start);
    t < selection.end;
    t += PLANNER_WINDOW.bucket
  ) {
    const day = Math.floor(t / 86400) * 86400;
    days.set(day, (days.get(day) ?? 0) + 1);
  }
  return [...days].map(([day, expected]) => ({ day, buckets: 0, expected }));
}

export function parsePlannerCoverage(
  rows: Record<string, unknown>[],
  selection: PlannerSelection,
): PlannerCoverage {
  const meta = completion(rows, "coverage_day");
  const days = expectedCoverage(selection);
  const byDay = new Map(days.map((d) => [d.day, d]));
  const data = rows.filter((row) => row.row_type === "coverage_day");
  let covered = 0;
  for (const row of data) {
    const day = integer(row.adm_day),
      buckets = integer(row.buckets);
    const target = day === undefined ? undefined : byDay.get(day);
    if (!target || buckets === undefined || buckets > target.expected)
      throw invalid("coverage row");
    target.buckets = buckets;
    covered += buckets;
  }
  if (
    integer(meta.output_count) !== data.length ||
    integer(meta.covered_buckets) !== covered
  )
    throw invalid("coverage envelope");
  return {
    coveredBuckets: covered,
    expectedBuckets: days.reduce((n, d) => n + d.expected, 0),
    days,
  };
}

export async function loadPlannerDataset(
  client: SearchClient,
  configClient: EvidenceConfigClient,
  input: PlannerSelection,
  signal: AbortSignal,
): Promise<PlannerDataset> {
  const selection = validatePlannerSelection(input);
  const config = await configClient.read(signal, [], selection.scope);
  const summaryIndex = validIndexSelector(config.summaryIndexes);
  if (
    !config.mappings.some(
      (m) => m.scope === selection.scope && m.mapping_status === "verified",
    )
  )
    throw new Error("Choose a verified routing scope.");
  const window = {
    earliest: String(bucketStart(selection.start)),
    latest: String(bucketEnd(selection.end)),
  };
  const result = await client.search({
    search: buildPlannerConversationSearch(
      selection,
      summaryIndex,
      config.trafficContract,
    ),
    ...window,
    maxRows: PLANNER_LIMITS.conversations + 2,
    allowEmpty: false,
    signal,
  });
  if (signal.aborted) throw new Error("Search cancelled.");
  requireNoSearchErrors(result, "Move-group conversation search");
  if (result.warnings.length)
    throw new Error(
      `Move-group conversation search was incomplete: ${result.warnings[0]}`,
    );
  const parsed = parsePlannerConversations(result.rows, selection);
  const coverageResult = await client.search({
    search: buildPlannerCoverageSearch(
      selection,
      summaryIndex,
      config.trafficContract,
    ),
    ...window,
    maxRows: 40,
    allowEmpty: false,
    signal,
  });
  if (signal.aborted) throw new Error("Search cancelled.");
  requireNoSearchErrors(coverageResult, "Move-group coverage search");
  if (coverageResult.warnings.length)
    throw new Error(
      `Move-group coverage search was incomplete: ${coverageResult.warnings[0]}`,
    );
  const coverage = parsePlannerCoverage(coverageResult.rows, selection);
  const after = await configClient.read(signal, [], selection.scope);
  if (after.fingerprint !== config.fingerprint)
    throw new Error(
      "Summary configuration changed during the search; load the conversations again.",
    );
  const gapDays = coverage.days.filter((d) => d.buckets < d.expected).length;
  return {
    schemaVersion: PLANNER_DATA_SCHEMA_VERSION,
    selection: {
      ...selection,
      configurationFingerprint: config.fingerprint,
      trafficContract: config.trafficContract,
    },
    capturedAt: Math.floor(Date.now() / 1000),
    ...parsed,
    coverage,
    warnings: [
      ...(parsed.capped
        ? [
            `${parsed.inputCount.toLocaleString()} distinct conversations matched; only the ${PLANNER_LIMITS.conversations.toLocaleString()} with the most flow records were loaded.`,
          ]
        : []),
      ...(parsed.unprotectedRows
        ? [
            `${parsed.unprotectedRows} legacy summary rows had no replay identifier and could not be deduplicated safely; counters may be overstated.`,
          ]
        : []),
      ...(gapDays
        ? [
            `${gapDays} of ${coverage.days.length} days have 5-minute buckets with no conversation summaries in this scope. A missing bucket is a collection gap or a quiet period; this search cannot tell which.`,
          ]
        : []),
      "Summary intervals that straddle the window edges are counted whole; counters are not prorated.",
    ],
  };
}
