import type { Row } from "../rows";
import { fingerprint, literal } from "../data/evidence";
import { optionalJobs } from "../data/optionalJobs";
import {
  SearchAccessDeniedError,
  requireNoSearchErrors,
  type SearchClient,
} from "../data/searchClient";
import {
  MAX_GROUPS,
  flowCounterFields,
  type FlowProfile,
  type GroupSummary,
  type IgmpProfile,
  type PointQueries,
  type ProfileSummary,
  type ScopeWindow,
  type StreamProfile,
} from "./contract";
import {
  groupAddress,
  parseProfile,
  sourceAddress,
  validateScopeWindow,
} from "./inputs";

const MAX_RAW = 16384;
const MAX_LIST = 64;
const MAX_QUERY_SENDERS = 16;
const GENERAL = "0.0.0.0";
const MULTICAST = `"^(22[4-9]|23[0-9])[.]"`;

const raw = (name: string) => `json_extract(_raw,"${name}")`;
/** Single-record encodings may carry scalars instead of one-element arrays. */
const mv = (name: string) =>
  `coalesce(json_array_to_mv(${raw(name)}),${raw(name)})`;

function igmpSearch(profile: IgmpProfile, index: string, observer: string) {
  const { segment } = profile;
  const segmentField =
    segment.kind === "vlan"
      ? "vlan_id"
      : segment.kind === "vni"
        ? "vxlan_id"
        : undefined;
  const filters = [
    `${raw("network_interface")}="${profile.captureInterface}"`,
    ...(segmentField
      ? [
          `(isnull(${raw(segmentField)}) OR tonumber(${raw(segmentField)})=${Number(segment.id)})`,
        ]
      : []),
  ];
  const v3 = `t=34 AND mvcount(ga)=tonumber(${raw("num_groups")}) AND mvcount(gt)=mvcount(ga) AND mvcount(gn)=mvcount(ga)${profile.v3Encoding === "single-record" ? " AND mvcount(ga)=1" : ""}`;
  return `search index="${index}" sourcetype="stream:igmp" host="${observer}"
| eval oversized=if(len(_raw)>${MAX_RAW},1,0)
| where if(oversized=1,false(),${filters.join(" AND ")})
| eval t=tonumber(${raw("type")}), src=${raw("src_ip")}, ga=${mv("group_record_multicast_address")}, gt=${mv("group_record_type")}, gn=${mv("group_record_num_sources")}
| where t=17 OR t=18 OR t=22 OR t=23 OR (${v3})
| eval rec=if(t=34,mvzip(mvzip(ga,gt,"|"),gn,"|"),${raw("multicast_address")}."|0|0")
| mvexpand rec
| eval g=mvindex(split(rec,"|"),0), op=tonumber(mvindex(split(rec,"|"),1)), n=tonumber(mvindex(split(rec,"|"),2))
| where match(g,${MULTICAST}) OR (t=17 AND g="${GENERAL}")
| eval class=case(t=17 AND g="${GENERAL}","general", t=17,"query", t=34 AND op=1 AND n=0,"none", t=23 OR op=6 OR (op=3 AND n=0),"leave", true(),"report")
| where class!="none"
| eventstats min(_time) AS qf max(_time) AS ql BY src class
| stats count(eval(class="report")) AS reports count(eval(class="leave")) AS leaves count(eval(class="query")) AS group_queries max(eval(if(class="leave",_time,null()))) AS last_leave max(eval(if(class="query",_time,null()))) AS last_group_query max(eval(if(class="general",_time,null()))) AS last_general_query values(eval(if(class="report",src,null()))) AS reporters values(eval(if(class="query" OR class="general",src."|".qf."|".ql,null()))) AS query_senders min(_time) AS first_seen max(_time) AS last_seen BY g
| eval group=g
| fields - g
| eval reporter_count=coalesce(mvcount(reporters),0), query_sender_count=coalesce(mvcount(query_senders),0), reporters=mvindex(reporters,0,${MAX_LIST - 1}), query_senders=mvindex(query_senders,0,${MAX_QUERY_SENDERS - 1})
| eval general=if(group="${GENERAL}",1,0), counted=1-general
| eventstats sum(counted) AS group_count
| sort 0 -general -last_seen
| head ${MAX_GROUPS + 1}
| fields - general counted`;
}

function flowSearch(profile: FlowProfile, index: string, observer: string) {
  const { packets, bytes } = flowCounterFields(profile);
  const filters = [
    `${raw("exporter_ip")}="${observer}"`,
    `tostring(${raw("observation_domain_id")})="${literal(profile.observationDomain)}"`,
    `tostring(${raw("template_id")})="${literal(profile.template)}"`,
    `tostring(${raw("flow_dir")})="${profile.direction === "egress" ? "1" : "0"}"`,
    `(isnull(${raw("exporter_sampling_interval")}) OR tonumber(${raw("exporter_sampling_interval")})=${profile.samplingInterval})`,
    `match(${raw("dest_ip")},${MULTICAST})`,
  ];
  return `search index="${index}" sourcetype="stream:netflow"
| eval oversized=if(len(_raw)>${MAX_RAW},1,0)
| where if(oversized=1,false(),${filters.join(" AND ")})
| eval src=${raw("src_ip")}, g=${raw("dest_ip")}, packets=tonumber(${raw(packets)}), bytes=tonumber(${raw(bytes)})
| stats count AS flows count(packets) AS packet_flows count(bytes) AS byte_flows dc(src) AS sender_count values(src) AS senders sum(packets) AS packets sum(bytes) AS bytes min(_time) AS first_seen max(_time) AS last_seen BY g
| eval group=g
| fields - g
| eval senders=mvindex(senders,0,${MAX_LIST - 1}), packets=if(packet_flows=flows,packets,null()), bytes=if(byte_flows=flows,bytes,null())
| fields - flows packet_flows byte_flows
| eventstats count AS group_count
| sort 0 -last_seen
| head ${MAX_GROUPS}`;
}

/** One bounded stats row per group; the window is bound as job time range, never as text. */
export function buildGroupSummarySearch(
  input: StreamProfile,
  scopeWindow: ScopeWindow,
): string {
  const profile = parseProfile(input);
  if (profile.source === "multicast_nxos")
    throw new Error("A Stream profile is required.");
  validateScopeWindow(scopeWindow);
  const index = literal(profile.index),
    observer = literal(profile.observer);
  const body =
    profile.source === "multicast_igmp"
      ? igmpSearch(profile, index, observer)
      : flowSearch(profile, index, observer);
  return `${body}
| eval kind="record"
| appendpipe [| stats count AS returned_count max(group_count) AS group_count | eval kind="completion", group_count=coalesce(group_count,0)]`;
}

function integer(value: unknown): number | undefined {
  if (
    (typeof value !== "string" && typeof value !== "number") ||
    !/^\d+$/.test(String(value))
  )
    return undefined;
  const n = Number(value);
  return Number.isSafeInteger(n) ? n : undefined;
}
function list(value: unknown): unknown[] | undefined {
  if (value === null || value === undefined || value === "") return [];
  if (Array.isArray(value)) return value.length <= MAX_LIST ? value : undefined;
  return [value];
}
const inWindow = (value: unknown, window: ScopeWindow) => {
  if ((typeof value !== "string" && typeof value !== "number") || value === "")
    return undefined;
  const n = Number(value);
  return Number.isFinite(n) && n >= window.earliest && n <= window.latest
    ? n
    : undefined;
};
const optionalTime = (value: unknown, window: ScopeWindow) =>
  value === null || value === undefined || value === ""
    ? { ok: true as const, value: undefined }
    : ((time) =>
        time === undefined
          ? { ok: false as const }
          : { ok: true as const, value: time })(inWindow(value, window));

/** Parsed `address|first|last` query-sender entries, or undefined when any is malformed. */
function querySenders(value: unknown, window: ScopeWindow) {
  const entries = list(value);
  if (!entries || entries.length > MAX_QUERY_SENDERS) return undefined;
  const parsed: PointQueries["querySenders"] = [];
  for (const entry of entries) {
    if (typeof entry !== "string") return undefined;
    const [address, first, last, ...rest] = entry.split("|");
    const sender = sourceAddress(address),
      from = inWindow(first, window),
      to = inWindow(last, window);
    if (!sender || from === undefined || to === undefined || from > to)
      return undefined;
    if (rest.length) return undefined;
    parsed.push({ address: sender, first: from, last: to });
  }
  return parsed;
}

interface Parsed {
  summary?: GroupSummary;
  queries?: PointQueries["querySenders"];
  lastGeneralQuery?: number;
  capped: boolean;
}

function parseRow(
  row: Row,
  profile: StreamProfile,
  window: ScopeWindow,
): Parsed | undefined {
  const firstSeen = inWindow(row.first_seen, window),
    lastSeen = inWindow(row.last_seen, window);
  if (firstSeen === undefined || lastSeen === undefined || firstSeen > lastSeen)
    return undefined;
  if (profile.source === "multicast_netflow") {
    const group = groupAddress(row.group),
      senders = list(row.senders),
      senderCount = integer(row.sender_count);
    if (
      !group ||
      !senders ||
      senderCount === undefined ||
      senderCount < senders.length ||
      !senders.every((sender) => sourceAddress(sender) !== undefined)
    )
      return undefined;
    const packets = row.packets == null ? undefined : integer(row.packets),
      bytes = row.bytes == null ? undefined : integer(row.bytes);
    if (
      (row.packets != null && packets === undefined) ||
      (row.bytes != null && bytes === undefined)
    )
      return undefined;
    return {
      capped: senderCount > senders.length,
      summary: {
        kind: "flow",
        profile: profile.id,
        group,
        observer: profile.observer,
        direction: profile.direction,
        senders: (senders as string[]).sort(),
        ...(packets !== undefined && { packets }),
        ...(bytes !== undefined && { bytes }),
        samplingInterval: profile.samplingInterval,
        replication: profile.replication,
        counters: profile.counters,
        firstSeen,
        lastSeen,
      },
    };
  }
  const queries = querySenders(row.query_senders, window),
    queryCount = integer(row.query_sender_count);
  if (!queries || queryCount === undefined || queryCount < queries.length)
    return undefined;
  const capped = queryCount > queries.length;
  if (row.group === GENERAL) {
    const last = inWindow(row.last_general_query, window);
    if (last === undefined) return undefined;
    return { queries, lastGeneralQuery: last, capped };
  }
  const group = groupAddress(row.group),
    reports = integer(row.reports),
    leaves = integer(row.leaves),
    groupQueries = integer(row.group_queries),
    reporters = list(row.reporters),
    reporterCount = integer(row.reporter_count),
    lastLeave = optionalTime(row.last_leave, window),
    lastGroupQuery = optionalTime(row.last_group_query, window);
  if (
    !group ||
    reports === undefined ||
    leaves === undefined ||
    groupQueries === undefined ||
    !reporters ||
    reporterCount === undefined ||
    reporterCount < reporters.length ||
    !reporters.every((reporter) => typeof reporter === "string") ||
    !lastLeave.ok ||
    !lastGroupQuery.ok ||
    (lastLeave.value === undefined) !== (leaves === 0) ||
    (lastGroupQuery.value === undefined) !== (groupQueries === 0)
  )
    return undefined;
  const endpointReporters =
    profile.placement === "endpoint"
      ? (reporters as string[])
          .filter(
            (reporter) =>
              sourceAddress(reporter) !== undefined &&
              profile.endpointReporters.includes(reporter) &&
              !profile.proxyReporters.includes(reporter),
          )
          .sort()
      : [];
  return {
    queries,
    capped: capped || reporterCount > reporters.length,
    summary: {
      kind: "igmp",
      profile: profile.id,
      group,
      segment: profile.segment,
      reports,
      leaves,
      groupQueries,
      endpointReporters,
      otherReporters: reporterCount - endpointReporters.length,
      firstSeen,
      lastSeen,
      ...(lastLeave.value !== undefined && { lastLeave: lastLeave.value }),
      ...(lastGroupQuery.value !== undefined && {
        lastGroupQuery: lastGroupQuery.value,
      }),
    },
  };
}

function mergeQueries(
  entries: PointQueries["querySenders"],
): PointQueries["querySenders"] {
  const byAddress = new Map<string, { first: number; last: number }>();
  for (const { address, first, last } of entries) {
    const seen = byAddress.get(address);
    byAddress.set(
      address,
      seen
        ? {
            first: Math.min(seen.first, first),
            last: Math.max(seen.last, last),
          }
        : { first, last },
    );
  }
  return [...byAddress]
    .map(([address, times]) => ({ address, ...times }))
    .sort((left, right) => left.address.localeCompare(right.address, "en"));
}

export async function loadGroupSummary(
  client: SearchClient,
  input: StreamProfile,
  scopeWindow: ScopeWindow,
  signal: AbortSignal,
): Promise<ProfileSummary> {
  const profile = parseProfile(input),
    window = validateScopeWindow(scopeWindow);
  if (profile.source === "multicast_nxos")
    throw new Error("A Stream profile is required.");
  const empty = (state: "blocked" | "unavailable", detail: string) => ({
    summaries: [],
    droppedGroups: 0,
    outcome: { source: profile.source, profile: profile.id, state, detail },
  });
  if (profile.scope !== window.scope)
    return empty("blocked", "Profile scope does not match the selected scope.");
  if (profile.validFrom > window.earliest || profile.validUntil < window.latest)
    return empty(
      "unavailable",
      "Source verification does not cover the selected time window.",
    );
  try {
    const search = buildGroupSummarySearch(profile, window),
      key = await fingerprint(["multicast-summary", profile, window, search]);
    const result = requireNoSearchErrors(
      await optionalJobs.run(profile.source, key, client, {
        search,
        earliest: String(window.earliest),
        latest: String(window.latest),
        maxRows: MAX_GROUPS + 2,
        allowEmpty: true,
        signal,
      }),
      "Multicast group summary",
    );
    if (result.warnings.length || result.truncated)
      throw new Error("Unverified search completion.");
    const meta = result.rows.filter((row) => row.kind === "completion"),
      rows = result.rows.filter((row) => row.kind === "record"),
      general = rows.filter((row) => row.group === GENERAL),
      groupRows = rows.filter((row) => row.group !== GENERAL);
    if (meta.length !== 1 || rows.length + 1 !== result.rows.length)
      throw new Error("Invalid completion envelope.");
    // IGMP keeps MAX_GROUPS + 1 rows so a general-query row never displaces a
    // group; without one, the extra group row is the lowest-ranked overflow.
    const groupLimit =
      profile.source === "multicast_igmp" && general.length === 0
        ? MAX_GROUPS + 1
        : MAX_GROUPS;
    const groupCount = integer(meta[0].group_count),
      returned = integer(meta[0].returned_count);
    if (
      groupCount === undefined ||
      returned !== rows.length ||
      general.length > (profile.source === "multicast_igmp" ? 1 : 0) ||
      groupRows.length !== Math.min(groupCount, groupLimit) ||
      new Set(groupRows.map((row) => row.group)).size !== groupRows.length
    )
      throw new Error("Invalid completion counts.");
    const summaries: GroupSummary[] = [],
      senders: PointQueries["querySenders"] = [];
    let lastGeneralQuery: number | undefined,
      incomplete = false;
    for (const row of [...general, ...groupRows.slice(0, MAX_GROUPS)]) {
      const parsed = parseRow(row, profile, window);
      if (!parsed) {
        if (row.group === GENERAL) incomplete = true;
        continue;
      }
      if (parsed.summary) summaries.push(parsed.summary);
      if (parsed.queries) senders.push(...parsed.queries);
      if (parsed.lastGeneralQuery !== undefined)
        lastGeneralQuery = parsed.lastGeneralQuery;
      incomplete ||= parsed.capped;
    }
    const droppedGroups = groupCount - summaries.length;
    const queries: PointQueries | undefined =
      profile.source === "multicast_igmp"
        ? {
            profile: profile.id,
            querySenders: mergeQueries(senders),
            ...(lastGeneralQuery !== undefined && { lastGeneralQuery }),
          }
        : undefined;
    const partial = droppedGroups > 0 || incomplete;
    return {
      summaries,
      ...(queries && { queries }),
      droppedGroups,
      outcome: {
        source: profile.source,
        profile: profile.id,
        state: partial ? "partial" : "complete",
        detail:
          droppedGroups > 0
            ? `Group summary was capped or contained rows that could not be validated; ${droppedGroups} groups are not shown. Coverage is incomplete.`
            : incomplete
              ? "Some reporter, sender or query sender lists were capped or could not be validated. Coverage is incomplete."
              : "Caller-visible observations only. Oversized events and unrecognized layouts may be excluded.",
      },
    };
  } catch (error) {
    if (signal.aborted)
      throw new Error(
        "Multicast group summary cancelled; cleanup may be pending.",
        { cause: error },
      );
    return error instanceof SearchAccessDeniedError
      ? empty("blocked", "Access to this source was denied.")
      : empty(
          "unavailable",
          "Source execution or completion could not be verified.",
        );
  }
}
