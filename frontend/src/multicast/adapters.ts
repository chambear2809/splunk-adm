import type { Row } from "../rows";
import { fingerprint, literal } from "../data/evidence";
import { optionalJobs } from "../data/optionalJobs";
import {
  SearchAccessDeniedError,
  requireNoSearchErrors,
  type SearchClient,
} from "../data/searchClient";
import {
  MAX_EVIDENCE_ROWS,
  MAX_INPUT_ROWS,
  type IgmpOperation,
  type MulticastEvidence,
  type StreamProfile,
  type MulticastRequest,
  type SourceOutcome,
} from "./contract";
import {
  groupAddress,
  parseProfile,
  sourceAddress,
  validateRequest,
} from "./inputs";

const MAX_RAW = 16384;
const MAX_SOURCES = 64;
const igmpFields = [
  "src_ip",
  "type",
  "multicast_address",
  "source_address",
  "num_sources",
  "num_groups",
  "group_record_type",
  "group_record_multicast_address",
  "group_record_num_sources",
  "group_record_source_address",
  "network_interface",
  "vlan_id",
  "vxlan_id",
];
const flowFields = [
  "src_ip",
  "dest_ip",
  "bytes",
  "packets",
  "exporter_ip",
  "observation_domain_id",
  "template_id",
  "flow_dir",
  "interface_name",
  "input_snmpidx",
  "output_snmpidx",
  "exporter_sampling_interval",
];

const rawField = (name: string) => `json_extract(_raw,"${name}")`;

/** Fixed projection: arbitrary event payload and URLs never leave the search. */
export function buildMulticastSearch(
  input: StreamProfile,
  selection: MulticastRequest,
): string {
  const profile = parseProfile(input);
  if (profile.source === "multicast_nxos")
    throw new Error("A Stream profile is required.");
  const request = validateRequest(selection);
  const index = literal(profile.index);
  const observer = literal(profile.observer);
  const group = request.group;
  const isIgmp = profile.source === "multicast_igmp";
  const projected = (isIgmp ? igmpFields : flowFields)
    .map((name) => `"${name}",${rawField(name)}`)
    .join(",");
  const groupRecords = rawField("group_record_multicast_address");
  const groupRegex = group.replaceAll(".", "[.]");
  const filters = isIgmp
    ? [
        `${rawField("network_interface")}="${profile.captureInterface}"`,
        `(${rawField("multicast_address")}="${group}" OR ${groupRecords}="${group}" OR isnotnull(mvfind(json_array_to_mv(${groupRecords}),"^${groupRegex}$")))`,
      ]
    : [
        `${rawField("dest_ip")}="${group}"`,
        `${rawField("exporter_ip")}="${observer}"`,
        `tostring(${rawField("observation_domain_id")})="${profile.observationDomain}"`,
        `tostring(${rawField("template_id")})="${profile.template}"`,
        `tostring(${rawField("flow_dir")})="${profile.direction === "egress" ? "1" : "0"}"`,
        ...(request.sender
          ? [`${rawField("src_ip")}="${request.sender}"`]
          : []),
      ];
  const metadata = isIgmp ? `host="${observer}"` : "";
  return `search index="${index}" sourcetype="stream:${isIgmp ? "igmp" : "netflow"}" ${metadata}
| eval oversized=if(len(_raw)>${MAX_RAW},1,0)
| where if(oversized=1,false(),${filters.join(" AND ")})
| head ${MAX_INPUT_ROWS + 1}
| eventstats count AS input_count
| head ${MAX_INPUT_ROWS}
| eval payload=json_object(${projected})
| fields _time index host payload input_count
| eval kind="record"
| appendpipe [| stats count AS returned_count max(input_count) AS input_count | eval kind="completion", input_count=coalesce(input_count,0)]`;
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
function array(value: unknown): unknown[] | undefined {
  if (value === null || value === undefined) return [];
  if (Array.isArray(value))
    return value.length <= MAX_SOURCES ? value : undefined;
  return [value];
}
function scalar(value: unknown): unknown {
  return Array.isArray(value) && value.length === 1 ? value[0] : value;
}
const operations: Record<number, IgmpOperation> = {
  1: "include",
  2: "exclude",
  3: "change-to-include",
  4: "change-to-exclude",
  5: "allow-new-sources",
  6: "block-old-sources",
};
function sourceList(value: unknown, expected: unknown): string[] | undefined {
  const values = array(value),
    count = integer(scalar(expected));
  if (!values || count === undefined || count !== values.length)
    return undefined;
  const sources = values.map((v) =>
    typeof v === "string" ? sourceAddress(v) : undefined,
  );
  return sources.every((v): v is string => !!v) ? sources : undefined;
}
function parseRow(
  row: Row,
  profile: StreamProfile,
  request: MulticastRequest,
  id: string,
): MulticastEvidence[] | undefined {
  if (
    typeof row.payload !== "string" ||
    row.payload.length > MAX_RAW * 2 ||
    row.index !== profile.index
  )
    return undefined;
  let data: Record<string, unknown>;
  try {
    const value: unknown = JSON.parse(row.payload);
    if (!value || typeof value !== "object" || Array.isArray(value))
      return undefined;
    data = value as Record<string, unknown>;
  } catch {
    return undefined;
  }
  const timestamp = Number(row._time);
  if (
    !Number.isFinite(timestamp) ||
    timestamp < request.earliest ||
    timestamp > request.latest
  )
    return undefined;
  const base = {
    id,
    scope: request.scope,
    group: request.group,
    observer: profile.observer,
    timestamp,
  };
  if (profile.source === "multicast_netflow") {
    if (
      data.exporter_ip !== profile.observer ||
      integer(data.observation_domain_id) !==
        Number(profile.observationDomain) ||
      integer(data.template_id) !== Number(profile.template) ||
      integer(data.flow_dir) !== (profile.direction === "ingress" ? 0 : 1) ||
      (data.exporter_sampling_interval != null &&
        integer(data.exporter_sampling_interval) !==
          profile.samplingInterval) ||
      data.dest_ip !== request.group ||
      typeof data.src_ip !== "string"
    )
      return undefined;
    const sender = sourceAddress(data.src_ip);
    if (!sender || (request.sender && sender !== request.sender))
      return undefined;
    const packets = data.packets == null ? undefined : integer(data.packets),
      bytes = data.bytes == null ? undefined : integer(data.bytes);
    if (
      (data.packets != null && packets === undefined) ||
      (data.bytes != null && bytes === undefined)
    )
      return undefined;
    const interfaceIndex = integer(
      profile.direction === "ingress"
        ? data.input_snmpidx
        : data.output_snmpidx,
    );
    const label = data.interface_name;
    const monitorInterface = interfaceIndex
      ? `ifIndex ${interfaceIndex}`
      : typeof label === "string" &&
          /^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,127}$/.exec(label)?.[0] === label
        ? label
        : undefined;
    return [
      {
        ...base,
        kind: "flow",
        source: profile.source,
        sender,
        observationDomain: profile.observationDomain,
        template: profile.template,
        direction: profile.direction,
        samplingInterval: profile.samplingInterval,
        replication: profile.replication,
        counters: profile.counters,
        interface: monitorInterface,
        packets,
        bytes,
        limits: [
          "Counters and sampling depend on the operator-attested exporter template; observations do not prove delivery.",
        ],
      },
    ];
  }
  if (
    row.host !== profile.observer ||
    data.network_interface !== profile.captureInterface ||
    (profile.segment.kind === "vlan" &&
      data.vlan_id != null &&
      integer(data.vlan_id) !== Number(profile.segment.id)) ||
    (profile.segment.kind === "vni" &&
      data.vxlan_id != null &&
      integer(data.vxlan_id) !== Number(profile.segment.id))
  )
    return undefined;
  const type = integer(data.type);
  const reporter =
    typeof data.src_ip === "string" ? sourceAddress(data.src_ip) : undefined;
  const make = (
    operation: IgmpOperation,
    sources: string[],
    ordinal: number,
  ): MulticastEvidence => ({
    ...base,
    id: `${id}:${ordinal}`,
    kind: "igmp",
    source: profile.source,
    operation,
    reporter,
    reporterKind: !reporter
      ? "anonymous"
      : profile.proxyReporters.includes(reporter)
        ? "proxy"
        : profile.placement === "endpoint" &&
            profile.endpointReporters.includes(reporter)
          ? "endpoint"
          : "unknown",
    interface: profile.captureInterface,
    segment: profile.segment,
    sources,
    limits: [
      "An observed message is not proof of current membership or delivery.",
      "Proxy and transit reports cannot establish downstream receiver identity.",
    ],
  });
  if (type === 17 || type === 18 || type === 22 || type === 23) {
    if (
      typeof data.multicast_address !== "string" ||
      groupAddress(data.multicast_address) !== request.group
    )
      return undefined;
    const sources =
      type === 17 ? sourceList(data.source_address, data.num_sources ?? 0) : [];
    if (!sources) return undefined;
    return [
      make(
        type === 17
          ? "query"
          : type === 18
            ? "report-v1"
            : type === 22
              ? "report-v2"
              : "leave",
        sources,
        0,
      ),
    ];
  }
  if (type !== 34) return undefined;
  const count = integer(data.num_groups),
    groups = array(data.group_record_multicast_address),
    types = array(data.group_record_type),
    counts = array(data.group_record_num_sources),
    flatSources = array(data.group_record_source_address);
  if (
    !count ||
    count > MAX_SOURCES ||
    !groups ||
    !types ||
    !counts ||
    !flatSources ||
    groups.length !== count ||
    types.length !== count ||
    counts.length !== count ||
    (profile.v3Encoding === "single-record" && count !== 1)
  )
    return undefined;
  let offset = 0;
  const records: MulticastEvidence[] = [];
  for (let i = 0; i < count; i++) {
    const n = integer(counts[i]),
      operation = operations[integer(types[i]) ?? -1],
      group = groups[i];
    if (
      n === undefined ||
      n > MAX_SOURCES ||
      !operation ||
      typeof group !== "string" ||
      !groupAddress(group) ||
      offset + n > flatSources.length
    )
      return undefined;
    const sources = sourceList(flatSources.slice(offset, offset + n), n);
    if (!sources) return undefined;
    offset += n;
    if (group === request.group) records.push(make(operation, sources, i));
  }
  if (offset !== flatSources.length) return undefined;
  return records;
}
export async function loadMulticastSource(
  client: SearchClient,
  input: StreamProfile,
  selection: MulticastRequest,
  signal: AbortSignal,
): Promise<{ evidence: MulticastEvidence[]; outcome: SourceOutcome }> {
  const profile = parseProfile(input),
    request = validateRequest(selection);
  if (profile.source === "multicast_nxos")
    throw new Error("A Stream profile is required.");
  if (
    profile.scope !== request.scope ||
    profile.validFrom > request.earliest ||
    profile.validUntil < request.latest
  )
    return {
      evidence: [],
      outcome: {
        source: profile.source,
        profile: profile.id,
        state: "blocked",
        detail: "Profile scope or validity does not cover the request.",
      },
    };
  try {
    const search = buildMulticastSearch(profile, request),
      key = await fingerprint(["multicast", profile, request, search]);
    const result = requireNoSearchErrors(
      await optionalJobs.run(profile.source, key, client, {
        search,
        earliest: String(request.earliest),
        latest: String(request.latest),
        maxRows: MAX_INPUT_ROWS + 1,
        allowEmpty: true,
        signal,
      }),
      "Multicast evidence",
    );
    if (result.warnings.length || result.truncated)
      throw new Error("Unverified search completion.");
    const meta = result.rows.filter((row) => row.kind === "completion"),
      rows = result.rows.filter((row) => row.kind === "record");
    if (meta.length !== 1 || rows.length + 1 !== result.rows.length)
      throw new Error("Invalid completion envelope.");
    const inputCount = integer(meta[0].input_count),
      returned = integer(meta[0].returned_count);
    if (
      inputCount === undefined ||
      returned !== rows.length ||
      inputCount > MAX_INPUT_ROWS + 1 ||
      returned !== Math.min(inputCount, MAX_INPUT_ROWS)
    )
      throw new Error("Invalid completion counts.");
    const evidence: MulticastEvidence[] = [];
    let rejected = 0,
      expansionCapped = false;
    for (let i = 0; i < rows.length; i++) {
      const id = await fingerprint([profile.id, request, i, rows[i]]);
      const parsed = parseRow(rows[i], profile, request, id);
      if (parsed) {
        const remaining = MAX_EVIDENCE_ROWS - evidence.length;
        if (parsed.length > remaining) expansionCapped = true;
        evidence.push(...parsed.slice(0, remaining));
      } else rejected++;
    }
    const partial =
      inputCount > MAX_INPUT_ROWS || rejected > 0 || expansionCapped;
    return {
      evidence: evidence.slice(0, MAX_EVIDENCE_ROWS),
      outcome: {
        source: profile.source,
        profile: profile.id,
        state: partial ? "partial" : "complete",
        detail: partial
          ? "Input was capped or contained records that could not be validated. Coverage is incomplete."
          : "Caller-visible observations only. Oversized events and unrecognized layouts may be excluded.",
      },
    };
  } catch (error) {
    if (signal.aborted)
      throw new Error(
        "Multicast investigation cancelled; cleanup may be pending.",
        { cause: error },
      );
    return {
      evidence: [],
      outcome: {
        source: profile.source,
        profile: profile.id,
        state:
          error instanceof SearchAccessDeniedError ? "blocked" : "unavailable",
        detail:
          error instanceof SearchAccessDeniedError
            ? "Access to this source was denied."
            : "Source execution or completion could not be verified.",
      },
    };
  }
}
