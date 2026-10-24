import { pageURL } from "../app/urlState";
import {
  literal,
  normalizeIp,
  routingScope,
  scopedAddressPredicate,
} from "./evidence";
import type { EvidenceSelection, TrafficContext } from "./evidence";
import type { EvidenceConfigClient } from "./evidenceConfig";
import type { IdentityRecord } from "./dnsAdapters";
import { requireNoSearchErrors, type SearchClient } from "./searchClient";

export const ENDPOINT_SCHEMA_VERSION = 1 as const;
export const ENDPOINT_LIMITS = {
  peers: 100,
  relationships: 500,
  contexts: 256,
  window: 86400,
} as const;
export interface EndpointSelection {
  schemaVersion: 1;
  id: string;
  address: string;
  scope: string;
  start: number;
  end: number;
  configurationFingerprint: string;
  trafficContract: 1 | 2;
}
export interface EndpointConversation {
  scope: string;
  root: string;
  client: string;
  server: string;
  peer: string;
  port?: number;
  transport: string;
  directionBasis: string;
  source: string;
  observer: string;
  first: number;
  last: number;
  records: number;
  bytesClientToServer?: number;
  bytesServerToClient?: number;
  packets?: number;
  conversations: number;
  sampled?: boolean;
  contextCapped: boolean;
}
export interface EndpointTrafficObservation {
  scope: string;
  source: string;
  observer: string;
  sourceIp: string;
  destinationIp: string;
  sourcePort: number;
  destinationPort: number;
  transport: string;
  first: number;
  last: number;
  records: number;
  counterSemantics: string;
  metricsAuthoritative: false;
}
export interface EndpointResult {
  schemaVersion: 1;
  selection: EndpointSelection;
  capturedAt: number;
  conversations: EndpointConversation[];
  observations: EndpointTrafficObservation[];
  observationState: "not_applicable" | "complete" | "unavailable";
  observationCapped: boolean;
  observationError?: string;
  identityAvailable: boolean;
  identityHistory: IdentityRecord[];
  identityHistoryCapped: boolean;
  peerCapped: boolean;
  relationshipCapped: boolean;
  warnings: string[];
}
export interface EndpointInput {
  address: string;
  scope: string;
  start: number;
  end: number;
}

function validText(value: unknown, maxLength: number): value is string {
  if (typeof value !== "string" || value.length > maxLength) return false;
  for (let i = 0; i < value.length; i += 1) {
    const code = value.charCodeAt(i);
    if (code <= 31 || code === 127) return false;
  }
  return true;
}

function envelopeInteger(value: unknown): number | undefined {
  if (typeof value === "number")
    return Number.isSafeInteger(value) && value >= 0 ? value : undefined;
  if (typeof value === "string" && /^\d+$/.test(value)) {
    const parsed = Number(value);
    return Number.isSafeInteger(parsed) ? parsed : undefined;
  }
  return undefined;
}

function validateEnvelope(
  rows: Record<string, unknown>[],
  dataType: string,
  cap: number,
  hasSentinel: boolean,
): {
  inputCount: number;
  outputCount: number;
  outputCapped: boolean;
  unprotectedCount: number;
} {
  const metaRows = rows.filter((row) => row.row_type === "completion");
  const allowedTypes = new Set([dataType, "completion"]);
  if (
    metaRows.length !== 1 ||
    rows.some((row) => !allowedTypes.has(String(row.row_type)))
  )
    throw new Error("Search returned an invalid bounded completion envelope.");
  const meta = metaRows[0] as Record<string, unknown>;
  const inputCount = envelopeInteger(meta.input_count);
  const outputCount = envelopeInteger(meta.output_count);
  const inputCapped = envelopeInteger(meta.input_capped);
  const outputCapped = envelopeInteger(meta.output_capped);
  const unprotectedCount = hasSentinel
    ? envelopeInteger(meta.unprotected_count)
    : 0;
  const expectedOutput = Math.min(inputCount ?? -1, cap + Number(hasSentinel));
  if (
    envelopeInteger(meta.schema_version) !== 1 ||
    inputCount === undefined ||
    outputCount === undefined ||
    inputCapped !== 0 ||
    outputCapped !== Number((inputCount ?? 0) > cap) ||
    outputCount !== expectedOutput ||
    unprotectedCount === undefined ||
    inputCount === undefined ||
    unprotectedCount > inputCount ||
    rows.filter((row) => row.row_type === dataType).length !== outputCount
  )
    throw new Error("Search returned an invalid bounded completion envelope.");
  return {
    inputCount,
    outputCount,
    outputCapped: outputCapped === 1,
    unprotectedCount,
  };
}

export function validateEndpointResult(value: EndpointResult): EndpointResult {
  if (
    !value ||
    value.schemaVersion !== 1 ||
    !value.selection ||
    value.selection.schemaVersion !== 1 ||
    !/^[a-f0-9]{64}$/.test(value.selection.configurationFingerprint) ||
    !Number.isFinite(value.capturedAt) ||
    value.capturedAt < 0 ||
    value.capturedAt > 253402300799 ||
    value.selection.end <= value.selection.start ||
    value.selection.end - value.selection.start > ENDPOINT_LIMITS.window ||
    !Array.isArray(value.conversations) ||
    value.conversations.length > ENDPOINT_LIMITS.relationships ||
    !Array.isArray(value.observations) ||
    value.observations.length > 100 ||
    !["not_applicable", "complete", "unavailable"].includes(
      value.observationState,
    ) ||
    typeof value.observationCapped !== "boolean" ||
    typeof value.identityAvailable !== "boolean" ||
    !Array.isArray(value.identityHistory) ||
    value.identityHistory.length > 256 ||
    typeof value.identityHistoryCapped !== "boolean" ||
    typeof value.peerCapped !== "boolean" ||
    typeof value.relationshipCapped !== "boolean" ||
    !Array.isArray(value.warnings)
  )
    throw new Error("Invalid endpoint investigation result.");
  validateEndpointInput({
    address: value.selection.address,
    scope: value.selection.scope,
    start: value.selection.start,
    end: value.selection.end,
  });
  for (const c of value.conversations) {
    if (
      c.scope !== value.selection.scope ||
      normalizeIp(c.root) !== c.root ||
      normalizeIp(c.client) !== c.client ||
      normalizeIp(c.server) !== c.server ||
      normalizeIp(c.peer) !== c.peer ||
      c.root !== value.selection.address ||
      (c.client !== c.root && c.server !== c.root) ||
      (c.port !== undefined &&
        (!Number.isInteger(c.port) || c.port < 0 || c.port > 65535)) ||
      !Number.isFinite(c.first) ||
      !Number.isFinite(c.last) ||
      c.first < 0 ||
      c.first > 253402300799 ||
      c.last > 253402300799 ||
      c.last < c.first ||
      !Number.isFinite(c.records) ||
      c.records < 0 ||
      !Number.isFinite(c.conversations) ||
      c.conversations < 0 ||
      [c.bytesClientToServer, c.bytesServerToClient, c.packets].some(
        (n) => n !== undefined && (!Number.isFinite(n) || n < 0),
      ) ||
      typeof c.contextCapped !== "boolean" ||
      (c.sampled !== undefined && typeof c.sampled !== "boolean") ||
      ![c.transport, c.directionBasis, c.source, c.observer].every((v) =>
        validText(v, 255),
      )
    )
      throw new Error("Invalid endpoint conversation result.");
  }
  for (const o of value.observations)
    if (
      o.scope !== value.selection.scope ||
      normalizeIp(o.sourceIp) !== o.sourceIp ||
      normalizeIp(o.destinationIp) !== o.destinationIp ||
      (o.sourceIp !== value.selection.address &&
        o.destinationIp !== value.selection.address) ||
      ![o.sourcePort, o.destinationPort].every(
        (p) => Number.isInteger(p) && p >= 0 && p <= 65535,
      ) ||
      !Number.isFinite(o.first) ||
      !Number.isFinite(o.last) ||
      o.first < 0 ||
      o.first > 253402300799 ||
      o.last > 253402300799 ||
      o.last < o.first ||
      o.records !== 1 ||
      o.metricsAuthoritative !== false ||
      ![o.source, o.observer, o.transport, o.counterSemantics].every((v) =>
        validText(v, 255),
      )
    )
      throw new Error("Invalid non-authoritative traffic observation.");
  for (const identity of value.identityHistory)
    if (
      identity.ip !== value.selection.address ||
      identity.scope !== value.selection.scope ||
      !identity.entity_id ||
      identity.entity_id.length > 1024 ||
      !identity.entity_kind ||
      identity.entity_kind.length > 128 ||
      !Number.isFinite(identity.valid_from) ||
      identity.valid_from < 0 ||
      identity.valid_from > 253402300799 ||
      (identity.valid_end !== undefined &&
        (!Number.isFinite(identity.valid_end) ||
          identity.valid_end > 253402300799 ||
          identity.valid_end <= identity.valid_from))
    )
      throw new Error("Invalid endpoint identity history.");
  return value;
}

export function validateEndpointInput(input: EndpointInput): EndpointInput {
  const address = normalizeIp(input.address.trim());
  const scope = routingScope(input.scope.trim());
  if (
    ![input.start, input.end].every(Number.isFinite) ||
    input.start < 0 ||
    input.end > 253402300799 ||
    input.end <= input.start ||
    input.end - input.start > ENDPOINT_LIMITS.window
  )
    throw new Error("Choose an absolute time window of up to 24 hours.");
  return { address, scope, start: input.start, end: input.end };
}

export function endpointUrl(
  input: EndpointInput,
  pathname = pageURL("endpoints"),
): string {
  const valid = validateEndpointInput(input);
  const params = new URLSearchParams({
    endpoint_ip: valid.address,
    endpoint_scope: valid.scope,
    endpoint_start: String(valid.start),
    endpoint_end: String(valid.end),
  });
  if (!/^(?:\/[^/]+)*\/app\/splunk_adm\/endpoints\/?$/.test(pathname))
    throw new Error("Invalid endpoint page path.");
  return `${pathname}?${params}`;
}

export function parseEndpointUrl(
  params: URLSearchParams,
): EndpointInput | undefined {
  const keys = [
    "endpoint_ip",
    "endpoint_scope",
    "endpoint_start",
    "endpoint_end",
  ];
  if (!keys.some((key) => params.has(key))) return undefined;
  if (
    keys.some((key) => !params.has(key)) ||
    [...params.keys()].some((key) => !keys.includes(key)) ||
    keys.some((key) => params.getAll(key).length !== 1)
  )
    throw new Error(
      "Endpoint links may contain only a literal address, scope, and absolute time bounds.",
    );
  const start = params.get("endpoint_start")!,
    end = params.get("endpoint_end")!;
  if (!/^\d+(?:\.\d+)?$/.test(start) || !/^\d+(?:\.\d+)?$/.test(end))
    throw new Error(
      "Endpoint link time bounds must be absolute epoch seconds.",
    );
  return validateEndpointInput({
    address: params.get("endpoint_ip")!,
    scope: params.get("endpoint_scope")!,
    start: Number(start),
    end: Number(end),
  });
}

export function buildEndpointSearch(
  selection: EndpointSelection,
  summaryIndex: string,
): string {
  if (
    selection.schemaVersion !== 1 ||
    ![1, 2].includes(selection.trafficContract) ||
    !/^[a-f0-9]{64}$/.test(selection.configurationFingerprint)
  )
    throw new Error("Invalid endpoint selection.");
  const valid = validateEndpointInput(selection);
  if (valid.address !== selection.address || valid.scope !== selection.scope)
    throw new Error("Endpoint selection inputs must be canonical.");
  const address = literal(valid.address, 64),
    scope = literal(valid.scope, 253);
  // Summary rows are bucketed by floor(adm_end/300)*300. Include the
  // containing bucket, then use the retained interval fields below to keep
  // attribution bounded to the requested half-open window.
  const summaryStart = Math.floor(valid.start / 300) * 300;
  const t = `_time>=${summaryStart} AND _time<${valid.end}`;
  const clientPredicate = scopedAddressPredicate("client_ip", [address]);
  const addressPredicate = `(${clientPredicate} OR ${scopedAddressPredicate("server_ip", [address])})`;
  if (
    !/^(?:index=[a-z][a-z0-9_-]{0,79})(?: OR index=[a-z][a-z0-9_-]{0,79})*$/.test(
      summaryIndex,
    )
  )
    throw new Error("Invalid configured summary index.");
  const contractFilter =
    selection.trafficContract === 1
      ? "(isnull(contract_version) OR tonumber(contract_version)=1)"
      : "(tonumber(contract_version)=2)";
  return `search (${summaryIndex}) source="adm:conversation" adm_record="conversation" ${t} | where ${contractFilter} AND ${addressPredicate} | eval adm_unprotected=if(isnull(rollup_id),1,0) | dedup rollup_id keepempty=true | eval scope=if(scope="default" AND coalesce(tostring(scope_mapping_verified),"0")!="1","unmapped:legacy-default",scope) | where scope="${scope}" | eval adm_root="${address}", adm_client=client_ip, adm_server=server_ip, adm_peer=if(${clientPredicate},server_ip,client_ip), adm_port=tonumber(server_port), adm_transport=transport, adm_first=tonumber(first_seen), adm_last=tonumber(last_seen), adm_records=tonumber(records), adm_conns=conns, adm_sampled=sampled, adm_context_capped=if(conns_capped="1",1,0), adm_direction=direction_basis, adm_source=flow_source, adm_observer=observer, adm_bcs=tonumber(bytes_c2s), adm_bsc=tonumber(bytes_s2c), adm_packets=tonumber(packets) | where isnotnull(adm_peer) AND isnotnull(adm_first) AND isnotnull(adm_last) AND adm_last>=${valid.start} AND adm_first<${valid.end} | eventstats count as input_count sum(adm_unprotected) as unprotected_count | sort 0 - adm_records | head ${ENDPOINT_LIMITS.relationships + 1} | eval row_type="conversation" | appendpipe [ stats max(input_count) as input_count max(unprotected_count) as unprotected_count count as output_count | eval input_count=coalesce(input_count,0), unprotected_count=coalesce(unprotected_count,0), row_type="completion", schema_version=1, input_capped=0, output_capped=if(input_count>${ENDPOINT_LIMITS.relationships},1,0) | fields row_type schema_version input_count output_count input_capped output_capped unprotected_count ] | fields row_type schema_version input_count output_count input_capped output_capped unprotected_count scope adm_root adm_client adm_server adm_peer adm_port adm_transport adm_first adm_last adm_records adm_conns adm_sampled adm_context_capped adm_direction adm_source adm_observer adm_bcs adm_bsc adm_packets`;
}

export function buildEndpointObservationSearch(
  selection: EndpointSelection,
  summarySelector: string,
): string {
  if (
    selection.schemaVersion !== 1 ||
    selection.trafficContract !== 2 ||
    !/^[a-f0-9]{64}$/.test(selection.configurationFingerprint)
  )
    throw new Error("Traffic observations require summary contract V2.");
  const valid = validateEndpointInput(selection);
  if (valid.address !== selection.address || valid.scope !== selection.scope)
    throw new Error("Endpoint selection inputs must be canonical.");
  if (
    !/^(?:index=[a-z][a-z0-9_-]{0,79})(?: OR index=[a-z][a-z0-9_-]{0,79})*$/.test(
      summarySelector,
    )
  )
    throw new Error("Invalid configured summary index.");
  const address = literal(valid.address, 64),
    scope = literal(valid.scope, 253);
  const summaryStart = Math.floor(valid.start / 300) * 300;
  const addressPredicate = `(${scopedAddressPredicate("source_ip", [address])} OR ${scopedAddressPredicate("destination_ip", [address])})`;
  return `search (${summarySelector}) source="adm:traffic_observation" adm_record="traffic_observation" contract_version=2 | where ${addressPredicate} AND _time>=${summaryStart} AND _time<${valid.end} AND scope="${scope}" AND adm_profile_status="mapped" AND records=1 AND metrics_authoritative=0 AND adm_quality_status IN ("accepted","accepted_with_warning") | eval traffic_observation_id=coalesce(rollup_id,traffic_observation_id) | streamstats count AS adm_observation_row | eval adm_observation_dedup_key=if(isnotnull(traffic_observation_id),traffic_observation_id,"unprotected:".tostring(adm_observation_row)) | dedup adm_observation_dedup_key | eval source=adm_scope_source, row_type="traffic_observation", adm_first=tonumber(first_seen), adm_last=tonumber(last_seen) | where isnotnull(adm_first) AND isnotnull(adm_last) AND adm_last>=${valid.start} AND adm_first<${valid.end} | eventstats count as input_count | head 100 | appendpipe [ stats max(input_count) as input_count count as output_count | eval input_count=coalesce(input_count,0), row_type="completion", schema_version=1, input_capped=0, output_capped=if(input_count>100,1,0) | fields row_type schema_version input_count output_count input_capped output_capped ] | fields row_type schema_version input_count output_count input_capped output_capped scope source adm_scope_authority source_ip destination_ip source_port destination_port transport adm_first adm_last records counter_semantics metrics_authoritative adm_quality_status`;
}

export function endpointEvidenceSelection(
  result: EndpointResult,
): EvidenceSelection {
  const contextsCapped =
    result.peerCapped ||
    result.relationshipCapped ||
    result.conversations.length > ENDPOINT_LIMITS.contexts ||
    result.identityHistoryCapped;
  const contexts: TrafficContext[] = result.conversations
    .slice(0, 256)
    .map((c) => ({
      client: c.client,
      server: c.server,
      scope: c.scope,
      first: c.first,
      last: c.last,
      timeBasis: "flow_observation",
      capped: c.contextCapped || contextsCapped,
    }));
  return {
    schemaVersion: 1,
    workflow: "endpoint",
    selectionId: result.selection.id,
    trafficContract: result.selection.trafficContract,
    window: { start: result.selection.start, end: result.selection.end },
    scope: result.selection.scope,
    addresses: [result.selection.address],
    contexts,
    identityBasis: contextsCapped
      ? "Scoped endpoint address; no workload identity inferred. Tuple context is incomplete because of a result or identity cap."
      : "scoped endpoint address; no workload identity inferred",
    configurationFingerprint: result.selection.configurationFingerprint,
  };
}

export async function runEndpointInvestigation(
  client: SearchClient,
  configClient: EvidenceConfigClient,
  input: EndpointInput,
  signal: AbortSignal,
): Promise<EndpointResult> {
  const valid = validateEndpointInput(input);
  const config = await configClient.read(signal, [valid.address], valid.scope);
  const index = config.summaryIndexes[0];
  if (!index) throw new Error("No active summary index is configured.");
  if (
    !config.mappings.some(
      (mapping) =>
        mapping.scope === valid.scope && mapping.mapping_status === "verified",
    )
  )
    throw new Error("Choose a verified routing scope.");
  // Selectors are validated as literal values before interpolating SPL.
  const selection: EndpointSelection = {
    schemaVersion: 1,
    id: `${valid.scope}:${valid.address}:${valid.start}:${valid.end}`,
    ...valid,
    configurationFingerprint: config.fingerprint,
    trafficContract: config.trafficContract,
  };
  const activeIndex = config.summaryIndexes
    .map((name) => {
      if (!/^[a-z][a-z0-9_-]{0,79}$/.test(name))
        throw new Error("Invalid configured summary index.");
      return `index=${name}`;
    })
    .join(" OR ");
  const result = await client.search({
    search: buildEndpointSearch(selection, activeIndex),
    earliest: String(Math.floor(valid.start / 300) * 300),
    latest: String(valid.end),
    maxRows: ENDPOINT_LIMITS.relationships + 2,
    allowEmpty: true,
    signal,
    budget: { serverSeconds: 30, clientMilliseconds: 35000 },
  });
  if (signal.aborted) throw new Error("Search cancelled.");
  requireNoSearchErrors(result, "Endpoint conversation search");
  if (result.warnings.length)
    throw new Error(
      `Endpoint conversation search was incomplete: ${result.warnings[0]}`,
    );
  const envelope = validateEnvelope(
    result.rows,
    "conversation",
    ENDPOINT_LIMITS.relationships,
    true,
  );
  const outputCapped = envelope.outputCapped;
  const unprotectedCount = envelope.unprotectedCount;
  const conversations = result.rows.flatMap((row) => {
    if (row.row_type !== "conversation") return [];
    const client = normalizeIp(String(row.adm_client ?? ""));
    const server = normalizeIp(String(row.adm_server ?? ""));
    const peer = normalizeIp(String(row.adm_peer ?? ""));
    if (
      row.scope !== valid.scope ||
      row.adm_root !== valid.address ||
      (client !== valid.address && server !== valid.address) ||
      peer !== (client === valid.address ? server : client)
    )
      throw new Error("Endpoint search returned an invalid conversation row.");
    const port =
        row.adm_port === null ||
        row.adm_port === undefined ||
        row.adm_port === ""
          ? undefined
          : Number(row.adm_port),
      transport = String(row.adm_transport ?? "unknown").toLowerCase(),
      first = Number(row.adm_first),
      last = Number(row.adm_last);
    if (
      (port !== undefined &&
        (!Number.isInteger(port) || port < 0 || port > 65535)) ||
      (port === undefined && !["icmp", "ipv6-icmp", "ipip"].includes(transport))
    )
      throw new Error("Endpoint search returned an invalid conversation port.");
    // Rollup buckets are 300s wide, so a bucket inside the window may hold flows outside it.
    if (
      !Number.isFinite(first) ||
      !Number.isFinite(last) ||
      first < 0 ||
      last < valid.start ||
      first >= valid.end ||
      last < first
    )
      throw new Error(
        "Endpoint search returned an invalid conversation interval.",
      );
    const records = Number(row.adm_records);
    if (!Number.isFinite(records) || records < 0)
      throw new Error("Endpoint search returned an invalid record counter.");
    const conns = String(row.adm_conns ?? "");
    if (
      conns &&
      conns
        .split("|")
        .some((item) => !/^\d+@\d+(?:\.\d+)?@\d+(?:\.\d+)?$/.test(item))
    )
      throw new Error("Endpoint search returned invalid tuple history.");
    const optionalCounter = (value: unknown, name: string) => {
      if (value === undefined || value === null || value === "")
        return undefined;
      const numeric = Number(value);
      if (!Number.isFinite(numeric) || numeric < 0)
        throw new Error(`Endpoint search returned an invalid ${name} counter.`);
      return numeric;
    };
    const sampled =
      row.adm_sampled === 1 || row.adm_sampled === "1"
        ? true
        : row.adm_sampled === 0 || row.adm_sampled === "0"
          ? false
          : undefined;
    return [
      {
        scope: valid.scope,
        root: valid.address,
        client,
        server,
        peer,
        ...(port === undefined ? {} : { port }),
        transport,
        directionBasis: String(row.adm_direction ?? "unknown"),
        source: String(row.adm_source ?? "unknown"),
        observer: String(row.adm_observer ?? "unknown"),
        first,
        last,
        records,
        ...(optionalCounter(row.adm_bcs, "bytes client-to-server") !== undefined
          ? {
              bytesClientToServer: optionalCounter(
                row.adm_bcs,
                "bytes client-to-server",
              ),
            }
          : {}),
        ...(optionalCounter(row.adm_bsc, "bytes server-to-client") !== undefined
          ? {
              bytesServerToClient: optionalCounter(
                row.adm_bsc,
                "bytes server-to-client",
              ),
            }
          : {}),
        ...(optionalCounter(row.adm_packets, "packet") !== undefined
          ? { packets: optionalCounter(row.adm_packets, "packet") }
          : {}),
        conversations: conns ? conns.split("|").length : 0,
        ...(sampled === undefined ? {} : { sampled }),
        contextCapped:
          row.adm_context_capped === 1 || row.adm_context_capped === "1",
      },
    ];
  });
  const observations: EndpointTrafficObservation[] = [];
  let observationCapped = false;
  let observationState: EndpointResult["observationState"] =
    config.trafficContract === 2 ? "complete" : "not_applicable";
  let observationError: string | undefined;
  if (config.trafficContract === 2) {
    try {
      const traffic = await client.search({
        search: buildEndpointObservationSearch(selection, activeIndex),
        earliest: String(Math.floor(valid.start / 300) * 300),
        latest: String(valid.end),
        maxRows: 101,
        allowEmpty: true,
        signal,
        budget: { serverSeconds: 30, clientMilliseconds: 35000 },
      });
      requireNoSearchErrors(traffic, "Endpoint V2 observation search");
      if (traffic.warnings.length)
        throw new Error(
          `Endpoint V2 observation search was incomplete: ${traffic.warnings[0]}`,
        );
      const trafficEnvelope = validateEnvelope(
        traffic.rows,
        "traffic_observation",
        100,
        false,
      );
      observationCapped = trafficEnvelope.outputCapped;
      for (const row of traffic.rows.filter(
        (row) => row.row_type === "traffic_observation",
      )) {
        const sourceIp = normalizeIp(String(row.source_ip)),
          destinationIp = normalizeIp(String(row.destination_ip));
        const sourcePort = Number(row.source_port),
          destinationPort = Number(row.destination_port),
          first = Number(row.adm_first),
          last = Number(row.adm_last);
        if (
          row.scope !== valid.scope ||
          !["accepted", "accepted_with_warning"].includes(
            String(row.adm_quality_status),
          ) ||
          ![sourcePort, destinationPort].every(
            (p) => Number.isInteger(p) && p >= 0 && p <= 65535,
          ) ||
          !Number.isFinite(first) ||
          !Number.isFinite(last) ||
          first < 0 ||
          last < valid.start ||
          first >= valid.end ||
          last < first
        )
          throw new Error("Traffic observations could not be validated.");
        observations.push({
          scope: valid.scope,
          source: String(row.source ?? "unknown"),
          observer: String(row.adm_scope_authority ?? "unknown"),
          sourceIp,
          destinationIp,
          sourcePort,
          destinationPort,
          transport: String(row.transport ?? "unknown"),
          first,
          last,
          records: 1,
          counterSemantics: String(row.counter_semantics ?? "unknown"),
          metricsAuthoritative: false,
        });
      }
    } catch (reason) {
      if (signal.aborted)
        throw new Error("Search cancelled.", { cause: reason });
      observations.length = 0;
      observationState = "unavailable";
      observationError =
        reason instanceof Error
          ? reason.message
          : "V2 traffic observations are unavailable.";
    }
  }
  const after = await configClient.read(signal, [valid.address], valid.scope);
  if (after.fingerprint !== config.fingerprint)
    throw new Error(
      "Endpoint configuration changed during the search; reload the investigation.",
    );
  const peerOrder = [...new Set(conversations.map((c) => c.peer))].slice(
    0,
    ENDPOINT_LIMITS.peers,
  );
  const boundedConversations = conversations
    .filter((c) => peerOrder.includes(c.peer))
    .slice(0, ENDPOINT_LIMITS.relationships);
  const peerCapped =
    new Set(conversations.map((c) => c.peer)).size > ENDPOINT_LIMITS.peers;
  const allIdentityHistory = config.identities.filter(
    (identity) =>
      identity.ip === valid.address &&
      identity.scope === valid.scope &&
      identity.valid_from < valid.end &&
      (identity.valid_end === undefined || identity.valid_end > valid.start),
  );
  return validateEndpointResult({
    schemaVersion: 1,
    selection: {
      schemaVersion: 1,
      id: selection.id,
      ...valid,
      configurationFingerprint: config.fingerprint,
      trafficContract: config.trafficContract,
    },
    capturedAt: Date.now() / 1000,
    conversations: boundedConversations,
    observations,
    observationState,
    observationCapped,
    ...(observationError ? { observationError } : {}),
    identityAvailable: config.identityAvailable,
    identityHistory: allIdentityHistory.slice(0, 256),
    identityHistoryCapped: allIdentityHistory.length > 256,
    peerCapped,
    relationshipCapped:
      outputCapped ||
      peerCapped ||
      conversations.length > ENDPOINT_LIMITS.relationships,
    warnings: [
      ...result.warnings,
      ...(boundedConversations.some(
        (c) => c.first < valid.start || c.last >= valid.end,
      )
        ? [
            "Some summary intervals straddle the requested window. Their counters cover the full retained interval and are not prorated to this window.",
          ]
        : []),
      ...(unprotectedCount
        ? [
            `${unprotectedCount} legacy summary rows had no replay identifier and could not be deduplicated safely.`,
          ]
        : []),
      ...(config.trafficContract === 2
        ? [
            "V2 traffic observations are nonauthoritative and are displayed separately from conversation totals.",
            ...(observationError
              ? [`V2 observations unavailable: ${observationError}`]
              : []),
          ]
        : []),
    ],
  });
}
