import type { Row } from "../rows";
import { normalizeDns } from "./dnsAdapters";
import {
  evidenceConfigClient,
  type DnsConfiguration,
  type EvidenceConfigClient,
  type EvidenceConfiguration,
} from "./evidenceConfig";
import {
  EVIDENCE_LIMITS,
  fingerprint,
  literal,
  validateDnsResult,
  validateSelection,
  scopedAddressPredicate,
  type DnsEvidenceResult,
  type DnsSourceResult,
  type EvidenceSelection,
} from "./evidence";
import { indexNames } from "./deploymentHealth";
import { optionalJobs } from "./optionalJobs";
import { requireNoSearchErrors, type SearchClient } from "./searchClient";

const selector = (indexes: string[]) => {
  const text = indexes.map((index) => `index=${index}`).join(" OR ");
  const definition = indexes.length === 1 ? text : `(${text})`;
  if (
    !indexes.length ||
    indexes.length > 16 ||
    indexNames({ name: "dns", definition }).length !== indexes.length
  )
    throw new Error("Invalid DNS index configuration.");
  return definition;
};
export const eventFingerprintExpression =
  "if(isnotnull(_bkt) AND isnotnull(_cd),sha256(json_array(index,_bkt,_cd)),null())";
/** Transport only the declared observation contract; never arbitrary TXT/payload fields. */
const boundedJsonScalar = (value: string) =>
  `if(isnull(${value}),null(),if(len(tostring(${value}))<=1024,tostring(${value}),substr(tostring(${value}),1,1025)))`;
const projectedRrArray = (path: string, mv: string) => {
  const value = (rr: string, ...keys: string[]) => {
    const expressions = keys.map((key) => `json_extract(${rr},"${key}")`);
    return boundedJsonScalar(
      expressions.length === 1
        ? expressions[0]
        : `coalesce(${expressions.join(",")})`,
    );
  };
  const type = value(mv, "type", "record_type");
  const address = `if(upper(tostring(${type})) IN ("A","AAAA","1","28"),${value(mv, "address", "answer", "ip")},null())`;
  const target = `if(upper(tostring(${type}))=="CNAME",${value(mv, "target", "value")},null())`;
  return `if(oversized=1,null(),if(isnull(json_extract(_raw,"${path}")),null(),mv_to_json_array(mvmap(${mv},json_object("address",${address},"type",${type},"owner",${value(mv, "owner", "name", "rr_name")},"section",${value(mv, "section", "record_section")},"ttl",${value(mv, "ttl")},"target",${target})),true())))`;
};
function projectedRaw(stream: boolean): string {
  const field = (path: string) => `json_extract(_raw,"${path}")`;
  const object = (pairs: [string, string][]) =>
    `json_object(${pairs.flatMap(([key, value]) => [`"${key}"`, value]).join(",")})`;
  if (stream)
    return object([
      ...[
        "query",
        "query_type",
        "message_type",
        "src_ip",
        "dest_ip",
        "reply_code",
        "transaction_id",
        "response_time",
        "duration",
        "timestamp",
        "endtime",
        "start",
        "end",
        "host_addr",
        "ttl",
      ].map((key) => [key, field(key)] as [string, string]),
      ["answer_records", "json_extract(_dns_stream_answer_records)"],
      ["answers", "json_extract(_dns_stream_answers)"],
    ]);
  const dns = object(
    ["query", "qtypes", "rcode", "ips", "cnames", "ttl", "rrtypes"]
      .map((key) => [key, field(`flow.l7.dns.${key}`)] as [string, string])
      .concat([
        ["answer_records", "json_extract(_dns_hubble_answer_records)"],
        ["answers", "json_extract(_dns_hubble_answers)"],
      ]),
  );
  const ip = object(
    ["source", "destination"].map((key) => [key, field(`flow.IP.${key}`)]),
  );
  const l7 = object([
    ["type", field("flow.l7.type")],
    ["dns", dns],
  ]);
  const flow = object([
    ...(
      [
        "time",
        "uuid",
        "node_name",
        "is_reply",
        "traffic_direction",
        "verdict",
      ] as const
    ).map((key): [string, string] => [key, field(`flow.${key}`)]),
    ["IP", ip],
    ["l7", l7],
  ]);
  return object([
    ["flow", flow],
    ["node_name", field("node_name")],
    ["time", field("time")],
  ]);
}
/** No macro, lookup, join, map or hidden subsearch is dispatched. */
export function buildDnsSearch(
  config: DnsConfiguration,
  selection: EvidenceSelection,
): string {
  validateSelection(selection);
  if (
    config.state !== "active" ||
    config.error ||
    !config.authorities.length ||
    config.authorities.length > 32
  )
    throw new Error("DNS source is not active and verified.");
  const authority = config.authorities
    .map((value) => `"${literal(value)}"`)
    .join(",");
  const stream = config.source === "dns_stream";
  const hubbleAuthorities = config.authorities
    .map(
      (value) =>
        `(node_name="${literal(value)}/*" OR "flow.node_name"="${literal(value)}/*")`,
    )
    .join(" OR ");
  // Early source predicates constrain caller-visible input before raw JSON parsing.
  const filter = stream
    ? `sourcetype="stream:dns" host IN (${authority}) src_ip=*`
    : `sourcetype="cilium:hubble:flow" (${hubbleAuthorities}) ("REQUEST" OR "RESPONSE") ("dns")`;
  const clientFilter = stream
    ? scopedAddressPredicate("src_ip", selection.addresses)
    : `${scopedAddressPredicate("'flow.IP.source'", selection.addresses)} OR ${scopedAddressPredicate("'flow.IP.destination'", selection.addresses)}`;
  const rrPath = stream ? "answer_records" : "flow.l7.dns.answer_records";
  const answersPath = stream ? "answers" : "flow.l7.dns.answers";
  const rrPrefix = stream ? "_dns_stream" : "_dns_hubble";
  const rrProjection = projectedRrArray(
    rrPath,
    `${rrPrefix}_answer_records_mv`,
  );
  const answersProjection = projectedRrArray(
    answersPath,
    `${rrPrefix}_answers_mv`,
  );
  return `search ${selector(config.indexes)} ${filter}
| where ${clientFilter}
| head ${EVIDENCE_LIMITS.input + 1}
| eval event_fingerprint=${eventFingerprintExpression}, oversized=if(len(_raw)>${EVIDENCE_LIMITS.recordBytes},1,0)
| eventstats count AS input_count sum(oversized) AS oversized_count
| sort 0 - _time index event_fingerprint
| head ${EVIDENCE_LIMITS.records}
| eval ${rrPrefix}_answer_records_mv=if(oversized=1,null(),json_array_to_mv(json_extract(_raw,"${rrPath}"))), ${rrPrefix}_answers_mv=if(oversized=1,null(),json_array_to_mv(json_extract(_raw,"${answersPath}")))
| eval ${rrPrefix}_answer_records=${rrProjection}, ${rrPrefix}_answers=${answersProjection}
| eval _raw=if(oversized=1,"{}",${projectedRaw(stream)})
| fields _raw _time _indextime host index event_fingerprint input_count oversized_count oversized
| eval kind="dns_record"
| appendpipe [| stats count AS returned_count max(input_count) AS input_count max(oversized_count) AS oversized
  | eval kind="dns_completion",schema_version=1,input_count=coalesce(input_count,0),input_capped=if(input_count>${EVIDENCE_LIMITS.input},1,0),oversized=coalesce(oversized,0)]`;
}
function count(value: unknown): number {
  if (
    (typeof value !== "number" && typeof value !== "string") ||
    value === "" ||
    !/^\d+$/.test(String(value)) ||
    !Number.isSafeInteger(Number(value))
  )
    throw new Error("Unverified DNS completion counts.");
  return Number(value);
}
export function parseDnsEnvelope(rows: readonly Row[]) {
  const metadata = rows.filter((row) => row.kind === "dns_completion");
  const records = rows.filter((row) => row.kind === "dns_record");
  if (
    metadata.length !== 1 ||
    records.length + 1 !== rows.length ||
    count(metadata[0].schema_version) !== 1
  )
    throw new Error(
      "DNS completion envelope is missing, duplicated or invalid.",
    );
  const meta = metadata[0],
    input = count(meta.input_count),
    returned = count(meta.returned_count),
    capped = count(meta.input_capped),
    oversized = count(meta.oversized);
  if (
    returned !== records.length ||
    returned !== Math.min(input, 64) ||
    input > 10001 ||
    capped !== Number(input > 10000) ||
    oversized > input
  )
    throw new Error("DNS completion envelope counts disagree.");
  return {
    rows: records,
    inputCount: input,
    inputCapped: capped === 1,
    outputCapped: input > returned,
    oversized,
  };
}
const COVERAGE = [
  "Caller-visible observations only; zero records do not prove access, absence of queries or complete coverage.",
  "Cached/encrypted DNS, forwarding, NAT, NodeLocal DNS and shared proxies can hide original clients or queries.",
  "DNS names do not establish application ownership, selected backends, actual name use or a causal diagnosis.",
  "This capture is independent of the graph snapshot ID and retains flow observation time rather than assuming a connection opening.",
];
export async function loadDnsEvidence(
  client: SearchClient,
  input: EvidenceSelection,
  signal: AbortSignal,
  configurationClient: EvidenceConfigClient = evidenceConfigClient,
  diagnostics: readonly ("dns_stream" | "dns_hubble")[] = [],
): Promise<DnsEvidenceResult> {
  const selection = validateSelection(input);
  if (
    diagnostics.some(
      (source) => !["dns_stream", "dns_hubble"].includes(source),
    ) ||
    diagnostics.length > 2
  )
    throw new Error("Invalid optional diagnostic source selection.");
  const config = await configurationClient.read(
    signal,
    selection.identityAddresses ?? selection.addresses,
    selection.scope,
  );
  if (config.fingerprint !== selection.configurationFingerprint)
    throw new Error(
      "Evidence configuration changed. Refresh the selection before inspecting DNS.",
    );
  const inspectedWindow = {
    start: Math.max(0, selection.window.start - config.maxAgeSeconds),
    end: selection.window.end,
  };
  const results = await Promise.all(
    config.dns.map(async (source) => {
      const base: DnsSourceResult = {
        source: source.source,
        intent: source.state,
        state: source.state === "active" ? "unavailable" : source.state,
        inputCount: 0,
        inputCapped: false,
        outputCapped: false,
        rejected: 0,
        expansionCapped: 0,
      };
      const stagedDiagnostic =
        source.state === "staged" && diagnostics.includes(source.source);
      if (source.state !== "active" && !stagedDiagnostic)
        return { metadata: base, records: [] };
      const started = performance.now();
      let stage: DnsSourceResult["errorCode"] = "configuration";
      try {
        const search = buildDnsSearch(
          stagedDiagnostic ? { ...source, state: "active" } : source,
          selection,
        );
        const key = await fingerprint([
          config.fingerprint,
          selection,
          source.source,
          search,
        ]);
        stage = "execution";
        const result = requireNoSearchErrors(
          await optionalJobs.run(source.source, key, client, {
            search,
            earliest: String(inspectedWindow.start),
            latest: String(inspectedWindow.end),
            maxRows: 65,
            signal,
          }),
          "DNS evidence",
        );
        // Unexpected search warnings can include peer/subsearch/extraction truncation.
        stage = "completion";
        if (result.warnings.length)
          throw new Error(
            "Splunk reported a warning; DNS completion cannot be established.",
          );
        const envelope = parseDnsEnvelope(result.rows);
        if (
          envelope.rows.some(
            (row) =>
              typeof row.index !== "string" ||
              !source.indexes.includes(row.index),
          )
        )
          throw new Error(
            "DNS result origin does not match the configured source.",
          );
        stage = "normalization";
        const normalized = await normalizeDns(
          source.source,
          envelope.rows,
          {
            scope: selection.scope,
            authorities: source.authorities,
            maxAgeSeconds: config.maxAgeSeconds,
            clockUncertaintySeconds: config.clockUncertaintySeconds,
            schemaQualified: source.schemaQualified && !stagedDiagnostic,
          },
          selection,
          config.identityAvailable ? config.identities : [],
        );
        if (
          !config.identityAvailable ||
          envelope.inputCapped ||
          stagedDiagnostic
        )
          normalized.records.forEach((r) => {
            r.attribution = "context_only";
            r.attributionReason = stagedDiagnostic
              ? "Explicit staged-source diagnostic; association disabled."
              : !config.identityAvailable
                ? "Identity history is unavailable."
                : "Input cap prevents complete traffic attribution.";
          });
        return {
          metadata: {
            ...base,
            state: "complete" as const,
            inputCount: envelope.inputCount,
            inputCapped: envelope.inputCapped,
            outputCapped: envelope.outputCapped,
            rejected:
              normalized.rejected +
              envelope.oversized -
              envelope.rows.filter((row) => Number(row.oversized) === 1).length,
            expansionCapped: normalized.expansionCapped,
            durationMilliseconds: performance.now() - started,
          },
          records: normalized.records,
        };
      } catch {
        if (signal.aborted)
          throw new Error(
            "DNS investigation cancelled; cleanup may be pending.",
          );
        return {
          metadata: {
            ...base,
            state: "unavailable" as const,
            durationMilliseconds: performance.now() - started,
            errorCode: stage,
            error:
              "DNS evidence unavailable: configuration, permissions, execution or completion could not be verified.",
          },
          records: [],
        };
      }
    }),
  );
  if (signal.aborted) throw new Error("DNS investigation cancelled.");
  let after: EvidenceConfiguration | undefined;
  try {
    after = await configurationClient.read(
      signal,
      selection.identityAddresses ?? selection.addresses,
      selection.scope,
    );
  } catch {
    /* association invalidated below */
  }
  const changed = !after || after.fingerprint !== config.fingerprint;
  const records = results
    .flatMap((r) => r.records)
    .sort(
      (a, b) =>
        b.eventTime - a.eventTime ||
        a.source.localeCompare(b.source) ||
        a.eventFingerprint.localeCompare(b.eventFingerprint),
    );
  if (changed)
    records.forEach((r) => {
      r.attribution = "context_only";
      r.attributionReason =
        "Configuration changed or became unreadable; refresh required.";
    });
  return validateDnsResult({
    schemaVersion: 1,
    selection,
    capturedAt: Date.now() / 1000,
    inspectedWindow,
    configurationFingerprint: config.fingerprint,
    configurationChanged: changed,
    sources: results.map((r) => r.metadata),
    records: records.slice(0, 64),
    outputCapped:
      records.length > 64 || results.some((r) => r.metadata.outputCapped),
    coverage: COVERAGE,
  });
}
