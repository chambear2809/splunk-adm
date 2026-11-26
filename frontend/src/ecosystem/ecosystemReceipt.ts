import type { Row } from "../rows";
import {
  evidenceConfigClient,
  type EvidenceConfigClient,
  type SupplementalSourceConfiguration,
} from "../data/evidenceConfig";
import { EVIDENCE_LIMITS, fingerprint } from "../data/evidence";
import {
  FIREWALL_CONTRACTS,
  firewallProjection,
  type FirewallSource,
} from "./firewallTrafficEvidence";
import {
  LOAD_BALANCER_CONTRACTS,
  type LoadBalancerSource,
} from "./loadBalancerEvidence";
import {
  AZURE_RECORD_PROJECTION,
  CLOUD_FLOW_CONTRACTS,
  type CloudFlowSource,
} from "./cloudFlowLogEvidence";
import {
  indexSelector,
  quotedList,
  verifiedAuthorities,
  type SourceIdentity,
} from "./shared";
import { optionalJobs } from "../data/optionalJobs";
import {
  requireNoSearchErrors,
  SearchAccessDeniedError,
  type SearchClient,
} from "../data/searchClient";

export type EcosystemSource =
  FirewallSource | LoadBalancerSource | CloudFlowSource;

/** Ecosystem sources whose receipt and field quality can be checked on demand. */
export const ECOSYSTEM_RECEIPT_SOURCES: readonly EcosystemSource[] = [
  "pan_traffic",
  "fortigate_traffic",
  "f5_ltm_http",
  "aws_elb_access",
  "azure_vnet_flow",
  "gcp_vpc_flow",
];
export const RECEIPT_LOOKBACK_SECONDS = 604800;
const RECEIPT_INPUT_LIMIT = EVIDENCE_LIMITS.input;

const ACTION_VALUES: Record<FirewallSource, readonly string[]> = {
  pan_traffic: [
    "allow",
    "deny",
    "drop",
    "reset-both",
    "reset-client",
    "reset-server",
  ],
  fortigate_traffic: [
    "accept",
    "close",
    "timeout",
    "deny",
    "start",
    "client-rst",
    "server-rst",
    "ip-conn",
    "dns",
  ],
};

interface ReceiptContract extends SourceIdentity {
  /** Same extraction the scoped investigation uses, without address filters. */
  projection: readonly string[];
  /** SPL predicate for an event the adapter can read. */
  valid: string;
}

export function receiptContract(source: EcosystemSource): ReceiptContract {
  if (source === "pan_traffic" || source === "fortigate_traffic") {
    const contract = FIREWALL_CONTRACTS[source];
    return {
      ...contract,
      projection: firewallProjection(contract),
      valid:
        contract.required
          .map((column) => "isnotnull(" + column + ")")
          .join(" AND ") +
        " AND in(fw_action," +
        quotedList(ACTION_VALUES[source]) +
        ")",
    };
  }
  if (source === "f5_ltm_http" || source === "aws_elb_access") {
    const contract = LOAD_BALANCER_CONTRACTS[source];
    return { ...contract, valid: contract.parseOk };
  }
  if (source === "azure_vnet_flow")
    return {
      ...CLOUD_FLOW_CONTRACTS[source],
      projection: AZURE_RECORD_PROJECTION,
      valid:
        'isnotnull(az_shape) AND az_category="FlowLogFlowEvent" AND isnotnull(az_time) AND in(az_version,"4","5") AND az_flows!="-"',
    };
  return { ...CLOUD_FLOW_CONTRACTS[source], valid: "flow_parse_ok=1" };
}

export interface EcosystemReceipt {
  source: EcosystemSource;
  state: "not_selected" | "staged" | "complete" | "unavailable";
  schemaQualified: boolean;
  checkedAt: number;
  probeLookbackSeconds: number;
  records: number;
  /** Events the adapter's extraction can read (required fields, known values). */
  validRecords: number;
  /** Rows whose host has a verified observer mapping. */
  mappedRecords: number;
  hosts: number;
  inputCapped: boolean;
  latestEvent?: number;
  latestIndexed?: number;
  maxIngestLag?: number;
  status:
    | "not_run"
    | "no_visible_records"
    | "quality_gaps"
    | "unmapped_hosts"
    | "stale"
    | "receipt_observed";
  error?: string;
}

/**
 * Seven-day indexed-receipt window, newest 10,001 events. Counts are lower
 * bounds once capped. Field quality uses the same projection as the scoped
 * investigation so the probe measures what the adapter will read.
 */
export function buildEcosystemReceiptSearch(
  source: EcosystemSource,
  config: SupplementalSourceConfiguration,
): string {
  const contract = receiptContract(source);
  if (
    config.source !== source ||
    config.error ||
    (config.state !== "active" && config.state !== "staged")
  )
    throw new Error("Ecosystem source configuration is unavailable.");
  const authorities = verifiedAuthorities(contract, config);
  return [
    "search " +
      indexSelector(config.indexes, true) +
      " sourcetype IN (" +
      quotedList(contract.sourcetypes) +
      ") earliest=0 latest=+10y _index_earliest=-" +
      RECEIPT_LOOKBACK_SECONDS +
      "s _index_latest=now",
    "| head " + (RECEIPT_INPUT_LIMIT + 1),
    ...contract.projection,
    "| eval atlas_valid=if(" +
      contract.valid +
      ",1,0), atlas_mapped=if(in(host," +
      quotedList(authorities) +
      "),1,0), atlas_lag=if(isnotnull(_indextime) AND isnotnull(_time),max(0,_indextime-_time),null())",
    "| stats count AS records sum(atlas_valid) AS valid_records sum(atlas_mapped) AS mapped_records dc(host) AS hosts max(_time) AS latest_event max(_indextime) AS latest_indexed max(atlas_lag) AS max_ingest_lag",
    '| eval kind="ecosystem_receipt", schema_version=1, records=coalesce(records,0), valid_records=coalesce(valid_records,0), mapped_records=coalesce(mapped_records,0), hosts=coalesce(hosts,0), input_capped=if(records>' +
      RECEIPT_INPUT_LIMIT +
      ",1,0), probe_lookback_seconds=" +
      RECEIPT_LOOKBACK_SECONDS,
    "| fields kind schema_version records valid_records mapped_records hosts latest_event latest_indexed max_ingest_lag input_capped probe_lookback_seconds",
  ].join("\n");
}

function count(value: unknown): number {
  const item = Array.isArray(value) && value.length === 1 ? value[0] : value;
  if (
    (typeof item !== "string" && typeof item !== "number") ||
    !/^\d{1,12}$/.test(String(item))
  )
    throw new Error("Invalid receipt count.");
  return Number(item);
}

function optionalEpoch(value: unknown): number | undefined {
  if (value === undefined || value === null || value === "") return undefined;
  if (!/^\d{1,12}(?:\.\d{1,9})?$/.test(String(value)))
    throw new Error("Invalid receipt time.");
  return Number(value);
}

/** Exactly one receipt row; every count must be internally consistent. */
export function parseEcosystemReceipt(
  rows: readonly Row[],
  staleAfterSeconds: number,
  now: number,
): Omit<
  EcosystemReceipt,
  "source" | "state" | "schemaQualified" | "checkedAt"
> {
  if (rows.length !== 1 || rows[0].kind !== "ecosystem_receipt")
    throw new Error("Receipt envelope is missing or duplicated.");
  const row = rows[0];
  if (
    count(row.schema_version) !== 1 ||
    count(row.probe_lookback_seconds) !== RECEIPT_LOOKBACK_SECONDS
  )
    throw new Error("Unsupported receipt schema.");
  const records = count(row.records);
  const validRecords = count(row.valid_records);
  const mappedRecords = count(row.mapped_records);
  const hosts = count(row.hosts);
  const inputCapped = count(row.input_capped) === 1;
  if (
    records > RECEIPT_INPUT_LIMIT + 1 ||
    validRecords > records ||
    mappedRecords > records ||
    hosts > records ||
    inputCapped !== records > RECEIPT_INPUT_LIMIT
  )
    throw new Error("Receipt counts disagree.");
  const latestEvent = optionalEpoch(row.latest_event);
  const latestIndexed = optionalEpoch(row.latest_indexed);
  const maxIngestLag = optionalEpoch(row.max_ingest_lag);
  if (records > 0 && latestIndexed === undefined)
    throw new Error("Receipt time is missing.");
  const status: EcosystemReceipt["status"] =
    records === 0
      ? "no_visible_records"
      : validRecords < records
        ? "quality_gaps"
        : mappedRecords < records
          ? "unmapped_hosts"
          : now - latestIndexed! > staleAfterSeconds
            ? "stale"
            : "receipt_observed";
  return {
    probeLookbackSeconds: RECEIPT_LOOKBACK_SECONDS,
    records,
    validRecords,
    mappedRecords,
    hosts,
    inputCapped,
    ...(latestEvent !== undefined ? { latestEvent } : {}),
    ...(latestIndexed !== undefined ? { latestIndexed } : {}),
    ...(maxIngestLag !== undefined ? { maxIngestLag } : {}),
    status,
  };
}

const EMPTY = {
  probeLookbackSeconds: RECEIPT_LOOKBACK_SECONDS,
  records: 0,
  validRecords: 0,
  mappedRecords: 0,
  hosts: 0,
  inputCapped: false,
  status: "not_run" as const,
};

/** Explicit, caller-permission receipt check; never scheduled or polled. */
export async function checkEcosystemReceipt(
  client: SearchClient,
  source: EcosystemSource,
  signal: AbortSignal,
  configurationClient: EvidenceConfigClient = evidenceConfigClient,
  now: () => number = () => Date.now() / 1000,
): Promise<EcosystemReceipt> {
  const checkedAt = now();
  let config: SupplementalSourceConfiguration | undefined;
  try {
    config = (await configurationClient.read(signal)).supplemental?.find(
      (entry) => entry.source === source,
    );
  } catch {
    config = undefined;
  }
  if (signal.aborted) throw new Error("Receipt check cancelled.");
  if (!config)
    return {
      ...EMPTY,
      source,
      state: "unavailable",
      schemaQualified: false,
      checkedAt,
      error: "Source configuration is unavailable to this caller.",
    };
  const base = {
    ...EMPTY,
    source,
    schemaQualified: config.schemaQualified,
    checkedAt,
  };
  if (config.state === "not_selected")
    return { ...base, state: "not_selected" };
  let search: string;
  try {
    search = buildEcosystemReceiptSearch(source, config);
  } catch {
    return {
      ...base,
      state: "unavailable",
      error:
        "Index selector or verified observer mapping is missing, invalid or conflicting.",
    };
  }
  try {
    const result = requireNoSearchErrors(
      await optionalJobs.run(
        source,
        await fingerprint(["ecosystem_receipt", source, search]),
        client,
        {
          search,
          earliest: "0",
          latest: "now",
          maxRows: 2,
          budget: { serverSeconds: 30, clientMilliseconds: 35000 },
          signal,
        },
      ),
      "Ecosystem receipt",
    );
    if (result.warnings.length)
      throw new Error("Splunk warnings prevent receipt verification.");
    return {
      ...base,
      state: config.state === "staged" ? "staged" : "complete",
      ...parseEcosystemReceipt(result.rows, config.staleAfterSeconds, now()),
    };
  } catch (error) {
    if (signal.aborted)
      throw new Error("Receipt check cancelled.", { cause: error });
    return {
      ...base,
      state: "unavailable",
      error:
        error instanceof SearchAccessDeniedError
          ? "Splunk denied this receipt search for the current user."
          : "Receipt search failed or returned an unverifiable result.",
    };
  }
}
