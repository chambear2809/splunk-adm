import type { Row } from "../rows";
import {
  EVIDENCE_LIMITS,
  literal,
  normalizeIp,
  validateSelection,
  type EvidenceSelection,
  type EvidenceWindow,
} from "./evidence";
import {
  evidenceConfigClient,
  type EvidenceConfigClient,
  type SupplementalSourceConfiguration,
} from "./evidenceConfig";
import { indexNames, validateIndexName } from "./deploymentHealth";
import { attributeThousandEyesRecords } from "./thousandEyesAttribution";
import {
  THOUSANDEYES_SOURCE,
  thousandEyesMappings,
  type ThousandEyesSourceMapping,
} from "./thousandEyesConfiguration";
import { normalizeThousandEyesRows } from "./thousandEyesAdapters";
import {
  loadSupplementalEvidence,
  type SupplementalResult,
} from "./supplementalEvidence";
import type {
  ThousandEyesAttributedObservation,
  ThousandEyesEvidenceResult,
  ThousandEyesFamily,
} from "./thousandEyesTypes";
import type { SearchClient } from "./searchClient";

const METRIC_SOURCE = "cisco:thousandeyes:stream";
const WEBHOOK_SOURCE = "cisco:thousandeyes:webhook";
const METRIC_SOURCETYPE = "cisco:thousandeyes:metric";
const TRACE_SOURCETYPE = "cisco:thousandeyes:trace";
const ACTIVITY_SOURCETYPE = "cisco:thousandeyes:activity";
const EVENT_SOURCETYPE = "cisco:thousandeyes:event";
const ALERT_SOURCETYPE = "cisco:thousandeyes:alerts";
const PATH_SOURCETYPE = "cisco:thousandeyes:path-vis";
const ATLAS_PATH_SOURCE = "atlas:thousandeyes:path";
const ATLAS_PATH_SOURCETYPE = "atlas:thousandeyes:path";
const PATH_SCHEMA = "application_atlas.thousandeyes_path.v1";
const MAX_RETENTION_SCAN_SECONDS = 253_402_300_799;
const MAX_STALE_SECONDS = 30 * 24 * 60 * 60;

export const THOUSANDEYES_COVERAGE = [
  "ThousandEyes is an optional, caller-session Splunk source. The six producer families are admitted only from configured indexes, exact source/sourcetype combinations, verified account identities, and the configured v2 or v7 schema. An empty result does not establish source health or coverage.",
  "The Cisco 0.9.0 package sets DATETIME_CONFIG=CURRENT for every supported family. The search therefore scans retained selected indexes through capture time and applies the selected measurement interval to native producer timestamps. Splunk _time is preserved separately as rowTime, not assumed to be receipt time; _indextime is the indexed-receipt basis. Index retention limits history, and the 10,001-row source cap or warnings make the source unavailable.",
  "The source scan is bounded by the existing 30-second server and 35-second client job deadlines, 10,000 eligible input-row cap, 64 displayed-row cap, and one completion row. A guarded native-time coarse filter runs before the input cap with a one-second margin; missing, invalid, or unrecognized timestamps remain eligible candidates for strict normalization. Source caps occur after that selected-window filter, so a dense selected window or many unrecognized-time rows can still make the search unavailable. Late-indexed evidence remains visible when its native measurement time is in the selected window. A displayed-row cap, oversized record, malformed record, duplicate conflict, or rejected row suppresses attribution and comparisons for the returned cohort.",
  "Metrics are accepted only as ThousandEyes OpenTelemetry data model v2 gauge or sum datapoints with documented metric names and source units. Metric values retain their native unit, aggregation, direction, denominator basis, and point or interval timestamp. Unsupported metrics, units, instrument kinds, account IDs, or data-model versions are rejected.",
  "Synthetic traces are accepted only as v2 spans with native test, agent, account, trace/span IDs and nanosecond start/end times. They remain synthetic spans; they do not create production service-call edges, passive traffic, ownership, or traffic counters. API-trace capability remains unqualified because Cisco's official descriptions disagree about API support.",
  "Path rows require native account-group, test, agent and round IDs. Cisco's 0.9.0 CEA path input omits request aid and testId; those anonymous rows cannot be joined by host, name or guessed test. The approved optional v7 CEA path exporter adds its explicitly requested account/test IDs in a versioned wrapper. Missing hops remain unknown and do not independently prove forwarding loss.",
  "Detected-event and alert lifecycles are shown as supplied. Event affected test/agent ID arrays are preserved as context only, and alert account IDs remain separate from organization IDs. Indexed silence, omitted pages and missing history do not establish current alert state, test health, or upstream continuity.",
  "Activity records are account-scoped OpenTelemetry logs. They have no guaranteed test or agent identity and remain context-only; actor names, tags, source hosts and current DNS are never used to invent historical identity.",
  "Authority-qualified native IDs and exact, time-qualified administrator bindings control test/agent attribution. Target hostname and address are preserved only when supplied by the producer; names and tags are labels, and current DNS cannot establish historical ownership. A compatible selected traffic observation does not prove the same route or protocol/port tuple.",
  "Receipt freshness describes only returned selected-evidence receipts. It does not measure index-wide collection, source health, upstream delivery continuity or complete test history. Historical measurements remain eligible for their selected interval even when their Splunk receipt is old.",
] as const;

function checkedIndexes(config: SupplementalSourceConfiguration): string[] {
  if (
    config.source !== THOUSANDEYES_SOURCE ||
    !Array.isArray(config.indexes) ||
    !config.indexes.length ||
    config.indexes.length > 16 ||
    config.indexes.some((index) => validateIndexName(index))
  )
    throw new Error("ThousandEyes index configuration is unavailable.");
  const definition = config.indexes
    .map((index) => `index=${index}`)
    .join(" OR ");
  const indexes = indexNames({
    name: "adm_index_thousandeyes",
    definition: config.indexes.length === 1 ? definition : `(${definition})`,
  });
  if (
    indexes.length !== config.indexes.length ||
    new Set(indexes).size !== indexes.length ||
    indexes.some((index) => !config.indexes.includes(index))
  )
    throw new Error("ThousandEyes index configuration is invalid.");
  return indexes;
}

function checkedMappings(
  config: SupplementalSourceConfiguration,
  selection: EvidenceSelection,
): ThousandEyesSourceMapping[] {
  if (
    config.state !== "active" ||
    config.error ||
    !config.schemaQualified ||
    !Number.isSafeInteger(config.staleAfterSeconds) ||
    config.staleAfterSeconds < 60 ||
    config.staleAfterSeconds > MAX_STALE_SECONDS
  )
    throw new Error("ThousandEyes source is not active and schema-qualified.");
  return thousandEyesMappings(config, selection);
}

function nativeField(name: string, value: string): string {
  return `${name}="${literal(value, 255)}"`;
}

function isoSecondsExpression(field: string): string {
  const utc = `^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`;
  const offset = `^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[+-][0-9]{2}:[0-9]{2}$`;
  return `if(match(${field},"${utc}"),strptime(replace(${field},"Z$","+0000"),"%Y-%m-%dT%H:%M:%S%z"),if(match(${field},"${offset}"),strptime(${field},"%Y-%m-%dT%H:%M:%S%:z"),null()))`;
}

function sourceField(value: string): string {
  return `source="${literal(value, 255)}"`;
}

function sourcetypeField(value: string): string {
  return `sourcetype="${literal(value, 255)}"`;
}

function sameApplication(
  binding: NonNullable<ThousandEyesSourceMapping["bindings"]>[number],
  selection: EvidenceSelection,
): boolean {
  if (!selection.application) return true;
  const application = binding.application;
  return (
    !!application &&
    application.service === selection.application.service &&
    application.environment === selection.application.environment &&
    application.cluster === selection.application.cluster &&
    application.namespace === selection.application.namespace
  );
}

function selectedBindings(
  mapping: ThousandEyesSourceMapping,
  selection: EvidenceSelection,
): ThousandEyesSourceMapping["bindings"] {
  const addresses = selection.identityAddresses ?? selection.addresses;
  if (!Array.isArray(addresses) || !addresses.length || addresses.length > 16)
    return [];
  const normalized = new Set(addresses.map(normalizeIp));
  return mapping.bindings.filter(
    (binding) =>
      binding.scope === selection.scope &&
      binding.validFrom < selection.window.end &&
      binding.validTo > selection.window.start &&
      sameApplication(binding, selection) &&
      binding.endpointAddresses.some((address) =>
        normalized.has(normalizeIp(address)),
      ),
  );
}

function familyClause(
  mapping: ThousandEyesSourceMapping,
  selection: EvidenceSelection,
  family: ThousandEyesFamily,
): string[] {
  if (!mapping.families.includes(family)) return [];
  const accountGroup = mapping.accountGroupId;
  const streamAccount = mapping.streamAccountId;
  switch (family) {
    case "metric":
      if (!streamAccount) return [];
      return [
        `(${sourcetypeField(METRIC_SOURCETYPE)} AND ${sourceField(METRIC_SOURCE)})`,
      ];
    case "trace":
      if (!streamAccount) return [];
      return [
        `(${sourcetypeField(TRACE_SOURCETYPE)} AND ${sourceField(METRIC_SOURCE)})`,
      ];
    case "activity":
      if (!streamAccount) return [];
      return [
        `(${sourcetypeField(ACTIVITY_SOURCETYPE)} AND ${sourceField(METRIC_SOURCE)})`,
      ];
    case "event":
      return [
        `(${sourcetypeField(EVENT_SOURCETYPE)} AND ${nativeField("aid", accountGroup)})`,
      ];
    case "alert":
      if (!mapping.alertAccountId || !mapping.organizationId) return [];
      return [
        `(${sourcetypeField(ALERT_SOURCETYPE)} AND ${sourceField(WEBHOOK_SOURCE)} AND ${nativeField("accountId", mapping.alertAccountId)} AND ${nativeField("orgId", mapping.organizationId)})`,
      ];
    case "path": {
      // thousandEyesMappings already verifies that each exact (index, source)
      // pair is unique and that its index belongs to this source configuration.
      const sources = mapping.pathSources;
      const clauses: string[] = [];
      for (const pathSource of sources) {
        if (pathSource.source === ATLAS_PATH_SOURCE) {
          clauses.push(
            `(index=${pathSource.index} AND ${sourcetypeField(ATLAS_PATH_SOURCETYPE)} AND ${sourceField(ATLAS_PATH_SOURCE)})`,
          );
        } else {
          clauses.push(
            `(index=${pathSource.index} AND ${sourcetypeField(PATH_SOURCETYPE)} AND ${sourceField(pathSource.source)})`,
          );
        }
      }
      return clauses;
    }
  }
}

function multiValueEquals(field: string, value: string): string {
  return `mvcount(mvfilter(${field}="${literal(value, 255)}"))>0`;
}

function nativeIdentityFilter(
  mappings: ThousandEyesSourceMapping[],
  selection: EvidenceSelection,
): string {
  // SPL's multivalue extraction flattens OTLP attributes; this stage is only a
  // bounded candidate filter. The strict JSON adapter checks each key/value
  // pair and account identity before any observation can be used.
  const metricRules: string[] = [];
  const traceRules: string[] = [];
  const activityRules: string[] = [];
  const pathRules: string[] = [];

  for (const mapping of mappings) {
    if (mapping.families.includes("metric") && mapping.streamAccountId) {
      const accountMatch = multiValueEquals(
        "_te_m_values",
        mapping.streamAccountId,
      );
      const bindingMatches = selectedBindings(mapping, selection).map(
        (binding) =>
          `(${multiValueEquals("_te_m_values", binding.testId)} AND ${multiValueEquals("_te_m_values", binding.agentId)})`,
      );
      const bound = bindingMatches.length
        ? `(${bindingMatches.join(" OR ")})`
        : "1=0";
      const bgpContext =
        "(_te_m_has_bgp=1 AND _te_m_has_monitor_key=1 AND mvcount(_te_m_values)>0)";
      metricRules.push(`(${accountMatch} AND (${bound} OR ${bgpContext}))`);
    }
    if (mapping.families.includes("trace") && mapping.streamAccountId) {
      const accountMatch = multiValueEquals(
        "_te_t_values",
        mapping.streamAccountId,
      );
      const bindingMatches = selectedBindings(mapping, selection).map(
        (binding) =>
          `(${multiValueEquals("_te_t_values", binding.testId)} AND ${multiValueEquals("_te_t_values", binding.agentId)})`,
      );
      if (bindingMatches.length)
        traceRules.push(
          `(${accountMatch} AND (${bindingMatches.join(" OR ")}))`,
        );
    }
    if (mapping.families.includes("activity") && mapping.streamAccountId)
      activityRules.push(
        multiValueEquals("_te_a_values", mapping.streamAccountId),
      );

    if (!mapping.families.includes("path")) continue;
    const bindings = selectedBindings(mapping, selection);
    for (const source of mapping.pathSources) {
      for (const binding of bindings) {
        if (source.source === ATLAS_PATH_SOURCE) {
          pathRules.push(
            `(index="${source.index}" AND ${sourceField(source.source)} AND ${sourcetypeField(ATLAS_PATH_SOURCETYPE)} AND _te_p_schema="${PATH_SCHEMA}" AND _te_p_schema_version="1" AND _te_p_wrapper_account="${mapping.accountGroupId}" AND _te_p_wrapper_test="${binding.testId}" AND _te_p_wrapper_domain="cea" AND _te_p_wrapper_agent="${binding.agentId}")`,
          );
        } else {
          pathRules.push(
            `(index="${source.index}" AND ${sourceField(source.source)} AND ${sourcetypeField(PATH_SOURCETYPE)} AND _te_p_vendor_account="${mapping.accountGroupId}" AND _te_p_vendor_test="${binding.testId}" AND _te_p_vendor_agent="${binding.agentId}")`,
          );
        }
      }
    }
  }

  const metricKeep = metricRules.length
    ? `(${metricRules.join(" OR ")})`
    : "1=0";
  const traceKeep = traceRules.length ? `(${traceRules.join(" OR ")})` : "1=0";
  const activityKeep = activityRules.length
    ? `(${activityRules.join(" OR ")})`
    : "1=0";
  const pathKeep = pathRules.length ? `(${pathRules.join(" OR ")})` : "1=0";

  return [
    "| spath input=_raw path=resource_metrics{}.resource.attributes{}.key output=_te_m_keys",
    "| spath input=_raw path=resource_metrics{}.resource.attributes{}.value output=_te_m_attribute_values",
    "| spath input=_raw path=resource_metrics{}.resource.attributes{}.value.string_value output=_te_m_string_values",
    "| spath input=_raw path=resource_metrics{}.resource.attributes{}.value.int_value output=_te_m_int_values",
    "| spath input=_raw path=resource_metrics{}.resource.attributes{}.value.double_value output=_te_m_double_values",
    "| spath input=_raw path=resource_metrics{}.resource.attributes{}.value.bool_value output=_te_m_bool_values",
    "| spath input=_raw path=resource_metrics{}.scope_metrics{}.metrics{}.name output=_te_m_metric_names",
    '| eval _te_m_values=mvappend(_te_m_string_values,_te_m_int_values,_te_m_double_values,_te_m_bool_values),_te_m_has_account_key=if(coalesce(mvcount(mvfilter(_te_m_keys="thousandeyes.account.id")),0)>0,1,0),_te_m_has_test_key=if(coalesce(mvcount(mvfilter(_te_m_keys="thousandeyes.test.id")),0)>0,1,0),_te_m_has_agent_key=if(coalesce(mvcount(mvfilter(_te_m_keys="thousandeyes.source.agent.id")),0)>0,1,0),_te_m_has_monitor_key=if(coalesce(mvcount(mvfilter(_te_m_keys="thousandeyes.monitor.id")),0)+coalesce(mvcount(mvfilter(_te_m_keys="thousandeyes.bgp.monitor.id")),0)>0,1,0),_te_m_has_bgp=if(coalesce(mvcount(mvfilter(like(_te_m_metric_names,"bgp.%"))),0)>0,1,0)',
    "| eval _te_m_identity_unknown=if(isnull(_te_m_keys) OR isnull(_te_m_attribute_values) OR mvcount(_te_m_keys)!=mvcount(_te_m_attribute_values) OR _te_m_has_account_key=0 OR ((_te_m_has_test_key=0 OR _te_m_has_agent_key=0) AND (_te_m_has_bgp=0 OR _te_m_has_monitor_key=0)),1,0)",
    "| eval _te_m_identity_match=if(_te_m_identity_unknown=1 OR " +
      metricKeep +
      ",1,0)",
    "| spath input=_raw path=resource_spans{}.resource.attributes{}.key output=_te_t_keys",
    "| spath input=_raw path=resource_spans{}.resource.attributes{}.value output=_te_t_attribute_values",
    "| spath input=_raw path=resource_spans{}.resource.attributes{}.value.string_value output=_te_t_string_values",
    "| spath input=_raw path=resource_spans{}.resource.attributes{}.value.int_value output=_te_t_int_values",
    "| spath input=_raw path=resource_spans{}.resource.attributes{}.value.double_value output=_te_t_double_values",
    "| spath input=_raw path=resource_spans{}.resource.attributes{}.value.bool_value output=_te_t_bool_values",
    '| eval _te_t_values=mvappend(_te_t_string_values,_te_t_int_values,_te_t_double_values,_te_t_bool_values),_te_t_has_account_key=if(mvcount(mvfilter(_te_t_keys="thousandeyes.account.id"))>0,1,0),_te_t_has_test_key=if(mvcount(mvfilter(_te_t_keys="thousandeyes.test.id"))>0,1,0),_te_t_has_agent_key=if(mvcount(mvfilter(_te_t_keys="thousandeyes.source.agent.id"))>0,1,0)',
    "| eval _te_t_identity_unknown=if(isnull(_te_t_keys) OR isnull(_te_t_attribute_values) OR mvcount(_te_t_keys)!=mvcount(_te_t_attribute_values) OR _te_t_has_account_key=0 OR _te_t_has_test_key=0 OR _te_t_has_agent_key=0,1,0)",
    "| eval _te_t_identity_match=if(_te_t_identity_unknown=1 OR " +
      traceKeep +
      ",1,0)",
    "| spath input=_raw path=resource_logs{}.resource.attributes{}.key output=_te_a_keys",
    "| spath input=_raw path=resource_logs{}.resource.attributes{}.value output=_te_a_attribute_values",
    "| spath input=_raw path=resource_logs{}.resource.attributes{}.value.string_value output=_te_a_string_values",
    "| spath input=_raw path=resource_logs{}.resource.attributes{}.value.int_value output=_te_a_int_values",
    "| spath input=_raw path=resource_logs{}.resource.attributes{}.value.double_value output=_te_a_double_values",
    "| spath input=_raw path=resource_logs{}.resource.attributes{}.value.bool_value output=_te_a_bool_values",
    '| eval _te_a_values=mvappend(_te_a_string_values,_te_a_int_values,_te_a_double_values,_te_a_bool_values),_te_a_has_account_key=if(mvcount(mvfilter(_te_a_keys="thousandeyes.account.id"))>0,1,0)',
    "| eval _te_a_identity_unknown=if(isnull(_te_a_keys) OR isnull(_te_a_attribute_values) OR mvcount(_te_a_keys)!=mvcount(_te_a_attribute_values) OR _te_a_has_account_key=0,1,0)",
    "| eval _te_a_identity_match=if(_te_a_identity_unknown=1 OR " +
      activityKeep +
      ",1,0)",
    "| spath input=_raw path=schema output=_te_p_schema",
    "| spath input=_raw path=schema_version output=_te_p_schema_version",
    "| spath input=_raw path=account_group_id output=_te_p_wrapper_account",
    "| spath input=_raw path=test_id output=_te_p_wrapper_test",
    "| spath input=_raw path=test_domain output=_te_p_wrapper_domain",
    "| spath input=_raw path=result.agent.agentId output=_te_p_wrapper_agent",
    "| spath input=_raw path=aid output=_te_p_vendor_account",
    "| spath input=_raw path=testId output=_te_p_vendor_test",
    "| spath input=_raw path=agentId output=_te_p_vendor_agent_top",
    "| spath input=_raw path=agent.agentId output=_te_p_vendor_agent_nested",
    '| eval _te_p_vendor_agent=coalesce(_te_p_vendor_agent_top,_te_p_vendor_agent_nested),_te_p_is_wrapper=if(_te_p_schema="' +
      PATH_SCHEMA +
      '" AND _te_p_schema_version="1",1,0)',
    '| eval _te_p_identity_unknown=if((_te_p_is_wrapper=1 AND (isnull(_te_p_wrapper_account) OR isnull(_te_p_wrapper_test) OR isnull(_te_p_wrapper_domain) OR _te_p_wrapper_domain!="cea" OR isnull(_te_p_wrapper_agent))) OR (_te_p_is_wrapper=0 AND (isnull(_te_p_vendor_account) OR isnull(_te_p_vendor_test) OR isnull(_te_p_vendor_agent))),1,0)',
    "| eval _te_p_identity_match=if(_te_p_identity_unknown=1 OR " +
      pathKeep +
      ",1,0)",
    '| where case(sourcetype="' +
      METRIC_SOURCETYPE +
      '",_te_m_identity_match=1,sourcetype="' +
      TRACE_SOURCETYPE +
      '",_te_t_identity_match=1,sourcetype="' +
      ACTIVITY_SOURCETYPE +
      '",_te_a_identity_match=1,sourcetype="' +
      PATH_SOURCETYPE +
      '",_te_p_identity_match=1,sourcetype="' +
      ATLAS_PATH_SOURCETYPE +
      '",_te_p_identity_match=1,1=1,1=1)',
  ].join("\n");
}

/**
 * Coarsely filter by native time before the retained-index row cap. Missing,
 * malformed, or unknown timestamps remain eligible for strict normalization.
 */
function nativeWindowFilter(selection: EvidenceSelection): string {
  const start = Math.max(0, selection.window.start - 1);
  const end = Math.min(MAX_RETENTION_SCAN_SECONDS, selection.window.end + 1);
  return [
    "| spath input=_raw path=resource_metrics{}.scope_metrics{}.metrics{}.gauge.data_points{}.time_unix_nano output=_te_m_gauge_end",
    "| spath input=_raw path=resource_metrics{}.scope_metrics{}.metrics{}.sum.data_points{}.time_unix_nano output=_te_m_sum_end",
    "| spath input=_raw path=resource_metrics{}.scope_metrics{}.metrics{}.gauge.data_points{}.start_time_unix_nano output=_te_m_gauge_start",
    "| spath input=_raw path=resource_metrics{}.scope_metrics{}.metrics{}.sum.data_points{}.start_time_unix_nano output=_te_m_sum_start",
    "| spath input=_raw path=resource_spans{}.scope_spans{}.spans{}.start_time_unix_nano output=_te_t_start",
    "| spath input=_raw path=resource_spans{}.scope_spans{}.spans{}.end_time_unix_nano output=_te_t_end",
    "| spath input=_raw path=resource_logs{}.scope_logs{}.log_records{}.time_unix_nano output=_te_a_ns",
    "| spath input=_raw path=resource_logs{}.scope_logs{}.log_records{}.Timestamp output=_te_a_iso",
    "| spath input=_raw path=startDate output=_te_e_start",
    "| spath input=_raw path=endDate output=_te_e_end",
    "| spath input=_raw path=alert.triggered.epochMilli output=_te_l_trigger",
    "| spath input=_raw path=alert.firstSeen.epochMilli output=_te_l_first",
    "| spath input=_raw path=alert.cleared.epochMilli output=_te_l_clear",
    "| spath input=_raw path=alert.timeCleared.epochMilli output=_te_l_end",
    "| spath input=_raw path=result.date output=_te_p_result_date",
    "| spath input=_raw path=date output=_te_p_date",
    "| spath input=_raw path=result.startTime output=_te_p_result_start",
    "| spath input=_raw path=startTime output=_te_p_start",
    "| spath input=_raw path=result.endTime output=_te_p_result_end",
    "| spath input=_raw path=endTime output=_te_p_end",
    "| spath input=_raw path=result.roundId output=_te_p_result_round",
    "| spath input=_raw path=roundId output=_te_p_round",
    "| eval _te_m_end=mvappend(_te_m_gauge_end,_te_m_sum_end),_te_m_start=mvappend(_te_m_gauge_start,_te_m_sum_start),_te_m_end_s=mvmap(_te_m_end,tonumber(_te_m_end)/1000000000),_te_m_start_s=mvmap(_te_m_start,tonumber(_te_m_start)/1000000000)",
    "| eval _te_m_unknown=if(isnull(_te_m_end) OR mvcount(_te_m_end_s)<mvcount(_te_m_end) OR (mvcount(_te_m_start)>0 AND mvcount(_te_m_start)!=mvcount(_te_m_end)),1,0),_te_m_first=coalesce(min(_te_m_start_s),min(_te_m_end_s)),_te_m_last=max(_te_m_end_s)",
    "| eval _te_t_start_s=mvmap(_te_t_start,tonumber(_te_t_start)/1000000000),_te_t_end_s=mvmap(_te_t_end,tonumber(_te_t_end)/1000000000)",
    "| eval _te_t_unknown=if(isnull(_te_t_start) OR isnull(_te_t_end) OR mvcount(_te_t_start_s)<mvcount(_te_t_start) OR mvcount(_te_t_end_s)<mvcount(_te_t_end) OR mvcount(_te_t_start)!=mvcount(_te_t_end),1,0),_te_t_first=min(_te_t_start_s),_te_t_last=max(_te_t_end_s)",
    `| eval _te_a_raw=mvappend(_te_a_ns,_te_a_iso),_te_a_s=mvmap(_te_a_raw,if(match(_te_a_raw,"^[0-9]{4}-[0-9]{2}-[0-9]{2}T"),${isoSecondsExpression("_te_a_raw")},tonumber(_te_a_raw)/1000000000))`,
    "| eval _te_a_unknown=if(isnull(_te_a_raw) OR mvcount(_te_a_s)<mvcount(_te_a_raw),1,0),_te_a_first=min(_te_a_s),_te_a_last=max(_te_a_s)",
    `| eval _te_e_start_s=${isoSecondsExpression("_te_e_start")},_te_e_end_s=${isoSecondsExpression("_te_e_end")}`,
    "| eval _te_e_unknown=if(isnull(_te_e_start_s) OR (isnotnull(_te_e_end) AND isnull(_te_e_end_s)),1,0)",
    "| eval _te_l_start=mvappend(_te_l_trigger,_te_l_first),_te_l_end_all=mvappend(_te_l_clear,_te_l_end),_te_l_start_s=mvmap(_te_l_start,tonumber(_te_l_start)/1000),_te_l_end_s=mvmap(_te_l_end_all,tonumber(_te_l_end_all)/1000)",
    "| eval _te_l_unknown=if(isnull(_te_l_start) OR mvcount(_te_l_start_s)<mvcount(_te_l_start) OR (mvcount(_te_l_end_all)>0 AND mvcount(_te_l_end_s)<mvcount(_te_l_end_all)),1,0),_te_l_first=min(_te_l_start_s),_te_l_last=coalesce(max(_te_l_end_s),max(_te_l_start_s))",
    `| eval _te_p_iso=mvappend(_te_p_result_date,_te_p_date),_te_p_iso_s=mvmap(_te_p_iso,${isoSecondsExpression("_te_p_iso")}),_te_p_start_raw=mvappend(_te_p_result_start,_te_p_start),_te_p_end_raw=mvappend(_te_p_result_end,_te_p_end),_te_p_round_raw=mvappend(_te_p_result_round,_te_p_round),_te_p_start_s=mvmap(_te_p_start_raw,tonumber(_te_p_start_raw)),_te_p_end_s=mvmap(_te_p_end_raw,tonumber(_te_p_end_raw)),_te_p_round_s=mvmap(_te_p_round_raw,tonumber(_te_p_round_raw))`,
    "| eval _te_p_first=coalesce(min(_te_p_start_s),min(_te_p_iso_s),min(_te_p_round_s)),_te_p_last=coalesce(max(_te_p_end_s),max(_te_p_iso_s),max(_te_p_round_s)),_te_p_unknown=if((isnull(_te_p_first) AND isnull(_te_p_last)) OR (mvcount(_te_p_start_raw)>0 AND mvcount(_te_p_start_s)<mvcount(_te_p_start_raw)) OR (mvcount(_te_p_end_raw)>0 AND mvcount(_te_p_end_s)<mvcount(_te_p_end_raw)),1,0)",
    '| where case(sourcetype="' +
      METRIC_SOURCETYPE +
      '",_te_m_unknown=1 OR (_te_m_first<=' +
      end +
      " AND _te_m_last>=" +
      start +
      '),sourcetype="' +
      TRACE_SOURCETYPE +
      '",_te_t_unknown=1 OR (_te_t_first<=' +
      end +
      " AND _te_t_last>=" +
      start +
      '),sourcetype="' +
      ACTIVITY_SOURCETYPE +
      '",_te_a_unknown=1 OR (_te_a_first<=' +
      end +
      " AND _te_a_last>=" +
      start +
      '),sourcetype="' +
      EVENT_SOURCETYPE +
      '",_te_e_unknown=1 OR (_te_e_start_s<=' +
      end +
      " AND (isnull(_te_e_end_s) OR _te_e_end_s>=" +
      start +
      ')),sourcetype="' +
      ALERT_SOURCETYPE +
      '",_te_l_unknown=1 OR (_te_l_first<=' +
      end +
      " AND _te_l_last>=" +
      start +
      '),sourcetype="' +
      PATH_SOURCETYPE +
      '",_te_p_unknown=1 OR (_te_p_first<=' +
      end +
      " AND _te_p_last>=" +
      start +
      '),sourcetype="' +
      ATLAS_PATH_SOURCETYPE +
      '",_te_p_unknown=1 OR (_te_p_first<=' +
      end +
      " AND _te_p_last>=" +
      start +
      "),1=1,1=1)",
  ].join("\n");
}

/** Literal, selected-source search over retained receipt time; native timestamps filter the window later. */
export function buildThousandEyesSearch(
  config: SupplementalSourceConfiguration,
  input: EvidenceSelection,
): string {
  const selection = validateSelection(input);
  const indexes = checkedIndexes(config);
  const mappings = checkedMappings(config, selection);
  const clauses = mappings.flatMap((mapping) =>
    (
      ["metric", "path", "trace", "event", "alert", "activity"] as const
    ).flatMap((family) => familyClause(mapping, selection, family)),
  );
  if (!clauses.length)
    throw new Error(
      "No selected native ThousandEyes identities or account context are configured.",
    );
  const indexSelector = indexes.map((index) => `index=${index}`).join(" OR ");
  return `search (${indexSelector}) (${clauses.join(" OR ")})
${nativeWindowFilter(selection)}
${nativeIdentityFilter(mappings, selection)}
| head ${EVIDENCE_LIMITS.input + 1}
| eval source_scan_row_invalid=if(isnull(index) OR isnull(source) OR isnull(sourcetype) OR len(coalesce(_raw,""))=0,1,0)
| eventstats count AS source_scan_count sum(source_scan_row_invalid) AS source_scan_invalid_count
| eval source_scan_capped=if(source_scan_count>${EVIDENCE_LIMITS.input},1,0),oversized=if(len(_raw)>${EVIDENCE_LIMITS.recordBytes},1,0),event_fingerprint=sha256(json_array(index,source,sourcetype,_raw)),row_time_epoch=tonumber(_time),indexed_time_epoch=tonumber(_indextime)
| eval _raw=if(oversized=1,"{}",_raw)
| eventstats count AS input_count sum(oversized) AS oversized_count
| eval kind="supplemental_record",input_capped=if(input_count>${EVIDENCE_LIMITS.input},1,0),record_truncated=if(input_count>${EVIDENCE_LIMITS.records},1,0)
| sort 0 - indexed_time_epoch event_fingerprint
| head ${EVIDENCE_LIMITS.records}
| fields kind _raw index source sourcetype event_fingerprint row_time_epoch indexed_time_epoch input_count input_capped source_scan_count source_scan_capped source_scan_invalid_count oversized record_truncated
| appendpipe [| stats count AS returned_count max(input_count) AS input_count max(input_capped) AS input_capped max(source_scan_count) AS source_scan_count max(source_scan_capped) AS source_scan_capped max(source_scan_invalid_count) AS source_scan_invalid_count sum(oversized) AS oversized | eval kind="supplemental_completion",schema_version=1,input_count=coalesce(input_count,0),returned_count=coalesce(returned_count,0),input_capped=coalesce(input_capped,0),source_scan_count=coalesce(source_scan_count,0),source_scan_capped=coalesce(source_scan_capped,0),source_scan_invalid_count=coalesce(source_scan_invalid_count,0),oversized=coalesce(oversized,0)]`;
}

function searchWindow(
  selection: EvidenceSelection,
  source: SupplementalSourceConfiguration,
): EvidenceWindow {
  validateSelection(selection);
  if (
    !Number.isSafeInteger(source.staleAfterSeconds) ||
    source.staleAfterSeconds < 60 ||
    source.staleAfterSeconds > MAX_STALE_SECONDS
  )
    throw new Error("ThousandEyes receipt freshness setting is invalid.");
  const end = Math.min(
    MAX_RETENTION_SCAN_SECONDS,
    Math.floor(Date.now() / 1000),
  );
  return { start: 0, end: Math.max(1, end) };
}

export function normalizeThousandEyesEvidence(
  rows: readonly Row[],
  input: EvidenceSelection,
  config: SupplementalSourceConfiguration,
): { records: ThousandEyesAttributedObservation[]; rejected: number } {
  const selection = validateSelection(input);
  const normalized = normalizeThousandEyesRows(rows, selection, config);
  const mappings = thousandEyesMappings(config, selection);
  const bindings = mappings.flatMap((mapping) => mapping.bindings);
  return {
    records: attributeThousandEyesRecords(
      normalized.records,
      selection,
      bindings,
    ),
    rejected: normalized.rejected,
  };
}

function suppressSourceAttribution<T extends ThousandEyesAttributedObservation>(
  result: SupplementalResult<T>,
): SupplementalResult<T> {
  const reasons: string[] = [];
  if (result.inputCapped || result.outputCapped)
    reasons.push("the source result was capped");
  if (result.oversized > 0) reasons.push("oversized source rows were omitted");
  if (result.rejected > 0)
    reasons.push("one or more selected source rows were rejected");
  if (!result.schemaQualified)
    reasons.push("the source schema is not qualified");
  if (result.configurationChanged)
    reasons.push("configuration changed during the search");
  if (!reasons.length) return result;
  return {
    ...result,
    records: result.records.map((record) => ({
      ...record,
      attribution: {
        state: "context_only",
        bindingIds: [],
        reason: `Source-wide uncertainty suppresses binding and comparison: ${reasons.join(", ")}. The returned row remains visible as context only.`,
        observedDependency: false,
      },
      limitations: [
        ...record.limitations,
        `Source-wide uncertainty suppresses binding and comparison because ${reasons.join(", ")}.`,
      ],
    })),
  };
}

function receiptFreshness(
  result: SupplementalResult<ThousandEyesAttributedObservation>,
  selection: EvidenceSelection,
  staleAfterSeconds: number | undefined,
): ThousandEyesEvidenceResult["receiptFreshness"] {
  const assessedAt = Math.floor(Date.now() / 1000);
  const latestIndexedTime = result.records.length
    ? Math.max(...result.records.map((record) => record.indexedTime))
    : undefined;
  const unknown =
    result.state !== "complete" ||
    result.configurationChanged ||
    result.inputCapped ||
    result.outputCapped ||
    result.sourceScanCapped === true ||
    result.oversized > 0 ||
    result.rejected > 0 ||
    latestIndexedTime === undefined ||
    staleAfterSeconds === undefined;
  if (unknown) {
    return {
      state: "unknown",
      basis: "selected_evidence_indexed_receipt",
      ...(latestIndexedTime !== undefined ? { latestIndexedTime } : {}),
      assessedAt,
    };
  }
  if (selection.window.end < assessedAt - staleAfterSeconds) {
    return {
      state: "historical",
      basis: "selected_evidence_indexed_receipt",
      latestIndexedTime,
      assessedAt,
    };
  }
  return {
    state:
      assessedAt - latestIndexedTime > staleAfterSeconds
        ? "stale"
        : "observed_receipt",
    basis: "selected_evidence_indexed_receipt",
    latestIndexedTime,
    assessedAt,
  };
}

export async function loadThousandEyesEvidence(
  client: SearchClient,
  selection: EvidenceSelection,
  signal: AbortSignal,
  configurationClient: EvidenceConfigClient = evidenceConfigClient,
): Promise<ThousandEyesEvidenceResult> {
  const validated = validateSelection(selection);
  let staleAfterSeconds: number | undefined;
  const trackingConfigurationClient: EvidenceConfigClient = {
    read: async (readSignal, addresses, scope) => {
      const configuration = await configurationClient.read(
        readSignal,
        addresses,
        scope,
      );
      if (staleAfterSeconds === undefined) {
        staleAfterSeconds = configuration.supplemental?.find(
          (source) => source.source === THOUSANDEYES_SOURCE,
        )?.staleAfterSeconds;
      }
      return configuration;
    },
  };
  const loaded = await loadSupplementalEvidence(
    client,
    validated,
    signal,
    THOUSANDEYES_SOURCE,
    buildThousandEyesSearch,
    normalizeThousandEyesEvidence,
    trackingConfigurationClient,
    false,
    searchWindow,
    THOUSANDEYES_COVERAGE,
  );
  const safe = suppressSourceAttribution(loaded);
  return {
    ...safe,
    receiptFreshness: receiptFreshness(safe, validated, staleAfterSeconds),
  };
}
