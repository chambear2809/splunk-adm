import type { ProtocolLensId } from "./contract";

/**
 * Fields that MUST NEVER be projected in any protocol lens SPL `| fields ...`,
 * `| stats ...`, or result table (security & privacy boundary).
 */
export const FORBIDDEN_SENSITIVE_FIELDS = new Set<string>([
  "cookie",
  "form_data",
  "uri_query",
  "sql_statement",
  "bind_variable_value",
  "content",
  "community",
  "value_raw",
  "varbind_list",
  "login",
  "password",
  "passwd",
  "authorization",
  "raw_packet",
  "payload",
  "src_content",
  "dest_content",
  "ssl_session_id",
  "_raw",
]);

/**
 * `query` is safe on DNS (`stream:dns`) where it holds the queried hostname,
 * but FORBIDDEN on SQL lenses (`stream:mysql`, `stream:postgres`, `stream:tds`,
 * `stream:tns`) where it holds SQL statement text.
 */
export const SQL_FORBIDDEN_FIELDS = new Set<string>(["query"]);

/**
 * Identity fields excluded from overview tables and allowed ONLY in explicit
 * single-row expansion details.
 */
export const ROW_EXPANSION_ONLY_FIELDS = new Set<string>([
  "calling_station_id",
  "user_id",
]);

const BASE_FIELDS = ["_time", "host", "sourcetype"] as const;

const SYSLOG_OP_FIELDS = [
  "category",
  "severity_id",
  "mnemonics",
  "dn",
  "descr",
  "syslog_msg",
  "interface",
  "neighbor_ip",
  "vrf",
] as const;

/** Strict per-lens field allowlists grounded in repo TA definitions. */
export const LENS_FIELD_ALLOWLISTS: Record<ProtocolLensId, readonly string[]> =
  {
    tcp_tls: [
      ...BASE_FIELDS,
      "src_ip",
      "dest_ip",
      "src_port",
      "dest_port",
      "transport",
      "client_rtt",
      "server_rtt",
      "initial_rtt",
      "client_rtt_packets",
      "server_rtt_packets",
      "bytes",
      "packets",
      "bytes_in",
      "bytes_out",
      "packets_in",
      "packets_out",
      "duplicate_packets_in",
      "duplicate_packets_out",
      "missing_packets_in",
      "missing_packets_out",
      "canceled",
      "refused",
      "tcp_status",
      "tcp_flags",
      "time_taken",
      "tls_version",
      "ssl_version",
      "ssl_subject",
      "ssl_cert_subject",
      "ssl_validity_end",
      "ssl_cert_not_after",
      "ssl_cert_days_remaining",
      "ssl_cert_self_signed",
      "ssl_validity_window",
      "ssl_end_time",
      "ssl_issuer",
      "ssl_subject_common_name",
      "ssl_error",
      "ssl_cipher_name",
      "ssl_cipher",
      "cipher_suite",
      "ssl_time",
      "sni",
      "vxlan_id",
      "exporter_ip",
    ],
    dns_ops: [
      ...BASE_FIELDS,
      "src_ip",
      "dest_ip",
      "query",
      "query_type",
      "reply_code",
      "reply_code_id",
      "message_type",
      "response_time",
      "time_taken",
      "ttl",
      "answer",
      "answers",
      "host_addr",
      "transaction_id",
      "flow.l7.dns.query",
      "flow.l7.dns.rcode",
      "flow.l7.dns.ips",
      "flow.l7.dns.qtypes",
      "flow.l7.dns.ttl",
    ],
    routing: [
      ...BASE_FIELDS,
      ...SYSLOG_OP_FIELDS,
      "vrf_name",
      "peer_ip",
      "peer_asn",
      "local_asn",
      "state",
      "oper_state",
      "operSt",
      "peer_state",
      "prefixes_received",
      "flap_count",
      "uptime",
      "protocol",
      "area",
      "src_ip",
      "dest_ip",
      "bytes",
      "bytes_in",
      "bytes_out",
      "packets",
      "exporter_ip",
    ],
    l2_control: [
      ...BASE_FIELDS,
      ...SYSLOG_OP_FIELDS,
      "src_ip",
      "dest_ip",
      "src_mac",
      "dest_mac",
      "client_mac",
      "dhcp_message_type",
      "message_type",
      "yiaddr",
      "lease_time",
      "option_53",
      "vlan",
      "vlan_id",
      "stp_root",
      "root_bridge",
      "port_state",
      "port_role",
      "port_channel",
      "member_interface",
      "oper_state",
      "operSt",
      "lacp_state",
      "vni",
    ],
    interface_health: [
      ...BASE_FIELDS,
      ...SYSLOG_OP_FIELDS,
      "interface_name",
      "speed",
      "mtu",
      "admin_state",
      "oper_state",
      "operSt",
      "adminSt",
      "in_octets",
      "out_octets",
      "in_errors",
      "out_errors",
      "in_discards",
      "out_discards",
      "crc_errors",
      "rx_bytes",
      "tx_bytes",
      "rx_drops",
      "tx_drops",
      "utilization_pct",
      "flap_count",
    ],
    qos_icmp: [
      ...BASE_FIELDS,
      "src_ip",
      "dest_ip",
      "src_port",
      "dest_port",
      "transport",
      "protoid",
      "exporter_ip",
      "dscp",
      "tos",
      "ip_dscp",
      "ecn",
      "min_ttl",
      "icmp_type",
      "icmp_code",
      "type",
      "code",
      "bytes",
      "bytes_in",
      "bytes_out",
      "packets",
      "packets_in",
      "packets_out",
      "time_taken",
      "queue",
      "drop_packets",
      "drop_bytes",
      "drop_reason",
      "drop_reason_desc",
      "dropPktCount",
      "dropReasons",
      "srcIp",
      "dstIp",
      "srcPort",
      "dstPort",
      "protocolName",
      "fabricName",
      "nd_host",
      "nodeName",
      "interface",
    ],
    enterprise_l7: [
      ...BASE_FIELDS,
      "src_ip",
      "dest_ip",
      "src_port",
      "dest_port",
      "protocol",
      "status",
      "status_code",
      "nt_status",
      "result_code",
      "response_code",
      "code",
      "message_type",
      "acct_status_type",
      "time_taken",
      "response_time",
      "command",
      "operation",
      "procedure",
      "method",
      "sip_method",
      "dialect",
      "smb_version",
      "nfs_version",
      "auth_type",
      "bind_type",
      "sasl_mechanism",
      "call_id",
      "mos",
      "jitter",
      "packet_loss",
      "packets_lost",
      "packet_loss_pct",
      "packets_in",
      "packets_out",
      "rtp_jitter",
      "rtcp_jitter",
      "codec",
      "nas_ip_address",
      "bytes_in",
      "bytes_out",
    ],
    drops: [
      ...BASE_FIELDS,
      "src_ip",
      "dest_ip",
      "src_port",
      "dest_port",
      "transport",
      "protocol",
      "action",
      "verdict",
      "drop_reason",
      "drop_reason_desc",
      "reason",
      "rule_name",
      "acl_name",
      "policy_name",
      "contract_name",
      "tenant",
      "vrf",
      "vni",
      "packets",
      "bytes",
      "device",
      "node",
      "exporter_ip",
      "dn",
      "descr",
      "InitiatorIP",
      "InitiatorPort",
      "ResponderIP",
      "ResponderPort",
      "Protocol",
      "AC_RuleAction",
      "AccessControlRuleName",
      "Device",
      "DeviceIP",
      "IngressZone",
      "EgressZone",
      "Application",
      "InitiatorBytes",
      "ResponderBytes",
      "InitiatorPackets",
      "ResponderPackets",
      "srcIp",
      "dstIp",
      "srcPort",
      "dstPort",
      "protocolName",
      "dropPktCount",
      "dropReasons",
      "fabricName",
      "nd_host",
      "namespace",
      "pod_name",
      "src_namespace",
      "dest_namespace",
      "src_pod",
      "dest_pod",
    ],
    endpoint_mobility: [
      ...BASE_FIELDS,
      ...SYSLOG_OP_FIELDS,
      "src_ip",
      "dest_ip",
      "src_mac",
      "dest_mac",
      "mac",
      "ip",
      "addr",
      "vlan",
      "vlan_id",
      "vni",
      "encap",
      "arp_opcode",
      "operation",
      "sender_ip",
      "sender_mac",
      "target_ip",
      "target_mac",
      "switch",
      "leaf",
      "nodeName",
      "port",
      "interface_name",
      "displayInterface",
      "endpointId",
      "modType",
      "createTime",
      "anomalyScore",
      "fabricName",
      "nd_host",
      "tenant",
      "displayBd",
      "displayEpg",
      "tDn",
      "modTs",
      "status",
      "lcC",
      "apic_host",
      "device",
      "component",
      "move_count",
    ],
    app_transactions: [
      ...BASE_FIELDS,
      "src_ip",
      "dest_ip",
      "dest_port",
      "protocol",
      "http_method",
      "method",
      "status",
      "status_code",
      "uri_path",
      "site",
      "time_taken",
      "response_time",
      "bytes_in",
      "bytes_out",
      "error_code",
      "db_type",
      "database",
      "rows_returned",
    ],
    state_events: [...BASE_FIELDS, ...SYSLOG_OP_FIELDS, "severity"],
    mgmt_plane: [
      ...BASE_FIELDS,
      ...SYSLOG_OP_FIELDS,
      "src_ip",
      "dest_ip",
      "dest_port",
      "transport",
      "protocol",
      "snmp_version",
      "version",
      "pdu_type",
      "command",
      "status",
      "bytes",
      "packets",
      "exporter_ip",
    ],
    lb_health: [
      ...BASE_FIELDS,
      "vip",
      "virtual_server",
      "pool",
      "pool_name",
      "member_ip",
      "member_port",
      "target_ip",
      "target_port",
      "target_group",
      "src_ip",
      "dest_ip",
      "status",
      "elb_status_code",
      "target_status_code",
      "http_status",
      "target_processing_time",
      "response_time",
      "time_taken",
      "bytes_in",
      "bytes_out",
      "ssl_protocol",
      "tls_version",
    ],
  };

/** Generic aggregated/derived stat field names safe across all lenses. */
const SAFE_DERIVED_FIELDS = new Set<string>([
  "count",
  "events",
  "flows",
  "errors",
  "error_rate",
  "p50",
  "p95",
  "p99",
  "avg_rtt",
  "p95_rtt",
  "max_rtt",
  "retransmits",
  "resets",
  "total_bytes",
  "total_packets",
  "first_seen",
  "last_seen",
  "latest_time",
  "bucket",
]);

export function isFieldAllowedForLens(
  lens: ProtocolLensId,
  field: string,
  options?: { includeRowExpansion?: boolean },
): boolean {
  const normalized = field.trim().toLowerCase();
  if (!normalized) return false;
  if (FORBIDDEN_SENSITIVE_FIELDS.has(normalized)) return false;
  if (lens === "app_transactions" && SQL_FORBIDDEN_FIELDS.has(normalized))
    return false;
  if (ROW_EXPANSION_ONLY_FIELDS.has(normalized))
    return Boolean(options?.includeRowExpansion);
  if (SAFE_DERIVED_FIELDS.has(normalized)) return true;
  return LENS_FIELD_ALLOWLISTS[lens].some(
    (allowed) => allowed.toLowerCase() === normalized,
  );
}

/**
 * Builds a Splunk `| table ...` projection clause after validating every field
 * against both the global sensitive-field denylist and the lens allowlist.
 *
 * Uses `| table` rather than `| fields` so Splunk drops internal fields such as
 * `_raw` server-side before results cross the wire.
 */
export function buildAllowedFieldsClause(
  lens: ProtocolLensId,
  fields: readonly string[],
  options?: { includeRowExpansion?: boolean },
): string {
  if (!fields.length)
    throw new Error(
      `Lens "${lens}" must request at least one allowlisted field.`,
    );
  const validated: string[] = [];
  for (const field of fields) {
    if (!isFieldAllowedForLens(lens, field, options)) {
      throw new Error(
        `Field "${field}" is not allowlisted for protocol lens "${lens}".`,
      );
    }
    validated.push(field.trim());
  }
  return `| table ${validated.join(" ")}`;
}

/**
 * Projects a returned Splunk row strictly to the lens allowlist (plus safe
 * derived stats keys), stripping any unexpected or sensitive fields even if a
 * Splunk knowledge object or search transformation attached them.
 */
export function projectRowToLensAllowlist(
  lens: ProtocolLensId,
  row: Record<string, unknown>,
  options?: { includeRowExpansion?: boolean },
): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(row)) {
    if (isFieldAllowedForLens(lens, key, options)) {
      out[key] = value;
    }
  }
  return out;
}

const WILDCARD_PROJECTION_RE =
  /\|\s*(?:fields|table|rename|foreach|stats)\s+[^|]*\*/i;

/**
 * Defensive runtime guard run by `runBoundedProtocolSearch` before dispatching
 * any SPL string, ensuring no forbidden sensitive field, wildcard projection,
 * or raw payload leaks into any lens search.
 */
export function assertNoForbiddenFieldsInSpl(
  lens: ProtocolLensId,
  spl: string,
): void {
  if (WILDCARD_PROJECTION_RE.test(spl)) {
    throw new Error(
      `Protocol lens "${lens}" SPL must not use wildcard field projections.`,
    );
  }
  // Strip double-quoted values only on the right-hand side of `=` predicates
  // (e.g. host="content-sw01") so quoted field references like `| table "payload"`
  // or `| rename "_raw" AS ssl_subject` remain blocked.
  const withoutRhsLiterals = spl.replace(/=\s*"(?:\\.|[^"\\])*"/g, "=");
  const tokens =
    withoutRhsLiterals.toLowerCase().match(/[a-z_][a-z0-9_]*/g) ?? [];
  for (const token of tokens) {
    if (FORBIDDEN_SENSITIVE_FIELDS.has(token)) {
      throw new Error(
        `Protocol lens "${lens}" SPL references forbidden sensitive field "${token}".`,
      );
    }
    if (lens === "app_transactions" && SQL_FORBIDDEN_FIELDS.has(token)) {
      throw new Error(
        `Protocol lens "${lens}" SPL must not select SQL query text ("${token}").`,
      );
    }
  }
}
