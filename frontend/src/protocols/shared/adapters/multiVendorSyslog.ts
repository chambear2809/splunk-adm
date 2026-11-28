import { literal } from "../../../data/evidence";
import type { ProtocolRow } from "../runner";
import {
  ALLOWED_SYSLOG_SOURCETYPES,
  CONFIG_CHANGE_MNEMONICS,
  buildSyslogStateSearch,
  classifySyslogDomain,
  normalizeSyslogRow,
  type AllowedSyslogSourcetype,
  type NormalizedStateEvent,
  type SyslogOperationalDomain,
} from "./nxosSyslog";

/**
 * Multi-vendor SC4S operational syslog sourcetypes.
 * Note: `juniper:junos:firewall` (SRX RT_FLOW session logs) belongs in the
 * Juniper flow adapter / Drops lens, never in operational state syslog.
 */
export const MULTI_VENDOR_SC4S_SOURCETYPES = [
  ...ALLOWED_SYSLOG_SOURCETYPES,
  "arista:eos",
  "juniper:junos:structured",
  "pan:system",
  "fortigate_event",
  "fgt_event",
  "f5:bigip:syslog",
  "cisco:asa",
  "cisco:ftd",
  "cisco:ftd:syslog",
] as const;

export type MultiVendorSyslogSourcetype =
  (typeof MULTI_VENDOR_SC4S_SOURCETYPES)[number];

/**
 * Explicit 6-digit operational message IDs for Cisco ASA / FTD syslog.
 * Never use a broad `713*` prefix because remote-access VPN messages such as
 * `%ASA-6-713228` carry `Username = ...` and client public IPs.
 */
export const ASA_OPERATIONAL_IDS = [
  "104001", // Switching to Active
  "104002", // Switching to Standby
  "104003", // Switching to Failed
  "104004", // Switching to OK
  "105003", // Failover monitoring on interface waiting
  "105004", // Failover monitoring on interface normal
  "105005", // Lost Failover communications with mate
  "105008", // Testing interface
  "105009", // Testing on interface passed/failed
  "318001", // OSPF internal error
  "318002", // OSPF adjacency state change
  "318003", // OSPF neighbor state change
  "411001", // Line protocol on interface changed state to up
  "411002", // Line protocol on interface changed state to down
  "411003", // Configuration status on interface changed
  "411004", // Configuration status on interface changed
  "713049", // LAN-to-LAN Security negotiation complete
  "713050", // LAN-to-LAN Connection terminated for peer
  "713120", // LAN-to-LAN PHASE 2 COMPLETED
] as const;

/**
 * Explicit operational `logid` prefixes for Fortinet FortiGate event logs.
 * Prevents `subtype="system"` admin logins and `subtype="vpn"` SSL-VPN user
 * login messages (which carry usernames in `msg`) from ever being projected.
 */
export const FORTIGATE_OPERATIONAL_LOGID_PREFIXES = [
  "01000200", // Interface link status
  "01000203", // BGP / OSPF / routing daemon state
  "01000370", // HA cluster failover / member state
  "01010371", // IPsec phase-1 / phase-2 tunnel up/down
  "01130229", // SD-WAN SLA health-check state change
] as const;

/**
 * Explicit operational categories for Arista EOS syslog.
 * Using an allowlist guarantees `%SYS-5-CONFIG_E` (which carries admin
 * usernames and source IPs), `CONFIG_STARTUP`, `AAA`, `CLI`, and `SECURITY`
 * messages can never leak into operational timelines.
 */
export const ARISTA_OPERATIONAL_CATEGORIES = [
  "LINEPROTO",
  "ETH",
  "ETHPORT",
  "BGP",
  "OSPF",
  "OSPFV3",
  "ISIS",
  "BFD",
  "MLAG",
  "LACP",
  "STP",
  "MSTP",
  "SPANTREE",
  "TRANSCEIVER",
  "DOM",
  "PIM",
  "IGMP",
  "HSRP",
  "VRRP",
] as const;

/**
 * Explicit operational F5 BIG-IP `mcpd`/`sod`/`tmm` message codes.
 * Strictly excludes `01220002` (iRule `log local0.` free-form text) and
 * `01070417` (`AUDIT - user admin`) messages.
 */
export const F5_OPERATIONAL_CODES = [
  "01070638", // Pool member monitor status down
  "01070727", // Pool member monitor status up
  "01070640", // Node monitor status down
  "01070728", // Node monitor status up
  "01071681", // Pool availability changed
  "01071682", // Pool member session status changed
  "010c0018", // HA standby -> active
  "010c0019", // HA active -> standby
  "010c0052", // HA failover state transition
  "010c0053", // HA device group state transition
  "010c0054", // HA traffic group state transition
  "01010029", // SNAT / ephemeral port exhaustion
] as const;

const JUNIPER_OPERATIONAL_DAEMONS = [
  "rpd",
  "chassisd",
  "l2ald",
  "mib2d",
  "bfdd",
] as const;

/**
 * Strictly operational PAN-OS system subtypes.
 * `general` is intentionally excluded because PAN-OS logs admin logins and
 * config commits naming the user under `subtype=general`.
 */
const PAN_OPERATIONAL_SUBTYPES = ["routing", "ha", "vpn"] as const;

const ASA_ID_SET = new Set<string>(ASA_OPERATIONAL_IDS);
const ARISTA_CAT_SET = new Set<string>(ARISTA_OPERATIONAL_CATEGORIES);
const F5_CODE_SET = new Set<string>(F5_OPERATIONAL_CODES);
const CONFIG_SET = new Set<string>(CONFIG_CHANGE_MNEMONICS);
const JUNIPER_DAEMON_SET = new Set<string>(JUNIPER_OPERATIONAL_DAEMONS);
const PAN_SUBTYPE_SET = new Set<string>(PAN_OPERATIONAL_SUBTYPES);

function asString(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

function asEpoch(value: unknown): number | undefined {
  if (typeof value === "number" && Number.isFinite(value) && value > 0)
    return value;
  if (typeof value === "string" && value.trim()) {
    const numeric = Number(value);
    if (Number.isFinite(numeric) && numeric > 0) return numeric;
    const parsed = Date.parse(value);
    if (Number.isFinite(parsed) && parsed > 0) return Math.floor(parsed / 1000);
  }
  return undefined;
}

function hostClauseFor(device?: string): string {
  return device ? ` host="${literal(device, 128)}"` : "";
}

export function buildAristaEosSyslogSearch(options: {
  index: string;
  device?: string;
  maxRows: number;
}): string {
  const idx = literal(options.index, 80);
  const allowedCats = ARISTA_OPERATIONAL_CATEGORIES.map((c) => `"${c}"`).join(
    ", ",
  );
  return (
    `search index=${idx} sourcetype="arista:eos"${hostClauseFor(options.device)} ` +
    `| rex "%(?<sc4s_cat>[A-Za-z0-9_]+)-(?<sc4s_sev>[0-7])-(?<sc4s_mnem>[A-Za-z0-9_]+):\\s*(?<sc4s_msg>.+)" ` +
    `| eval category=upper(coalesce(category, sc4s_cat)), severity_id=coalesce(severity_id, sc4s_sev), mnemonics=coalesce(mnemonics, sc4s_mnem), syslog_msg=coalesce(syslog_msg, sc4s_msg) ` +
    `| where isnotnull(mnemonics) AND category IN (${allowedCats}) AND NOT like(upper(mnemonics), "CONFIG_%") ` +
    `| head ${options.maxRows + 1} ` +
    `| table _time host sourcetype category severity_id mnemonics syslog_msg interface neighbor_ip vrf`
  );
}

export function buildCiscoAsaFtdSyslogSearch(options: {
  index: string;
  sourcetypes?: readonly ("cisco:asa" | "cisco:ftd" | "cisco:ftd:syslog")[];
  device?: string;
  maxRows: number;
}): string {
  const idx = literal(options.index, 80);
  const sts = options.sourcetypes?.length
    ? options.sourcetypes
    : (["cisco:asa", "cisco:ftd", "cisco:ftd:syslog"] as const);
  const stClause =
    sts.length === 1
      ? `sourcetype="${sts[0]}"`
      : `(${sts.map((s) => `sourcetype="${s}"`).join(" OR ")})`;
  const idList = ASA_OPERATIONAL_IDS.map((id) => `"${id}"`).join(", ");
  return (
    `search index=${idx} ${stClause}${hostClauseFor(options.device)} ` +
    `| rex "%(?:ASA|FTD)-(?<sc4s_sev>[0-7])-(?<asa_id>\\d{6}):\\s*(?<sc4s_msg>.+)" ` +
    `| where isnotnull(asa_id) AND asa_id IN (${idList}) AND NOT match(sc4s_msg, "(?i)Username\\s*=") ` +
    `| eval category="ASA_OP", severity_id=coalesce(severity_id, sc4s_sev), mnemonics=asa_id, syslog_msg=coalesce(syslog_msg, sc4s_msg) ` +
    `| head ${options.maxRows + 1} ` +
    `| table _time host sourcetype category severity_id mnemonics syslog_msg interface neighbor_ip vrf`
  );
}

export function buildJuniperJunosSyslogSearch(options: {
  index: string;
  device?: string;
  maxRows: number;
}): string {
  const idx = literal(options.index, 80);
  const daemonList = JUNIPER_OPERATIONAL_DAEMONS.map((d) => `"${d}"`).join(
    ", ",
  );
  // Matches both RFC5424 structured (`rpd 1234 BGP_... [junos@2636 ...] msg`)
  // and legacy BSD (`rpd[1234]: RPD_BGP_...: msg`) formats.
  return (
    `search index=${idx} sourcetype="juniper:junos:structured"${hostClauseFor(options.device)} ` +
    `| rex "(?:^|\\s)(?<junos_daemon>rpd|chassisd|l2ald|mib2d|bfdd)(?:(?:\\[\\d+\\])?:\\s*(?<junos_bsd_tag>[A-Z0-9_]+):\\s*(?<junos_bsd_msg>.+)|\\s+(?:\\d+|-)\\s+(?<junos_5424_tag>[A-Z0-9_]+)\\s+(?:\\[[^\\]]*\\]\\s*)?(?<junos_5424_msg>.+))" ` +
    `| eval category=lower(coalesce(category, junos_daemon)), mnemonics=coalesce(mnemonics, junos_5424_tag, junos_bsd_tag), syslog_msg=coalesce(syslog_msg, junos_5424_msg, junos_bsd_msg) ` +
    `| where isnotnull(mnemonics) AND category IN (${daemonList}) ` +
    `| head ${options.maxRows + 1} ` +
    `| table _time host sourcetype category severity_id mnemonics syslog_msg interface neighbor_ip vrf`
  );
}

export function buildPanSystemSearch(options: {
  index: string;
  device?: string;
  maxRows: number;
}): string {
  const idx = literal(options.index, 80);
  const subtypes = PAN_OPERATIONAL_SUBTYPES.map((s) => `"${s}"`).join(", ");
  return (
    `search index=${idx} sourcetype="pan:system"${hostClauseFor(options.device)} ` +
    `| where lower(subtype) IN (${subtypes}) ` +
    `| eval category=upper(subtype), mnemonics=coalesce(eventid, mnemonics), syslog_msg=coalesce(opaque, description, syslog_msg) ` +
    `| where isnotnull(mnemonics) ` +
    `| head ${options.maxRows + 1} ` +
    `| table _time host sourcetype category severity_id mnemonics syslog_msg interface neighbor_ip vrf`
  );
}

export function buildFortigateEventSearch(options: {
  index: string;
  sourcetypes?: readonly ("fortigate_event" | "fgt_event")[];
  device?: string;
  maxRows: number;
}): string {
  const idx = literal(options.index, 80);
  const sts = options.sourcetypes?.length
    ? options.sourcetypes
    : (["fortigate_event", "fgt_event"] as const);
  const stClause =
    sts.length === 1
      ? `sourcetype="${sts[0]}"`
      : `(${sts.map((s) => `sourcetype="${s}"`).join(" OR ")})`;
  const logidPred = FORTIGATE_OPERATIONAL_LOGID_PREFIXES.map(
    (p) => `like(logid, "${p}%")`,
  ).join(" OR ");
  return (
    `search index=${idx} ${stClause}${hostClauseFor(options.device)} ` +
    `| where isnotnull(logid) AND (${logidPred}) ` +
    `| eval category=upper(coalesce(subtype, "EVENT")), code=logid, mnemonics=coalesce(logdesc, logid), syslog_msg=coalesce(logdesc, msg) ` +
    `| head ${options.maxRows + 1} ` +
    `| table _time host sourcetype category severity_id code mnemonics syslog_msg interface neighbor_ip vrf`
  );
}

export function buildF5SyslogSearch(options: {
  index: string;
  device?: string;
  maxRows: number;
}): string {
  const idx = literal(options.index, 80);
  const codeList = F5_OPERATIONAL_CODES.map((c) => `"${c}"`).join(", ");
  return (
    `search index=${idx} sourcetype="f5:bigip:syslog"${hostClauseFor(options.device)} ` +
    `| rex "(?<f5_daemon>mcpd|tmm|sod)(?:\\[\\d+\\])?:\\s*(?<f5_code>[0-9a-fA-F]{8}):(?<f5_sev>[0-7]):\\s*(?<f5_msg>.+)" ` +
    `| eval category=lower(coalesce(category, f5_daemon)), severity_id=coalesce(severity_id, f5_sev), code=lower(coalesce(code, f5_code)), mnemonics=coalesce(mnemonics, f5_code), syslog_msg=coalesce(syslog_msg, f5_msg) ` +
    `| where isnotnull(code) AND code IN (${codeList}) AND NOT match(syslog_msg, "(?i)\\bAUDIT\\b") ` +
    `| head ${options.maxRows + 1} ` +
    `| table _time host sourcetype category severity_id code mnemonics syslog_msg interface neighbor_ip vrf`
  );
}

export function buildMultiVendorSyslogSearches(options: {
  index: string;
  sourcetypes: readonly MultiVendorSyslogSourcetype[];
  device?: string;
  includeAci?: boolean;
  maxRows: number;
}): Array<{ family: string; spl: string }> {
  const out: Array<{ family: string; spl: string }> = [];
  const requested = new Set(options.sourcetypes);

  const ciscoIosAci = ALLOWED_SYSLOG_SOURCETYPES.filter((s) =>
    requested.has(s),
  ) as AllowedSyslogSourcetype[];
  if (ciscoIosAci.length) {
    out.push({
      family: "cisco_ios_aci",
      spl: buildSyslogStateSearch({
        index: options.index,
        device: options.device,
        sourcetypes: ciscoIosAci,
        includeAci: options.includeAci,
        maxRows: options.maxRows,
      }),
    });
  }
  if (requested.has("arista:eos")) {
    out.push({
      family: "arista_eos",
      spl: buildAristaEosSyslogSearch({
        index: options.index,
        device: options.device,
        maxRows: options.maxRows,
      }),
    });
  }
  const asaFtd = (
    ["cisco:asa", "cisco:ftd", "cisco:ftd:syslog"] as const
  ).filter((s) => requested.has(s));
  if (asaFtd.length) {
    out.push({
      family: "cisco_asa_ftd",
      spl: buildCiscoAsaFtdSyslogSearch({
        index: options.index,
        sourcetypes: asaFtd,
        device: options.device,
        maxRows: options.maxRows,
      }),
    });
  }
  if (requested.has("juniper:junos:structured")) {
    out.push({
      family: "juniper_junos",
      spl: buildJuniperJunosSyslogSearch({
        index: options.index,
        device: options.device,
        maxRows: options.maxRows,
      }),
    });
  }
  if (requested.has("pan:system")) {
    out.push({
      family: "pan_system",
      spl: buildPanSystemSearch({
        index: options.index,
        device: options.device,
        maxRows: options.maxRows,
      }),
    });
  }
  const fgt = (["fortigate_event", "fgt_event"] as const).filter((s) =>
    requested.has(s),
  );
  if (fgt.length) {
    out.push({
      family: "fortigate_event",
      spl: buildFortigateEventSearch({
        index: options.index,
        sourcetypes: fgt,
        device: options.device,
        maxRows: options.maxRows,
      }),
    });
  }
  if (requested.has("f5:bigip:syslog")) {
    out.push({
      family: "f5_syslog",
      spl: buildF5SyslogSearch({
        index: options.index,
        device: options.device,
        maxRows: options.maxRows,
      }),
    });
  }
  return out;
}

function classifyVendorDomain(
  category: string,
  mnemonic: string,
  summary: string,
): SyslogOperationalDomain {
  const base = classifySyslogDomain(category, mnemonic);
  if (base !== "other") return base;
  const hay = `${category} ${mnemonic} ${summary}`.toUpperCase();
  if (hay.includes("MLAG") || hay.includes("LACP")) return "port_channel";
  if (hay.includes("BGP")) return "bgp";
  if (hay.includes("OSPF")) return "ospf";
  if (hay.includes("BFD")) return "bfd";
  if (hay.includes("STP") || hay.includes("SPANNING")) return "stp";
  if (
    hay.includes("HA") ||
    hay.includes("FAILOVER") ||
    hay.includes("HSRP") ||
    hay.includes("VRRP")
  )
    return "hsrp_vrrp";
  if (
    hay.includes("LINK") ||
    hay.includes("TRANSCEIVER") ||
    hay.includes("PORT") ||
    hay.includes("POOL")
  )
    return "link";
  return "other";
}

export function normalizeMultiVendorSyslogRow(
  row: ProtocolRow,
  indexInBatch: number,
): NormalizedStateEvent | undefined {
  const sourcetype = asString(row.sourcetype).toLowerCase();
  if (
    ALLOWED_SYSLOG_SOURCETYPES.includes(sourcetype as AllowedSyslogSourcetype)
  ) {
    return normalizeSyslogRow(row, indexInBatch);
  }
  const timestamp = asEpoch(row._time);
  const host = asString(row.host);
  if (!timestamp || !host) return undefined;

  const category = asString(row.category || row.subtype).toUpperCase();
  const code = asString(row.code);
  const mnemonic = asString(
    row.mnemonics || row.mnemonic || row.eventid || row.logdesc || code,
  ).toUpperCase();
  const summary = asString(row.syslog_msg || row.opaque || row.descr);
  if (!mnemonic) return undefined;
  if (CONFIG_SET.has(mnemonic) || mnemonic.startsWith("CONFIG_"))
    return undefined;

  let sourceKind: NormalizedStateEvent["sourceKind"];
  if (sourcetype === "arista:eos") {
    if (!ARISTA_CAT_SET.has(category)) return undefined;
    sourceKind = "sc4s_arista_eos";
  } else if (
    sourcetype === "cisco:asa" ||
    sourcetype === "cisco:ftd" ||
    sourcetype === "cisco:ftd:syslog"
  ) {
    if (!ASA_ID_SET.has(mnemonic) || /username\s*=/i.test(summary)) {
      return undefined;
    }
    sourceKind = "sc4s_cisco_asa_ftd";
  } else if (sourcetype === "juniper:junos:structured") {
    if (!JUNIPER_DAEMON_SET.has(category.toLowerCase())) return undefined;
    sourceKind = "sc4s_juniper_junos";
  } else if (sourcetype === "pan:system") {
    if (!PAN_SUBTYPE_SET.has(category.toLowerCase())) return undefined;
    sourceKind = "sc4s_pan_system";
  } else if (sourcetype === "fortigate_event" || sourcetype === "fgt_event") {
    const fgtCode = code || (/^\d+$/.test(mnemonic) ? mnemonic : "");
    if (
      !fgtCode ||
      !FORTIGATE_OPERATIONAL_LOGID_PREFIXES.some((p) => fgtCode.startsWith(p))
    ) {
      return undefined;
    }
    sourceKind = "sc4s_fortigate_event";
  } else if (sourcetype === "f5:bigip:syslog") {
    const f5Code = (code || mnemonic).toLowerCase();
    if (!F5_CODE_SET.has(f5Code) || /\bAUDIT\b/i.test(summary)) {
      return undefined;
    }
    sourceKind = "sc4s_f5_syslog";
  } else {
    return undefined;
  }

  let severity = Number(row.severity_id ?? row.severity ?? NaN);
  if (!Number.isFinite(severity) || severity < 0 || severity > 7) severity = 5;
  const iface = asString(row.interface) || undefined;
  const neighborIp = asString(row.neighbor_ip) || undefined;
  const vrf = asString(row.vrf) || undefined;

  return {
    id: `${host}:${timestamp}:${mnemonic}:${indexInBatch}`,
    timestamp,
    host,
    sourceKind,
    domain: classifyVendorDomain(category, mnemonic, summary),
    category: category || sourcetype.toUpperCase(),
    severity,
    mnemonic,
    mnemonicQualified: false,
    summary: summary.slice(0, 240) || `${category}-${severity}-${mnemonic}`,
    ...(iface ? { interface: iface } : {}),
    ...(neighborIp ? { neighborIp } : {}),
    ...(vrf ? { vrf } : {}),
  };
}
