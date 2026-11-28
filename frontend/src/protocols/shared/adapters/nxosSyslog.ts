import { literal } from "../../../data/evidence";
import type { ProtocolRow } from "../runner";

export type SyslogOperationalDomain =
  | "link"
  | "bgp"
  | "ospf"
  | "isis"
  | "bfd"
  | "stp"
  | "port_channel"
  | "hsrp_vrrp"
  | "pim"
  | "other";

/**
 * Supported literal syslog sourcetypes:
 * - SC4S defaults: `cisco:ios` (NX-OS / IOS / IOS-XE via SC4S `cisco_ios` parser),
 *   `cisco:aci` (ACI via SC4S `cisco_aci` parser)
 * - Cisco DC Networking 2.0.10 TA (or SC4S `splunk_metadata.csv` override):
 *   `cisco:dc:nexus9k:syslog`, `cisco:dc:aci:syslog`
 */
export const ALLOWED_SYSLOG_SOURCETYPES = [
  "cisco:ios",
  "cisco:dc:nexus9k:syslog",
  "cisco:aci",
  "cisco:dc:aci:syslog",
] as const;

export type AllowedSyslogSourcetype =
  (typeof ALLOWED_SYSLOG_SOURCETYPES)[number];

export interface NormalizedStateEvent {
  id: string;
  timestamp: number;
  host: string;
  sourceKind:
    | "sc4s_cisco_ios"
    | "nxos_syslog"
    | "aci_syslog"
    | "aci_fault"
    | "sc4s_arista_eos"
    | "sc4s_juniper_junos"
    | "sc4s_pan_system"
    | "sc4s_fortigate_event"
    | "sc4s_f5_syslog"
    | "sc4s_cisco_asa_ftd"
    | "sc4snmp_trap";
  domain: SyslogOperationalDomain;
  category: string;
  severity: number;
  mnemonic: string;
  /** True only for TA-extracted or lab-qualified operational mnemonics. */
  mnemonicQualified: boolean;
  summary: string;
  interface?: string;
  neighborIp?: string;
  vrf?: string;
}

/**
 * Config-change mnemonics belong to docs/change-correlation/sources/nxos.md
 * and are excluded from operational state-change lenses both in SPL and client-side.
 */
export const CONFIG_CHANGE_MNEMONICS = [
  "VSHD_SYSLOG_CONFIG_I",
  "CONFIG_I",
  "USER_CONFIG",
  "SYSTEM_CONFIG",
  "COPY_RUNNING_STARTUP",
  "CFGLOG_LOGGEDCMD",
] as const;

const CONFIG_CHANGE_SET = new Set<string>(CONFIG_CHANGE_MNEMONICS);

/**
 * Authentication / AAA syslog categories are excluded from operational state
 * lenses so usernames and login events never leak into operational summaries.
 */
export const EXCLUDED_AUTH_CATEGORIES = [
  "AUTH",
  "AUTHPRIV",
  "AAA",
  "DAEMON",
  "VSHD",
  "SEC_LOGIN",
  "SSH",
] as const;

const EXCLUDED_AUTH_SET = new Set<string>(EXCLUDED_AUTH_CATEGORIES);

const CATEGORY_DOMAIN: Record<string, SyslogOperationalDomain> = {
  ETHPORT: "link",
  LINK: "link",
  LINEPROTO: "link",
  ETH_PORT_CHANNEL: "port_channel",
  LACP: "port_channel",
  EC: "port_channel",
  BGP: "bgp",
  OSPF: "ospf",
  OSPFV3: "ospf",
  ISIS: "isis",
  BFD: "bfd",
  STP: "stp",
  MSTP: "stp",
  SPANTREE: "stp",
  HSRP: "hsrp_vrrp",
  VRRP: "hsrp_vrrp",
  PIM: "pim",
  IGMP: "pim",
};

const QUALIFIED_CATEGORIES = new Set<string>(["ETHPORT", "BFD", "OSPF", "PIM"]);

/** Matches standard Cisco `%FACILITY[-SUBFACILITY]-SEV-MNEMONIC: msg` after SC4S header stripping. */
const CISCO_SYSLOG_RE =
  /%([A-Za-z0-9_]+)(?:-[A-Za-z0-9_]+)?-([0-7])-([A-Za-z0-9_]+):\s*(.*)/;

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

export function classifySyslogDomain(
  category: string,
  mnemonic: string,
): SyslogOperationalDomain {
  const cat = category.toUpperCase();
  if (CATEGORY_DOMAIN[cat]) return CATEGORY_DOMAIN[cat];
  const m = mnemonic.toUpperCase();
  if (m.includes("BGP")) return "bgp";
  if (m.includes("OSPF")) return "ospf";
  if (m.includes("ISIS")) return "isis";
  if (m.includes("BFD")) return "bfd";
  if (m.includes("HSRP") || m.includes("VRRP")) return "hsrp_vrrp";
  if (m.includes("STP") || m.includes("ROOT")) return "stp";
  if (m.includes("PORT_CHANNEL") || m.includes("LACP") || m.includes("BUNDLE"))
    return "port_channel";
  if (m.includes("LINK") || m.includes("IF_DOWN") || m.includes("IF_UP"))
    return "link";
  if (m.includes("PIM")) return "pim";
  return "other";
}

export function normalizeSyslogRow(
  row: ProtocolRow,
  indexInBatch: number,
): NormalizedStateEvent | undefined {
  const timestamp = asEpoch(row._time);
  const host = asString(row.host);
  if (!timestamp || !host) return undefined;
  const sourcetype = asString(row.sourcetype).toLowerCase();
  const isAci = sourcetype.includes("aci");
  const isSc4sIos = sourcetype === "cisco:ios";

  let category = asString(row.category || row.facility).toUpperCase();
  let mnemonic = asString(
    row.mnemonics || row.mnemonic || row.code,
  ).toUpperCase();
  let severity = Number(row.severity_id ?? row.severity ?? NaN);
  let summary = asString(row.syslog_msg || row.descr);

  if ((!category || !mnemonic || !Number.isFinite(severity)) && summary) {
    const match = CISCO_SYSLOG_RE.exec(summary);
    if (match) {
      category = category || match[1].toUpperCase();
      if (!Number.isFinite(severity)) severity = Number(match[2]);
      mnemonic = mnemonic || match[3].toUpperCase();
      summary = match[4].trim();
    }
  }
  if (!mnemonic) return undefined;
  if (CONFIG_CHANGE_SET.has(mnemonic)) return undefined;
  if (category && EXCLUDED_AUTH_SET.has(category)) return undefined;
  if (!Number.isFinite(severity) || severity < 0 || severity > 7) severity = 5;

  const domain = classifySyslogDomain(category, mnemonic);
  const iface = asString(row.interface || row.dn) || undefined;
  const neighborIp = asString(row.neighbor_ip) || undefined;
  const vrf = asString(row.vrf) || undefined;

  return {
    id: `${host}:${timestamp}:${mnemonic}:${indexInBatch}`,
    timestamp,
    host,
    sourceKind: isAci
      ? "aci_syslog"
      : isSc4sIos
        ? "sc4s_cisco_ios"
        : "nxos_syslog",
    domain,
    category: category || (isAci ? "ACI" : "NXOS"),
    severity,
    mnemonic,
    mnemonicQualified: QUALIFIED_CATEGORIES.has(category),
    summary: summary.slice(0, 240) || `${category}-${severity}-${mnemonic}`,
    ...(iface ? { interface: iface } : {}),
    ...(neighborIp ? { neighborIp } : {}),
    ...(vrf ? { vrf } : {}),
  };
}

/**
 * Builds a bounded SPL query for SC4S (`cisco:ios`, `cisco:aci`) and/or
 * Cisco DC Networking TA (`cisco:dc:nexus9k:syslog`, `cisco:dc:aci:syslog`)
 * operational syslog rows. Extracts facility/severity/mnemonic/message from
 * SC4S-stripped payloads via `rex` inside Splunk and drops `_raw`, config-change
 * mnemonics, and AAA/auth categories before `head` so operational events are
 * never crowded out or exposed with auth data.
 */
export function buildSyslogStateSearch(options: {
  index: string;
  device?: string;
  sourcetypes?: readonly AllowedSyslogSourcetype[];
  categories?: readonly string[];
  includeAci?: boolean;
  maxRows: number;
}): string {
  literal(options.index, 80);
  const requested: readonly AllowedSyslogSourcetype[] = options.sourcetypes
    ?.length
    ? options.sourcetypes
    : options.includeAci
      ? ALLOWED_SYSLOG_SOURCETYPES
      : (["cisco:ios", "cisco:dc:nexus9k:syslog"] as const);
  for (const st of requested) {
    if (!ALLOWED_SYSLOG_SOURCETYPES.includes(st))
      throw new Error(`Unsupported syslog sourcetype "${st}".`);
  }
  const stClause =
    requested.length === 1
      ? `sourcetype="${requested[0]}"`
      : `(${requested.map((st) => `sourcetype="${st}"`).join(" OR ")})`;
  const hostClause = options.device
    ? ` host="${literal(options.device, 128)}"`
    : "";
  const catFilter = options.categories?.length
    ? ` AND (category IN (${options.categories
        .map((cat) => `"${literal(cat, 32)}"`)
        .join(", ")}))`
    : "";
  const excludedMnemonics = CONFIG_CHANGE_MNEMONICS.map((m) => `"${m}"`).join(
    ", ",
  );
  const excludedCategories = EXCLUDED_AUTH_CATEGORIES.map((c) => `"${c}"`).join(
    ", ",
  );
  return (
    `search index=${options.index} ${stClause}${hostClause} ` +
    `| rex "%(?<sc4s_cat>[A-Za-z0-9_]+)(?:-[A-Za-z0-9_]+)?-(?<sc4s_sev>[0-7])-(?<sc4s_mnem>[A-Za-z0-9_]+):\\s*(?<sc4s_msg>.+)" ` +
    `| eval category=coalesce(category, facility, sc4s_cat), severity_id=coalesce(severity_id, severity, sc4s_sev), mnemonics=coalesce(mnemonics, mnemonic, code, sc4s_mnem), syslog_msg=coalesce(syslog_msg, descr, sc4s_msg) ` +
    `| where isnotnull(mnemonics) AND NOT (upper(mnemonics) IN (${excludedMnemonics})) AND (isnull(category) OR NOT (upper(category) IN (${excludedCategories})))${catFilter} ` +
    `| head ${options.maxRows + 1} ` +
    `| table _time host sourcetype category severity_id mnemonics dn descr syslog_msg interface neighbor_ip vrf`
  );
}
