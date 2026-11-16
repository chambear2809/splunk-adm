import type { Device } from "./topology";

/**
 * Interface names for NetFlow/IPFIX ifIndex values. Collected names
 * (SC4SNMP IF-MIB ifDescr, VMware DVS ports) always win; a Cisco NX-OS/ACI
 * ifIndex can otherwise be decoded from its documented bit layout, which is
 * shown as decoded, never as collected.
 */

const IFINDEX = /^ifIndex\s+(\d+)$/i;

/** The numeric ifIndex of an observer interface token such as "ifIndex 7". */
export function ifIndexOf(raw?: string): number | undefined {
  const m = raw ? IFINDEX.exec(raw.trim()) : null;
  if (!m) return undefined;
  const n = Number(m[1]);
  return Number.isSafeInteger(n) ? n : undefined;
}

/**
 * NX-OS (including ACI leaf and spine) ifIndex layout, checked against
 * IF-MIB ifDescr polled from ACI 16.1 switches:
 * 0x1a000000 + ((port-1) << 12) + sub → Ethernet1/port[.sub] (slot 1 only),
 * 0x16000000 + (n-1) → port-channel n, 0x09010000 + vlan → Vlan SVI,
 * 0x14000000 + n → loopback n, 0x18010000 + n → Tunnel n, 0x05000000 → mgmt0.
 */
export function decodeNxosIfIndex(n: number): string | undefined {
  if (!Number.isSafeInteger(n) || n < 0) return undefined;
  if (n === 0x05000000) return "mgmt0";
  const within = (base: number, size: number) => n >= base && n < base + size;
  if (within(0x1a000000, 0x80000)) {
    const offset = n - 0x1a000000;
    const port = (offset >> 12) + 1;
    const sub = offset & 0xfff;
    return `Ethernet1/${port}${sub ? `.${sub}` : ""}`;
  }
  if (within(0x16000000, 4096)) return `port-channel${n - 0x16000000 + 1}`;
  if (within(0x09010000 + 1, 4094)) return `Vlan${n - 0x09010000}`;
  if (within(0x14000000, 4096)) return `loopback${n - 0x14000000}`;
  if (within(0x18010000, 0x10000)) return `Tunnel${n - 0x18010000}`;
  return undefined;
}

/** Text for an ifIndex nobody named: the decoded NX-OS name when allowed. */
export function unnamedIfIndexLabel(n: number, nxos: boolean): string {
  const decoded = nxos ? decodeNxosIfIndex(n) : undefined;
  return decoded ? `${decoded} (decoded)` : `ifIndex ${n}`;
}

/** Raw ifIndex text still shown to the user (rendered neutral, not as an error). */
export const isRawIfIndex = (label?: string) =>
  !!label && /(^|\s)ifIndex \d+/.test(label);

/** Cisco NX-OS/ACI switches, whose ifIndex layout can be decoded. */
export const isNxosDevice = (d?: Device) =>
  !!d &&
  d.kind === "switch" &&
  (!!d.aci_node ||
    /^(aci|nxos):/.test(d.id) ||
    d.sources.some((s) => s === "aci" || s === "nxos" || s === "cdp"));
