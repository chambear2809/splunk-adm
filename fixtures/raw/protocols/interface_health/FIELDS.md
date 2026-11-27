# `interface_health` Synthetic Fixture Field Grounding

All fields in `fixtures/raw/protocols/interface_health/` are grounded in Cisco DC Networking 2.0.10 (`research/extracted/cisco-dc-networking_2010/cisco_dc_networking_app_for_splunk/`) and the shared NX-OS/ACI syslog adapter (`frontend/src/protocols/shared/adapters/nxosSyslog.ts`).

## `dcn_interface_dme.ndjson` (`cisco:dc:nexus9k:dme` / `cisco:dc:nd:*`)

Grounded in `default/props.conf`, `bin/cisco_nexus_9k.py` (`cisco:dc:nexus9k:dme` DME polling of `l1PhysIf`, `ethpmPhysIf`, `rmonEtherStats`, `rmonIfIn`, `rmonIfOut`), and `bin/cisco_dc_n9k_custom.py`:

| Field | Grounding / Alias | Meaning in `interface_health` |
| --- | --- | --- |
| `_time` | epoch seconds | DME poll timestamp |
| `host` | `props.conf:1022` (`dvc`/`dest`) | Switch hostname or management IP |
| `sourcetype` | `props.conf:1005` (`cisco:dc:nexus9k:dme`) or `cisco:dc:nd:protocols` | DME / Nexus Dashboard sourcetype |
| `dn` | DME distinguished name (`sys/intf/phys-[eth1/1]`) | Fallback interface selector when `interface` is absent |
| `interface`, `interface_name` | `props.conf:910` / `interfaceName` | Interface display name (e.g. `Ethernet1/1`) |
| `descr` | `props.conf:841` / `interfaceDescription` | Interface description |
| `admin_state`, `adminSt` | `props.conf:827` / `l1PhysIf.adminSt` | Administrative port state (`up` / `down`) |
| `oper_state`, `operSt` | `ethpmPhysIf.operSt` / `operStatus` | Operational port state (`up` / `down` / `err-disabled`) |
| `speed` | `l1PhysIf.speed` / `props.conf:902` (`eth_speed`) / `portSpeed` | Port speed (e.g. `25G`, `100G`, `10000`) |
| `mtu` | `l1PhysIf.mtu` / `props.conf:884` (`eth_mtu`) | Configured MTU bytes |
| `crc_errors` | `rmonEtherStats` / `props.conf:852` (`eth_crc`) | CRC alignment errors |
| `in_errors`, `out_errors` | `rmonIfIn` / `rmonIfOut` / `props.conf:869,890` | Input and output packet error counters |
| `in_discards`, `out_discards`, `rx_drops`, `tx_drops` | `rmonIfIn` / `rmonIfOut` / `props.conf:868,889` | Ingress and egress discard/drop counters |
| `in_octets`, `out_octets`, `rx_bytes`, `tx_bytes` | `rmonIfIn` / `rmonIfOut` / `props.conf:867,888` | Cumulative RX and TX byte/octet counters |
| `utilization_pct` | `cisco:dc:nd:protocols` `interfaceRateIngress` / derived utilization | Interface utilization percentage `(0..100]` |
| `flap_count` | `props.conf:879` (`eth_link_flapped`) | Link flap counter when reported by DME |

Note: `totalErrors` is computed as `(crcErrors ?? 0) + (inErrors ?? 0) + (outErrors ?? 0)` and `totalDiscards` as `(inDiscards ?? 0) + (outDiscards ?? 0) + (rxDrops ?? 0) + (txDrops ?? 0)` from the latest defined counter per `(device, interface)` so multi-class DME events combine without double-counting cumulative snapshots across polls.

## `nxos_interface_syslog.ndjson` (`cisco:ios`, `cisco:aci`, `cisco:dc:nexus9k:syslog`, `cisco:dc:aci:syslog`)

Grounded in `default/props.conf:1045-1085`, `default/transforms.conf:109-111,277-279`, and `frontend/src/protocols/shared/adapters/nxosSyslog.ts`:

| Field | Grounding | Meaning in `interface_health` |
| --- | --- | --- |
| `_time` | epoch seconds | Syslog event timestamp |
| `host` | Syslog sender host | Switch hostname or IP |
| `sourcetype` | SC4S (`cisco:ios`, `cisco:aci`) or DCN TA (`cisco:dc:nexus9k:syslog`, `cisco:dc:aci:syslog`) | Syslog sourcetype |
| `category` | `props.conf:1071` or SC4S `rex` | Facility category (`ETHPORT`, `LINK`, `LINEPROTO`, `TRANSCEIVER`) |
| `severity_id` | `props.conf:1071` or SC4S `rex` | Syslog severity `0..7` |
| `mnemonics` | `props.conf:1071` or SC4S `rex` | Operational mnemonic (`IF_DOWN_*`, `IF_UP`, `IF_ERROR_*`, `DOM_*`) |
| `syslog_msg` | `props.conf:1071` or SC4S `rex` | Stripped operational syslog message (no auth/AAA or config commands) |
| `interface` | `transforms.conf:278` or extracted from `syslog_msg` / `dn` | Interface identifier |

When only syslog events are present for an interface (no DME counter rows), error counters, discards, and utilization explicitly display **Not covered** (never synthetic zeros), and non-fault syslog-only rows render as `not_covered` rather than `ok`.
