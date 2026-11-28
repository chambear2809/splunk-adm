# `state_events` Synthetic Fixture Field Grounding

All fields in `fixtures/protocols/state_events/` are grounded in the shared SC4S / NX-OS / ACI operational syslog contract (`frontend/src/protocols/shared/adapters/nxosSyslog.ts`), Cisco DC Networking TA (`cisco:dc:nexus9k:syslog`, `cisco:dc:aci:syslog`, `cisco:dc:aci:fault`, `cisco:dc:aci:event`, `cisco:dc:aci:class`), and `LENS_FIELD_ALLOWLISTS.state_events` (`frontend/src/protocols/shared/fields.ts`).

## `nxos_state_syslog.ndjson` (SC4S `cisco:ios` / `cisco:aci` & DCN TA `cisco:dc:nexus9k:syslog` / `cisco:dc:aci:syslog`)

| Field | Grounding | Meaning in `state_events` |
| --- | --- | --- |
| `_time` | epoch seconds | Event timestamp |
| `host` | `props.conf` (`EVAL-dest`, `EVAL-dvc`) | Reporting switch hostname or management IP (`192.0.2.11` preserved intact; `leaf-01.dc1.local` shortened to `leaf-01`) |
| `sourcetype` | SC4S (`cisco:ios`, `cisco:aci`) or DCN TA (`cisco:dc:nexus9k:syslog`, `cisco:dc:aci:syslog`) | Syslog source type |
| `category` | `props.conf` `EXTRACT-fields` / `nxosSyslog.ts` `| rex` | Cisco facility (`ETHPORT`, `LINK`, `BGP`, `OSPF`, `ISIS`, `BFD`, `STP`, `ETH_PORT_CHANNEL`, `HSRP`, `VRRP`, `PIM`) |
| `severity_id` | `props.conf` `EXTRACT-fields` / `nxosSyslog.ts` `| rex` | Syslog severity `0`–`7` |
| `mnemonics` | `props.conf` `EXTRACT-fields` / `nxosSyslog.ts` `| rex` | Operational mnemonic |
| `syslog_msg` | `props.conf` `EXTRACT-fields` / SC4S message body | Operational transition message |
| `interface` | `nxosSyslog.ts` / `SYSLOG_OP_FIELDS` | Optional affected interface |
| `neighbor_ip` | `nxosSyslog.ts` / `SYSLOG_OP_FIELDS` | Optional routing neighbor IP |
| `vrf` | `nxosSyslog.ts` / `SYSLOG_OP_FIELDS` | Optional VRF context |

### Qualification Note (HSRP/VRRP & Exclusions)

- **HSRP/VRRP:** Collected on the syslog path (`cisco:ios`, `cisco:dc:nexus9k:syslog`); NX-OS DME HSRP/VRRP classes are not qualified in the TA schema.
- **Excluded Categories & Mnemonics:** AAA/auth categories (`AUTH`, `AUTHPRIV`, `AAA`, `DAEMON`, `VSHD`, `SEC_LOGIN`, `SSH`) and config-change mnemonics (`VSHD_SYSLOG_CONFIG_I`, `CONFIG_I`, `USER_CONFIG`, `SYSTEM_CONFIG`, `COPY_RUNNING_STARTUP`, `CFGLOG_LOGGEDCMD`) are excluded both in SPL (`buildSyslogStateSearch`) and client-side (`normalizeSyslogRow`, `normalizeStateSyslogRow`).

## `aci_fault_event.ndjson` (Cisco DC Networking ACI `faultInst` & `eventRecord`)

Grounded in `docs/change-correlation/sources/aci.md`, `docs/FEATURE_SOURCE_OBSERVATIONS.md` (`faultRecord`, `eventRecord`, `faultInst` classInfo collector), and `LENS_FIELD_ALLOWLISTS.state_events`:

| Field | Grounding | Meaning in `state_events` |
| --- | --- | --- |
| `_time` | epoch seconds | Indexed timestamp (falls back to `lastTransition` or `created`) |
| `host`, `apic_host` | `cisco_nexus_aci.py` (`apic_host`) | Reporting APIC controller host |
| `sourcetype` | `cisco:dc:aci:fault`, `cisco:dc:aci:event`, or `cisco:dc:aci:class` | ACI fault/event source type |
| `component` | `cisco_nexus_aci.py` (`component`) | Must be `faultInst` or `eventRecord` when reading `cisco:dc:aci:class` (other classes like `topSystem` are ignored) |
| `dn`, `affected` | APIC `faultInst` / `eventRecord` attributes | Managed-object DN (`topology/pod-<p>/node-<n>/...` attributes to `pod-<p>/node-<n>`) |
| `code`, `rule` | APIC `faultInst` / `eventRecord` attributes | Fault or event code (e.g. `F0546`, `F1296`, `E4204936`) |
| `descr`, `cause`, `subject`, `type`, `lifecycle` | APIC `faultInst` / `eventRecord` attributes | Fault/event description and lifecycle state (`raised`, `soaking`, `cleared`, `created`) |
| `severity` | APIC fault severity (`critical`, `major`, `minor`, `warning`, `info`, `cleared`) | Mapped to numeric syslog-aligned scale `0`–`7` (`critical=2`, `major=3`, `minor/warning=4`, `info/cleared=6`) |
| `domain` | APIC fault domain (`infra`, `access`, `tenant`, etc.) | Operational ACI domain (AAA/auth domains excluded) |
| `created`, `lastTransition` | APIC ISO-8601 timestamps | Source creation and transition timestamps |

### Fields Not Yet Verified in a Deployed Feed

The synthetic `cisco:dc:aci:fault` / `cisco:dc:aci:event` / `cisco:dc:aci:class` (`faultInst`, `eventRecord`) fault attributes (`rule`, `lifecycle`, `lastTransition`) and SC4S `cisco:ios` / `cisco:aci` HSRP/VRRP/STP/PIM syslog payloads are grounded in vendor documentation and TA extracts; live emission against a deployed APIC / NX-OS SC4S feed remains to be verified per environment.
