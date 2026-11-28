# Operator Guide: Interface & Link Health (`interface_health`)

The **Interface & Link Health** lens surfaces switch interface administrative/operational state mismatches (`admin=up` with `oper=down`), CRC/input/output errors, discards/drops, link utilization, and `ETHPORT` / `TRANSCEIVER` link-flap and optical DOM events per `(device, interface)` across a bounded UTC window.

## 1. Supported Data Sources

| Role | Sourcetypes | Collector | Coverage |
| --- | --- | --- | --- |
| Primary (Counters & State) | `cisco:dc:nexus9k:dme`, `cisco:dc:nd:*` (`cisco:dc:nd:protocols`, `cisco:dc:nd:congestion`, `cisco:dc:nd:anomalies`) | Cisco DC Networking App for Splunk (2.0.10+) | Full counter and state coverage: `adminSt`/`admin_state`, `operSt`/`oper_state`, `speed`, `mtu`, `crc_errors`, `in_errors`, `out_errors`, `in_discards`, `out_discards`, `rx_drops`, `tx_drops`, `in_octets`/`rx_bytes`, `out_octets`/`tx_bytes`, `utilization_pct`. |
| Primary Syslog (Recommended) | `cisco:ios`, `cisco:aci` | **SC4S (Splunk Connect for Syslog)** | Link flaps (`ETHPORT-5-IF_DOWN_*`, `ETHPORT-5-IF_UP`), interface errors (`ETHPORT-3-IF_ERROR_*`), and optical DOM alarms (`TRANSCEIVER-4-DOM_*`). |
| Fallback Syslog | `cisco:dc:nexus9k:syslog`, `cisco:dc:aci:syslog` | UDP syslog receiver / Cisco DC Networking TA 2.0.10 | Same operational link/transceiver mnemonics when SC4S is not deployed. |

When **only** syslog is present in a scope (no DME counter events), error counters, discards, and utilization explicitly display **Not covered** (never synthetic zeros), and non-fault syslog-only rows render as `not_covered` rather than green `OK`.

## 2. Collecting Interface Telemetry

### Cisco DC Networking 2.0.10 DME Groups

Configure the Nexus 9000 DME or Custom API inputs (`cisco_nexus_9k` / `cisco_dc_n9k_custom.py`) to poll the `interfaces_neighbors` DME classes into your target index (for example `cisco_dc`):

- **State & inventory:** `l1PhysIf`, `ethpmPhysIf`
- **Errors, discards, and octet counters:** `rmonEtherStats`, `rmonIfIn`, `rmonIfOut`
- **Optional Nexus Dashboard:** `cisco:dc:nd:protocols` (port speed, `adminStatus`, `operStatus`, `interfaceRateIngress`)

### Syslog Collection (SC4S Primary, UDP Fallback)

1. **Recommended — SC4S (Splunk Connect for Syslog):**
   - Point NX-OS (`logging server <sc4s-ip> 6`) and APIC syslog destinations at SC4S on TCP/TLS or UDP 514.
   - SC4S routes NX-OS messages to `sourcetype="cisco:ios"` and ACI messages to `sourcetype="cisco:aci"`, or applies `splunk_metadata.csv` overrides to `cisco:dc:nexus9k:syslog` / `cisco:dc:aci:syslog`.
   - The shared `nxosSyslog.ts` adapter extracts `%FACILITY-SEV-MNEMONIC` from SC4S-stripped payloads via `rex` inside Splunk and excludes config-change mnemonics (`VSHD_SYSLOG_CONFIG_I`, `CFGLOG_LOGGEDCMD`, etc.) and `AUTH`/`AAA` categories before `| head`.
2. **Fallback — Direct UDP / Heavy Forwarder Syslog:**
   - If SC4S is not available, send syslog to a Splunk Heavy Forwarder UDP/TCP input tagged `sourcetype="cisco:dc:nexus9k:syslog"` or `sourcetype="cisco:dc:aci:syslog"` with Cisco DC Networking 2.0.10 installed on the HF/search tier.

## 3. Profile Configuration (`adm_protocol_profiles`)

Create one or more profiles for `lens: "interface_health"` under a scope (for example `dc-east`):

```json
{
  "id": "intf-dc-east",
  "lens": "interface_health",
  "scope": "dc-east",
  "index": "cisco_dc",
  "label": "Nexus 9K DME & Syslog (dc-east)",
  "extra": {
    "sourceKind": "auto",
    "errorWarnCount": 1,
    "discardWarnCount": 10,
    "flapWarnCount": 2,
    "utilizationWarnPct": 80
  }
}
```

Use `"sourceKind": "dme"` and `"sourceKind": "syslog"` on separate profiles if DME counters and syslog live in different indexes.

### Validated `extra` Keys (Fail-Closed)

| Key | Type | Default | Allowed Range |
| --- | --- | --- | --- |
| `sourceKind` | `"dme" \| "syslog" \| "auto"` | `"auto"` | Exact enum only |
| `errorWarnCount` | integer (errors) | `1` | `[1, 1000000]` |
| `discardWarnCount` | integer (discards) | `10` | `[1, 1000000]` |
| `flapWarnCount` | integer (flaps) | `2` | `[1, 1000]` |
| `utilizationWarnPct` | number (%) | `80` | `(0, 100]` |

Unknown keys or out-of-range values fail closed at profile validation time.

## 4. Field Grounding & Security Boundaries

- **TA source:** `research/extracted/cisco-dc-networking_2010/cisco_dc_networking_app_for_splunk/` (`default/inputs.conf`, `default/props.conf`, `bin/cisco_nexus_9k.py`, `bin/cisco_dc_n9k_custom.py`).
- **Server-side projection:** DME searches emit `| head <maxRows + 1> | eval ... | table <allowlisted fields>` and syslog searches use `buildSyslogStateSearch` (`| table ... | head <maxRows + 1>`), bounding rows at the indexers and dropping `_raw` before results cross the wire.
- **No AAA/auth leakage:** Authentication syslog categories (`AUTH`, `AUTHPRIV`, `AAA`, `DAEMON`, `VSHD`, `SEC_LOGIN`, `SSH`) and config-change mnemonics are excluded both in SPL and client-side normalization.
- **Role scoping:** Per `splunk_app/splunk_adm/metadata/default.meta`, the `adm_protocol_profiles` KV Store collection grants read access to `adm_investigate`, `adm_viewer`, `admin`, and `sc_admin`, and write access only to `admin` and `sc_admin`.

## 5. Verification Checklist

1. Verify DME and/or syslog events are landing in the configured index:
   - DME: `index=<index> (sourcetype="cisco:dc:nexus9k:dme" OR sourcetype="cisco:dc:nd:*") | head 5 | table _time host interface admin_state oper_state crc_errors in_errors in_discards utilization_pct`
   - Syslog: `index=<index> (sourcetype="cisco:ios" OR sourcetype="cisco:dc:nexus9k:syslog" OR sourcetype="cisco:aci" OR sourcetype="cisco:dc:aci:syslog") | head 5 | table _time host sourcetype syslog_msg`
2. Open **Application Atlas → Protocols → Interface & Link Health**, select the configured scope and UTC window, and click **Investigate**.
3. Confirm:
   - `admin=up` + `oper=down` mismatches, CRC/error/discard violations, link flaps, and high utilization sort first in Overview and highlight in Matrix.
   - Link-flap timelines appear in `SwimlaneTimeline` when syslog events exist.
   - Selecting any interface opens the Detail drawer with state, speed/MTU, error breakdown, discards, flaps, utilization, recent syslog mnemonics, and a literal-quoted **Open raw events in Splunk** link.

## PseudoCo Live Validation

- **Verdict:** **Live verified** (Link state + RMON counters via Cisco DCN 2.0.10 DME)
- **Observed (as `se_demo_readonly`, scope `pseudoco-dc1`):** Bounded `_index_earliest`/`_index_latest` DME snapshot queries (`| head 2048 | dedup 2` for counters plus bounded `dme_state` fallback for `l1PhysIf`/`ethpmPhysIf`) surface both admin/oper link state and RMON counters across all 6 Nexus switches (`178` interfaces inspected, real `admin up / oper down` mismatches flagged with natural interface sorting `eth1/1`..`eth1/9`, `eth1/10`..`eth1/20` in Overview and Matrix). Filtering by **Device** (`198.18.131.2`) and **Interface** (`eth1/1`) isolates a single port (`1 of 1`) below the row cap.

