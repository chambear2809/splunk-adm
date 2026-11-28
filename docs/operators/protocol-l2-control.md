# Operator Guide: L2 Control Plane (`l2_control`)

The **L2 Control Plane** lens correlates DHCP DORA / NAK health, Spanning Tree (STP) topology changes and Root Guard blocks, LACP / port-channel member drops, duplicate ARP / DAI violations, and LLDP neighbor events per `(subsystem, device, VLAN/interface)` across a bounded UTC window.

## 1. Supported Data Sources

| Priority | Sourcetype | Collector | Coverage |
| --- | --- | --- | --- |
| Primary (Syslog) | `cisco:ios`, `cisco:aci` | **SC4S (Splunk Connect for Syslog)** | Recommended syslog collector. Parses Cisco NX-OS / IOS / ACI facility, severity, and mnemonics (`STP-*`, `LACP-*`, `ETH_PORT_CHANNEL-*`, `ARP-*`, `DHCP_SNOOPING-*`, `LLDP-*`) without needing a heavy forwarder UDP listener. |
| Fallback (Syslog) | `cisco:dc:nexus9k:syslog`, `cisco:dc:aci:syslog` | Cisco DC Networking 2.0.10 TA (UDP/syslog input or SC4S `splunk_metadata.csv` override) | Pre-extracted `category`, `severity_id`, `mnemonics`, `interface`, `dn`, and `syslog_msg`. |
| Primary (DHCP/ARP Wire) | `stream:dhcp`, `stream:arp` | Splunk Stream (`Splunk_TA_stream` / `splunk_app_stream` 8.1.6+) | Full DHCP DORA/NAK visibility (`chaddr`, `yiaddr`, `ip_lease_time`, `opcode`, `vlan_id`) and ARP request/reply MAC conflict detection. |
| Optional (State) | `cisco:dc:nexus9k:dme` | Cisco DC Networking 2.0.10 TA NX-API DME | Port-channel (`pcAggrIf`, `pcRsMbrIfs`), STP (`stpInst`, `stpVlan`), and LLDP (`lldpAdjEp`) operational state (`operSt`, `lacp_state`, `stp_root`). |

## 2. Syslog Collection: SC4S Primary vs. UDP Fallback

### Recommended: SC4S (Splunk Connect for Syslog)

1. Point NX-OS (`logging server <sc4s-ip> 5`) and ACI syslog destinations to your SC4S collector over TLS or RFC5424/3164 syslog.
2. SC4S routes NX-OS / IOS switches to `sourcetype="cisco:ios"` and ACI fabrics to `sourcetype="cisco:aci"`, preserving the `%FACILITY-SEV-MNEMONIC: message` body.
3. Application Atlas extracts `category`, `severity_id`, and `mnemonics` safely via `buildSyslogStateSearch` (`nxosSyslog.ts`) while excluding AAA/auth categories (`AUTH`, `AUTHPRIV`, `AAA`, `VSHD`, `SEC_LOGIN`, `SSH`) and config-change mnemonics (`VSHD_SYSLOG_CONFIG_I`, `CFGLOG_LOGGEDCMD`, etc.).

### Fallback: Direct UDP/TCP Syslog + Cisco DC Networking TA

If SC4S is not deployed, configure a Splunk syslog input on a dedicated Heavy Forwarder with `sourcetype = cisco:dc:nexus9k:syslog` (or `cisco:dc:aci:syslog`) per the Cisco DC Networking 2.0.10 TA. Avoid terminating raw UDP syslog directly on Splunk Cloud indexers.

## 3. Enabling Splunk Stream `dhcp` & `arp` (Estimate Mode vs. Enabled)

In Splunk App for Stream 8.1.6, `streams/dhcp` and `streams/arp` ship with `enabled: true` and `statsOnly: true` (**Estimate mode**). In Estimate mode, Stream writes volume telemetry to `_internal` (`sourcetype="stream:stats"`) but does **not** index `stream:dhcp` or `stream:arp` events.

1. Confirm a capture interface (`sniffer.captures`) is attached to `streamfwd` on your tap/SPAN host or DHCP relay segment.
2. In Splunk App for Stream (**Configuration → Configure Streams → dhcp** and **arp**), switch `dhcp` (and optionally `arp`) from **Estimate** (`statsOnly: true`) to **Enabled** (`statsOnly: false`) and select your target index (for example `netflow` or `stream`).
3. Leave payload capture fields disabled. Application Atlas blocks `src_content`, `dest_content`, `option_value`, and `_raw` in both SPL construction (`| table ...`) and client-side row projection (`FORBIDDEN_SENSITIVE_FIELDS`).

### On-Demand Estimate-Mode Check

Application Atlas never runs searches on page load. When an operator clicks **Investigate** and `stream:dhcp` completes with 0 rows (or clicks **Check Stream mode** in the banner), Atlas queries `index=_internal sourcetype="stream:stats"` (parsing `senders{}.streams{}.id` and `senders{}.streams{}.stats_only` for `dhcp` and `arp`) and reports whether either stream is still in Estimate mode.

## 4. Profile Configuration (`adm_protocol_profiles`)

Create one or more profiles for `lens: "l2_control"` under a scope (for example `prod:dc1`):

```json
{
  "id": "l2-dc1-auto",
  "lens": "l2_control",
  "scope": "prod:dc1",
  "index": "cisco_dc",
  "label": "L2 Control Plane (DC1)",
  "extra": {
    "sourceKind": "auto",
    "dhcpNakWarnCount": 1,
    "stpTcnWarnCount": 1,
    "lacpDropWarnCount": 1
  }
}
```

Or split Stream DHCP (`"sourceKind": "stream_dhcp"` on index `netflow`) and NX-OS Syslog (`"sourceKind": "syslog"` on index `cisco_dc`) into separate profiles under the same `scope`.

### Validated `extra` Keys (Fail-Closed)

| Key | Type | Default | Allowed Range |
| --- | --- | --- | --- |
| `sourceKind` | `"stream_dhcp" \| "syslog" \| "dme" \| "auto"` | `"auto"` | Exact enum only |
| `dhcpNakWarnCount` | integer | `1` | `[1, 1000]` |
| `stpTcnWarnCount` | integer | `1` | `[1, 1000]` |
| `lacpDropWarnCount` | integer | `1` | `[1, 1000]` |

Unknown keys or out-of-bounds values fail closed at profile validation time.

## 5. Field Grounding & Security Boundaries

- **TA sources:** `research/extracted/splunk-app-for-stream_816/splunk_app_stream/default/streams/{dhcp,arp}` and `research/extracted/cisco-dc-networking_2010/cisco_dc_networking_app_for_splunk/default/{inputs.conf,props.conf}`.
- **Server-side projection:** Stream and DME searches emit `| head <maxRows + 1>` before `| table <allowlisted fields>`, capping rows at the indexers and dropping `_raw` before results cross the wire. Syslog searches use the shared `buildSyslogStateSearch` helper in `nxosSyslog.ts`.
- **Role scoping:** Per `splunk_app/splunk_adm/metadata/default.meta`, `adm_protocol_profiles` is readable by `adm_investigate`, `adm_viewer`, `admin`, and `sc_admin`, and writable only by `admin` and `sc_admin`.

## 6. Verification Checklist

1. Verify L2 events are landing in the configured indexes:
   - `index=<index> sourcetype="stream:dhcp" | head 5 | table _time host chaddr opcode yiaddr ip_lease_time vlan_id`
   - `index=<index> (sourcetype="cisco:ios" OR sourcetype="cisco:dc:nexus9k:syslog") | head 5 | table _time host sourcetype category mnemonics syslog_msg`
2. Open **Application Atlas → Protocols → L2 Control Plane**, select the configured scope and UTC window, and click **Investigate**.
3. Confirm:
   - DHCP NAKs, STP RootGuard/TCN, LACP member drops, duplicate ARP, and DHCP snooping alerts sort first in Overview and render in the Swimlane timeline.
   - Switching to **Matrix** displays **Device × Subsystem** (`DHCP`, `STP`, `LACP`, `ARP`, `LLDP`), showing **Not covered** for uncollected subsystems and **None observed** (or **Unknown** when capped) for empty pairs.
   - Selecting any row opens the Detail drawer with Status chip first, DHCP/LACP/STP details, recent mnemonics, Exceptions, and a bounded **Open raw events in Splunk** link.

## PseudoCo Live Validation

- **Verdict:** **Enabled, no events yet**
- **Observed (as `se_demo_readonly`, scope `pseudoco-dc1`):** DCN 2.0.10 `w0_n9k_dme_layer2` and NX-OS syslog (`udp://5514`) are enabled; `0` STP, LACP, or DHCP control-plane events arrived in the 60-minute validation window (**None observed**).

