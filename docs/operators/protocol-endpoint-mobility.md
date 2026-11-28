# Operator Guide: Endpoint Mobility & Address Conflicts (`endpoint_mobility`)

Status: **Staged**

The **Endpoint Mobility & Address Conflicts** lens correlates duplicate IP conflicts (multiple MACs observed claiming one IP), MAC/IP moves across switch/leaf ports, ARP packet rate spikes, and attachment-port link flaps across a bounded UTC window.

## 1. Supported Data Sources

| Priority | Sourcetype | Collector | Coverage |
| --- | --- | --- | --- |
| Primary (ARP Wire) | `stream:arp` | Splunk Stream (`Splunk_TA_stream` / `splunk_app_stream` 8.1.6+) | Duplicate IP -> MAC ARP conflicts and ARP rate spikes per sender MAC/IP. |
| Primary (Fabric Endpoints) | `cisco:dc:nd:endpoints` | Cisco DC Networking 1.2.2 / 2.0.10 TA | Endpoint creations, deletions, modifications, MAC/IP moves (`nodeName`, `displayInterface`, `modType`), and ND `anomalyScore`. |
| Primary (ACI Fabric) | `cisco:dc:aci:stats`, `cisco:dc:aci:class` (`fvCEp`) | Cisco DC Networking TA | ACI `fvCEp` MAC/IP bindings, `tDn` leaf/port path attachments, `encap`, and `lcC` learning flags. |
| Optional (NX-OS DME) | `cisco:dc:nexus9k:dme` (`epmMacEp`, `l2MacAddressEntry`) | Cisco DC Networking TA NX-API DME | Switch-local MAC/IP endpoint tables and `move_count` telemetry. |
| Primary (Syslog) | `cisco:ios`, `cisco:aci` | **SC4S (Splunk Connect for Syslog)** | Recommended syslog collector. Parses `%L2FM-*`, `%MATM-*`, `%ARP-*`, `%DAI-*`, and `%ETHPORT-*` / `%LINK-*` events without a heavy forwarder UDP listener. |
| Fallback (Syslog) | `cisco:dc:nexus9k:syslog`, `cisco:dc:aci:syslog` | Cisco DC Networking TA (UDP/syslog lab fallback or SC4S metadata override) | Pre-extracted `category`, `severity_id`, `mnemonics`, `interface`, `dn`, and `syslog_msg`. |

## 2. Enabling Splunk Stream `arp` (Estimate Mode vs. Enabled)

In Splunk App for Stream 8.1.6, `streams/arp` ships with `enabled: true` and `statsOnly: true` (**Estimate mode**). In Estimate mode, Stream writes volume telemetry to `_internal` (`sourcetype="stream:stats"`) but does **not** index `stream:arp` events.

1. Confirm a capture interface (`sniffer.captures`) is attached to `streamfwd` on your tap/SPAN host or access-edge segment.
2. In Splunk App for Stream (**Configuration → Configure Streams → arp**), switch `arp` from **Estimate** (`statsOnly: true`) to **Enabled** (`statsOnly: false`) and choose your target index (for example `netflow` or `stream`).
3. Leave raw packet capture disabled. Application Atlas blocks `raw_packet`, `payload`, `src_content`, `dest_content`, and `_raw` in both SPL construction (`| table ...`) and client-side row projection (`FORBIDDEN_SENSITIVE_FIELDS`).

### On-Demand Estimate-Mode Check

Application Atlas never runs searches on page load. When an operator clicks **Investigate** and `stream:arp` completes with 0 rows (or clicks **Check Stream mode** in the banner), Atlas queries `index=_internal sourcetype="stream:stats"` (parsing `senders{}.streams{}.id` and `senders{}.streams{}.stats_only` for `arp`) and reports whether `arp` is stuck in Estimate mode.

## 3. Syslog Collection: SC4S Primary vs. UDP Lab Fallback

### Recommended: SC4S (Splunk Connect for Syslog)

1. Point NX-OS (`logging server <sc4s-ip> 5`) and ACI syslog destinations to your SC4S collector over TLS or RFC5424/3164 syslog.
2. SC4S routes NX-OS / IOS switches to `sourcetype="cisco:ios"` and ACI fabrics to `sourcetype="cisco:aci"`, preserving the `%FACILITY-SEV-MNEMONIC: message` body.
3. Application Atlas extracts `category`, `severity_id`, and `mnemonics` safely via `buildSyslogStateSearch` (`nxosSyslog.ts`) using `MOBILITY_SYSLOG_CATEGORIES` while excluding AAA/auth categories (`AUTH`, `AUTHPRIV`, `AAA`, `VSHD`, `SEC_LOGIN`, `SSH`) and config-change mnemonics (`VSHD_SYSLOG_CONFIG_I`, `CFGLOG_LOGGEDCMD`, etc.).

### Lab Fallback: Direct UDP/TCP Syslog + Cisco DC Networking TA

If SC4S is not deployed in a lab, configure a syslog input on a dedicated Heavy Forwarder with `sourcetype = cisco:dc:nexus9k:syslog` (or `cisco:dc:aci:syslog`) per the Cisco DC Networking TA. Avoid terminating raw UDP syslog directly on Splunk Cloud indexers.

## 4. Fabric Sources: Nexus Dashboard, ACI `fvCEp`, and NX-OS DME

1. **Nexus Dashboard Endpoints (`cisco:dc:nd:endpoints`):** Enable the DC Networking TA `endpoints` modular input pointing at Nexus Dashboard; verify `endpointId`, `mac`, `ip`, `nodeName`, `displayInterface`, `modType`, and `anomalyScore` are extracted.
2. **ACI Endpoint History (`cisco:dc:aci:stats`, `cisco:dc:aci:class`):** Enable `fvCEp` collection; Atlas filters `component="fvCEp"` before `| head` so inventory classes (`topSystem`, `compVm`) do not crowd out endpoint rows.
3. **Nexus 9K DME (`cisco:dc:nexus9k:dme`):** Enable `epmMacEp` / `l2MacAddressEntry` DME polling; Atlas filters `(component="epmMacEp" OR component="l2MacAddressEntry" OR dn="sys/eps/*" OR dn="sys/bd/*")` before `| head`.

## 5. Profile Configuration (`adm_protocol_profiles`)

Create one or more profiles for `lens: "endpoint_mobility"` under a scope (for example `prod:dc1`):

```json
{
  "id": "mobility-dc1-auto",
  "lens": "endpoint_mobility",
  "scope": "prod:dc1",
  "index": "cisco_dc",
  "observer": "nd-01",
  "validFrom": 1700000000,
  "validUntil": 1900000000,
  "extra": {
    "sourceKind": "auto",
    "arpSpikeWarnCount": 20,
    "macMoveWarnCount": 1,
    "portFlapWarnCount": 2,
    "anomalyScoreWarn": 50
  }
}
```

Or split Stream ARP (`"sourceKind": "stream_arp"` on index `netflow`) and Fabric/Syslog (`"sourceKind": "nd_endpoints"`, `"aci_fvcep"`, `"dme"`, or `"syslog"` on index `cisco_dc`) into separate profiles under the same `scope`.

### Validated `extra` Keys (Fail-Closed)

| Key | Type | Default | Allowed Range |
| --- | --- | --- | --- |
| `sourceKind` | `"stream_arp" \| "nd_endpoints" \| "aci_fvcep" \| "dme" \| "syslog" \| "auto"` | `"auto"` | Exact enum only |
| `arpSpikeWarnCount` | integer | `20` | `[1, 100000]` |
| `macMoveWarnCount` | integer | `1` | `[1, 1000]` |
| `portFlapWarnCount` | integer | `2` | `[1, 1000]` |
| `anomalyScoreWarn` | number | `50` | `[1, 100]` |

Unknown keys or out-of-bounds values fail closed at profile validation time.

## 6. Field Grounding & Security Boundaries

- **Field allowlist:** Strictly bounded by `LENS_FIELD_ALLOWLISTS.endpoint_mobility` in `frontend/src/protocols/shared/fields.ts` and `fixtures/protocols/endpoint_mobility/FIELDS.md`.
- **Server-side projection:** Every SPL builder emits `| head <maxRows + 1>` before `| table <allowlisted fields>`, capping rows at the indexers and dropping `_raw` before results cross the wire.
- **Evidence wording:** Findings report observable duplicate IP-to-MAC mappings, port transitions, ARP counts, and link flaps without claiming malicious spoofing. Missing sources render **Not covered** (`not_covered`), distinct from **None observed** (`none_observed`).

## 7. Verification Checklist

1. Verify mobility events are landing in the configured indexes:
   - `index=<index> sourcetype="stream:arp" | head 5 | table _time host sender_ip sender_mac target_ip arp_opcode vlan_id`
   - `index=<index> sourcetype="cisco:dc:nd:endpoints" | head 5 | table _time nodeName displayInterface mac ip modType anomalyScore`
   - `index=<index> (sourcetype="cisco:dc:aci:stats" OR sourcetype="cisco:dc:aci:class") component="fvCEp" | head 5 | table _time mac ip addr tDn encap`
2. Open **Application Atlas → Protocols → Endpoint Mobility & ARP**, select the configured scope and UTC window, and click **Investigate**.
3. Confirm:
   - Duplicate IPs, MAC moves, ARP spikes, and correlated port flaps sort first in Overview and render on the Swimlane timeline.
   - Switching to **Matrix** displays **Switch / Leaf × VLAN/VNI**, showing **None observed** (or **Unknown** when capped) for empty pairs.
   - Selecting any row opens the Detail drawer with Status chip first, observed MACs/IPs (`<CopyableIp>`), chronological path transitions, ARP rate, correlated port flaps, and a bounded **Open raw events in Splunk** link.

## PseudoCo Live Validation

- **Verdict:** **Live verified** (`cisco:dc:nd:endpoints` + `stream:arp`)
- **Observed (as `se_demo_readonly`, scope `pseudoco-dc1`):** `266` endpoints inspected across live `cisco:dc:nd:endpoints` and scoped `stream:arp` (`5` ARP rate spikes flagged, `0` MAC moves); port flaps truthfully marked **Not covered**. Filter by **Endpoint IP** or **Device** to inspect a specific host below the row cap.

