# Operator Guide: Blocked Traffic & Drops (`drops`)

Status: **Staged**

The **Blocked Traffic & Drops** lens answers *"why can't A reach B?"* across heterogeneous enforcement points while preserving every source's **native** rule, contract, verdict, or drop reason without conflating vendor policy semantics.

## 1. Supported Data Sources

| Enforcer Label | Sourcetype(s) | Collector | Native Fields Projected |
| --- | --- | --- | --- |
| **FTD** | `cisco:sfw:estreamer` | Cisco Security Cloud (`sbg_fw_estreamer_input`) | `AC_RuleAction` (`Block`, `Block with reset`, `Drop`, `Reset`), `AccessControlRuleName`, `InitiatorIP`/`Port`, `ResponderIP`/`Port`, `Protocol`, `Device`, `DeviceIP`, `IngressZone`, `EgressZone`, `Application`, packet/byte counts. |
| **Hubble** | `cilium:hubble:flow` | Cilium Hubble static exporter + OTel filelog receiver | `flow.verdict="DROPPED"`, `drop_reason_desc` (e.g., `POLICY_DENIED`), `drop_reason`, `src_ip`/`dest_ip`, `src_port`/`dest_port`, `src_namespace`/`src_pod`, `dest_namespace`/`dest_pod`, `node`. |
| **Nexus Dashboard** | `cisco:dc:nd:flows` | Cisco DC Networking (`cisco_dc_nd_collector`) | `srcIp`, `dstIp`, `srcPort`, `dstPort`, `protocolName`, `dropPktCount`, `dropReasons`, `fabricName`, `nd_host`, `node`. |
| **ACI** | `cisco:dc:aci:class` (`acllogDropL3Pkt`), `cisco:dc:aci:syslog` | Cisco DC Networking (`classInfo_fvRsCEpToPathEp`) or SC4S | `src_ip`/`srcIp`, `dest_ip`/`dstIp`, `src_port`/`srcPort`, `dest_port`/`dstPort`, `protocol`, `drop_reason`, `contract_name`, `tenant`, `vrf`, `dn`, `descr`, `node`, `device`, `pktLen` (`bytes`). |
| **Firewall** | `pan:traffic`, `fortigate_traffic`, `fgt_traffic`, `aws:cloudwatchlogs:vpcflow`, `mscs:vnet:flow`, `google:gcp:compute:vpc_flows`, or CIM Network Traffic | **SC4S (Splunk Connect for Syslog)** for syslog firewalls; vendor TAs for cloud flow logs | `src_ip`, `dest_ip`, `src_port`, `dest_port`, `transport`, `action` (`block`, `deny`, `drop`, `reject`, `reset`), `reason`, `rule_name`, `acl_name`, `policy_name`, `packets`, `bytes`, `device`, `exporter_ip`. |

## 2. Collector Setup

### Cisco Secure Firewall (FTD eStreamer)

1. Configure the **Cisco Security Cloud** app's FTD eStreamer input (`sbg_fw_estreamer_input`) against FMC and route to `cisco_secure_fw` (the TA default).
2. Ensure `ConnectionEvent` logging is enabled on Access Control Policy rules that `Block`, `Block with reset`, or `Drop` traffic.

### Cilium Hubble

1. Enable Hubble static export (`/var/run/cilium/hubble/events.log`) and ship via the OTel agent `logsCollection.extraFileLogs` pipeline with `sourcetype="cilium:hubble:flow"` into `cilium_hubble`.
2. Ensure drop events (`flow.verdict="DROPPED"`) are not filtered out at the Cilium exporter.

### Cisco Nexus Dashboard & ACI ACL Drops

1. In **Cisco DC Networking** (`cisco_dc_networking_app_for_splunk`), enable the `cisco:dc:nd:flows` input and the `classInfo_fvRsCEpToPathEp` input (`acllogDropL3Pkt`) into `cisco_dc`.
2. On APIC contracts where explicit deny visibility is required, enable `directives=log` on the deny subject (`vzRsSubjFiltAtt`). Note that APIC leaf buffers re-report `acllogDropL3Pkt` across 5-minute polls; Atlas deduplicates identical record DNs client-side.

### Syslog Firewalls & Cloud Flow Logs (SC4S Recommended)

For syslog-backed firewalls (PAN-OS `pan:traffic`, FortiGate `fortigate_traffic` / `fgt_traffic`, Cisco ACI syslog `cisco:dc:aci:syslog`), **SC4S (Splunk Connect for Syslog)** is the primary recommended collector so syslog headers are stripped and TA sourcetypes are assigned consistently before search-time extraction. Route cloud flow logs (`aws:cloudwatchlogs:vpcflow`, `mscs:vnet:flow`, `google:gcp:compute:vpc_flows`) via their respective Splunk Add-ons.

## 3. Profile Configuration (`adm_protocol_profiles`)

Configure one or more `drops` profiles per scope in `adm_protocol_profiles`:

```json
{
  "version": 1,
  "profiles": [
    {
      "id": "drops-ftd-prod",
      "source": "protocol_drops",
      "lens": "drops",
      "scope": "prod:dc1",
      "index": "cisco_secure_fw",
      "observer": "ftd-edge",
      "validFrom": 1700000000,
      "validUntil": 1900000000,
      "extra": {
        "sourceKind": "ftd",
        "dropWarnCount": 1
      }
    },
    {
      "id": "drops-hubble-prod",
      "source": "protocol_drops",
      "lens": "drops",
      "scope": "prod:dc1",
      "index": "cilium_hubble",
      "observer": "prod-k8s",
      "validFrom": 1700000000,
      "validUntil": 1900000000,
      "extra": {
        "sourceKind": "hubble"
      }
    },
    {
      "id": "drops-pan-prod",
      "source": "protocol_drops",
      "lens": "drops",
      "scope": "prod:dc1",
      "index": "pan",
      "observer": "pa-fw-01",
      "validFrom": 1700000000,
      "validUntil": 1900000000,
      "extra": {
        "sourceKind": "firewall",
        "sourcetype": "pan:traffic",
        "dropWarnCount": 1
      }
    }
  ]
}
```

### Validated `extra` Keys (Fail-Closed)

| Key | Type | Default | Allowed Values |
| --- | --- | --- | --- |
| `sourceKind` | `"ftd" \| "hubble" \| "nd" \| "aci" \| "firewall" \| "auto"` | `"auto"` | Exact enum only |
| `sourcetype` | string | omitted | Optional sourcetype selector (`^[A-Za-z0-9][A-Za-z0-9:._-]{0,79}$`) |
| `dropWarnCount` | integer | `1` | `1` – `1000000` |

Unknown keys or out-of-range values fail closed at profile validation time.

## 4. Field Grounding & Security Boundaries

- **Server-side bounding & projection:** Every search emits `| head <maxRows + 1>` before `| table <allowlisted fields>` (with `| spath` after `| head` for Hubble JSON and Nexus Dashboard `stats{}` arrays), dropping `_raw` at the indexers.
- **Unquoted dotted search predicates:** Hubble base searches use unquoted `flow.verdict="DROPPED"` predicates so Splunk JSON field matching functions accurately.
- **Truthful absence vs. coverage:** Zero observed drops reports **None observed** (`"No drops observed in configured sources."`) and never claims traffic was delivered. Capped-empty searches (`rows.length === 0 && capped`) report **Unknown / Partial** instead of **None observed**. Missing service/port or packet counters render **Not covered** rather than `"—"` or `0`.
- **Sensitive fields:** Global `FORBIDDEN_SENSITIVE_FIELDS` (`_raw`, `cookie`, `form_data`, `uri_query`, `sql_statement`, `bind_variable_value`, `content`, `community`, `value_raw`, `varbind_list`, `login`, `password`, `src_content`, `dest_content`) and row-expansion user identifiers are never projected.

## 5. Verification Checklist

1. Confirm drop events exist in the target index (`index=cisco_secure_fw sourcetype="cisco:sfw:estreamer" AC_RuleAction="*Block*" | head 5 | table _time Device InitiatorIP ResponderIP ResponderPort AC_RuleAction AccessControlRuleName`).
2. Open **Application Atlas → Protocols → Blocked Traffic & Drops**, choose scope and UTC window, and click **Investigate**.
3. Verify each source displays its native enforcer (`FTD`, `Hubble`, `Nexus Dashboard`, `ACI`, `Firewall`) and native rule/reason, `HeatMatrix` shows `Source × Destination` drops, and clicking a row opens the detail drawer with a bounded raw-events Splunk link.

## PseudoCo Live Validation

- **Verdict:** **Live verified**
- **Observed (as `se_demo_readonly`, scope `pseudoco-dc1`):** `44 of 44` blocked flows attributed (`FTD Block`, `243` drop events, `1.2k` dropped packets) from live `cisco:sfw:estreamer` (`fmcv01.pseudo.co`). Nexus Dashboard `stats{}.dropPktCount>0` brace-field SPL is also lab-verified (`tests/splunk/test_protocol_lenses.py::test_drops_nd_brace_field_search_returns_only_drop_rows`).

