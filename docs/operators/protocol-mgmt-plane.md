# Operator Guide: Management-Plane Hygiene (`mgmt_plane`)

**Status:** Staged (synthetic fixture-verified; not yet qualified against a live deployed feed)

The **Management-Plane Hygiene** lens aligns with DoD STIG and NetBrain management-plane practices to surface SNMPv1/v2c usage, SNMP SET write operations, cleartext FTP/Telnet/TFTP/HTTP management sessions, and per-device syslog receipt gaps across a bounded UTC window.

## 1. Supported Data Sources

| Priority | Sourcetype | Collector | Coverage |
| --- | --- | --- | --- |
| Primary (SNMP) | `stream:snmp` | Splunk Stream (`Splunk_TA_stream` / `splunk_app_stream` 8.1.6+) | SNMP protocol version (`v1`, `v2c`, `v3`), PDU operation (`GetRequest`, `GetBulkRequest`, `SetRequest`), source manager IP, target device IP, status, and byte/timing counters. |
| Primary (FTP) | `stream:ftp` | Splunk Stream (`Splunk_TA_stream` / `splunk_app_stream` 8.1.6+) | Cleartext FTP sessions (`command`, `reply_code`, `status`, `src_ip`, `dest_ip`, `bytes_in`, `bytes_out`, `time_taken`). |
| Primary (Cleartext Flows) | `stream:netflow` | Splunk Stream (`streamfwd` NetFlow receiver) | Filtered before `| head` on cleartext management ports: FTP (`21`), Telnet (`23`), TFTP (`69`), SNMP (`161`/`162`), and HTTP (`80`), optionally scoped by `mgmtIps` or `filter.dst`/`filter.device`. |
| Primary (Syslog) | `cisco:ios`, `cisco:aci` | **SC4S (Splunk Connect for Syslog)** | Recommended syslog collector for NX-OS, IOS/IOS-XE, and ACI receipt-gap monitoring (`stats max(_time) AS last_seen count BY host sourcetype`). |
| Fallback (Syslog) | `cisco:dc:nexus9k:syslog`, `cisco:dc:aci:syslog` | Cisco DC Networking 2.0.10 TA (UDP/TCP syslog on Heavy Forwarder or SC4S `splunk_metadata.csv` override) | Pre-extracted syslog timestamps and categories when SC4S is not deployed. |

## 2. Syslog Collection & Receipt Gap Semantics (SC4S Primary vs. UDP Fallback)

### Recommended: SC4S (Splunk Connect for Syslog)

1. Configure network devices (`logging server <sc4s-ip> 5` on NX-OS; syslog destination group on ACI) to send syslog over TLS or RFC5424/3164 to SC4S.
2. SC4S assigns `sourcetype="cisco:ios"` (NX-OS/IOS) or `sourcetype="cisco:aci"` (ACI) and strips syslog transport headers.
3. Application Atlas excludes AAA/auth categories (`AUTH`, `AUTHPRIV`, `AAA`, `DAEMON`, `VSHD`, `SEC_LOGIN`, `SSH`) and aggregates `stats max(_time) AS last_seen count BY host sourcetype` before `| head` so chatty switches cannot crowd quiet devices out of the row cap.

### Lab / Fallback: Heavy Forwarder Syslog Input

If SC4S is not deployed in a lab or staging environment, terminate UDP/TCP syslog on a dedicated Splunk Heavy Forwarder with `sourcetype = cisco:dc:nexus9k:syslog` (or `cisco:dc:aci:syslog`). Avoid sending raw UDP syslog directly to Splunk Cloud indexers.

### Why "Receipt gap" is NEVER Labeled "Device down"

A syslog **Receipt gap** means a device stopped delivering syslog events for at least `receiptGapMinutes` (default `15` min) before the latest peer syslog event while one or more peer devices continued reporting. **Syslog stopped arriving while peers continued reporting; this does not prove the device is down.** Common non-outage causes include:

- An upstream SC4S, syslog-ng, or Heavy Forwarder queue stall or restart
- A management VRF / ACL change blocking UDP/514 or TLS/6514
- A device logging buffer or `logging source-interface` change, or simply a quiet control plane

If fewer than 2 devices report syslog in the selected UTC window, Application Atlas cannot establish a peer baseline and marks receipt-gap coverage **Not covered** (informational only — never a false-positive alert).

## 3. Enabling Splunk Stream `snmp` and `ftp` (Estimate Mode vs. Enabled)

In Splunk App for Stream 8.1.6, `snmp` and `ftp` streams may be configured in **Estimate mode** (`statsOnly: true`), which writes volume telemetry to `index=_internal sourcetype="stream:stats"` without indexing `stream:snmp` or `stream:ftp` events.

1. Confirm a capture interface (`sniffer.captures`) is attached to `streamfwd` on your tap/SPAN host covering out-of-band or in-band management segments.
2. In Splunk App for Stream (**Configuration → Configure Streams → snmp** and **ftp**), switch both streams from **Estimate** (`statsOnly: true`) to **Enabled** (`statsOnly: false`) and assign your target index (for example `netflow` or `stream`).
3. Keep credential and community capture disabled; Application Atlas never selects those fields in SPL.

### On-Demand Estimate-Mode Check

Application Atlas never runs searches on page load. When an operator clicks **Investigate** and `stream:snmp` or `stream:ftp` completes with 0 rows, or clicks **Check Stream mode** in the banner, Atlas inspects `index=_internal sourcetype="stream:stats"` (`senders{}.streams{}.id` and `senders{}.streams{}.stats_only`) and reports whether `snmp` or `ftp` is in Estimate mode.

## 4. Privacy & Security Guarantees

Application Atlas enforces a strict server-side projection and static SPL guard (`LENS_FIELD_ALLOWLISTS.mgmt_plane` and `FORBIDDEN_SENSITIVE_FIELDS`):

- **SNMP privacy:** `community`, `value_raw`, `varbind_list`, `payload`, and `_raw` are **never** selected, filtered on, or referenced in SPL or returned rows.
- **FTP privacy:** `login`, `password`, `passwd`, `authorization`, `content`, `src_content`, `dest_content`, and `_raw` are **never** selected, filtered on, or referenced in SPL or returned rows. Furthermore, `buildMgmtFtpSearch` strips `command`/`method` down to the first uppercase verb inside SPL before `| table` and redacts `USER`, `PASS`, and `ACCT` to `AUTH_CMD` so credential arguments never cross the wire.
- **Syslog privacy:** `_raw`, `syslog_msg`, and AAA/authentication syslog categories (`AUTH`, `AUTHPRIV`, `AAA`, `DAEMON`, `VSHD`, `SEC_LOGIN`, `SSH`) are excluded before `| head`.
- **Bounded server-side projection:** Every search emits `| head <maxRows + 1>` before `| table <allowlisted fields>`, bounding rows at the indexers and dropping `_raw` server-side.

## 5. Profile Configuration (`adm_protocol_profiles`)

Configure either an `auto` profile (when sourcetypes share an index) or source-specific profiles under the same `scope`:

```json
{
  "id": "mgmt-plane-dc1",
  "source": "protocol_mgmt_plane",
  "lens": "mgmt_plane",
  "scope": "prod:dc1",
  "index": "netflow",
  "observer": "stream-fwd-01",
  "validFrom": 1764243000,
  "validUntil": 1764250200,
  "extra": {
    "sourceKind": "auto",
    "receiptGapMinutes": 15,
    "flagSnmpV2c": true,
    "flagHttpPort80": true,
    "mgmtIps": ["192.0.2.10", "192.0.2.11", "192.0.2.12"]
  }
}
```

### Validated `extra` Keys (Fail-Closed)

| Key | Type | Default | Allowed Range |
| --- | --- | --- | --- |
| `sourceKind` | `"auto" \| "stream_snmp" \| "stream_ftp" \| "netflow" \| "syslog"` | `"auto"` | Exact enum only |
| `receiptGapMinutes` | integer | `15` | `[5, 1440]` |
| `flagSnmpV2c` | boolean | `true` | `true` or `false` |
| `flagHttpPort80` | boolean | `true` | `true` or `false` |
| `mgmtIps` | `string[]` | `[]` | Up to 64 IPv4/IPv6 literals |

Unknown keys or out-of-range values fail closed during profile parsing.

## 6. Verification Checklist

1. Verify management-plane sources in Splunk:
   - `index=<netflow_index> sourcetype="stream:snmp" | head 5 | table _time src_ip dest_ip snmp_version pdu_type status`
   - `index=<netflow_index> sourcetype="stream:ftp" | head 5 | table _time src_ip dest_ip command reply_code status`
   - `index=<netflow_index> sourcetype="stream:netflow" (dest_port=21 OR dest_port=23 OR dest_port=69 OR dest_port=161 OR dest_port=162 OR dest_port=80) | head 5 | table _time exporter_ip src_ip dest_ip dest_port bytes`
   - `index=<syslog_index> (sourcetype="cisco:ios" OR sourcetype="cisco:dc:nexus9k:syslog" OR sourcetype="cisco:aci" OR sourcetype="cisco:dc:aci:syslog") | stats max(_time) AS last_seen count BY host sourcetype | head 5 | table host sourcetype last_seen count`
2. Open **Application Atlas → Protocols → Management-Plane Hygiene**, select the scope and UTC window, and click **Investigate**.
3. Confirm SNMPv1/v2c, SNMP SET writes, cleartext FTP/Telnet/TFTP/HTTP sessions, and **Receipt gap** rows sort first, populate the `Findings by category` distribution bar and Manager × Target matrix, and open with remediation guidance and `literal()`-quoted raw-event links in the Detail drawer.
