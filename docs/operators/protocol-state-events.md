# Operator Guide: Network State-Change Timeline (`state_events`)

The **State-Change Timeline** lens answers *"what changed on the network in this window?"* by correlating operational state transitions across link, routing (`BGP`, `OSPF`, `IS-IS`, `BFD`), L2 (`STP`, `LACP`/port-channel), first-hop redundancy (`HSRP`, `VRRP`), multicast (`PIM`), and Cisco ACI `faultInst` / `eventRecord` telemetry onto one chronological swimlane per device.

## 1. Supported Data Sources

| Priority | Sourcetype | Collector | Coverage |
| --- | --- | --- | --- |
| Primary (Syslog) | `cisco:ios`, `cisco:aci` | **SC4S (Splunk Connect for Syslog)** | **Recommended production syslog collector.** Routes NX-OS, IOS/IOS-XE, and ACI syslog messages into Splunk over TCP/TLS or UDP without a heavy-forwarder UDP listener. Extracts facility, severity, mnemonic, and message body via `buildSyslogStateSearch`. |
| Lab / Fallback (Syslog) | `cisco:dc:nexus9k:syslog`, `cisco:dc:aci:syslog` | Splunk `udp://5514` + Cisco DC Networking TA 2.0.10 | Lab fallback when SC4S is not deployed. Relies on TA `props.conf` / `transforms.conf` extractions (`category`, `severity_id`, `mnemonics`, `syslog_msg`, `interface`, `neighbor_ip`, `vrf`). |
| ACI Faults & Events | `cisco:dc:aci:fault`, `cisco:dc:aci:event`, `cisco:dc:aci:class` (`faultInst`, `eventRecord`) | Cisco DC Networking App for Splunk (`cisco_nexus_aci` classInfo / fault inputs) | Captures APIC `faultInst` and `eventRecord` records (`code`, `severity`, `domain`, `cause`, `lifecycle`, `affected`, `dn`, `descr`, `created`, `lastTransition`). Unrelated `cisco:dc:aci:class` inventory classes (such as `topSystem`) are ignored. |

## 2. Collector Setup

### Primary Production Syslog Collector: SC4S (Splunk Connect for Syslog)

1. Deploy **SC4S** on your syslog collection tier and configure NX-OS (`logging server <sc4s-vip> 5 use-vrf management`), IOS/IOS-XE, and APIC syslog destinations to send RFC 3164 or RFC 5424 syslog over TCP/TLS (or UDP) to SC4S.
2. SC4S automatically assigns `sourcetype="cisco:ios"` for NX-OS/IOS devices and `sourcetype="cisco:aci"` for ACI fabric nodes.
3. Ensure switches log operational state changes at Notice (`5`) or higher:
   - NX-OS interfaces & port-channels: `logging level ethpm 5`, `logging level lacp 5`
   - Routing & BFD: `logging level bgp 5`, `logging level ospf 5`, `logging level bfd 5`, `logging level isis 5`
   - L2 & FHRP / Multicast: `logging level stp 5`, `logging level hsrp 5`, `logging level vrrp 5`, `logging level pim 5`

### Lab Fallback Syslog Collector (`udp://5514`)

When SC4S is unavailable in an isolated lab, configure a Splunk `udp://5514` input on a Heavy Forwarder running the Cisco DC Networking TA with `sourcetype = cisco:dc:nexus9k:syslog` (or `cisco:dc:aci:syslog`). Avoid terminating raw unauthenticated UDP syslog directly on Splunk Cloud indexers.

### ACI `faultInst` and `eventRecord` Collection

1. Enable `faultInst` and `eventRecord` polling in your Cisco DC Networking ACI modular input (`cisco:dc:aci:fault`, `cisco:dc:aci:event`, or `cisco:dc:aci:class` with `component="faultInst"` / `"eventRecord"`).
2. Send ACI fault/event records to the same scope index (for `"sourceKind": "auto"`, `"includeAci": true`) or configure a dedicated profile with `"sourceKind": "aci_faults"`.
3. To query syslog only without ACI, set `"includeAci": false` (or `"sourceKind": "syslog"` with `"includeAci": false`).

### Qualification Note: HSRP & VRRP

HSRP and VRRP state transitions stay on the **syslog** collection path (`%HSRP-*` / `%VRRP-*`). NX-OS DME HSRP/VRRP classes are not qualified in the TA schema and are not queried.

## 3. Profile Configuration (`adm_protocol_profiles`)

Create one or more profiles for `lens: "state_events"` under a scope (for example `prod:dc1`):

```json
{
  "id": "state-events-dc1",
  "lens": "state_events",
  "scope": "prod:dc1",
  "index": "cisco_dc",
  "observer": "sc4s-dc1",
  "validFrom": 1700000000,
  "validUntil": 1900000000,
  "extra": {
    "sourceKind": "auto",
    "burstWarnCount": 5,
    "maxSeverityAttention": 3,
    "includeAci": true
  }
}
```

### Validated `extra` Keys (Fail-Closed)

| Key | Type | Default | Allowed Range / Values |
| --- | --- | --- | --- |
| `sourceKind` | `"auto" \| "syslog" \| "aci_faults"` | `"auto"` | `"auto"` queries both operational syslog and ACI `faultInst`/`eventRecord`; `"syslog"` or `"aci_faults"` restricts to one source family. |
| `burstWarnCount` | integer | `5` | `[1, 1000]` — devices with `eventCount ≥ burstWarnCount` are flagged `Attention`. |
| `maxSeverityAttention` | integer | `3` | `[0, 7]` — syslog or ACI events with numeric severity `≤ maxSeverityAttention` (`3` = Error or worse: Emergency `0`, Alert `1`, Critical `2`, Error `3`) flag the device `Attention`. |
| `includeAci` | boolean | `true` | Exact boolean. When `false`, excludes ACI syslog (`cisco:aci`, `cisco:dc:aci:syslog`) and skips ACI `faultInst`/`eventRecord` queries. Contradictory `{ "sourceKind": "aci_faults", "includeAci": false }` fails validation. |

Unknown keys or out-of-range values fail closed during profile validation.

## 4. Security Boundaries & Evidence Honesty

- **Config-Change & AAA/Auth/Audit Exclusion:** Both SPL (`buildSyslogStateSearch` / `buildStateSyslogSearch`) and client-side normalizers (`normalizeSyslogRow`, `normalizeStateSyslogRow`, `normalizeAciFaultEventRow`) exclude configuration-change mnemonics (`VSHD_SYSLOG_CONFIG_I`, `CONFIG_I`, `USER_CONFIG`, `SYSTEM_CONFIG`, `COPY_RUNNING_STARTUP`, `CFGLOG_LOGGEDCMD`), authentication/AAA categories (`AUTH`, `AUTHPRIV`, `AAA`, `DAEMON`, `VSHD`, `SEC_LOGIN`, `SSH`), and ACI audit/session categories (`AUDIT`, `SESSION`, `LOGIN`) so usernames and CLI/APIC audit trails never leak into operational state timelines.
- **Server-Side Projection & Row Caps:** Every search emits `| head <maxRows + 1>` before `| table <allowlisted fields>` (strictly within `LENS_FIELD_ALLOWLISTS.state_events`), dropping `_raw` and all sensitive fields server-side with no post-`| head` `| where` filtering.
- **Degraded Coverage:** If any source returns `blocked`, `unavailable`, or hits the row cap (`partial`), 0-event runs report `Unknown` (never `None observed`), and Matrix cells without observed events switch from `None observed` to `Unknown`.

## 5. Verification Checklist

1. Verify SC4S or DCN TA events exist in the target index:
   `index=<index> (sourcetype="cisco:ios" OR sourcetype="cisco:dc:nexus9k:syslog" OR sourcetype="cisco:aci" OR sourcetype="cisco:dc:aci:fault") | head 5 | table _time host sourcetype category mnemonics code severity descr syslog_msg`
2. Open **Application Atlas → Protocols → State-Change Timeline**, select the configured scope and UTC window, and click **Investigate**.
3. Confirm:
   - Overview shows a single-sentence verdict, up to 4 KPI tiles, flagged-first device rows with `Show all (N)`, the chronological **Device timeline** (`SwimlaneTimeline`), and the **Operational domains** distribution bar.
   - Matrix shows **Device × operational domain** (`HeatMatrix`) with `None observed` when uncapped and `Unknown` when capped or partial.
   - Clicking any device row, timeline dot, or matrix cell opens the detail drawer with Status first, transition history, the HSRP/VRRP syslog qualification note, and a `literal()`-quoted **Open raw events in Splunk** link.

## PseudoCo Live Validation

- **Verdict:** **Live verified** (NX-OS DME `faultInst` + SC4S `cisco:ios` & `udp://5514` syslog)
- **Observed (as `se_demo_readonly`, scope `pseudoco-dc1`):** `3` deduplicated NX-OS DME `faultInst` records (`F1680` across `198.18.131.3` and `198.18.131.4`, deduplicated server-side by `(device, dn, code, lifecycle)` while keeping ACI `faultInst`/`eventRecord` distinct via `_cd|splunk_server|index`). SC4S 3.49.0 (`atlas-sc4s.service`, UDP/TCP `5515` → HEC `atlas-sc4s-syslog`) verified end-to-end routing NX-OS syslog into `index=cisco_dc` with `sourcetype="cisco:ios"` alongside existing `udp://5514` (`cisco:dc:nexus9k:syslog`).

