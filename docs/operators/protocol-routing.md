# Operator Guide: Routing Control Plane (`routing`)

The **Routing Control Plane** lens tracks BGP, OSPF, BFD (plus optional IS-IS, HSRP, and VRRP) peer states, adjacency transition timelines, and flap counts per `(device, vrf, peer_ip, protocol)` across a bounded UTC window.

## 1. Supported Data Sources

| Priority | Sourcetype | Collector | Coverage |
| --- | --- | --- | --- |
| Primary (Syslog) | `cisco:ios`, `cisco:aci` | **SC4S (Splunk Connect for Syslog)** | Recommended syslog collector. Captures `BGP-5-ADJCHANGE`, `OSPF-5-ADJCHG`, `BFD-5-SESSION_STATE_DOWN/UP`, `ISIS`, `HSRP`, and `VRRP` transitions with timestamps and neighbor details. Prefix counts and peer ASNs report **Not covered** when syslog-only. |
| Lab / Fallback (Syslog) | `cisco:dc:nexus9k:syslog`, `cisco:dc:aci:syslog` | Splunk `udp://5514` + Cisco DC Networking TA 2.0.10 (`props.conf` / `transforms.conf`) | Fallback/lab UDP syslog when SC4S is not deployed. Uses TA-extracted `category`, `severity_id`, `mnemonics`, and `syslog_msg`. |
| State / DME | `cisco:dc:nexus9k:dme` (and `cisco:dc:nd:*`) | Cisco DC Networking App for Splunk 2.0.10 (`cisco_nexus_9k` DME / Nexus Dashboard inputs) | Authoritative operational peer state (`operSt`), `peer_asn`, `local_asn`, `prefixes_received`, `flap_count`, VRF, and OSPF `area`. |

## 2. Collector Setup

### Primary Syslog Collector: SC4S (Splunk Connect for Syslog)

1. Deploy **SC4S** on your syslog collection tier and point NX-OS, IOS/IOS-XE, and ACI syslog destinations to the SC4S VIP/port (RFC 3164 or RFC 5424 over TCP/TLS or UDP).
2. SC4S routes Cisco NX-OS/IOS messages to `sourcetype="cisco:ios"` and ACI messages to `sourcetype="cisco:aci"` automatically into your configured network syslog index (for example `cisco_dc` or `netops`).
3. Ensure switches log routing adjacency changes at notice level (`severity 5`) or higher:
   - NX-OS: `logging level bgp 5`, `logging level ospf 5`, `logging level bfd 5`
   - BGP neighbor state logging: `router bgp <asn>` → `log-neighbor-changes`
   - OSPF adjacency logging: `router ospf <tag>` → `log-adjacency-changes detail`

### Lab / Fallback Syslog Collector (`udp://5514`)

When SC4S is unavailable in an isolated lab, configure a Splunk `udp://5514` input with `sourcetype = cisco:dc:nexus9k:syslog` (or `cisco:dc:aci:syslog`) on a host running the Cisco DC Networking 2.0.10 TA so `EXTRACT-fields`, `extract_bfd_fields_9k`, and `extract_ospf_fields_9k` populate `category`, `severity_id`, `mnemonics`, and `syslog_msg`.

### State & Prefix Coverage: Cisco DC Networking 2.0.10 DME

1. Configure a `cisco_nexus_9k` DME input in Cisco DC Networking 2.0.10 (`sourcetype="cisco:dc:nexus9k:dme"`) querying classes `bgpPeerEntry`, `bgpPeer`, `ospfAdjEp`, and `bfdSess`.
2. Send DME events to the same `cisco_dc` index (with `sourceKind: "auto"`) or a dedicated index with a `sourceKind: "dme"` profile.
3. Without DME, prefix counts (`prefixes_received`) and peer ASNs explicitly display **Not covered** — never synthetic zeros.

## 3. Profile Configuration (`adm_protocol_profiles`)

Create one or more profiles for `lens: "routing"` under a scope (for example `dc-east`):

```json
{
  "id": "routing-dc-east",
  "lens": "routing",
  "scope": "dc-east",
  "index": "cisco_dc",
  "observer": "sc4s-dc-east",
  "validFrom": 1700000000,
  "validUntil": 1900000000,
  "extra": {
    "sourceKind": "auto",
    "flapWarnCount": 2,
    "protocolFilter": "all"
  }
}
```

### Validated `extra` Keys (Fail-Closed)

| Key | Type | Default | Allowed Range / Values |
| --- | --- | --- | --- |
| `sourceKind` | `"syslog" \| "dme" \| "auto"` | `"auto"` | `"auto"` queries both syslog and DME on the profile index; `"syslog"` or `"dme"` restricts to one collector class. |
| `flapWarnCount` | integer | `2` | `[1, 1000]` — peers with `flapCount ≥ flapWarnCount` are flagged `Attention`. |
| `protocolFilter` | `"all" \| "bgp" \| "ospf" \| "bfd"` | `"all"` | Exact enum only. |

Unknown keys or out-of-range values fail closed during profile validation.

## 4. Field Grounding & Security Boundaries

- **TA & Adapter Grounding:** Syslog searches use `buildSyslogStateSearch` and `normalizeSyslogRow` (`frontend/src/protocols/shared/adapters/nxosSyslog.ts`), which strip AAA/auth categories (`AUTH`, `AUTHPRIV`, `AAA`, `DAEMON`, `VSHD`, `SEC_LOGIN`, `SSH`) and config-change mnemonics (`VSHD_SYSLOG_CONFIG_I`, `CONFIG_I`, `CFGLOG_LOGGEDCMD`, etc.) both in SPL and client-side.
- **Server-side Projection:** DME queries emit `| head <maxRows + 1>` before `| eval` and `| table <allowlisted fields>`, bounding indexer work and dropping `_raw`, `password`, and all unallowlisted attributes server-side.
- **Degraded Coverage:** If any configured profile returns `blocked` or `unavailable`, 0-row runs report `Unknown` (`blocked` / `unavailable` banner) rather than `None observed`, and partial multi-source runs surface a cause-specific `Partial` banner.
- **Role Scoping (`splunk_app/splunk_adm/metadata/default.meta`):** `adm_protocol_profiles` and app objects are readable by `adm_investigate`, `adm_viewer`, `admin`, and `sc_admin`, and writable only by `admin` and `sc_admin`.

## 5. Verification Checklist

1. Confirm SC4S or DCN TA events exist in the target index:
   `index=<index> (sourcetype="cisco:ios" OR sourcetype="cisco:dc:nexus9k:syslog" OR sourcetype="cisco:dc:nexus9k:dme") | head 5 | table _time host sourcetype category mnemonics syslog_msg dn operSt`
2. Open **Application Atlas → Protocols → Routing Control Plane**, select the configured scope and UTC window, and click **Investigate**.
3. Confirm:
   - Down or flapping peers sort to the top of Overview and appear in the **Adjacency transitions** swimlane timeline.
   - The **Matrix** tab renders both the **Device ↔ peer adjacencies** graph (`AdjacencyOverlay`) and **Device × peer routing state** grid (`HeatMatrix`).
   - Selecting any peer opens the detail drawer with Status chip first, copyable peer IP, VRF, ASN, state, flap count, recent mnemonics, and a bounded **Open raw events in Splunk** link.

## PseudoCo Live Validation

- **Verdict:** **Live verified**
- **Observed (as `se_demo_readonly`, scope `pseudoco-dc1`):** `14 of 14` BGP sessions healthy (`Established`, `0` flaps) across all 6 Nexus switches (`198.18.131.1..6`) from live DCN 2.0.10 `cisco:dc:nexus9k:dme` (`bgpPeerEntry`).

