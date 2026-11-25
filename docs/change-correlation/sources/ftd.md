# FTD eStreamer connection observations

## Collection and qualification boundary

Cisco Security Cloud Add-on for Splunk 3.7.2 remains the preferred package for
FTD eStreamer. Its ConnectionEvent request includes `HeaderFieldSet`,
`ConnectionKeySet`, and `DetailFieldSet`, with explicit `Device`, `DeviceIP`,
and `DeviceSerialNumber` fields. The TA adds `SourceHost` from its configured
FMC host and otherwise writes the returned event JSON unchanged. Static source
references are `fw_estreamer/utils.py:103-116` and
`fw_estreamer/collect_events.py:150-164` in the reviewed 3.7.2 package.

`adapt_ftd_connection_records` accepts a sidecar record containing three
separate values: a trusted indexed `event_fingerprint`, the record's actual
Splunk `_indextime`, and a parsed `native_event` JSON object. The caller must
obtain the fingerprint from a trusted indexed-event query; this adapter checks
its lowercase SHA-256 shape but cannot independently prove how it was made.
`ConnectionID` is retained only as an optional attribute and never becomes the
event identity. The collection `authority` must be the configured FMC host
value, and every native `SourceHost` must match it exactly. `SourceHost` is the
TA's FMC collector host, not the managed FTD identity.

The result is an `ftd/connection_observation` collection of `operational`
observations. Each object's `observed_at` comes from the separately supplied
`_indextime`; collection `received_at` remains the time the export batch was
received. `DeviceIP` is required and validated as one IP address. `DeviceUUID`,
`DeviceSerialNumber`, `InstanceID`, and `ConnectionID` are optional. The
reported initiator/responder IPs, ports, and protocol are copied as reported;
present IPs must be individual literals, ports must be integers from 0 through
65535, and multivalue or malformed fields fail closed. Missing tuple members
remain null. No direction or original-address alias is inferred.

Only `FirewallPolicy` and `FirewallRule` names are retained, when present.
`FirewallPolicyUUID`, `FirewallRuleID`, action IDs, monitor-rule lists, and
other policy identities are not projected. The reviewed TA request does not
explicitly enumerate those identifiers; Cisco says the precise predefined
field-set expansion is in the FMC's version-specific `EventCatalog.json`.
Even when a rule name is present, it is context only: the action associated
with a connection can reflect Security Intelligence or intrusion/file
inspection, so a `Block` does not identify which inspection layer denied the
traffic or prove the displayed rule was the denying rule. No policy/rule
identity join is performed.

## Reported action and times

The adapter preserves only the documented `AC_RuleAction` values and maps
them conservatively:

| Native `AC_RuleAction` | `reported_action` | `outcome` |
| --- | --- | --- |
| `Block`, `Block with reset` | Exact source value | `reported_block` |
| `Allow`, `Trust` | Exact source value | `reported_allow_trust` |
| `Interactive Block`, `Interactive Block with reset` | Exact source value | `interactive_initial_block` |
| `Fastpath` | Exact source value | `fastpath` |
| `Default Action` | Exact source value | `unknown` |
| Missing, blank, or unrecognized value | null | `unknown` |

Cisco documents `Allow` as explicitly allowed or allowed after a user bypasses
an interactive block; `Trust` as access-control trusted. `Block` and `Block
with reset` represent blocked connections. A connection blocked by intrusion
or file inspection can still report `Block` even when an access-control Allow
rule invoked inspection. Interactive Block values describe the initial HTTP
request block; a later record after user bypass may report `Allow`. `Fastpath`
is a prefilter fast-path action, not an allow alias. `Default Action` does not
state the configured policy result. Blank means the connection ended before a
rule match was possible. Missing, blank, default, and future/unrecognized
values never imply permission.

`FirstPacketSecond` is required and retained as `first_packet_at`, the Unix
time of the session's first packet. It is not used as the event time.
`EventSecond`, when present, is separately retained as `event_detected_at` and
the normalized `event_at`. If absent, event time remains unknown; it is never
filled from FirstPacketSecond or `_indextime`. The TA's `props.conf` timestamp
prefix accepts `FirstPacketSecond`, `EventSecond`, or `ts` and the TA does not
set an event time in `smi.Event`; verify the effective indexed `_time` against
the target's actual event shape before using it. The public FQE guide says
`ConnectionDuration` is syslog-only; this adapter does not invent an eStreamer
end time.

## Source limits

The adapter projects only the frozen FTD observation fields. Unreviewed native
fields, including NAT tuples, bytes, packets, and raw payloads, are discarded.
It does not change traffic totals, construct backend hand-offs, or derive
firewall policy history. It does not assert complete device telemetry or
coverage from the fact that a Splunk export completed. Keep collection status,
window, and permissions evidence explicit in the receipt.

The fixture
`fixtures/change-correlation/ftd/connection_event_fqe74_doc_shaped_synthetic.json`
is synthetic and shaped from the inspected TA 3.7.2 request and Cisco FQE 7.4
documentation. Its event fingerprints and receipt times are placeholders. It
is not a native sample, Splunk capture, or live qualification. In particular,
the public detailed eStreamer FQE guide found for this work is version 7.4;
there is no claim that a target FMC/FTD 7.7 event has been verified. The shared
projection remains marked `normalized_export_only` and
`native_sample_unqualified` pending a sanitized TA-produced indexed sample
from the target release, including `SourceHost`, `_indextime`, `_time`,
`event_fingerprint`, and the exact emitted action, identity, and time fields.

## Primary references

- [Cisco Secure Firewall eStreamer FQE 7.4, Available Fully Qualified Events](https://www.cisco.com/c/en/us/td/docs/security/firepower/741/api/FQE/secure_firewall_estreamer_fqe_guide_740/c_available_fqe.html)
- [Cisco Secure Firewall eStreamer FQE 7.4, Understanding the eStreamer Protocol](https://www.cisco.com/c/en/us/td/docs/security/firepower/741/api/FQE/secure_firewall_estreamer_fqe_guide_740/c_estreamer_protocol.html)
- [Cisco FMC 7.7 Administration Guide, Connection and Security-Related Connection Events](https://www.cisco.com/c/en/us/td/docs/security/secure-firewall/management-center/admin/770/management-center-admin-77/events-connection-secint.html)
