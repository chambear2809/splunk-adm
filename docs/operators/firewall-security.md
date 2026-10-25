# Firewall and security team (Cisco FTD / FMC)

**Purpose:** send FTD connection events to Splunk so that conversations crossing the firewall show the firewall as an observation point with its ingress/egress interface observations. This is needed only for application traffic that crosses an FTD, for example to the internet or between VRFs.

For source selection and release limits, see [deployment options](deployment-options.md). Skip this setup when the selected application traffic does not cross an FTD. Other traffic feeds can still contribute conversations. Missing FTD observations do not prove that a firewall allowed or denied a connection.

## What we need from you

- [ ] An eStreamer client certificate from FMC for the Splunk input host.
- [ ] The Cisco Security Cloud eStreamer input configured for connection events.
- [ ] Connection logging enabled on the access-control rules that carry application traffic.
- [ ] A sanitized sample of NAT'd connection events so we can check which addresses the deployed FMC/FTD actually emits.

## Configuration

1. In FMC, create an eStreamer client for the Splunk input host's IP and download its PKCS#12 certificate and password. Use the FMC menu for your version.
2. In Cisco Security Cloud, add an **E-Streamer** input:

| Field                       | Value                         |
| --------------------------- | ----------------------------- |
| FMC host                    | `<fmc-host>`                  |
| Port                        | `8302`                        |
| PKCS certificate / password | from step 1                   |
| Event types                 | Connection (`connection_log`) |
| Sourcetype                  | `cisco:sfw:estreamer`         |
| Index                       | `cisco_secure_fw`             |
| Interval                    | `600` (default)               |

The equivalent `inputs.conf` keys are `fmc_host`, `fmc_port`, `event_types`, `sourcetype`, `index`, `estreamer_import_time_range`, `interval`. Certificate handling is done through the input form.

3. Make sure access-control rules for the application's flows log connections at the end of the connection, so byte counts are complete.

## NAT

Cisco's eStreamer ConnectionEvent field set documents `NAT_InitiatorIP`, `NAT_InitiatorPort`, `NAT_ResponderIP` and `NAT_ResponderPort` as translated tuple fields. `OriginalInitiatorIP` is a separate field; the app does not label `InitiatorIP` categorically as the original endpoint. Cisco notes passthrough tunnel events can report tunnel endpoints in the base initiator/responder fields. The inspected TA versions request a `DetailFieldSet` containing these fields, but their explicit `props.conf` mappings do not add NAT aliases. Splunk's default automatic JSON extraction can expose raw JSON values, so Application Atlas conditionally preserves a complete, changed tuple from the same event.

This evidence is shown on the existing firewall conversation with its mapped scope, reporting device, event fingerprint, event time and Splunk receipt time. Incomplete, malformed, multivalue, unmapped or unchanged tuples are not shown. It does not change traffic counters, join observations across events or devices, or select a Kubernetes/load-balancer backend. The graph filters each tuple against Splunk's effective `addinfo` event-time bounds. Direct `adm_graph` callers must pass absolute earliest and latest bounds aligned to whole milliseconds; extra trailing decimal zeroes are harmless. Finer absolute precision is unsupported at either edge, while relative bounds are resolved natively by Splunk. In the local Splunk 10.6.0.5 probe, earliest `N+0.0005` produced `info_min_time=N.000` and included event `N`, while latest `N+0.0005` produced `info_max_time=N.000` and excluded event `N`. This tested-image result shows that finer-than-millisecond precision can widen the effective start or narrow the effective end; it is not a release-wide guarantee. See the [data-layer precision and correlation limits](../DATA_LAYER.md#ftd-nat-evidence). V2 is staged and does not currently project this field, and preservation across a V1-to-V2 cutover is unqualified. The local synthetic fixture validates parsing only; representative live eStreamer emission has not been qualified. Send sanitized events for one DNAT and one SNAT connection so the deployed FMC/FTD version, settings and emitted values can be confirmed.

Field references: [Cisco Connection Event field definitions](https://www.cisco.com/c/en/us/td/docs/security/firepower/741/api/FQE/secure_firewall_estreamer_fqe_guide_740/c_available_fqe.html), [Cisco eStreamer OutputFieldSet protocol](https://www.cisco.com/c/en/us/td/docs/security/firepower/741/api/FQE/secure_firewall_estreamer_fqe_guide_740/c_estreamer_protocol.html), [Splunk automatic JSON extraction](https://help.splunk.com/en/splunk-cloud-platform/manage-knowledge-objects/knowledge-management-manual/10.4.2604/use-the-configuration-files-to-configure-field-extractions/configure-automatic-key-value-field-extraction), and the inspected local package paths in [TA package analysis](../TA_PACKAGE_ANALYSIS.md#cisco-security-cloud-four-requested-products-in-one-package).

## How to verify

```spl
index=cisco_secure_fw sourcetype="cisco:sfw:estreamer" | stats count by DeviceIP
index=cisco_secure_fw sourcetype="cisco:sfw:estreamer" | head 5
```

## Automation skills

Skills from [splunk-cisco-skills](https://github.com/chambear2809/splunk-cisco-skills) render a plan for review, apply only the requested change, and validate it. Run them from Claude Code, Codex or Cursor, or run their scripts directly. Use the vendored commit rather than assuming upstream `main` matches it. Check the exact skill/package release status and guardrails in [SPLUNK_ENTERPRISE_10_6_COMPATIBILITY.md](https://github.com/chambear2809/splunk-cisco-skills/blob/1c93cd87b5a97fe54a2b3284b1d2c43034413edd/SPLUNK_ENTERPRISE_10_6_COMPATIBILITY.md) and follow any documented guardrails before applying.

- [cisco-security-cloud-setup](https://github.com/chambear2809/splunk-cisco-skills/tree/1c93cd87b5a97fe54a2b3284b1d2c43034413edd/skills/cisco-security-cloud-setup): Cisco Security Cloud inputs, including the FTD eStreamer input, indexes and product flows.

## What to send back

- FMC and FTD versions; FTD device names and management IPs (the map uses them to name the firewall).
- Interface names on the path of application traffic. Zone names may be retained as raw source context but are not displayed by the current FTD map contract.
- Sample DNAT and SNAT connection events (raw JSON from Splunk).

## Open questions

- Does any application traffic cross the FTD inside the data center, or only at the internet edge?
- Is FTD syslog also sent to Splunk? The add-on supports it, but the eStreamer connection events are the ones the map uses.

## Sources

Cisco Security Cloud 3.6.5 and 3.7.2: `bin/CiscoSecurityCloud/fw_estreamer/utils.py` requests `DetailFieldSet` for ConnectionEvent; `default/inputs.conf:44-50`, `README/inputs.conf.spec` (`sbg_fw_estreamer_input`), `appserver/static/js/build/globalConfig.json` (E-Streamer fields and event types), `default/props.conf:985` (initiator/responder aliases only). See [TA package analysis](../TA_PACKAGE_ANALYSIS.md#cisco-security-cloud-four-requested-products-in-one-package) for the inspected field-set definition and live-emission limitation.
