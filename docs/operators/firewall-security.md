# Firewall and security team (Cisco FTD / FMC)

**Purpose:** send FTD connection events to Splunk so that conversations crossing the firewall show the firewall as an observation point with its interfaces and zones. This is needed only for application traffic that crosses an FTD, for example to the internet or between VRFs.

## What we need from you

- [ ] An eStreamer client certificate from FMC for the Splunk input host.
- [ ] The Cisco Security Cloud eStreamer input configured for connection events.
- [ ] Connection logging enabled on the access-control rules that carry application traffic.
- [ ] A sample of NAT'd connection events so we can check which addresses the events record.

## Configuration

1. In FMC, create an eStreamer client for the Splunk input host's IP and download its PKCS#12 certificate and password. Use the FMC menu for your version.
2. In Cisco Security Cloud, add an **E-Streamer** input:

| Field | Value |
| --- | --- |
| FMC host | `<fmc-host>` |
| Port | `8302` |
| PKCS certificate / password | from step 1 |
| Event types | Connection (`connection_log`) |
| Sourcetype | `cisco:sfw:estreamer` |
| Index | `cisco_secure_fw` |
| Interval | `600` (default) |

The equivalent `inputs.conf` keys are `fmc_host`, `fmc_port`, `event_types`, `sourcetype`, `index`, `estreamer_import_time_range`, `interval`. Certificate handling is done through the input form.

3. Make sure access-control rules for the application's flows log connections at the end of the connection, so byte counts are complete.

## NAT

The add-on does not extract a translated (post-NAT) address or port from FTD connection events, so the map cannot yet link a public VIP or SNAT address on the firewall to the internal endpoint behind it. Send us events for one DNAT and one SNAT connection. If FMC can include the translated initiator/responder addresses and ports in eStreamer connection events for your version, tell us how it is enabled.

## How to verify

```spl
index=cisco_secure_fw sourcetype="cisco:sfw:estreamer" | stats count by DeviceIP
index=cisco_secure_fw sourcetype="cisco:sfw:estreamer" | head 5
```

## What to send back

- FMC and FTD versions; FTD device names and management IPs (the map uses them to name the firewall).
- Interface and zone names on the path of application traffic.
- Sample DNAT and SNAT connection events (raw JSON from Splunk).

## Open questions

- Does any application traffic cross the FTD inside the data center, or only at the internet edge?
- Is FTD syslog also sent to Splunk? The add-on supports it, but the eStreamer connection events are the ones the map uses.

## Sources

Cisco Security Cloud 3.7.2: `default/inputs.conf:44-50`, `README/inputs.conf.spec` (`sbg_fw_estreamer_input`), `appserver/static/js/build/globalConfig.json` (E-Streamer fields and event types), `default/props.conf:985` (field mappings); NAT gap: `docs/TA_PACKAGE_ANALYSIS.md`.
