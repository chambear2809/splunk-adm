# Splunk Stream / NetFlow owner

**Purpose:** receive NetFlow v9 from the ACI leaves with a Splunk Stream forwarder and index the records, so each conversation shows which leaf saw it and on which ingress interface.

## What we need from you

- [ ] A Stream forwarder (Splunk Add-on for Stream Forwarders) on a host the leaves' out-of-band network can reach over UDP.
- [ ] A NetFlow receiver on that forwarder, restricted to the leaf OOB addresses.
- [ ] The `netflow` stream enabled in the Splunk App for Stream, with the fields below, writing to index `netflow`.
- [ ] The receiver IP and UDP port sent to the ACI team for their exporter.

## Receiver configuration (`Splunk_TA_stream/local/streamfwd.conf` on the forwarder)

```ini
[streamfwd]
netflowReceiver.0.ip = <receiver IP>
netflowReceiver.0.port = <UDP port, e.g. 2055>
netflowReceiver.0.decoder = netflow
netflowReceiver.0.filter = <leaf-101 OOB IP>,<leaf-102 OOB IP>,<leaf-103 OOB IP>
netflowReceiver.0.decodingThreads = 4
netflowReceiver.0.templateExpiry = 3600
```

`filter` limits senders to the listed leaves. `templateExpiry` defaults to 3600 seconds. Size `decodingThreads` to the flow rate.

## Stream definition

In the Splunk App for Stream, enable the **Netflow** stream (it ships disabled), set its index to `netflow`, and keep at least these fields enabled:

```text
src_ip  dest_ip  src_port  dest_port  protoid
bytes  packets
exporter_ip  input_snmpidx  output_snmpidx  ingress_vlan
exporter_sampling_interval  exporter_sampling_mode
flow_start_time  flow_end_time  flow_start_rel  flow_end_rel
observation_domain_id  tcp_flags
```

Stream adds `timestamp` (flow start) and `endtime` (flow end) to each event. ACI records carry the ingress interface only, so `output_snmpidx` is usually empty.

## Sizing

Each exported flow becomes one event. Estimate events per second as active flows per leaf ÷ export interval × number of leaves. Size the forwarder, the `netflow` index and license accordingly. Sampling on the exporter reduces volume; the map scales bytes by `exporter_sampling_interval` when present.

## How to verify

```spl
index=netflow sourcetype=stream:netflow | stats count, dc(src_ip) AS sources by exporter_ip
index=netflow sourcetype=stream:netflow | table _time timestamp endtime exporter_ip src_ip src_port dest_ip dest_port protoid bytes input_snmpidx | head 20
```

Every leaf OOB address should appear as an `exporter_ip`, and `timestamp` should be earlier than or equal to `endtime`.

## Automation skills

Skills from [splunk-cisco-skills](https://github.com/chambear2809/splunk-cisco-skills) render a plan for review, apply only the requested change, and validate it. Run them from Claude Code, Codex or Cursor, or run their scripts directly. Their `main` branch is verified on Splunk Enterprise 10.4; review plans against 10.6 for this pilot.

- [splunk-stream-setup](https://github.com/chambear2809/splunk-cisco-skills/tree/main/skills/splunk-stream-setup): Splunk Stream, stream forwarder (`streamfwd`) and the NetFlow/IPFIX receiver (`netflowReceiver`).

## What to send back

- Splunk Stream and forwarder versions, the receiver IP and port.
- Measured events per second per leaf after one day.
- One hour of sample `stream:netflow` events.

## Open questions

- Is the Stream forwarder in the same OOB network as the leaves, or do firewalls need a UDP rule?
- Do you sample on the leaves? If so, at what rate?

## Sources

Receiver keys: Splunk Add-on for Stream Forwarders 8.1.3 `README/streamfwd.conf.spec:214-236`. NetFlow stream and fields: Splunk App for Stream 8.1.6 `default/streams/netflow` (stream disabled by default; field names). Time fields: Stream Wire Data 8.1.6 `default/props.conf:4-10`. ACI record contents: APIC Management Information Model 6.1(x), NetFlow record policy.
