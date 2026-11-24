# Multicast source qualification

The Stream IGMP and multicast NetFlow adapters have been exercised against package definitions, synthetic fixtures and one indexed lab cohort. The examples in `fixtures/multicast/candidates.json` are synthetic, and `fixtures/raw/stream_netflow.ndjson` contains synthetic unicast traffic. Verify actual multicast events and indexed extraction under the caller's role before relying on either adapter in another deployment.

Static evidence inspected: Splunk App for Stream 8.1.6 `default/streams/igmp` lists `type`, `multicast_address`, and group-record fields, with group-record fields and source addresses marked `isList`; it does not establish how parallel lists or nested sources appear in indexed JSON. `default/streams/netflow` lists `exporter_ip`, `src_ip`, `dest_ip`, `bytes`, and `packets`. The extracted Stream Forwarders 8.1.3 vocabularies describe the corresponding terms. The IGMP vocabulary in the Stream Forwarders 8.1.7 archive matches the extracted Stream App 8.1.6 vocabulary apart from its version attribute. Package provenance and checksums are in `research/package-manifest.json`.

IGMP v1/v2 group reports, leaves, and group-specific queries are candidate observations. General queries are capture-level query evidence. IGMPv3 group detail requires agreement between record counts, types, groups and flattened source counts, plus an explicit attestation of the encoding. `single-record` accepts one group record per message. `flat-counted` assumes sources are concatenated in record order. The package field list alone cannot establish either representation. A report describes an observation. Proxy, transit capture, gaps, loss and repeated reports preclude inferring current membership or delivery, counting receivers, or deduplicating packets. Endpoint attribution requires both endpoint-facing placement and an explicit reporter address attestation. The adapter classifies configured proxies first and retains other reporters as unknown. Identical reports and different observers remain separate.

NetFlow observations require an exact configured exporter and destination group. The configured observation domain, template, direction, sampling, counter semantics and replication point are operator attestations: the Stream field list does not validate the deployed export template or identify where replication occurs. No counter scaling, addition across exporters, receiver inference, or delivery claim is made. An empty result does not prove absence or permission coverage. The page reports input and expansion caps and records rejected after selection. Oversized events or events with an unrecognized layout can fall outside the search filter. The product caps each profile at 256 input and evidence rows and the combined display at 256 evidence rows.

Stream Forwarders ships an sFlow vocabulary with sampling and packet metadata. An sFlow adapter would require an indexed multicast sample and a validated sampling and packet contract. The available Nexus Dashboard, FTD, ACI ACL and Hubble materials describe traffic and policy records. Multicast membership and forwarding state require their own source evidence.

## Indexed Stream lab cohort

On November 24, 2026, Splunk Stream 8.1.7 decoded seven IGMP messages from a one-time Ethernet capture on an isolated bridge and decoded two IPFIX records exported from the UDP packets observed there. IGMPv3 messages contained two ordered group records with one source each. Stream recorded the absolute capture file path in `network_interface`. The ingress IPFIX records used observation domain 42, template 256, sampling 1:1, and the `packets_in` and `bytes_in` delta fields.

Both generated scope searches and both group-detail searches completed against these indexed events. Atlas reported two groups, retained the `0.0.0.0` query as capture-level evidence, and matched the wire counts of 7 packets and 868 bytes for one group and 4 packets and 624 bytes for the other. This run exercised one capture layout and one exporter template using the lab administrator role. Live capture, unequal IGMPv3 source-list lengths, and deployment-specific caller access require their own checks.

## Verified NX-OS forwarding replay

In a lab, read-only NX-OS route and adjacency checks qualified one point-in-time VXLAN underlay `(S,G)` cohort. Outgoing and incoming interfaces matched reciprocal CDP and PIM adjacency and the downstream reverse-path forwarding (RPF) neighbor. The attested cohort was indexed as one event in Splunk. The native Atlas Multicast replay showed **four supported forwarding links and two unresolved NVE boundaries**.

This result qualifies the indexed replay of device-reported underlay forwarding state for one cohort. Continuous collection, packet delivery, overlay next hops, and endpoint membership require separate evidence. [Operator replay procedure](operators/multicast.md#replay-an-nx-os-forwarding-snapshot)

## Search and profile limits

Searches are caller-owned and restricted to the configured index, fixed Stream sourcetype, selected observer and group, and a bounded time range. Group and capture-interface predicates precede the row cap. Only selected fields are transported. Profiles must identify the actual capture/exporter and routing scope. The optional job budget is shared with other investigations. Scope labels do not authorize access and zero observations do not establish coverage.

For illustration only, the profile below asserts a capture interface and VLAN namespace for a historical interval. The source must actually emit `network_interface` matching the profile; Stream's reference IGMP stream disables that field by default. Do not use the example as evidence that a capture is configured or qualified.

```json
{
  "version": 1,
  "profiles": [{
    "id": "igmp-sensor-1",
    "source": "multicast_igmp",
    "scope": "prod",
    "index": "multicast",
    "observer": "sensor1",
    "validFrom": 1790000000,
    "validUntil": 1800000000,
    "captureInterface": "eth0",
    "segment": {"kind": "vlan", "id": "10", "domain": "fabric"},
    "placement": "endpoint",
    "endpointReporters": ["192.0.2.10"],
    "proxyReporters": ["192.0.2.11"],
    "v3Encoding": "single-record"
  }]
}
```

The IGMP search selects group addresses from recognized JSON fields; unknown or malformed encodings can be missed entirely, so a completed search does not establish coverage. NetFlow candidate records must also emit matching `observation_domain_id`, `template_id`, and `flow_dir` (0 ingress, 1 egress), in addition to the matching exporter. These fields are declared in the Stream reference stream, but their presence and numeric representation in a deployed feed are unverified. Missing or conflicting fields are rejected, rather than assigning observations from a different template or direction to the profile.
