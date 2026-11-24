# Multicast source qualification

The Stream IGMP and multicast NetFlow adapters remain candidate producer contracts. Qualification used package definitions and synthetic fixtures. The examples in `fixtures/multicast/candidates.json` are synthetic, and `fixtures/raw/stream_netflow.ndjson` contains synthetic unicast traffic. Verify actual multicast events and indexed extraction under the caller's role before relying on either adapter.

Static evidence inspected: Splunk App for Stream 8.1.6 `default/streams/igmp` lists `type`, `multicast_address`, and group-record fields, with group-record fields and source addresses marked `isList`; it does not establish how parallel lists or nested sources appear in indexed JSON. `default/streams/netflow` lists `exporter_ip`, `src_ip`, `dest_ip`, `bytes`, and `packets`. The extracted Stream Forwarders 8.1.3 vocabularies describe the corresponding terms. The IGMP vocabulary in the Stream Forwarders 8.1.7 archive matches the extracted Stream App 8.1.6 vocabulary apart from its version attribute. Package provenance and checksums are in `research/package-manifest.json`.

IGMP v1/v2 group reports, leaves, and group-specific queries are candidate observations. IGMPv3 group records are accepted only when all record counts, types, groups and flattened source counts agree and the operator has explicitly attested the encoding; `single-record` rejects multiple records, while `flat-counted` assumes sources are concatenated in record order. Neither representation is proven by the package. General queries, malformed or ambiguous records and unsupported layouts are not interpreted. A report is an observation, not current membership or delivery; proxy, transit capture, gaps, loss and repeated reports preclude counting receivers or deduplicating packets. Endpoint attribution requires both endpoint-facing placement and an explicit reporter address attestation; configured proxies are classified first and other reporters remain unknown. These attestations are not proven host identity. Identical reports and different observers remain separate.

NetFlow observations require an exact configured exporter and destination group. The configured observation domain, template, direction, sampling, counter semantics and replication point are operator attestations: the Stream field list does not validate the deployed export template or identify where replication occurs. No counter scaling, addition across exporters, receiver inference, or delivery claim is made. An empty result does not prove absence or permission coverage. The page reports input and expansion caps and records rejected after selection. Oversized events or events with an unrecognized layout can fall outside the search filter. The product caps each profile at 256 input and evidence rows and the combined display at 256 evidence rows.

Stream Forwarders ships an sFlow vocabulary with sampling and packet metadata. An sFlow adapter would require an indexed multicast sample and a validated sampling and packet contract. The available Nexus Dashboard, FTD, ACI ACL and Hubble materials describe traffic and policy records. Multicast membership and forwarding state require their own source evidence.

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
