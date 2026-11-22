# Bounded live path evidence

Live Trace can consume administrator-qualified, bounded path captures alongside its existing scoped observations. A capture retains independent evidence segments with explicit gaps between them. It provides a way to inspect real device observations and attachment evidence during a controlled investigation. Prefer supported native collection for ongoing demonstrations; this envelope is a supplementary capture format.

Native Stream NetFlow, Cisco Secure Firewall eStreamer and Hubble observations now have independent evidence cards in scoped Live Trace. NetFlow qualification is described in [network-stream.md](network-stream.md#native-nx-os-observations-in-live-trace). FTD and Hubble require an exact mapped firewall or cluster authority in `adm_observer_scope`, with finite `valid_from` / `valid_end` bounds containing the selected window. Their timestamps must come from the source: FTD `FirstPacketSecond` / `LastPacketSecond`, or Hubble `flow.time` / `time`; missing source times do not fall back to index time. These cards aggregate an IP pair and may include multiple connections. They do not prove a translation or connect independent observations into a single route. Hubble's collector metadata identifies its qualified cluster; a node label alone is insufficient.

The shipped `adm_path_evidence(3)` generator returns no rows. An administrator can override it in the deployment's `local/macros.conf` with a search over one exact index, source and `adm:path:evidence:v1` sourcetype. Preserve the shipped argument validation. Restrict ingestion to the controlled producer and retain the caller's normal index permissions. A client-side scope filter does not grant access or replace index ACLs.

For example, replace the deployment-specific index and producer only after reviewing their authority and ACLs.

```ini
[adm_path_evidence(3)]
definition = search index=<approved_index> source="<approved_producer>" sourcetype="adm:path:evidence:v1" scope="$scope$" src="$src$" dst="$dst$" | fields _raw
```

Use a dedicated source with immutable capture IDs. Publish the JSON envelope as one event with its event time set to `start`. The indexed event, original receipts and collector checksums should be retained together. Collect only selected tuples and necessary inventory fields. Keep authentication material and unrelated traffic out of the capture.

## Envelope

The version 1 envelope contains `schema_version`, `capture_id`, `scope`, `src`, `dst`, `protocol`, `source_port`, `destination_port`, `start`, `end`, `collected_at`, `producer` and `segments`. Times are finite UTC epoch seconds. TCP and UDP require ports. The capture interval must be fully inside the selected trace window and at most 300 seconds long. Use exact source/destination orientation. A reverse-direction capture has a separate identity and reversed tuple.

Each segment contains `id`, `label`, `source`, `reference`, `observed_at` and `hops`. A hop contains `kind`, `label`, `evidence` and optional `device`, `detail`, `in` and `out`. Evidence is `observed`, `inferred` or `gap`. Supported kinds are `endpoint`, `host`, `virtual_switch`, `switch`, `firewall`, `handoff` and `gap`. Optional envelope `notes` carry collection limitations.

The producer must retain provenance for every segment. `observed` requires a flow record or endpoint receipt matching that segment's connection. Inventory and attachment evidence use `inferred`. A CDP ingress neighbor, observed switch and CDP egress neighbor can form one locally ordered segment when the observation explicitly identifies the switch's ingress and egress ports. The adjacent leaves still carry inferred traversal unless their own matching forwarding evidence exists.

Independent segments remain separated by ordering gaps. A pod tuple and a post-masquerade node tuple need explicit translation or handoff evidence before they can be represented as one transport leg. Without that proof, record the workload correlation as a limitation and trace the node tuple independently. Source labels must describe the actual collection method, including CLI cache snapshots. Never emit a CLI snapshot under a vendor continuous-export sourcetype.

## Qualification

Verify a positive capture through the deployed Trace route and inspect its hop details. Exercise wrong scope, wrong tuple, stale or incomplete intervals, conflicting capture IDs, multiple captures, malformed evidence and result overflow. Search failures remain visible. The app never combines captures across different connections. Identical repeated capture IDs may be deduplicated, while conflicting copies must fail.

The bounded reader accepts at most 32 result rows, 32 segments per capture and 16 hops per segment. Each independent source keeps its own counters. A partial route remains partial even if its endpoint socket connected successfully. The selected evidence window and receipt references must remain visible during the demonstration.

To disable the source, remove only the local macro override and verify the empty default readback. Preserve captured events and evidence receipts for historical investigation. Rolling back the frontend should restore the prior installed assets and configuration from the deployment backup.

## Match pod and node sockets through NAT

Verify the pod identity in the observation window. Record the original
protocol and tuple before the request, then read the exact egress translation
and reciprocal ingress entry. Match the translated address and port to the
same connection at the firewall or another independent observer. A paired
readback qualifies that connection. Continuous NAT history requires its own
qualified producer.

## Qualify each direction across a firewall

Match request and reply separately at the outside and inside capture points.
A matching firewall verdict establishes the recorded policy action. If the
firewall changes TCP sequence numbers, derive each direction's offset from the
captured handshake and verify it against additional unique headers. Across a
virtual switch, confirm the interface mapping and match the same headers at
the gateway vNIC and the physical uplink. Report the count that matches at
every claimed point and retain the independent allow or deny receipt.

## Compare counters on both ends of a link

Use reciprocal LLDP or equivalent interface inventory to establish the peer
pair. Check recent indexed metrics for each exact device, interface, ifIndex,
and collector source before building a replay. A running collector and a
successful read of the interface do not establish that the stream is reaching
the index. Test a known-good interface from the same source as a control.

For a new gNMI target, confirm the service and management VRF, then verify
certificate validity, endpoint identity and trust before sending credentials.
Check active subscriptions with the device owner before replacing a shared
certificate. Verify the selected metric by name in the indexed scope. [Cisco gNMI status checks](https://www.cisco.com/c/en/us/td/docs/dcn/nx-os/nexus9000/106x/programmability/cisco-nexus-9000-series-nx-os-programmability-guide-106x/m-gnmi.html)

For a branch with only local neighbor reports, retain the reporting interface,
advertised peer port, and observation time. Corroborate the peer name and
management address against the controller inventory in the intended fabric.
Preserve differing chassis identifiers and label which device reported each
one. A neighbor report establishes an advertised adjacency. A matching
connection observation is needed to show forwarding across it.

For an ESXi path, match the guest’s active interface MAC to its runtime vNIC
before using a host placement in Trace. Confirm each physical uplink against
the host network hint and the switch port-channel member. Where both sides
report LACP, compare the negotiated keys and member state and retain each
reported identifier. A bundled uplink establishes eligibility for a later
connection capture. [Broadcom ESXi uplink identification](https://knowledge.broadcom.com/external/article/435164/vm-connectivity-loss-on-a-vsphere-distri.html)

For a distributed port group, check the effective VLAN and teaming policy for
the connected dvPort, including inheritance and port-level overrides. In the
connection window, record the dvPort and team uplink and match headers at the
vNIC and physical uplink. A vNIC capture can have untagged Ethernet headers
while the uplink capture reports VLAN metadata. Use an independent receipt
for the exact connection to identify the leaf ingress.

Compare counter deltas over the same sample buckets at both ends. Preserve the
sample count, link state, and carrier transitions. Leave missing or reset
counters unqualified. Traffic with no observed error or discard increase is a
healthy comparison window. To attribute an incident to the link, capture the
counter change in the incident window and corroborate it with independent
evidence of the affected connection or user outcome.

For an optical baseline, compare transmit and receive dBm at both ends with
each optic’s reported warning thresholds. Keep the sample times alongside the
link identity and bracket the readings with independent traffic and error
counters. Use a separate qualification to verify continuous optical collection.

When two devices reuse an ifIndex, verify each device and source address
association in the selected scope. Run a swapped-source control in the same
time window. If the collector encodes link state as separate 0/1 gauge series,
check the value of the state gauge. A sample count includes zero-valued gauges.

## Fixed-window Impact

The built-in **If this fails** view can compare recorded user journeys for an explicitly qualified device cohort. The shipped `adm_impact_journeys(1)` reader is empty. Configure its local override to read exactly one approved index, immutable producer source and journey sourcetype using the request's scope and exact absolute start and end. Keep the normal caller's index permissions. Use one JSON event per cohort, timestamped at the cohort start. Unsupported scopes, times and devices produce no assessment.

A cohort has `schema_version`, `scope`, `start`, `end`, up to eight `devices` and up to eight `trials`. A device supplies its canonical management IPv4 address as `id`, display `name`, `role` and its numeric observation `domain`. A trial supplies `id`, `app`, `journey`, `actor` (`browser` or `operator`), `outcome`, exact TCP `src`, `dst`, `source_port` and `destination_port`, and an absolute `start` and `end` inside the cohort. `captures.forward` and optional `captures.reverse` identify authorized Trace receipts. Group repeats under the same journey name only when the producer has confirmed the same user action and its outcome.

Version 1 uses `role: "spine"`, with `spines.forward` and `spines.reverse` for native exporter observations. Version 2 adds `leaf` and `border` roles and uses `exports.forward` and `exports.reverse` for native observations. Optional directional `trace_hops` bind a canonical `device` to an observed `segment` ID and exact `hop` label in that direction's Trace receipt. Publish these bindings only for an exact switch observation or packet-matched endpoint handoff, with independently verified device identity. A transmit-only host attachment or a switch interface that points toward a neighbor does not establish forwarding at that neighbor.

Version 2 can also carry `linked_captures` with `src`, `dst`, `source_port`, `destination_port`, `capture`, `device`, `segment` and `hop`. This attaches a downstream exact TCP connection to the same journey. The source must establish that relationship with application, proxy or database evidence even when the transport tuple changes. A downstream observation contributes to exposure and preserves its own Trace replay.

Impact rechecks the scoped receipts in each trial window and re-reads native Stream by exact TCP tuple, exporter and observation domain. The candidate reader assigns no routing scope to raw records. Distinct scope and exact window pairs can coexist. Missing, ambiguous or capped evidence fails closed. Remove only the deployment's cohort reader override to disable the reader.

Impact counts journeys and exact browser samples that touch any selected device, even when a sample has more than one observed TCP leg. A remaining bidirectional sample requires positive request and reply observations at each selected device tier and no observations on the selection. A linked downstream leg does not fill a browser direction. Samples that cannot meet either condition appear as incomplete coverage. The calculation does not establish outage, post-failure availability, or reconvergence.
