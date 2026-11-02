# Cisco Nexus Hyperfabric and DPU Smart Switch support research

Research date: 2026-10-28. Status: feasibility research; no collector, parser, product configuration, or live qualification was performed. Scope includes Cisco Nexus Smart Switches with onboard DPUs, as clarified during research.

## Recommendation

Support two independently qualified sources:

1. **Hyperfabric fabric context:** inventory, configured connectivity, interface measurements, assertion notifications, and configuration activity.
2. **Nexus Smart Switch / Hypershield evidence:** DPU-exported IPFIX and audit/enforcement syslog, associated with separately collected switch inventory and security-policy context.

The second source materially improves the prospect of application dependency discovery because Cisco documents flow export from the network enforcers. It still requires exact exporter templates and received events before Atlas can claim compatible flow ingestion. Neither source is implemented in Atlas today.

## The Smart Switch distinction

Cisco identifies N9324C-SE1U and N9348Y2C6D-SE1U as DPU Smart Switches. Their network management uses NX-OS/Nexus Dashboard/NX-API, while Hypershield manages security services. DPUs are powered down by default until those services are enabled. Cisco describes a zone-segmentation deployment alongside a Hyperfabric fabric; that interoperability does not establish that Hyperfabric manages the switch or its DPUs. Do not infer operating mode from the Nexus brand or model family alone. [Cisco Smart Switch FAQ](https://www.cisco.com/c/en/us/products/collateral/switches/9300-series-smart-switches/n9300-series-smart-switch-faq.html)

| Deployment | Collection approach to investigate | Atlas opportunity |
| --- | --- | --- |
| Hyperfabric-managed fabric | Hyperfabric REST plus native Splunk HEC notifications | Fabric context and operational evidence |
| NX-OS Smart Switch, DPUs inactive | Qualify the existing NX-OS/Nexus Dashboard collection path against the exact model/release | Switch inventory and supported network telemetry |
| Smart Switch with Hypershield active | Network collection plus separate DPU IPFIX, syslog, and policy-context collection | Observed conversations and enforcement evidence, subject to qualification |
| Smart Switch providing segmentation alongside Hyperfabric | Collect both management domains and explicitly bind their identities | Correlate fabric context with the enforcement point |

These are proposed integration boundaries, not a Cisco compatibility matrix.

## What DPU services expose

Hypershield v10.0.0.0 release notes, dated 2026-08-21, document IPFIX export from Network Enforcers and syslog audit/enforcement export from Agent Gateways to configured destinations. The controller supports network-object and security-policy REST operations. Enforcement concerns unicast flows steered to the DPU; broadcast, unknown-unicast, and multicast bypass it. The notes also describe policy-status reporting issues and possible service-interface drop-counter double counting in inter-VRF mode. These are relevant qualification cases, not reasons to alter a customer's steering configuration. [Hypershield release notes](https://www.cisco.com/c/dam/en/us/td/docs/security/hypershield/v10-0-0/release-notes/hypershield-release-notes.html)

The user guide distinguishes syslog, IPFIX, and Timescape event history. Telemetry destinations and logging groups select collectors and exporting clusters. Traffic outside configured DPU steering bypasses the enforcer. Public REST policy configuration is not a general flow-history API, and successful policy configuration is not proof that every enforcer applied that revision. [Hypershield user documentation](https://www.cisco.com/c/dam/en/us/td/docs/security/hypershield/v10-0-0/user-documentation/hypershield.html)

**Design consequence:** prioritize a Hypershield IPFIX qualification spike when DPUs are active. Preserve DPU/enforcer identity, exporter/observation-domain identity, routing domain, flow direction, native times, counters, and any policy/action fields actually exported. Treat unavailable fields as unknown. Do not relabel this stream as Hyperfabric telemetry, FTD eStreamer, or Hubble JSON. Any relationship to Atlas application identities must use independent, time-qualified address bindings.

## Hyperfabric collection surfaces

### Assertions to Splunk

Hyperfabric supports native Splunk HEC notifications and Amazon S3 delivery. Notifications follow changes in latched assertions; Cisco lists a maximum 30-second duration for Splunk and S3 notification endpoints. The Splunk guide describes timestamps, criticality, fabric links, and configuration-commit summaries, but does not establish the exact received JSON envelope, sourcetype, delivery guarantees, replay behavior, or a heartbeat. S3 notifications are JSON files. Splunk Enterprise HEC behind a firewall requires the current documented source-address allowlist. Use a sanitized HEC readback to establish the parser contract. [Hyperfabric notifications](https://www.cisco.com/c/en/us/td/docs/dcn/hyperfabric/software/cisco-nexus-hyperfabric-notifications.html)

**Design consequence:** no new notification collector is needed to prove receipt in Splunk. Atlas still needs a source-specific parser and authority mapping. An absence of alerts cannot establish collection health or a healthy fabric.

### REST inventory, configuration, and counters

The API base is `https://hyperfabric.cisco.com/api/v1/`. Bearer tokens are user- and organization-specific. Cisco documents a read-only role and token scope/duration selection; qualify required GET permissions with that role. Keep credentials in the existing protected operator workflow. [Getting started](https://developer.cisco.com/docs/hyperfabric/getting-started/), [authentication](https://developer.cisco.com/docs/hyperfabric/authentication/)

The inspected operation pages identify API revision `1.4.0-Rev.2026-09-02.2fa23`. The changelog documents pagination changes, 307 redirects, and breaking schema changes, including removed port-channel properties. Pin the qualified revision and validate redirect destinations before forwarding authorization. Published numeric rate limits were not established by this research. [API changelog](https://developer.cisco.com/docs/hyperfabric/api-changelog/)

All paths below are GET operations relative to that base. Rows describe public schemas, not verified events from a deployed tenant.

| API path | Useful evidence | Boundary / qualification need |
| --- | --- | --- |
| `/fabrics` | Fabric ID, name, location, labels, topology; `max`/`cursor` pagination | Snapshot configuration; retain request authority and complete all pages. [Reference](https://developer.cisco.com/docs/hyperfabric/get-the-list-of-fabrics/) |
| `/devices` | Device ID, serial, model, bound node/fabric, roles; includes bound and unbound hardware | Hardware inventory does not prove workload identity or reachability. [Reference](https://developer.cisco.com/docs/hyperfabric/get-the-list-of-devices/) |
| `/fabrics/{fabricId}/nodes` | Native node ID, device binding, roles, model, OS type; optional metadata | Configured node state does not establish live forwarding health. [Reference](https://developer.cisco.com/docs/hyperfabric/get-the-list-of-nodes/) |
| `/fabrics/{fabricId}/connections` | Connection ID and local/remote node and canonical port names | Supports candidate configuration selection; qualify configured versus observed connection semantics before drawing live adjacency. [Reference](https://developer.cisco.com/docs/hyperfabric/get-the-list-of-connections/) |
| `/fabrics/{fabricId}/nodes/{nodeId}/ports` | Port ID/name, roles, configured addressing, VLAN/VNI and VRF association | `enabled`, `linkDown`, and configured speed are not an attested operational link-state measurement. [Reference](https://developer.cisco.com/docs/hyperfabric/get-the-list-of-ports/) |
| `/fabrics/{fabricId}/vrfs`, `/fabrics/{fabricId}/vnis`, `/fabrics/{fabricId}/vnis/{vniId}/members` | Routing-domain IDs, VNI-to-VRF association, SVI addressing, VLAN/port membership | Network configuration does not identify learned endpoint IP/MAC ownership. [VRFs](https://developer.cisco.com/docs/hyperfabric/get-the-list-of-vrfs/), [VNIs](https://developer.cisco.com/docs/hyperfabric/get-the-list-of-vnis/), [members](https://developer.cisco.com/docs/hyperfabric/get-the-list-of-vni-members/) |
| `/fabrics/{fabricId}/nodes/{nodeId}/counters` | Port and VLAN measurements; port octets, packets, errors/discards, bit/packet rates, PFC counters, `collectedAt`, port `lastClear` | Aggregate interface measurements cannot become application flow tuples. [Reference](https://developer.cisco.com/docs/hyperfabric/get-the-list-of-node-counters/) |
| `/fabrics/{fabricId}/candidates` | Candidate transaction/revision IDs, activity-event IDs/times/objects/operations; optional reviews; time bounds and cursor | Request `needInactive`, `needEvents`, and optionally `needReviews`. Distinguish edits, reviews, commit/revert activity, and proven deployment. [Reference](https://developer.cisco.com/docs/hyperfabric/get-the-list-of-candidate-configurations/) |
| `/fabrics/{fabricId}/bgpPeers` | Peer configuration, VRF/interface associations, ASN/address/policy references | Configuration is not session-up evidence. The schema includes a password field: exclude it from exported records. [Reference](https://developer.cisco.com/docs/hyperfabric/get-the-list-of-bgp-peers/) |

Counter schema details: many cumulative values are uint64 encoded as strings; preserve precision. Rates are already bits/second or packets/second. Retain native `collectedAt`, collector receipt time, and indexed time separately. Use `lastClear` and reset-aware deltas before deriving new rates. The public node-counter request has no historical time-range parameter; storage in Splunk would build a history of collected observations, not backfill arbitrary controller history.

The API introduction mentions assertions, but the inspected public operation catalog did not expose dedicated assertion-history, learned endpoint/ARP/MAC, or per-conversation flow operations. Treat these as unresolved access gaps rather than inventing endpoints or equating UI availability with API support. [Public API catalog](https://developer.cisco.com/docs/hyperfabric/)

### Additional traffic collection possibilities

The Cisco 6000 datasheet lists NetFlow v9/IPFIX with a footnote indicating hardware capability and lack of availability at first customer shipment. That is insufficient evidence of availability on a customer's current software. Confirm model, software, configuration mechanism, and emitted templates with Cisco before selecting this path. [Cisco 6000 datasheet](https://www.cisco.com/c/en/us/products/collateral/switches/6000-series-switches/6000-series-switches-ds.html)

October 2026 release notes introduce local SPAN. Cisco's guide describes same-switch physical-port mirroring to an external probe, without sending mirrored payloads to the cloud controller. It limits source/destination selection, excludes port channels as direct sources/destinations, and warns about destination oversubscription. A local Splunk Stream probe is a candidate architecture requiring separate validation of mirrored coverage, drops, direction, duplicates, and encrypted payload limits. [2026 release notes](https://www.cisco.com/c/en/us/td/docs/dcn/hyperfabric/software/release-notes/cisco-hyperfabric-release-notes-2026.html), [SPAN guide](https://www.cisco.com/c/en/us/td/docs/dcn/hyperfabric/software/cisco-nexus-hyperfabric-configure-span.html)

The ordinary Hyperfabric NetFlow uncertainty does not override the separately documented Hypershield DPU IPFIX export path.

## Fit with Application Atlas

Repository inspection found no Hyperfabric runtime adapter. The pinned operator catalog records `cisco_nexus_hyperfabric` as `unsupported_roadmap`, with no install apps, sourcetypes, or primary setup skill. This is a local automation gap, not evidence that Cisco lacks an integration. [Catalog](../../vendor/splunk-cisco-skills/skills/cisco-product-setup/catalog.json)

| Existing surface | Required work for qualified support |
| --- | --- |
| [`adm_flows_nd`](../../splunk_app/splunk_adm/default/macros.conf), [`DATA_LAYER.md`](../DATA_LAYER.md) | Preserve ND's native contract. Qualify DPU IPFIX through the actual receiver/parser before deciding whether the existing Stream normalization can be reused. Hyperfabric counters cannot enter `adm_flows`. |
| `adm_identity_observations` and `adm_observer_scope` | Introduce source-qualified authorities and time-qualified mappings. An interface IP, VLAN, or configured server group is insufficient evidence for workload identity. |
| `adm_topology_v2` and [`cisco-pipeline-interface.json`](../../research/cisco-pipeline-interface.json) | Use stable organization/fabric/node/device IDs; qualify connection semantics and time bounds. Represent configured connectivity distinctly until operational evidence supports stronger claims. Preserve interfaces such as `Ethernet1_1` with an explicit normalization map. |
| [`SUPPLEMENTAL_EVIDENCE_CONTRACT.md`](../SUPPLEMENTAL_EVIDENCE_CONTRACT.md), [`evidenceConfig.ts`](../../frontend/src/data/evidenceConfig.ts) | Add independent parsers/configuration for assertions, counters, candidate activity, and Hypershield enforcement. Keep uncertainty, provenance, cancellation, caller permissions, and source-specific measurement totals. |
| [`deployment-health.json`](../../config/deployment-health.json), [`setupClient.ts`](../../frontend/src/data/setupClient.ts), health macros | Add explicit source selection, index/schema qualification, authority configuration, receipt checks, and independent collector status. Alert silence is not a missing-poll condition. |
| [`operators/`](../operators/README.md) | Add an intake/collection guide and exact qualification record. Keep external collectors outside the Splunk app package; update the skills submodule only through its own reviewed change. |

## Proposed qualification sequence

1. **Resolve the deployment.** Obtain exact switch models, operating image/version, management controller/version, Hypershield/AGW/enforcer versions, DPU activation and license status, steering scope, and network/security owners. Record whether Smart Switches are fabric members or adjacent enforcement devices.
2. **Qualify the DPU feed first when active.** Capture sanitized IPFIX templates/options and decoded records, both traffic directions, allowed and denied test traffic, long-lived flow updates, replay, restart/reset, HA/failover, and collection gaps. Establish whether counts are cumulative or interval deltas, exporter domains, template refresh, timestamps/units, policy identifiers, and which traffic bypasses observation. Inspect the receiver's actual output and retained enterprise-specific elements before selecting an Atlas adapter.
3. **Collect fabric context independently.** Read one complete inventory/configuration snapshot and two or more counter observations. Obtain an assertion change and resolution readback and candidate edit/commit/revert samples. Preserve native IDs, exact API revision, request context, collection completeness, and all relevant times. Redact actors, free text, identifiers, addresses, and secrets consistently.
4. **Prove useful correlation.** Demonstrate one synthetic application's conversation at the enforcer, independently bind its endpoints and switch, then show related fabric measurements and policy/event context. Keep enforcement observation, desired policy, deployment status, and possible cause as separate claims. Never sum the same conversation across DPU, Stream, Hubble, and ND sensors.
5. **Implement after the contracts are established.** Add parser/normalization tests, caller-permission and cross-scope collision tests, cap/partial/replay/time tests, and installed-app SPL qualification. A phase-one release can expose optional fabric evidence while DPU flow qualification remains pending; do not advertise dependency discovery from inventory alone.

Open questions: exact public IPFIX information elements and vendor extensions; enforcement-event schema; export coverage of denied attempts; flow expiration/refresh and sampling; current controller rate limits; assertion replay/retry guarantees; historical learned endpoint access; installed policy revision evidence; and actual Splunk receiver compatibility. Public documentation establishes feasibility, not production qualification.
