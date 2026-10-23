# Optional DNS evidence operations

**Status:** optional, on-demand evidence. This guide does not establish production readiness. Read the [DNS evidence design](../DNS_EVIDENCE_DESIGN.md) and [DNS ingestion research](../DNS_INGESTION_RESEARCH.md) before enabling a source. The app does not install, configure, or change a Stream sensor, Hubble policy, collector, resolver, index, or Splunk quota.

DNS observations can provide candidate name context for an address and show resolution outcomes. They do not establish an application dependency, successful connection, service ownership, or traffic path. DNS-only activity creates no network edge. No scheduled DNS builder or automatic collector/policy configuration is included.

The endpoint workflow displays V2 traffic observations only when their source quality status is `accepted` or `accepted_with_warning`. Excluded, unknown, and missing quality statuses cannot produce peer edges. An unexpected quality status in a returned result makes the additional observation section unavailable while preserving valid conversation summaries. Endpoint links retain the current Splunk proxy prefix and locale path.

## Prerequisites and access

- Select a customer-approved Stream DNS or Hubble DNS L7 feed and confirm that its event fields, timestamps, client address visibility, source authority, and routing scope fit the use case. Keep request and response semantics from the producer; do not manufacture missing fields.
- For Stream, attest the sensor host and its packet vantage point. Confirm that the captured client address is the original workload address for the intended segment, or document where NAT/proxying prevents workload association.
- For Hubble, attest the exact cluster whose exported flows contain the DNS L7 events. Confirm that DNS L7 export is enabled for the intended scope and that the feed retains both sides needed by the chosen adapter. Enabling a Cilium policy can change traffic behavior; have the cluster owner review and apply any such change outside Atlas.
- Confirm that every Atlas app viewer is allowed to see the configured DNS index, queried names, and client identity. Existing shared app readers can see the complete configured dataset; routing scope is attribution context, not tenant authorization.
- Reading the shared DNS selector uses Splunk's Configuration Management API with `POST /servicesNS/nobody/splunk_adm/configs/v1/conftypes/macros/stanzas:get?view=app-merged` and a JSON body containing the exact stanza name. In the disposable Splunk 10.6 lab, a role with `search` plus `list_conf_objects` could read the app-merged stanza; a pure-search role was denied by this same v1 POST endpoint. The v1 response contains settings but no per-stanza ACL metadata. Its `list_conf_objects` capability allows listing and reading configuration objects more broadly than these DNS selectors, so grant it only after security review of that visibility; do not replace it with `admin_all_objects`. The `nobody` + app-merged scope reads the app's local and default layers and excludes user-private stanzas; a user-private macro shadow does not alter the shared value. If policy does not allow this capability, DNS evidence and the new scoped endpoint page cannot read their selectors for that viewer. Existing core map and summary searches retain their prior permissions and behavior. A private macro or lookup shadow must never be used as a workaround for a denied shared read.
- Qualify Splunk role permissions, search quotas, cancellation/expiry behavior, and scan cost on the target. A display cap does not cap raw events scanned. Do not increase quotas automatically.

## Safe initial configuration

DNS selectors are literal index configuration values retrieved through the explicit `nobody/splunk_adm` Configuration Management v1 `stanzas:get` app-merged REST endpoint. The app treats them as configuration data; it must not execute a DNS configuration macro as SPL or accept event data as an index selector. Configure only a reviewed literal `index=<lowercase-index>` value with a bounded index name.

The shipped defaults are:

| REST macro | Default definition | Meaning |
| --- | --- | --- |
| `adm_index_dns_stream` | `index=unconfigured_dns` | Safe placeholder; it does not enable a sensor or prove that this index/feed exists. Replace it only after selecting and qualifying the Stream source. |
| `adm_index_dns_hubble` | `index=cilium_hubble` | Candidate Hubble index; it is inert while the source is unselected. Confirm the actual target's index and sourcetype. |
| `adm_dns_max_age_seconds` | `3600` | One-hour initial DNS association-age cap. |
| `adm_dns_clock_uncertainty_seconds` | `unknown` | No time-based DNS association is allowed until an operator qualifies the clock uncertainty. |
| `adm_dns_stream_schema_qualified` | `0` | Stream schema is unqualified. |
| `adm_dns_hubble_schema_qualified` | `0` | Hubble schema is unqualified. |

These values are configuration literals, not callable SPL searches. Keep both schema qualification values at `0` until the exact source product/version and target feed have passed sample-based field and timestamp review plus the target acceptance checks below. Do not set a qualification flag because a macro or index exists. An `unknown` clock uncertainty suppresses time-based name/address association; it does not mean zero skew. Set a numeric value only after the source and target clocks have been measured and accepted.

The initial adapter source-type allowlist is `stream:dns` for Stream and `cilium:hubble:flow` for Hubble. Do not broaden it to an arbitrary sourcetype to make an empty search return data. Preserve the producer schema and validate actual samples before setting the matching qualification flag.

## Scope mapping and operator attestation

A DNS event can be associated with a routing scope only when its source authority and observer mapping are explicit and unambiguous. In the existing administrator-managed `adm_observer_scope` mapping, require all of these values to match the verified source:

- `observer_kind` identifies the observer type (`dns_sensor` for a Stream sensor or `cluster` for Hubble).
- `observer` is the canonical lowercase sensor host identity or exact cluster name.
- `scope` is the approved routing domain.
- `cluster` is the attested cluster for Hubble and the operator-attested cluster context where the Stream deployment uses one.
- `mapping_status` is exactly `verified`.

The new `mapping_status` field is administrator attestation. A missing, `mapped`, ambiguous, or otherwise different value is not verified and must suppress scope-dependent association. For Stream, record which sensor host and segment the operator verified; for Hubble, record the exact cluster attested by the Kubernetes owner. Do not infer scope from a private IP, index, source label, or a shared resolver address. If a source cannot preserve the client address or distinguish overlapping routing domains, use only the source context that is actually supported and leave workload association unavailable.

## Qualification and acceptance

Before selecting the source in Setup, retain a sanitized representative sample set and record collector/product version, source index, sourcetype, sensor/cluster authority, mapping, event-time behavior, ingestion delay, and the exact field contract. Include successful and negative responses, multiple answers, IPv4/IPv6 where present, aliases, missing fields, and the observed quiet-feed behavior. Do not store customer names, full DNS payloads, tokens, or credentials in this repository.

On the target deployment, verify that each source has the expected client and response semantics, that time values and units are correctly interpreted, that clock uncertainty is bounded, and that the `verified` scope mapping is unique. Exercise access denied, missing index, malformed sample, quiet feed, capped result, failed/expired job, and stale-configuration cases. Confirm that DNS errors remain isolated from core traffic health, that quiet feeds stay unknown, and that no DNS-only event creates a traffic edge or changes conversation counters.

The design proposes initial bounds of a one-hour evidence window, up to 24 hours when explicitly requested, a one-hour association-age cap configurable from 60 seconds through 24 hours, at most 10,000 matching observations plus an overflow sentinel per adapter/request, at most 64 displayed DNS records, and 30-second server / 35-second client deadlines. Optional searches share a browser budget of at most two jobs, one per adapter, with core traffic work taking priority. These are product targets that still require target qualification; they do not prove a bound on indexer scan cost. Measure workload and Splunk resource use, and qualify real cancellation/expiry before production use.

A successful pilot qualifies only the exact app package, index/schema, Splunk version/topology, permissions, quotas, mappings, clock assumptions, and measured capacity tested. Missing samples or unverified source access leave that source unqualified. No general production-ready claim follows from a successful local test or from enabling a selector.

Cancellation starts bounded native job-status checks when a job identifier is known, even if the cancellation request does not finish. The execution slot stays occupied until cancellation is acknowledged or Splunk confirms a terminal/deleted job. If the status-check budget is exhausted without confirmation, cleanup remains pending; the app must not infer that the slot is free or dispatch a replacement in that slot.

## Enable, disable, upgrade, and rollback

1. Install the reviewed candidate consistently on every search head serving Atlas. Keep deployment settings writes disabled unless the topology and target meet the existing [settings persistence gate](../DEPLOYMENT_HEALTH.md#supported-write-contract-and-deployment-gate). Cloud and unqualified deployments remain read-only.
2. Review effective values through the configuration REST endpoint. Set the chosen literal DNS index selector and source-specific schema flag only after sample qualification. Keep the other source unselected and its qualification flag at `0`. Save source intent through Atlas Setup after all-member package and settings compatibility checks.
3. Start with a narrow, explicitly selected endpoint address, verified scope, and bounded time window. Inspect source status, completeness, caps, and attribution basis. Do not interpret no records as proof that no DNS queries occurred.
4. To disable a feed, use the supported settings endpoint to mark that DNS source `not_selected`; set its schema qualification macro back to `0` and restore its index selector to the safe default if desired. Confirm all search heads have the same effective selector and qualification values. No scheduled builder needs disabling.
5. For package rollback, first disable the optional source on every member and restore the safe selector and qualification defaults. Preserve the `adm_deployment_settings` immutable ledger, its revision chain, the legacy `deployment` migration anchor, and existing collection data. Do not delete ledger rows, create/edit the old fixed `deployment` record, or bypass the supported settings endpoint.

A newer ledger can contain `dns_stream` and `dns_hubble` keys that an older app version does not recognize. An older client may then report settings unavailable and must not save over, strip, or migrate those keys. Before rollback, confirm that the selected older build can safely read the current settings schema; otherwise keep the ledger intact and restore a version that understands it or use a separately reviewed migration. Do not enable writes to work around an unknown-source error. Update every member to a compatible app build before resuming settings changes.

If the source needs to be restored later, recheck the index, schema samples, mapping attestation, clock uncertainty, viewer access, and target capacity before selecting it again. A previously successful qualification does not cover changed sensors, clusters, index routing, mappings, versions, quotas, or topology.

Interpretation examples and explicit no-inference boundaries for VMs, Kubernetes Services, pod churn, proxies, shared services, external APIs and resolution failures are in the [scenario guide](../DNS_EVIDENCE_SCENARIOS.md).
