# Splunk setup guide for Application Atlas

An ordered runbook for the Splunk administrator, from a Splunk Enterprise 10.6 deployment to a working dependency map. Choose [deployment options and missing sources](deployment-options.md) first. Each phase ends with a check for the sources/features you selected; skip instructions for absent products and record the resulting coverage gaps. The tables of indexes, tokens and add-on placement are in [splunk-platform.md](splunk-platform.md); this guide is the order of work.

Automation: each step names the matching skill from [splunk-cisco-skills](https://github.com/chambear2809/splunk-cisco-skills), vendored in this repo at `vendor/splunk-cisco-skills` (pinned submodule) and discoverable from Claude Code, Cursor and Codex — see [the main README](../../README.md#operator-setup-skills). Skills are render-first: they produce a plan you review, apply only the requested change, then validate. Run them from Claude Code, Codex or Cursor, or run their scripts directly from that directory: `cd vendor/splunk-cisco-skills && bash skills/<skill-name>/scripts/setup.sh --help`.

> **Compatibility.** Use the vendored skill commit, not a newer upstream default. Check the exact skill/package release status in [SPLUNK_ENTERPRISE_10_6_COMPATIBILITY.md](https://github.com/chambear2809/splunk-cisco-skills/blob/1c93cd87b5a97fe54a2b3284b1d2c43034413edd/SPLUNK_ENTERPRISE_10_6_COMPATIBILITY.md) and follow any documented guardrails before applying. The pilot uses **Cisco Security Cloud 3.7.2** (the version this app's field mappings were verified against). The `cisco-security-cloud-setup` skill's default install path pins `3.6.10`; select 3.7.2 explicitly with `--version 3.7.2` (and `--accept-unsupported-platform` with documented vendor approval if the skill doesn't carry independent 10.6/Cloud evidence for that exact release), and confirm the installed version afterwards.

## Phase 0. Plan

Record selected sources, expected collection intervals, application/cluster identities, routing domains and the features you need. The original ACI pilot is one example. Optional Catalyst/Meraki enrichment ships staged under V1; read the [Cisco handout](cisco-enterprise-networking.md) and [qualification limits](../CISCO_NETWORKING_QUALIFICATION.md) before planning V2. Captured demos require no collectors and are not evidence of live readiness.

1. Size the deployment for the expected NetFlow, Hubble and span volume. Hubble flow logs are usually the largest source. Skill: [splunk-platform-sizing](https://github.com/chambear2809/splunk-cisco-skills/tree/1c93cd87b5a97fe54a2b3284b1d2c43034413edd/skills/splunk-platform-sizing).
2. Decide which host runs the modular inputs (DC Networking, Cisco Security Cloud) and which host receives NetFlow (Stream forwarder). A heavy forwarder for the inputs: [splunk-enterprise-host-setup](https://github.com/chambear2809/splunk-cisco-skills/tree/1c93cd87b5a97fe54a2b3284b1d2c43034413edd/skills/splunk-enterprise-host-setup).
3. Confirm the license covers the source volume. The app's own summary data uses the `stash` sourcetype and is not licensed. Skill: [splunk-license-manager-setup](https://github.com/chambear2809/splunk-cisco-skills/tree/1c93cd87b5a97fe54a2b3284b1d2c43034413edd/skills/splunk-license-manager-setup).

**Check:** you know the search head, the indexers, the input host and the NetFlow receiver host.

## Phase 1. Indexes

Create `adm_summary` and the raw indexes needed by selected inputs: `netflow`, `cisco_dc`, `cisco_secure_fw`, `cisco_isovalent`, `k8s`, `otel_traces` and/or `cilium_hubble`, with the retention you chose (the original pilot uses Hubble 7–14 days). For optional V2 qualification also plan `cisco_catalyst`, `cisco_meraki` and the separate `adm_summary_v2`, as applicable; see the [index tables](splunk-platform.md#indexes). Use your normal `indexes.conf` deployment; for retention planning and later changes use [splunk-index-lifecycle-smartstore-setup](https://github.com/chambear2809/splunk-cisco-skills/tree/1c93cd87b5a97fe54a2b3284b1d2c43034413edd/skills/splunk-index-lifecycle-smartstore-setup). On Splunk Cloud later: [splunk-cloud-acs-admin-setup](https://github.com/chambear2809/splunk-cisco-skills/tree/1c93cd87b5a97fe54a2b3284b1d2c43034413edd/skills/splunk-cloud-acs-admin-setup).

**Check:** `| eventcount summarize=false index=* | search index IN (netflow, cisco_dc, cisco_secure_fw, cisco_isovalent, k8s, otel_traces, cilium_hubble, adm_summary)` is a receipt check for indexes with events; restrict the list to selected inputs and add optional Cisco indexes when used. Empty indexes may not appear, so verify index existence and access separately before ingestion.

## Phase 2. HEC tokens

For selected HEC feeds, create `otel-k8s` (allow only the selected destinations among `k8s`, `otel_traces`, `cilium_hubble`) and/or `isovalent` (allowed index `cisco_isovalent`, sourcetype `cisco:isovalent`). Skip unused tokens. Catalyst/Meraki modular inputs use vendor accounts rather than these tokens. Skill: [splunk-hec-service-setup](https://github.com/chambear2809/splunk-cisco-skills/tree/1c93cd87b5a97fe54a2b3284b1d2c43034413edd/skills/splunk-hec-service-setup). Hand the token values to the Kubernetes and Isovalent teams through your secret-management process, never in tickets or chat.

**Check:** each token appears under **Settings → Data inputs → HTTP Event Collector**, enabled, with only its allowed indexes.

## Phase 3. Add-ons

Install the packages required by selected sources on the tiers in [splunk-platform.md](splunk-platform.md#add-on-placement): Splunk Add-on for Stream Wire Data, Splunk App for Stream, Splunk Add-on for Stream Forwarders, Cisco Security Cloud, Cisco DC Networking. Skill: [splunk-app-install](https://github.com/chambear2809/splunk-cisco-skills/tree/1c93cd87b5a97fe54a2b3284b1d2c43034413edd/skills/splunk-app-install). If you manage forwarders centrally: [splunk-deployment-server-setup](https://github.com/chambear2809/splunk-cisco-skills/tree/1c93cd87b5a97fe54a2b3284b1d2c43034413edd/skills/splunk-deployment-server-setup). Restart only where needed: [splunk-platform-restart-orchestrator](https://github.com/chambear2809/splunk-cisco-skills/tree/1c93cd87b5a97fe54a2b3284b1d2c43034413edd/skills/splunk-platform-restart-orchestrator).

For optional Catalyst Center/Meraki inputs, install the corresponding Cisco Enterprise Networking/Meraki add-ons on vendor-supported tiers and validate their required runtime and API access; follow the [Cisco handout](cisco-enterprise-networking.md). Synthetic lab results do not qualify vendor collection.

If DC Networking is selected, set its macros `cisco_dc_aci_index`, `cisco_dc_nd_index`, `cisco_dc_n9k_index` to `index IN ("cisco_dc")`. If Security Cloud is selected, confirm the input host's Python runtime meets its `python.required = 3.13`.

**Check:** **Manage Apps** shows each package on the intended hosts; `splunk btool check` reports no errors.

## Phase 4. Data sources

Work with each selected source's team using its handout. Configure the Splunk-side inputs yourself where they run on Splunk hosts.

| Source                                      | Splunk-side work                                                                                                  | Skill                                                                                                                                                                                                                                                                                                                                                                                              | Team handout                                                     |
| ------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------- |
| APIC / Nexus Dashboard                      | DC Networking accounts and inputs, plus the `application-atlas`/`adm` and `adm-policy` `classInfo` presets        | [cisco-dc-networking-setup](https://github.com/chambear2809/splunk-cisco-skills/tree/1c93cd87b5a97fe54a2b3284b1d2c43034413edd/skills/cisco-dc-networking-setup)                                                                                                                                                                                                                                    | [aci-network.md](aci-network.md)                                 |
| ACI NetFlow                                 | Stream forwarder NetFlow receiver, `netflow` stream enabled                                                       | [splunk-stream-setup](https://github.com/chambear2809/splunk-cisco-skills/tree/1c93cd87b5a97fe54a2b3284b1d2c43034413edd/skills/splunk-stream-setup)                                                                                                                                                                                                                                                | [network-stream.md](network-stream.md)                           |
| FTD                                         | Security Cloud eStreamer input                                                                                    | [cisco-security-cloud-setup](https://github.com/chambear2809/splunk-cisco-skills/tree/1c93cd87b5a97fe54a2b3284b1d2c43034413edd/skills/cisco-security-cloud-setup)                                                                                                                                                                                                                                  | [firewall-security.md](firewall-security.md)                     |
| Isovalent                                   | Security Cloud Isovalent HEC input                                                                                | [cisco-security-cloud-setup](https://github.com/chambear2809/splunk-cisco-skills/tree/1c93cd87b5a97fe54a2b3284b1d2c43034413edd/skills/cisco-security-cloud-setup)                                                                                                                                                                                                                                  | [cilium-isovalent.md](cilium-isovalent.md)                       |
| Hubble flow export                          | Cilium's `hubble_flow_export` block                                                                               | [cisco-isovalent-platform-setup](https://github.com/chambear2809/splunk-cisco-skills/tree/1c93cd87b5a97fe54a2b3284b1d2c43034413edd/skills/cisco-isovalent-platform-setup)                                                                                                                                                                                                                          | [cilium-isovalent.md](cilium-isovalent.md)                       |
| Kubernetes objects, spans, Hubble file tail | None (Helm chart sends to HEC)                                                                                    | [splunk-observability-otel-collector-setup](https://github.com/chambear2809/splunk-cisco-skills/tree/1c93cd87b5a97fe54a2b3284b1d2c43034413edd/skills/splunk-observability-otel-collector-setup), [splunk-observability-isovalent-integration](https://github.com/chambear2809/splunk-cisco-skills/tree/1c93cd87b5a97fe54a2b3284b1d2c43034413edd/skills/splunk-observability-isovalent-integration) | [kubernetes-platform.md](kubernetes-platform.md)                 |
| Catalyst Center / Meraki (optional V2)      | Vendor accounts and client/association inputs; explicit source profiles; separate compatible Stream/IPFIX traffic | Follow the reviewed vendor input procedure and qualification gates                                                                                                                                                                                                                                                                                                                                 | [cisco-enterprise-networking.md](cisco-enterprise-networking.md) |

**Check:** each selected input shows data (restrict the example index list and add `cisco_catalyst`/`cisco_meraki` as applicable):

```spl
| tstats count where index IN (netflow, cisco_dc, cisco_secure_fw, cisco_isovalent, k8s, otel_traces, cilium_hubble) by index, sourcetype
```

For the full original pilot, expected sourcetypes include `stream:netflow`, `cisco:dc:aci:class`, `cisco:dc:aci:stats`, `cisco:dc:nd:flows`, `cisco:dc:nd:endpoints`, `cisco:sfw:estreamer`, `cisco:isovalent:processConnect`, `kube:object:pods`, `kube:object:services`, `kube:object:endpointslices`, `otel:traces` and `cilium:hubble:flow`. Optional Cisco inputs use `cisco:dnac:client` and `meraki:accesspoints`; verify actual association events and compatible flow templates, not just inventory counts. Missing products are not automatically failures; see [partial-deployment checks](deployment-options.md#check-a-partial-deployment). For a fuller readiness report: [splunk-data-source-readiness-doctor](https://github.com/chambear2809/splunk-cisco-skills/tree/1c93cd87b5a97fe54a2b3284b1d2c43034413edd/skills/splunk-data-source-readiness-doctor).

## Phase 5. Install Application Atlas

Install `splunk_adm-<version>.tar.gz` (built with `npm run package`, checksum alongside) on the search head: **Manage Apps → Install app from file**, or [splunk-app-install](https://github.com/chambear2809/splunk-cisco-skills/tree/1c93cd87b5a97fe54a2b3284b1d2c43034413edd/skills/splunk-app-install) with a local package. On SHC, use coordinated deployer distribution and the [qualified SHC procedure](../SHC_FINAL_QUALIFICATION.md); a single-member upload does not establish convergence. On Splunk Cloud, submit it for private-app vetting; actual Cloud runtime remains unqualified. The same archive updates an existing installation, but contains neither deployment-owned scope KV rows nor the legacy CSV migration source. Back up deployment state and follow [upgrade preservation checks](../UPGRADES.md) before enabling searches.

**Check:** the **Application Atlas** app opens and shows the synthetic demo.

## Phase 6. Configure the app

1. Open **Application Atlas → Setup** as an administrator to review index macros, summary-index availability, stored observer keys and builder schedules. Set the index macros there (list in [splunk-platform.md](splunk-platform.md#application-atlas-configuration)). Skill: [splunk-knowledge-objects-setup](https://github.com/chambear2809/splunk-cisco-skills/tree/1c93cd87b5a97fe54a2b3284b1d2c43034413edd/skills/splunk-knowledge-objects-setup).
2. As an administrator, populate the `adm_observer_scope` KV lookup with one row per exporter, APIC, Nexus Dashboard, fabric, firewall, cluster and Isovalent HEC source; use the [KV upsert search](splunk-platform.md#application-atlas-configuration). Keep matching keys lowercase and verify collection/lookup ACLs: read `*`, write `admin`/`sc_admin`. Existing installations must first complete the [one-time CSV migration](../UPGRADES.md#one-time-csv-to-kv-scope-migration). The old CSV is not live configuration and no `limits.conf` override is needed.
3. Grant pilot users read on selected source indexes, the active summary index and the app; give the saved-search owner the corresponding source-read and summary-write access. Verify lookup ACLs and effective search/dispatch permissions. Do not grant unrelated data access just to suppress a warning.
4. For optional Cisco V2, configure `adm_index_catalyst`, `adm_index_meraki`, the separate summary pair, explicit `adm_network_source_scope` profiles and per-cluster settings using the [migration runbook](../CISCO_CONTRACT_MIGRATION.md). A configured input or index does not switch the active contract. Keep public selectors at the shipped V1 definitions until authorized, validated cutover.
5. Qualify deployment-settings persistence before saving intent: writes ship disabled, and the endpoint gate is pinned to Enterprise 10.6.0.5. Follow [the supported write contract and deployment gate](../DEPLOYMENT_HEALTH.md#supported-write-contract-and-deployment-gate) for a standalone namespace or coordinated SHC, including package agreement and KV readiness. Cloud and unqualified targets remain read-only. Then use **Setup** to set each source active, staged or not selected, choose expected cadence and receipt freshness, and **Save deployment expectations**. Verify the saved values after refresh. A save does not create inputs, enable jobs, change selectors or authorize migration. Preserve drafts on conflict or uncertain outcomes and follow the [settings recovery rules](../DEPLOYMENT_HEALTH.md#immutable-successor-arbitration) before retrying.

**Check:** `` `adm_index_netflow` | head 1 `` and other selected index macros return the expected raw events; `| inputlookup adm_observer_scope` lists the configured V1 observers. Test optional source profiles independently; they are not replaced by a V1 observer row. Confirm Setup shows the saved source expectations and a coherent active contract. Without saved intent, health stays unknown and Setup's schedule-enable actions remain gated; do not bypass a write-unavailable result.

## Phase 7. Enable the saved searches

After saving expectations and checking source prerequisites, use the [V1 job table](deployment-options.md#choose-v1-jobs) and Setup's job-specific readiness checks to enable only the builders/rollup/catalog needed by the selected features. All ship disabled. Enable prerequisite jobs first (for example, Identity before Service backends). **ADM - Application catalog** runs hourly at minute 15; wait for its actual successful scheduled run before diagnosing an empty catalog. Do not enable V2 writers or change selectors outside the [migration procedure](../CISCO_CONTRACT_MIGRATION.md).

Keep all prune searches disabled, including the Cisco client-history prune. Pruning requires the [paused-writer maintenance procedure](../RECOVERY.md#pruning-and-maintenance). Recovery actions and alerts also need explicit configuration; they are not automatically enabled by installing the app. KV store must be healthy; backup and health: [splunk-kvstore-admin-setup](https://github.com/chambear2809/splunk-cisco-skills/tree/1c93cd87b5a97fe54a2b3284b1d2c43034413edd/skills/splunk-kvstore-admin-setup).

**Check after the applicable jobs complete:**

```spl
`adm_index_summary` source="adm:conversation" | stats count by flow_source
```

```spl
| inputlookup adm_ip_identity | stats count by source, entity_kind
```

These are independent checks: selected traffic feeds contribute summary rows; eligible pod/endpoint feeds contribute identity rows. A source need not populate both. V2 uses its staged summary index and client-history collection, checked through migration validation. Skipped scheduled runs appear in **Activity → Jobs** and the Monitoring Console ([splunk-monitoring-console-setup](https://github.com/chambear2809/splunk-cisco-skills/tree/1c93cd87b5a97fe54a2b3284b1d2c43034413edd/skills/splunk-monitoring-console-setup)).

## Phase 8. Validate the map

Open **Application Atlas → Applications**, select an application or use **Find**, then open its map. In map settings choose **Splunk data**, choose the applicable scope/time window and **Build map**. Validate only claims supported by the selected sources:

- Review warnings for missing evidence, incomplete reads and identity conflicts; compare them with the deployment's recorded source selection.
- Check available workload, IP and external identities. Missing Kubernetes or controller evidence may leave identities unresolved.
- Inspect conversations and **Seen by** observers against raw source records. A candidate fabric path requires corresponding topology; it is not proof of an ordered packet route.
- Check **Devices** against collected, time- and scope-qualified inventory; do not assume every traffic observer has a resolved inventory record.
- For qualified V2, verify Catalyst attachment is not backdated before receipt, and Meraki AP/SSID attribution requires compatible association and flow evidence. Selecting a demo never proves the live path works.
- Confirm a live search failure stays visible and does not substitute synthetic rows. Use **Data health** alongside the [partial-deployment limitations](deployment-options.md#check-a-partial-deployment).

Send the app team the header warnings and one exported **Required flows (CSV)** from this view.

## Operate

- Health and coverage: [splunk-admin-doctor](https://github.com/chambear2809/splunk-cisco-skills/tree/1c93cd87b5a97fe54a2b3284b1d2c43034413edd/skills/splunk-admin-doctor).
- Restarts without surprises: [splunk-platform-restart-orchestrator](https://github.com/chambear2809/splunk-cisco-skills/tree/1c93cd87b5a97fe54a2b3284b1d2c43034413edd/skills/splunk-platform-restart-orchestrator).
- Retention and index growth, especially `cilium_hubble`: [splunk-index-lifecycle-smartstore-setup](https://github.com/chambear2809/splunk-cisco-skills/tree/1c93cd87b5a97fe54a2b3284b1d2c43034413edd/skills/splunk-index-lifecycle-smartstore-setup).
- Don't run a manual identity backfill while **ADM - Identity builder** is running; both write the same KV store collections.
