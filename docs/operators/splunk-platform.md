# Splunk platform team

**Purpose:** prepare Splunk Enterprise 10.6 for the selected Application Atlas sources: indexes, HEC tokens, add-on placement and app configuration. First choose [deployment options](deployment-options.md); the original full pilot is not a requirement to install every product. Cloud requires its own runtime qualification and private-app vetting. The V2 migration helper does not support Cloud or distributed deployments.

## What we need from you

- [ ] Create selected raw indexes and the active summary index with the retention you choose.
- [ ] Create HEC tokens only for selected OTel/Isovalent feeds, restricted to their destination indexes.
- [ ] Install the add-ons on the right tiers.
- [ ] Install Application Atlas on the search head, set its macros and scope lookup, enable its saved searches.
- [ ] Grant pilot users and the saved-search owner access to the indexes.
- [ ] Confirm the runtime required by every selected vendor input is available on its input tier.
- [ ] Qualify deployment-settings persistence, save selected-source expectations in Setup, and verify the stored values before using schedule-enable actions.

## Indexes

Create the raw indexes for selected sources, plus the summary index for the active contract. Names below are defaults; update the corresponding macros if your deployment uses other names.

| Index             | Data                                               | Notes                                                                     |
| ----------------- | -------------------------------------------------- | ------------------------------------------------------------------------- |
| `netflow`         | Splunk Stream NetFlow from ACI leaves              | Volume scales with flow count; see [network-stream.md](network-stream.md) |
| `cisco_dc`        | APIC and Nexus Dashboard objects, flows, endpoints | Polled every 5 minutes by default                                         |
| `cisco_secure_fw` | FTD connection events                              | Default index of the Security Cloud eStreamer input                       |
| `cisco_isovalent` | Isovalent Runtime Security events                  | Default index of the Security Cloud Isovalent input                       |
| `k8s`             | Kubernetes objects from the OTel Collector         | Container logs also land here unless routed elsewhere                     |
| `otel_traces`     | Application spans                                  |                                                                           |
| `cilium_hubble`   | Hubble flow logs                                   | Usually the largest; keep retention short (7–14 days)                     |
| `adm_summary`     | Application Atlas conversation rollups             | Written with the `stash` sourcetype, so it does not count against license |

### Optional Cisco V2 indexes

| Index            | Data                                                                            | Macro / activation                                                        |
| ---------------- | ------------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| `cisco_catalyst` | Catalyst Center client observations                                             | `adm_index_catalyst`; optional V2 enrichment.                             |
| `cisco_meraki`   | Meraki association and inventory observations                                   | `adm_index_meraki`; optional V2 enrichment.                               |
| `netflow`        | Profile-qualified campus, Meraki MS390 and optional SD-WAN Stream/IPFIX traffic | `adm_index_netflow`; exporter profiles distinguish sources.               |
| `adm_summary_v2` | Staged V2 conversations and traffic observations                                | `adm_index_summary_v2` and `adm_summary_index_v2_name`; separate from V1. |

Creating these indexes does not activate V2. Follow the [Cisco handout](cisco-enterprise-networking.md) and [migration procedure](../CISCO_CONTRACT_MIGRATION.md) for source profiles, ACLs, staging and cutover.

## HEC tokens

Create only the tokens needed by selected HEC sources and restrict each to its destination indexes. Catalyst/Meraki modular inputs use the vendor account configuration, not these OTel/Isovalent tokens.

| Token       | Used by                                                        | Allowed indexes                                                      | Default sourcetype                       |
| ----------- | -------------------------------------------------------------- | -------------------------------------------------------------------- | ---------------------------------------- |
| `otel-k8s`  | Splunk OTel Collector Helm chart (`/services/collector/event`) | `k8s`, `otel_traces`, `cilium_hubble` (plus any container-log index) | None; the collector sets each sourcetype |
| `isovalent` | Isovalent Runtime Security export                              | `cisco_isovalent`                                                    | `cisco:isovalent`                        |

The HEC token name becomes the event `source` (`http:<token name>`). Application Atlas uses that source to map Isovalent events to their cluster, so tell us the token name.

## Add-on placement

| Package                             | Search head                      | Indexers / HEC receivers                                 | Heavy forwarder (inputs)                                                       |
| ----------------------------------- | -------------------------------- | -------------------------------------------------------- | ------------------------------------------------------------------------------ |
| Application Atlas (`splunk_adm`)    | Yes                              | No                                                       | No                                                                             |
| Splunk Add-on for Stream Wire Data  | Yes                              | Yes                                                      | No                                                                             |
| Splunk App for Stream               | Yes (manages stream definitions) | No                                                       | No                                                                             |
| Splunk Add-on for Stream Forwarders | No                               | No                                                       | On the host that receives NetFlow (see [network-stream.md](network-stream.md)) |
| Cisco Security Cloud                | Yes                              | Yes (its Isovalent sourcetype rename runs at index time) | Yes, if the eStreamer input runs there                                         |
| Cisco DC Networking                 | Yes                              | Yes                                                      | Yes, where the APIC / Nexus Dashboard inputs run                               |

Install only add-ons required by the selected sources. Optional Catalyst Center and Meraki inputs use the Cisco Enterprise Networking and Cisco Meraki add-ons, respectively. Their inspected versions and raw schemas are recorded in the [package manifest](../../research/package-manifest.json) and [Cisco handout](cisco-enterprise-networking.md). Verify each release's supported input/search/index-tier placement and Python runtime before installation; the local synthetic lab does not qualify vendor input execution.

Cisco Security Cloud inputs declare `python.required = 3.13`; DC Networking inputs declare `3.9`. Confirm the Splunk 10.6 Python runtime on the input tier satisfies both before enabling inputs.

DC Networking's own dashboards use the macros `cisco_dc_aci_index`, `cisco_dc_nd_index` and `cisco_dc_n9k_index`, which default to `index IN ("main")`. Set them to `index IN ("cisco_dc")`.

## Application Atlas configuration

Install from file (**Manage Apps → Install app from file**), then edit these macros under **Settings → Advanced search → Search macros** (app `splunk_adm`):

```text
adm_index_netflow       index=netflow
adm_index_dcn           index=cisco_dc
adm_index_ftd           index=cisco_secure_fw
adm_index_isovalent     index=cisco_isovalent
adm_index_k8s           index=k8s
adm_index_traces        index=otel_traces
adm_traces_sourcetype   sourcetype="otel:traces"
adm_index_summary       index=adm_summary
adm_summary_index_name  adm_summary
adm_index_hubble        index=cilium_hubble
adm_hubble_sourcetypes  sourcetype="cilium:hubble:flow"
# Optional Cisco inputs and staged V2 summary (do not activate by editing selectors):
adm_index_catalyst      index=cisco_catalyst
adm_index_meraki        index=cisco_meraki
adm_index_summary_v2    index=adm_summary_v2
adm_summary_index_v2_name adm_summary_v2
```

### Routing scope lookup

Populate the `adm_observer_scope` KV lookup (fields `observer_kind,observer,scope,cluster`) as an administrator. Its collection and lookup allow all roles to read and only `admin`/`sc_admin` to write, including REST and `outputlookup`. Normalize `observer_kind` and `observer` to lowercase; retain the scope/cluster values. For an existing installation, manually run the disabled administrator migration search as described in the [one-time CSV migration](../UPGRADES.md#one-time-csv-to-kv-scope-migration) before enabling searches. The old CSV is no longer live configuration. IP identities only join within one scope, so every observer of the same routing domain needs the same `scope` value. Example for one ACI VRF:

```csv
observer_kind,observer,scope,cluster
exporter,<leaf-101 OOB IP>,shop-prod,
exporter,<leaf-102 OOB IP>,shop-prod,
apic,<APIC host as configured in DC Networking>,shop-prod,
nd_host,<Nexus Dashboard host>,shop-prod,
fabric,<Nexus Dashboard site/fabric name>,shop-prod,
firewall,<FTD device IP>,shop-prod,
cluster,<Kubernetes cluster name>,shop-prod,<Kubernetes cluster name>
hec_source,http:isovalent,shop-prod,<Kubernetes cluster name>
```

To import administrator-reviewed rows, create them as search results (for example with `makeresults format=csv` using the header above), then finish the search with:

```spl
| eval observer_kind=lower(observer_kind), observer=lower(observer),
       _key=sha256(json_array(observer_kind, observer))
| fields _key observer_kind observer scope cluster
| outputlookup append=true key_field=_key override_if_empty=false adm_observer_scope
```

Verify `| inputlookup adm_observer_scope | table observer_kind observer scope cluster`, and check the collection and lookup ACLs before granting viewer access. No system `limits.conf` override is needed.

Unmapped observers remain isolated in authority-qualified `unmapped:<hash>` scopes. For each selected Kubernetes cluster, the `cluster` row is required: it also scopes Hubble flows and Service frontends (LoadBalancer IPs, NodePorts). The `apic` row also scopes ACI ACL-log records. The cluster, the ACI NetFlow exporters, Nexus Dashboard and the APIC must share one scope, or the map can't link a client's fabric conversation to the backend pod Hubble saw.

Leave `adm_aci_policy_complete` at `0` unless the ACI team collects the optional policy classes in [aci-network.md](aci-network.md#optional-complete-policy-evaluation). With `0`, conversations without a matching permit show "Policy not evaluated" rather than "no permitting contract".

### Saved searches

In **Setup**, configure shared source expectations (active, staged or not selected), cadence and receipt freshness. Writes ship disabled and require [qualified deployment persistence](../DEPLOYMENT_HEALTH.md#supported-write-contract-and-deployment-gate) on the exact Enterprise 10.6.0.5 target; Cloud and unqualified targets remain read-only. Qualifying SHC persistence is separate from the standalone-only V2 migration helper. Verify a saved configuration after refresh; no saved intent means unknown deployment health. Saving expectations does not configure inputs, mappings, public selectors or schedules.

All saved searches ship disabled. Use the [source-to-job table](deployment-options.md#choose-v1-jobs) and Setup's selected-source/contract readiness checks to enable only the V1 builders, conversation rollup and catalog needed for your selected features. Schedule-enable actions require saved expectations; enable prerequisite jobs first. The catalog is **ADM - Application catalog**; it runs hourly at minute 15. Do not enable V2 writers as part of ordinary V1 setup; use the [migration procedure](../CISCO_CONTRACT_MIGRATION.md).

**Keep all prune schedules disabled**, including **ADM - Network client history prune**. Pruning requires pausing and draining every writer and following [Pruning and maintenance](../RECOVERY.md#pruning-and-maintenance); the `adm_prune_maintenance` gate is not a concurrency lock. Do not run a manual builder/backfill concurrently with scheduled writers.

Saved searches run as their owner. Grant source-index reads and the derived-index write capabilities needed by the selected contract; validate their effective app/lookup ACLs and dispatch permissions.

## Roles and KV store

- Pilot users: read on selected source indexes and active derived indexes, plus the `splunk_adm` app; verify effective search messages and lookup ACLs. Shared searches can reference absent/unselected indexes; do not broaden access to unrelated data just to suppress a warning.
- Saved-search owner: same, plus the ability to write to the active contract's derived index (`adm_summary` for V1; the separately configured V2 index after qualified cutover).
- KV store must be healthy. In addition to `adm_ip_identity`, `adm_service_workload` and `adm_interfaces`, the app uses scope, Kubernetes backend/route, ACI policy and catalog collections; V2 adds network source profiles/client history and a separate catalog. Preserve deployment-owned KV data during upgrades; see [backup/restore](../BACKUP_RESTORE.md) and [upgrades](../UPGRADES.md).

## How to verify

```spl
| tstats count where index IN (netflow, cisco_dc, cisco_secure_fw, cisco_isovalent, k8s, otel_traces, cilium_hubble) by index, sourcetype
```

Limit the index list above to selected inputs (add `cisco_catalyst`/`cisco_meraki` when selected). Confirm source-specific schemas, not just event counts. After applicable jobs complete successfully, check their separate outputs:

```spl
`adm_index_summary` source="adm:conversation" | stats count by flow_source
```

```spl
| inputlookup adm_ip_identity | stats count by source, entity_kind
```

These are separate searches: traffic sources populate summaries; eligible endpoint observations populate identity history. Not every source appears in both. For V2, use the active contract's summary index and migration validation, and inspect `adm_network_client_history` independently. Use [readiness checks](../PILOT_READINESS.md) with saved expectations or explicit selected sources in the lab; CLI runs without `--lab` analyze an empty snapshot. The UI uses saved deployment expectations and the active contract for source probes and required jobs; see [deployment checks](deployment-options.md#check-a-partial-deployment).

## Automation skills

Skills from [splunk-cisco-skills](https://github.com/chambear2809/splunk-cisco-skills) render a plan for review, apply only the requested change, and validate it. Run them from Claude Code, Codex or Cursor, or run their scripts directly. Use the vendored commit rather than assuming upstream `main` matches it. Check the exact skill/package release status and guardrails in [SPLUNK_ENTERPRISE_10_6_COMPATIBILITY.md](https://github.com/chambear2809/splunk-cisco-skills/blob/1c93cd87b5a97fe54a2b3284b1d2c43034413edd/SPLUNK_ENTERPRISE_10_6_COMPATIBILITY.md) and follow any documented guardrails before applying.

- Step-by-step order of work with a skill for each step: [splunk-setup-guide.md](splunk-setup-guide.md).
- [splunk-hec-service-setup](https://github.com/chambear2809/splunk-cisco-skills/tree/1c93cd87b5a97fe54a2b3284b1d2c43034413edd/skills/splunk-hec-service-setup), [splunk-app-install](https://github.com/chambear2809/splunk-cisco-skills/tree/1c93cd87b5a97fe54a2b3284b1d2c43034413edd/skills/splunk-app-install), [splunk-knowledge-objects-setup](https://github.com/chambear2809/splunk-cisco-skills/tree/1c93cd87b5a97fe54a2b3284b1d2c43034413edd/skills/splunk-knowledge-objects-setup), [splunk-lookup-file-editing-setup](https://github.com/chambear2809/splunk-cisco-skills/tree/1c93cd87b5a97fe54a2b3284b1d2c43034413edd/skills/splunk-lookup-file-editing-setup), [splunk-kvstore-admin-setup](https://github.com/chambear2809/splunk-cisco-skills/tree/1c93cd87b5a97fe54a2b3284b1d2c43034413edd/skills/splunk-kvstore-admin-setup), [splunk-index-lifecycle-smartstore-setup](https://github.com/chambear2809/splunk-cisco-skills/tree/1c93cd87b5a97fe54a2b3284b1d2c43034413edd/skills/splunk-index-lifecycle-smartstore-setup), [splunk-data-source-readiness-doctor](https://github.com/chambear2809/splunk-cisco-skills/tree/1c93cd87b5a97fe54a2b3284b1d2c43034413edd/skills/splunk-data-source-readiness-doctor).

## What to send back

- Index names (if different from the table), HEC token names, the search head and input hosts, the saved-search owner account.

## Open questions

- Will Hubble flow volume need a separate indexer tier or shorter retention than 7 days?
- For Splunk Cloud later: confirm private-app vetting for custom dashboard JavaScript and the Python version on the IDM / Victoria input tier.

## Sources

App macros, saved searches and collections: `splunk_app/splunk_adm/default/{macros,savedsearches,collections}.conf`. Default indexes and Python requirement: Cisco Security Cloud 3.7.2 `default/inputs.conf:44-49,120-125`; DC Networking 1.2.2 `default/inputs.conf:2-11`, `default/macros.conf:1-9`. Isovalent index-time sourcetype routing: Security Cloud `default/props.conf:2282-2303`, `default/transforms.conf:98-121`. Contract: `docs/DATA_LAYER.md`.
