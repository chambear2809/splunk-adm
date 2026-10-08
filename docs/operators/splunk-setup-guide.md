# Splunk setup guide for Application Atlas

An ordered runbook for the Splunk administrator, from a Splunk Enterprise 10.6 deployment to a working dependency map. Each phase ends with a check; don't start the next phase until it passes. The tables of indexes, tokens and add-on placement are in [splunk-platform.md](splunk-platform.md); this guide is the order of work.

Automation: each step names the matching skill from [splunk-cisco-skills](https://github.com/chambear2809/splunk-cisco-skills), vendored in this repo at `vendor/splunk-cisco-skills` (pinned submodule) and discoverable from Claude Code, Cursor and Codex — see [the main README](../../README.md#operator-setup-skills). Skills are render-first: they produce a plan you review, apply only the requested change, then validate. Run them from Claude Code, Codex or Cursor, or run their scripts directly from that directory: `cd vendor/splunk-cisco-skills && bash skills/<skill-name>/scripts/setup.sh --help`.

> **Compatibility.** The skills repo's `main` branch now covers Splunk Enterprise 10.6: check each skill's own 10.6 status (`supported`, `conditional`, or `not-applicable`) in [SPLUNK_ENTERPRISE_10_6_COMPATIBILITY.md](https://github.com/chambear2809/splunk-cisco-skills/blob/main/SPLUNK_ENTERPRISE_10_6_COMPATIBILITY.md) and follow any documented guardrails before applying. The pilot uses **Cisco Security Cloud 3.7.2** (the version this app's field mappings were verified against). The `cisco-security-cloud-setup` skill's default install path pins `3.6.10`; select 3.7.2 explicitly with `--version 3.7.2` (and `--accept-unsupported-platform` with documented vendor approval if the skill doesn't carry independent 10.6/Cloud evidence for that exact release), and confirm the installed version afterwards.

## Phase 0. Plan

1. Size the deployment for the expected NetFlow, Hubble and span volume. Hubble flow logs are usually the largest source. Skill: [splunk-platform-sizing](https://github.com/chambear2809/splunk-cisco-skills/tree/main/skills/splunk-platform-sizing).
2. Decide which host runs the modular inputs (DC Networking, Cisco Security Cloud) and which host receives NetFlow (Stream forwarder). A heavy forwarder for the inputs: [splunk-enterprise-host-setup](https://github.com/chambear2809/splunk-cisco-skills/tree/main/skills/splunk-enterprise-host-setup).
3. Confirm the license covers the source volume. The app's own summary data uses the `stash` sourcetype and is not licensed. Skill: [splunk-license-manager-setup](https://github.com/chambear2809/splunk-cisco-skills/tree/main/skills/splunk-license-manager-setup).

**Check:** you know the search head, the indexers, the input host and the NetFlow receiver host.

## Phase 1. Indexes

Create `netflow`, `cisco_dc`, `cisco_secure_fw`, `cisco_isovalent`, `k8s`, `otel_traces`, `cilium_hubble` and `adm_summary` on the indexers, with the retention you chose (Hubble 7–14 days). Use your normal `indexes.conf` deployment; for retention planning and later changes use [splunk-index-lifecycle-smartstore-setup](https://github.com/chambear2809/splunk-cisco-skills/tree/main/skills/splunk-index-lifecycle-smartstore-setup). On Splunk Cloud later: [splunk-cloud-acs-admin-setup](https://github.com/chambear2809/splunk-cisco-skills/tree/main/skills/splunk-cloud-acs-admin-setup).

**Check:** `| eventcount summarize=false index=* | search index IN (netflow, cisco_dc, cisco_secure_fw, cisco_isovalent, k8s, otel_traces, cilium_hubble, adm_summary)` lists all eight.

## Phase 2. HEC tokens

Create `otel-k8s` (allowed indexes `k8s`, `otel_traces`, `cilium_hubble`) and `isovalent` (allowed index `cisco_isovalent`, sourcetype `cisco:isovalent`). Skill: [splunk-hec-service-setup](https://github.com/chambear2809/splunk-cisco-skills/tree/main/skills/splunk-hec-service-setup). Hand the token values to the Kubernetes and Isovalent teams through your secret-management process, never in tickets or chat.

**Check:** each token appears under **Settings → Data inputs → HTTP Event Collector**, enabled, with only its allowed indexes.

## Phase 3. Add-ons

Install each package on the tiers in [splunk-platform.md](splunk-platform.md#add-on-placement): Splunk Add-on for Stream Wire Data, Splunk App for Stream, Splunk Add-on for Stream Forwarders, Cisco Security Cloud, Cisco DC Networking. Skill: [splunk-app-install](https://github.com/chambear2809/splunk-cisco-skills/tree/main/skills/splunk-app-install). If you manage forwarders centrally: [splunk-deployment-server-setup](https://github.com/chambear2809/splunk-cisco-skills/tree/main/skills/splunk-deployment-server-setup). Restart only where needed: [splunk-platform-restart-orchestrator](https://github.com/chambear2809/splunk-cisco-skills/tree/main/skills/splunk-platform-restart-orchestrator).

Set DC Networking's macros `cisco_dc_aci_index`, `cisco_dc_nd_index`, `cisco_dc_n9k_index` to `index IN ("cisco_dc")`. Confirm the input host's Python runtime meets Security Cloud's `python.required = 3.13`.

**Check:** **Manage Apps** shows each package on the intended hosts; `splunk btool check` reports no errors.

## Phase 4. Data sources

Work with each team using its handout. Configure the Splunk-side inputs yourself where they run on Splunk hosts.

| Source                                      | Splunk-side work                                                                                           | Skill                                                                                                                                                                                                                                                                                                                      | Team handout                                     |
| ------------------------------------------- | ---------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------ |
| APIC / Nexus Dashboard                      | DC Networking accounts and inputs, plus the `application-atlas`/`adm` and `adm-policy` `classInfo` presets | [cisco-dc-networking-setup](https://github.com/chambear2809/splunk-cisco-skills/tree/main/skills/cisco-dc-networking-setup)                                                                                                                                                                                                | [aci-network.md](aci-network.md)                 |
| ACI NetFlow                                 | Stream forwarder NetFlow receiver, `netflow` stream enabled                                                | [splunk-stream-setup](https://github.com/chambear2809/splunk-cisco-skills/tree/main/skills/splunk-stream-setup)                                                                                                                                                                                                            | [network-stream.md](network-stream.md)           |
| FTD                                         | Security Cloud eStreamer input                                                                             | [cisco-security-cloud-setup](https://github.com/chambear2809/splunk-cisco-skills/tree/main/skills/cisco-security-cloud-setup)                                                                                                                                                                                              | [firewall-security.md](firewall-security.md)     |
| Isovalent                                   | Security Cloud Isovalent HEC input                                                                         | [cisco-security-cloud-setup](https://github.com/chambear2809/splunk-cisco-skills/tree/main/skills/cisco-security-cloud-setup)                                                                                                                                                                                              | [cilium-isovalent.md](cilium-isovalent.md)       |
| Hubble flow export                          | Cilium's `hubble_flow_export` block                                                                        | [cisco-isovalent-platform-setup](https://github.com/chambear2809/splunk-cisco-skills/tree/main/skills/cisco-isovalent-platform-setup)                                                                                                                                                                                      | [cilium-isovalent.md](cilium-isovalent.md)       |
| Kubernetes objects, spans, Hubble file tail | None (Helm chart sends to HEC)                                                                             | [splunk-observability-otel-collector-setup](https://github.com/chambear2809/splunk-cisco-skills/tree/main/skills/splunk-observability-otel-collector-setup), [splunk-observability-isovalent-integration](https://github.com/chambear2809/splunk-cisco-skills/tree/main/skills/splunk-observability-isovalent-integration) | [kubernetes-platform.md](kubernetes-platform.md) |

**Check:** every source shows data:

```spl
| tstats count where index IN (netflow, cisco_dc, cisco_secure_fw, cisco_isovalent, k8s, otel_traces, cilium_hubble) by index, sourcetype
```

Expect at least `stream:netflow`, `cisco:dc:aci:class`, `cisco:dc:aci:stats`, `cisco:dc:nd:flows`, `cisco:dc:nd:endpoints`, `cisco:sfw:estreamer`, `cisco:isovalent:processConnect`, `kube:object:pods`, `kube:object:services`, `kube:object:endpointslices`, `otel:traces` and `cilium:hubble:flow`. For a fuller readiness report: [splunk-data-source-readiness-doctor](https://github.com/chambear2809/splunk-cisco-skills/tree/main/skills/splunk-data-source-readiness-doctor).

## Phase 5. Install Application Atlas

Install `splunk_adm-<version>.tar.gz` (built with `npm run package`, checksum alongside) on the search head: **Manage Apps → Install app from file**, or [splunk-app-install](https://github.com/chambear2809/splunk-cisco-skills/tree/main/skills/splunk-app-install) with a local package. On Splunk Cloud, submit it for private-app vetting.

**Check:** the **Application Atlas** app opens and shows the synthetic demo.

## Phase 6. Configure the app

1. Set the index macros (list in [splunk-platform.md](splunk-platform.md#application-atlas-configuration)). Skill: [splunk-knowledge-objects-setup](https://github.com/chambear2809/splunk-cisco-skills/tree/main/skills/splunk-knowledge-objects-setup).
2. Fill `adm_observer_scope.csv` with one row per exporter, APIC, Nexus Dashboard, fabric, firewall, cluster and Isovalent HEC source. Skill: [splunk-lookup-file-editing-setup](https://github.com/chambear2809/splunk-cisco-skills/tree/main/skills/splunk-lookup-file-editing-setup).
3. Grant pilot users read on the source indexes and the app; give the saved-search owner write to `adm_summary`.

**Check:** `` `adm_index_netflow` | head 1 `` and the other index macros return events; `| inputlookup adm_observer_scope.csv` lists every observer.

## Phase 7. Enable the saved searches

Enable **ADM - Identity builder**, **ADM - Service binding**, **ADM - Service backends**, **ADM - ACI policy**, **ADM - Interface inventory**, **ADM - Conversation rollup**, **ADM - Identity prune**, **ADM - Service binding prune**, **ADM - Service backends prune**, **ADM - Service routes prune** and **ADM - ACI policy prune** (they ship disabled). Skill: [splunk-knowledge-objects-setup](https://github.com/chambear2809/splunk-cisco-skills/tree/main/skills/splunk-knowledge-objects-setup). KV store must be healthy on the search head; backup and health: [splunk-kvstore-admin-setup](https://github.com/chambear2809/splunk-cisco-skills/tree/main/skills/splunk-kvstore-admin-setup).

**Check (after 15 minutes):**

```spl
index=adm_summary source="adm:conversation" | stats count by sources
```

```spl
| inputlookup adm_ip_identity | stats count by source, entity_kind
```

Both return rows for every source you enabled. Skipped scheduled runs appear in **Activity → Jobs** and the Monitoring Console ([splunk-monitoring-console-setup](https://github.com/chambear2809/splunk-cisco-skills/tree/main/skills/splunk-monitoring-console-setup)).

## Phase 8. Validate the map

Open **Application Atlas**, switch to **Splunk data**, enter the entry service, environment, cluster and namespace, and load the last hour. Check:

- The header warnings: each names a missing source, a capped read, or an identity conflict.
- Pods, the ACI VM clients and external destinations appear with the right identity state (Identified, Unknown IP, External).
- Selecting a conversation shows the candidate path with leaves and spines, and **Seen by** lists the devices you expect.
- **Devices** lists every leaf and node that exported data.

Send the app team the header warnings and one exported **Required flows (CSV)** from this view.

## Operate

- Health and coverage: [splunk-admin-doctor](https://github.com/chambear2809/splunk-cisco-skills/tree/main/skills/splunk-admin-doctor).
- Restarts without surprises: [splunk-platform-restart-orchestrator](https://github.com/chambear2809/splunk-cisco-skills/tree/main/skills/splunk-platform-restart-orchestrator).
- Retention and index growth, especially `cilium_hubble`: [splunk-index-lifecycle-smartstore-setup](https://github.com/chambear2809/splunk-cisco-skills/tree/main/skills/splunk-index-lifecycle-smartstore-setup).
- Don't run a manual identity backfill while **ADM - Identity builder** is running; both write the same KV store collections.
