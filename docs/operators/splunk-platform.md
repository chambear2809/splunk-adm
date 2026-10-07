# Splunk platform team

**Purpose:** prepare Splunk Enterprise 10.6 for the pilot: indexes, HEC tokens, add-on placement, and the Application Atlas app itself. Every other team sends data to what you set up here. Splunk Cloud follows the same plan with ACS and private-app vetting.

## What we need from you

- [ ] Create the indexes below with the retention you choose.
- [ ] Create two HEC tokens (OTel Collector, Isovalent) restricted to their indexes.
- [ ] Install the add-ons on the right tiers.
- [ ] Install Application Atlas on the search head, set its macros and scope lookup, enable its saved searches.
- [ ] Grant pilot users and the saved-search owner access to the indexes.
- [ ] Confirm the Python runtime required by Cisco Security Cloud is available.

## Indexes

| Index | Data | Notes |
| --- | --- | --- |
| `netflow` | Splunk Stream NetFlow from ACI leaves | Volume scales with flow count; see [network-stream.md](network-stream.md) |
| `cisco_dc` | APIC and Nexus Dashboard objects, flows, endpoints | Polled every 5 minutes by default |
| `cisco_secure_fw` | FTD connection events | Default index of the Security Cloud eStreamer input |
| `cisco_isovalent` | Isovalent Runtime Security events | Default index of the Security Cloud Isovalent input |
| `k8s` | Kubernetes objects from the OTel Collector | Container logs also land here unless routed elsewhere |
| `otel_traces` | Application spans | |
| `cilium_hubble` | Hubble flow logs | Usually the largest; keep retention short (7–14 days) |
| `adm_summary` | Application Atlas conversation rollups | Written with the `stash` sourcetype, so it does not count against license |

## HEC tokens

| Token | Used by | Allowed indexes | Default sourcetype |
| --- | --- | --- | --- |
| `otel-k8s` | Splunk OTel Collector Helm chart (`/services/collector/event`) | `k8s`, `otel_traces`, `cilium_hubble` (plus any container-log index) | None; the collector sets each sourcetype |
| `isovalent` | Isovalent Runtime Security export | `cisco_isovalent` | `cisco:isovalent` |

The HEC token name becomes the event `source` (`http:<token name>`). Application Atlas uses that source to map Isovalent events to their cluster, so tell us the token name.

## Add-on placement

| Package | Search head | Indexers / HEC receivers | Heavy forwarder (inputs) |
| --- | --- | --- | --- |
| Application Atlas (`splunk_adm`) | Yes | No | No |
| Splunk Add-on for Stream Wire Data | Yes | Yes | No |
| Splunk App for Stream | Yes (manages stream definitions) | No | No |
| Splunk Add-on for Stream Forwarders | No | No | On the host that receives NetFlow (see [network-stream.md](network-stream.md)) |
| Cisco Security Cloud | Yes | Yes (its Isovalent sourcetype rename runs at index time) | Yes, if the eStreamer input runs there |
| Cisco DC Networking | Yes | Yes | Yes, where the APIC / Nexus Dashboard inputs run |

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
```

The Hubble index and sourcetype macros arrive with the access-path release; use `cilium_hubble` and `cilium:hubble:flow` so no change is needed later.

### Routing scope lookup

Fill `adm_observer_scope.csv` (columns `observer_kind,observer,scope,cluster`). IP identities only join within one scope, so every observer of the same routing domain needs the same `scope` value. Example for one ACI VRF:

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

Unmapped observers fall into scope `default`.

### Saved searches

Enable after the macros and lookup are set (they ship disabled): **ADM - Identity builder**, **ADM - Service binding**, **ADM - Interface inventory**, **ADM - Conversation rollup**, **ADM - Identity prune**, **ADM - Service binding prune**. They run as their owner, so the owner needs read access to all source indexes and write access to `adm_summary`. Do not run a manual identity backfill while the scheduled builder runs; both write the same KV store collections.

## Roles and KV store

- Pilot users: read on all indexes above, read on the `splunk_adm` app.
- Saved-search owner: same, plus the ability to write to `adm_summary`.
- KV store must be running on the search head; Application Atlas stores identity history in collections `adm_ip_identity`, `adm_service_workload` and `adm_interfaces`.

## How to verify

```spl
| tstats count where index IN (netflow, cisco_dc, cisco_secure_fw, cisco_isovalent, k8s, otel_traces, cilium_hubble) by index, sourcetype
```

After the saved searches have run for 15 minutes:

```spl
index=adm_summary source="adm:conversation" | stats count by sources
| inputlookup adm_ip_identity | stats count by source, entity_kind
```

## What to send back

- Index names (if different from the table), HEC token names, the search head and input hosts, the saved-search owner account.

## Open questions

- Will Hubble flow volume need a separate indexer tier or shorter retention than 7 days?
- For Splunk Cloud later: confirm private-app vetting for custom dashboard JavaScript and the Python version on the IDM / Victoria input tier.

## Sources

App macros, saved searches and collections: `splunk_app/splunk_adm/default/{macros,savedsearches,collections}.conf`. Default indexes and Python requirement: Cisco Security Cloud 3.7.2 `default/inputs.conf:44-49,120-125`; DC Networking 1.2.2 `default/inputs.conf:2-11`, `default/macros.conf:1-9`. Isovalent index-time sourcetype routing: Security Cloud `default/props.conf:2282-2303`, `default/transforms.conf:98-121`. Contract: `docs/DATA_LAYER.md`.
