# AppDynamics inventory evidence

Application Atlas does not call an AppDynamics Controller from the browser or
Splunk search head. An operator runs a bounded read-only collector, validates
the generated capture locally, then queues the two finalized HEC captures with
the shared delivery utility. One capture contains the Controller hierarchy
and modeled backend candidates. The second contains current-only node-IP rows
in the existing Asset History v1 contract.

## Controller access

Use a Controller version whose Application Model API response fields match
the [documented 26.10 contract](https://help.splunk.com/en/appdynamics-saas/extend-splunk-appdynamics/26.10.0/extend-splunk-appdynamics/splunk-appdynamics-apis/application-model-api).
The collector reads XML from the applications, tiers, nodes-by-tier and
application-backends GET endpoints. The node response must have the documented
`ipAddresses/ipAddress` wrapper. Unknown or partial response shapes fail the
whole capture. The collector does not use `time-range-type`, since “alive on a
GMT day” does not establish an address assignment interval.

Create a dedicated API client with a read-only role and **Applications > View**
on only the applications the export should include. The [least-privilege API
client guidance](https://help.splunk.com/en/appdynamics-saas/mcp-server-integration/26.7.0/configure-a-least-privileged-api-client)
describes that read permission. The API client uses OAuth client credentials;
the account name and API client name are combined as
`<apiClientName>@<accountName>`. Give the runtime client no app-edit,
configuration, event-mutation or account-administration rights.

The collector accepts only an exact HTTPS origin. TLS verification is enabled,
redirects are refused, and requests stay on the configured origin. Inject
`APPD_API_CLIENT_NAME`, `APPD_ACCOUNT_NAME` and `APPD_CLIENT_SECRET` through
your secret manager or controlled process environment. Do not put values in
shell history, command-line arguments, chat, source files or reports. The
collector does not print them. The output snapshot and derived captures are
created outside the repository with owner-only file permissions.

## Collect and validate

Run the commands from the unpacked toolkit root. Set the Controller authority
to the same lowercase stable name used in its `appd_controller` scope mapping.
The authority is an Application Atlas identity namespace; it is not the
Controller URL or account name.

```sh
python3 -m tools.export_appdynamics \
  --controller-origin https://controller.example.test \
  --authority appd-prod-east \
  --scope prod-east \
  --output /var/tmp/appdynamics.snapshot.json

python3 -m tools.import_appdynamics /var/tmp/appdynamics.snapshot.json \
  --appd-output /var/tmp/appdynamics.hec.ndjson \
  --asset-history-output /var/tmp/appdynamics-asset-history.hec.ndjson \
  --report /var/tmp/appdynamics.validation.json
```

The collector uses the documented read endpoints only and enforces per-response
8 MiB, total-response 50 MiB, 600-second wall-clock, 20-second request,
application/tier/node/backend and 10,000-record caps. It retries only HTTP
429/502/503/504, at most twice. Any failed request, unknown response shape or
limit breach fails the whole snapshot. The importer rejects mismatched schema,
authority, scope, snapshot times, record counts, fingerprints, identity
references, IP data or backend associations. It validates the Asset History
manifest against the same node records before writing either output. The
importer caps accepted snapshot input at 50 MiB and rejects a record whose
rendered HEC line exceeds 65,535 bytes, so Splunk does not silently truncate a
large evidence record.

Review the sanitized validation summary. `asset_history_conflict_count` reports
shared-IP ambiguity; it is not a reason to merge distinct node IDs. Snapshot
absence does not retire prior node assignments. The generated records use
`validity_basis=snapshot_current`, contain no `valid_to` or `retired_at`, and
must not be used to claim who owned an IP earlier in the selected traffic
window.

## Queue and deliver

Qualify each destination index and source before enabling the source. The
hierarchy capture uses source ID `appdynamics_inventory`,
`sourcetype=adm:appdynamics_inventory` and schema
`application_atlas.appdynamics_inventory.v1`. The node-IP capture uses source
ID `appdynamics_asset_history`, `sourcetype=adm:asset_history` and the existing
Asset History schema. Route both through your approved HEC receiver and use
the shared durable sender; it owns retries, checkpoints and HEC TLS behavior.

```sh
python3 -m tools.hec_delivery enqueue \
  --input /var/tmp/appdynamics.hec.ndjson \
  --source-id appdynamics_inventory
python3 -m tools.hec_delivery enqueue \
  --input /var/tmp/appdynamics-asset-history.hec.ndjson \
  --source-id appdynamics_asset_history
python3 -m tools.hec_delivery status
python3 -m tools.hec_delivery send
```

Provide `ATLAS_HEC_URL`, `ATLAS_HEC_TOKEN` and `ATLAS_HEC_SPOOL_DIR` through
the controlled runtime environment. Configure `ATLAS_HEC_CA_BUNDLE` if the
receiver uses a private CA. The sender requires verified HTTPS and refuses
redirects. It retains the input capture and reports HTTP acceptance separately
from Enterprise indexer acknowledgement; neither status proves that events
are searchable. Verify readback in the target search indexes with the exact
sourcetype, source, schema version, authority, snapshot ID and count.

## Configure Atlas

1. Add one verified `adm_observer_scope` mapping per Controller authority and
   routing scope: `observer_kind=appd_controller`, lowercase `observer`, the
   exact `scope`, and `mapping_status=verified`. Set `controller_origin` to
   the exact HTTPS Controller origin, with no path, query, fragment or user
   information. This value controls only the safe root link in the panel.
2. Set the app-merged `adm_index_appdynamics_inventory` macro to the literal
   destination index or approved index list. Set
   `adm_appdynamics_inventory_schema_qualified=1` only after inspecting
   indexed sample events for the complete v1 schema, timestamp extraction,
   counts and Controller authority.
3. In Setup, select `appdynamics_inventory`, keep the Controller mapping
   verified for the investigation scope, and choose `staleAfterSeconds` to
   match collection cadence and index delay. The window is a current-snapshot
   freshness bound, not a historical assignment interval.
4. Configure the existing `adm_index_asset_history` and
   `adm_asset_history_schema_qualified` settings separately for
   `appdynamics_asset_history`. Add the same scope mapping under
   `observer_kind=asset_authority`, using the canonical authority emitted in
   the Asset History event. Follow the [Asset History handout](asset-history.md)
   for its current-only semantics.

The optional source remains disabled until its index, schema qualification,
permissions and mapping are verified. The search uses the viewer's Splunk
permissions and runs only after the user requests inspection. It is bounded to
a 10,001-row authority scan and a 64-row focused result. A cap, timeout, stale
snapshot, tied latest capture, incomplete manifest, changed configuration or
unqualified source suppresses relationships.

## Read the panel

The panel displays current node IPs that exactly match the selected endpoint,
along with separate application, tier and node IDs. A shared address can
produce multiple nodes. Backend rows are candidate inventory. A
`verified_node` association means only the positive Controller IDs matched a
node in this same complete snapshot; zero IDs are application-scoped, and
unmatched positive IDs remain unverified. Endpoint candidate equality is not
observed traffic, a runtime-selected destination or a graph edge. Hostname
candidates remain unresolved.

The 26.10 [Tiers and Nodes UI guide](https://help.splunk.com/en/appdynamics-saas/application-performance-monitoring/26.10.0/tiers-and-nodes)
shows users how to locate an application and expand its tier in the Controller
UI. The reviewed documentation does not publish stable application/tier/node
or backend UI deep-link routes. The panel links only to the configured
Controller origin and shows object IDs for manual navigation. It does not
construct URLs from source event names, IDs or backend properties.

## Rollback and retention

Disable `appdynamics_inventory` in Setup to stop future Atlas searches. Remove
the optional source macro/schema qualification and verified AppDynamics scope
mapping after disabling it, if the data source is retired. Previously indexed
events remain subject to normal Splunk retention, index ACLs and your
organization's deletion process. The independent Asset History source has its
own selector and mapping; disable or retain it separately.

Qualification is local and synthetic in this repository. It does not prove a
customer Controller version, the assigned API role, network reachability,
indexer timing, retention, deployment search permissions or HEC searchable
readback. Capture those checks in the target environment before relying on the
source.
