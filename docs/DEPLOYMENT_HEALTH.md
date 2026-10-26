# Deployment expectations and health

The source registry classifies readiness impact. Existing sources are `core`; `dns_stream`, `dns_hubble`, `proxy_envoy`, `aws_vpc_flow`, `asset_history`, and `o11y_health` are `optional_evidence` and default to unselected, including when old settings omit them. Optional diagnostics are displayed separately and do not affect core readiness, required jobs, quality warnings or the Python readiness exit status. Optional-only selection does not establish a traffic pipeline. These sources are inspected only after an explicit scoped investigation; no background optional evidence macro probes are dispatched. See [operator handouts](operators/README.md#optional-evidence-and-endpointservice-investigations).

Application Atlas uses `config/deployment-health.json` for source names, evidence
types, cadence defaults, active contract dependencies, builder schedules and
prerequisites. The frontend and `tools/pilot_readiness.py` consume this registry.
Source probes return evidence; they do not choose what an administrator intends
to deploy.

Selection happens before dispatch: each configured, applicable source contributes
its named source and quality probes. Shared profile and IPFIX probes are deduplicated,
and the browser runs at most four probes concurrently. Failure or restricted access
is attributed to its probe without hiding other results. Selected index macros are
read and validated before searches; empty or invalid configuration is explicitly
not configured, and unreadable configuration is unknown. Neither state dispatches
a search through a default or unverified index. Unselected sources cannot introduce
unrelated index errors. The readiness tool uses the same probe registry and guard.

## Shared configuration

Setup administrators select each source as active, staged or not selected and
set its expected cadence and receipt freshness in seconds. Settings are shared
deployment state in the app's `adm_deployment_settings` KV collection. Existing
app readers retain read access; the collection's admin/sc_admin write ACL stays
unchanged. The authenticated `adm/deployment-settings` server endpoint requires
`admin_all_objects` for POST and checks the caller's effective capability and
collection write permission again. All downstream requests use the caller's
session token; no system token or credential escalation is used. Splunk documents
that both `admin` and `sc_admin` have this capability by default. Browser CSRF
protection remains enabled through the native `web.conf.spec` default
`skipCSRFProtection = 0`. The exposure defines only `pattern` and `methods`, as
required by AppInspect; it does not override CSRF handling. The custom
`reload.adm_settings = simple` trigger avoids a restart because the endpoint
fetches effective configuration on each request.

### Supported write contract and deployment gate

Writes are disabled by default. After installing the same candidate package on
**every** search head serving this app, an operator must qualify the topology and
set these app-local values in `local/adm_settings.conf`:

```ini
[persistence]
platform = enterprise
write_mode = single_namespace
```

`single_namespace` means one standalone search-head KV Store, including one search
head using distributed indexers. Independent search heads with separate KV Stores
behind a load balancer are unsupported. Their settings are separate deployments;
do not enable this mode to represent them as shared settings. The client binds a
save to the namespace observed on GET, derived from matching search-head and KV current-member GUIDs, and rejects a POST routed to another namespace.

`qualified_shc` is reserved for a coordinated, qualified SHC deployment using one
shared KV namespace. The captured ready 10.6.0.5 cohosted PDL response has
`standalone = false` and no Mongo `replicaSet` or `members` fields; its `peers`
value is null. The endpoint instead checks `/shcluster/status?advanced=1` and
`/shcluster/member/info` with the caller's token. These require the caller's
existing administrator permission or `list_search_head_clustering` capability;
an authorization failure leaves writes unavailable without escalating access.
It requires at least three distinct Up peers with unique HTTPS management URIs,
the qualified version on each peer, no detention, pending restart or out-of-sync
state, a registered Up local member outside maintenance/restart, and an
initialized, stable, service-ready captain outside KV maintenance and rolling
restart/upgrade. The captain management URI must identify exactly one peer.
The current KV GUID must match the server GUID and an SHC peer GUID.

The request namespace uses the documented SHC **cluster GUID** (`captain.id`,
which is distinct from every member GUID), plus sorted member GUIDs and management
URIs. It excludes the elected captain URI and ephemeral PDL port, so captain
changes do not change the namespace. Membership changes require a fresh client
session; this protocol binding does not change ledger keys or discard existing
settings. SHC's configuration captain is distinct from the KV Store captain;
app/configuration distribution does not prove shared persistence. The app calls
the supported KV REST endpoint
on the current member. Splunk delegates SHC writes to the KV captain and keeps
reads local, as documented for the 10.6 cohosted KV store. Qualify competing requests through different members
before enabling this mode, and stop writes for mixed-version upgrades, KV
maintenance, restoration, or replication failures. The endpoint requires ready KV
status, explicit enabled/standalone/backup readiness evidence, matching instance
GUIDs for standalone mode, no version upgrade, and the captured non-migrating
`NotStarted` state. The captured cohosted backend must report `ready` and type
`Pdl`; unknown or unready backend status is rejected. Its dynamically allocated
local service URL is never used for routing or namespace identity. Standalone
10.6 status omits `replicaSet`/`members`; it does not
need invented replica-set metadata. Neither the captured PDL status nor SHC Up
membership establishes each peer's KV replication readiness. The local readiness
and SHC identity checks are deployment guards, not proof of distributed write
arbitration. Operator attestation still requires all-member KV readiness and
coordinated cross-member duplicate-key/concurrency qualification before enabling
writes; local snapshots can remain stale. The runtime gate is pinned to Enterprise
10.6.0.5, the qualification target. Other versions remain read-only until their
installed endpoint/concurrency behavior is qualified. These guards do not replace
deployment qualification. The persistent endpoint explicitly selects
`python.required = 3.13`, supported by the target's native `restmap.conf.spec`;
installed qualification uses Python 3.13.11. A legacy `python.version = python3`
declaration also remains because AppInspect 4.3.1 has an older rule requiring
that selector. Its newer rule accepts the explicit `python.required = 3.13`;
the native specification gives `python.required` precedence, so the qualified
runtime selects Python 3.13. This dual declaration reconciles both tool checks
without weakening them or expanding the qualified platform boundary. Other
Python/platform combinations remain unqualified.

The custom `adm_settings.conf` qualification gate deliberately retains the
platform's default **nonreplicated** configuration behavior. This file is an
operator attestation for the qualified target, separate from the shared settings
ledger. Distribute and verify its approved values on every member through the
coordinated deployment procedure; changing one member must not automatically
enable writes elsewhere. AppInspect's custom-conf replication warning remains
visible for this intentional boundary. No `server.conf` replication override is
shipped to silence it, and a missing/unqualified member gate continues to refuse
writes. This does not change Splunk's KV data replication behavior.

Splunk Cloud remains **unqualified and read-only** pending installation of this
custom endpoint and actual authorized stack qualification. AppInspect alone does
not establish this capability. Unknown versions, unavailable status evidence,
unrecognized topology/configuration, and disabled modes fail closed with a
visible write-unavailable explanation. Existing valid settings remain readable.
There is no fallback to browser writes or unconditional KV updates. The shipped
`platform = unqualified` must be explicitly changed as part of operator
qualification; it is an administrative topology attestation, not automatic Cloud
or load-balancer discovery.

### Immutable successor arbitration

The concurrency primitive is documented KV Store **insert with a unique `_key`**:
POST to the collection inserts a document and duplicate keys are prohibited.
Keyed POST overwrites and `batch_save` upserts, so neither is used. Each accepted
operation occupies an immutable successor slot. The first save competes for
`atomic_root`; later saves compete for `after_<SHA256(expected revision)>`.
Consequently two different operations based on one revision cannot both insert
a successor, including concurrent creation. Browser coordination, process mutexes,
file locks, preflight reads, and readback do not supply this guarantee.

Each inserted row contains the predecessor revision, canonical source settings,
operation/request identity, content fingerprint, and deterministic new revision.
A failed insert is resolved by reading the slot: the same operation is an
idempotent retry; another operation is HTTP 409 conflict. Reusing a request ID
with different expectations is rejected. Retrying a request after its response
was lost still finds its exact immutable operation even after a later successor.
No mutable head pointer, overwrite, or history deletion is needed. The contract
assumes administrators do not bypass the endpoint to edit/delete ledger records;
those operations are outside the concurrency contract and can invalidate history.

Reads describe the observed KV snapshot, which can lag replication. They do not
promise a linearizable distributed read. Bounded reads validate the complete
observed chain and reject malformed, disconnected, or capped history. A sorted
read and its one-row-shifted overlap must agree before a short result can count
as complete; a lower server query cap cannot silently become a valid history
prefix. One bounded rescan can settle a concurrent insertion; repeated mismatch
is unavailable. The 1,024-record bound includes legacy and ledger records. Reaching the bound disables
further changes and requires a separately reviewed migration; never delete old
slots to reclaim space. A client refuses to move behind a revision it has already
observed or silently switch namespaces. A stale first read can produce a conflict
on save, but cannot overwrite a successor.

The endpoint and Setup expose `recordCount`, `maxRecords` and `remainingRecords`.
A warning appears at 90% utilization, and a full history remains readable while
new writes are advertised as unavailable. Plan the separately reviewed migration
before exhaustion; there is no automatic deletion, rotation or limit increase.
The capacity check does not prevent an exact retry of an already committed
operation in the final slot. A separate retry capability still requires current
administrator authorization and a qualified namespace; the browser only uses it
for its retained operation identity. Malformed or inconsistent capacity metadata
leaves the browser read-only.

After insertion the server must observe the exact operation in a valid chain,
and the browser performs another refresh that must contain its committed revision.
Unverifiable outcomes return explicit **uncertain** status, preserve the draft,
and retain the request identity for retry. Cancellation/timeout does not undo an
accepted operation. A retry with identical draft and expected revision resolves
the same operation; after reloading the page, refresh and inspect stored values
before making another edit. If a later operation already superseded the save,
Setup preserves the draft and reports a conflict instead of announcing that its
values remain current. Confirmed conflict requires explicit discard/reload;
background refresh never discards an unsaved draft.

### Existing settings and upgrade safety

The old fixed `deployment` record remains a read-only migration anchor. Its schema
and expectations remain valid. The first endpoint save records its canonical
fingerprint (or explicit absence) in `atomic_root`, then inserts the new settings.
It never rewrites the old record. Every subsequent read checks the anchor. A write
from an older client, creation of an old-format record after an absent migration,
or removal/change of that anchor makes persistence unavailable rather than silently
choosing a competing configuration. Stop old clients/writers and reconcile the
retained values before enabling saves again. Once a ledger exists, malformed or
unavailable ledger data never falls back to legacy settings.

The readiness tool reads the same endpoint. Tools that directly read the old
`deployment` key must migrate to the endpoint before enabling this contract.

The primitive and authentication behavior are documented in Splunk's
[Enterprise KV endpoint reference](https://help.splunk.com/en/splunk-enterprise/leverage-rest-apis/rest-api-reference/10.6/kv-store-endpoints/kv-store-endpoint-descriptions),
[Cloud KV endpoint reference](https://help.splunk.com/en/splunk-cloud-platform/leverage-rest-apis/rest-api-reference/10.0.2503/kv-store-endpoints/kv-store-endpoint-descriptions),
[REST handler configuration](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.6/configuration-file-reference/10.6.0-configuration-file-reference/restmap.conf),
[capability prerequisites](https://help.splunk.com/en/splunk-enterprise/search/search-manual/9.1/run-federated-searches-across-multiple-splunk-deployments/define-a-federated-provider), and
[SHC architecture](https://help.splunk.com/en/splunk-enterprise/administer/distributed-search/9.4/overview-of-search-head-clustering/search-head-clustering-architecture), and
[10.6 KV write routing/local reads](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.6/administer-the-app-key-value-store/about-the-app-key-value-store).
SHC gate fields and cluster identity are documented in the
[10.6 cluster endpoint reference](https://help.splunk.com/en/splunk-enterprise/rest-api-reference/10.6/cluster-endpoints/cluster-endpoint-descriptions)
and [SHC status guidance](https://help.splunk.com/en/splunk-enterprise/administer/distributed-search/10.6/troubleshoot-search-head-clustering/use-the-cli-to-view-information-about-a-search-head-cluster).

No settings is a supported upgrade state: existing maps/searches still work,
while deployment health is **unknown**, with an invitation to configure intent.
All sources initially default to not selected. Missing/malformed/unreadable
settings cannot establish healthy status. A valid configuration with no active
sources also remains unknown. Saving expectations never changes collectors,
source mappings, public macro selectors, pruning, or V2 activation.

The active data contract is read from the marker and all public selector
definitions in the existing reviewed pipeline interface. Missing or mixed
selector evidence is unknown. V2 sources selected while V1 is active are staged.
V2 builders and manual maintenance searches remain outside required V1 job health.

## Evidence and freshness

| Evidence | Interpretation |
| --- | --- |
| Not selected | No operational failure or builder requirement for that source. |
| Staged | Intended future/inactive integration; no production writer requirement. |
| Selected, profile/configuration absent | Not configured; show the missing dependency. |
| No visible indexed records | No recent visible evidence; not proof of a collection outage. |
| Restricted, incomplete or malformed result | Unknown; explain the unavailable evidence. |
| Receipt older than configured freshness | Stale data, or unknown continuity for a quiet feed. |
| Required job disabled, unscheduled, failed or overdue | Needs attention, with configuration/run evidence distinguished. |
| Missing scheduler outcome | Unknown; no success inferred from an enabled search. |
| Unmapped, ambiguous, conflicting or capped correlation | Retain the diagnostic and unresolved relationship. |
| All applicable required evidence supported | Healthy data/job evidence, within the stated observability boundary. |

Raw-source probes use a seven-day **indexed receipt** window, including old or
clock-skewed event timestamps. Settings enforce `60 <= cadence <= freshness <=
604800`. Each row reports its probe window; evidence from a shorter retained
window cannot establish a longer freshness expectation. A recent event timestamp
does not substitute for indexed receipt. Neither proves collector/API permission,
checkpoint progress or uninterrupted collection. Those checks remain unknown
unless independently verified. Health is not production qualification.

Catalyst defaults allow an hourly poll (three-hour freshness). Meraki associations,
Nexus Dashboard discovery and Kubernetes object feeds can be quiet; lack of new
receipt does not by itself prove collection failed. Configuration rows use mapping
completeness instead of fictitious event timestamps. V2 profile health is partitioned
by supported source family. A global inventory of profiles remains diagnostic;
unselected families do not fail selected-family health. Unclassifiable IPFIX profile
evidence remains explicit uncertainty for a selected IPFIX integration.

Quality searches use their documented candidate eligibility and 24-hour window;
they are not raw collection audits. Selected-family evaluated rows supply quality
coverage. Missing selected-family evidence stays unknown even if other sources
have events. Unknown supported V2 dispositions and reasons remain visible.

## Setup lifecycle and readiness

Setup loads shared expectations and configuration plus **one targeted
`adm_health_jobs` search**. It does not dispatch source or quality probes and has
no health polling timer. Initial load, explicit refresh and a verified write
refresh job evidence. Navigation, replacement clients, hiding the page and stale
responses cancel or invalidate pending work. Other live pages retain the existing
five-minute health refresh; Help does not start health searches.

Unsaved expectation edits survive passive health refreshes, including leaving and
returning to the browser tab. If another administrator saves a newer revision,
Setup preserves the draft and blocks saving until the administrator explicitly
discards/reloads or resolves the conflict. A verified save resets the draft.

Builder requirements come from the selected source chain and contract. Inventory-only
NX-OS has no mandatory rollup; NetFlow does not require DC Networking, Kubernetes
or traces. Kubernetes backends require identity; trace binding requires its trace
configuration. Observer mapping requirements use each job's source-specific observer
kinds. Read-only Cisco diagnostics distinguish staged V1, coherent active V2 and
mixed/incomplete configuration; they provide no activation or migration controls.

`pilot_readiness.py --lab` reads the shared settings using the exclusive local lab
workflow. Explicit `--source` arguments scope an operator's read-only investigation;
they do not persist deployment intent. The tool checks the same cadence/job registry
and retains stricter qualification evidence for permissions, schemas and collection.
Its `ready` result does not qualify an untested vendor deployment.
Required summary and profile-family evidence is assessed along with the selected
raw sources. Raw-field probes inherit the same contract and index guards. Snapshot
completion time and fractional scheduler timestamps are retained, so observations
received during collection do not become false future-clock failures.
