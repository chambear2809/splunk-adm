# Deployment expectations and health

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
set its expected cadence and receipt freshness in seconds. Settings are stored
in the app's `adm_deployment_settings` KV collection, fixed key `deployment`.
They are shared deployment state, independent of browser preferences and saved
views. The collection permits app readers to read; writes require the effective
`admin_all_objects` capability and collection write permission. The shipped ACL
restricts writes to `admin` and `sc_admin`. Every write has a fresh authorization
and revision preflight followed by a matching readback. Revision checks detect
stale editors and readback conflicts; KV record updates do not provide an atomic
compare-and-swap transaction, so administrators should coordinate concurrent edits.

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
