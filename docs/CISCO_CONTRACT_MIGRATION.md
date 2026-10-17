# Summary contract v2 staging and migration

## Current status

The migration helper supports preparation, bounded backfill, persisted-row
validation, read-only public-surface smoke checks, and journaled cutover or
rollback on a qualified standalone Splunk Enterprise target. Cutover remains
blocked until every required public surface and activation target passes the
exact manifest checks and successful, contiguous V2 scheduler cycles are
observed through a frozen index-ingestion audit boundary. The isolated target's
deployment shape passed TLS-verified qualification. The local disabled-origin
stage, scheduled-cycle bridge, selector cutover, and rollback run passed.
Enabled-origin missed-window recovery also passed with diagnostic artifact retention and same-journal resumption; consult
[the qualification record](CISCO_NETWORKING_QUALIFICATION.md) for current gates.

The shipped contract remains v1: `adm_data_contract_version=1`,
`adm_graph(4)`, the legacy `ADM - Conversation rollup` writer, and
`adm_summary_index_name=adm_summary`. The separate v2 index is
`adm_summary_v2`; the v2 writer index macro is
`adm_summary_index_v2_name=adm_summary_v2`. The helper never redirects the
legacy v1 index macro. Old summary data remains available for rollback.

## Qualification and prerequisites

Run `tools/cisco_contract_migration.py` from a checkout of the matching Atlas
release using Python 3.11 or newer. This external operator tool uses the
checkout's `research/cisco-pipeline-interface.json` and bundled REST client.
It is not installed as an executable inside the Splunk app archive. Keep that
checkout available with the durable migration evidence throughout rollback.

The helper calls the package's deployment qualifier before REST access that
can mutate state. The observed target is standalone Splunk Enterprise
10.6.0.5 with Search Head Clustering explicitly disabled and no remote peers.
The qualifier refuses Cloud, Search Head Cluster, indexer clustering, unknown
deployment shape, and missing/incomplete evidence. This local shape check does
not qualify SHC, Cloud, a customer environment, or an exporter deployment.

Use a TLS-verified local management endpoint and an administrator session
with the required search and collection capabilities. The command reads the
session key from standard input (or a hidden prompt), never from an argument.
Use an owner-only journal path on durable local storage. The journal and its
lock contain SIDs, query fingerprints, bounded normalized summary evidence,
history hash keys, and migration state. Some bounded V1 recovery evidence and
origin lookup snapshots include normalized client or deployment values such as
IP addresses and network identifiers. The journal does not contain raw source
events or the session key. Keep it on owner-only durable storage with the
migration record, and do not edit it by hand.

Completed query results are stored beside the journal in owner-only,
checksummed `.result-*.json` artifacts. Each artifact binds its migration ID,
job ID, query fingerprint, exact bounds, and result count. Retain the whole
migration directory for resume and rollback: missing, changed, or unsafe files
stop recovery without redispatch. The journal remains limited to 16 MiB;
each result artifact is limited to 16 MiB and aggregate result evidence to
256 MiB, including orphan files from an interrupted journal replacement.
Existing inline results are moved into this format on the next durable write.
Artifact durability precedes the journal reference, and an interrupted write
reuses the same recorded SID and immutable artifact. These bounds limit the
supported backfill volume; split larger qualification work into independently
reviewed windows rather than raising the limits without measurement.

Splunk's scheduled-job artifacts must also remain available throughout the
cutover audit, including any interruption. The helper does not automatically
extend their TTL. Before an artifact expires, an operator may extend the TTL
of the exact verified scheduler SID using Splunk's job-control `setttl` action;
record the request and verify the same SID and TTL on readback. Allow enough
retention for the planned audit and recovery interval. The local diagnosis
extended four existing artifacts from 600 to 7,200 seconds and verified each
readback. This retains existing evidence; it does not execute another search.
Missing or expired required cycles still block qualification. A successful
scheduler log entry alone cannot replace the required job and result evidence.

## Staging flow

1. Choose an inclusive start and exclusive end aligned to five-minute UTC
   epochs. The selected closed index-time range may not exceed seven days,
   and its end must leave two five-minute slices for indexing lag.
2. Prepare once with the chosen range. Preparation qualifies the deployment,
   verifies the effective v1/v2 macros and writers, records the initial
   effective configuration and ACLs, and audits pre-existing v2 index rows.
3. Backfill runs the conversation and traffic searches separately
   for every five-minute index-time slice. Because Splunk cannot dispatch a
   disabled saved search, the helper journals a temporary manual-execution
   window: turn scheduling off, enable the search, dispatch with actions off,
   then disable the search before restoring its original schedule. Every
   configuration transition requires ACL/definition checks and readback.
   Already enabled writers authorized by cutover retain their schedule. It also stages the additive
   adm_network_client_history collection from the exact bounded history
   observation query. History validation requires every expected hash key,
   allowed mapping status, complete paged collection reads, and receipt merge
   semantics; the journal stores hash keys and fingerprints for that collection.
   A summary slice compares source-derived rollup IDs
   and event-record counts with the actual persisted rows in
   `adm_summary_v2`. An empty slice is also compared. The job must complete
   with no truncation, dropped events, warnings, or incomplete result pages.
   The source search is bounded by the selected raw index-time slice and a
   journaled absolute event-time upper bound. The persisted-summary search is
   keyed by that slice's expected rollup IDs and a separate bounded summary
   ingestion-time window; it never reuses raw slice index-time bounds. The
   helper polls a limited number of times for index visibility before it
   refuses an incomplete match.
4. Validate repeats the source and persisted-coverage checks, then builds the
   separate adm_app_catalog_v2 collection. It requires one valid catalog
   status row, complete output rows, and a complete unique-key readback whose
   exact key set and stable values match the collection. A new staged-data
   fingerprint starts a distinct durable catalog build generation; update
   timestamps may change without making otherwise identical rows drift. It
   does not overwrite the v1 catalog.
5. The final pass rereads source-derived history and the complete history KV
   collection, so a mutation after initial backfill blocks cutover. It then
   records an independent observation timestamp before inventorying
   scheduler-owned V2 jobs. After manual gap writes are complete, it records a
   later independent audit boundary and repeats the complete scheduler
   inventory through that boundary. Each accepted job must have scheduler provenance,
   the expected saved-search ACL and label, a matching successful scheduler
   log row, complete results, and exact resolved search-window bounds. The
   helper derives raw index bounds only from the verified `-10m@m` / `-5m@m`
   request and its matching `-24h` / `+15m` resolved search bounds; it never
   treats `indexEarliestTime` as a request bound. Manual dispatches and
   ambiguous or in-flight jobs do not qualify.
   The separately scheduled history builder is inventoried through its own
   observation boundary. Its exact `-10m@m` / `@m` index window and resolved
   `0` / `+15m` event bounds are recorded per scheduler SID; source-derived
   history keys and merged receipt extrema are re-read across the immutable
   baseline, manual slices, and every completed history cycle. A history-only
   gap before its first scheduled window is durably backfilled and included in
   final collection equality. The one exact `No results to summary index.`
   warning is accepted only for an allowlisted summary writer with zero
   results; its independent bounded source and retained-index audit must both
   prove the window empty. Other warnings remain fatal.
6. The bridge journals every closed gap slice by stable index bounds and
   resumes its existing progress after interruption. It validates both V2 writers
   for each observed contiguous scheduler cycle, and uses each job's own
   resolved event-time bounds. The complete `adm_summary_v2` audit checks all
   expected and unexpected rows through the later audit boundary, after
   re-inventorying scheduler jobs at that same boundary. It does not derive
   the audit watermark from the maximum timestamp of expected rows. A later
   validation attempt records a new observation boundary.
7. Validate also runs an owner-only JSON scenario file containing the
   required deployment-specific
   values from the manifest's `scenario_schema`; the helper substitutes only
   literal-safe values into the exact allowlisted macro invocations. It runs
   each V2 public-surface query, requires complete job metadata and pages,
   checks required fields and supported predicates, and binds the results to
   the target, effective configuration, manifest, scenario, and journal. If
   any surface is incomplete, blocked, or uses a predicate the helper does not
   implement, it refuses to produce cutover-eligible evidence.

Run these operator tools from the reviewed repository checkout and use the
same journal and exact range for each step:

```sh
python3 tools/cisco_contract_migration.py --journal /secure/path/cisco-v2.json prepare --start <UTC_EPOCH> --end <UTC_EPOCH>
python3 tools/cisco_contract_migration.py --journal /secure/path/cisco-v2.json backfill
python3 tools/cisco_contract_migration.py --journal /secure/path/cisco-v2.json validate --scenario /secure/path/cisco-scenario.json
python3 tools/cisco_contract_migration.py --journal /secure/path/cisco-v2.json cutover
python3 tools/cisco_contract_migration.py --journal /secure/path/cisco-v2.json rollback
```

The scenario file must be readable only by its owner, contain exactly the
manifest's required string fields, and contain no credentials. Do not copy the
example checkout, cluster, or IP values from research into a deployment
scenario. The helper refuses unknown surface names, missing selector targets,
changed writer definitions, a blocked topology entry, and unsupported result
predicates. No operator-supplied “validated” flag or arbitrary SPL is accepted.

The helper requires a standalone target at `https://localhost:8089` by
default. Add `--ca-file` only for the local management certificate's trusted
CA. Do not put credentials in command arguments or shell history.

## Interrupted and failed operations

Every search dispatch is journaled before the REST POST. A timeout or missing
SID is an unknown outcome, not permission to retry. Configuration preparation
is journaled separately from dispatch intent. An interrupted preparation may
start a new attempt only after verified restoration and origin checks; a
known rejected request without a SID may likewise start a linked new attempt.
The old record is retained, and the latest matching attempt controls resumption. Find the original SID in
Splunk Job Manager/audit evidence, then reconcile it explicitly:

```sh
python3 tools/cisco_contract_migration.py --journal /secure/path/cisco-v2.json reconcile --sid <DISCOVERED_SID>
```

The helper checks the SID's saved-search name or exact search fingerprint and
then applies the same completion and result checks. Never guess a SID. A
known REST permission rejection is recorded as rejected; resolve the access
issue and review the journal rather than assuming a write occurred.

If effective configuration or the authoritative manifest changes after
preparation, resume is refused. Start a separately reviewed migration after
resolving the state; do not edit journal fingerprints to bypass drift checks.
The journal binds the target Splunk GUID/version, effective macro and
transform inventories, writer definitions and schedules, observer/source
profiles, Cilium cluster settings, IP identity rows, interfaces, and the
authenticated principal. Before each staged writer dispatch, the helper
rechecks these inputs and refuses an unjournaled active v2 writer job.

The opt-in local qualification harness deliberately retains its journal and live
state after a failed or interrupted migration. It reports the journal location;
it does not automatically reverse an operation whose outcome may be unknown.
Reconcile the recorded SIDs and configuration through the helper before retrying,
running another lab scenario, or resetting the lab. A qualification range must
contain actual raw source receipts as well as retained V1 baseline evidence;
summary ingestion time alone is not a raw-source backfill window.

## Cutover and rollback

Cutover is available only from a candidate with actual read-only smoke results
for graph, catalog, topology, Find, health, and evidence/drilldown surfaces.
The manifest must enumerate the exact macro selectors, writer definitions,
REST targets, and prior/desired fields. The helper verifies those definitions
against live REST values and refuses unknown or incomplete targets. It then
journals the complete reversible plan before the first mutation, disables the
legacy conversation writer, waits for its active jobs to drain, stages any
newly closed five-minute slices through a recorded source watermark, reruns
coverage checks, and enables the staged V2 writers. It then waits for the first
scheduled conversation and traffic jobs with exact absolute raw-index bounds
and complete success metadata. It fills and validates the contiguous bridge
from the staged watermark through every completed cycle observed for both
writers. If scheduler evidence is incomplete, cutover returns
`awaiting_first_scheduled_cycle`; rerun cutover with the same journal after
evidence arrives. An in-flight job, missing cycle, incomplete index audit, or
unexplained row blocks the reader switch. The
helper then applies the allowlisted selectors and runs public wrapper queries
again to catch alias or recursion errors. Each update has a durable intent
record and exact REST readback. An interrupted update is reconciled from the
live value; an unknown request whose old value remains is not resent
automatically.

The REST updates are a sequence, not an atomic Splunk transaction. During an
interrupted cutover, the journal records `cutover_in_progress`; operators must
resume that exact journal or roll it back before starting another migration.
The helper refuses values outside both journaled states and refuses ACL drift.

Rollback accepts a complete or partial journaled cutover. For a V1 writer
that was originally enabled, cutover first requires a recent, scheduler-log
confirmed V1 slice with complete retained rows; otherwise it refuses before
pausing that writer. Rollback restores only the V1 writer first and leaves the
V2 public selectors in place. It waits for a real, successful resumed V1
scheduler cycle, checks raw-index retention for the entire gap, fills each
missed closed slice with the original V1 writer into `adm_summary`, and
compares stable rollup IDs and material row contents against retained V1 rows.
Unstable IDs, incomplete readback, unexplained rows, or insufficient retention
keep the rollback pending. Only after exact coverage through the observed
resumed boundary does it restore the remaining selectors and V2 writer states
and rerun V1 public wrapper queries. If the real resumed scheduler boundary
has not arrived yet, rollback returns `awaiting_v1_recovery`; rerun the same
command with the same journal. A V1 writer that was originally disabled
remains disabled and does not need this recovery path. Rollback keeps
`adm_summary_v2` and staged V2 collections for inspection and never changes
the legacy summary index macro. Restoring
effective REST values preserves the prior effective local overrides; it does
not recreate their exact app bundle/local-file placement. Exact file-layout
restoration requires a separate backup of the original app files.

The helper never grants or broadens ACLs. If an update changes an ACL, later
steps stop; restore the recorded permission state through the approved
Splunk administration process before resuming. The journal contains no
session key.

## Evidence limits

Successful local synthetic backfill and validation demonstrate only those
bounded queries and rows in that local target. The implementation's pure
regression tests do not qualify the live scheduled boundary or enabled-origin
rollback. They do not establish
customer-scale capacity, unrestricted scale, Stream Forwarder or exporter
qualification, SHC/Cloud readiness, or automatic recovery qualification for
new writers. Stream Forwarder compatibility and its release-specific source
formats require separate operator qualification. Preserve the journal and
candidate evidence for review, and keep V2 staged until every cutover gate is
implemented and independently validated on the intended target.

### Scheduler observation boundaries

A scheduler job still running at an observation boundary currently causes a safe refusal, rather than an automatic wait. Preserve the journal and resume after that exact job completes. The next attempt revalidates its identity, bounds, completion, messages and scheduler log; a failed, truncated or otherwise incomplete job remains a refusal. A resumed successful run does not establish unattended recovery across this boundary.
