# Owned standalone V2 qualification procedure

This procedure qualifies a disposable, exclusively owned standalone lab. It is
not production activation, an SHC/Cloud procedure, or evidence that those
platforms support the helper. The helper continues to refuse unsupported
deployment shapes. Retain the exact candidate archive/checksum, matching
checkout, initialization manifest, journals, result artifacts, and raw logs.
Do not start another scenario or reset a target with an unresolved journal.

## Recorded candidate09 evidence

Evidence links below refer to the retained qualification checkout's ignored
`dist/` directory. Operators need that evidence bundle to inspect the fixture
preparation aids; these aids are not installed production commands.

Runtime checks passed. Independent review48 verified the retained runtime,
source binding and package-byte evidence with no findings. The combined [export manifest](../dist/final-qualification/native-09-migration-complete-02/export-manifest.json)
retains 474 hash-verified files and reports zero credential matches. Its archive
SHA-256 is `58a3167b53ccdd32ffec541f10ef4deb3d565dd8c9c13ba0d1eb5a4bbfd6ccb2`.
This is owned standalone synthetic evidence, with no Cloud/SHC cutover or
collector qualification claim.

| Evidence                                          | Recorded result                                                                                                                       |
| ------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------- |
| Installed candidate09 archive                     | SHA-256 `024d11c83ae9cb21a19259b57038d0e4a68414d1b2d3dde82cad527d789a0097`; package source `6ebbf0dae3bd9ff0a2d982fe9f3b561687764eca` |
| Complete suite and migration source               | `c314cc89f7ea6e14f317371fd5c2d19e5b74cc6b`                                                                                            |
| Final browser05 and byte-check source             | `d7d0c61f818018ef9cbf8ee6ad17ca9fd246aa69`; all 85 installed package files remained byte-exact                                        |
| Disabled-origin rehearsal                         | 2026-10-18 23:10:00–23:16:20 UTC; 2 tests passed in 380.464s; terminal repeat passed in 0.275s                                        |
| Enabled-origin rehearsal and fresh V2 restoration | 23:20:58–23:52:40 UTC; 2 tests passed in 1901.969s; terminal repeat passed in 0.980s                                                  |
| Active V2 browser05                               | 2026-10-19 00:26:59–00:28:16 UTC; both recorded scenarios passed; unchanged configuration, zero writes and zero demo requests         |

The separate [complete-suite export](../dist/final-qualification/native-09-complete-suite/export-manifest.json)
records 393 tests: 390 passed and 3 skipped in 2173.773s. All three pruning cases
passed. The skips were the explicit migration opt-in and two distributed SHC
interface cases; the suite itself does not qualify those skipped paths. The
migration rehearsals above exercised the exact upgrade test and its gap-envelope
companion separately. The manifest binds each historical wrapper/source and the
later browser-only qualifier changes to the unchanged package; it does not claim
that all runs used one source revision.

Both original migration journals finished `rolled_back` after completed
activation; the fresh restoration journal finished `cutover`. Each activation
recorded 13 applied mutations, including all eight public selectors. The enabled
run injected a single raw receipt at 23:22:08 UTC into receipt slice
`[1792365600,1792365900)`. Rollback completed at 23:40:34 UTC after exact manual
V1 recovery with one retained copy of rollup
`76658a5577bcccbdaf8d3eb7d8be60d57ce5053d00e8be09cc1e1d9da234c61a`.
The recovery SID was
`admin__nobody_c3BsdW5rX2FkbQ__RMD58b8ebc5b13d11344_at_1792366815_37`.

Restoration automatically waited for the actual 23:45 V1 checkpoint,
`scheduler__nobody_c3BsdW5rX2FkbQ__RMD58b8ebc5b13d11344_at_1792367100_42`,
whose anchor followed the completed recovery boundary. It then validated the
23:50 conversation/traffic cycles and the 23:51 history cycle. Those scheduled
slices legitimately had zero expected rows; bounded empty-summary and final
history readback proofs were retained. Their success is not evidence of newly
arriving traffic. The [concurrent-operation proof](../dist/final-qualification/native-09-migration-complete-02/runs/native-09-concurrent-migration.json)
records exit 2, no competing journal, unchanged configuration and a readable
original journal for the same-controller/OS-user guard.

The [final browser evidence](../dist/final-qualification/native-09-migration-complete-02/browser/evidence.json)
records Catalyst/ACI (`cilium-aci-east`, 25 nodes/36 edges) and Meraki/NX-OS
(`cilium-nxos-west`, 21 nodes/23 edges). Both passed graph, Inspector, exact
scoped-IP backend/receiver path, attachment inventory, reload, Find,
preceding-window comparison, JSON, context CSV and required-flow CSV checks.
Setup observed all eight V2 selectors. Health followed the configured source,
profile, quality, summary and scheduler dependencies. It truthfully showed aged
source warnings and four disabled prerequisite builders (Identity, Service
binding, Service backends and ACI policy), alongside recent successful V2
history, conversation, traffic and catalog jobs. This is not an all-green
health or prerequisite-automation claim.

All four earlier native09 browser attempts remain failed evidence: raw versus
canonical JSON representation, an Inspector pointer interception, CSV quote
encoding, and canonical versus displayed scheduler names respectively. They
were fixed in the qualifier without changing the installed product or resetting
the active V2 data. These are distinct from the historical candidate08 missing
first-history-cycle and HTTP 401 recovery attempts described below.

The [native cleanup record](../dist/final-qualification/native-09-cleanup.json)
confirms removal of the recorded container
`25ac217aa8e568c019a6e1682f59afa9a3da50f31fd2386411417189611a3f1d`,
its volumes and lab credentials at 2026-10-19 00:41:17.436082 UTC. The lifecycle
owner exited and released its locks. No unrelated containers were included.
Cloud cutover remains deferred; separate SHC qualification does not extend this
standalone migration result.

## Prepare the owned lifecycle

The coordinator holds `tools/lab_lock.py` across prepare, install, seed, all
qualification, inspection, restore, and final disposition. Install the exact
candidate package using the repository's package-staging workflow; do not
replace it with a fresh build midway through qualification. Start from coherent
V1 selectors with the V2 writers disabled, exact source profiles and Cilium
cluster settings configured, and a nonempty initialized synthetic workload.
Record all effective selector/writer states before starting. The optional
history builder remains a prerequisite for receipt-qualified Catalyst topology.

The networking loader initializes V2 fixture state; it does not create the real
V1 summary baseline required for this rehearsal. Before migration, derive the
nine-field scenario from the initialized raw workload and generate/read back
that baseline using the installed V1 normalization and writer definitions. The
reviewed fixture-only `prepare-migration-09.py` aid is retained under `helpers/`
in the combined export, together with its tests and exact bytes. Under the held
lab lock, its tested preparation commands were:

```sh
python3 tools/load_networking_lab.py --reset --regenerate \
  --raw-dir dist/networking-path-tests \
  --output dist/networking-path-tests/initialization.json
python3 dist/final-qualification/prepare-migration-09.py --fixture-target \
  --runtime-root "$ADM_MIGRATION_RUNTIME_ROOT" \
  --ca-file "$ADM_CISCO_MIGRATION_CA_FILE"
```

Create a new mode-0700 external runtime root before invoking the reviewed aid;
this is not a production setup tool. The aid refuses a preexisting partial baseline.
Only after one verified completed collect may readback poll exact subsets until
full equality within one shared 90-second deadline; unknown rows, conflicting
material, excess copies and timeout refuse without recollecting. In native09,
one 90-row collect was followed by eight 85-row exact subsets and then full
90-row equality. The aid also records the fixture scope, truthful saved
expectations, protected session/scenario paths and unchanged selectors/writers.
Read its emitted environment paths and readiness evidence; never evaluate
artifact text as shell code. Native09 preparation initially reported
`closed_and_lagged=false`; migration waited until 23:10 UTC rather than forcing
a future receipt range. Do not reinitialize after migration begins.

Supply these external owner-only files through the existing lab authentication
workflow; credentials never belong in command arguments, repository files, or
logs:

- `ADM_CISCO_MIGRATION_SESSION_FILE`: one administrator session key, mode 0600.
- `ADM_CISCO_MIGRATION_CA_FILE`: trusted local management CA/certificate.
- `ADM_CISCO_MIGRATION_SCENARIO`: mode-0600 JSON with the manifest's exact
  required string fields (`client_ip`, `server_ip`, `server_port`, `transport`,
  `service`, `environment`, `cluster`, `namespace`, `query`). Use values from
  the actual initialized scenario, not an unrelated example.
- `ADM_CISCO_MIGRATION_JOURNAL`: a new absolute path in a private durable
  directory outside the checkout.
- `ADM_CISCO_MIGRATION_RESTORE_JOURNAL`: another absolute journal path in that
  directory. Never reuse the first journal or edit a terminal journal.

The initialization manifest's `index_window` bounds the loading interval; it
is not a measured minimum/maximum of every event's `_indextime`. Derive a
containing five-minute-aligned range, then ensure its end
leaves two closed five-minute slices before the current scheduler watermark:

```sh
python3 - <<'PY'
import json, math, time
from pathlib import Path
m = json.loads(Path('dist/networking-path-tests/initialization.json').read_text())
a, b = m['index_window']
start, end = int(a)//300*300, math.ceil(int(b)/300)*300
print('ADM_CISCO_MIGRATION_START=' + str(start))
print('ADM_CISCO_MIGRATION_END=' + str(end))
print('closed_and_lagged=' + str(end <= int(time.time())//300*300-600))
PY
```

Export the two printed epoch values only after checking the range contains the
owned raw input and retained V1 baseline. If `closed_and_lagged=False`, continue
independent work until the range closes; do not force a future bound. The
helper refuses ranges longer than seven days. It keeps an absolute journaled
event upper bound equivalent to the shipped `+15m` writer bound, including
history staging and scheduler validation. Far-future raw `_time` remains
outside builder coverage; the independent raw health probe can expose it.

## Cut over, interrupt, resume, roll back, restore V2

Use distinct journals for the two origins. Run the disabled-origin rehearsal
first with `ADM_CISCO_MIGRATION_RESTORE_V2=0` and
`ADM_CISCO_MIGRATION_V1_GAP_INJECTION=0`, then repeat it before changing the
origin. For the final enabled-origin rehearsal, establish the real V1 checkpoint
and protected gap fixture below. With its emitted paths and epochs exported,
run under the same existing lab owner (nested lock ownership is supported):

```sh
ADM_LAB=1 ADM_CISCO_MIGRATION_RUN=1 \
ADM_CISCO_MIGRATION_INTERRUPT_ONCE=1 \
ADM_CISCO_MIGRATION_RESTORE_V2=1 \
ADM_CISCO_MIGRATION_V1_GAP_INJECTION=1 \
ADM_CISCO_MIGRATION_TIMEOUT=3600 \
python3 tools/lab_lock.py --root . -- \
  python3 -m unittest discover -s tests/splunk -p test_cisco_upgrade.py -v
```

The harness performs bounded preparation/backfill, complete source/readback
validation, all manifest public-surface probes, scheduled-cycle qualification,
coherent selector activation, and repeated-cutover revalidation. The
interruption opt-in stops control flow once immediately after a real mutation
has been verified and journaled; it then recreates the controller from that
durable state and resumes. The journal records `qualification_interrupt` so a
retry cannot inject a second stop. This is a controlled controller interruption,
not a claim that an OS kill during an arbitrary network request was exercised;
unknown-response and dispatch-reconciliation paths have separate deterministic
regressions.

It then verifies rollback to the recorded V1 origin. The first journal must
finish `phase=rolled_back`, `rollback.state=complete`, and
`candidate_cutover_eligible=true`, plus `cutover.state=complete`, valid completion
time, applied verified mutations, scheduler bounds and public-selector evidence.
Eligibility alone is insufficient. When restoration is enabled, it starts a
fresh journal from that restored V1 state, stages and validates again, and leaves the tested
candidate fully active under V2. The second journal must finish
`phase=cutover`, with eligible candidate evidence and a
`.restoration-evidence.json` artifact asserting verified selectors and repeated
cutover. Repeating the same harness command verifies existing terminal
journals/current V2 state rather than recycling a rolled-back journal.

For enabled-origin recovery qualification, first establish and record a real
recent successful V1 scheduler checkpoint. Native09 used the reviewed
`refresh-migration-session-09.py` aid after disabled-origin rollback to obtain a
fresh external `session*` file, verifying the same target, eight V1 selectors and
original writer states without changing session policy. The reviewed
`prepare-enabled-origin.py` aid then enabled only the V1 rollup, verified its
configuration, and waited for an actual scheduler-owned completed checkpoint.
It retained before/after state, scheduler SID, an external gap-fixture copy and
new unused enabled/restore journal paths. Both aids and their execution records
are retained with the export. Do not rerun a failed preparation marker blindly.
For enabled-origin qualification set
`ADM_CISCO_MIGRATION_V1_GAP_INJECTION=1` and
`ADM_CISCO_MIGRATION_V1_GAP_FIXTURE` to an absolute, nonsymlink copy of the
initialized `campus_netflow.ndjson` outside the checkout. Preserve all lines and
record its origin and checksum; the harness selects one eligible TA-shaped
standard Stream record. The harness injects one uniquely tagged current raw record while V1
is paused, waits beyond the resumed scheduler's lookback, and requires exact
manual gap recovery. It preserves `.v1-gap-evidence.json`, verified manual SID,
raw index bounds, source-derived fingerprint, and retained material row.
This can add more than eleven minutes to the run. Do not inject a second copy
if a prior receipt outcome is unknown; reconcile the durable marker first.
Use distinct original/restore journals for disabled- and enabled-origin runs.
Do not restore V2 after the first origin run if another V1-origin run follows;
restore after the final qualifying rollback.

After enabled-origin rollback, restoration waits for an actual completed V1
scheduler checkpoint whose anchor is later than the durable recovery audit and
rollback completion. A manual gap recovery can add retained rows after the
previous empty scheduled cycle; immediately reusing that cycle correctly fails
the unexplained-row audit. The harness records the completed rollback identity,
boundary and new scheduler SID as `qualification_restoration_checkpoint`, then
uses the unchanged source, retained-row, empty-window and 600-second freshness
checks. Before activation, a resumed journal recaptures this checkpoint; once
activation starts, its rollback anchor remains immutable. Missing, failed or
active scheduler evidence still refuses, and the bounded wait does not authorize
unexplained summary rows or replace scheduled proof with a manual dispatch.

A timeout or failure retains live state and all journals. Inspect status without
a session or operation lock:

```sh
python3 tools/cisco_contract_migration.py --journal "$ADM_CISCO_MIGRATION_JOURNAL" status
```

Resume the exact same command, paths, package, and source after reconciling
reported SIDs/configuration. An ambiguous dispatch is not automatically retried;
use the existing `reconcile --sid` procedure. Do not delete the journal or
reset the lab to make a failure disappear.

Use a fresh administrator session from the approved login workflow before a
long rehearsal. A prior candidate08 run encountered HTTP 401 after roughly an
hour; this observation is not a guarantee about another platform's session
lifetime.
If a request returns HTTP 401, preserve the failed run and journal, obtain a
new session into a mode-0600 external file, and verify the authenticated target
and live selector/writer state. Then resume with the same journal and source,
changing only the session-file path. Inspect and reuse recorded job SIDs;
do not reissue an uncertain dispatch or reset the origin. The prior candidate08
enabled-origin rehearsal exercised this recovery while rollback was in progress,
with the V2 public contract still coherent. Final native09 refreshed its session
before enabled-origin preparation and completed without that HTTP 401 recovery.
Session policy was not extended or disabled.

The prior candidate08 attempt also retained a missed first-history-cycle failure
and completed rollback before a fresh successful attempt. Logs showed the
missing expected slot and a scheduler “Could not get next runtime” message;
they did not establish a guaranteed timing-based root cause. A missing first
scheduled cycle is a different condition from a cycle that has not yet completed. Inspect the recorded enablement time, expected scheduler
anchor, actual job metadata and `scheduler.log`. A later successful cycle does
not prove that the required first cycle ran. If the expected dispatch was
missed, retain that failed attempt and use the supported rollback operation:

```sh
python3 tools/cisco_contract_migration.py \
  --journal "$ADM_CISCO_MIGRATION_JOURNAL" \
  --ca-file "$ADM_CISCO_MIGRATION_CA_FILE" rollback \
  < "$ADM_CISCO_MIGRATION_SESSION_FILE"
```

Complete any requested recovery, verify `rolled_back` and the exact original
selectors/writer states, then use a new journal for a fresh attempt. Leave time
for scheduling to initialize before the next expected slot; no fixed lead time
is a platform guarantee. Do not edit the expected anchor, substitute manual
dispatch for scheduled evidence, or treat a failed attempt's rollback as a
successful cutover. `candidate_cutover_eligible=true` records staging
eligibility and can also be present in a failed attempt. Terminal success must
additionally prove completed cutover and the verified mutations, scheduled
cycles and public-selector checks. A failed attempt cannot be reused by that
terminal-success branch of the qualification harness.

## Pruning disposable history

Run this only after migration/rollback/restoration has reached a known state:

```sh
ADM_LAB=1 ADM_CISCO_PRUNE_RUN=1 \
python3 tools/lab_lock.py --root . -- \
  python3 -m unittest discover -s tests/splunk -p test_cisco_pruning.py
```

The three live cases pause every ADM schedule, verify pause, and drain app/ADM
jobs before backup. `FINALIZING` is active even if an early `isDone` is present.
Two equal REST reads prove the bounded backup is stable: pages of 500, no more
than 100,000 rows/16 MiB, valid unique keys, stable `_key` sort and an overlapping final-page completion
probe (a short capped response alone is insufficient). Unsafe reads
refuse before replacing the collection. Original documents, fixture before/after
states, restored documents, and SHA-256 summaries are retained privately under
`dist/final-qualification/pruning/<unique-run>/`.

Only disposable fixture rows are then installed. A fixture-only retention
scalar fixes an exact cutoff while exercising the actual shipped prune SPL;
production defaults and schedules are not globally enabled. Assertions cover:
closed gate means no deletion; enabled pruning removes only expired rows;
exact-boundary/current/latest-received replay rows survive; absent/invalid
receipt evidence survives; repeat execution is idempotent; incomplete reads
and all-expired empty-write protection refuse deletion; a search-only user
cannot delete the collection, dispatch the prune, open the gate, or run its
write through SPL. KV number fields can reject malformed strings before
persistence, so malformed persisted evidence uses an invalid negative epoch
and missing typed receipt fields.

Cleanup closes the gate first. A failed setup before a verified backup never
rewrites history. A failed restore leaves schedules paused and evidence intact;
do not resume them until exact documents/macros are recovered. On success the
harness verifies original documents and macro definitions before restoring
and verifying prior schedule states. Summary indexes and V1/V2 data are not
pruned by these tests. Record each test's actual outcome before claiming
qualification.

The paged REST primitives (`sort`, `skip`, `limit` and `batch_save`) follow
[Splunk’s 10.6 KV Store endpoint reference](https://help.splunk.com/en/splunk-enterprise/leverage-rest-apis/rest-api-reference/10.6/kv-store-endpoints/kv-store-endpoint-descriptions).
The overlapping probe is an additional client completeness check, not a server
transaction. The migration helper applies the same sorted completeness proof
when reading staged collections.

## Concurrent-operation boundary

Mutating CLI commands and this harness acquire a nonblocking local target lock
before the journal lock. Its identity is the authenticated target server GUID
plus app, so local URI aliases and different journal paths for the same target
share a guard. The default lock directory is
`~/.splunk-adm/cisco-target-locks`, owner-only; unsafe directories/files,
symlinks, missing GUIDs, or another active local operation refuse. Status reads
an atomically replaced owner-only journal without blocking a writer.

While the live harness is awaiting scheduled evidence, a second process using
the same OS user can verify refusal against the real target, with a new unused
journal path (the session remains stdin-only):

```sh
python3 tools/cisco_contract_migration.py \
  --journal /secure/path/competing-qualification.json \
  --ca-file "$ADM_CISCO_MIGRATION_CA_FILE" \
  prepare --start "$ADM_CISCO_MIGRATION_START" --end "$ADM_CISCO_MIGRATION_END" \
  < "$ADM_CISCO_MIGRATION_SESSION_FILE"
```

Require exit 2 for the held operation lock, no competing journal/candidate,
and no configuration write. Record its output and the still-running original
journal. `status` on the original journal must remain readable during the
contention. This live contention check complements the deterministic subprocess
unit check; it must be recorded separately from a fake-API test result.

This guard coordinates the same OS user on one controller using that shared
lock directory. It cannot fence another machine, OS user, arbitrary REST
client, or remote scheduler. The operator's exclusive-controller lifecycle is
still mandatory. It adds no distributed migration or SHC/Cloud support.

## Native browser qualification after restoration leaves V2 active

Do not reinitialize after cutover. `qualify_cisco_v2_browser.py` reads the existing
`dist/networking-path-tests/initialization.json` and the installed configuration.
It reuses `CiscoV2BrowserTest._read_scenarios` without invoking that test's
reset/selector-override setup. It separately checks all eight installed public
selectors, disabled V1 rollup, enabled/scheduled V2 writers, complete raw-fixture
selected-client/backend handoffs, configured deployment expectations and index
metadata. It then exercises the native packaged application through public
searches: both recorded graphs, MAC Inspector provenance, the exact scoped IP
conversation's backend and receiving-node evidence, candidate path, physical attachment
inventory, reload, Find, preceding-window comparison, JSON, context CSV and required-flow CSV
exports, Setup and Data health. Missing required behavior fails the run.

The MAC network-client node's traffic observations and the scoped IP
conversation are distinct evidence paths. Matching observed source/destination
addresses, ports, transport, scope, cluster and overlapping times can verify
their tuple evidence; this does not establish continuous MAC/IP identity.
The qualifier preserves the IP node's unresolved identity reason, checks the
original Hubble tuple and the conversation's own backend/receiver attribution,
and checks both paths in comparisons and exports. Aggregate service backends
cannot replace those records. A missing direct conversation edge from the MAC
node is not itself missing Hubble handoff evidence.

The qualifier compares raw query records to canonical graph evidence using an
independent explicit field/type contract: only documented numeric identifiers
become text, literal `"0"`/`"1"` metric flags become booleans, and known optional
null/`"Null"`/empty members may be omitted. Every retained field, value and record
order must match; malformed values, unknown fields and lost nonempty evidence
fail. CSV checks parse quoted cells, require complete record equality, bind both
flattened authority columns to that same record and require the opposite-kind
authority column to be blank. Raw CSV substring spelling is not an authority
check. Map cards use their exact accessible names and supported focus/Enter
selection, verifying focus, selected state and prior-card deselection. No forced
pointer clicks or injected selection state are used.

Before running, an administrator must already have saved expectations matching
the initialized workload in Setup. Select at least NetFlow, DC Networking,
Kubernetes, Traces, Hubble, Catalyst Center, Meraki and Catalyst SD-WAN as active.
Keep other choices truthful. The qualifier never changes expectations, selectors,
schedules or data. Health follows the saved active sources through their actual
index macro metadata, raw/profile/derived-summary/quality probes and applicable
V2 jobs. Setup must observe the active V2 selectors and scheduled writers and
load `adm_health_jobs`. Legitimate negative fixtures and disabled prerequisites
can show attention; this qualification does not require every source to be green.
Incomplete probe retrieval is a failure.

Health displays scheduler names without the `ADM - ` prefix and includes the
full registry, including inactive diagnostics. The qualifier retains canonical
required V2 job names from preflight and matches each exact scheduler-table row
once, preserving its status, last run/success and failure/skip cells. A required
row classified `Not required for this deployment` fails; unknown, aged, disabled
or warning evidence remains visible. Extra inactive V1 diagnostic rows cannot
substitute for required V2 rows and need not be hidden.

Under the same lab owner, use a **new evidence directory for every attempt**:

```sh
ADM_LAB=1 python3 tools/lab_lock.py --root . -- \
  python3 tests/splunk/qualify_cisco_v2_browser.py \
    --initialization dist/networking-path-tests/initialization.json \
    --output dist/final-qualification/post-cutover-01/evidence.json
```

Keep `ADM_CISCO_MIGRATION_CA_FILE` exported. Management requests use that CA
with hostname verification at `https://localhost:8089`. The existing
`ADM_LAB_SECRETS` file (or the normal lab secret file) must be an owner-only
regular file. Its password travels to the native driver only through stdin;
credentials never appear in arguments, browser evidence, screenshots, HARs or
traces. Browser stdout contains sanitized checks and errors; authentication
screens are not captured. The qualifier preserves JSON/CSV downloads and their
hashes, native Health rows, public-selector hashes and unchanged configuration
readback. A failed browser check remains a failed result even if the readback
succeeds. Outputs are synthetic standalone lab evidence, not collector or
production qualification.

For migration's nine-field scenario, derive values from the initialized raw
workload rather than copying a demo scope. With an unused owner-only destination
in `ADM_CISCO_MIGRATION_SCENARIO`, run this before the migration harness:

```sh
python3 - <<'PY'
import json, os
from pathlib import Path
root = Path.cwd()
m = json.loads((root/'dist/networking-path-tests/initialization.json').read_text())
raw = root/m['raw_dir']
config = json.loads((raw/'scenario.json').read_text())
c = next(x for x in config['connections'] if x['cluster_id']=='aci')
cluster = next(x for x in config['clusters'] if x['id']==c['cluster_id'])
traces = [json.loads(x) for x in (raw/'otel_traces.ndjson').read_text().splitlines()]
t = next(x for x in traces if x['fields']['k8s.cluster.name']==cluster['name']
         and x['event'].get('attributes',{}).get('client.address')==c['source_ip'])
f = t['fields']
s = dict(client_ip=c['source_ip'], server_ip=c['destination_ip'],
         server_port=str(c['destination_port']), transport='tcp',
         service=f['service.name'], environment=f['deployment.environment.name'],
         cluster=f['k8s.cluster.name'], namespace=f['k8s.namespace.name'],
         query=c['source_ip'])
with os.fdopen(os.open(os.environ['ADM_CISCO_MIGRATION_SCENARIO'],
                      os.O_WRONLY|os.O_CREAT|os.O_EXCL, 0o600),'w') as out:
    json.dump(s,out,indent=2)
print(json.dumps(s,indent=2))
PY
```

The current initialized ACI fixture yields `10.61.0.20` to
`10.50.0.20:8080/tcp`, `checkout/demo/cilium-aci-east/shop`, and query
`10.61.0.20`; the raw trace check binds those values to the actual generated
workload.

Do not run the full `test_cisco_browser.py`, `test_cisco_paths.py` or
`test_cisco_history_edges.py` after cutover: their setup resets/regenerates the
lab. `test_views_viewer.py` seeds a V1 catalog and clears expectations, and its
native driver hardcodes a V1 scope. `test_setup_browser.py` clears expectations
and enables a legacy catalog schedule. The browser-only `health-review.spec.ts`
uses mocked data and cannot replace this native dependency-chain qualification.
