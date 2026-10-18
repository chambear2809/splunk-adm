# Owned standalone V2 qualification procedure

This procedure qualifies a disposable, exclusively owned standalone lab. It is
not production activation, an SHC/Cloud procedure, or evidence that those
platforms support the helper. The helper continues to refuse unsupported
deployment shapes. Retain the exact candidate archive/checksum, matching
checkout, initialization manifest, journals, result artifacts, and raw logs.
Do not start another scenario or reset a target with an unresolved journal.

## Prepare the owned lifecycle

The coordinator holds `tools/lab_lock.py` across prepare, install, seed, all
qualification, inspection, restore, and final disposition. Install the exact
candidate package using the repository's package-staging workflow; do not
replace it with a fresh build midway through qualification. Start from coherent
V1 selectors with the V2 writers disabled, exact source profiles and Cilium
cluster settings configured, and a nonempty initialized synthetic workload.
Record all effective selector/writer states before starting. The optional
history builder remains a prerequisite for receipt-qualified Catalyst topology.

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

The initialization manifest's `index_window` records actual raw indexed
receipts. Derive a containing five-minute-aligned range, then ensure its end
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

With the paths and epochs above exported, run under the same existing lab
owner (nested lock ownership is supported):

```sh
ADM_LAB=1 ADM_CISCO_MIGRATION_RUN=1 \
ADM_CISCO_MIGRATION_INTERRUPT_ONCE=1 \
ADM_CISCO_MIGRATION_RESTORE_V2=1 \
ADM_CISCO_MIGRATION_TIMEOUT=3600 \
python3 tools/lab_lock.py --root . -- \
  python3 -m unittest discover -s tests/splunk -p test_cisco_upgrade.py
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
`candidate_cutover_eligible=true`. The restoration starts a fresh journal from
that restored V1 state, stages and validates again, and leaves the tested
candidate fully active under V2. The second journal must finish
`phase=cutover`, with eligible candidate evidence and a
`.restoration-evidence.json` artifact asserting verified selectors and repeated
cutover. Repeating the same harness command verifies existing terminal
journals/current V2 state rather than recycling a rolled-back journal.

For enabled-origin recovery qualification, first establish and record a real
recent successful V1 scheduler checkpoint. In addition set
`ADM_CISCO_MIGRATION_V1_GAP_INJECTION=1` and
`ADM_CISCO_MIGRATION_V1_GAP_FIXTURE` to an absolute, nonsymlink copy of one
TA-shaped standard Stream envelope outside the checkout. Record its origin and
checksum. The harness injects one uniquely tagged current raw record while V1
is paused, waits beyond the resumed scheduler's lookback, and requires exact
manual gap recovery. It preserves `.v1-gap-evidence.json`, verified manual SID,
raw index bounds, source-derived fingerprint, and retained material row.
This can add more than eleven minutes to the run. Do not inject a second copy
if a prior receipt outcome is unknown; reconcile the durable marker first.
Use distinct original/restore journals for disabled- and enabled-origin runs.
Do not restore V2 after the first origin run if another V1-origin run follows;
restore after the final qualifying rollback.

A timeout or failure retains live state and all journals. Inspect status without
a session or operation lock:

```sh
python3 tools/cisco_contract_migration.py --journal "$ADM_CISCO_MIGRATION_JOURNAL" status
```

Resume the exact same command, paths, package, and source after reconciling
reported SIDs/configuration. An ambiguous dispatch is not automatically retried;
use the existing `reconcile --sid` procedure. Do not delete the journal or
reset the lab to make a failure disappear.

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
searches: both recorded graphs, client Inspector provenance, this client's own
backend and receiving-node evidence, candidate path, physical attachment
inventory, reload, Find, preceding-window comparison, JSON and context CSV
exports, Setup and Data health. Missing required behavior fails the run.

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
