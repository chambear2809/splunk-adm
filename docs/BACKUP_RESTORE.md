# Backup and restore rehearsal

The current native same-build follow-up is the
[isolated case/ledger library exercise](CASE_NATIVE_RECOVERY.md). It adds
synthetic source-backed captures, current source redaction and partial-copy
failure checks using the installed 0.9.11 libraries. Its passed result and
independent unchanged-live-data checks do not extend the older cold endpoint
restore result to source-backed endpoints or production recovery.

`tools/rehearse_restore.py` retains the earlier KV/configuration restore
rehearsal. Its earlier results do not qualify the new case, baseline or
capture-job SQLite databases. The synthetic local check for those databases is
`python3 -m unittest tests.test_sqlite_restore_rehearsal`, described below.

The KV/lab lifecycle has not been requalified after the task-owned verified-TLS
lab changes. Do not use a default or user-owned lab for this task. Any future
installed rehearsal must follow [task-owned lab setup](TASK_LABS.md), bind its
exact container identity, and independently verify cleanup. The tool's
`--reset-lab` flag authorizes destructive recreation of its selected disposable
lab; it is not a production backup command. No current installed run of that
workflow is claimed here.

## What it verifies

1. Build deterministic workload data containing current and historical identities. Populate all eight configured ADM collections (including observer scope and app catalog); otherwise unused collections receive isolated synthetic history records.
2. Pause all pipeline saved searches and the one-time migration search and refuse a snapshot while app jobs are active. Read each collection in ordered key pages until an empty page, including when the server returns a short page. Repeat reads and reject any change.
3. Save the eight collections, including live observer scope, including `_key` and validity history, plus an explicit allowlist of local configuration, metadata, and the legacy scope CSV (migration/rollback evidence only). Missing files remain explicitly absent. Splunk's generated `_user` storage field is omitted; restoration uses the same shared `nobody/splunk_adm` namespace.
4. Validate a schema and SHA-256 digest before restoring. Require matching installed app-default fingerprints and empty target collections. No archive extraction or arbitrary backup paths are used for server writes.
5. Recreate the container and app, restore the backup, and compare all restored collection values and file bytes with the snapshot.
6. Reingest the identical retained synthetic fixtures into the clean raw indexes and rebuild the summary. Builders are **not** rerun to recreate the restored collections. Compare the complete map before/after, excluding only its generation timestamp, and confirm the collections remain unchanged.

The snapshot is stored under ignored `dist/restore/<run-id>/backup.json`, created with private directory/file permissions. The bounded reader rejects more than 100,000 rows per collection or a backup exceeding 64 MiB. The report at `dist/restore/latest.json` records collection counts, fingerprints, graph comparisons, and search outcomes without the backup contents or credentials.

## Limits

This exercises a clean restore on the same app defaults and Splunk image. It does not back up Splunk passwords, HEC tokens, platform configuration, TA installations, raw buckets, or summary indexes. The fixture files retained on the host stand in for an independently retained raw-data source; production raw-index backup and recovery need their own platform procedure. A failed restore can be partial: keep writers paused and recreate the disposable target before retrying. The SHA-256 value detects accidental corruption, not authenticity of an externally supplied backup.

For production recovery planning, retain the [recovery procedure](RECOVERY.md), a trusted complete platform backup, the exact app package/configuration, and verified raw-data retention. The rehearsal uses Splunk's documented [KV collection and batch-save endpoints](https://help.splunk.com/en/splunk-enterprise/rest-api-reference/10.6/kv-store-endpoints/kv-store-endpoint-descriptions).

The KV-scope version writes backup schema 2. CSV-era schema-1 backups are rejected before restore writes with an explicit message to use the matching CSV-era restore tool and then migrate; restore them with their matching older app/tooling, export a trusted scope CSV, then follow the [one-time migration](UPGRADES.md#one-time-csv-to-kv-scope-migration). Do not relabel an old backup as schema 2 or omit live scope KV rows. Retaining the legacy CSV in the file allowlist does not make it an active lookup.

## Synthetic SQLite copy rehearsal

`python3 -m unittest tests.test_sqlite_restore_rehearsal` exercises a separate,
synthetic, offline same-build SQLite copy. With fixture writers quiesced, it uses
SQLite's backup API to create new private files in a private temporary directory;
existing destinations are rejected. It checks integrity, foreign keys and schema
identity before reopening the copies. The checks cover case notes and revisions,
ACLs, capture links, retry receipts and audit records; baseline versions, watch
observations and deduplication; and the separate capture-job ledger, including
unknown creation and cleanup records. Current source denial still redacts case
evidence and blocks protected baseline reads. Unresolved job slots remain charged
when reopened, including after the fixture clock advances. A copied ledger with
an unsupported future schema is rejected; a legacy ledger migration runs only on
a copy and retains an unknown, unbound job.

This is a local test, not an operational backup or restore procedure. Each
database is copied separately, so the test does not establish a single atomic
snapshot across databases. It does not qualify live writers, Splunk deployment,
upgrade or downgrade compatibility, production recovery, or native job
reconciliation. In particular, it does not clear unknown jobs or infer that a
job is absent from elapsed time. Preserve the case database and capture-job
ledger together in any future qualified recovery procedure; do not overwrite
existing state or clear unresolved slots to restore capacity.

## Installed cold case recovery rehearsal

The 2026-11-17 local Docker rehearsal passed against the frozen 0.9.8 archive.
It qualifies only the same-build synthetic notes and populated-ledger scenario
below. Exact archive/snapshot hashes, failed attempts, cleanup and remaining
limits are retained in the [qualification record](FEATURE_QUALIFICATION.json).

`tools/rehearse_case_recovery.py` is a test-only, same-build rehearsal using
three exact disposable task namespaces: source, occupied negative target and
fresh positive target. It runs one Splunk container at a time. It does not
provide a production backup command or qualify the older KV workflow above.

The source fixture creates private, shared and revoked synthetic notes cases,
then checks the same records, immutable revisions, exports and original retry
responses after a container restart. Fixture accounts and roles are removed and
the disabled configuration is restored before the cold copy. Three deliberately
unresolved synthetic capture-ledger slots are seeded without dispatching searches.
These represent `creating`, `creation_unknown` and `cleanup_unknown` states.

Both databases are read from the **same stopped container**, after verifying its
exact recorded ID, pinned image, labels, complete mount set, local socket,
loopback ports and stopped process state. Other containers mounting either
volume prevent copying. The fixed directory is
`$SPLUNK_DB/splunk_adm_investigations`; arbitrary source or restore paths are not
accepted. The Docker archive reader manually accepts only this directory and
its known database/WAL/SHM files, with service ownership and modes 0700/0600.
It rejects links, unexpected entries and excessive physical size before opening
SQLite. No general archive extraction is used.

The host uses SQLite's backup API to include any retained WAL rows and writes
new sealed databases in DELETE journal mode. Schema identities come from fresh
stores created independently by the installed runtime. Integrity, foreign keys,
logical table digests, database bytes, exact source provenance and an externally
retained manifest digest must agree. SHA-256 detects changed bytes; it does not
authenticate an untrusted backup and manifest supplied together. Both databases
are retained together; explicit ledger absence is supported by the helper but
the installed scenario exercises a populated ledger.

An occupied target must reject restoration without changing its sentinel.
Corrupt and unsupported-future backups must fail before creating any restore
destination. Only a fresh stopped target with no case directory may receive the
validated sealed files. Target file bytes are compared before startup, then the
installed runtime checks schema, service permissions, every logical table and
the unresolved slots before opening case endpoints. Advancing the fixture clock
must leave all three slots charged. Recreated fixture identities then exercise
the saved ACLs, notes, exports and old retries through authenticated Splunk Web
proxy sessions, followed by a new shared question entry.

The constructed tar carries numeric service IDs and fixed permissions. Restore
uses tar stdin without `docker cp -a`: the CLI maps that option to `CopyUIDGID`,
and the daemon applies the image's configured user, overriding tar ownership.
See the primary [CLI copy implementation](https://github.com/docker/cli/blob/master/cli/command/container/cp.go)
and [daemon ownership handling](https://github.com/moby/moby/blob/master/daemon/archive_unix.go).
The cold readback must still prove service ownership, permissions and exact bytes;
a successful copy command alone is insufficient evidence.

All three cross-worktree locks remain held by the parent through child retirement,
evidence retention and cleanup. Cancellation retires each child process group;
receipt or log write failures cannot prevent attempts to clean every owned lab.
Interrupted mutations and cleanup uncertainty remain failures. A forced parent
kill, host crash or unavailable Docker engine can still require explicit recovery
using retained ownership evidence. Never prune or adopt an existing namespace.

Run only after reviewing [task lab requirements](TASK_LABS.md), with a new empty
mode-0700 runtime directory outside every checkout, a retained canonical archive
and checksum, and read-only reviewed TA inputs:

```sh
python3 tools/rehearse_case_recovery.py --run \
  --runtime /absolute/private/new-recovery-attempt \
  --package /absolute/private/artifacts/splunk_adm-0.9.8.tar.gz \
  --package-sha256 <trusted-retained-sha256> \
  --extracted /absolute/read-only/research/extracted \
  --socket unix:///absolute/local/docker.sock
```

The driver verifies the active local context and Unix socket, a cached reviewed
Linux/amd64 image, available resources, empty fixed namespaces and available
ports. It retains a private verified archive copy for every installation. Fixed
ports are 30900/30989/30988, 31900/31989/31988 and 32900/32989/32988. Each container
has the framework's 4-CPU, 8-GiB, no-extra-swap and 1,024-process limits. The task
has a 45-minute execution deadline plus bounded cleanup, an 8-GiB aggregate
named-volume budget sampled between phases, and a 12-GiB host disk reserve.
Disk checks are cooperative, not filesystem quotas; image cache, writable layers
and logs are outside that volume budget. Management, HEC and Web TLS each require
trusted success plus wrong-CA and wrong-hostname rejection.

Private outputs include the frozen archive, raw synthetic databases, sealed
bundle, external manifest digest, request journals and final recovery receipt.
Keep them outside Git with directories 0700 and files 0600. Credentials, cookies,
CSRF tokens and private keys are excluded from evidence. The fixture uses new
passwords after restore: Splunk identities and authentication state are not backed
up. Purge removes only exact owned containers, networks, volumes and credentials;
retained backups and audit/retry/history records are not erasure.

This scope excludes baseline/watch SQLite state, KV/platform configuration,
indexes, live writers, schema upgrades/downgrades, cross-build compatibility,
Cloud/SHC, real source authorization, source capture, job reconciliation and
production recovery. See [delivery evidence](FEATURE_DELIVERY.md) and the
[qualification record](FEATURE_QUALIFICATION.json) for performed tests and limits.

## Watch management journal schema 2

The baseline operator workflow upgrades `watch_runs.sqlite` from schema 1 to 2
transactionally to retain exact management request receipts. Existing binding
and unresolved run identities are preserved. This is not an installed recovery
qualification: preserve both baseline databases and use a validated compatible
writer for rollback; older writers reject schema 2. Never remove unresolved
runs or receipts to recover quota. See
[operator provisioning and reconciliation](BASELINE_SOURCE_PROVIDER.md).
