# Backup and restore rehearsal

`tools/rehearse_restore.py` retains the earlier KV/configuration restore
rehearsal. Its earlier results do not qualify the new case, baseline or
capture-job SQLite databases. The current local check for those databases is
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
