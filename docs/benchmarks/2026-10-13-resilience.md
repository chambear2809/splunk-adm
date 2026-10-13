# Local resilience validation — 2026-10-13

These are disposable localhost lab rehearsals using synthetic events, not
measurements from the future pilot or evidence of production capacity.

## Backup and restore

Command: `python3 tools/rehearse_restore.py --reset-lab`.

Result: passed. The harness recreated the Splunk container, restored all six KV
collections (20 rows total) and the allowlisted app configuration, reingested
22 retained synthetic raw events, and rebuilt/replayed six flow records.
The graph SHA-256 before and after restore was identical:
`89f6263c14f43d33955d38be5a905039e59637f3c55ae9c91cc24373977a8617`.

[Sanitized evidence](2026-10-13-restore.json) records app/image fingerprints,
collection counts, fixture and graph digests, and search completion. The actual
backup stays in ignored `dist/restore/` and is not committed. This rehearsal
covers app state plus reconstruction from retained raw fixtures; it does not
back up production raw indexes, credentials, or external integrations.

## Process interruption

Command: `python3 tools/fault_pipeline.py --reset-lab --flow-copies 500`.

Result: passed. The harness observed a running rollup, killed the container,
restarted it, cleared only the derived summary index, and rebuilt the closed
raw slice. All 10,081 raw events remained; their identity digests matched before
and after recovery. The rebuilt summary contained the expected 10,000 flow
records. Recovery through final verification took 165.357 seconds on this lab.

[Sanitized evidence](2026-10-13-fault.json) includes the real interruption,
completion checks, counts, digests, and environment. The first attempt exposed
a harness startup race: management/KV became available before the image's
startup playbook completed, and summary maintenance failed. The harness now
waits for that completion before maintenance; the full rerun above passed.
This is retained-raw rebuild recovery, not transactional replay of a partial
summary or a production recovery-time guarantee.

## Read-only readiness

The lab adapter checked NetFlow, Kubernetes, traces, and summaries after the
fault rehearsal. All four required-field checks and the effective ACL check
passed. It correctly reported blocked readiness because the harness leaves
builders unscheduled; it also reported unmapped flow scope and maintenance
warnings. No evidence was unknown, and a before/after digest confirmed that
allowlisted app files and all six KV collections were unchanged.

[Readiness evidence](2026-10-13-readiness.json) records every finding. This is a
check of the local adapter and reporting behavior; a real pilot still needs
its own source, access, collector, device, and delivery validation.

## Repository checks

64 standalone Python tests, Python lint/format checks, `npm run lint`,
`npm run package`, and release archive validation passed. Release validation is
now part of the frontend CI job. These checks were run locally; no changes were
committed, pushed, or released as part of this work.
