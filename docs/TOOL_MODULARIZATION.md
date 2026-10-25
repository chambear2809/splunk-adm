# Operational tool modularization

The migration operator and raw fixture generator remain runnable from their
existing script paths. Their modules now separate contract and persistence
rules from the command-line entrypoints and domain-specific builders.

## Cisco contract migration

`tools/cisco_contract_migration.py` is the compatibility facade. It keeps the
existing CLI, imports, `Migration` class, `Journal` class, and test patch seams.
`Migration` is defined in this facade and composes the responsibility mixins so
the standalone-deployment qualifier continues to bind it to this source file.

| Module | Responsibility |
| --- | --- |
| `tools/cisco_migration/common.py` | Contract constants, refusal types, pure comparisons and planning helpers, and protected state-directory checks. |
| `tools/cisco_migration/journal.py` | Owner-only journal and artifact reads, locking, and durable atomic writes. |
| `tools/cisco_migration/core.py` | Target qualification, configuration snapshots, preparation, and operation fencing. |
| `tools/cisco_migration/evidence.py` | Bounded result artifacts, validation evidence, and public-surface checks. |
| `tools/cisco_migration/dispatch.py` | Search dispatch, reconciliation, staged writers, and stream backfill. |
| `tools/cisco_migration/history.py` | Client-history and application-catalog staging and validation. |
| `tools/cisco_migration/cutover.py` | Cutover mutations, scheduler-boundary checks, and activation evidence. |
| `tools/cisco_migration/recovery.py` | V1 retention checks, rollback recovery planning, and rollback execution. |
| `tools/cisco_migration/cli.py` | Argument parsing, safe scenario reads, stdin authentication, and command dispatch. |

Use the same operator commands as before, for example:

```sh
python3 tools/cisco_contract_migration.py --journal /secure/path/cisco-v2.json status
python3 tools/cisco_contract_migration.py --journal /secure/path/cisco-v2.json prepare --start <UTC_EPOCH> --end <UTC_EPOCH>
```

The extracted modules retain the migration's journal schema, write ordering,
authentication, TLS, bounds, refusal paths, and resumable state transitions.
Qualification snapshots now hash the facade and every file in
`MIGRATION_SOURCE_FILES` in `tools/qualification_shc_run.py`; changing an
extracted implementation file invalidates the existing source snapshot just as
changing the original script did.

## Raw fixture generator

`tools/gen_raw_fixtures.py` keeps the original command-line path and re-exports
the generator functions used by tests and capture tools.

| Module | Responsibility |
| --- | --- |
| `tools/raw_fixtures/common.py` | Scenario primitives, stable IDs, timestamp formatting, shared constants, and NDJSON writing. |
| `tools/raw_fixtures/nxos.py` | NX-OS, NetFlow, FTD, Isovalent, Kubernetes, and OTel fixture builders. |
| `tools/raw_fixtures/aci.py` | ACI, Kubernetes, Hubble, OTel, edge-case, and prior-window builders. |
| `tools/raw_fixtures/networking.py` | Combined campus/Meraki fixture construction. |
| `tools/raw_fixtures/cli.py` | Existing `--scenario`, `--base-time`, and `--output-dir` behavior. |

Anchor combined networking output when regenerating or comparing it:

```sh
python3 tools/gen_raw_fixtures.py --scenario networking --base-time 2026-10-16T13:00:00Z --output-dir /tmp/networking-fixtures
```

`generator_source_hashes()` in the facade returns hashes for the complete
generator implementation closure. The networking capture tool records that
closure in initialization and capture evidence. The historical ACI capture
keeps its original `generator_sha256`, timestamp, rows, input hashes, and
qualification; `reviewed_generator_compatibility` records static byte-
equivalence evidence for the extracted implementation without claiming a new
live capture.

## Compatibility checks

The focused regression commands are:

```sh
python3 -m unittest discover -s tests -p 'test_cisco_contract_migration.py'
python3 -m unittest discover -s tests -p 'test_cisco_migration_fencing.py'
python3 -m unittest discover -s tests -p 'test_cisco_upgrade_harness.py'
python3 -m unittest discover -s tests -p 'test_fixture_drift.py'
python3 -m unittest discover -s tests -p 'test_previous_demo.py'
python3 -m unittest discover -s tests -p 'test_capture_networking.py'
```

The migration qualification harness binds all extracted modules before it
starts its phase checks. Generator capture fingerprints do the same for the
fixture-builder closure. Historical fixture compatibility is a static source
review backed by byte-for-byte output comparison with the recorded inputs and
clock settings; it does not establish a new Splunk lab result.
