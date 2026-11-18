# Isolated native case recovery exercise

The isolated synthetic library recovery exercise **passed on the native target**
on 2026-11-18. It used installed application storage libraries and synthetic source callbacks in a new,
private directory. It is not an installed endpoint test, a cold Splunk platform
restore, a production backup procedure, or real-source qualification. It does
not start searches, touch live case databases, reserve live capture quota, change
configuration, or create Splunk users or roles.

The exercise creates independently initialized schemas using `CaseStore` and
`JobLedger`; saves a comparison through the installed `ComparisonSource` with
synthetic graph rows and warnings; and retains a note and its immutable revision,
attachment, ACL, capture, audit and exact retry. It seeds three isolated ledger
slots in `creating`, `creation_unknown` and `cleanup_unknown`, including one
synthetic bound SID. Quiescent databases are sealed by the existing
`tools/case_recovery_snapshot.py` helper, with schema, integrity, foreign-key,
logical-table, manifest, provenance and file-byte checks. It refuses an occupied
target without changing its sentinel, rejects corrupt bundle bytes before target
creation, and injects failure while copying the second database: the helper must
remove its own new partial target and leave the sealed bundle valid. A separate
new target is restored and the complete logical tables are compared. Reopened
stores exercise source rechecks, current synthetic access and config denial on
selected read/export and exact capture retry; notes remain available while source
evidence is withheld. The ACL and audit are checked, the original retry retains
capture identity and revision, and all three unresolved slots remain charged after
the clock advances. No native SID is created or reconciled.

## Installed result — 2026-11-18

The authorized Enterprise 10.6.0.5 target ran the frozen Atlas 0.9.11 build on
native Linux x86_64. The launcher verified the target GUID and all 88 installed
runtime hashes. All eight recovery checks passed. The retained receipt SHA-256 is
`e7c142c14b727128773a9f2eb9f1ce96540613bd030a0001916382356e198f93`;
the sealed bundle manifest SHA-256 is
`12434cbb0f46fd809151ad60f30f075a8f0df9b0c7fb483d8e905382b4c2954c`.
The independent postcheck passed all eight checks, including matching receipt
and manifest hashes, private retained permissions, active service, disabled
persistence/capture, and unchanged live database and local configuration file
bytes and metadata. The synthetic private fixture tree and evidence remain
retained; this is not an erasure claim.

The private `recovery-installed-output.json` has SHA-256
`99cf8b5bb7c1d20896d7156cd3947913fac0748329be82a6cafaf6a42d3f8e31` and
`recovery-independent-postcheck.json` has SHA-256
`fe9f8b7b6c4c0fcb1f6446f56e5ca88f8ef03f36022652a3d676991e3571de9a`.
Both remain outside Git under `atlas-recovery-qualification`. This result is
same-build isolated installed-library recovery with synthetic callbacks, not a
real-source, authenticated endpoint, cold platform, Cloud/SHC or production
recovery qualification.

## Execution boundary

`tools/qualify_native_recovery.py --installed` allows only the fixed new directory
`/opt/splunk/var/atlas-recovery-isolated-20261118` and imports libraries only from
`/opt/splunk/etc/apps/splunk_adm/bin`. It requires the Splunk service user and a
reviewed transport to the separately attested target. The fixed directory must
be absent; the tool refuses to adopt or overwrite it. The external launcher must
provide `case_recovery_snapshot.py` as the importable sibling module, using the
exact reviewed helper bytes; an in-memory module loaded by the launcher is also
acceptable. A launcher must preserve isolated Python import behavior and must not
put credentials into arguments or output. Review that launcher and both exact
scripts before dispatch. The tool creates and syncs its owned private directory,
retains the synthetic databases, bundle, failed negative copies and receipt there,
and does not delete the tree. A failure may leave partial owned evidence; inspect
it and do not rerun into the same directory. Any later deletion must be limited
to a separately verified exact owned tree.

The external lifecycle must verify native architecture, target identity, frozen
0.9.11 package and installed hashes before execution and retain those attestations
with the tool and helper hashes. The receipt records the three imported library
hashes and a package SHA-256 **claim**, not an independent archive attestation.
Keep evidence outside Git, inspect the manifest and receipt and record their
SHA-256 values. A printed pass is supported only if all checks and independent
attestations agree. This exercises isolated SQLite copies made after fixture
writers stop; it does not prove an atomic cross-database snapshot with live
writers, endpoint authorization or transport, raw data or platform recovery,
unknown native job reconciliation, different builds, Cloud/SHC, or production
readiness. Shipped gates remain disabled.
