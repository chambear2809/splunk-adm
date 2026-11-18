# Injected isolated installed endpoint restore

The installed synthetic scenario passed, and its corrected independent read-only
postcheck passed all 29 checks. This is an **injected, isolated endpoint
restore**: it does not restore a full Splunk installation, replace live case
databases, establish a fresh native instance or qualify an operational cold
restore. The task-only hook was outside the archive; no shipped app runtime
bytes were changed.

The authorized native Enterprise lab used the frozen 0.9.11 build `1795023134`
archive (SHA-256
`0a87171ca77fbeedc778844fb326e523f7c427920ea36dcd4fc4cd54cb62bc7e`).
The private fixture payload SHA-256 was
`1cfa49d52b54c0460882517077a4c210a657e5cf4b4551c7d678030dfec73df6`.
Both fixture principals were authenticated and attested against separate private
canaries before source and restored case requests. The installed workflow passed
its five scenario checks: the source case, notes, revision, capture reference,
ACL, audit and old retry were available after the paired restore; current source
access was denied and restored as exercised; one synthetic unbound unknown ledger
row remained; and occupied, corrupt and partial-copy targets were rejected.
The original live case and capture-ledger databases were never opened through
SQLite by the fixture or postcheck.

The independent postcheck verified the original live database and sidecar
hashes and metadata, all 88 installed runtime hashes, original startup
source/cache and app-local configuration, retained private case/ledger pairs,
exact original capture receipt digest in both copies, route markers and empty
canaries, and the unchanged single archived unknown row. It verified 35 native
source-job ledger rows across the two private copies as terminal with their
bound native SIDs absent, along with absence of the task users, roles, HEC input,
indexes, credentials and installed hook. The private source and restored
databases, sealed snapshot and synthetic journals were retained. API absence does
not prove physical data erasure. The postcheck result SHA-256 is
`4057d4b1d07789505099a7b84adbec16cfa90f1ba6f4feeff54f3712f54c6616`;
the private native operation journal SHA-256 is
`4c8f1af03b53389c39a1783ded9a798841bbbc344bb6a3187cad3bcd3066bb9d`.

The first independent read-only checker failed after an admin-context response
shadowed its TLS context; its failed output and checker are retained unchanged.
Only the checker was corrected and independently reviewed, including a local
regression with two actual HTTPS calls after the context read. The installed
scenario was not repeated, and its original successful result was not changed.
The scenario does not establish recovery from an unknown real remote-job
creation or deletion, Cloud/SHC support, real-source behavior or production
readiness.

A task-only startup hook outside the frozen archive matches the exact request
worker argv and changes only `SplunkHost.database` for two newly created,
collision-checked synthetic principals. It rechecks the actual authenticated
principal, selects a fixed private source or restored root through a private,
generation-bound control file, then delegates to the original database path
and file safety checks. Other principals delegate to the original route.
Caller input cannot select a path. Missing, malformed, stale or ambiguous
control blocks both fixture users; it never falls through to the live database.
The fixture serializes route changes, first blocks new fixture database access,
and requires all journaled requests to have settled and their request workers
and groups to have retired before copying, changing routes, removing the hook
or cleaning up. The persistent supervisor remains running.
It does not stop unrelated users or writers. Before the first case write,
the fixture invokes the unchanged request supervisor and worker under each
authenticated fixture principal with a separate private canary `SPLUNK_DB`.
It requires a retired worker, a durable route marker proving the principal,
generation and private destination, an untouched canary and unchanged live
file hashes. It repeats this check for the restored route before any restored
case request. An absent or skipped hook can access only the canary during this
probe. Hook installation failures terminate the exact worker rather than being
ignored by Python's `sitecustomize` startup mechanism.

The standalone native fixture used temporary synthetic-only callers,
roles, bounded task indexes and a temporary HEC input. Through the installed
handler, request supervisor, case API/store, native comparison search and
supervised transport it creates a case with a note revision, source capture,
capture reference, share, revoked membership and audit history. Exact original
request identities are durably journaled before dispatch. Once fixture writers
are quiescent, an isolated archived synthetic principal receives exactly one
`creation_unknown` ledger row with no native SID. That row remains charged to
the global three-slot budget; two slots remain for normal fixture callers.

The existing paired case/ledger snapshot helper seals both private source files
against schemas derived from fresh installed-runtime instances and restores to
a fresh private target. Occupied, corrupt and injected partial-copy negatives
must reject without changing their sentinel or producing an adopted target.
The restored pair must retain the unknown row even after a large clock advance,
and the same archived principal's native reconciliation must remain blocked
without issuing a native request. Only then may the fixture route move to the
restored root. It verifies private/shared/revoked access, note revisions,
capture reference, audit and exact old retry, plus source-backed selected reads
and source-filter denial/restoration. Actual source jobs must be terminal and
absent by native SID; the synthetic unknown row has no native SID and is not a
claim about real unknown remote-job recovery.

The original live case and capture-ledger databases are never opened through
SQLite or selected by the injected fixture. Read-only byte hashing and metadata
checks before and after are independent integrity evidence; a mismatch is
uncertain, not authorization to repair or replace live data. The original
startup source/cache and app-local configuration bytes, ownership, mode and
modification times are independently compared after guarded restoration. The
separate source and restored private databases, snapshot and journals are
retained. Cleanup may remove only the task's users, roles, HEC input, synthetic
indexes and hook after all operations and native job outcomes are reconciled;
uncertainty preserves access and credentials. API absence does not establish
physical index-data erasure.

`tools/qualify_native_endpoint_restore.py` supplies the fixed-principal route
hook/control and paired-snapshot negative checks. The private driver supplies
the reviewed installed endpoint workflow, task-specific root hook transaction,
process/operation reconciliation, synthetic setup and cleanup. Native service
availability, target identity, TLS, the exact candidate archive and runtime
hashes are separate preflight requirements. The coordinating owner serializes
host access and obtains independent prelaunch review; the existence of this
fixture does not authorize execution. Cloud, SHC, real-source and production
behavior remain unqualified, and shipped capture and persistence stay disabled.
