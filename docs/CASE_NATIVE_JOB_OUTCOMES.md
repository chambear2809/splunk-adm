# Native job acknowledgement uncertainty

The native synthetic acknowledgement-loss scenarios both passed their fault
and exact-retry checks against frozen Application Atlas 0.9.11. The original
installed primary remains **`failed_or_uncertain`** because its cleanup verifier
rejected an incomplete early job observation and correctly retained access. A
separate reviewed reconciliation passed, followed by **21/21 independent
postchecks**; cleanup does not rewrite that primary result.

The current library refuses to reconcile an unbound `creation_unknown` record and
continues to charge its slot. A bound `cleanup_unknown` record also remains
charged when its current caller's exact-SID proof receives 404: `_finish` does
not infer deletion or clear the ledger from that response. Neither elapsed time
nor an owner-wide search establishes the outcome. No runtime repair or automatic
reconciliation is claimed.

## Bounded installed-library exercise

`tools/qualify_native_job_outcomes.py --installed` is a test primitive for a
separately reviewed native fixture and uses the actual installed
`NativeComparisonSearch`, `SupervisedTransport`, `CaseStore` and `JobLedger`.
Its case database, ledger and quota are private synthetic fixtures; they are
not the live case database or live global capture quota. The CLI defaults to
separate child directories under the private, Splunk-owned mode-0700
`/opt/splunk/var/atlas-job-outcomes-20261118` root. The reviewed installed outer
fixture instead called `run_fixture` with isolated `private/create` and
`private/delete` directories under its fresh task-owned source-fixture stage. An outer lifecycle must create
and verify that root exclusively, serialize with other tasks, verify the exact
host, service UID, trusted TLS, frozen archive and all installed runtime hashes,
and provision and independently clean only its exact temporary synthetic source
and caller. The tool checks native x86_64, management preflight, server GUID,
Enterprise version and current caller context; those checks do not replace outer
attestation or cleanup. It makes no user, role, index, source configuration or
live-ledger modifications. No live execution is authorized by this document.

The launcher supplies one bounded JSON object on stdin containing `principal`,
`token`, `query`, `start`, `end`, and `mode` (`create` or `delete`). For the separate bound-job operator
exercise, delete mode additionally accepts `admin_principal` and `admin_token`
on stdin. Both tokens remain out of the evidence. The reviewed
query must be the fixed valid `admqualified` graph query over the fixture's own
synthetic source and usable bounded window. Pass a token only on stdin, never in
arguments, logs or source control. The tool independently verifies the current
caller has the supplied principal and `search`. Exact query/transport hashes,
principal, local capture request body, key and path, and the local ledger intent
are journalled before dispatch; no token is retained. The local case operation
uses the actual store library but is not an installed HTTP case endpoint or a
Web/CSRF test.

The create-loss wrapper allows the actual supervised native POST to complete,
records its returned server SID privately and durably for the fixture observer,
then raises a lost-acknowledgement error to the unchanged runtime. The SID is
never supplied to the runtime or bound into its ledger. The fixture checks the
unbound `creation_unknown` record, query/transport identity, no capture receipt,
no replacement POST on exact same-body/key/principal retry, and charged private
quota. It also checks a synthetic local entitlement denial, changed transport
fingerprint, different-principal denial and held-lease exclusion. These local
checks are not an installed role-revocation or configuration-change test.

The delete-loss wrapper verifies the bound SID's current metadata before the
actual native DELETE, then records the successful acknowledgement privately and
raises the injected error. The runtime retains `cleanup_unknown` and its bound
SID. The same exact local capture retry must not dispatch a replacement job;
the checks above are repeated against the private ledger. A pair of fixture-only
ledger reservations fills the remaining two slots under a distinct synthetic principal so a fourth
reservation fails. These artificial reservations do not represent actual native
jobs and must stay out of the live ledger.

After the uncertainty and retry observations, the fixture observer may use the
privately retained creation SID only to check exact caller, app, query hash and
window metadata and issue a separately journalled exact-SID cleanup. It does not
bind that SID to the runtime ledger. For deletion loss the native DELETE has
already returned success to the fixture. In both modes, a same-caller exact-SID
404 is recorded **only as that caller's observation**, not authoritative proof
of physical absence. A separately authenticated, independently qualified operator
must verify exact task-owned job retirement and preserve uncertainty if visibility
or a response is ambiguous. The fixture leaves uncertain and artificial ledger
slots charged and retains all private journals and isolated databases. A run can
fail after native job creation or deletion; preserve the private stage, original
operation identity, hidden SID evidence and recovery access rather than deleting
resources by broad owner, clearing the ledger or inventing a replacement write.
An initial acknowledgement can be lost before the private SID is durably saved;
that is an unresolved outcome and cleanup must not guess a job identity.

The operator observer uses the unchanged supervised transport for server info,
current context and exact job GETs. Because that transport deliberately rejects
role metadata paths, a test-only read-only adapter fetches only roles named by
the freshly authenticated context over pinned loopback TLS, with a three-second
deadline, a 1 MiB response cap and no redirects. It neither expands the runtime
allowlist nor logs authorization. Its target and lifecycle require review.

The optional operator path is restricted to the bound `cleanup_unknown` record
in the **isolated fixture ledger**. Before the native DELETE, a fresh supervised
admin observer must verify the exact native SID, owning principal, app, query
hash and time window; it durably records that proof, the caller and transport,
target GUID, CA-bound transport fingerprint, service PID/start ticks/executable,
effective administrator capabilities and roles, and hashes of each role definition.
The DELETE must return success to the fixture before its acknowledgement is
intentionally withheld. After the uncertainty and exact-retry checks, the admin
observer independently checks the exact SID, requiring an unambiguous 404 with
no uncertain transport result. Fresh authenticated context, both `search` and
`admin_all_objects`, role definitions, CA bytes, target GUID and service process
identity must agree before and after that check. The operator path records this
proof, compares the exact existing ledger identity and current revision, and
uses the original retry's still-owned lease to claim with CAS and transition
only that bound record to `deleted`. After clearance, the same local case request
body, key and principal are retried: one new native job must produce one capture
and one receipt, the original exact replay must retain that capture ID and
revision without dispatching another job, and a freshly checked admin observer
must find the new job absent. The synthetic quota fillers remain charged. This
is an installed-library case, not an HTTP case endpoint. Any proof failure, changed role, service
restart, unavailable HTTP, different SID, stale revision or competing lease
leaves the slot unresolved and charged. This is a separately supervised test
operator action, not a change to runtime auto-reconciliation.

An authenticated 404 is meaningful here only under the reviewed observer's
verified all-objects visibility, matching role definitions and unchanged service
and transport identity. Visibility and permissions are checked around the
request, not atomically with Splunk's internal authorization state; the outer
lifecycle must prevent concurrent administrator/configuration changes and
record uncertainty if it cannot. The pre-delete job check and the delete
acknowledgement must be in the private journal before clearance. Unbound
`creation_unknown` is never eligible, even if a fixture observer later cleans up
its hidden job. The operator path was exercised on an installed native instance
only with an isolated synthetic fixture ledger. There is no qualified production
operator interface, and the path must not be applied to any live global ledger.

Before any native invocation, review the exact payload and outer lifecycle,
including source isolation, bounds, durable journal recovery, target attribution,
independent observation, exact-job cleanup and retention of caller access. Record
fault injection, native observations, ledger states, exact retry and cleanup
separately. A local unit test or this scaffold does not qualify native behavior,
real sources, Cloud/SHC or production readiness.


## Installed evidence and reconciliation

The fixture withheld successful acknowledgements after actual supervised native
job creation and deletion. Create mode retained one unbound `creation_unknown`
row, no capture receipt and two artificial quota reservations. Exact retry did
not create a replacement job; physical cleanup of the privately observed native
SID did not bind or clear the unknown ledger row. Delete mode retained the bound
`cleanup_unknown` observation, then used the separately attested operator proof
and CAS/lease transition in its isolated ledger. The exact original local case
body, key and principal then converged to one capture and one receipt, with a
distinct new local/native job identity and stable exact replay. The two artificial
quota rows remain charged. These are synthetic installed-library results, not
case HTTP endpoint authorization or a shipped automatic recovery interface.

The original outer cleanup treated every retained poll observation as a full
identity proof. One initial `PARSING` response had the correct SID, owner, app,
request query and time bounds but no top-level search text. Later responses
contained full matching metadata. The cleanup guard stopped before deleting
resources and kept the generated credentials. The failed primary, original
journal and diagnostic remain retained.

The test-only `verify_retained_metadata` repair accepts only that observed first
`PARSING`/`isDone=false`/missing-search shape, validates every other identity field
with the unchanged installed native verifier, preserves the incomplete record,
and requires a later unmodified full proof. Contradictory owner, app, SID,
query, time bounds, state or ordering fails closed. It does not change the
runtime verifier or establish job completion from a parsing response. Separate
reviewed reconciliation checked all three fault/convergence native SIDs and
independently anchored deletion histories, all four setup count-job chains,
fresh administrator/service/transport identity, unchanged private ledger row
sets, original app settings and live database bytes before removing only the
owned temporary resources. No fault, capture or native job was retried.

The independent postcheck verified 21 checks, all 88 installed runtime hashes,
three exact fault/convergence SID metadata associations and native 404s, four
settled setup count chains, exact delete-mode capture receipt/retry identity,
zero create-mode capture receipts, retained unknown/artificial rows, unchanged
live main databases and SQLite sidecars, restored app settings, and absent owned
users, roles, indexes, HEC input and generated credentials. Setup count chains
are separately identified; they are not claimed as full source-job metadata
proofs. API absence is not physical data erasure. The private case/ledger pairs,
raw observations, original failed primary and separate reconciliation receipt
remain retained under the private `atlas-uncertain-outcomes` evidence root.

No live global ledger slot was stranded or reset. Unbound creation recovery,
production operator tooling, unknown remote outcomes without retained exact
identity, real-source completeness and production readiness remain unsupported
or unqualified. This result does not qualify all host authorization-file layers.
