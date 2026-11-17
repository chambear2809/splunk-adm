# Dependency watch execution contract

This is a local execution-mechanics contract. A production complete source
provider is still unavailable. No schedule, notification or infrastructure
operation is enabled, and these mechanics do not qualify source-backed scheduling.

## Ownership and evidence

One immutable binding identifies one baseline, watch, pinned baseline version,
execution principal, exact service/environment/cluster/namespace selection and
provider contract revision. Bindings start disabled. Creating or enabling them
requires a currently authenticated administrator who also owns the baseline.
Stopping an existing binding requires the current administrator to match its
immutable execution principal; it does not require current source or baseline
access. Administration does not grant access to another owner's baseline.
Execution requires the same current administrator/owner, an enabled unchanged
binding and current source access. A definition change creates a new binding ID.

Each run accepts only a binding ID, one explicit absolute window of at most five
minutes and a stable request key. There is no automatic slot selection, catch-up,
wall-clock completeness inference, all-user enumeration or notification.

The trusted provider's `contract_revision` must match the binding. Its capture,
resolve, entitlement and selection-attestation operations receive the same run
budget object. The budget permits at most three source searches within the
existing 25-second collection allowance and shared three-second cleanup allowance.
Provider qualification must enforce transport deadlines, cleanup and global
job accounting; synchronous trusted Python callbacks alone cannot establish a
hard wall-clock bound. Late callback results must not be accepted.

`attest_selection(principal, selection, reference, capture, *, budget)` returns
exactly `selection`, `providerContractRevision`, `captureDigest`, `authority`,
`scope`, `sourceRevision`, `configRevision`, `normalizationRevision` and
`matches: true`. The digest uses the baseline store's canonical JSON. Every
field must match the actual capture and expected binding. The provider must
establish the selection from retained authorized provenance, including for
empty captures; echoing arguments is not an implementation of that proof.
Revalidate the pinned baseline and candidate on every run. Attestation does not
replace current `resolve` and `entitled` checks.

The baseline store supplies a private owner-only execution context containing
the current revision, pinned version, retained reference and capture. This is
not a new public endpoint or source-permission grant. The executor constructs
its store with callbacks that use the same provider and run budget.

## Durable uncertainty

The separate private `watch_runs.sqlite` contains immutable binding definitions,
revocable enabled state, run fingerprints, technical state and opaque nonsecret
provider references. A run also retains its original binding revision and
canonical capture digest. It contains no session tokens, source captures or query
payloads. Its directory must be owner-only and files regular, single-link and
mode 0600. Unsupported schemas and unsafe paths fail closed.
Existing SQLite sidecars must meet the same file protections. WAL mode is not
supported. The guards assume an owner-controlled private directory; they do not
protect against a process already acting as that filesystem owner.

The states are:

- `intent`: reserved durably before capture. A crash-left expired intent becomes
  `capture_unknown`; it must never automatically dispatch another capture.
- `capture_unknown`: no trusted reference was retained. Do not guess or recapture.
- `prepared`: retain the trusted reference, canonical capture digest, original
  baseline CAS revision and stable evaluation request key before evaluating.
- `evaluation_unknown`: persisted before the evaluation call. Reconcile only by
  repeating that exact reference, revision and request key, with fresh authority.
- `committed`: acknowledge success, including a withheld retry receipt. Do not
  replay protected inserted/surfaced counts from the run journal.
- `rejected`: only a demonstrably definitive noncommit. A transport failure,
  source/ownership loss or disabled binding does not prove noncommit.

Concurrent owners use revisioned leases; a lease timeout is not evidence that a
remote operation did not occur. A fresh request key cannot bypass an unresolved
run for the same binding/window. Reusing a key with different input conflicts.
No retry adopts a new baseline CAS revision automatically. Binding disablement
prevents subsequent admission and prepared work that reaches a binding recheck.
Capture or evaluation already in flight may still finish; stopping cannot
retroactively cancel a committed evaluation.
Disabling and re-enabling advances the binding revision; an older unresolved
run cannot resume under that new revision. Candidate evidence must match its
retained digest both during retry proof and when the baseline store actually
resolves it for evaluation. A changed reference cannot silently change findings.

The default journal allows three nonterminal runs and reserves terminal receipt
capacity before capture. At 128 retained run identities it refuses new work;
it does not delete retry identity or clear unknown runs from age alone. Binding
definitions are also bounded. Explicit retention/reconciliation and installed
operational recovery need separate qualification.

## Integration boundary

The default entrypoint must refuse before source dispatch when disabled or when
the provider is unavailable. Any shipped action uses the owner's session from
bounded standard input only, never system authentication or stored credentials.
Action and owner-dispatched search read/write ACLs remain administrator-only.
The action may record authorized findings only; notifications and infrastructure
changes are outside this contract. Automatic schedule/window closure remains
blocked on the complete provider's qualified watermark and lateness contract.

## Local adapter and remaining qualification

`adm_dependency_watch.py` reads at most 64 KiB of UTF-8 JSON from standard input.
Required envelope fields are `app`, `session_key`, and `result`; result contains
exactly `binding_id`, `start`, `end`, and `request_id`. It accepts integer seconds
or their canonical ASCII decimal string representation, normalizing to integers
before journal identity. Duplicate keys, booleans, floats, signs, whitespace,
exponents, leading zeros and additional result fields are rejected. Allowlisted
Splunk envelope metadata is ignored; supplied owner, configuration, URLs and
paths never determine identity, transport or source behavior. Splunk's published
[webhook payload example](https://help.splunk.com/en/splunk-enterprise/alert-and-respond/alerting-manual/10.6/configure-alert-actions/use-a-webhook-alert-action)
supports string-valued results, but does not qualify the complete custom-action
envelope. Actual installed invocation remains untested.

The shipped action's `passSystemAuth` is false. `adm_dependency_watch.conf`
defaults to `enabled = false`; this is separate from each binding's opt-in.
The execution host refuses an absent provider before opening its database or
journal. Its separate trusted `watch_manager()` opens only an existing valid
private journal and returns a disable-only `WatchStopper`; it requires current
authentication and administrator authority without checking execution readiness,
source availability or baseline persistence configuration. The manager cannot
create or enable a binding, execute a run, bootstrap an empty journal or recreate
a missing database. It returns only binding ID, revision and `enabled: false`.
Stopping preserves all uncertain run states, retained references and quota
accounting. Existing journal schema and canonical binding records are validated
before their ownership data is used. A narrow authenticated HTTP stop route is
described below. No management UI, provisioning or enable route is exposed.
Bindings can currently be provisioned only through the trusted host/executor
interface. This is a local execution-mechanics increment, not an operator-ready
watch workflow.

Local tests use an explicitly injected synthetic provider. They verify journal
admission, crash boundaries, leases, source/owner revocation, capture digests,
unchanged binding revisions, exact idempotent evaluation and compact withheld
receipts. Host tests check that authorization callbacks can acquire a separate
SQLite writer: SDK/configuration work is outside the baseline write transaction.
Provider transport/global-job enforcement, installed action ACLs/session behavior,
positive real-source scheduling and operational journal recovery remain unqualified.

For rollback, keep execution disabled and preserve both databases. Do not delete
uncertain runs to regain quota, rewrite binding revisions, or run an older writer
against this journal. Schema 1 is the first local contract; unsupported or earlier
unreleased layouts fail closed. Offline backup/restore of this new journal has
not been operationally qualified.


## Operator stop command

`POST adm/dependency-monitoring/watch-management/disable` accepts JSON containing
exactly `binding_id` and integer `expected_revision`. The binding ID and current
revision must come from the trusted provisioning/management record. There is no
HTTP binding enumeration or provisioning workflow. Requests require the current
investigator capability and administrator role; the immutable binding principal
must match that authenticated administrator. Splunk Web exposes only this exact
POST route with its native session/CSRF protections. No CSRF override is shipped.
Direct API clients need authenticated verified HTTPS. Installed Web/CSRF and
effective-ACL qualification of this new route remains outstanding.

The stop command deliberately runs before execution/persistence/source readiness
checks. It opens only an existing private validated journal, never a new one.
It cannot enable a binding, create work, dispatch a search, delete uncertain runs
or recover quota. It returns only `id`, the new `revision` and `enabled: false`.
A concurrent revision change returns 409. This command does not add idempotency
receipts: a lost successful response followed by the original CAS can also return
409. Treat that result as unresolved and reconcile through the trusted journal
management path; do not assume a conflict proves either enabled or disabled.
Keep execution disabled during operational reconciliation. Already admitted work
may still finish, as described above.

The JSON body is limited to 4 KiB. Extra fields, duplicate JSON/query/header keys,
malformed revisions and extra query arguments are rejected. The route supplies
no source captures, run references, credentials or binding definitions. Local
host tests use synthetic state and verify authorization, revision conflicts,
source-independent stop, missing/corrupt journal refusal, and preservation of
uncertain run records. They are implementation checks, not installed or
real-source qualification. Removing the route on code rollback preserves the
journal; the trusted disable-only manager remains the fallback. Do not downgrade
or reset journal data to regain capacity.
