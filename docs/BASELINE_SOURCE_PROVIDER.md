# Retained baseline source adapter (unqualified)

The shipped host still has no production source provider and refuses source
capture. The retained-artifact adapter and provisioning command in this change
are local integration components, not evidence of a complete source or an
installed operator workflow. No configuration switch wires them into the host.
Do not enable capture, action execution or scheduling on their account.

A separately reviewed producer must establish the exact four-field selection,
including empty results, and preserve a record of every closed half-open window.
Its evidence must independently establish coverage, unsampled operation, zero
loss and truncation, no caps, stable identity/normalization and watermark closure
with the required lateness. A self-reported JSON manifest or successful search
cannot establish those facts. No such producer or production entitlement
integration exists here. A future integration must verify producer evidence,
bind the producer revision to its deployment, use the current caller's actual
source permissions for every operation and prove revocation, tampering and
retention behavior before enabling the adapter. Local filesystem access and
operator claims do not grant source access.

`RetainedArtifacts` reads a 0700 owner-private directory containing 0600 regular,
single-link JSON files. An index named `index-<sha256>.json` is a lookup hint;
the hash covers canonical JSON `[selection, window]`, and the file contains only
`{"reference":"<sha256>"}`. The record file `<reference>.json` contains exactly
`capture` and `provenance`. Its reference is the SHA-256 of canonical JSON of
the record before adding `provenance.reference`. The reader checks that digest,
rejects duplicate JSON fields, unsafe files and oversized records. The directory
must be controlled by the service owner; the reader does not defend against a
malicious process running as that owner. Writers must publish atomically and
retain records as long as any baseline, occurrence or unresolved run references
them. Indexes may change; previously addressed records must remain available.

Provenance carries the exact selection and requested window, capture digest,
authority, scope, source/configuration/normalization revisions, signature
version, required lateness and knowledge horizon matching the capture, plus
producer revision, `windowSemantics: "half-open"`, coverage start/end, watermark,
`sampling: "none"`, zero lost events and false truncated/capped values. The
source revision starts with the configured producer revision followed by a
colon. The adapter checks boundaries, exact agreement, watermarks and horizon,
then requires an independent producer-evidence verifier and calls the current-source authorization function on every
resolution, entitlement check and selection attestation. This validation checks
consistency of assertions; it cannot independently validate their truth. A
producer integration must independently verify those claims in that verifier. Its authorization function must fail closed on unknown or
revoked access. `lookup` only retrieves retained captures and never dispatches
collection jobs. Transport deadlines, global quotas and producer identity need
separate qualification before integration.

`adm_baseline_provision.py` accepts at most 64 KiB of JSON on stdin. The
`session_key` comes from the current caller and is never written to the journal
or output. The `operation` is one of:

- `create`: `baseline_id`, `watch_id`, the exact four-field `selection` and a
  stable `request_id`. It verifies the current administrator, baseline owner,
  pinned capture, source access and selection; a new immutable binding starts
  disabled. Exact retries reuse the same binding identity.
- `enable`: `binding_id`, `expected_revision` and a stable `request_id`. It
  rechecks the owner, administrator, pinned capture and current source authority
  before a revision-checked state change.
- `disable`: the same three fields as enable. It checks the administrator and
  immutable owner without requiring the source or execution to be available.
- `inspect`: `binding_id` returns the current binding definition and state to
  its authenticated administrator owner. It contains no capture or session.
- `find_created`: `request_id` locates a previously committed create for the
  current administrator, including when the source is unavailable.
- `receipt`: `binding_id` and `request_id` retrieve a committed enable/disable
  receipt for the current administrator, including after source revocation.

Create request keys and state-change request keys use separate namespaces;
state-change keys are unique per principal across bindings and operations. A
state-change receipt is recorded atomically with its revision change. Exact
retries return that historical receipt, even if the binding was subsequently
changed; use `inspect` for current state. Reuse with a different binding,
revision or operation conflicts. After a lost response, retain the original key
and fields. A missing receipt is not proof of noncommit while a request may
still be in flight. Source revocation can prevent replay of enable; use the
source-independent receipt lookup to reconcile it. No command starts a source
job or clears an uncertain run.

The journal migrates schema 1 to schema 2 transactionally, preserving binding
and run identities. Older writers reject schema 2; preserve both databases and
use a validated compatible writer for recovery. The journal retains up to 1,024
management receipts, admitting keyed enables only below 896 and reserving one
stop receipt for every binding that will remain enabled, including bindings
enabled through legacy unkeyed calls. No-op disables cannot consume this stop
reserve. It does not automatically delete receipts; exact stored retries remain
available at capacity. A legacy journal already full while bindings remain
enabled can still use the unkeyed disable-only route, without a new receipt.
This is local synthetic
coverage, not installed provisioning qualification. The command still returns
unavailable for create/enable in the shipped host, which has no verified
provider.

Before deployment, separately qualify installed caller/session and ACL behavior,
producer integrity and completeness, entitlement revocation, backup/restore,
concurrency, quotas, and bounded transport/cleanup. Cloud and search-head
cluster storage remain unsupported. Preserve the baseline and watch journal
and all unresolved runs during rollback.
