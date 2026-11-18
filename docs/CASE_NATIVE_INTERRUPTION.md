# Native capture worker interruption

The frozen 0.9.11 candidate passed a native, installed synthetic capture
exercise with injected precommit and postcommit **server-worker interruptions**.
A corrected independent read-only postcheck passed all 25 checks. This
result does not establish service-restart, host-failure or cold-restore recovery.
The earlier native exercise closed its client connection after a durable receipt;
that was a client disconnect, not a worker interruption.

On the authorized Enterprise lab, attempt 2 used the frozen 0.9.11 build
`1795023134` archive (SHA-256
`0a87171ca77fbeedc778844fb326e523f7c427920ea36dcd4fc4cd54cb62bc7e`).
The private fixture payload SHA-256 was
`9c9bb9ccbe71e5f76727a85c02e18102c9d3866f1c216efbc32ef80d51dbfece`.
Preflight verified the host, Enterprise platform, all 88 installed runtime
hashes and native x86-64 execution. A direct root invocation of the embedded
Python 3.13 interpreter used fixed public environment values; its UID, runtime
and SDK path were verified separately. The pidfd preflight opened a handle to
its own process and successfully sent signal zero using the exported libc APIs.

The task-only hook paused each capture immediately before or after SQLite commit.
The fixture durably retained the original body bytes, principal and operation
key before dispatch, verified the checkpoint and worker identity, and sent
SIGKILL through a pidfd to that worker alone. The supervisor retired the owned
worker group and benign descendant. The precommit checkpoint observed no
receipt or new capture; the postcommit checkpoint observed one of each. Exact
retries converged on one receipt and capture and preserved the committed capture
identity. At each checkpoint two source jobs had already been deleted in
the ledger and were absent by native SID; four jobs per phase were accounted
for after retry. The exercise did not interrupt job
creation or deletion, and does not qualify reconciliation of unknown job outcomes.
Permission and synthetic-configuration changes were checked against stored reads,
exports and exact retries; restoring access allowed the original operation again.
A further uninjected capture, selected read and exact retry passed after restoring
the platform startup hook. The fixture's reported cleanup conditions met their expected
values, including retention of no recovery access after successful cleanup. The
separate progress observation recorded both interruption acknowledgements,
phase-retirement records and hook-task removal. The independent postcheck
verified all 34 task-owner source-ledger jobs terminal with their bound native
SIDs absent, both original worker groups and descendants absent, all 88 runtime
hashes, exact original startup source/cache and app-local configuration bytes
and metadata, and removal of the hook task and temporary API resources and
credentials. It checked the three original write receipt digests and matching
owned-delete receipts. Case deletion intentionally clears the protected stored
response snapshots; those payloads are not claimed as retained. The corrected
postcheck summary SHA-256 is
`e7510daaff9265c0d7e130ae6b594798d80d2cc78377838d89eb7a400995933b`;
the native private operation journal SHA-256 is
`9583066338c54ccb6484dcf4d4d51b496a18efefdaceefd2bf4acc18b6832cb5`.
The first read-only checker failed because it assumed the wrong stored action,
projection and post-delete snapshot contract. The corrected checker was tested
against three actual CaseStore create, capture and delete regressions; no fault
was repeated and the original primary result remains unchanged.

The first interruption attempt remains **failed_or_uncertain**: its root-helper
launcher ran as the Splunk UID and refused preparation before a hook was
installed or a case or fault request was dispatched. A separately reviewed
recovery reconciled the exact temporary resources. Its independent read-only
postcheck passed 19 checks, including original startup source and cache bytes and
metadata, absence of the hook task, restored configuration and absent owned
resources. The initial postcheck report counted five runtime files because of a
reporting-variable error; a retained correction records that its comparisons
used the pinned 88-file manifest. The original failure receipt was not changed.

Raw synthetic journals, both attempts and their separate cleanup evidence remain
private outside Git. API resource absence does not prove physical index-data
erasure. The successful exercise is bounded injected evidence, not qualification
of unknown remote job creation/deletion, cleanup after a host crash, real-source
behavior, strict whole-endpoint resource limits, Cloud, SHC or production
readiness. Shipped persistence and capture remain disabled.

Before any live exercise, independently review the task-specific native adapter
and its integration with the authenticated synthetic fixture. The adapter must use an exclusive, private, newly created
staging and control directory; verify the exact installed archive and runtime
hashes, the target, ownership and TLS; and preserve startup source and bytecode
bytes, uid, gid, mode and nanosecond modification time before installing any
hook. The transaction and restoration logic in
`tests/splunk/case_request_native.py` is an existing starting point, but its
fixed Docker-lab paths and guards do not authorize its use on a native host.
The adapter verifies pinned source hashes and stages a task-only adaptation of
`tests/splunk/case_request_fault_hook.py` outside the archive. The hook is
restricted to the exact worker argv and request key. Each key must be
`atlas_intr_` followed by 32 cryptographically random lowercase hex digits.
The fresh-operation receipt check must fail closed on a collision. Record and verify
the derived hook hash. Restore the original startup source and cache even if
installation acknowledgement, fault disablement or the scenario fails; if
restoration cannot be proven, stop and preserve the private recovery material.
Never replace an unexpected source or cache. No app runtime bytes are changed.

For each of two distinct synthetic capture operations, fsync the complete exact
body bytes, principal, method, path and idempotency key in a private directory
before dispatch. Never substitute a new operation when a response is unknown.
An injected checkpoint immediately before SQLite commit must show zero receipts
and zero new captures; one immediately after commit must show one receipt and one
new capture, measured independently before retry. The checkpoint must identify
its worker and a benign descendant. Verify the worker's uid, fixed entrypoint,
PID, session and process group, kernel start time, parent identity and start
time, descendant relationship and start time. The local helper uses a pidfd and
rechecks these identities before signaling only the worker with SIGKILL. It does
not signal a process group. The supervisor must then retire its worker group and
descendant. A disconnect, timeout, missing checkpoint, PID reuse or uncertain
signal is not a passed worker interruption.

Observe each known search job by exact owner and SID in both the capture ledger
and native API. Require terminal/deleted ledger state and native API absence;
do not claim unknown creation/deletion recovery. After each fault, disable the
hook, retry the exact original operation, and verify one receipt, one capture,
the same committed identity after the postcommit case, and recovery access.
Exercise current source permission and configuration changes against stored
reads, exports and exact retry; verify redaction, restoration and subsequent
access. Run an uninjected positive capture after verified hook restoration.

Cleanup must use the exact task-owned resource identities and independently
verify their absence and original configuration restoration. Preserve audit,
retry and ledger history, private journals, and unresolved resources if recovery
is uncertain. Record primary scenario, restoration, cleanup and independent
postcheck separately. API absence is not proof of physical index-data erasure.
A live run also requires the coordinating owner to serialize access and obtain
independent prelaunch clearance. No credentials belong in arguments, prompts,
logs or the repository. Use the approved pinned SSH and verified TLS paths.

## Adapter contract

Invoke the adapter using Splunk's embedded Python on the verified native target;
the surrounding fixture passes the checked-in helper and hook source bytes, and
must verify the adapter's own bytes before execution. `prepare_native_hook`
creates the new fixed `/opt/splunk/var/atlas-interruption-20261118` task root as
root. It refuses a preexisting root; stage and control are private to the
Splunk uid, and the backup is root-owned. `native_hook_action` exposes install
and restore as root and arm, observe and disable as the Splunk uid. Install
writes the original-source/cache transaction durably before any platform file
is changed. `installed_native_hook` attempts both disable and guarded restore,
including after an uncertain install or failed disable, and preserves the
primary error with cleanup uncertainty attached. A missing transaction on an
unknown installation is not restoration proof.

The synthetic fixture supplies `run_capture_phase` with an operation containing
exact `principal`, `method`, `path`, `key` and byte-valued `body`, a fresh
mode-0700 journal directory outside the checkout, and an `io` object. Its
callbacks are `arm(mode, operation)`, `dispatch(operation)`,
`observe(mode, operation)`, `interrupt(marker)`, `wait_retired(marker)`,
`inspect(operation)`, `disable(operation)`, `retry(operation)`, and
`check_access(operation, capture_id)`. Dispatch and retry must use the original
bytes, principal, path and key. The scaffold's interrupt callback must call
`interrupt_checkpoint` with independently collected expected worker, parent and
child start times and uid, plus the independently approved supervisor argv digest;
checkpoint authenticates the private config and
marker before using the pidfd. No callback should log credentials.

`inspect` obtains independent read-only SQLite and native API observations;
it returns `receipt_count`, the entire case's `capture_count`, `receipt_digest`,
`capture_id`, and `new_jobs`. Each new job has its exact `sid`, ledger `state`
and `native_absent` boolean from a separately authenticated native API check.
The callback must compare against a job inventory captured before dispatch, use
only the exact owned principal, and fail on a truncated or uncertain response.
The `wait_retired` result must separately establish worker, group and child
absence, accounting for PID/start-time reuse. The access callback must perform
the checks named by the return keys in `run_capture_phase`, including exact
retry after both permission and configuration changes. These callbacks are
part of the safety boundary and require review with the scaffold; the local
coordinator cannot prove that a callback's boolean is backed by an observation.
The coordinator runs one phase at a time and requires two distinct operation
identities and journal directories for precommit and postcommit. Its successful
return does not establish hook restoration, final uninjected positive capture,
resource cleanup or independent postcheck; record each separately.
