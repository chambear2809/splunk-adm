# Native service restart during capture

The third attempt passed an installed native synthetic capture exercise with
one service restart at each of the precommit and postcommit checkpoints. An
independent read-only postcheck subsequently passed all 29 checks, including a
fresh check of the admin authority used for job-absence observations. This is
bounded injected evidence; it does not establish host-failure or cold-restore
recovery. The separate earlier exercises interrupted a request worker with a
pidfd SIGKILL or disconnected the client after commit; neither was a service
restart.

On the authorized standalone Enterprise 10.6.0.5 lab, the task used the frozen
0.9.11 build `1795023134` archive (SHA-256
`0a87171ca77fbeedc778844fb326e523f7c427920ea36dcd4fc4cd54cb62bc7e`).
The successful private fixture payload SHA-256 was
`c0393b0b4631884648dd1baa61a43c8b0aaa88e173a9d9c7896e40f219290f77`.
The fixed standalone Splunk CLI was launched at each held checkpoint. The
worker was observed live immediately after command launch; the service returned
with a new systemd invocation and daemon identity, and the old request worker,
its descendant and group were absent. The normal request-supervisor deadline
could also retire the worker, so this observation does not by itself prove that
the service restart caused the worker's termination.

Before dispatch, each original capture's principal, exact body bytes, path,
idempotency key and expected revision were retained durably. The precommit
checkpoint had zero receipts and captures before the restart; the exact retry
converged on one of each. The postcommit checkpoint had one receipt and one
capture, and the exact retry preserved both the receipt digest and capture
identity. At each checkpoint the known source jobs had already been deleted;
retries, current source-permission and configuration revocation/restoration, and
a final uninjected capture after hook restoration passed. No unknown remote
job-creation or deletion outcome was exercised.

The independent postcheck verified the two restart and retirement records,
new service and handler identities, all 34 retained source-ledger jobs terminal
with their native SIDs absent, all 88 installed runtime hashes, and original
startup source/cache and app-local configuration bytes and metadata. It also
verified the three original capture receipt digests and their owned-delete
receipts, absence of the task hook and temporary resources/credentials, and
restored disabled capture/persistence. Deleting the cases intentionally clears
the protected stored response snapshots; the payloads are not claimed retained.
The postcheck result SHA-256 is
`0d51dbc063b0abd6ed62a1bda1c8b0adca09e605126ad07f293f6d5e224bd564`;
the private native journal SHA-256 is
`c19e9bf3704226293d142729fca91436ad8bcd0403683a593bc0fa3404371ed6`.
API absence is not evidence of physical index-data erasure.

The first attempt remains **failed_or_uncertain**: a preflight rejected a
mismatch between displayed unit/boot evidence and the bytes hashed by the
fixture, before any task resources, hook or restart. Read-only postcheck
confirmed the service identity and original settings remained unchanged. The
second attempt also remains **failed_or_uncertain**: one precommit restart was
verified and its worker retired, but new-handler discovery scanned PID 1 and
failed before completing the scenario. A separate read-only postcheck verified
cleanup and 14 terminal source jobs with native SIDs absent. The PID scan was
corrected and independently reviewed for the third attempt; neither failed
receipt was rewritten. All synthetic journals and failure evidence remain
private outside Git.

The native fixture uses the reviewed, temporary synthetic-only
capture setup on the authorized standalone Enterprise lab: collision-checked
fixture users and roles, only `search` and `adm_investigate`, bounded task-owned
indexes and a temporary HEC input. It uses the frozen 0.9.11 build `1795023134`
archive (SHA-256
`0a87171ca77fbeedc778844fb326e523f7c427920ea36dcd4fc4cd54cb62bc7e`),
with the original app configuration and startup source/cache preserved for
guarded restoration. It grants no access to real sources and changes no AWS,
Kubernetes or host infrastructure. Synthetic journals, temporary credentials
and task recovery state stay in private directories outside Git.

Each distinct precommit and postcommit operation must retain its exact body
bytes, principal, path, idempotency key and expected revision durably before
dispatch. A test-only hook outside the archive pauses the actual capture
worker at the SQLite commit boundary. Before issuing each of two separately recorded restarts, the fixture
checks receipt and capture cardinality, the known source jobs and their exact
native SIDs, the worker, its handler and benign descendant, and membership in
the attested service cgroup. It writes and syncs a restart intent with process
identities before dispatch. The signal-free restart operation is the fixed
standalone systemd-aware `sudo -n /opt/splunk/bin/splunk restart` CLI, as
specified by the reviewed operator restart workflow. It never sends a signal
to a process, retries an uncertain restart, force-starts the service or uses a
REST restart fallback. The fixture records whether the held worker is still live immediately after the
restart command launches; if not, it refuses to count the phase. The request
supervisor has its own deadline, so worker retirement after launch alone does
not prove the service restart caused it. Restart timeout, partial shutdown, missing identity,
failed readiness or an unknown operation is a failed or uncertain outcome;
retain the original request and task-owned recovery resources for investigation.

A successful phase requires the CLI to finish successfully, the same service
unit and cgroup to be active with a different systemd invocation and daemon
PID/start identity, the prior daemon to be absent, trusted management and HEC
TLS/readiness, and the original worker group and descendant to retire. A
post-recovery request must also establish a new authenticated handler process
identity in that service. It then retries the unchanged operation under current
permissions, reconciles exact receipt/capture cardinality and identities, and
checks stored reads, exports and retries across temporary source-permission and
configuration changes. Known search jobs must be terminal in the ledger and
absent by exact native SID. Jobs were already deleted at the chosen commit
checkpoint in the earlier worker exercise; this design does not assert recovery
from an unknown remote job creation or deletion.

The restart task keeps source/cache restoration independent of management REST.
It does not delete cases, users, roles, indexes or recovery credentials when a
restart, request, hook restoration or worker retirement remains unresolved.
Original app configuration is restored independently per file even on failure;
if management is unavailable, reload and effective-state confirmation remain
uncertain. A fresh uninjected capture and exact retry after hook restoration,
verified owned-resource cleanup, and an independent read-only postcheck are
separate acceptance gates. API absence is not physical data erasure. Audit,
retry and ledger history remain intact.

`tools/qualify_native_service_restart.py` implements the fixed CLI and a
callback-based checkpoint/restart contract. The private synthetic scaffold
supplies authenticated requests, durable journals, exact service and process
observations, verified TLS and cleanup. The read-only native inventory attested `Splunkd.service`, its unit-file hash,
`/system.slice/Splunkd.service`, daemon executable and the parent-handler argv.
The fixture pins those identities and the host boot ID but observes new PIDs,
start times and service invocation IDs for each phase. The systemd stop timeout
is six minutes; each CLI wait is bounded to 390 seconds, followed by a separate
readiness allowance. A timed-out command is left alone and requires an operator
handoff. The coordinating owner serializes all host activity and
obtains independent prelaunch review; the implementation itself is not
permission to execute. Shipped capture and persistence remain disabled. Cloud,
SHC, real-source behavior and production readiness are not established.
