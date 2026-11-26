# Case request supervision

Case notes requests execute in a fresh supervised Linux child. The parent keeps
the authenticated persistent-handler registration, native Web CSRF protections
and fixed worker entrypoint. Caller authentication and every entitlement recheck
remain inside the child, alongside configuration/topology reads, SQLite work and
response construction. No authorization result or session is cached across requests.

The **40-second operational budget** starts when the persistent handler receives
the request envelope. It covers elapsed worker startup, execution and pipe I/O;
an overrun detected after launch returns is refused. Retirement has a separate
one-second allowance. Synchronous process creation, filesystem/kernel stalls,
operating-system scheduling and the surrounding Splunk Web/delivery layer are
not hard real-time guarantees. This is not complete CPU/memory or production
endpoint qualification. See the performed results in
[feature qualification](FEATURE_QUALIFICATION.json).

## Admission and process lifetime

A module-wide pool of three worker slots (`MAX_CONCURRENT`) admits concurrent
case requests from different users, so one slow request no longer refuses every
other caller. Busy admission returns a generic 503 without starting another
worker. There is no unbounded queue. Each worker keeps its own one-job capture
admission, and the durable capture ledger's global three-slot quota still bounds
concurrent captures across all workers and persistent-handler processes.

The parent requires Linux child-subreaper support and verifies that process-local
setting before launch. Unsupported platforms or unavailable setup fail closed.
The Mac development host exercises this server code in its Linux container;
Darwin-skipped process tests are not counted as Linux evidence.

Each worker starts a new session. It verifies that its PID is also its session
and process-group ID before reading credentials, and disables core dumps. The
parent also disables its core dumps. A held worker leader pins the process-group
ID after emitting a complete response frame. A 42-second worker watchdog remains
alive until retirement, including when the parent disappears after receiving a
frame. This does not make interpreter startup or uninterruptible kernel work
independently bounded.

The parent sends TERM and then KILL to the owned group **before** reaping its
leader. It subsequently reaps only descendants in that group and verifies group
absence. It sends no later mutating group signal after the leader is reaped.
A request whose retirement fails or is uncertain keeps its slot. Each later
admission first re-checks those groups for 0.2 seconds each: it signals a group
only if its leader is still unreaped, otherwise it only reaps descendants and
probes for absence. Worker launches, leader reaping and those probes share one
lock, and a probed PGID now held by an unreaped worker leader is treated as proof
that the old group is gone, so a recycled PGID is never reaped or signalled on
behalf of a different request. A group proven gone releases its slot. At most three
unretired groups can therefore exist per handler process, and admission closes
only while all three slots are held. If it stays closed, investigate and restart
the affected handler through the platform's supported procedure. Deleting case
data or the capture ledger is not a recovery action.

## Data and authority boundaries

- Raw persistent-handler envelopes are bounded to 1 MiB before launching work;
  the existing 128,000-byte application body limit remains inside the authenticated
  adapter. Early oversized-envelope rejection discloses no stored data.
- Worker output is a bounded 2 MiB length-prefixed JSON response. Malformed,
  oversized, truncated, timed-out or unretired work yields a generic unavailable
  result. No raw child diagnostics, tokens or configuration contents are returned.
- Session credentials travel only through the child's stdin. Command arguments
  are fixed; the environment contains only public runtime settings needed by the
  embedded interpreter and fixed Splunk home/database paths. Caller loader paths,
  `PYTHONPATH`, proxy settings and credentials are not inherited.
- The SHC safety check reads only the global effective `shclustering` stanza
  through the absolute `$SPLUNK_HOME/bin/splunk btool server list shclustering`
  command, with a three-second subprocess timeout and a 16 KiB output cap. It
  fails closed when the output is missing, malformed, too large or ambiguous.
- Child response headers are restricted to the existing no-store, JSON and
  no-sniff values. Authentication, capability checks, private membership, current
  revocation and source-authorized reads/retries are not replaced by the supervisor.
- Source-helper CPU/address-space limits and its native request/recovery contract
  remain unchanged. Positive current source capture and native AMD64 resource
  enforcement are separate qualifications; this work does not enable them.

Case lists retain their `items`/`next` shape but may return fewer than the requested
count to keep the complete compact ASCII JSON page within **1,500,000 bytes**.
The continuation cursor is the last returned case; the first over-budget eligible
case remains available on the next page. Clients must follow `next`, including
after a short page. The existing Cases UI already does so. The trusted standalone
store library may return one oversized first item when custom case-size settings
exceed that budget; the HTTP host uses its unchanged 1,000,000-byte case limit.
Default single-case reads/exports and bounded audit pages fit the response frame.

SQLite connection setup now closes a newly opened connection when initialization
fails. Normal store transactions already close their connections. Test fixtures
using SQLite's transaction-only context manager were corrected to close their
connections too; warning suppression is not used as evidence of cleanup.

## Unknown writes and retries

A deadline, disconnect or unavailable response does not prove that a mutation
failed. The transaction may have committed before response delivery. Preserve
the exact idempotency key, body and expected revision, then retry that same
operation after access/service recovery. Existing current-authorization checks
still apply to its stored receipt. Do not create a replacement operation merely
because the client lost its response. The browser's pending state remains
memory-only; navigation can discard it.

## Disposable installed rehearsal

`tools/rehearse_case_requests.py --run` uses the exact task
`cases-requests-20261118`, namespace `adm-cases-requests-20261118`, ports
34900/34989/34988 and a new private external runtime directory. It retains the
exact validated candidate archive and holds the same parent lab lock through
creation, installation, evidence and purge. The existing task framework supplies
4 CPUs, 8 GiB memory with no extra swap, 1,024 processes and bounded logs. The
task declares a 45-minute execution lifetime plus bounded cleanup, a 12 GiB host
disk reserve and cooperative 4 GiB named-volume checks. Disk checks exclude image
cache, writable layers and logs and are not filesystem quotas. Peer memory
admission uses actual bytes plus a 10 GiB reserve, not container percentages.

The installed fixture runs real SDK authentication and notes operations before
and after fault tests. A task-only platform `sitecustomize` extension preserves
the original startup code and cache, is restricted to the exact request-worker
argv, and is never included in the app package. Its private controls inject SDK
authentication/configuration stalls and pauses immediately before/after an actual
SQLite commit. A benign
same-group child ignores TERM to exercise KILL and descendant reaping. A client
disconnect is triggered only after a durable-commit marker. Exact retries must
converge on one case and one receipt, and native process observations must prove
retirement. Response, observed retirement and reconciliation times are separate.

Original startup source/cache bytes and metadata are retained in a root-owned
transaction before mutation. Ownership, source hashes and cache headers guard
restoration of that exact original state before the final uninjected positive run.
If the final restoration acknowledgement is lost, the rehearsal records failure
or uncertainty and purges only its verified owned container; it does not claim
that a repeated hook-removal call is an idempotent success.
These fault results are **injected boundary evidence**, not proof of all possible
native OS failures. Captures stay disabled; fixture users have only the investigator
capability and no searchable indexes. Users/role and saved flags are checked before
purge. Raw synthetic journals and diagnostics remain private outside Git.

Permanent Enterprise/Cloud targets, shared forwarders and global trust are outside
this rehearsal. Shipped persistence/capture/watch/schedule gates remain disabled.
Cloud/SHC, real sources, strict whole-endpoint resources, cross-build recovery and
production readiness remain unqualified. Rollback preserves databases, original
retry identities and unresolved ledgers; no data reset is authorized.
