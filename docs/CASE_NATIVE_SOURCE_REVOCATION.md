# Non-admin real-source revocation exercise

A bounded **case-only non-admin real-source revocation exercise passed** on the
native x86_64 Splunk Enterprise 10.6.0.5 lab with the installed Atlas 0.9.11
build. An independently checked temporary investigator used the exact exclusive
role and historical source selection below. The case retained a note and one
real comparison. Selected reads, exports and the exact original capture retry
were visible before source permission narrowing, withheld while narrowed, and
visible after restoration; the note remained unchanged throughout.

The case-only run did **not** perform the separate selected-source or
out-of-scope count controls. Their absence is recorded as `not_run`, and those
negative controls and broader filter coverage remain unqualified. Earlier
failed attempts and their separately verified cleanup remain part of the record.
No application runtime change was made for this exercise.

## Eligibility and source boundary

The driver requires the actual current caller context to name the already
prepared investigator and exactly one role, with effective and role capabilities limited
to `search` and `adm_investigate`, no imported roles, and no administrative or
role/user-edit privileges. An administrator cannot be the investigator. A
complete, bounded administrator-visible inventory must establish that the role
is assigned to that investigator alone; a shared or incompletely enumerated
role is refused. This is a deliberately restrictive contract, so a legitimate
account with extra benign capabilities or multiple roles may not qualify. No
role membership, capability, index grant or other account is changed by this
driver. The authorized temporary role grants exactly the two index/source/type
triples `atlas_identity` / `atlas:identity:uktme` / `adm:pod_ip_interval:v2`
and `otel_traces` / `atlas:k8s:uktme:tenant-jobs` / `otel:traces`, restricted to
`1794844500 <= _time < 1794844620`; default indexes and imported roles are empty.
The optional count-control lifecycle is separate from the case-only exercise.
It is intended to test selected sources and other sources, indices and times with
bounded independent controls when data exists; its coverage was not established
by the passing case-only run.
A zero or unavailable administrator control leaves that negative case unqualified;
user zero is not proof of denial when the administrator also observes zero. A
source failure or an uncertain search job remains a failure. Do not widen the
grant or manufacture data to force a pass.

The exact retained real-source candidate is `coreapi` in `tenant-jobs`, lab
cluster `k8s-01.uktme.cisco.com`, 2026-11-16 15:55–15:56 and 15:56–15:57 UTC.
The source profile bytes, stored comparison digest and configuration fingerprint
must match the previously qualified values recorded in
[real-source qualification](CASE_REAL_SOURCE_QUALIFICATION.md). A caller-visible
selected capture and original retry must first reproduce that evidence. Retained
warnings and unknown source loss still apply; this test cannot establish source
completeness or production readiness. If the historical data has expired or the
source/profile changed, refuse and qualify a new source separately; do not weaken
these checks.

## Reviewed lifecycle

The coordinating lifecycle must verify the target, frozen 0.9.11 archive and
installed hashes, exact service user, trusted TLS and source history. Before
creating the unassigned role, it snapshots the relevant authorization layers,
original role definitions and memberships, and the system-local configuration
file's bytes, UID, GID, mode and nanosecond modification time. It then proves
that only the system-local layer changed when the role was created, and repeats
the layer proof after capability narrowing, before creating the user. It
independently compares the original state after the exercise. A successful
API restore alone does not prove byte-for-byte file restoration; do not overwrite
a shared file to force a match, and report any difference as unresolved. It creates
a new private mode-0700 `/opt/splunk/var/atlas-real-revocation-20261118` stage,
then creates the uniquely named, collision-checked temporary user and exact role
and uses the reviewed `qualify_native_real_source.py` primitive and that actual
investigator to prepare a task-owned case with a note, one saved real
comparison and the private durable original capture operation in `requests/`.
It must retain the exact operation bytes, key, principal and response. The
primitive and this driver must be loaded as reviewed bytes in the native isolated
Python process; the surrounding process supplies the investigator's username,
password and authenticated token plus the administrator token only on stdin.
No credential belongs in a command argument, journal, repository or chat.

`tools/qualify_native_source_revocation.py --installed` reads one bounded JSON
object on stdin with `principal`, `password`, `user_token`, `admin_token`, `role`,
`case_id`, `capture_id` and `original_operation`. Missing inputs fail closed.
It verifies the loopback TLS connections and server GUID/version for both
callers, rejects administrator investigators and checks the eligibility above.
The unchanged supervised transport handles identity and case operations. A
separate test-only, pinned-loopback TLS adapter permits only GET for the exact
role and bounded user inventory and POST of its `srchFilter`; it accepts no
other role change or endpoint. Its request deadline and 1 MiB response cap do
not change the shipped runtime transport allowlist. The outer lifecycle must
serialize the whole exercise with other operators: inventory and configuration
checks cannot atomically prevent a concurrent role assignment or change.

The driver privately records the full original role definition, caller context,
original operation identity and source profile before mutation. The installed
case-only failure showed that `last_successful_login` changed during repeated
authentication while the caller's identity, roles and capabilities remained
unchanged. The fixture compares that field as a present, nonnegative integer but
excludes its value from context equality; it compares every other context field
exactly and records both raw contexts and the exclusion reason privately. This
fixture rule does not change the application's runtime authorization checks. Its only proposed
role change adds a `NOT source="atlas:k8s:uktme:tenant-jobs"` restriction to
the existing source filter; it does not remove index grants or change other
fields. It verifies the expected role definition after the change. Selected
stored reads, selected exports and the exact original capture retry must show
visible evidence before narrowing, withhold it during narrowing, and show it
after exact restoration. The same notes must remain present and unchanged in
all three phases; caller identity, effective capabilities and exclusive role
membership are checked throughout. Original response loss, failure to prove
redaction or unexpected source data cannot pass.

Restoration is attempted independently after a failed or uncertain primary
operation, including a lost role-change acknowledgement. It restores the
original filter only if the current role is exactly the original or the one
reviewed narrowed value and the investigator context and exclusive membership
remain unchanged; a concurrent or unrecognized change is preserved and reported
uncertain rather than overwritten. Journal failures cannot prevent an otherwise
safe restoration attempt, but they prevent a passing result. Compare the full
original role definition after restore and retain the private journal, case
history and original operation. If restoration or role/user state cannot be
proven, preserve recovery access and coordinate exact remediation; do not assume
success or issue a replacement capture. The fixture's success is not cleanup:
the outer lifecycle must independently check exact case and job ownership,
restore any task configuration, and remove only owned temporary resources with
separate evidence. API absence does not establish physical erasure.

## Installed evidence and limits

The passing case-only attempt used the separate private stage
`/opt/splunk/var/atlas-real-revocation-20261118-case-only-attempt2` and
reproduced the previously retained comparison
digest `3f749c656afab7c0a56369437226c88e4e2cc397c9b1b49a7050685d73bf31e8`
and configuration fingerprint
`23337b1eb5770878cf5098f123ca7db4d3af4bebb6b213470e43a1ca91db4341`
for the two selected windows. Its independent postcheck passed 28 checks,
including all nine selected read/export/original-retry operations, unchanged
notes, six recorded context comparisons, case receipts and deletion tombstones,
exact restoration of authorization layers and application configuration, and
removal of the temporary account, role and credential. Seventeen bound source
jobs were terminal and absent on exact administrator reads. Count-control jobs
were not run. The retained private outputs are:

- `revocation-case-only-attempt2-installed-output.json`: SHA-256
  `a415ff5e76cd71b3376c9ff46ea59f149667e7e0458984fa82b74109230a434b`.
- `revocation-case-only-attempt2-postcheck.json`: SHA-256
  `dad0f350686b808d28881e520b7b56c45bb6d2940a221a1b60f4db19a78495ac`.

These files are retained under the private `atlas-uncertain-outcomes` evidence
directory, not as customer rows in this repository. The first case-only run
remains failed: its original capture and allowed read/export/retry succeeded,
but the fixture's whole-context comparison rejected a changed login timestamp
before any source-role mutation. Its separately reviewed exact-owned recovery
and independent 18-check postcheck restored authority and authorization files,
removed the temporary resources, and retained the failed primary unchanged.
The original failed result, context differential and recovery postcheck are
retained as `revocation-case-only-installed-output.json`,
`revocation-case-context-diff-fixed.json`, and
`revocation-case-cleanup-postcheck.json` respectively.

Earlier setup and count-control attempts also remain failed or incomplete. A
role creation initially received native default capabilities; the subsequently
reviewed workflow narrowed the unassigned role and verified the exact two
capabilities before user creation. The count fixture later encountered an INFO
message about a substituted time range. A separate bounded diagnostic observed
336 identity events, the same known INFO message, and matching effective and
search-command bounds for that selected window. A later, separate single-task
count diagnostic observed HTTP 200, a completed native job and a count of 336
for that same bounded identity selection. Its count validator failed with
`native count incomplete`: the validator first requires empty job-content
messages, and the observed job content included the native INFO message. It
therefore did not reach its later INFO and time checks. The projected
`resultIsTruncated` value was unavailable or otherwise unclassified and does not
establish an additional blocker. The diagnostic's independent postcheck passed
18 checks for its observation and cleanup; it did not pass the count validator.
Its private `counter-independent-postcheck.json` has SHA-256
`1d0bf036d609c334b2c449a2fde2e7b7349b628199f7e9ec2469f5da90be513a`.

A subsequent fixture-only change applies the exact observed INFO rule consistently
at the job, job-content and results message locations, after the native identity,
completion, truncation and effective-window checks. Unknown or malformed messages
still fail. This fixture change does not alter the application's native capture
message policy.

A separate installed count-only matrix passed with nine validated native jobs;
its independent postcheck passed all 19 checks, including exact job retirement,
proof replay and restoration of the temporary account and configuration. For the
selected historical window, the administrator and temporary investigator each
observed 336 identity events and 258 spans. With positive administrator
comparators, an outside-window identity query returned 9,856 versus zero to the
restricted investigator, and an `_internal` index query returned 2,301 versus
zero. These are bounded controls for the exact account, queries and time ranges,
not general proof of access isolation. The alternate span-source administrator
count was zero, so the investigator query was not run and that control remains
unavailable. Count controls were separate from the earlier passing case-only
exercise and do not establish source population completeness or loss bounds.

The private `count-matrix-installed-output.json` has SHA-256
`5e711e8225709a786d4c1efee3f688e77b511435351934b52a089abbc5e64c0b`, and
`count-matrix-independent-postcheck.json` has SHA-256
`000e9e6ced1c596c208f92f8191e3e6a65a2e5018760ca766fb2c12e3f8f13a5`.
No warning was generalized into permission to ignore other messages.

The retained historical graph evidence included excluded-span warnings of 87
and 90 for the two windows and no network/ACI path. Collector loss, lateness and
source completeness are not established. This exercise does not qualify
Web/CSRF, an arbitrary non-admin role topology, all sources, complete source
coverage, Cloud/SHC or production operation.
