# Final candidate distributed qualification

Status (2026-10-18): corrected tooling and native platform bootstrap diagnostics
are recorded; no final-candidate application qualification pass is claimed.
Attempt05 used source
`50e098a602a21ef386172015aa2ed888b936efd4` and candidate08 archive SHA-256
`946ff4806917bda093659328811b05c348251a9197e3b61244b0902254a9b4b6`.
Its bootstrap and strict three-member KV/PDL readiness passed; bundle verification
failed on the generated `install_source_checksum` field described below. The
original failed phase remains recorded; no application checks are relabeled as
passed. A corrected harness requires a separately recorded fresh lifecycle with
the same unchanged candidate archive.
The earlier results in `SHC_QUALIFICATION.md` remain bound to their original
archives. A passing offline harness test is not a live platform qualification
result.

The accepted base for this work is
`64473e54d1fca4311ac592bc34c4a96a022efd48`. The coordinator records the final
source revision, test hashes, archive checksum, commands, UTC timestamps and
actual outcomes in the new run's external evidence directory. Retain the exact
archive. Subsequent executable/configuration changes require the applicable
acceptance checks against the new archive; selected reruns do not become a
complete installed-suite result.

## Target and ownership

The authorized disposable qualification host is EC2
`i-0b186b390ea7ff8dc` in `us-east-1`, named
`splunk106-validation-20261007`. Authentication follows the existing `duo-sso`
workflow. SSH host-key verification stays enabled. No AWS infrastructure changes
are required. The host is ephemeral, but the new harness still identifies every
resource by full Docker ID, exact task name and task label before lifecycle
operations. It never uses a global prune, image removal, wildcard deletion or
container name alone.

The coordinator owns a single host-level exclusive lock throughout preparation,
startup, installation, seeding, checks, failure investigation and cleanup.
Standalone and SHC runs use the same lock path and execute sequentially. Use
`Lab.locked()` from `tools/qualification_shc_lab.py` inside one reviewed external
Python driver; do not compose independently locked per-phase invocations. The
worker does not operate remote lifecycle actions.

Create one fresh task identity matching `adm-shc-<suffix>`. State, credentials,
private CA, certificate keys, staged data and logs live in a fresh owner-only
directory outside the repository. The lifecycle helper refuses a preexisting
task directory. Secrets are generated there; Docker uses an external env file,
CLI login receives input through stdin, and REST authentication is created in
memory from protected files. Never print Docker environment inspection, server
configuration containing secrets, authentication responses or raw exception
bodies into evidence.

## Exercised topology and limits

Use three search heads, a separate deployer and one separate search/indexing
peer on the same 8-vCPU/32-GiB host. Pin every container to:

```text
splunk/splunk@sha256:9280f9ce267b212e5596aa1832cdfd3f9be886c378da35ebc87499323ee447a4
```

Verify `/services/server/info` reports Enterprise `10.6.0.5` and the expected
task-specific server name for each role. Give each member and the peer 4 GiB/2
CPU limits, and the deployer 2 GiB/1 CPU. The default SHC port range is
22000–22049, bound only to loopback, separate from the standalone lab's
18000/18088/18089 ports. Use SHC replication factor 3 and observe the platform's
actual cohosted KV/PDL status without replacing its cluster identity or lowering
readiness requirements.

All management clients require the private CA and certificate hostname match;
certificates include the role's internal task hostname and localhost. The client
disables proxies and redirects. Search peer trust/configuration must also be
checked on the actual platform. Summary forwarding uses task-network TCP 9997;
it is not evidence of production end-to-end TLS. The lab has no independent
machine failure domains, production sizing, load balancer, SSO, indexer cluster
or multisite deployment. It establishes bounded app functionality only and does
not satisfy the supported production SHC topology requirement of a separate
machine/VM per member.

The platform's inherited internal sidecar TLS settings are a separate boundary
from the harness's strict management/CLI checks. Attempt04's native Patroni log
records disabled Etcd certificate verification. The harness does not replace
those platform-managed sidecar settings, and the run does not qualify internal
sidecar trust or end-to-end TLS for a production deployment.

## Coordinator execution sequence

`tools/qualification_shc_run.py` provides the reviewed phase driver. Import
`Driver` into the coordinator's already locked process with the same `Lab`
object, or launch its explicit `--apply --interactive` command loop on the
qualification host:

```bash
python3 tools/qualification_shc_run.py --apply --interactive \
  --source /reviewed/source --archive /external/exact-candidate.tar.gz \
  --source-sha <full-final-source-sha> --directory /external/new-private-task \
  --task adm-shc-<unique-suffix> \
  --addon-root /reviewed/extracted/TA_cisco_catalyst \
  --addon-root /reviewed/extracted/other-required-addon
```

Pass every required reviewed add-on root; the paths above illustrate the input
shape. Python 3.12 is the target driver runtime. The process accepts one JSON
command per line: `{"phase":"prepare"}`, `{"action":"inspect"}`, and then
the remaining phases listed by its startup message. Each phase is separately
invoked and recorded while the same process holds the same host lock. A failed
phase preserves containers, files and diagnostics and leaves the loop available.
Use `{"phase":"name","rerun":true}` only after inspection/repair; rerunning a
completed earlier phase invalidates its later acceptance phases. Ingestion
records are marked before POST, so uncertain HEC outcomes require explicit
inspection and do not silently resend. `quit` requires task cleanup first.

The driver runs the two original interface tests programmatically and exports
their real per-member SIDs, counts, failures and skips. It checks the independent
base ACI semantic contract and full all-member graph equality. Optionally pass
`--reference-graph /external/standalone-graph.json`, containing
`{"archive_sha256":"...","rows":[...]}`, to additionally require exact
standalone equality for the same package. Without that file, its evidence
explicitly reports semantic/all-member equality only.

The separate `topology` phase follows `graph`. It runs the actual base-search
`adm_topology` macro on each member over the independently declared ACI topology
window. It requires the fixture's six identified devices with their management
addresses/ACI roles and eleven exact fabric/host links, complete count metadata,
and no warnings. Full returned rows must agree across members, excluding only
`generated_at`. Per-member rows, window, archive hash and search SID are retained
even when a semantic assertion fails. Viewer access and deployer reapplication
repeat this topology check against the initial administrator capture. This is
V1 ACI/networking fixture evidence; it does not establish V2 topology cutover,
other source combinations, Cloud or production scale.

The `v2` phase then seeds exact standard-NetFlow exporter profiles and one
`demo-cluster` Cilium settings row, using the base fixture's SNAT/dedicated
Ingress/BGP assumptions. It preserves the original observer-scope rows and all
V1 public selectors. The two shipped V2 writers run manually through different
members over the original closed indexed-receipt slice into `adm_summary_v2`;
their original disabled/schedule states are restored. Dispatch SIDs are
journaled before waiting; an uncertain dispatch is never silently repeated.

Explicit `adm_graph_v2` reads must contain the fixture's service owners, all
raw trace spans, its trace-backed service call and the same-node
frontend-b → checkout Hubble/Isovalent/span witness from the independent ACI
oracle. These witnesses have no NetFlow wire record. NetFlow is absent from V2
conversation source evidence. Every original raw NetFlow tuple and raw counter
instead appears exactly once in separate traffic-observation summaries with
`counter_semantics=unknown`, `metrics_authoritative=0`, and the exact exporter,
scope, cluster and absent-domain profile. No client-history record exists in
this fixture, so V2 must not invent a network-client graph attachment.

Explicit `adm_topology_v2` reads require the raw scenario's six authority-keyed
ACI devices and three native-UID-keyed Kubernetes hosts. The existing APIC scope
row has no cluster: ACI inventory must remain visibly unmapped, and unsupported
physical links must remain absent. The Kubernetes hosts remain mapped to the
known scope/cluster. Missing Catalyst history, unqualified inventory and
unsupported Nexus Dashboard fabric correlation diagnostics are required and
retained; they are not suppressed to obtain a clean result. This tests the
conservative staged boundary, not mapped ACI adjacency or additional source
combinations.

V2 graph, topology and summary results must agree across all members and with
the least-privileged viewer, and repeat unchanged after bundle reapplication.
V1 graph/topology and every actual cutover selector are compared before/after.
The optional same-archive reference file can additionally contain both
`v2_graph_rows` and `v2_topology_rows` for exact standalone parity. Without
these fields the result explicitly reports independent fixture invariants and
all-member parity only. Actual recovery/migration qualifiers must still refuse
SHC. No SHC cutover, rollback, operational failover, browser qualification or
Cloud support follows from these staged reads; full V2 activation/rollback is
qualified separately on the owned standalone instance.

The scheduler phase derives a current probe from the shipped raw NetFlow
fixture. It records its predicted production `rollup_id`, requires absence
before the eligible real five-minute slot, then requires the corresponding
actual scheduler success and one summary with `records=1`, `bytes_c2s=900`.
It restores the prior schedule flags afterward. The driver does not perform
captain failure injection, browser automation or Cloud operations; those gates
need separately recorded coordinator checks where required. Attempt04 established
the native bootstrap/status response shapes during diagnosis; packaged endpoint
behavior and the complete acceptance sequence still require the fresh exact
candidate run. Do not relabel diagnostics or driver implementation as an
application qualification pass.

After the `cleanup` phase, rerun `manifest` to include cleanup evidence before
export. Inspect unsuccessful phases separately; `cleanup` is allowed after a
failure and does not mark other phases passed. No automatic error cleanup
removes diagnostics.

The lifecycle API is intentionally small and must be reviewed before execution.
`prepare(source_root, archive, source_sha=...)` records package/test hashes and
creates external secrets/PKI. `create()` registers each container ID before any
later action can fail. `install_support(source_root, addon_roots)` copies only
reviewed add-on configuration, CSV data and metadata; it never copies vendor
inputs or scripts. The indexing peer receives its index-time definitions before
first startup, preventing the previous run's corrective reingestion issue.
`install_candidate()` stages the exact candidate under the deployer's
`etc/shcluster/apps/`. Start the five roles, verify certificate/identity and
wait for management readiness before authenticated captain bootstrap.

`bootstrap()` uses a local Splunk CLI session, then the actual
`bootstrap shcluster-captain` command with the global `--answer-yes` flag.
`apply_bundle()` uses that same double-hyphen spelling; the single-hyphen
`-answer-yes` is rejected by the pinned CLI parser. Preserve failures and stop
for coordinator diagnosis. No automatic KV reset, second restart or readiness
override is performed.

The initial fresh harness attempt completed create/support, then all five
containers exited with code 2 during Ansible's version fact. The reported
missing `/opt/splunk/etc/splunk.version` was a traversal failure: the genuine
pinned-image file already existed, mode 0444, owned by UID/GID 41812, and
declared Enterprise 10.6.0.5. The harness's tar parent headers had changed
`/opt/splunk/etc` to 0750 owned by 41812, while the image starts Ansible as UID
999 without membership in that group. The corrected copy helper uses standard
0755 parent directories, preserving 0600 secret/config leaves and explicit
0700 executable leaves. No version marker is fabricated and the genuine image
bootstrap sequence is unchanged. Startup waits now inspect exact owned IDs,
names and labels and immediately retain sanitized exit-state evidence when a
container exits or dies, instead of waiting the full readiness timeout. This
is a harness correction, not a passing live qualification result; the failed
attempt and fresh corrected run retain separate evidence.

In the next attempt all five strict-CA management/identity startup checks passed,
but piping username/password lines to `splunk login` failed before captain
bootstrap. The native 10.6 CLI requires an interactive terminal. The corrected
helper runs the actual CLI under a controlling PTY inside the container, using
the pinned bundled Python 3.13. Credentials enter that helper only through
protected-file-derived stdin JSON and are sent once, only after recognized
username/password prompts, with terminal echo disabled before each write.
A successful cached-session exit with no prompts is accepted; partial,
out-of-order, repeated or rejected prompt flows fail without a retry. A
60-second deadline and 64-KiB output bound trigger process-group termination,
child reaping and PTY closure. Only status, exit code, prompt flags and reap
status are retained in an exclusive mode-0600 `evidence/cli-login-*.json` file
before rejecting a failed login, and in lifecycle state; no terminal transcript
leaves the helper.

The forked child removes `SPLUNK_USERNAME`, `SPLUNK_PASSWORD` and
`SPLUNK_PASSCODE` before exec; the parent environment is unchanged. Native
10.6 CLI code otherwise accepts those inherited image-bootstrap credentials,
which caused a username-only exit before the expected password prompt in
attempt03. A controlled native child-only scrub completed both prompts; this
does not authorize accepting partial prompt flows. Even after the direct child
exits, queued PTY output must pass the same prompt/byte/deadline checks through
EOF/EIO before an exit-zero result can be accepted as a cached login.

CLI TLS verification is explicit and separate from the REST client's strict
TLS checks: the task's `[sslConfig] cliVerifyServerName = true` uses the existing
`sslRootCAPath` and hostname/IP SANs for local and remote CLI connections, as
specified in the [Enterprise 10.6 server.conf reference](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.6/configuration-file-reference/10.6.0-configuration-file-reference/server.conf).
No hostname-check bypass or broader `sslVerifyServerCert` change is applied.
The failed piped-login and inherited-environment attempts retain separate
evidence from the later successful interactive login.

Attempt04 completed all five strict-CA startup/identity checks and interactive
login, then its original bootstrap phase failed on `-answer-yes`. A separately
recorded corrected-command diagnostic succeeded at 18:00:56 UTC. The original
phase remains failed. All three members subsequently passed the corrected
strict SHC/current-KV/cohosted-PDL readiness gate at 18:18:44 UTC, without a
member restart, database reset, resync or configuration change.

The first-start delay included sh1's PostgreSQL clone waiting on a paced forced
checkpoint (`checkpoint_timeout=900`, `checkpoint_completion_target=0.9`).
During storage initialization, PDL exhausted individual startup attempts and
the supervisor continued retrying; native logs also recorded internal OAuth
client-bootstrap EOF failures. These retries eventually converged automatically.
The retained record is
`dist/final-qualification/shc-attempt-04/evidence/diagnostic-assessment-15.json`,
with native status, PostgreSQL/Patroni and supervisor retry diagnostics in the
same hash-manifest-verified evidence directory. This establishes observed
platform bootstrap behavior, not application acceptance or a production recovery
time objective.

Keep the existing bounded 1,200-second readiness wait. A `starting` or `failed`
PDL status remains unready throughout it; PostgreSQL port health alone cannot
satisfy the KV gate. Retain timeout evidence for coordinator diagnosis rather
than automatically restarting, changing checkpoint settings, extending the
deadline or bypassing a prerequisite.

Apply the deployer bundle with `apply_bundle()`. Enterprise 10.6.0.5 does not
provide `validate shcluster-bundle`; do not report a separate successful CLI
validation. Add only the dedicated task peer to every member using
`qualification_shc.add_remote_peer()`, then require all peer statuses `Up`.
`verify_instances()`, `verify_shc_ready()` and `Lab.verify_candidate()` provide
bounded gates. Missing or unsupported required response shapes fail closed.
The pinned 10.6 native readiness contract is:

- `/services/shcluster/member/info` reports `status=Up`, registration true and
  maintenance false on every member; it does not provide `captain_uri`.
- `/services/shcluster/status?advanced=1` reports the exact three owned
  management URIs, all peers `Up`, and identical peer-GUID-to-URI mappings on
  all members. Compare full URIs; aliases and hostname substrings do not prove
  task ownership.
- Every member agrees on `captain.mgmt_uri` and `captain.id`. The URI identifies
  an owned elected member; `captain.id` is the shared cluster GUID, distinct
  from the elected member's server GUID. Never substitute or generate either
  platform identity.
- Captain initialization, minimum-peer and service-ready flags are true, the
  captain is stable, rolling restart/upgrade flags are false, and KV maintenance
  is disabled. Every peer is synchronized, has manual detention off and
  `restart_required=0`. The captain's own info endpoint also confirms the three
  ready flags.
- `/services/kvstore/status` reports both `current.status=ready` and
  `cohosted.status=ready`, with `cohosted.serviceInfo.type=Pdl`. Each member's
  `current.disabled` and `current.standalone` are false. Native cohosted PDL
  responses can have `peers=null`; MongoDB replica-set/member fields are not
  prerequisites. A ready `current` record with missing, starting or failed
  cohosted state is rejected.

`Lab.verify_candidate()` compares every installed package file on all members.
The `default/app.conf` allowance is limited to whitespace and a newly
generated `[install] install_source_checksum`, whose observed pinned-image shape
is 40 lowercase hexadecimal characters. The [Enterprise 10.6 app.conf reference](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.6/configuration-file-reference/10.6.0-configuration-file-reference/app.conf)
identifies this field as automatically populated from the installation tarball.
The harness validates its shape and records its value and both the archive-file
and installed-file SHA-256 values; it does not equate the generated checksum to
the raw candidate archive SHA-256. Every declared setting, including a checksum
already declared in the archived app.conf, must match exactly. An added `checksum` key,
other generated-field names, unexpected sections or unrelated changes are not
allowed. The separate, explicit settings-overlay allowance below applies only
after the exact task opt-in is recorded. Record task-local overrides separately.
Verify effective definitions after deployment
as well as archive bytes, because a preserved local override can change runtime
behavior without changing `default/` files.

Before builders populate the interface collection, load the raw ACI NetFlow
fixture on the remote peer and run the two existing regression methods:

```bash
ADM_SHC_QUALIFICATION=1 \
ADM_SHC_CLIENT_MODULE=qualification_shc \
ADM_SHC_STATE=/external/private-task/state.json \
ADM_SHC_EARLIEST=1791373500 ADM_SHC_LATEST=1791374400 \
PYTHONPATH=/reviewed/source/tools \
python3 -m unittest discover -s tests/splunk -p test_distributed_interfaces.py -v
```

These environment variables contain no credentials. The coordinator holds the
host lock while running this subprocess. Check the fixture's actual declared
window before dispatch; the illustrative bounds above are the base fixture
window. Require two executions and zero skips, with empty-inventory ifIndex
fallback and populated-inventory labels on all three members. The client fails
on search warnings as well as errors. Retain SIDs and test outcome, then verify
probe removal before interface builders run. Do not replace these tests with
mock assertions.

Next ingest a pristine all-source base slice with vendor indexing definitions
already active. Record each fixture checksum, input count and observed
index/sourcetype classification. Use `tests/splunk/test_aci.py`'s documented
scope rows, builder definitions, expected arguments and closed index-time slice
protocol. Run builders through different members, forward summaries to the
peer, then compare graph/topology rows on all three members with the exact
standalone candidate capture, excluding only `generated_at`. Do not substitute
previous-package or corrective-reingestion oracle evidence.

## Required recorded checks

| Check | Required evidence |
| --- | --- |
| Distribution | Full candidate hashes on every member, effective macros/configuration, peer-only raw data, fresh bundle generation |
| Lookup locality | The actual two distributed interface tests, all members, zero warning/partial-result jobs |
| Shared persistence | Every shipped collection create → cross-member update → delete convergence, with only task-unique probes removed |
| Reader access | Full expected graph/topology with a search-only viewer on every member; stored writes, private recovery/settings data and owner-dispatched writers denied |
| Actual scheduling | Shipped five-minute conversation schedule, current unique fixture, real scheduler success SID for every expected slot and matching new summary; no manual dispatch substituted |
| Concurrent settings | Initial creation and existing-revision races through different members; one success/one 409, stale revision rejection, stable request-ID retry after simulated response loss, all-member read convergence, viewer refusal |
| V1/V2 boundaries | Actual packaged recovery and current migration deployment qualifiers refuse all members before mutations; no SHC cutover enabled |
| Reapplication | Same exact candidate reapplied via deployer; settings ledger, task configuration override and lookup data retained and effective definitions understood |
| Final state | All members/KV ready; exact graph and settings agreement; fresh configuration creation/deletion convergence |

`collection_convergence()` inserts only unique task probe keys, updates on a
second member, deletes on a third and requires deletion convergence. Run it
before the immutable settings endpoint checks so malformed generic probe rows
cannot overlap the endpoint's ledger inspection. Do not delete real fixture
rows or reuse fixed keys.

Collection agreement/preservation snapshots request an explicitly `_key`-sorted
bounded scan, compare a second query shifted by one row with the exact expected
tail, and confirm the original scan is unchanged. A hidden server cap below the
requested 10,000-row limit cannot pass merely because all members return the
same truncated prefix. Malformed, duplicate/unordered, bound-reaching, capped
or persistently changing scans fail closed after at most two attempts. This
proof requires quiescent qualification state and is not a transactional
cross-collection backup or a production consistency guarantee.

For settings, the package defaults keep writes disabled. After the cluster and
KV namespace are verified, `Lab.opt_in_settings()` adds only this disposable
lab's deployer-local `adm_settings.conf` override:

```ini
[persistence]
write_mode = qualified_shc
platform = enterprise
```

Reapply the bundle and confirm the effective override everywhere. Read
`/servicesNS/nobody/splunk_adm/adm/deployment-settings` on every member. Require
`canWrite=true`, equal nonempty `namespace`, and converged current revision.
`settings_race()` posts JSON `{settings, expectedRevision, requestId, namespace}`
with a barrier across two members and retries the winning request on the third.
Use valid schema-1 source expectations from `config/deployment-health.json`;
the settings object contains `schemaVersion`, a fresh revision token and
`sources`. Test absent creation first, then a second race from the committed
revision. Refusal or uncertainty is a failed prerequisite requiring evidence,
not permission to relax namespace/KV/version checks. This run cannot establish
Cloud or unrelated independent search-head persistence behavior.

The endpoint replaces the caller's draft revision with a deterministic revision
derived from the expected revision, request ID, schema and source settings.
The race helper independently computes that expected revision and requires the
full winning settings in the commit response, retry response and every member
read. Its evidence records the operation fingerprint, submitted/committed
payload hashes and all-member agreement. Equal server-reported revisions alone
are insufficient. The 69 distributed tooling tests include wrong revision,
wrong commit/retry payload and same-revision/wrong-member-payload regressions.

The deployer's documented default push mode is `merge_to_default`: settings in
an app's deployer `local/` files override the corresponding settings in its
`default/` files and are delivered to members' `default/` files. An app-specific
or global mode can change that behavior; see the [Enterprise 10.6 deployer push-mode reference](https://help.splunk.com/en/splunk-enterprise/administer/distributed-search/10.6/update-search-head-cluster-members/use-the-deployer-to-distribute-apps-and-configuration-updates).
The harness does not change the mode or infer its effective value from package
identity. Initial candidate09 has no `local/` files, and support-app configuration
is staged under the support apps' own names; neither establishes a settings
merge into the candidate during its initial bundle.

After opt-in, package verification accepts a changed
`default/adm_settings.conf` only when lifecycle state records exactly
`settings_override={write_mode:qualified_shc,platform:enterprise}`. It applies
those two values to the existing `[persistence]` keys of the archived baseline
and compares every resulting section/key/value. No other default, extra key,
section, or unrecorded/malformed override is accepted. It records both raw file
hashes, the exact expected overlay and observed variant
`task_overlay_merged_to_default`. If the original default remains byte-exact,
it records `archive_byte_exact` instead. Neither variant alone proves effective
opt-in; all-member endpoint write-readiness, namespace and settings agreement
checks remain required.

The settings phase verifies and records all archive files immediately after its
bundle/readiness checks, before the first settings endpoint or ledger operation.
The reapplication phase repeats the same file verification. The candidate
archive and its hash remain unchanged; these records explicitly distinguish a
reviewed task configuration from the archived default bytes.

`assert_standalone_only(packaged_app, source_root)` invokes the actual recovery
and migration qualifiers behind a GET-only adapter. It passes only when each
refuses every member, and fails if either attempts a mutation. V1 normal
builders/graph are exercised; SHC migration/cutover remains explicitly
unsupported. Standalone V2 activation/rollback/pruning requires its separate
qualification and is not inferred from this refusal check.

Captain-loss/rejoin can be added only as an explicitly recorded coordinator
phase. Preserve all original failures and elapsed times. A scheduled success
does not establish full RF3 configuration readiness while a member is absent.
Do not turn an assisted restart into an unassisted result. A same-host loss test
still cannot establish supported production failure-domain behavior.

## Evidence export, cleanup and unavailable boundaries

Attempt06 deployed candidate09 to all three members and verified every archived
file after unassisted cluster/KV readiness. Both original interface cases ran:
all six member searches completed, but cleanup of the populated-inventory case
failed. Splunk returned HTTP 200 with zero response bytes for the successful
KV item DELETE; the qualification client incorrectly required JSON. The client
now accepts an empty body only for a successful 2xx DELETE. Empty GET/POST,
nonempty malformed JSON and HTTP errors still fail. The original interface
assertions remain unchanged. All 65 distributed tooling tests pass, including
the original cleanup path with a successful empty DELETE followed by replicated
404 responses. Independent review found no actionable defect in the correction.

Attempt06 remains failed. Its 30 exported files, including the failure,
diagnosis and owned cleanup, were credential-scanned and hash-verified in
`dist/final-qualification/shc-attempt-06-failure-final/`; archive SHA-256 is
`8d633d31bf4719d552314d82fbe8225e2c0aaaac8a99853ecd1fa7ded5e94e17`.
Fresh full SHC execution with the reviewed client is still required.

Attempt07 completed preparation, container creation, support installation and
strict management TLS/identity checks. It was stopped before cluster bootstrap
to strengthen the settings payload assertions described above. Its 15 exported
files and owned cleanup were verified in
`dist/final-qualification/shc-attempt-07-superseded-final/`; archive SHA-256 is
`b11161b9e19d7ee61dda5708923c431599cec5f127540c24aad3697258126dae`.
This superseded preparation is not application acceptance evidence. Independent
review found no actionable defect in the strengthened settings assertions.

Attempt08 used source `c314cc89f7ea6e14f317371fd5c2d19e5b74cc6b` and the
unchanged candidate09 archive. Unassisted bootstrap and bundle readiness passed;
all 85 archived files were verified on each member, allowing only Splunk's
generated install checksum. Both original interface tests passed (two tests,
zero failures/errors/skips), followed by create/update/delete convergence for
all 15 collections. The base phase then failed: Service binding's configuration
POST returned 200, but a dispatch 51 milliseconds later returned 400 because
the target member still considered the search disabled. Later reads showed the
intended flags on all three members. Configuration acceptance is asynchronous;
a successful POST alone does not establish dispatch readiness.

The failed run remains failed. Its 36 exported files, including native refusal
diagnostics and exact owned cleanup, were credential-scanned and verified under
`dist/final-qualification/shc-attempt-08-failure-final/`; archive SHA-256 is
`20690327c28d44e08b14f06d7308db2bbc8accb38d99c0b288b6e94eca99e667`.
The corrected harness posts each intended saved-search configuration once and
requires exact `disabled` and `is_scheduled` values on all three members before
dispatch. Its 120-second transition budget covers response bodies and parsing,
using an owned POSIX main-thread timer; an existing timer or blocked deadline
signal refuses before mutation. Configuration convergence does not establish
dispatch-engine atomicity: a remaining native rejection is still a failure.

Base retries reuse the original persisted receipt window and known SIDs. V2
writer retries restore both persisted original flags before reporting success.
The scheduler preserves its original flags and acknowledged probe across
failures. Unknown dispatch/ingestion outcomes require inspection; an elapsed
slot with no proven pre-slot absence also refuses rather than becoming a
successful retry. All 87 distributed tooling tests pass. Independent review
identified and closed three P2s in the correction: changing retry windows,
incomplete restoration on retry, and late responses accepted after the deadline.
The reviewer independently ran the 11 added follow-up regressions. Fresh
complete SHC execution remains pending.

Store sanitized evidence under the external task's `evidence/` directory.
`write_evidence()` uses owner-only exclusive writes and returns a SHA-256.
Export a manifest covering every evidence record, the exact archive and the
relevant test files. Record UTC timestamps, command arguments excluding secrets,
actual counts, warnings, skips and nonzero exits. The original distributed
tests retain their per-member job evidence on the class; the coordinator can
run them programmatically to export it alongside the unittest result.

After exporting and verifying hashes, call `Lab.cleanup()` while still holding
the same lock. It checks the entire recorded ID/name/label removal set and
rejects any unowned network attachment before removing resources. It removes
only recorded task containers, their anonymous volumes and the task network;
the image cache remains. The external private directory, state and credentials
remain until the coordinator verifies export and explicitly disposes it. Do
not publish secrets with the evidence.

No authorized Splunk Cloud test stack/access has been identified. Cloud
installation, capabilities, shared persistence, searches/builders, browser
behavior and cutover operations remain unverified. AppInspect is a separate
package check and cannot close that deployment gate. The final release report
must retain this exact missing-environment boundary until actual supported
Cloud execution is available.
