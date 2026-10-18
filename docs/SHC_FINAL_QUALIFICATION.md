# Final candidate distributed qualification

Status: tooling and procedure prepared; no fresh live SHC result is claimed by
this document. The earlier results in `SHC_QUALIFICATION.md` remain bound to
their original archives. A passing offline harness test is not a live platform
qualification result.

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
need separately recorded coordinator checks where required. Runtime bootstrap,
SHC status response shapes and packaged endpoint behavior still require the
actual fresh run. Do not relabel this driver implementation as a live pass.

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
`bootstrap shcluster-captain` command. Config-first initialization and platform
response shapes must be verified in the fresh run; the helper is not evidence
that bootstrap passed. Preserve failures and stop for coordinator diagnosis.
No automatic KV reset, second restart or readiness override is performed.

Apply the deployer bundle with `apply_bundle()`. Enterprise 10.6.0.5 does not
provide `validate shcluster-bundle`; do not report a separate successful CLI
validation. Add only the dedicated task peer to every member using
`qualification_shc.add_remote_peer()`, then require all peer statuses `Up`.
`verify_instances()`, `verify_shc_ready()` and `Lab.verify_candidate()` provide
bounded gates. Verify platform endpoint response fields before accepting the
first readiness result; unknown fields fail closed. All three members must be
`Up`, agree on the captain and have ready KV Stores. Captain initialization,
minimum-peer and service-ready flags must all be true.

`Lab.verify_candidate()` compares every installed package file on all members.
The only non-byte-exact allowance is `default/app.conf` whitespace and Splunk's
generated `[install] checksum`; declared values must match exactly. Record
task-local overrides separately. Verify effective definitions after deployment
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
