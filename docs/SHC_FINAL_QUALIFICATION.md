# Final candidate distributed qualification

Status (2026-10-19 UTC): Attempt16 completed every required application gate
using the unchanged candidate09 archive and frozen source28 at
`5391d93d7fe4ca63aab63080fc833979d09173bb`. It required the explicitly
recorded SDK prerequisite repair described below; its first refusal import
failure is retained. Both original distributed cases, settings races,
reapplication and verified cleanup/export passed. This is same-host synthetic
SHC functionality, with the production and Cloud boundaries below.

Historical attempts: Attempt12 was interrupted when its EC2 host was
terminated externally at `03:13:15Z`. Captain-bootstrap CLI acknowledgment
does not establish readiness; no application phases ran, and no original remote
evidence snapshot was exported. After existing-host checks and the user's
authorization of a new disposable host, Attempt13 ran on
`i-029223a47cbb06aee`. It passed unassisted bootstrap, bundle distribution,
both original interface cases and collection checks, then failed the exact
base-classification oracle. The installed CiscoSecurityCloud 3.7.2 add-on
correctly rewrote four submitted `cisco:isovalent` events to
`cisco:isovalent:processConnect`; the qualifier had expected their submitted
sourcetype. All 963 events and the other 15 groups matched. No application
builder was dispatched. The failed prefix is retained. Its reviewed correction ran as Attempt14,
which passed the V1 application gates and then failed the staged V2 diagnostic
oracle described below. Attempt15 subsequently failed in the runtime settings-overlay copy; those attempts do not establish application acceptance.
Attempt11 failed the 1200-second bootstrap readiness gate
after 1202.322 seconds at `2026-10-19T02:53:42Z`. No application phases ran.
An ordinary coordinator-controlled Splunk restart of sh1 at
`02:51:44Z`–`02:52:20Z` returned exit 0, but did not establish full KV readiness.
This attempt is an assisted failed platform preparation, not an application
qualification pass. Attempt10 earlier failed the base phase, where the interface
writer completed with a warning and no inventory rows. No
application acceptance is attributed to Attempt10.
Frozen source22 `7fc04abbda74b2840174fe4a305220dae7237873` and candidate09
archive SHA-256
`024d11c83ae9cb21a19259b57038d0e4a68414d1b2d3dde82cad527d789a0097`
passed unassisted bootstrap, strict member/KV readiness, bundle verification,
peer checks, both original distributed interface cases and all 15 collection
convergence checks. The local configuration gate allowed the actual Identity
and Service binding writers to complete through different members. The
NX-OS-only Interface inventory writer had no matching inputs in the ACI-only
batch. Its native warning remains a rejection; the remaining application phases
were not qualified. The final 57-file failure export and removal of the exact
five containers/network have been independently verified.

The next correction adds reviewed positive NX-OS input and an independent exact
inventory oracle while retaining strict warning rejection. It passed independent
review and ran as Attempt11 from source
`56947e7466851ec2b6584eb2060466551a5314f2`, with the unchanged candidate09
archive and 144 verified source inputs. Attempt11 did not qualify application behavior.
The new-source correction described below permits explicit readiness-only retry
after a durably acknowledged bootstrap; it is not applied to frozen Attempt11.
The coordinator retains exclusive ownership of execution, export and cleanup.

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

The historical authorized disposable qualification host was EC2
`i-0b186b390ea7ff8dc` in `us-east-1`, named
`splunk106-validation-20261007`. Authentication follows the existing `duo-sso`
workflow. That instance is terminated. Existing-host selection requires live
access/resource checks and confirmation before disrupting its demo workload;
the old host's disposable-data permission does not transfer to another host.
SSH host-key verification stays enabled. The harness identifies every
resource by full Docker ID, exact task name and task label before lifecycle
operations. It never uses a global prune, image removal, wildcard deletion or
container name alone.

The user subsequently authorized creation of a dedicated disposable host rather
than disruption of the existing demo machines. Attempt13 uses
`i-029223a47cbb06aee` in `us-east-1`, `m6i.2xlarge`, with an encrypted 100-GiB
root volume. The existing validation security group permits only controller
SSH ingress. Its task-specific key-pair registration uses an external key's
public half; no private key enters the repository or instance user data.
The scanned SSH host fingerprint was verified against authenticated EC2 console
output. Ubuntu 24.04, Python 3.12.3 and Docker 29.1.3 are recorded separately
from the pinned Enterprise image. The exact source24 archive is verified and
extracted to the fresh `atlas-final-shc-source-25` path with 144 inputs and
38 Git-bound files; the original source/archive/manifest are unchanged.
Attempt13's 27-record failed prefix, including its exact base failure and
manifest, is retained in `dist/final-qualification/shc13-failed-prefix-evidence.json`
(SHA-256 `ef807818f932895b3e058cb797df9c66dbcf2cf5709fa4d46dc871e33b1d6917`).
The classification diagnostic is separate read-only evidence and does not
convert the failed oracle into a pass. A future oracle must derive the expected
indexed classification from the reviewed add-on rules and fixture payloads,
while retaining every count and strict subtype checks.

The failed Attempt13 precleanup export lists 30 verified payload files; the final
export lists 34, retaining all 27 original records and their byte continuity.
Those original bytes were checked against 12 separately retained prefix
snapshots; the snapshot JSON files are not payloads in these archives.
Final archive SHA-256:
`07cedfa23ee66280111a712048cd520c2fe78da096a11ba2bda25f171f182da6`.
The exact five containers and network were removed at
`2026-10-19T04:16:15.027462Z`; independent review71 verified both archives and
cleanup. An initial final-export attempt rejected a stale precleanup manifest.
That rejection remains retained; an explicit fresh manifest preceded the
successful final export. The failed run is not application acceptance.

The reviewed correction is committed at
`74a77e1f28c3d454bdf7bb38257d02f018b26480`. Its 116 offline cases passed,
including exact subtype/count/configuration and pre-mutation refusal checks.
The pure preflight independently derives the declared-versus-indexed mapping
from pinned CiscoSecurityCloud props/transforms and fixture payloads.
Fresh Attempt14 uses the verified source26 archive (144 inputs/38 Git bindings,
only the qualification driver changed) and the unchanged candidate09 archive.
Its private directory/task are `atlas-final-shc-01a15236-14` /
`adm-shc-01a15236-14`. It passed unassisted bootstrap (855.785 seconds),
85-file distribution on all three members, both original interface tests
(13.687 seconds, zero skips), all 15 collection checks, exact 963-event/16-group
classification, and the exact two NX-OS interface rows on every member.
Its ACI graph (25 nodes/33 edges) and topology (6 devices/11 links) passed
independent fixture semantics and identical all-member readback. No optional
standalone row reference was supplied.

Attempt14 failed the staged V2 topology warning oracle after its staged graph
passed. The oracle had required a generic unsupported-inventory warning
from a different standalone APIC mapping. In this fixture, six source-qualified
APIC devices remain explicitly unmapped and three Kubernetes hosts are mapped;
unclustered APIC adjacency rows are filtered before unsupported-row counting.
The actual two warnings preserve missing Catalyst history and uncorrelated
Nexus Dashboard labels. The failed run remains nonacceptance. Its 96 original
records plus sanitized dispatch state are retained in
`dist/final-qualification/shc14-failed-prefix-evidence.json`
(SHA-256 `82c0fdfe81028e8f379edb94f6870b65a458880594b4e2beeb25fa191e7a0de5`).
The strict fixture-specific correction is committed at
`7659d84339b9ea3901c00fba9eec5c9287e8d876`; independent review73 and
118 offline tests passed. It requires exactly two full diagnostic strings,
zero interface metadata, and exact APIC/Kubernetes fixture mappings while
retaining identity, authority, scope, cluster and adjacency guards.
Attempt14's precleanup/final exports list 100/104 verified payload files,
retaining all 96 original records with byte continuity and zero credential
matches. Those bytes were verified against 22 separately retained prefix
snapshots, which are not archive payloads. Final archive SHA-256:
`beea77c81b89f52264df10390eec2866a22c94c7776fb1d97fd64939b5438e7f`.
The exact five containers/network were removed at
`2026-10-19T05:02:15.372244Z`; a fresh manifest preceded the final export.
Independent review74 verified the actual exports and cleanup.

Fresh Attempt15 uses source27 at the new commit (144 inputs/38 Git bindings,
only the driver input changed from source26), the unchanged candidate09 archive,
and task `adm-shc-01a15236-15`. Its first all-member readiness check failed
at `2026-10-19T05:25:10.923722Z` (1202.272 seconds including CLI setup)
after the strict 1200-second readiness check. The
acknowledged bootstrap was not dispatched again. An explicit readiness-only
retry in the same continuously locked controller passed the complete gate at
`05:30:28.474908Z` in 290.735 seconds. The first failure and both attempt
journals remain retained. No manual restart, KV reset or internal configuration
change occurred. The prepared ordinary-restart fallback remained unused.

Troubleshooting compared PostgreSQL, Patroni, PgBouncer, Traefik, PDL and
supervisor logs across the three members. sh1's replica basebackup waited on
the primary's forced/wait checkpoint (`05:07:51.541Z`–`05:18:23.823Z`,
632.282 seconds); the backup completed 0.405 seconds later. The checkpoint's
write phase consumed 632.245 seconds and sync 0.013 seconds. Pacing is a
supported inference from those timings, but actual pacing settings versus I/O
contribution remain unproven. After the database/proxy became ready, a native
PDL bootstrap attempt at `05:25:00.954Z` failed on an internal OAuth-client
POST returning EOF; the update succeeded at `05:30:26.130Z`, followed by
PDL startup and full readiness. The bounded supervisor tail does not establish
its exact retry policy or permanent exhaustion, and the EOF cause remains
unmeasured. Automatic recovery made a
manual restart unnecessary. Sanitized, bounded diagnostics and exact selected
line references are retained under
`dist/final-qualification/shc15-startup-diagnosis-worker-01/`; they are
explicitly separate from original byte-exact qualification records. Application
qualification continues after this platform preparation.

The fresh application prefix passed bundle verification on all three members
(361.977 seconds), exact peers, both original distributed interface cases
(13.119 seconds, zero skips), all 15 collection checks, and the complete
963-event/16-group classification with two exact NX-OS interface rows on every
member (79.975 seconds). Independent V1 graph (25 nodes/33 edges) and topology
(6 devices/11 links) semantics and all-member equality passed. No optional
standalone row oracle was supplied.

Staged V2 passed in 68.307 seconds: the two writers completed through different
members, yielding 35 conversation and 33 separate traffic records. All three
members returned the same 23-node/32-edge graph, 16 spans, two independent
witnesses and nine-device/zero-link topology with exactly two expected warnings.
V1 selectors, graph/topology and original observer-scope rows remained unchanged.
The least-privileged viewer then passed the same V1/V2 read equality across all
members in 115.372 seconds. Protected recovery state/builders were inaccessible,
and settings/KV writes returned 403. Actual scheduling then passed in 347.033
seconds: the uniquely indexed probe was absent before the eligible `05:55Z`
slot, and the native scheduler SID produced exactly one 900-byte, one-record
summary. The original schedule flags were restored.

Attempt15 failed its settings phase at `2026-10-19T05:55:57.361387Z`, before
bundle application or any administrator settings API writes. The staged
`qualified_shc` override and lifecycle state had already been saved. Deployer
login exited 24; a separate authenticated request returned HTTP 500. The other
four roles accepted the same protected administrator credentials.

Read-only diagnostics established a qualification-harness ownership defect.
Docker 29.1.3's `docker cp -a` extraction selects the container's configured
`ansible` user (UID 999), overriding the tar's explicit UID 41812. The runtime
overlay copy consequently changed `/opt/splunk/etc` and its staged overlay
ancestors to `999:999`, mode 0755, and the overlay leaf to mode 0600. Splunk
runs as UID 41812. Its log records `Permission denied` creating the
`login-info.cfg` temporary file, followed by the authentication HTTP 500;
the overlay leaf is also unreadable by Splunk. No OOM kill was recorded.
The same unrelated orchestrator health warnings appeared on the healthy indexer
and do not explain this permission failure. [Docker's extraction options](https://github.com/moby/moby/blob/docker-v29.1.3/daemon/archive_tarcopyoptions_unix.go)
and [archive extraction](https://github.com/moby/moby/blob/docker-v29.1.3/daemon/archive_unix.go)
corroborate the ownership mechanism.

Independent review confirmed the harness defect. An unchanged retry would
repeat it. The frozen source27 and original failed records are preserved;
a reviewed copy fix and fresh pinned lifecycle are required. Administrator
races, refusal and reapplication remain unqualified by Attempt15. This prefix
is not full application acceptance. Sanitized diagnosis and exact permissions
metadata are retained in `dist/final-qualification/shc15-deployer-diagnosis-worker-01/`,
`shc15-permissions-02.json` and `shc15-diagnosis-reconciliation-01.json`.

The independently reviewed one-flag copy correction at `5391d93` preserves
numeric archive ownership instead of requesting Docker's configured-user
override. All 122 distributed offline checks passed. An isolated native Docker
probe reproduced UID999 with the old flag and UID41812 without it, with the
same 0755/0600/0700 modes; both temporary trees were removed. It touched no
application paths and does not establish application acceptance.

Attempt15's verified failure exports list 116 precleanup and 120 final
payload files, preserving all 95 original records and 15 pinned diagnostic
artifacts. The original bytes were verified against 28 separately retained
prefix snapshots; the snapshot JSON files are not in these archives. Their archive SHA-256 values are
`a4a91480f1fe05d792e576a800cdf603f65d846f75497212a21ca4e0d16cf188` and
`8010b11dcbd99bfa2fecec05b7a99ffe73e5f0fc8d321525146f6eef9dab5789`.
Both retain the first bootstrap failure and the settings failure, with zero
credential matches and exact precleanup-byte continuity. The five exact
containers and network were removed at `2026-10-19T06:13:42.771240Z`;
a fresh manifest preceded final export, and the locked controller exited 0.

Fresh Attempt16 uses source28 at
`5391d93d7fe4ca63aab63080fc833979d09173bb`, the same candidate09 package,
144 inputs/38 Git bindings and task `adm-shc-01a15236-16`. Only the copy helper
input differs from source27. Independent review verified the actual source
archive, launcher and unchanged acceptance contracts. Startup passed with strict
management TLS/identity checks in 83.386 seconds. The first all-member bootstrap
readiness attempt passed in 860.579 seconds at `2026-10-19T06:30:42.307465Z`,
with one acknowledged bootstrap dispatch and no retry, restart, reset or tuning.
The primary checkpoint took 633.507 seconds (`06:19:14.897Z`–`06:29:48.403Z`);
the lagging replica began listening at `06:29:49.158Z`, followed by its proxies
and native PDL start at `06:30:37.155Z`. These timings establish the dependency
chain, without proving checkpoint pacing settings or an I/O root cause.

The actual Attempt16 prefix then passed all 85 installed files on every member,
the two original distributed cases (2 passed, no skips), all 15 collections,
963 indexed events in the 16 exact groups, six native V1 builders, and V1
member parity (25 graph nodes/33 edges; 6 topology devices/11 links). Both staged
V2 writers completed on different members, producing 68 summary rows; all three
members agreed on 23 graph nodes/32 edges and 9 topology devices/0 links with
exactly the two independently derived uncertainty warnings. Public V1 selectors
and observer scope stayed unchanged. Viewer reads matched administrator reads;
protected recovery/builders were inaccessible and stored-data/settings writes
returned 403. The actual five-minute scheduler gate passed with one native
success SID and exactly one 900-byte/one-record summary at the eligible
`2026-10-19T06:55:00Z` slot; original scheduler flags were restored.

Settings passed at `2026-10-19T06:56:00.464500Z`. Initial creation and the
subsequent same-revision race each returned `[200,409]`; retrying the winning
request through the third member returned the same result, and complete
settings converged across members. Stale revision writes returned 409 and
viewer writes returned 403. The final settings SHA-256 is
`4be7d7269a68bf9401c1cf5efad4436a0b785ac68bfc3bbf1f2d899a1833b967`.
Actual native metadata confirmed UID/GID41812 and the intended modes on all six
copied overlay paths, with deployer/indexer authentication returning HTTP200;
independent review closed the ownership defect using this runtime evidence.

The next refusal phase failed before API calls at `07:02:19.771772Z` with
`ModuleNotFoundError`. The harness imports the packaged recovery qualifier,
which needs the SDK retained under candidate `bin/lib`; its import path omitted
that directory. Actual-host reproduction confirmed missing `splunklib` before
any API construction. Independent review85 cleared a narrow same-controller
prerequisite installation: all 27 SDK Python files from the exact candidate
were copied into an absent root-owned host Python package directory at
`07:11:09.503481Z`, with every hash verified. The 144 frozen source inputs and
staged package were unchanged. The original failed record remains retained.

The explicit refusal retry passed in 0.123 seconds at `07:11:11.872071Z`.
Packaged recovery and the actual migration qualifier each refused all three
members using GET only. The permanent harness correction at
`5b305648aa465ebdaec74ff0074673fbf26d1729` adds candidate `bin/lib` and
rejects SDK modules loaded from another candidate before API construction.
Its 125 offline distributed tests passed, including three clean/ambient-import
regressions. A separate fresh `-S -B` native check of those committed client
bytes passed against all three members at `07:13:06.208067Z`, with six actual
GETs and SDK origins bound to the exact staged archive. The initial supplemental
probe remains failed and is excluded from acceptance. Its fixed twelve-GET
expectation used the offline fixture's control flow: fixture responses take
four GETs per member, whereas actual SHC server-role responses allow both tools
to refuse after two GETs per member.

Bundle reapplication passed in 86.956 seconds at `07:12:43.229750Z`, preserving
the complete winning settings, all 15 collection snapshots, V1 graph/topology,
public V1 selectors and staged V2 administrator/viewer results. The precleanup
export lists 112 payload files, SHA-256
`819854f6171afe2d99d5f493a4a667ffb4cc2f6c40fbca9d016e376946391e4f`;
the final export lists 117 payload files, SHA-256
`c73950125b2e17a90a082c41eef0c2759d8c7b69d922efb89ec3823dbcc9a494`.
Both retain the failed refusal record and all original prefix bytes, with zero
credential matches. The 94 original records were byte-verified against nine
separately retained append-only prefix snapshots; those snapshot JSON files
are not payloads in the archives. The exact five containers
and network were removed at `07:13:31.799045Z`; a fresh manifest at
`07:13:49.480767Z` preceded final export, and full precleanup continuity was
verified. The exact 27-file temporary SDK copy was removed at `07:14:15.574439Z`
under the same attested controller lock, then the controller exited 0. No
existing demo host or workload was disrupted. The additional host SDK receipts,
startup diagnosis and corrected-client proof remain separately hash-bound
under `dist/final-qualification/`; they are not silently inserted into frozen
original phase records.

At `2026-10-19T07:17Z`, AWS credentials were expired and the approved `duo-sso`
refresh had failed while the Mac was locked. EC2 instance/root-volume and task
AWS public-key registration disposal remained pending; Docker and SDK cleanup
must not be represented as instance termination. The final publication record
tracks any later resource state or cleanup after renewed access and exact
ownership verification.

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

In the new source, captain bootstrap is journaled as `started` before calling
the CLI and `acknowledged` only after a known successful return. The journal
binds the exact source snapshot/hash, archive hash, task directory, image,
network, full container IDs, task names and management URLs. After a readiness
timeout, `{"phase":"bootstrap","rerun":true}` validates that durable journal,
the unchanged source and every live ID/name/task label, then runs only the same
full `verify_shc_ready` gate with the same 1200-second bound. Native readiness
results retain their original shape; separate UTC-timestamped evidence identifies
each initial or readiness-only attempt. The manifest includes a detached copy of
the sanitized bootstrap journal, binding those attempts to their source and
owned resources. Original failure records remain retained. A started,
failed, malformed or undurably acknowledged CLI attempt refuses redispatch,
including HTTP 400 or a lost CLI response. No bootstrap retry is inferred from
an apparently initialized cluster or from a platform error message.

Splunk's [10.6 deployment procedure](https://help.splunk.com/en/splunk-enterprise/administer/distributed-search/10.6/deploy-search-head-clustering/deploy-a-search-head-cluster)
describes bootstrap as selecting the first captain. It does not promise generic
idempotence on an existing dynamic cluster. Rebootstrap is separately documented
within [static-to-dynamic disaster recovery](https://help.splunk.com/en/splunk-enterprise/administer/distributed-search/10.6/manage-search-head-clustering/use-static-captain-to-recover-from-loss-of-majority);
that procedure does not apply here. The [10.6 sidecar lifecycle](https://help.splunk.com/en/data-management/splunk-enterprise-admin-manual/10.6/splunk-sidecars/about-splunk-sidecars)
assigns unhealthy/terminated sidecar restarts to the supervisor. The reviewed
official lifecycle and KV endpoint documentation provide no targeted manual PDL
restart command for this condition. No sidecar kill, KV reset or configuration
workaround is introduced.

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
known scope/cluster. Exactly the missing-Catalyst-history and unsupported
Nexus Dashboard fabric-label correlation diagnostics are required. A valid
unmapped device remains a supported inventory row; the unclustered APIC
adjacency branches filter their rows before unsupported-row counting. This
fixture therefore must not emit the generic unsupported-inventory or unresolved
LLDP warnings associated with differently mapped fixtures. The oracle rejects
missing, additional, changed or duplicate warnings and requires zero link and
interface counts. This tests the conservative staged boundary, not mapped ACI
adjacency or additional source combinations.

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
index/sourcetype classification. The ACI data supplies 825 base events plus the
33 NetFlow events loaded before the original interface cases. Add the unchanged
105-event `fixtures/raw-networking/nxos_inventory.ndjson` file to the base batch:
the acknowledged base POSTs then cover 930 events and the combined classified
inventory is exactly 963 events. The NX-OS file SHA-256 is
`753a7c58f7db489d2a575474ca207d0cab03383d140bb5c01b7a58528b3d0062`.
Its provenance remains `fixtures/raw-networking/FIELDS.md` and the NX-OS command
contract in `fixtures/raw/FIELDS.md`; the fixture and product files are unchanged.

Preflight before preparation and base ingestion requires the pinned bytes,
105 source-qualified records, component counts (21 hostname, 21 version,
28 neighbor, 35 interface), consistent envelope/event timestamps and the exact
event interval `[1792293814,1792295615)`. That October 18 interval must be disjoint
from both declared October 7 ACI graph/topology windows. All inputs share the
original persisted closed receipt slice for builder dispatch; the receipt bounds
are distinct from these fixture event-time windows. The ordinary NX-OS fixture
under `fixtures/raw/nexus9k.ndjson` is not substituted because its event times
overlap the ACI topology window. Every expected index/sourcetype count, including
105 `cisco_dc` / `cisco:dc:nexus9k` events, must match before dispatch.

The actual Interface inventory writer must populate exactly these two rows on
each member, with `_key=device_ip|ifindex` and `updated=1792295614`:

| Device IP  | Device   | ifIndex   | Interface    | Neighbor | Neighbor interface |
| ---------- | -------- | --------- | ------------ | -------- | ------------------ |
| 192.0.2.11 | leaf-101 | 436232192 | Ethernet1/49 | border-1 | Ethernet1/1        |
| 192.0.2.12 | leaf-102 | 436232192 | Ethernet1/49 | border-1 | Ethernet1/2        |

The oracle is declared independently of query output and checked against the
reviewed raw hostname/CDP fields during preflight. All stored semantic keys and
values must match; only native KV `_user` metadata is excluded from the semantic
comparison, while full returned rows are retained. Per-member row/hash evidence,
fixture path/hash/count/event bounds and the common receipt bounds are recorded.
Missing/altered input fields, overlapping event windows, missing/duplicate/wrong
inventory rows, or native warnings cannot become a positive builder result.

Use `tests/splunk/test_aci.py`'s documented
scope rows, builder definitions, expected arguments and closed index-time slice
protocol. Run builders through different members, forward summaries to the
peer, then compare graph/topology rows on all three members with the exact
standalone candidate capture, excluding only `generated_at`. Do not substitute
previous-package or corrective-reingestion oracle evidence.

## Required recorded checks

| Check               | Required evidence                                                                                                                                                                                                         |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Distribution        | Full candidate hashes on every member, effective macros/configuration, peer-only raw data, fresh bundle generation                                                                                                        |
| Lookup locality     | The actual two distributed interface tests, all members, zero warning/partial-result jobs                                                                                                                                 |
| Shared persistence  | Every shipped collection create → cross-member update → delete convergence, with only task-unique probes removed                                                                                                          |
| Reader access       | Full expected graph/topology with a search-only viewer on every member; stored writes, private recovery/settings data and owner-dispatched writers denied                                                                 |
| Actual scheduling   | Shipped five-minute conversation schedule, current unique fixture, real scheduler success SID for every expected slot and matching new summary; no manual dispatch substituted                                            |
| Concurrent settings | Initial creation and existing-revision races through different members; one success/one 409, stale revision rejection, stable request-ID retry after simulated response loss, all-member read convergence, viewer refusal |
| V1/V2 boundaries    | Actual packaged recovery and current migration deployment qualifiers refuse all members before mutations; no SHC cutover enabled                                                                                          |
| Reapplication       | Same exact candidate reapplied via deployer; settings ledger, task configuration override and lookup data retained and effective definitions understood                                                                   |
| Final state         | All members/KV ready; exact graph and settings agreement; fresh configuration creation/deletion convergence                                                                                                               |

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
are insufficient. The distributed tooling regressions include wrong revision,
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

Attempt05 used source `50e098a602a21ef386172015aa2ed888b936efd4` and
candidate08 archive SHA-256
`946ff4806917bda093659328811b05c348251a9197e3b61244b0902254a9b4b6`.
Its bootstrap and strict three-member KV/PDL readiness passed; bundle verification
failed on the generated `install_source_checksum` field described above. The
original failed phase remains recorded. The checksum correction and subsequent
fresh lifecycles do not relabel that earlier result.

Attempt06 deployed candidate09 to all three members and verified every archived
file after unassisted cluster/KV readiness. Both original interface cases ran:
all six member searches completed, but cleanup of the populated-inventory case
failed. Splunk returned HTTP 200 with zero response bytes for the successful
KV item DELETE; the qualification client incorrectly required JSON. The client
now accepts an empty body only for a successful 2xx DELETE. Empty GET/POST,
nonempty malformed JSON and HTTP errors still fail. The original interface
assertions remain unchanged. At that correction, all 65 distributed tooling
tests passed, including the original cleanup path with a successful empty DELETE
followed by replicated
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
The scan found zero credential matches. All five exact owned containers and
their task network were removed; the retained export preserves the failure.
The corrected harness posts each intended saved-search configuration once and
originally required matching `disabled` and `is_scheduled` values from three
saved-search endpoint requests before dispatch. Attempt09 showed these reads
could all proxy to the captain; they were not local-member readiness proof.
The 120-second transition budget covers response bodies and parsing,
using an owned POSIX main-thread timer; an existing timer or blocked deadline
signal refuses before mutation. Configuration convergence does not establish
dispatch-engine atomicity: a remaining native rejection is still a failure.

Base retries reuse the original persisted receipt window and known SIDs. V2
writer retries restore both persisted original flags before reporting success.
The scheduler preserves its original flags and acknowledged probe across
failures. Unknown dispatch/ingestion outcomes require inspection; an elapsed
slot with no proven pre-slot absence also refuses rather than becoming a
successful retry. All 87 distributed tooling tests passed in the coordinator's
1.125-second offline run. Independent review identified and closed three P2s in
the correction: changing retry windows,
incomplete restoration on retry, and late responses accepted after the deadline.
The review33 findings were closed through review34; the reviewer independently
ran the 11 added follow-up regressions. These are offline harness results.
Those fixes did not establish a live SHC pass in Attempt09.

Attempt09, task `adm-shc-01a14f65-09`, used source21
`f3b42485e38119f93e6363bfdeb28a0e99973788`, driver SHA-256
`8280b38a38e8d69c4409a035080f090f08e711b9f12a117d51fa12b7d04cbc9b`, and
the unchanged candidate09 archive. Bootstrap passed in 844.093 seconds and
bundle verification in 365.854 seconds, followed by peer checks, both original
interface cases with zero skips in 7.598 seconds, and all 15 collection checks
in 2.344 seconds. The base phase failed after 29.166 seconds at
`2026-10-19T01:07:46.959560Z`: sh2 rejected Service binding dispatch as disabled.
The identity builder had a known completed SID; Service binding remained
`dispatching` without a SID. The acknowledged fixture inputs and original
closed receipt window remain recorded; no uncertain dispatch is repeated.

Read-only diagnostics in
`dist/final-qualification/shc09-service-binding-object-diagnostic.json`
(SHA-256 `6fc53bb12ba8cfeae69d019178bac7b03766fe1f261d9766ff68bb2e86b45d2b`)
show sh2 saved-search GETs in the nobody, admin and wildcard namespaces all
returning sh1's captain URI. The local configuration endpoint and exact btool
stanza instead identified sh2 and reported `disabled=false`, `enableSched=0`.
These later reads do not prove the dispatch engine continued rejecting the
search; only the original dispatch was attempted. They expose a gap in the
purported all-member pre-dispatch proof. The [Enterprise 10.6 server.conf reference](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.6/configuration-file-reference/10.6.0-configuration-file-reference/server.conf)
documents saved-search proxying to the captain. The harness does not disable
that global behavior or rely on an undocumented `shc_local_only` parameter.

The revised transition gate keeps the same single configuration POST, then
reads the exact `/servicesNS/nobody/splunk_adm/configs/conf-savedsearches/{name}`
stanza independently from each member using the [documented configuration API](https://help.splunk.com/en/splunk-enterprise/leverage-rest-apis/rest-api-reference/10.6/configuration-endpoints/configuration-endpoint-descriptions).
Each response must contain exactly one named entry whose HTTPS origin equals
the requested client's origin and whose canonical escaped path equals the
requested stanza path. Its native `eai:appName` and `eai:userName` must be
`splunk_adm` and `nobody`. Native `disabled` and strict `enableSched=0|1` values
are normalized to the existing desired disabled/schedule flags, and the exact
local URI and normalized flags are retained. A captain/foreign origin,
different namespace/stanza or malformed/missing flags cannot converge.
All 91 offline distributed-tooling tests pass, including captain-proxy,
individual-member lag, exact local identity/namespace, malformed native flags,
deadline, durable retry and HTTP400-without-redispatch regressions.

This is a bounded local configuration proof, not an atomic dispatch-engine
guarantee. The full wall-clock budget still covers requests, response bodies
and parsing. Dispatch uses the actual packaged saved search through the
assigned different members exactly once; rejection still fails. Neither
HTTP400 alone nor a lost response clears an unknown SID or authorizes a retry.
The failed Attempt09 record remains retained separately from Attempt10.

Attempt10, task `adm-shc-01a14f65-10`, used source22
`7fc04abbda74b2840174fe4a305220dae7237873` and the unchanged candidate09 archive.
Bootstrap passed in 844.253 seconds. During bundle application, sh2 PDL failed
to connect to the local PostgreSQL primary proxy at `127.0.0.1:5433`. It later
recovered automatically; all three members became ready and bundle verification
passed in 926.492 seconds at `2026-10-19T02:08:29.491237Z`. A proposed member
restart's precondition refused because KV was already ready, before any restart
marker or mutation. No manual restart, KV reset or configuration change occurred.
This remains observed bounded platform behavior, not an availability guarantee.

Peers, both original interface cases and all 15 collections then passed.
Identity and Service binding writers completed successfully with local member
configuration readback. Interface inventory reached `DONE` but reported
`Found no results to write to collection`, with zero matching inputs and zero
stored interface rows. The retained read-only job capture is
`dist/final-qualification/shc10-base-job-diagnostic-01.json`. The original two
interface cases insert a temporary KV probe to test lookup locality; they do not
populate raw NX-OS inventory. The ACI-only fixture contains no NX-OS events.
Standalone `test_aci.py` runs this same empty writer, but its lab helper rejects
ERROR/FATAL rather than WARN; that does not satisfy this harness's stricter gate.
The original base phase failed at `2026-10-19T02:22:23.760001Z` after 657.05
seconds. Its 50 original evidence records are retained in
`dist/final-qualification/shc10-failed-prefix-evidence.json` (SHA-256
`03dd158df78dac98239994f7ee357093594e59dc05d1a03fdffafb1cfd496ecb`).
The final failure export subsequently retained 57 verified files, including all
50 original records and cleanup of the five owned containers/network at
`2026-10-19T02:30:13.987706Z`. Final archive SHA-256:
`626217006eb730335acdb09902dffeb75312d2656a6b9f9f8418dd6700c4473e`.
Independent review verified both precleanup/final archives, exact original
bytes, ownership and continued failed/incomplete classification. The old owner
session closed before Attempt11 acquired its lifecycle locks.

The correction retains the warning rejection and requires the positive NX-OS
fixture/oracle above. Terminal WARN/ERROR/FATAL or failed/cancelled search states
now leave the job polling loop and fail immediately, retaining the known SID and
sanitized terminal status; ordinary incomplete healthy jobs continue polling.
Result warnings still fail. None of these outcomes triggers another dispatch.
All 99 offline tooling tests pass, including missing/altered fixture and overlap
preflight, exact two-row all-member inventory, 963-event classification, and
prompt terminal warning/failure regressions. The current Attempt10 source is not
modified. Review57 cleared this source correction; Review59 verified source23
transfer and the failed-run exports. Attempt11 subsequently failed bootstrap
readiness as recorded above; no application phase was executed. Its 31-file final failure export preserves all 24 original records, including
the executed restart, and exact five-container/network cleanup at
`2026-10-19T03:07:31.204705Z` (4.177 seconds). Final archive SHA-256:
`2c9f7f553544d3beed9b60fe65ce1ba21a25455a0808c540306079f32c1f6cfb`.
Review63 independently verified both exports and cleanup. The readiness-only
retry change passed 106 offline cases and independent review61. Attempt12
used `79c18ce8f3b63aee657ab12a6a3a7705504d8086` with 144 verified inputs,
but the EC2 host was terminated from the AWS console at
`2026-10-19T03:13:15Z`, closing the controller during bootstrap. Its CLI
acknowledgment at `03:12:54.245993Z` is not a readiness pass; no application
phases ran. Local owner responses/runtime/acknowledgment and EC2/CloudTrail
records survive, while the original remote evidence snapshot was not exported
before termination. The lost controller cannot use the same-controller retry
contract. The authorized new host's Attempt13 subsequently failed the exact
base-classification oracle; its retained exports and cleanup are recorded above.
This does not change Attempt11's failed result.

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

After cleanup, request `{"phase":"manifest","rerun":true}` and require its
actual `outcome=passed` response before the final export. A manifest command
without explicit rerun returns `already_complete` when a precleanup manifest
exists; it does not capture the new cleanup evidence. Preserve any rejected
export attempt and verify the final archive against the original precleanup
bytes before releasing the controller.

No authorized Splunk Cloud test stack/access has been identified. Cloud
installation, capabilities, shared persistence, searches/builders, browser
behavior and cutover operations remain unverified. AppInspect is a separate
package check and cannot close that deployment gate. The final release report
must retain this exact missing-environment boundary until actual supported
Cloud execution is available.
