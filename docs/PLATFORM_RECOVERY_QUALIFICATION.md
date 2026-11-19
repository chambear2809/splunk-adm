# Platform recovery qualification: preparation and boundary

**Status: not operationally qualified.** No fresh native platform has been
restored by this increment. The existing native endpoint test uses an injected
isolated route; it does not restore a platform. The earlier eight-collection KV
rehearsal and cold paired-case rehearsal have different scopes and cannot be
combined into proof of complete platform recovery. Local Docker is ARM64 and the
existing AMD64 supervised-helper behavior under emulation is unsupported; it is
not a substitute for a native installed run. A read-only probe found native
x86-64 capacity on the existing host. The user approved the bounded isolated
environment and packaged license acceptance on the condition that the original
Splunk service remains active. The first bootstrap attempt failed before its
new Splunk daemon started; it is retained as `failed_or_uncertain`.

The independent read-only reconciliation verified the exact failed unit's
retirement, original service identity and selected protected state, retained
input hashes and journals, and absence of the task source home, TLS material,
secret and success result for the first attempt. The original service remained active with the same
PID, start ticks and invocation. This establishes the observed bootstrap failure
boundary; it does not qualify a restore or uninterrupted production behavior.
The first failure occurred when a no-follow directory operation encountered
systemd's legitimate relative StateDirectory alias. The reviewed retry passed
live verification of the exact service-visible directory mapping, dynamic UID,
private network namespace, cgroup controls, read-only mounts and original-home
mask. Its native setup still ended `failed_or_uncertain`: the driver retained
`source_create_ack` and `start_intent`, but no readiness/result receipt. The
supervisor acknowledged the exact owned-unit stop; independent checks found
the original driver absent, the cgroup empty and the unit absent. The selected
original-service baseline remained byte-identical. The retry's precise failure
predicate has not been established; a prior invocation's journal error must not
be attributed to it. Source home, TLS and private credentials remain retained
for reconciliation.

A third, separately reviewed instrumented attempt reached authenticated native
server information and recorded a Trial license, then failed the fixture's
daemon-identity cardinality check. Its stop command acknowledged completion,
but the immediate process-retirement flag was false. Later independent host
checks found the unit failed with MainPID zero, no cgroup processes, the old
driver absent, and no process matching the task binary inode, executable path,
cgroup or private network namespace. The scan inspected 433 process records
with no errors or disappearing records; the original protected baseline still
matched. These observations establish contained fixture retirement, not an
invented historical daemon PID or proof of graceful shutdown. All three primary
outcomes remain `failed_or_uncertain`; no native readiness or restore pass is
claimed.

Aggregate retained task state, custody and input archives occupy
15,203,082,240 bytes against the 16 GiB allocation. A fourth fresh installation
is held because it would exceed that aggregate budget. A proposed private
archive-and-verification step must preserve all failed-state bytes and recovery
access before any exact owned raw-tree cleanup; it has not run. Moving a tree
into custody does not remove its disk charge.

`tools/qualify_platform_recovery.py` offers a separate offline inventory and
fresh-directory staging primitive. It verifies eleven fixed component files,
private ownership/mode, bounded sizes, a package digest and a canonical manifest
against a separately retained digest. Unsettled dispatched operations, missing components,
changed bytes, links, an occupied target and partial retry are refused. A failed
copy retains its new directory and journal. This primitive handles opaque
artifacts: it does **not** create a Splunk backup, authenticate a manifest, prove
quiescence, validate the completeness of exported state, restore Splunk, or
qualify an operational recovery. Its `operational_restore_qualified` value is
always false. The separate trusted digest protects against corruption only when
retained through an independent trusted channel.
The inventory gate rejects unsettled dispatches; it does not require erasing or
resolving a known uncertain ledger row. Future restore evidence must preserve
such rows exactly, including their quota effect.

The same tool also contains a cold four-database backup adapter for a fixed
private fixture export. It refuses sidecars or unexpected files, checks trusted
schema descriptors and SQLite integrity, creates a fresh destination, and
compares schema and logical rows. Its caller must separately establish that
source writers and processes are retired; it does not establish quiescence.

The non-executing native launch renderer checks the fixed root-owned read-only input stage, pinned
Splunk and Atlas archive digests and a separately supplied driver digest. Its
proposed transient service uses a private network, an inaccessible existing
Splunk home and optional masks for the named system-bus, Docker, and containerd
sockets, a transient non-root identity distinct from the existing service and a
root-protected systemd private state directory, 4 CPU, 8 GiB, no swap, 1,024 tasks and
up to 45 minutes. The retry budget conservatively deducts the observed first
unit's lifetime and reserves a bounded stop grace. Configured termination
deadlines do not prove process retirement; that requires the independent
postcheck. The renderer does not execute
systemd, establish kernel enforcement or verify the driver's behavior; the
native lifecycle remains blocked until those properties and every actual adapter
are independently reviewed. A private network limits host exposure, but the
driver must still check loopback listener identities and TLS trust.

A narrower bootstrap is being prepared before any restore exercise. Its proposed
unit uses a temporary systemd identity, a root-protected private StateDirectory
and a root-owned, mode-0700 input directory at
`/var/lib/atlas-platform-recovery-inputs-20261118`. Only five fixed root-owned,
read-only files are bound into a task RuntimeDirectory: the pinned Splunk and
Atlas packages, manifest, reviewed driver, and an approval receipt. The driver
must observe a different UID/GID from the original service, no capabilities,
original-process signal-0 denial, inaccessible process root/file descriptors,
and a different network namespace before extracting or starting. An independent
host monitor must verify the live unit and an independent postcheck must compare
the externally sealed original-service baseline. The proposed start would
explicitly accept the packaged Splunk license; the user approved that concrete
action subject to the original service remaining active. The first unit failed
before live namespace attestation; later attempts passed that attestation but
did not produce a native readiness pass. The third recorded authenticated
server/license information before its fixture failure. Combined startup,
listener, retirement and recovery acceptance remains unqualified.

For bootstrap only, the proposed supervisor checks the task state size and
filesystem free space on a nominal two-second cooperative cadence and requests a stop of the
exact owned unit if state exceeds 16 GiB or free space drops below 12 GiB.
Scheduling can delay checks; this is a cooperative budget, not a hard filesystem quota: writes can exceed the
limit between checks or after an observer failure. A full restore requires its
own reviewed disk budget and enforcement. The named socket masks and selected
process checks do not establish absence of every host socket or alias.

## Cold restore packet — blocked pending independent launch review

The cold restore needs an independently reviewed executable snapshot, restore
and cleanup driver within the user-approved disposable native Linux AMD64
allocation. This document itself authorizes no new host, service, port, grant, or platform
mutation is authorized by this document. The existing shared native instance
and its live databases are not restore destinations. Identify a source and a
fresh destination by host key, instance ID, exact dedicated `SPLUNK_HOME`, UID,
filesystem device/inode, package hash, native architecture, and service
PID/start ticks before their first write. The target must be new and empty; no
in-place replacement or shared-index mount is permitted. Preserve originals and
stop on ambiguity. Acquire task-owned exclusive locks across the complete
lifecycle. Stop and retire only recorded task-owned services and processes; if
stop, identity, or I/O completion is uncertain, retain the resources and ask an
operator to reconcile, rather than force-start, overwrite, or broadly delete.

The non-secret launch packet must bind all of the following before approval:

* Exact host allocation and cumulative lifetime, isolated source and fresh
  restore generations with only one task service active at a time, native
  x86-64, Splunk Enterprise 10.6.0.5 build and
  package digest, installed Atlas archive digest, bounded CPUs, memory, disk and
  log retention, cleanup owner and cost. The target must have a valid permitted
  license and no shared production indexing/search peers, SHC or Cloud topology.
* Independently assigned, verified-free ports for management, Web, appserver,
  KV Store, IPC broker, six PostgreSQL sidecar ports and two Nascent ports, plus
  the separately configured HEC listener if used. Reserve source and target
  ports distinctly when instances coexist, pin management TLS and SSH host identity, and disable
  boot-start. Recheck bindings immediately before launch. The vendored
  `splunk-enterprise-host-setup` skill describes fresh side-by-side setup;
  its install phase starts Splunk, so it is not a read-only probe. Its current
  fresh configuration binds management to `0.0.0.0`; it does not satisfy the
  proposed loopback-only boundary without a separately reviewed pre-start adapter.
* Collision-checked task-only synthetic users and role grants, synthetic HEC
  inputs and bounded raw/summary indexes; no new grants to real sources. Bind
  every process, request, native SID and cleanup action to the specific task.
  Authentication and any session credentials stay in protected external files
  or memory, never arguments, logs, retained manifests, or Git.
* Explicit treatment of all 15 configured collection stanzas in
  `default/collections.conf`, including recovery state/audit and v2 catalog.
  The legacy eight-collection helper is insufficient. Determine the installed
  KV engine and verify its supported backup and restore procedure. For cohosted
  PostgreSQL (`type=Pdl`), point-in-time backup is unsupported; a parallel
  backup alone is not a consistency proof. Pause all writers and establish
  quiescence before snapshot, retaining supported backup provenance and
  recovery checks. See [Splunk's KV Store backup procedure](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.6/administer-the-app-key-value-store/back-up-and-restore-kv-store).
* Explicitly inventory the fixed app package and non-secret app configuration,
  all applicable platform configuration, task-owned source and summary index
  buckets, and four SQLite files: `$SPLUNK_DB/splunk_adm_baselines/` contains
  `baselines.sqlite` and `watch_runs.sqlite`; `$SPLUNK_DB/splunk_adm_investigations/`
  contains `cases.sqlite` and `capture_jobs.sqlite`. Quiesce writers, preserve
  SQLite sidecars or use a verified consistent backup, and restore the case and
  ledger together. Include unbound and other unresolved records as retained
  evidence, never silently clear them. Verify exact package/schema compatibility,
  owner, permissions, integrity, row state and application-visible behavior.
  Index copying must follow the [supported indexed-data procedure](https://help.splunk.com/en/splunk-enterprise/administer/manage-indexers-and-indexer-clusters/10.6/back-up-and-archive-your-indexes/back-up-indexed-data).
* Define identity recovery separately. Broad platform configuration copies can
  contain `$SPLUNK_HOME/etc/auth` and other secrets; do not copy or retain them
  in Git or an unreviewed evidence bundle. Privately retaining and restoring
  task-only credentials, keys and CA material requires explicit fixture custody
  and source/target authorization checks. Such a synthetic restoration does not
  qualify restoration of production authentication,
  keys, certificates, TAs, distributed peers, or external dependencies.
* Predeclare exact positive and negative checks: real endpoint readback for
  baseline and watch state; restored case, note, revision, ACL and capture link;
  original request body/principal/key and receipt; quota and unresolved ledger
  state; native source-job terminal state/404; full KV/index data comparisons;
  corrupted, incomplete and occupied-target refusal before target writes; and
  original live state unchanged. Record durable intents before every dispatch.
  Unknown outcomes retain the identities and credentials needed to reconcile.
* Independently verify preflight and postflight service identity, readiness,
  installed hashes, flags and resource ownership. After every request and worker
  is retired and all jobs reconciled, remove only the exact owned synthetic
  resources and credentials. Preserve private source, restore evidence and
  original failed receipts; never use broad cleanup or reset unrelated data.

Even if all of this proposed synthetic workflow passes, any omitted identity,
TA, source index, platform configuration or external dependency must remain an
explicit exclusion. A synthetic-only fresh-target result is not automatically a
production full-platform disaster recovery guarantee.

A planned cold restore may reuse the task's canonical home name only after the
source service and all owned processes have retired and the entire prior source
and TLS trees have moved into root-protected, no-replace custody. The restore
home must then be absent and created fresh; the retained source must be
inaccessible to the restore service. This does not authorize overwriting any
existing original-host home or adopting a partial target as a verified restore.
