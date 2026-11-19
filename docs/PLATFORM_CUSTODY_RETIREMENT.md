# Exact-owned custody retirement

Current result: the exact archived tree was retired and independently reconciled;
see the final section below. The candidate and capacity sections preserve
chronological pre-execution snapshots. Their pending-action statements describe
those earlier points, not the current result. Operational restore remains
unqualified.

## Initial offline candidate — pre-execution snapshot

**Not admitted for native execution.** The primitive is an offline candidate;
it is not an executable packet, complete guard chain, hard resource limit, or
proof of a restore. It calls the corrected archive verifier, not the prior
writer's `verify_complete`. It requires an independent verifier receipt and
separately trusted archive and manifest digests, then repeats the full source,
archive and manifest comparison before it writes an intent. Its caller supplies
all identities and must independently authenticate these inputs; a receipt or
digest from an untrusted caller is not authorization.

The journal must be a new, empty, mode-0600 single-link file in a private
mode-0700 directory. The function checks named identity, calculates the exact
maximum journal bytes for the manifest before mutation, refuses a reservation
above 64 MiB, writes and fsyncs the overall intent and each entry intent before
removal, and fsyncs each parent and completion record. An interrupted operation
can leave a partially removed tree or an intent without a completion: retain
both journal and remainder, do not retry blindly, and independently reconcile
against the sealed archive. An optional paired transition lock and callback let
a cooperating watcher observe the source-present to source-removed transition;
the callback runs immediately after successful root removal under the lock. A
callback or subsequent fsync failure may still leave a removed root without a
completion record and requires reconciliation. It opens descendants relative to held directories,
checks no-follow metadata, mount identities, xattrs and symlink targets, and
refuses unexpected inventory. A stale or hostile manifest is rejected by the
corrected verifier before deletion. Directory metadata necessarily changes as
children are removed, so only stable ownership/identity attributes can be
compared after traversal.

There is a critical remaining gate: Linux does not offer an inode-conditional
`unlinkat`. A separate actor able to replace a name between final inspection and
unlink can cause removal of a different entry. A trusted lifecycle lock does not
by itself exclude an actor that ignores it. Therefore this candidate cannot be
used until an independently reviewed control establishes **exclusive control of
the complete source namespace throughout verification and retirement**, including
all principals capable of rename, mount or write and all task processes, and
binds the same protection to the live guard. Keep the original service and all
other state outside that control. This control is not implemented here. The
per-entry guard is caller code; it must fail closed on uncertain original-service
identity, task retirement, lock, mount, capacity, journal, archive or process
state, and must be bound with the verifier, Python interpreter, imports, all
executables and settings in the reviewed execution packet. Neither an in-memory
callback nor a prior receipt alone establishes any of those conditions.

The proposed target is solely the stopped second-attempt `canonical-state`
under its exact recorded parent, device 2050, inode 6588437, UID 61397 and mode
0700. Bind its parent and name as well as the root, boot identity and the sealed
archive directory device 2050/inode 6588752, independently pinned full archive
and manifest digests and sizes. Recheck the archive and manifest by descriptor,
verify actual source content afresh with the corrected verifier, and keep that
verified custody accessible outside the removed tree. Preserve the archive,
manifest-only partial, all failed primaries, operation journals, credentials,
TLS and private recovery access; verify which exact protected custody holds the
keys before action. Archive fidelity does not prove a logical SQLite/KV backup,
recovery of identity or platform restore. The prior full comparison is a
historical observation, not an authorization to delete now.

The last recorded aggregate is 17,014,661,120 bytes against 17,179,869,184,
leaving 165,208,064 bytes. A proposed 64 MiB journal and small input reservation
would leave at most 98,099,200 bytes before input, evidence, metadata, other
writes and independent free-space floor. The observer's separate 144 MiB
reservation is not used in this packet. These are historical arithmetic, not
current measured free space, allocated-block accounting, a quota, or a safe
admission. Before any packet is considered, calculate exact serialized journal
size from the trusted manifest, conservatively reserve filesystem blocks and all
input/output/guard/witness overhead, measure current complete aggregate and
filesystem headroom under the lock, and enforce a reviewed stop/retirement
boundary. No new instance is assumed safe.

Tests use actual temporary trees and check successful traversal, replacement
refusal, interrupted partial state, hostile manifest, pin and journal capacity
refusals. Local macOS tests patch Linux-specific verifier mount, no-atime and
xattr checks; they do not qualify native Linux behavior. Independent review,
full Linux tests, and a separately bounded native packet remain outstanding.
No cleanup or fresh restore is performed by this work.

## Subsequent observations and capacity follow-up — pre-execution snapshot (19 November)

The earlier candidate limitations and historical measurements above remain part
of the record. A later native Linux synthetic run exercised three positive,
refusal and interrupted-partial cases with the pinned retirement library
`f7f5d6f8a292d89e61b1e29ac61ee4a19208fa006b9f8239c7e173445504d943`.
That run passed; it did not retire retained raw state or demonstrate a restore.

Preflight attempt 2 failed or was uncertain during independent verification
with the generic `live_guard_unavailable` result; its particular guard predicate
was not established. A separate read-only reconciliation observed all 38,587
source entries matching the retained manifest, the exact archive, the original
baseline and 88 runtime files, retired controller and verifier, and zero journal
bytes. It preserved the failed primary; it did not prove the historical cause or
authorize a retry. Revised preflight attempt 4 subsequently validated the
integrated controller without removing the source. Independent postcheck attempt
3 observed the source fully present, the same 38,587 entries, zero journal rows,
four protected access records, retired registered processes, the original
baseline and 88 runtime files. The failed attempt remains a separate failure.
These are point-in-time observations, not continuous global process exclusion.

The separate frozen actual-retirement packet is prepared only. It targets the
canonical-state entry at device 2050, parent inode 7088895 and source inode
6588437, and pins the archive SHA-256
`73459275aae5120eefd308de282fad97ae6c1ca8f2af387b7592b2fcca7920fc`
and manifest SHA-256
`46c1e469945d7ae6cb623877a80103db0b2f1496850e8e4b0e87840b3246cd37`.
It has not been cleared or dispatched by this documentation work. Its guard,
controller and verifier are pinned in the packet, which relies on trusted host
administrator serialization and has phase-boundary process proofs rather than
continuous global process absence. A successful preflight does not establish a
completed retirement or substitute for current admission and independent
post-action reconciliation.

The latest postcheck measured 17,014,824,960 bytes against the unchanged
17,179,869,184-byte task budget. Assuming the full 4,340,588,544-byte canonical
measurement is reclaimable, and charging the packet's 65 MiB reservation,
leaves 4,437,475,328 bytes. The distinct current private source alone measured
5,502,337,024 bytes and remains unarchived and untouched; a comparable fresh
source would exceed that remainder by 1,064,861,696 bytes before further
inputs, backup, restore, evidence, metadata, or growth. This is a planning
comparison, not a guaranteed reclaim or a fresh-source size bound. A measured
post-retirement aggregate, allocated blocks, filesystem floor, transient peaks,
and reserve for all phases are required before any admission.

The prior attempt-1 input, attempt-2 noncanonical portion and root input each
measure roughly 1.786 GB in the frozen capacity plan. Their apparent similarity
is not proof of duplication, independent custody, or safe deletion. A separately
reviewed read-only inventory must bind every candidate's parent and entry,
device/inode, ownership, mode, link count, allocated blocks, mount, inventory,
content hashes and provenance to retained independently verified inputs and
failed-attempt evidence. Account for shared hard links and dependencies, and
identify which copies and access material must be preserved. Only after that
and a distinct narrow review could any additional retirement be considered;
credit no speculative bytes. No budget increase is assumed.

A viable future rehearsal also needs an integrated reviewed lifecycle, not just
these custody observations: all 15 KV collections, all four SQLite families
and sidecars with consistent backup, index data, configuration, authentication,
CA and GUID/identity, version and license must be captured and restored and
independently checked. The external `platform_source_phase.py` explicitly
returns a pre-backup observation, and `platform_source_capture_fixture.py` is
a draft fixture; `platform_source_controller.py`, lease monitor, witness and
outer registry are components, not an admitted end-to-end restore packet. Their
barrier, durable journal, observer, writer retirement, backup, stop, target
restore and validation integrations must be reviewed and exercised together.
The cumulative 184 seconds already consumed and 15-second stop reserve leave
at most 2,501 seconds, or 41 whole minutes, within a 45-minute limit; prove a
bounded phase schedule and enforcement before dispatch. No full platform
restore is claimed.


## Exact action and independent reconciliation — November 19 continuation

The one-shot cleanup packet was separately cleared and executed after the
successful revised preflight and its independent postcheck. It retired only the
archived second-attempt `canonical-state` directory, device 2050/inode 6588437
under parent inode 7088895. The archive directory remained sealed with exactly
its original manifest and archive; new control, independent receipt and removal
journal were retained outside that custody.

The separate post-action observer verified 77,175 exact postorder records for
38,587 manifest entries, source absence, all six control states and registered
PID/start retirement. It rechecked archive contents and manifest, the four
recovery-access records, selected original protected state and all 88 runtime
hashes. Clean postcheck samples counted 438 and 437 processes, with every
adverse counter zero. The failed preflight and all earlier failed bootstrap and
compaction primaries remain unchanged.

Fresh aggregate native task storage is 12,686,090,240 bytes, down
4,328,734,720 bytes from the action's 17,014,824,960-byte baseline. Its
11,836,308-byte journal and all other retained state remain charged. Remaining
headroom is 4,493,778,944 bytes against the same 16 GiB budget. This is a
point-in-time cooperative measurement after source descriptors closed, not a
hard quota or a fresh-instance admission. It remains below the distinct
5,502,337,024-byte failed tree before additional backup, observer and restore
cost. The separately prepared progress snapshot was not executed because the
primary had already completed.

No source/index/KV backup, extraction, restored target, original-service restart
or additional Splunk instance occurred. Byte custody and this exact cleanup
passed; logical recovery and operational platform restore remain unqualified.
Exact primary/postcheck/packet hashes are recorded under
`native_custody_retirement_20261119` in `FEATURE_QUALIFICATION.json`.
