# Offline native recovery admission building blocks

These primitives do not launch, restore, delete, reserve space, authenticate an
approval, or establish operational qualification. They are not integrated into
any native launcher. Failure or an unavailable observation must stop admission;
exceptions, including OS errors, are refusal. Never use these primitives to
justify mutation until the complete launch chain and its enforcement have been
independently reviewed.

`admit_packet` accepts an independently trusted exact name-to-SHA256 map and an
already-open private directory. It checks every named byte, exact inventory,
private directory ownership, single-link root-owned (when called with UID 0)
mode-0444 regular files, and stable descriptor and path metadata. The caller
must enumerate **all** executable code: entrypoints, root launcher, monitor,
controller, observer, witness, imported modules and interpreter/runtime and
installed app dependencies as applicable. Separately bind the actual interpreter,
import paths, package bytes, trusted digest provenance and environment; an
attacker-controlled manifest is not authority. Directory and file descriptors,
trusted directory ancestry and immutability through use remain caller duties;
post-checking a pathname cannot prevent a replacement after admission. The
private lease monitor's fixed module manifest covers its listed worker inputs,
but does not by itself bind the root outer launcher, monitor and their entire
execution and dependency chain.

`charge_tree` counts all entries, including database, WAL, shared-memory,
auxiliary and stale files, at the larger of apparent and allocated bytes. It
rejects links, special files, device crossings and observed changes. By default
it also requires Linux procfs mount IDs on the root and every opened entry and
rejects different mount IDs, including same-device bind mounts. Missing mount
identity is a refusal. The explicit portable opt-out checks devices only and
is not sufficient for native admission; a separate mount gate is then required.
Scanning requires a bounded, quiescent, complete set of task roots. `Capacity` retains a
process-local high-water mark, adds the full proposed reservation, and checks
both task budget and filesystem reserve. The caller must include every retained
root and other charged artifacts once, preserve a trusted durable high-water
across restarts, and independently observe free bytes. These scans and checks
are not a hard quota and cannot bound concurrent writes or the interval after a
monitor failure. No launch is admitted on the basis of stale estimates.

`Lease` checks a single in-memory nonce, monotonic deadline and ordered
new/admitted/active/retired transitions. It is not a durable lease, replay
registry, heartbeat, or fencing mechanism. The caller must durably bind the
nonce to boot identity, exact generation, deadline, lock and dispatch journal,
reject replays across restarts, and retain uncertainty. `verify_inherited_lock`
is Linux-specific and requires a direct parent with recorded start ticks, same
named inode and a shared observed exclusive flock in procfs plus independent
contention. It does not validate the lock's trusted ancestry or owner, prove
all competing actors honor it, or stop the parent releasing it immediately
after observation. Recheck while the lifecycle is active. The Linux process
and mount checks require native Linux tests; the local macOS tests are skipped.

The historical receipts show 27.197522 seconds for the first unit from its
monotonic start and exit; the second unit's classified journal started at
3232512018609 and stopped at 3232580233412 microseconds (68.214803 seconds);
the third unit's monotonic start and exit differ by 86.522156 seconds. Rounding
up separately gives 28 + 69 + 87 = 184 seconds, excluding any other allocation
usage. The last reported task charge is 17,014,624,256 of 17,179,869,184 bytes.
A 144 MiB observer reservation alone leaves 14,249,984 bytes of task headroom;
this estimate is not a current scan or a safe launch allowance. No new
allocation or launch is assumed safe.

## Exact-owned custody plan, not an execution instruction

Under the lifecycle lock, independently identify the host and boot, original
service, every task unit and process by invocation, PID/start ticks, cgroup,
executable and namespace, and require recorded task processes and I/O to be
retired. Inventory each retained raw tree and existing archive by exact path,
device/inode, ownership, mode, allocated and logical size, and digest; include
partial archives, journals, manifests and credentials in protected custody.
Preserve the uncertain receipts and all raw bytes. Confirm the storage budget
covers the entire additional archive, verification workspace, sidecars and
failure margin *before* creating anything. A mere move within the filesystem
does not reduce charge. Create any approved archive in a fresh protected
no-replace location, retain durable intent, verify every entry and metadata
against the independently sealed inventory with a separate reader, and prove
recovery access with an appropriately isolated verification. Retain the archive,
source, and all partial results whenever a check or outcome is uncertain.
Deletion of exact owned raw trees is not admitted by these primitives. Existing
task-only cleanup authorization still requires a concrete per-inode plan and
independently verified custody and retirement; never recursively delete by broad path or use a partial
archive as proof.

## Read-only native preflight packet

Before asking for any new execution, independently bind the current host key,
instance and boot identity, original service invocation/PID/start ticks and
selected protected-state baseline; exact retained task roots, ownership and
capacity/free-space observations; prior unit identity and complete retirement;
all packet/interpreter/import digests and trusted manifest provenance; lock
owner and direct parent; fresh one-use generation, deadline and durable journal;
complete database/WAL/auxiliary/high-water accounting; exact cleanup and
custody ownership; and native version/license/topology/ports/TLS facts without
reading credentials into evidence. Inventory actual installed app collection
stanzas, SQLite stores and task indexes, and reconcile all uncertain dispatches.
No source credentials, live source changes, archive creation, service start or
cleanup belongs in this read-only packet.

For Splunk Enterprise 10.6, determine the actual KV engine and establish both
KV status and backup/restore status ready. Splunk documents that parallel backup
is not point-in-time consistent and cohosted PostgreSQL (`type:Pdl`) cannot use
point-in-time backup. Thus externally established writer quiescence is a separate
gate. The documented parallel backup uses `-archiveName` without `.tar.gz`;
restore names the `.tar.gz` archive, and collection definitions must exist in
the same app before restore. See [Splunk KV backup and restore](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.6/administer-the-app-key-value-store/back-up-and-restore-kv-store).
For indexes, active hot buckets cannot be ordinarily backed up; determine the
supported shutdown, roll or snapshot procedure and warm/cold bucket treatment
before proposing any action. See [Splunk indexed-data backup](https://help.splunk.com/en/splunk-enterprise/administer/manage-indexers-and-indexer-clusters/10.6/back-up-and-archive-your-indexes/back-up-indexed-data).
These documentation facts do not prove source consistency or a valid restore.


## Native primitive observation — November 19 continuation

A separately reviewed immutable packet ran the exact public module and its ten
tests on native Linux x86_64 under the host's `/usr/bin/python3.12`; all ten
passed with no skips. The two Linux-only checks exercised actual procfs mount
IDs and a direct parent's inherited exclusive flock, followed by refusal after
unlock. This is native tool evidence, separate from Splunk's installed Python
3.13, application API acceptance, complete launcher integration and restoration.
The packet reserved 1 MiB under the held lifecycle lock, used a fresh protected
task-only stage and bounded process-group supervision with original-service
checks. It retained 36,864 allocated bytes of test inputs; temporary test scratch
was empty at completion. The new aggregate was 17,014,661,120 bytes. No isolated
Splunk instance started, so this did not consume additional instance lifetime.
The existing failed bootstrap and compaction outcomes remain unchanged.

The independently reviewed current-state observation before testing verified
unchanged original protected records and all 88 runtime hashes, pinned custody
metadata and mount IDs, and two clean 442-process samples. It did not repeat
archive-content verification. The native test result and a separate postcheck
are recorded append-only in `FEATURE_QUALIFICATION.json`; retained input stage
and all earlier custody remain charged. These observations neither admit a
source launch nor qualify a full operational restore.
