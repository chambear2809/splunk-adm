# Current case source capture qualification

The current supervised source-capture path is **not yet qualified** by this
record. `tests/splunk/case_source_capture.py` is an opt-in synthetic installed
fixture, adapted from the earlier evidence scenario. Its existence or a local
unit-test pass does not show that installed capture, source revocation, recovery,
or access to real sources works. Native Linux/amd64 resource qualification is
also deferred. Shipped persistence and capture remain disabled; Cloud and SHC
remain unsupported.

## Disposable exercise

The fixture refuses all but task `cases-source-20261118`, lab
`adm-cases-source-20261118`, `ADM_LAB=1`, and the explicit
`ADM_LAB_SOURCE_CAPTURE=1` opt-in. Use ports 35000, 35089 and 35088 for Web,
management and HEC respectively. `tools/rehearse_case_source_capture.py` cleared independent prelaunch review
for the recorded disposable attempts. It holds the direct cross-worktree lab lock
through verified purge and requires a
local user-owned Unix Docker socket, pinned image
`splunk/splunk@sha256:9280f9ce267b212e5596aa1832cdfd3f9be886c378da35ebc87499323ee447a4`,
4 CPUs, 8 GiB without extra swap, 1,024 processes, verified loopback TLS, and
one container. Enforce a 45-minute execution lifetime and a 12 GiB host free
space reserve; sample the 4 GiB named-volume budget at each phase. Sampling is
not a disk quota and excludes the image cache, writable layer and logs. Cleanup
must identify the exact owned container, network, volumes, credentials and TLS
material, preserve private evidence first, and record uncertainty if cleanup
cannot be proven. Do not use broad Docker cleanup.

In that disposable container only, the fixture creates two short-lived users and
two roles with `search` and `adm_investigate`, no imported roles, and allowed
and default indexes exactly `k8s`, `otel_traces`, `cilium_hubble` and `netflow`.
Its synthetic HEC fixtures use the existing rollup interval, span and Hubble
builders. One role initially permits the fixture source and the other excludes
`http:atlas-lab`; the fixture changes those temporary filters to exercise
current caller source access. It checks effective role and caller contexts.
These roles, indexes and filters are not authorization to grant access on any
permanent or remote system. The fixture enables only the necessary identity and
case settings inside the disposable lab; the lab must be purged afterward.

Set `ADM_LAB_SOURCE_JOURNAL` to a new absolute path in a mode-0700 directory
outside the checkout. Before each case endpoint request, the fixture fsyncs its
synthetic body, request key, path, caller and dispatch state. Completed responses
are appended separately; credentials and authorization headers are omitted.
An unmatched dispatch remains uncertain: retain the exact operation identity
and do not infer failure or issue a replacement operation. The journal is private
and can contain synthetic evidence and case identifiers; keep it out of Git.
Record the archive checksum, installed runtime hashes, image/container identity,
TLS negative checks, role configuration, exact test result and final resource
absence separately. Capture and read/export/retry checks must show actual
supervised helper execution, not merely enabled flags or notes success.

The positive fixture, parent lifecycle and separate pre/post-commit capture
fault fixture passed independent prelaunch review. The fault work retains exact
request identities, checks known source jobs are deleted before commit
interruption, observes worker/group/descendant retirement and checks source
revocation on stored reads, exports and old retries. It does not exercise
unknown remote job creation or deletion outcomes. The reviewed startup
source/cache preservation transaction is reused unchanged; restoration attempts
are independent of installation acknowledgement and fault-disable success.

Two disposable attempts against frozen 0.9.10 are retained privately. Attempt 1
stopped at a transient TLS EOF after restart, before source checks. Bounded
trusted readiness polling was added; certificate rejection still fails
immediately and wrong-CA/wrong-host checks remain unchanged. Attempt 2 passed
install, TLS and runtime hashes, returned native indexed synthetic graph rows,
then received `available: true`, `evidenceWrites: false` from the handler before
its first capture. No positive capture or interruption test passed. Both
primary outcomes remain failed/uncertain; six cleanup checks were independently
verified. Prior Rosetta incompatibility with the unchanged 256 MiB address-space
contract is documented separately. This response alone did not identify the
readiness gate that failed in attempt 2.

The explicit `--expect-unsupported-helper` mode checks the installed negative
contract without synthetic index grants: helper preflight must fail closed,
notes must remain usable and no source-job ledger may exist. It records
`unsupported_helper_verified`, never a positive capture pass. The frozen
0.9.11 candidate (build 1795023134, SHA-256
`0a87171ca77fbeedc778844fb326e523f7c427920ea36dcd4fc4cd54cb62bc7e`)
passed this one installed test in 10.516 seconds. Its full lifecycle took
286.8 seconds; trusted, wrong-CA and wrong-host TLS checks passed before/after
installation, all installed runtime Python hashes matched, and all six cleanup
checks were independently confirmed. Receipt SHA-256:
`194151a368e16e0309c07032f92356e72c6cef8f6c61f2b2005e1912f26addb8`.
The positive capture/revocation/recovery scenarios remain unqualified on a
compatible runtime; this negative result cannot substitute for them.

After that recorded run, host-only journal publication was hardened by syncing
its parent directory before dispatch and syncing the runtime directory entries
before external operations. Focused failure/order tests and independent review
cover this follow-up; it was not included in that installed run's fixture
fingerprint. No application runtime bytes changed. The frozen archive contains
the documentation snapshot at packaging time; final records and later CI
archives are distinct. Neither test mode relaxes helper limits, TLS or
permission checks. Native amd64 resources, real-source behavior and production
readiness remain unqualified.
