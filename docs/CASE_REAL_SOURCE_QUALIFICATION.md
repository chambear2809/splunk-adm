# Native real-source capture qualification

A bounded installed real-source capture and configuration-withholding exercise
passed through the current supervised transport on the authorized native Enterprise
10.6.0.5 / Atlas 0.9.11 lab. It covers one existing administrator's source access
and the specific historical source and windows below. Non-admin real-source
revocation, complete collection and production readiness remain unqualified.
Shipped persistence and capture defaults remain disabled.

Read-only inventory on the authorized Enterprise 10.6.0.5 search head found
an enabled current identity profile for `k8s-01.uktme.cisco.com`, environment
`lab`, scope `uktme-k8s-lab`, producer `uktme-atlas-identity`, and namespace
`tenant-jobs`. Its identity feed is `atlas_identity`, source
`atlas:identity:uktme`, sourcetype `adm:pod_ip_interval:v2`; its span feed is
`otel_traces`, source `atlas:k8s:uktme:tenant-jobs`, sourcetype `otel:traces`.
The retained profile configuration SHA-256 is
`1e7d289037f437f48bc1cc48c2d6003a2b3298d63b1eeac7632e2754677e948e`.
The identity feed's latest observed event was 2026-11-16 16:03:56 UTC and the
span feed had events on November 18. Inventory alone does not prove historical ownership, complete source coverage,
or entitlement for another investigator. The bounded installed observations
below provide only the stated evidence for this selected case. The
[lab collection record](operators/local-access-and-tenant-jobs.md) describes a
memory-backed retry queue; delivery loss and lateness are not bounded by that
record. Unknown loss is not zero loss, and an indexed-time horizon is not proof
of complete collection.

## Installed results — 2026-11-18

The frozen 0.9.11 archive SHA-256 is
`0a87171ca77fbeedc778844fb326e523f7c427920ea36dcd4fc4cd54cb62bc7e`.
The native x86_64 target verified the server identity, Enterprise version and
all 88 installed runtime hashes. The selection was `coreapi` in `tenant-jobs`,
environment `lab`, on `k8s-01.uktme.cisco.com`, with windows 2026-11-16
15:55–15:56 and 15:56–15:57 UTC. The comparison had four useful graph rows.
Its identity context names `uktme-atlas-identity`, scope `uktme-k8s-lab`,
contract `qualified_v2`, and producer configuration revision
`0b0d18412ba0d8c424ca1d0abe7603612edd66a48a9501eb82d6a288208266fc`;
the context agrees with the independently retained catalog observation. That
agreement is not proof of complete producer history or lossless collection.
The windows reported 87 and 90 spans excluded because scope, clocks, or finite
ownership could not be qualified. The result explicitly does not establish
network traffic or an ACI path. The row/byte limits are 2,000 and 524,288 per
window; the collection's memory-backed queue leaves loss and lateness unknown.

The first attempt remains **failed_or_uncertain**. Selected stored read,
selected export and exact original capture retry were visible under current
access, and all three withheld the capture when the identity profile was
disabled. Re-enabling the profile through its configuration API changed the
identity file bytes and the next selected read withheld the capture; the
attempt did not pass its restored phase. Final cleanup restored the exact
original configuration and administrator roles. Its independent postcheck
passed all 11 checks and found 13 bound jobs in the conservative administrator
sequence-range superset terminal with native SIDs absent. The failed primary
receipt is retained unchanged.

The independently reviewed second attempt used a separate task directory. It
verified the identity file's original bytes, owner, group, mode and nanosecond
modification time immediately before disabling the profile, then restored those
exact bytes and metadata while case persistence remained enabled. Selected read,
export and the exact original retry were visible before the change, withheld
during the change, and visible after restoration with the original configuration
fingerprint. The two attempts produced the same canonical evidence digest
`3f749c656afab7c0a56369437226c88e4e2cc397c9b1b49a7050685d73bf31e8`.
This is reproducibility evidence for these exact observations, configuration
and windows; it does not establish completeness or future reproducibility.

The exercise used the existing administrator's source authority and added only
a temporary investigator-capability role; it made no real-index grants. All
cleanup flags passed and the independent postcheck passed 11 checks: the exact
task case was absent, the two app-local configuration files and administrator
roles were restored, the temporary role was absent, source role definitions
were unchanged, the service was active and the gates were disabled. All 17
bound SIDs in the conservative administrator sequence-range job superset were
terminal and absent. That superset is not an ownership claim over other admin
jobs; no owner-wide deletion was performed. Audit and retry identities/digests
are retained; owned case deletion clears protected response snapshots,
and API absence is not a claim of physical data erasure. Existing administrator
access does not qualify non-admin real-source authorization or revocation.

Private evidence is retained outside Git under
`atlas-recovery-qualification`: `source-installed-output.json` SHA-256
`91283b359769eb147523ed064007d6b2a2eb984acbd4b3628ad9c8c52847c4ef`,
`source-independent-postcheck.json` SHA-256
`1c4c76c79ca9f279b717b63fbf043e732dddafaf1d44e650c7d6966a86e20023`,
`source-attempt2-installed-output.json` SHA-256
`411cddc6c3f6c3768fd096a96f26328b0eb9e4a9a5a615e5c19f984a6932a568`,
and `source-attempt2-independent-postcheck.json` SHA-256
`620da76757d6844c1462b65f77abf4a889f266550114aa0e4b214ab72276c8dc`.
The source catalog receipt is `catalog-output.json` SHA-256
`24ef3302d5c3d2a942a3ab1c076b34109dcadeafd655622f92657778a0111b92`.
These private artifacts contain source details and must not be copied into Git.
Cloud/SHC, source-backed Web/CSRF, real-source non-admin revocation,
complete-source or historical audit producers and production operation remain
unqualified.

## Installed request tool

`tools/qualify_native_real_source.py --installed` is a narrowly scoped native
request primitive, not a complete rehearsal or an authorization grant. It reads
one bounded JSON command including credentials from **stdin**, checks strict TLS
on the local management port and the recorded server GUID, Enterprise license
group and version, and allows only case creation, capture, selected stored read,
selected export and exact original write retry. It makes no role, index, source
or configuration changes. A reviewed outer lifecycle must separately verify the
frozen 0.9.11 archive and installed hashes, effective caller permissions, source
profile and selection, enabled gates, process/job reconciliation, and exact
restoration and cleanup. In particular, the GUID check is not package attestation.
Do not invoke it until that lifecycle, caller, selected windows and target are
reviewed. No broad grants, real index modifications or source ingestion are
implied by this tool.

The native process must run as the Splunk service user on the exact target. It
creates `/opt/splunk/var/atlas-real-source-20261118` with mode 0700 and an
exclusive lock. Commands contain `username`, `password` and `action`; `create`
additionally contains a case `body`, `capture` a UUID `case_id` and capture
`body`, `read`/`export` the case and selected `capture_id`, and `retry` the
`original_operation` UUID. `body` shapes follow the current case API. Choose
actual comparable, ordered two or three absolute windows of at most five
minutes based on observed data, and retain the exact reviewed reference. Avoid
credentials in arguments, logs or shell history. The command may report an
operation ID and response status only; full responses and exact request bodies,
keys and caller identifiers are in its private journal and can include customer
data. Do not copy those into Git or chat.

Each request's intent is fsynced, including its exact body and key, before the
network dispatch; response records are synced separately. A missing or uncertain
response remains uncertain. New case and capture writes are refused while an
original write is unresolved; retry uses the original body, key, path and caller
from the journal. Even a returned non-2xx response does not automatically prove
that a write was not committed. Reconcile it with the exact retry and retained
store/job evidence. An incomplete final journal record is retained byte-for-byte
in a private, synced quarantine file before the intact prefix is repaired;
non-final corruption is refused. The quarantine and its recovery marker remain
evidence and do not establish a missing response. Never replace an uncertain
write with a new key. The tool
makes no cleanup or job-retirement claim and retains its private journal.

For a real-source exercise, observe selected stored reads, selected exports and
the exact original capture retry before, during and after a reviewed source
configuration change. Also test the same operations under an actually verified
permission revocation/restoration if separately authorized and feasible, without
granting new access to real indexes. Existing administrator access is not
proof of non-admin entitlement or revocation. If those tests cannot be safely
performed, report them as unqualified; synthetic revocation evidence does not
fill the real-source gap. Record changes and restoration byte-for-byte and
verify effective state, host and all owned source jobs. Retain cases, audit and
retry history until reviewed reconciliation; deletion or physical erasure is
not assumed.

## Offline evidence check

`python3 tools/qualify_native_real_source.py /private/path/summary.json` checks
consistency of a bounded private JSON summary. A zero exit means only that the
summary is **structurally complete and unverified**; it does not verify source
truth, authorization, digests, producer evidence, raw response content, or
cleanliness, and is never a qualification verdict. A nonzero exit returns named
gaps without printing private values. A single record must contain `source`,
`entitlement`, `coverage`, `windows`, `capture` and `phases` objects as required
by `check_summary`. Evidence fields are SHA-256 references to retained private
artifacts, not substitutes for independent inspection. Coverage fields accept
explicit documented unknowns and do not turn unknowns into completeness.

The five required phases are `allowed`, `permission_revoked`,
`permission_restored`, `config_changed`, and `config_restored`. Each records an
effective-state evidence digest and `stored_read`, `selected_export`, and
`original_retry` observations. The changed/revoked phases require withholding;
the other phases require visible evidence. Every observation requires a
completed dispatch and private response evidence digest; reads and exports bind
the selected capture, and retries bind the exact original body, key, path and
caller digests. Uncertain dispatches, missing phases, unmatched selection or
changed retry identity remain gaps. Inspect the referenced artifacts, warnings,
actual job lifecycle and configuration revisions independently before any claim.
