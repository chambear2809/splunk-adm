# Investigation records and portable evidence

The incident workspace provides two explicitly separate workflows. Portable
records capture fixed graph comparisons and note revisions for download. Shared
cases store user-authored notes, hypotheses, questions and absolute time windows
through `adm/investigations`. An additional disabled-by-default mode can save
server-rechecked comparison evidence. Creating a case does not copy portable
notes or graphs. New cases are private; an owner can grant a named member read,
append and export access, revoke access, or delete the case through the API.
Case membership does not grant access to captured sources.

## Deployment boundary

`adm_investigations.conf` ships with persistence disabled and platform
unqualified. `adm_investigate` is a dedicated capability with no default role
assignment. The host derives the principal from the caller's current Splunk
context and rechecks it during store operations; it never requests system auth.
Investigator roles do not need administrator access. The local server process
checks the fixed SHC disabled setting without exposing configuration to callers.
It reads only the fixed app-scoped persistence control flags using local btool;
investigators do not receive configuration-read privileges. The fixed app/user
switches follow the [Splunk 10.6 btool documentation](https://help.splunk.com/en/splunk-enterprise/administer/troubleshoot/10.6/first-steps/use-btool-to-troubleshoot-configurations).

The candidate host is restricted to explicitly attested single-search-head
Enterprise 10.6.0.5, a known Enterprise/Trial license group, no positive Cloud
markers, and disabled SHC. Local storage cannot be shared across independent
search heads. Cloud and SHC remain unsupported. Passing synthetic tests does not
qualify another target or prove protected-source authorization.

The database is fixed under `$SPLUNK_DB/splunk_adm_investigations/cases.sqlite`,
with a private owner-only directory and file. Request data cannot select a path.
The host rejects uploaded graphs and arbitrary attachment files. Explicit links to same-case saved comparisons are supported only after source reauthorization. With capture mode disabled,
existing protected items are withheld while notes remain readable. An explicit
redaction count distinguishes withheld evidence from an empty investigation.

Protected capture also requires an explicitly configured local management peer
and its public CA in the app's effective `adm_investigations.conf`:

```ini
[capture_transport]
management_uri = https://127.0.0.1:8089
ca_file = /absolute/path/to/approved-public-ca.pem
```

The example URI is appropriate only if that address and port are the intended
local management endpoint and the certificate is valid for the IP address.
The supported hosts are `127.0.0.1`, `localhost`, and `::1`; configure the exact
peer and a hostname-matching certificate. The CA file must be an absolute path
to a regular, single-link file owned by root or the Splunk process user, not
group/world writable, at most 128 KiB, and must contain no private key. The host
checks the certificate, hostname, and server GUID against the hosting search
head. It does not accept peer or CA settings from the browser. A missing,
changed or untrusted peer disables source capture and rechecks; notes remain
available. This configuration does not by itself qualify a deployment.

## Rechecked comparison evidence

After separate target qualification, an operator may set
`capture_mode = reproducible_qualified_v1`. The browser sends only validated
selection arguments, two or three ordered absolute windows and a revision/key;
it never uploads its graph or source-access claims. Each window is at most five
minutes. This selects the raw `admqualified mode=graph` path, which avoids
owner-produced long-window summaries. Demo comparisons cannot initiate this
source capture.

This contract reads observations indexed by each window's end. Later arrivals
are excluded, and aggregate rows do not all retain an exact indexed timestamp.
That horizon is distinct from the server capture time and does not establish
complete collection or absence of dependencies.

The server runs the fixed graph command under the current investigator's session,
captures original rows and warnings, and records the scope, windows, capture
time, source contract, installed code/configuration fingerprint and digest.
Only the reviewed metadata field `generated_at` and row ordering are excluded
from the digest; evidence fields remain covered. This is a new server read,
not a copy of the displayed graph. Unknown topology and source coverage remain
unknown and cannot establish an eligible dependency baseline.

On each protected read, export or historic retry response, the current reader
must reproduce the same canonical evidence under compatible configuration.
An index grant alone is insufficient: native search filters still apply.
Request-local proof reuse is confined to the same caller and request; there is
no saved owner authorization. Source searches run outside SQLite write locks,
with case access and revision checked again before saving or releasing data.
Lists withhold all source evidence without dispatching searches for every case.
Case-authorized opaque `capture_ids` allow an explicit `capture_id` selection on
GET and export. This rechecks exactly one comparison within the same request
budget and withholds the others; selecting a later capture cannot be starved by
earlier captures. The UI requires an explicit selection when an index is present
and labels export omissions. Selectors never contain source query arguments.
Failed source proof withholds the affected capture and leaves notes usable.
Retention loss or changed code/configuration can therefore make a capture
temporarily unverifiable without deleting its stored bytes or the case.

Limits are three source jobs per request, 2,000 rows and 512 KiB per window,
five seconds of server search runtime per job, short expiry and native
completion/truncation checks. The supervised local transport uses a separate
worker, bounds request and response buffers, and checks per-call deadlines. The
source reader targets a 25-second elapsed budget and a shared three-second
cleanup budget; successful known jobs are deleted before their results are
accepted. Ordinary process scheduling and operating-system behavior are not
hard real-time guarantees. Case authentication, configuration and other
ordinary Splunk SDK calls remain outside the source deadline. Linux-specific
resource-limit behavior and the end-to-end transport lifecycle remain unqualified
on a supported native Linux/amd64 host. The local Rosetta runtime failed the
unchanged 256 MiB address-space contract; its token-free preflight keeps capture
unavailable before any job intent. This is a failed source qualification, not a
successful capture check. The mode ships disabled. No Cloud or SHC write
support, arbitrary SPL, external attachment upload, collector or notification
is enabled.

Saving source evidence and exporting a case each require explicit consent.
Both JSON and readable handoff downloads use a fresh server-authorized case
projection. The readable handoff includes entries, source/window summaries,
reported coverage warnings and withheld counts; it omits raw source rows.

## Entry history and saved evidence links

Editing appends a new same-type entry with `supersedes_entry_id`; it never
rewrites the earlier text or author. The server requires the latest entry in
the same case and the current case revision. History preserves each version's
author and time. Stale edits require review and explicit reapplication; unknown
writes retry the identical request. Revoked case access never grants access to
an earlier draft's source evidence.

An explicit attachment associates one entry revision with a saved comparison
in that case. Admission rechecks the current caller's source access outside the
write transaction, then rechecks case revision and access before committing.
Reads, exports and old retry responses expose the association only alongside
its independently authorized capture in that response. Selecting another
capture or losing source access withholds the association, retaining the note.
No source rows are duplicated, and a link grants no new access. The browser
requires a chosen entry, a visible comparison and explicit consent. Files,
URLs and browser-supplied evidence payloads remain unsupported.

## Writes, retries and retention

Mutations carry an `Idempotency-Key`, and updates require the expected revision.
Uncertain browser outcomes preserve the exact request ID/payload and block other
writes until the same request is retried. Editors are locked while the result is
unknown. This state is in memory: navigating away loses it. Do not claim an
uncertain write failed or create a replacement operation without reconciliation.
Authentication expiry and permission denials clear displayed shared records.
A mutation denied or missing after authorization changes can already have
committed. Mutation responses with 401, 403 or 404 therefore retain the exact
uncertain request for reconciliation after access returns; they do not permit a
replacement write. Read denials do not imply an uncertain mutation.
Server-authorized export
rechecks current case access; portable downloads carry no recipient grant.

SQLite transactions arbitrate concurrent mutations and retain retry receipts.
Case, item, membership, audit and retry quotas are bounded. Reserved capacity lets
owners revoke access and delete cases when ordinary metadata capacity is full.
Expired records are unreadable immediately; trusted maintenance must invoke
`purge_expired` to reclaim data and aged metadata. No maintenance schedule is
enabled in this increment. Backup/restore and cleanup scheduling require target
qualification. Preserve the database through code rollback; disabling the host
does not delete retained investigations.

To roll back capture availability, set `capture_mode = disabled`; the current
host retains case notes and withholds source evidence. Downgrading binaries to
an earlier notes-only handler is not qualified and may refuse cases containing
protected items. Preserve the database and validate compatibility before using
an older writer.

Source-job cleanup has a separate private SQLite ledger at
`$SPLUNK_DB/splunk_adm_investigations/capture_jobs.sqlite`. It stores bounded
technical metadata, the authenticated principal, hashes and leases; it does not
store session tokens, query plaintext or source rows. A random local intent ID
is not a Splunk job ID. The ledger records the server-assigned SID only after a
successful creation response and binds recovery to the verified peer, CA trust
and hosting instance GUID. At most three unresolved jobs can be held globally
across investigators, in addition to the per-request source-job limit.

When a creation response is unknown, the server SID is unknown: the host does
not guess it, issue a replacement search, or release the slot merely because a
TTL elapsed or a lookup returned 404. An uncertain deletion also stays reserved
until the same principal can prove the known job against the same peer and
trust and receive a deletion acknowledgement. Changed peer or trust blocks
reconciliation. Exhausted or unreconciled slots make capture unavailable;
notes, owner revocation and case deletion remain available. There is no
automated safe orphan purge. Preserve the ledger and seek operator review;
deleting or resetting it merely to regain capacity would discard unresolved
job state. Backup and restore procedures must cover both case and job ledgers
and require separate qualification.

## Validation scope

Domain, request-adapter and host tests cover private access, current entitlement,
revocation, concurrency, uncertain retries, limits, expiry, invalid requests,
forged identity fields and evidence rejection. Browser replay covers draft
preservation, lost-response retries, sharing, revocation, export and access-denied
refresh. It is synthetic UI evidence. Installed lab results and remaining
qualification are recorded separately in `FEATURE_DELIVERY.md`.

## Current installed evidence

An earlier backend passed the notes and caller-filter evidence checks
on a fresh Enterprise 10.6.0.5 single-head lab against archive
`21245b2804474d654d504b05a4f98c4db0f1fb3f6a167aec68ce6d8d416302a9`.
Management and HEC qualification traffic verified the task CA and hostname;
wrong-CA and wrong-hostname connections failed. Native output includes typed
service identity provenance. The evidence fixtures were synthetic, and the lab
was purged with independent resource and credential cleanup checks. See
[exact qualification scope and hashes](FEATURE_QUALIFICATION.json). This does
does not qualify the newer supervised transport or ledger, Linux resource limits,
Web/CSRF, backup/restore, Cloud/SHC or real-source coverage. Persistence and
capture remain disabled by default.
