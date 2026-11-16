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
The host rejects uploaded graphs and attachments. With capture mode disabled,
existing protected items are withheld while notes remain readable. An explicit
redaction count distinguishes withheld evidence from an empty investigation.

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

Limits are three owned source jobs per request, 2,000 rows and 512 KiB per
window, five seconds of server search runtime per job, short expiry and native
completion/truncation checks. A 25-second elapsed budget and per-call socket
timeouts are checked; successful known jobs are deleted before accepting their
results. The SDK buffers a response before the two MiB check, and its socket
timeout is not proven to impose a hard wall-clock read deadline. Those transport
limits remain a qualification constraint; the mode ships disabled. No Cloud or
SHC write support, arbitrary SPL, external attachment upload, collector or
notification is enabled.

Saving source evidence and exporting a case each require explicit consent.
Both JSON and readable handoff downloads use a fresh server-authorized case
projection. The readable handoff includes entries, source/window summaries,
reported coverage warnings and withheld counts; it omits raw source rows.

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

## Validation scope

Domain, request-adapter and host tests cover private access, current entitlement,
revocation, concurrency, uncertain retries, limits, expiry, invalid requests,
forged identity fields and evidence rejection. Browser replay covers draft
preservation, lost-response retries, sharing, revocation, export and access-denied
refresh. It is synthetic UI evidence. Installed lab results and remaining
qualification are recorded separately in `FEATURE_DELIVERY.md`.
