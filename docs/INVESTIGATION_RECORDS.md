# Investigation records and portable evidence

The incident workspace provides two explicitly separate workflows. Portable
records capture fixed graph comparisons and note revisions for download. Shared
cases store user-authored notes, hypotheses, questions and absolute time windows
through `adm/investigations`. Creating a shared case does not copy portable notes
or graphs. New cases are private; an owner can grant a named member read, append
and export access, revoke that access, or delete the case through the API.

## Deployment boundary

`adm_investigations.conf` ships with persistence disabled and platform
unqualified. `adm_investigate` is a dedicated capability with no default role
assignment. The host derives the principal from the caller's current Splunk
context and rechecks it during store operations; it never requests system auth.
Investigator roles do not need administrator access. The local server process
checks the fixed SHC disabled setting without exposing configuration to callers.

The candidate host is restricted to explicitly attested single-search-head
Enterprise 10.6.0.5, a known Enterprise/Trial license group, no positive Cloud
markers, and disabled SHC. Local storage cannot be shared across independent
search heads. Cloud and SHC remain unsupported. Passing synthetic tests does not
qualify another target or prove protected-source authorization.

The database is fixed under `$SPLUNK_DB/splunk_adm_investigations/cases.sqlite`,
with a private owner-only directory and file. Request data cannot select a path.
The host rejects graph captures and attachments without a source validator; it
also refuses to read/export/list existing protected records through this notes
host. A future source adapter must bind immutable captured data to server-verified
source entitlements and recheck those entitlements on all later access.

## Writes, retries and retention

Mutations carry an `Idempotency-Key`, and updates require the expected revision.
Uncertain browser outcomes preserve the exact request ID/payload and block other
writes until the same request is retried. Editors are locked while the result is
unknown. This state is in memory: navigating away loses it. Do not claim an
uncertain write failed or create a replacement operation without reconciliation.
Permission denials clear displayed shared records. Server-authorized export
rechecks current case access; portable downloads carry no recipient grant.

SQLite transactions arbitrate concurrent mutations and retain retry receipts.
Case, item, membership, audit and retry quotas are bounded. Reserved capacity lets
owners revoke access and delete cases when ordinary metadata capacity is full.
Expired records are unreadable immediately; trusted maintenance must invoke
`purge_expired` to reclaim data and aged metadata. No maintenance schedule is
enabled in this increment. Backup/restore and cleanup scheduling require target
qualification. Preserve the database through code rollback; disabling the host
does not delete retained investigations.

## Validation scope

Domain, request-adapter and host tests cover private access, current entitlement,
revocation, concurrency, uncertain retries, limits, expiry, invalid requests,
forged identity fields and evidence rejection. Browser replay covers draft
preservation, lost-response retries, sharing, revocation, export and access-denied
refresh. It is synthetic UI evidence. Installed lab results and remaining
qualification are recorded separately in `FEATURE_DELIVERY.md`.
