# Local investigation record engine

`CaseStore(database_path, entitlement_callback)` is a SQLite domain engine. The
`adm/investigations` persistent handler connects it to shared notes controls in the
incident workspace. The handler ships disabled in `adm_investigations.conf`.
The caller supplies a protected database directory, an authenticated principal
from server context, and a callback `(principal, action, case_id) -> bool` which
checks current deployment/case permission. Never accept these values from request JSON.
Unknown or failed case-entitlement checks deny access. A separate trusted
`capture_resolver(principal, reference)` builds immutable `{captured_at,data,source}`
items; `source_entitlement(principal, kind, stored_item)` rechecks current source
access. Both default to denial for protected evidence. Arbitrary capture data
and attachments cannot bypass admission through direct generic `append` calls.

Cases start private. Only the owner may grant/revoke membership or delete a case;
all access also requires current entitlement. `list_cases` rechecks read access
before returning data. Trusted captures, notes, hypotheses and questions append
under a revision precondition; attachment uploads remain unsupported. Mutations
require a caller request ID: retrying returns the original mutation outcome with
current source redactions; changing its payload conflicts. An interrupted client
must retain its request ID until the outcome is known.

The engine bounds case bytes/items/count, membership, retry response bytes/rows,
and audit rows. Mutations roll back on quota exhaustion. Existing memberships
and cases reserve metadata capacity for revocation and deletion. Expired cases
are inaccessible before cleanup. A trusted adapter must call `purge_expired`
under its maintenance identity to remove expired evidence and aged audit/retry
metadata. Choose quotas and retention for the deployment; no scheduler is enabled.

All response paths, including old retry snapshots, project protected items under
current source authorization. Failed checks withhold the item with an explicit
count; notes remain readable. Lists withhold source payloads without searching
every case. Opaque `capture_ids` permit an explicit `capture_id` selection on
case GET/export so every saved comparison can be rechecked within the unchanged
three-job request budget. Other captures are withheld from that response.

The optional comparison adapter uses caller-context raw qualified graph queries,
not owner-produced summaries. It binds exact windows, immutable original rows,
warnings, a source/configuration fingerprint and a canonical evidence digest.
Native replay under the current reader must match before releasing stored facts.
Entry revisions append immutable same-type superseding entries in the same case;
branching from an older revision is refused. Saved-comparison attachments store
only an entry/capture association. Admission requires current source proof, and
read/export/retry projections withhold that association unless the same response
contains its independently authorized capture. Files and URLs are unsupported.
The mode ships disabled, supports only the separately qualified single-head
Enterprise target, and does not authorize arbitrary uploaded evidence.

Protected capture additionally requires the `[capture_transport]` settings in
`adm_investigations.conf`: an exact HTTPS loopback management URI and the
absolute path of the public CA that validates that endpoint. The CA must be a
regular, single-link file owned by root or the Splunk process user, not
group/world writable, no larger than 128 KiB, and must not contain private key
material. The peer's certificate and hostname are checked, and its server GUID
must match the hosting search head. Missing, changed or untrusted transport
leaves notes available and source evidence unavailable. Configuration cannot be
supplied in a case request.

The supervised source transport uses a short-lived subprocess with bounded
request/response buffers and configured CPU, address-space and core-dump
limits. The source reader targets a 25-second request budget that includes
proof and deletion for successful jobs. A shared three-second reserve covers
recovery cleanup and retirement after the deadline. Case authentication,
configuration and other ordinary Splunk SDK calls are outside that source
deadline. Linux-specific resource behavior and the complete
transport lifecycle require separate installed qualification. The local Rosetta
runtime failed the unchanged 256 MiB address-space contract; token-free readiness
preflight refuses capture before allocating a job intent. Native Linux/amd64
positive qualification is still required.

Cleanup state is stored separately in the private
`$SPLUNK_DB/splunk_adm_investigations/capture_jobs.sqlite` ledger. A random local
intent ID is not a Splunk job ID: a server-assigned SID is recorded only after
its successful creation response. The ledger contains bounded technical
metadata and hashes, not session tokens, query plaintext, or source rows. It
permits at most three unresolved jobs globally across investigators; known jobs
can be reconciled only by the same principal against the same verified peer and
trust, with job identity proof and an acknowledged deletion. If a creation
response is unknown, no SID is guessed, no replacement search is automatically
submitted, and neither a 404 nor elapsed TTL clears the slot. Cleanup-unknown
also remains reserved until reconciliation succeeds. If the budget is exhausted,
capture becomes unavailable while notes remain usable. There is no automated
safe orphan purge; retain the ledger for operator review and do not clear it
merely to restore capacity.

Back up both databases consistently before upgrade using a deployment-qualified
procedure. Schema initialization
is additive; exported documents carry schema version 1. Multi-host storage,
Splunk Cloud, attachment upload, cleanup scheduling and operational backup/restore
remain unqualified. Legacy evidence without a trusted descriptor stays withheld.
Rollback must retain this database; never replace it with settings storage or
delete it as code cleanup. Code/configuration changes can invalidate source
reproducibility; do not infer archival source entitlement from case membership.
