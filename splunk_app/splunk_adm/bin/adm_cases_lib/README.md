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
The mode ships disabled, supports only the separately qualified single-head
Enterprise target, and does not authorize arbitrary uploaded evidence.

Back up the entire database consistently before upgrade. Schema initialization
is additive; exported documents carry schema version 1. Multi-host storage,
Splunk Cloud, attachment upload, cleanup scheduling and operational backup/restore
remain unqualified. Legacy evidence without a trusted descriptor stays withheld.
Rollback must retain this database; never replace it with settings storage or
delete it as code cleanup. Code/configuration changes can invalidate source
reproducibility; do not infer archival source entitlement from case membership.
