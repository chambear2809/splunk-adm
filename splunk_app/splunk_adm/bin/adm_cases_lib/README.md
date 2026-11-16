# Local investigation record engine

`CaseStore(database_path, entitlement_callback)` is a SQLite domain engine. It is
not registered as a Splunk REST handler, and the browser handoff does not call it.
The caller supplies a protected database directory, an authenticated principal
from server context, and a callback `(principal, action, case_id) -> bool` which
checks current source entitlements. Never accept these values from request JSON.
Unknown or failed entitlement checks deny access. A deployment adapter must bind
each capture to the sources whose current access the callback rechecks.

Cases start private. Only the owner may grant/revoke membership or delete a case;
all access also requires current entitlement. `list_cases` rechecks read access
before returning data. Captures, notes, hypotheses, questions, and explicit
attachments append under a revision precondition. Mutations require a caller
request ID: retrying the same request returns the original response after
rechecking authorization; changing its payload conflicts. An interrupted client
must retain its request ID until the outcome is known.

The engine bounds case bytes/items/count, membership, retry response bytes/rows,
and audit rows. Mutations roll back on quota exhaustion. Existing memberships
and cases reserve metadata capacity for revocation and deletion. Expired cases
are inaccessible before cleanup. A trusted adapter must call `purge_expired`
under its maintenance identity to remove expired evidence and aged audit/retry
metadata. Choose quotas and retention for the deployment; no scheduler is enabled.

Back up the entire database consistently before upgrade. Schema initialization
is additive; exported documents carry schema version 1. This increment does not
establish multi-host storage, Splunk Cloud support, HTTP authorization, an install
migration, or an operational backup/restore procedure. Rollback must retain this
database; never replace it with settings storage or delete it as code cleanup.
