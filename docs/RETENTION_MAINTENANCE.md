# Bounded retention maintenance

`tools/retention_maintenance.py` provides read-only capacity reports and an
explicit row-wise prune for the six existing retention-managed KV collections.
The tool runs from a checkout of the Atlas source repository on the Splunk host
(it imports the app's `bin/` recovery libraries). It is **not shipped in the
Splunk app package**; the copy of this document inside the package only describes
the tool.
It pages by `_key` until an empty cursor page proves completion, including when
the server returns fewer rows than requested. It can inspect collections beyond
the SPL reader's 200,000-row ceiling without changing that reader or rewriting
the entire collection.

The offline suite covers cursor bounds, expiry rules, backup ordering and
uncertain-delete handling. Installed qualification additionally exercises the
actual REST responses, verified TLS and collection behavior. Retain the results
for the exact tool, package and target; qualify a disposable instance before
operational adoption rather than inferring support from offline results alone.
The write gate only admits the existing qualified standalone Enterprise topology;
this does not add SHC, remote-peer or Cloud qualification.

## Capacity reports

Use a local, hostname-verified management endpoint and trusted CA. The tool prompts
for the session key without echoing it. `--session-key-stdin` accepts one line from
an approved secret-injection mechanism; never place the key in command arguments,
repository files or shell history.

```sh
python3 tools/retention_maintenance.py --ca-file /secure/splunk-ca.pem \
  status adm_network_client_history
```

Reports include rows read, expired rows, malformed expiry rows retained, oldest
expiry, remaining rows below the SPL ceiling, completeness and warning codes.
`spl_reader_capacity` appears from 160,000 visible rows onward. Counts are
observational while writers run; an incomplete scan cannot establish headroom or
the absence of expired data. A read-only status report does not enable pruning.

The effective `adm_identity_retention` macro supplies the period. An explicit
`--retention-seconds` must match it exactly. Expiry follows the shipped rules:

| Collection | Expiry basis |
| --- | --- |
| `adm_ip_identity` | `valid_end` |
| `adm_service_workload` | `last_seen` |
| `adm_service_backends` | `valid_to` |
| `adm_service_routes` | `valid_to` |
| `adm_aci_policy` | `last_seen` |
| `adm_network_client_history` | Later of both indexed receipt extrema |

Missing, malformed, negative or nonfinite values are retained. In particular,
open intervals are retained, and client history requires both receipt extrema.

## Explicit maintenance

Follow [the pause, backup and replay procedure](RECOVERY.md#pruning-and-maintenance).
Record pause times; prevent manual dispatches, pause/disable every ADM schedule,
and drain visible jobs before setting `adm_prune_maintenance=1`. The tool verifies
the administrator, collection ACL, qualified topology, target identity, schedule
inventory and job inventory. Unknown or incomplete evidence blocks deletion.
Quiescence and the effective retention period are checked again between batches.
The operator assertion is still necessary: these checks are not a distributed
lock against another administrator starting a writer or changing KV data.

Provide a new directory beneath an existing private external backup location.
The leaf must not already exist, lie inside the repository, or traverse symlinks.

```sh
python3 tools/retention_maintenance.py --ca-file /secure/splunk-ca.pem \
  prune adm_network_client_history --confirm-maintenance \
  --backup-dir /secure/atlas-backups/client-history-run-001
```

Before the first DELETE, the tool streams the complete collection into a private
NDJSON backup, fsyncs it and a private manifest, and records its hash, row count,
cutoff and target-identity fingerprint. Files use mode `0600`, the directory uses
`0700`, and directory entries are fsynced. A failed or capped snapshot never
authorizes deletion. These backups contain deployment data and must stay outside
sanitized CI qualification packets.

Each expired row is reread and compared with its backed-up material. Its exact
key is durably journaled before DELETE; acknowledged results clear the pending
key. Changed rows stop the operation. A lost response produces `uncertain` and
stops without retrying. Inspect the protected manifest and live row before any
further operation. There is no automatic resume or takeover of an uncertain run.

The default ceilings are 1,000,000 scanned rows, 512 MiB serialized backup bytes,
an overall 900-second budget checked between requests, and 1,000 acknowledged
deletions per run.
Reads have a 16 MiB response cap. Oversized inventory pages are retried with fewer
entries at the same offset. Inventory also has a cumulative byte budget and a
10,000-entry ceiling; a single oversized entry or inconsistent paging blocks
deletion. Lower ceilings are configurable; deletion may
be increased to at most 10,000 per run. A deletion-budget stop returns `partial`
with `complete=false` and no pending key. Retain that backup, verify outcomes,
and use a new backup directory for another explicitly reviewed maintenance run.

After verifying outcomes, restore the maintenance gate to zero before resuming
writers, keep prune schedules disabled, and reconcile the paused slices using
the recovery procedure. CLI exit zero means a complete observation/prune or a
known bounded partial prune; incomplete, stopped and uncertain results exit two.
Read the structured status rather than treating every zero exit as a full prune.
