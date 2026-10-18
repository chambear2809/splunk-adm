# Catalyst indexed receipt and retained history

The accepted base `64473e54d1fca4311ac592bc34c4a96a022efd48` lost
Catalyst topology context before its eligibility check: the raw client adapter
inherited the map's event-time window, so an older `_time` never reached the
subsequent indexed-receipt predicate. Independently, graph context rejected a
snapshot whose controller `lastUpdatedTime` was more than an hour older than
receipt. That timestamp describes controller record update, not a verified
collector observation time.

Catalyst topology now reads the same staged `adm_network_client_history` used
by graph attribution and Find. Its read happens once per topology request and
is independent of the selected source-event window. The existing history
builder reads event time from epoch through `+15m` inside a bounded indexed
receipt slice (`-10m@m` through `@m`). Installers must configure exact source
profiles, run a reviewed bounded index-time backfill, and enable the builder;
new receipts become available after staging and a normal application refresh.
No raw fallback manufactures a new eligibility origin for an unstaged replay.

A valid wired connected snapshot is eligible from its earliest **retained**
indexed receipt through the earlier of receipt plus 3,600 seconds or the next
retained receipt for that source, authority and native identity. A disconnected,
incomplete, malformed-time or conflicting transition also ends the previous
attachment; it cannot revive that attachment merely by failing eligibility.
Equal-receipt claims share the next distinct receipt and retain conflict status.
The interval computation sorts the bounded history once and streams receipt
times; it does not expand a per-identity array for every observation.
The selected interval end
is exclusive. A snapshot received after that end cannot appear earlier, and
source time never backdates attachment. Old numeric source time within the
configured history horizon remains useful context and carries
`source_time_status=stale`; source and receipt timestamps remain separate.
Collection time remains absent when the source supplies none. Missing or
malformed source time, more than 300 seconds of forward skew, conflicts,
incomplete history, or capped history prevent positive attachment.

Source update age exceeding `adm_identity_retention` (seven days by default)
carries `history_coverage=unconfirmed`. It does **not** prove an actual
collection outage: a legitimate old controller record could first arrive now.
Without an external poll ID, the app cannot distinguish that case from a
replay whose earlier fingerprint was pruned. The client device and its
source/receipt provenance remain visible, while positive physical and traffic
attachment remain unresolved. Find retains the original evidence and explains
this uncertainty. `retained_evidence` means there is retained receipt evidence;
it does not certify continuous collection or globally first receipt.

Identical retained payloads preserve the earliest receipt and latest observed
receipt when replayed. Read-only semantic deduplication also handles old and
new fingerprint keys together, so adding routing domain to Catalyst's
fingerprint does not manufacture a simultaneous conflict. Distinct source
authority, routing domain, scope, cluster, identity, source time, or attachment
payload remain distinct. Client identity retains the existing
`source + source_authority + native_id` contract. Identical native IDs on one
controller across sites/scopes are not silently treated as independent clients;
simultaneous incompatible claims remain conflicting/ambiguous and cannot
attach across scopes. Existing records are not destructively rewritten.
Moves, IP reuse, conflicting same-time claims, missing identity, and selected
client backend/receiving-node gaps retain the existing conservative rules.

The collection read uses the existing twenty 10,000-row pages and verifies
completeness. At the 200,000-row boundary or with a shortened KV query limit,
attachments are unresolved and topology/Find report incomplete retrieval.
Per-client correlation still refuses history at the 1,000-row lookup ceiling.
Pruning expires a fingerprint only after both valid indexed-receipt extrema
are older than retention. A current latest receipt protects its earlier origin;
missing or malformed extrema are retained for administrator inspection.
Pruning requires the existing disabled-by-default maintenance controls; it does
not recover missing history or prove replay origin. There are no permanent
receipt tombstones. An expired receipt does not become fresh merely because
its identical retained payload is indexed again. Meraki topology retains its
raw association event-time semantics and graph context retains its 900-second
association lifetime.

The builder's `+15m` event upper bound remains coordinated with the migration
journal and scheduler validation. Events whose raw `_time` lies farther ahead
can be diagnosed by the independent `+10y` raw health probe but are not staged
by that builder. Changing that boundary requires a coherent migration-contract
change; this work does not silently widen it.

Regression commands (run the integration command only under the repository's
exclusive lab owner):

```sh
python3 -m unittest discover -s tests -p test_cisco_late_receipts_contract.py
python3 -m unittest discover -s tests/splunk -p test_cisco_identity_quality.py
ADM_LAB=1 python3 tools/lab_lock.py --root . -- python3 -m unittest discover -s tests/splunk -p test_cisco_late_receipts.py
```

The integration matrix evaluates shipped SPL for inside/before/after receipts,
old/malformed/forward-skewed timestamps, conflicting/capped/incomplete history,
old/new fingerprint coexistence, replay, order, moves, IP reuse, and exact
scope/cluster separation. A uniquely tagged raw Catalyst fixture exercises
normalization, exact profile resolution, staging, topology, Find, refresh and
retained replay without accessing a controller. Frontend integration checks
must separately retain provenance through inspector, paths, comparison, and
export. Qualification logs belong in
`dist/final-qualification/late-receipts`; no live result is claimed by merely
adding the test.
