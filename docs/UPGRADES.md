# Application Atlas upgrades

Apply an app update over the existing `splunk_adm` installation. Do not use `tests/splunk/lab.sh install` as an upgrade check: that helper removes the app directory first and can hide loss of deployment-local state.

**Use the same `splunk_adm-<version>.tar.gz` archive for installs and updates.** `npm run package` produces one archive and its checksum. It contains neither scope KV data nor the legacy scope CSV. Splunk preserves an existing legacy CSV as a one-time migration source during update; the live upgrade test verifies its bytes and the scope collection ACLs. New installations start with an empty scope KV collection.

Before updating, back up the KV collections and record effective index and scope macros. Packaged defaults live in `default/`; operator values belong in `local/` and remain deployment-owned. Verify the live `adm_observer_scope` KV mappings, the retained legacy CSV, validity history in `adm_ip_identity`, and the other `adm_*` KV collections after the update.

## One-time CSV-to-KV scope migration

Do this once when upgrading from a CSV-scope version. There is no automatic import or scheduled privileged migration. Pause builders and rollup, back up the current CSV and derived state, and keep viewers off the pipeline until the following verification is complete. The archive does not contain `lookups/adm_observer_scope.csv`. Splunk retains an existing deployment-local copy during the update so an administrator can read it by filename after the named lookup changes to KV; verify it against the pre-upgrade backup.

1. Install the upgrade package. Before enabling access/searches, run the release check with an installed-app directory when the tools/archive are available on that host:

```sh
python3 tools/check_release.py --dist dist --installed-app "$SPLUNK_HOME/etc/apps/splunk_adm"
```

It specifically rejects a `local/transforms.conf [adm_observer_scope] filename=...` CSV override or an override that redirects the lookup away from the scope KV collection. Packaged local configuration is also forbidden. Without `--installed-app`, the checker validates archives only; it cannot inspect remote deployment overrides. Check the effective `adm_observer_scope` lookup definition under **Settings → Lookups → Lookup definitions**: `external_type=kvstore`, `collection=adm_observer_scope`. Remove or update any operator `local/transforms.conf` override that still points the named lookup at CSV. Check both the collection and definition ACLs: read `*`, write `admin`/`sc_admin`. The migration step must run in app `splunk_adm` as an administrator.
2. Compare `| inputlookup adm_observer_scope.csv | table observer_kind observer scope cluster` with the trusted pre-upgrade backup. The retained file is import-only; it is no longer the protected live mapping. Resolve blank matching keys or scope values, and normalize matching keys before checking duplicates. This search must return **no rows** (the same matching pair cannot map to different output values):

```spl
| inputlookup adm_observer_scope.csv
| eval observer_kind=lower(observer_kind), observer=lower(observer), cluster=coalesce(cluster, "")
| stats dc(scope) AS scopes dc(cluster) AS clusters by observer_kind observer
| where scopes>1 OR clusters>1
```

3. Check `| inputlookup adm_observer_scope | stats count`. For the initial migration, the collection must be empty. If it already contains mappings, stop and compare them with the source; do not overwrite later operator edits. Exact duplicate source mappings may be deduplicated. For a repeat of a previously verified import, confirm existing output values still match the source before rerunning.
4. As an administrator, enable **ADM - Migrate observer scope** for one manual run; keep `enableSched=0`. Dispatch it from the app namespace, for example:

```spl
| savedsearch "ADM - Migrate observer scope"
```

Then disable it again. This saved search ships disabled, has no cron schedule and is owner-dispatched behind the app's admin/sc_admin-only saved-search ACL. It lowercases only matching keys, preserves output values and uses stable `_key=sha256(json_array(observer_kind, observer))` upserts. It validates blank keys/scope, conflicting normalized source pairs and differences from existing live KV mappings before writing anything. A refusal returns `blocked=1`, `rows_written=0` and a warning. A verified idempotent repeat returns the same unique mapping count; it cannot overwrite a different current mapping. Do not schedule this search or periodically reimport the legacy file.

5. Compare `| inputlookup adm_observer_scope | table observer_kind observer scope cluster` with the normalized trusted source, including every row and output value; compare row count with the number of distinct matching pairs. A failed/partial search is not a completed migration. Stable `_key` values make a verified rerun update the same mappings rather than duplicate them. Test a known mapping through the app's read macros, and verify a viewer can read the lookup but cannot write it through `outputlookup adm_observer_scope` or the REST collection endpoint. KV ACLs enforce this even with `[outputlookup] outputlookup_check_permission=false`; no platform override is required.
6. Resume the pipeline only after the KV mapping and ACL checks pass. Stop using the CSV as configuration. Keep its trusted backup for rollback, but never periodically reimport the retained runtime file: a CSV write or tamper must not alter live scope mappings. For rollback to a CSV-era release, restore that release's CSV permission control and trusted mapping before resuming access/searches.

Fresh installations start with an empty KV collection; administrators populate the named lookup using the same normalized-key upsert pattern. Never import unreviewed rows automatically from a header-only legacy template retained from an older release. The four public field names and lookup name are unchanged. Case normalization is limited to `observer_kind`/`observer`, preserving the former case-insensitive matching without changing mixed-case scope or cluster values.

## IPFIX exporter authority normalization

Stream/IPFIX events now derive their source-scope mapping key from the lowercase, trimmed `exporter_ip`, and `ADM - Migrate network source scope` normalizes `stream_ipfix` authorities the same way. An `adm_network_source_scope` row written earlier with a mixed-case (typically IPv6) or padded `stream_ipfix` authority no longer matches its exporter's events, so those events become unmapped. Health reports such rows under **Stream source scope profiles** or **SD-WAN source scope profiles** as `incomplete`.

1. As an administrator, list affected rows:

```spl
| inputlookup adm_network_source_scope
| where source=="stream_ipfix" AND source_authority!=lower(trim(source_authority))
| table _key source_authority domain_kind observation_domain_present observation_domain_id vpn_id routing_domain scope cluster profile
```

2. If any are listed, enable **ADM - Normalize IPFIX source scope authority** for one manual run (keep `enableSched=0`), dispatch `| savedsearch "ADM - Normalize IPFIX source scope authority"` from the app namespace, then disable it again. It rewrites each affected row in place under its existing `_key` with the normalized authority and recomputed `mapping_key`; scope, cluster, profile and status are unchanged. A rerun writes nothing.
3. It refuses (`blocked=1`, `rows_written=0`, no writes) when two distinct mappings would normalize to the same key, for example an old mixed-case row next to a newer lowercase row for the same exporter. Delete the stale row through the collection's REST endpoint, then rerun.
4. Rerun the step 1 search; it must return no rows, and the profile health rows must no longer report these mappings as incomplete.

## Upgrade regression

Run the live check against an already running and installed lab:

```sh
ADM_LAB=1 ADM_UPGRADE_PACKAGE="$PWD/dist/splunk_adm-0.3.0.tar.gz" \
  python3 tools/lab_lock.py --root . -- \
  python3 -m unittest discover -s tests/splunk -p test_upgrade.py -v
```

Set `ADM_UPGRADE_BASELINE_PACKAGE` to an actual prior-version archive to check a real version transition. `ADM_UPGRADE_PACKAGE` always identifies the new candidate. The test installs the baseline, updates to the candidate, rolls back to the baseline, and restores the candidate. It derives each release's saved-search inventory from that archive and checks the installed versions. Record the source commit and checksum if the baseline was built from a commit instead of a published release.

Without `ADM_UPGRADE_BASELINE_PACKAGE`, the test creates an explicitly synthetic old-package stand-in; that checks update mechanics only. Both paths verify exact local macro and legacy-file contents, live scope KV rows and their effective collection/lookup ACLs, and two historical identity rows. Effective read and write permissions for all shipped owner-dispatched saved searches must stay administrator-only. The test also inspects a deployment-local metadata override, allowing only Splunk’s generated install-checksum bookkeeping stanza to differ. A permissive local ACL fails the check even when packaged `default.meta` is restrictive.

The check is opt-in and does not start, stop, reset, or provision the lab; it does replace the app through Splunk’s update endpoint. Build the package first with `npm run package`. In a real deployment, repeat the same checks with a package from the target release and a backup taken before the change.

The harness uses Splunk’s [app update endpoint](https://help.splunk.com/en/splunk-enterprise/leverage-rest-apis/rest-api-reference/9.4/application-endpoints/application-endpoint-descriptions), with `filename=true` and `update=1`, on a package copied into the disposable container.

## Cisco V2 derived-data migration

Installing 0.3.0 does not migrate existing summaries or activate the optional Cisco V2 readers. The [V2 migration procedure](CISCO_CONTRACT_MIGRATION.md) stages separate derived data, validates source coverage, and journals selector and writer changes. Keep its journal and captured configuration for recovery. Package rollback and derived-data rollback are separate checks; neither implies the other has passed. The [Cisco qualification record](CISCO_NETWORKING_QUALIFICATION.md) tracks their status and the remaining deployment gates.

## Scope-provenance and historical correctness upgrade

Pause writers, drain jobs, retain the previous archive and configuration, and back up all `adm_*` collections and summary data before adopting the scope-isolation changes. New unmapped observations no longer share the `default` routing scope. New conversation summaries and identity rows record whether their routing mapping was explicit. Existing quarantined identity rows remain in the collection for administrator inspection through `adm_ip_identity_all`; maintenance pruning uses that unfiltered inventory. Readers isolate legacy `default` summaries and hide legacy `default` identity rows without explicit-mapping proof; installing a package does not establish the provenance of persisted rows.

Review and populate every observer mapping, then rebuild affected identity/catalog state and summary history from retained raw data into separate staging collections/indexes under an administrator-reviewed procedure. Do not mix changed normalization with an in-place replay: overlapping aggregate identities can double-count. Validate exact counts, scope attribution, historical ownership, and public readers before switching selectors. Retain the old data and selectors for rollback. Where raw retention cannot reconstruct the affected history, leave that history unresolved rather than relabeling it as verified.

Local overrides of shipped macros and lookup definitions take precedence over these corrections. Compare effective definitions with the candidate and explicitly reconcile overrides before resuming readers or writers. Include `adm_ip_identity`, `adm_ip_identity_service`, and `adm_ip_identity_all` in that comparison: the public aliases must retain the provenance filter, the maintenance alias must retain its administrator-only ACL, and all three must refer to the intended identity collection. Existing Service frontend rows need parent-UID history reconstruction to establish removals and reopening intervals; package replacement cannot invent snapshots no longer retained. ACI filter actions also require provenance from the original raw record: legacy policy rows may contain permits synthesized after the add-on rewrote a deny. Leave those rows unevaluated until the policy builder reconstructs them from retained raw records or a fresh controller poll; do not manually mark their actions as verified.

## Decommission and uninstall

Disable Atlas scheduled searches and alert actions, prevent manual dispatch, and drain active jobs before removal. Export complete KV data, local configuration/metadata, the exact archive, and recovery/migration journals with their result artifacts to trusted durable storage. Reconcile every outstanding paused writer or uncertain claim before uninstalling.

Summary and raw indexes are platform-owned and require a separate retention/deletion decision. Do not assume app removal preserves KV collections or that reinstalling restores them. Rehearse removal and restoration on the intended platform, including SHC/Cloud procedures where applicable, before deleting the deployment or its backups.
