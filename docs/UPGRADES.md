# Application Atlas upgrades

Apply an app update over the existing `splunk_adm` installation. Do not use `tests/splunk/lab.sh install` as an upgrade check: that helper removes the app directory first and can hide loss of deployment-local state.

**Use the `-upgrade.tar.gz` archive for an existing installation.** `npm run package` produces both a full-install archive and an upgrade archive. The full archive includes the empty legacy scope CSV and Splunk overwrites an existing copy during an app update. The upgrade archive omits that deployment-owned migration source; the live test verifies that Splunk preserves it. Live scope mappings now reside in the `adm_observer_scope` KV collection, whose data is never shipped in either archive. The upgrade archive is not suitable for a first install.

Before updating, back up the KV collections and record effective index and scope macros. Packaged defaults live in `default/`; operator values belong in `local/` and remain deployment-owned. Verify the live `adm_observer_scope` KV mappings, the retained legacy CSV, validity history in `adm_ip_identity`, and the other `adm_*` KV collections after the update.

## One-time CSV-to-KV scope migration

Do this once when upgrading from a CSV-scope version. There is no automatic import or scheduled privileged migration. Pause builders and rollup, back up the current CSV and derived state, and keep viewers off the pipeline until the following verification is complete. The upgrade archive preserves `lookups/adm_observer_scope.csv` so an administrator can still read it by filename after the named lookup changes to KV.

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

Fresh installations start with an empty KV collection; administrators populate the named lookup using the same normalized-key upsert pattern. Never import unreviewed rows automatically from the shipped header-only legacy template. The four public field names and lookup name are unchanged. Case normalization is limited to `observer_kind`/`observer`, preserving the former case-insensitive matching without changing mixed-case scope or cluster values.

## Upgrade regression

Run the live check against an already running and installed lab:

```sh
ADM_LAB=1 ADM_UPGRADE_PACKAGE="$PWD/dist/splunk_adm-0.2.0-upgrade.tar.gz" \
  python3 -m unittest tests/splunk/test_upgrade.py -v
```

The test seeds an explicitly synthetic prior-version state when no released baseline is available, then sends the package to Splunk's app update endpoint. This qualifies the upgrade *mechanics* against a stand-in; it does not substitute for upgrading from an actual prior release. Once a first tagged release exists, re-run this check with `ADM_UPGRADE_PACKAGE` pointing at that release's real `-upgrade.tar.gz` archive (installed first, then updated to the candidate package) instead of the synthetic seed, and keep doing so for the most recent released version on every subsequent release. It verifies a changed packaged description, exact local macro and legacy-file contents, live scope KV rows and their effective collection/lookup ACLs, and two historical identity rows. Effective read and write permissions for all shipped owner-dispatched saved searches must stay administrator-only. It also inspects a deployment-local metadata override, allowing only Splunk’s generated install-checksum bookkeeping stanza to differ. A permissive local ACL is reported as an unsafe upgrade and fails the check; it is never treated as protected merely because packaged `default.meta` is restrictive.

The check is opt-in and does not start, stop, reset, or provision the lab; it does replace the app through Splunk’s update endpoint. Build the package first with `npm run package`. In a real deployment, repeat the same checks with a package from the target release and a backup taken before the change.

The harness uses Splunk’s [app update endpoint](https://help.splunk.com/en/splunk-enterprise/leverage-rest-apis/rest-api-reference/9.4/application-endpoints/application-endpoint-descriptions), with `filename=true` and `update=1`, on a package copied into the disposable container.
