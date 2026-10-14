# Application Atlas upgrades

Apply an app update over the existing `splunk_adm` installation. Do not use `tests/splunk/lab.sh install` as an upgrade check: that helper removes the app directory first and can hide loss of deployment-local state.

**Use the `-upgrade.tar.gz` archive for an existing installation.** `npm run package` produces both a full-install archive and an upgrade archive. The full archive includes the empty scope CSV and Splunk overwrites an existing copy during an app update. The upgrade archive omits that deployment-owned file; the live test verifies that Splunk preserves it. The upgrade archive is not suitable for a first install.

Before updating, back up the KV collections and record effective index and scope macros. Packaged defaults live in `default/`; operator values belong in `local/` and remain deployment-owned. Verify `adm_observer_scope.csv`, validity history in `adm_ip_identity`, and the other `adm_*` KV collections after the update.

Run the live check against an already running and installed lab:

```sh
ADM_LAB=1 ADM_UPGRADE_PACKAGE="$PWD/dist/splunk_adm-0.2.0-upgrade.tar.gz" \
  python3 -m unittest tests/splunk/test_upgrade.py -v
```

The test seeds an explicitly synthetic prior-version state when no released baseline is available, then sends the package to Splunk's app update endpoint. This qualifies the upgrade *mechanics* against a stand-in; it does not substitute for upgrading from an actual prior release. Once a first tagged release exists, re-run this check with `ADM_UPGRADE_PACKAGE` pointing at that release's real `-upgrade.tar.gz` archive (installed first, then updated to the candidate package) instead of the synthetic seed, and keep doing so for the most recent released version on every subsequent release. It verifies a changed packaged description, exact local macro and scope-file contents, and two historical identity rows. Effective read and write permissions for all eleven owner-dispatched saved searches must stay administrator-only. It also inspects a deployment-local metadata override, allowing only Splunk’s generated install-checksum bookkeeping stanza to differ. A permissive local ACL is reported as an unsafe upgrade and fails the check; it is never treated as protected merely because packaged `default.meta` is restrictive.

The check is opt-in and does not start, stop, reset, or provision the lab; it does replace the app through Splunk’s update endpoint. Build the package first with `npm run package`. In a real deployment, repeat the same checks with a package from the target release and a backup taken before the change.

The harness uses Splunk’s [app update endpoint](https://help.splunk.com/en/splunk-enterprise/leverage-rest-apis/rest-api-reference/9.4/application-endpoints/application-endpoint-descriptions), with `filename=true` and `update=1`, on a package copied into the disposable container.
