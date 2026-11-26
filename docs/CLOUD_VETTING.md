# Splunk Cloud vetting readiness

This page records local Splunk AppInspect results for the packaged app and the
disposition of every warning. Local AppInspect results do not establish Splunk
Cloud acceptance, runtime qualification or manual-review approval. Splunk Cloud
vetting has previously reported AppInspect 4.4.0 with the `private_victoria` tag
for uploaded archives (see [feature delivery](FEATURE_DELIVERY.md)).

## How to reproduce

Use a throwaway virtual environment outside the repository. AppInspect 4.4.0
supports Python 3.8, 3.9 and 3.13 according to its runtime check; this run used
Python 3.11, the version the CI frontend job uses. An earlier run under Python
3.14 failed analyzer initialization and was not counted.

```sh
python3.11 -m venv /tmp/appinspect-venv
/tmp/appinspect-venv/bin/pip install --index-url https://pypi.org/simple 'splunk-appinspect==4.4.0'
/tmp/appinspect-venv/bin/splunk-appinspect list tags
npm ci --registry=https://registry.npmjs.org --ignore-scripts
npm run package
for tag in cloud private_victoria private_classic; do
  /tmp/appinspect-venv/bin/splunk-appinspect inspect dist/splunk_adm-0.10.0.tar.gz \
    --mode precert --included-tags "$tag" --output-file "/tmp/appinspect-$tag.json"
  python3 tools/check_appinspect.py "/tmp/appinspect-$tag.json"
done
```

CI runs one inspection with all three `--included-tags` options. That run
covers all 251 checks selected by the three tags individually (`cloud` 248,
`private_victoria` 244, `private_classic` 245). Keep raw reports outside Git;
they contain file paths and message text.

## Results for the 0.10.0 working tree (2026-11-26)

Archive `dist/splunk_adm-0.10.0.tar.gz`, build `1795725206`, SHA-256
`a61d35c0df4197362482b89ff24fbf12a118796f785346479a540ad656653ac2`. Packaging
stamps a new build number, so a rebuilt archive has a different hash and needs
its own run.

| AppInspect | Tags                      | Success | Warning | Failure | Error | Skipped | N/A |
| ---------- | ------------------------- | ------- | ------- | ------- | ----- | ------- | --- |
| 4.4.0      | `cloud`                   | 139     | 6       | 0       | 0     | 1       | 102 |
| 4.4.0      | `private_victoria`        | 137     | 6       | 0       | 0     | 1       | 100 |
| 4.4.0      | `private_classic`         | 138     | 6       | 0       | 0     | 1       | 100 |
| 4.4.0      | all three (CI)            | 141     | 6       | 0       | 0     | 1       | 103 |
| 4.3.1      | `cloud` (previous CI pin) | 139     | 6       | 0       | 0     | 1       | 100 |

No run reported a failure, error or future failure. `tools/check_appinspect.py`
passed for every report. Each run reported the same six warnings and one skip.

## Warning dispositions

| Check                                  | Finding                                                                                             | Disposition                                                                                                                                                                                                                                                                                                                                                                                                                                |
| -------------------------------------- | --------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `check_for_python_script_existence`    | 89 Python files trigger the generic Python 2/3 migration notice.                                    | Accepted. Informational; the code targets Python 3.13 only and every extension point declares `python.required = 3.13`.                                                                                                                                                                                                                                                                                                                    |
| `check_custom_conf_replication`        | Custom `adm_*.conf` files without a `[shclustering]` replication declaration in `server.conf`.      | Accepted by design. Operator attestation files are intentionally not replicated; see [deployment health](DEPLOYMENT_HEALTH.md). No `server.conf` override is shipped to silence this warning.                                                                                                                                                                                                                                              |
| `check_collections_conf`               | The app ships `collections.conf`.                                                                   | Accepted. The check states that no action is required. KV collection ACLs are enforced by `metadata/default.meta` and `tools/check_release.py`.                                                                                                                                                                                                                                                                                            |
| `check_python_sdk_version`             | Bundled Splunk SDK for Python 2.1.1; the check recommends 3.0.0 or later.                           | **Needs follow-up.** Upgrading the SDK touches every REST handler and needs its own compatibility review and lab run. It is out of scope for configuration and packaging changes.                                                                                                                                                                                                                                                          |
| `check_for_possible_threading`         | `subprocess.Popen` and `os.killpg` in `bin/adm_cases_lib/transport.py` and `request_supervisor.py`. | **Needs Splunk review.** The cases handler isolates each request in a bounded `python -I` worker process with a fixed environment, three slots and process-group cleanup ([case request supervision](CASE_REQUEST_SUPERVISION.md)). Removing it would weaken request isolation.                                                                                                                                                            |
| `check_hostnames_and_ips`              | Addresses in code and packaged docs. AppInspect lists 24 messages and suppresses 10.                | Accepted after follow-up: Splunk version strings (`10.6.0.5`, `10.6.1.1`), a V8 version string, RFC 1918, multicast and documentation ranges used for classification in `macros.conf`, loopback addresses and RFC 5737 examples. The two internal qualification records containing a private lab address (`docs/FEATURE_QUALIFICATION.json` and `docs/FEATURE_DELIVERY.md`) are no longer packaged (kept in the repository only, enforced by `tools/check_release.py`). |
| `check_for_valid_package_id` (skipped) | No `app.manifest`.                                                                                  | Accepted. The skip is not evidence of a validated package ID. Add an `app.manifest` only together with packaging and release-gate support.                                                                                                                                                                                                                                                                                                 |

## Other items reviewed

- **Simple XML dashboards with custom JavaScript.** All eleven views are Simple
  XML `version="1.1"` dashboards that load `script="pages/atlas.js"` and
  `stylesheet="adm.css"` into a single `<html>` panel. `check_for_splunk_js`,
  `check_simplexml_standards_version`, `check_html_dashboards` and the
  `splunkjs` deprecation checks all pass. Splunk's manual Cloud review can still
  examine custom dashboard JavaScript; this needs Splunk review rather than a
  configuration change.
- **`web.conf` exposure of `configs/v1/conftypes/macros/stanzas:get`.**
  `check_web_conf` passes. The exposure is limited to `POST` on that exact
  read-only stanza lookup, and Splunk still requires the caller's own
  `list_conf_objects` capability ([security](SECURITY.md)). `tools/check_release.py` rejects any
  broadened pattern or method. Because it exposes a core endpoint rather than an
  app handler, flag it for Splunk review.
- **`python.required`.** The `adm_recovery` alert action declared
  `python.required = 3.9,3.13`. AppInspect accepted this because 3.13 is present,
  and Splunk selects the newest listed version. Splunk Cloud disables Python 3.9,
  and every other shipped extension point requires 3.13 only, so the action now
  declares `3.13`, which `tools/check_release.py` enforces. The legacy
  `python.version = python3` selector remains because AppInspect 4.4.0 still
  checks it.
- **Subprocess use in the cases handler.** Besides the worker processes above,
  `bin/adm_cases_lib/splunk_host.py` runs `$SPLUNK_HOME/bin/splunk btool` with a
  fixed argument list, a three-second timeout and a 16 KiB output cap to read
  this app's own control stanzas and the global `shclustering` state. AppInspect
  does not flag it. Executing the Splunk CLI from an app handler is a likely
  manual-review question on Cloud, where case persistence is not supported (see
  [feature delivery](FEATURE_DELIVERY.md)). **Needs Splunk review.**
- **`app.conf`.** `[id]`, `[launcher]` and `[package]` declare a matching
  `splunk_adm` identity and version; `check_for_updates = false`; packaging adds
  `[install] build`. All `app.conf` checks pass.
- **Reload triggers.** Every custom configuration file has a
  `reload.<conf> = simple` trigger. `check_for_trigger_stanza`,
  `check_reload_trigger_for_all_custom_confs`, `check_reload_trigger_for_meta` and
  `check_reload_trigger_value` pass. `tools/check_release.py` requires the
  triggers, which closes the 0.9.0 Cloud vetting failure.
