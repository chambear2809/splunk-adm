# Application Atlas — Phase 1 migration foundation

2026-10-14. Committed locally on `codex/atlas-phase-1` in the attached `atlas-phase-1` worktree.

## Delivered

- One shared React 18 / Splunk UI Toolkit bundle, hosted by Simple XML 1.1 views for Applications (default), Map, Data health, Setup, and Help. Setup's server ACL permits only `admin` / `sc_admin`.
- The old `dependency_map` host redirects to Map, preserving its query string. Routing accepts Splunk locale and root-path prefixes and rejects unknown pages.
- Validated scope/time/deep-link state, including the latest bound, map tab, highlight query, and demo scenario. Invalid scope text remains in the form rather than entering a shared URL or search.
- Toolkit theme resolution retains the proven RequireJS workaround. Scoped colors and fonts feed the existing SVG map, with the standard dashboard panel boundary retained as requested.
- The signed-in user's timezone is read through Splunk REST and used for the map window; unavailable/invalid zones fall back to the browser.
- SearchJob replaces SplunkJS. Search requests carry Splunk's default CSRF fetch settings, explicit earliest/latest values, caps, cancellation and a 120-second timeout. Final row counts must match. Failed jobs reject immediately; finalized results carry a warning. Optional inventory failure degrades paths without hiding a graph failure.
- Captured demo rows are separate static JSON assets. Live startup does not require demo downloads. Map helpers and exports are separated from the page; per-user preference storage has a foundation module.
- CI builds and checks the actual bundle with dashboard AMD globals, runs Cloud AppInspect under Python 3.11, and fails on report errors/failures regardless of the inspector's exit code.
- A cooperative-lock lab smoke test uses an ephemeral search-only viewer, environment-only credentials, bounded error evidence, and cleanup in `finally`. It verifies live counts/scope, reload, legacy bookmarks, dark/light themes, timezone, demo mode, readable page hosts, and denial of Setup.

Applications currently provides a validated scope entry form. Catalog/Find, cascading scope options, the Toolkit time picker, and interactive Setup writes belong to later phases; the phase-one hosts are ready for them. Existing map interactions, table, inspector, path, CSV and JSON exports remain available.

## Verification

Commands run from this worktree unless stated otherwise. Final results are recorded below.

| Command | Result |
| --- | --- |
| `npm run lint` | Passed. |
| `npm test` | 236 tests passed across 18 files. |
| `npm run package` | Passed; one `dist/splunk_adm-0.2.0.tar.gz` plus checksum. |
| `python3 tools/check_release.py --dist dist` | Passed; requires all five hosts and demo assets, Cloud prerequisites and no custom Mako paths. |
| `npm run test:browser` | 9 passed, including real demo bootstrap and built-bundle AMD isolation. |
| `npm run typecheck:browser` | Passed. |
| `ruff check tools tests` | Passed. |
| `ruff format --check tools tests` | Passed after incorporating the upstream ACI formatting fix. |
| `python3 -m unittest tests.test_release tests.test_appinspect tests.test_atlas_build` | 20 passed. |
| `python3 -m unittest discover -s tests -p 'test_*.py'` | 149 passed after the initial run collided with the active lab lock. |
| `splunk-appinspect inspect dist/splunk_adm-0.2.0.tar.gz --mode precert --included-tags cloud --output-file dist/appinspect-cloud.json` | Python 3.11.15; 0 failures, 0 errors, 5 warnings. |
| `python3 tools/check_appinspect.py dist/appinspect-cloud.json` | Passed. |
| Locked lab lifecycle and `ADM_LAB=1 python3 -m unittest discover -s tests/splunk -v` | 160 passed, none skipped; 1,186 seconds. Includes the live upgrade and viewer smoke tests. |

The lab lifecycle is wrapped by `ADM_LAB=1 python3 tools/lab_lock.py --root . -- python3 /tmp/atlas-phase1-lab.py`. That local driver refuses an existing container, temporarily links the ignored `research/extracted` data, runs `tests/splunk/lab.sh up`, `tests/splunk/lab.sh install`, and the full suite with `ADM_UPGRADE_PACKAGE` pointing at the single final archive, then calls `tests/splunk/lab.sh purge` and removes its symlink in `finally`. The final bundle is installed at initial lab setup; the upgrade test also validates the same archive.

The initial live run exposed a transient KV-store initialization response in upgrade setup and a viewer-harness readiness selector error. The fresh rerun passed all 160 tests. Both were corrected; the upgrade test retries only explicit KV initialization rejections, with a bounded deadline and no retry of permission errors.

Independent read-only review found and verified fixes for incomplete result handling, failed job states, root-path routing, live/demo startup independence, prompt graph-error reporting, and asynchronous page-heading qualification. Final review has no remaining actionable findings.

The final executable bundle is **1,174,455 bytes raw / 310,737 bytes gzip** (gzip measured with Python). `npm ls lodash colorjs.io` confirms one deduplicated version of each. The five AppInspect warnings are the existing Python-script, Python-SDK, custom-conf replication, collections, and synthetic host/IP warnings. The prior SplunkJS warning is gone; there is no custom-Mako warning.

The final run removed its container, volumes, cached image and lab credentials through `purge`, and removed the temporary research symlink. Temporary viewer accounts/roles were removed through class cleanup. Pipe handles were also closed explicitly after qualification to avoid Python resource warnings.

Screenshots from the real viewer (`dist/atlas-live-dark.png`, `dist/atlas-live-light.png`) and the demo checks (`dist/atlas-applications-light.png`, `dist/atlas-demo-dark.png`) were local diagnostics in the ignored `dist/` directory of the qualification checkout. They are not committed or shipped; rerun the phase's browser checks to reproduce them.

## Qualification limits and integration

Runtime qualification targets Splunk Enterprise 10.6.0.5. Splunk Cloud has an offline AppInspect gate; live Cloud runtime and a formal Cloud vetting submission are not exercised here.

Phase 1 is based on main at `d3529bc`, including Claude’s merged Cloud prerequisites, Hubble Enterprise support and Toolkit spike. Their newer scope ACL, migration and regression fixes are retained. The Phase 1 commit is local; no push, PR or release publication was performed.

No new product decision is outstanding. The user chose to retain the standard panel boundary.
