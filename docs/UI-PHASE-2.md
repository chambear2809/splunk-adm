# Application Atlas — Phase 2 scope and time controls

2026-10-14. Phase 1 is committed locally as `50111a7` on `codex/atlas-phase-1`. Phase 2 is committed locally on `codex/atlas-phase-2` in the attached `atlas-phase-1` worktree. No push, PR, merge or publication was performed.

## Delivered

- Visible Toolkit ComboBoxes cascade Environment → Cluster → Namespace → Service on Map and Applications. Changing a parent clears its descendants. Invalid options are disabled with an explanation; lookup errors permit validated manual scope entry and offer Retry.
- Read-only `adm_scope_options` aggregates distinct pod UIDs and latest observation time from the existing service-binding KV lookup. Calls use the generating-search prefix `|`.
- Pinned `@splunk/react-time-range` 12.1.1 replaces the preset-only selector. Presets, relative, date and date-time controls use the signed-in timezone; date selections become epoch bounds before URL/search dispatch. Real-time searches are disabled.
- A bounded, strict relative-time/epoch parser validates ordered bounds, including calendar snaps, chained offsets, Sunday week boundaries, DST and mixed epoch/relative windows. Both graph and topology receive latest and timezone. URL parsing defers relative ordering until the signed-in timezone is known.
- Recent latest bounds show **Incomplete window**, explaining five-minute buckets and ten-minute rollup lag. Superseded time previews are canceled and ignored; active preview errors and timeouts are explained.
- `fixtures/demo-scopes.json` contains six scopes captured from the initialized lab's actual macro output, with query, window, input/output schema, source and macro hash. Demo scope controls retain the captured map scope and its historical window; uncaptured map scopes are disabled.
- Integration preserves main's complete KV/legacy migration-source backup allowlist and aligns current install/upgrade guidance with the single release archive.

## Verification

| Command | Result |
| --- | --- |
| `npm run lint` | Passed. |
| `npm test` | 253 passed across 21 files. |
| `npm run package` | Passed; one archive and checksum. |
| `python3 tools/check_release.py --dist dist` | Passed; now requires the scope fixture. |
| `npm run test:browser` | 12 passed, including picking a scope/preset, invalid drafts, dependent clearing, demo truthfulness and classic-dashboard form-style isolation. |
| `npm run typecheck:browser` | Passed. |
| `ruff check tools tests` | Passed. |
| `ruff format --check tools tests` | Passed. |
| `python3 -m unittest tests.test_demo_scopes` | 2 passed; nonempty capture and schema/hash grounding. |
| `python3 -m unittest tests.test_release tests.test_appinspect tests.test_atlas_build` | 22 passed. |
| `splunk-appinspect inspect dist/splunk_adm-0.2.0.tar.gz --mode precert --included-tags cloud --output-file dist/appinspect-cloud.json` | Python 3.11, AppInspect 4.3.1: 0 failures, 0 errors, same 5 warnings. |
| `python3 tools/check_appinspect.py dist/appinspect-cloud.json` | Passed. |
| Locked full lab suite including restricted-viewer browser checks | 172 ran in 1,269.840 seconds; 171 passed, one existing supervisor alert-tracking test timed out at 30 seconds. All Phase 2 scope and viewer tests passed; no tests skipped. |
| `python3 -m unittest discover -s tests -p 'test_*.py'` | 158 passed. |
| `ADM_LAB=1 python3 tools/lab_lock.py --root . -- python3 /tmp/atlas-phase2-supervisor.py` | The exact failed supervisor test passed unchanged in a fresh lab: 1 passed in 38.913 seconds. |

The final real screenshot exposed classic dashboard form rules painting white fields inside dark Toolkit ComboBoxes. A scoped input reset corrected that without changing Splunk chrome. A new browser regression verifies the reset under classic form rules. `ADM_LAB=1 python3 tools/lab_lock.py --root . -- python3 /tmp/atlas-phase2-viewer.py` then repeated the real viewer test in both themes: 1 passed in 144.333 seconds, including computed field surface/border/shadow checks. AppInspect was rerun against the revised archive and retained 0 failures, 0 errors and 5 warnings.

The full suite’s sole failure was `test_expired_claim_matrix_is_read_only_and_tracks_alert`: its row, immutability and schedule assertions passed, but the asynchronous fired-alert record did not appear within 30 seconds under the full run’s load. The exact test passed unchanged in a fresh lab. This remains an existing timing flake; the full-suite run itself was not completely green. No check was relaxed or skipped.

The locked lifecycle uses `ADM_LAB=1 python3 tools/lab_lock.py --root . -- python3 /tmp/atlas-phase2-lab.py`. It refuses an existing lab container, temporarily links ignored research data, starts/installs the source app, initializes TA-shaped fixtures through `DataLayerTest.setUpClass`, and runs `tools/capture_demo_fixtures.py --output fixtures/demo-scopes.json`. It then installs the final package assets and runs `ADM_LAB=1 ADM_UPGRADE_PACKAGE=dist/splunk_adm-0.2.0.tar.gz python3 -m unittest discover -s tests/splunk -v`, followed by purge and symlink cleanup in `finally`.

Early capture attempts exposed incorrect generating-search invocation; those runs were cleaned up. The final capture uses `| adm_scope_options` macro expansion and returned six genuine binding scopes.

Independent review found and verified fixes for malformed relative-time gaps, timezone disagreement between validation layers, repeated DST hours, stale preview responses/timeouts, captured demo truthfulness and a job-cancellation race in the viewer harness. Targeted final review passed 49 tests. The restricted viewer passed both dark/light themes, actual Honolulu offset 600, macro-driven scopes, a completed recent-window build, historical reload, legacy bookmarks, demo mode and Setup denial.

## Size and limits

The Toolkit time picker increases the bundle beyond the earlier 350 KB gzip comparison target. Final measured size: **2,073,514 bytes raw / 512,912 bytes gzip**, measured with Python gzip. The five warnings remain Python script existence, custom-conf replication, collections, Python SDK version, and synthetic host/IP values. No SplunkJS or custom-Mako warning was introduced. The standard dashboard panel boundary is retained. Captured demo screenshots (`dist/atlas-phase2-demo-light.png`, `dist/atlas-phase2-demo-dark.png` in the ignored `dist/` directory of the qualification checkout) were inspected; they are not committed or shipped.

All lab runs purged their owned container, volumes, cached image and lab credentials and removed the temporary research symlink. Ephemeral viewer accounts and roles were cleaned up. Real viewer screenshots (`dist/atlas-live-dark.png`, `dist/atlas-live-light.png`) are uncommitted local diagnostics in the same ignored directory.

Live qualification targets Splunk Enterprise 10.6.0.5. Live Splunk Cloud runtime and formal vetting remain unverified. No new product decision is outstanding.
