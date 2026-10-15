# Application Atlas — Phase 4 catalog and Find

2026-10-14. Phase 3 was committed locally as `ca77f18`. Phase 4 is on
`codex/atlas-phase-4` in the attached `atlas-phase-1` worktree and is committed locally. No push, PR, merge or publication was performed.

## Delivered

- Disabled-by-default hourly `ADM - Application catalog`, restricted to
  administrator owner dispatch. The catalog KV/lookup is readable by viewers;
  REST and `outputlookup` writes require `admin`/`sc_admin`.
- Stable keys hash an unambiguous JSON array of the four scope dimensions.
  Bound pods count retained OTel bindings. Metrics count distinct direct
  conversations and peers in the recorded observation window, with observed
  ACL drops and private unknown peers distinguished. Multiple services sharing
  a pod retain their own binding timestamps.
- Inline paged reads and expansion checks prevent publishing incomplete
  snapshots. A failed/capped computation leaves the previous catalog intact.
  The writer upserts retained scopes; it does not prune old scopes.
- Exact IP/EPG/device Find uses the existing temporal, scoped identity rules.
  It returns applications bound to a matching pod or observed communicating
  with the matching endpoint. Both client and server enforce a single-line
  allowlist. Incomplete evidence produces a warning instead of a false no-match.
- Sortable Toolkit table, Toolkit Find field, accessible map actions, displayed
  metric windows, and configured-scope fallback with unavailable metrics.
  Missing/unsupported dimensions remain visible as disabled repair rows.
  Empty data alone does not establish that the catalog job is disabled.
- Actual ACI captures in `fixtures/demo-catalog.json` and `demo-find.json`:
  five scopes and four exact queries, with schema, raw source and transitive
  macro definition hashes. Find uses the captured one-hour window; map links
  use the actual captured 15-minute map window. Uncaptured queries/maps are
  disabled with explanations. Fixture files load only on demand.
- Catalog state participates in the existing backup/restore collection list.
  Pipeline health recognizes its hourly cadence. The standard dashboard panel
  boundary remains in place.

## Verification

| Command | Result |
| --- | --- |
| `npm run lint` | Passed. |
| `npm test` | 296 passed across 26 files. |
| `npm run test:browser` | 24 passed, including catalog/Find routing, sorting, stale responses, demo limits and table layout on wide/narrow screens. |
| `npm run typecheck:browser` | Passed. |
| `npm run package` / `python3 tools/check_release.py --dist dist` | Passed. |
| `ruff check tools tests` / `ruff format --check tools tests` | Passed. |
| `python3 -m unittest tests.test_demo_catalog -v` | 3 passed; actual capture schemas, keys and transitive macro provenance match. |
| Python 3.11 AppInspect Cloud precert / `python3 tools/check_appinspect.py dist/appinspect-cloud.json` | Passed: 0 failures, 0 errors, same 5 warnings. |
| Locked focused catalog lab suite | 12 passed in 134.261 seconds. |
| Locked full Splunk 10.6 lab suite | 188 ran in 1,400.732 seconds: 187 passed; the new native Find browser selector was ambiguous. |
| Corrected real restricted-viewer browser qualification | Passed in 161.046 seconds, exercising dark/light themes, catalog → map, Find → map, and completed nonempty native evidence searches. |
| `python3 -m unittest discover -s tests -p 'test_*.py'` | 161 passed in 7.671 seconds after lab cleanup. |

The full run itself was not completely green. Its new Find browser locator
resolved multiple matches in the native Splunk page. The corrected
harness scopes controls to `#atlas-root .atlas-find` and selects the first Find
results container before selecting the requested application. The focused live
rerun passed both themes without weakening backend, permission, map or search
assertions. Its seed/query window is exactly the preceding hour. The installed
Atlas asset matched the final built asset after the package upgrade. A duplicate
queued full run was stopped during fixture setup and supplied no additional
qualification result.

The full lifecycle held the cooperative lab lock with
`python3 tools/lab_lock.py --root . -- python3 -u /tmp/atlas-phase4-lab.py`.
It refused an existing lab container, installed the source app and ran
`ADM_LAB=1 ADM_UPGRADE_PACKAGE=dist/splunk_adm-0.2.0.tar.gz python3 -m unittest discover -s tests/splunk -v`.
The focused rerun used the same owned lab and lock with
`python3 -m unittest tests.splunk.test_views_viewer.ViewerBrowserTest -v`.
Cleanup successfully removed the owned container, volumes, image, lab secrets
and temporary research link. Ephemeral viewer accounts/roles were cleaned by
the harness. The three foreign collector containers remained untouched, and
the temporary preview server was stopped.

Final archive SHA-256:
`623b986cc97d66b992a2d9747f861d9f74131883a0935de1c0ed921280ec5fbf`.

Independent review addressed scope timestamp association, paging/expansion
completeness, cancellation, captured window truthfulness, and overlong binding
values. Visual QA caught incorrect Toolkit header nesting that functional tests
missed; the corrected table uses direct HeadCells and contained horizontal
scrolling. Dark/light screenshots are available under `dist/atlas-phase4-*.png`.

## Limits

Live Splunk Cloud runtime and formal Cloud vetting remain unverified. The final
Atlas JavaScript is 2,287,372 raw / 570,821 gzip bytes, above the original
1.2 MB raw / 350 KB gzip comparison budget. The local AppInspect result is not a
substitute for formal Cloud vetting. No production resources were changed.
