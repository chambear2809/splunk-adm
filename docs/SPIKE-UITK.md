# Application Atlas — Phase 0 UI Toolkit compatibility spike

Date: 2026-10-14. Scope: local only; no commit, push, or PR.

## Recommendation: PENDING sign-off — evidence now favours HYBRID

The Toolkit itself is not blocked. Gates 1 and 2 pass. Gate 3's two AppInspect failures also occur on unchanged main, so they are **not Toolkit-attributable**. HYBRID is the worktree's shipping prototype. It runs offline Cloud precert with **no custom-Mako warning and no new warnings**, and on 2026-10-14 it **passed gates 4–7 live on Splunk 10.6.0.5** as a search-only viewer: render, 46 rows, CSRF, dark and light theme, `Pacific/Honolulu`, and PNG export. Getting there needed three host-compatibility fixes, described under [HYBRID runtime qualification](#hybrid-runtime-qualification-splunk-10605); all three are in the worktree. GO-builtin has no runtime evidence yet.

**Support targets (final decision, 2026-10-14): Splunk Cloud and Splunk Enterprise 10.6+.** Splunk 10.4 is not supported. Cloud support carries the most weight in this comparison.

| Criterion                                                  | GO — full-page Toolkit on built-in `pages/splunk_ui_app.html`                                                                                                                                                                                                                                                                                                  | HYBRID — Simple XML `script=` mounts Toolkit React (worktree)                                                                                                                                                                                   | FALLBACK — legacy Simple XML UI + SearchClient adapter                                                     |
| ---------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| **Cloud vetting risk**                                     | Medium. The platform template is documented only through `@splunk/create` 11.x (Splunk 10.4+). We have not checked Cloud documentation saying which Cloud stack releases ship it. The candidate package has 1 extra warning (`check_for_splunk_js_header_and_footer_view`, from `react-page`'s HeaderView). The full-page JS bundle still needs manual review. | Low–medium. Splunk documents Simple XML `script=` for Cloud apps. The worktree package's AppInspect result is check-for-check identical to main. The custom JS still needs manual review, and only a real vetting submission confirms approval. | Low. Same structure as main today. Custom JS still needs review.                                           |
| **Mako deprecation exposure**                              | None from the app; the template is platform-owned. Measured on the diagnostic package: `check_for_custom_mako_templates` not_applicable. (The earlier custom-template variant warned twice.)                                                                                                                                                                   | None. Measured on the worktree package: `check_for_custom_mako_templates` not_applicable. The release validator now rejects `appserver/templates/` and `appserver/modules/`.                                                                    | None.                                                                                                      |
| **Bundle raw / gzip (measured, app-owned JS)**             | 1,076,220 / 272,633 (react-page full-page variant)                                                                                                                                                                                                                                                                                                             | **1,059,561 / 267,139** (`pages/atlas.js` as shipped). `adm.css` is not loaded on `map`.                                                                                                                                                        | 323,023 / 93,400 today, plus the adapter (not built or measured)                                           |
| **Theme / CSRF / timezone**                                | Same `SpikePage` code passed live on the custom-template host. The built-in host's bootstrap has not been tested.                                                                                                                                                                                                                                              | **PASS live on 10.6.0.5** after the theme-API and CSS fixes. The classic dashboard canvas around the panel stays light under a dark preference; this is a platform limitation shared with the legacy `dependency_map`.                          | Existing legacy implementation; CSRF is handled inside SplunkJS. No Toolkit theme.                         |
| **SearchManager retirement**                               | Removed (`@splunk/search-job`)                                                                                                                                                                                                                                                                                                                                 | Removed from `pages/atlas.js`: 0 matches for `SearchManager`, `splunkjs/` and `HeaderView`. The legacy `adm.bundle.js` still ships for `dependency_map` until Phase 1.                                                                          | Kept behind the adapter. The SplunkJS dependency and its AppInspect telemetry warning remain.              |
| **Migration effort**                                       | Medium. The built-in host loads a view-named asset (`pages/<view>.js`), so each page needs its own entry or copy. Page chrome comes from `react-page` or our own code.                                                                                                                                                                                         | Low–medium. One Simple XML view per page, all loading `pages/atlas.js`; the plan's "shared template" items map directly. The React page sits inside a dashboard panel, which limits layout.                                                     | Lowest now, highest later: Phases 2–8 would rebuild scope bar, time picker and tables without the Toolkit. |
| **Splunk version support**                                 | Covered on 10.6: the built-in template needs 10.4+. Whether Cloud stacks ship it is unverified.                                                                                                                                                                                                                                                                | Covered on 10.6. Needs only Simple XML `version="1.1"`, which `map.xml` uses (10.4 removed 1.0 and HTML dashboards). Uses no classic custom visualizations (deprecated in 10.6).                                                                | Same as HYBRID                                                                                             |
| **Cloud prerequisite: `default/limits.conf`**              | Required: remove it (`check_limits_conf`)                                                                                                                                                                                                                                                                                                                      | Required: remove it                                                                                                                                                                                                                             | Required: remove it                                                                                        |
| **Cloud prerequisite: `[triggers]` in `default/app.conf`** | Required: add it (`check_reload_trigger_for_all_custom_confs`)                                                                                                                                                                                                                                                                                                 | Required: add it                                                                                                                                                                                                                                | Required: add it                                                                                           |

The two Cloud prerequisites apply equally to all three options. They belong in the separate prerequisite PR: per the plan, `adm_observer_scope` moves to KV store and `limits.conf` is dropped. They do not distinguish the options.

### Is HYBRID the best fix?

On current evidence, **HYBRID is the strongest candidate for the Cloud + 10.6 requirement**. It is now runtime-qualified on 10.6 but not yet vetted for Cloud:

- **Fewest platform assumptions.** HYBRID depends only on Simple XML 1.1 and `script=`, both documented for Cloud. The 10.4 and 10.6 deprecation notes were checked on 2026-10-14. 10.4 removed jQuery 2 / `version="1.0"` and HTML dashboards; classic-dashboard PDF export has been deprecated since 9.4. 10.6 newly deprecates custom visualizations in classic dashboards, which Atlas doesn't use. Neither release lists Simple XML 1.1, dashboard custom JS, or SplunkJS. GO depends on a platform template we have only seen in the `@splunk/create` changelog and generator. Its availability on a given Cloud stack is unverified, and Cloud stack upgrades run on Splunk's schedule.
- **Same offline result as main.** No new AppInspect findings. The only message differences from main are line-number shifts inside the legacy `adm.bundle.js`.
- **Cheap to reverse.** The host-specific code is about 60 lines in `frontend/src/spike/main.tsx` plus one XML file per view. Page components, SearchJob, theme and timezone code don't depend on the host. If GO-builtin later qualifies on 10.6 and the target Cloud stack, switching costs one entry-point change per page.
- **Runtime-qualified.** HYBRID passed gates 4–7 on 10.6.0.5 (run 4 below). GO-builtin has not been run.
- **Known HYBRID costs.** The UI lives inside a classic dashboard panel, which constrains full-height map layout. The dashboard canvas stays light under a dark preference. The bundle must defend itself against the classic page's globals and CSS: RequireJS `define` and dashboard HTML-panel text colours both broke the first runs. Splunk steers new dashboard work toward Dashboard Studio; the 10.6 deprecation of classic custom visualizations is a sign of that direction, though not one that affects the `script=` hook. We don't use classic PDF export: PNG uses canvas, and planned PDF uses `window.print()`.
- **FALLBACK is not supported by the evidence.** Its AppInspect result is the same as HYBRID's, yet it keeps SplunkJS and forgoes the Toolkit for every later phase.

What remains for HYBRID: (1) confirm the Cloud stack version the pilot will run on; (2) eventually, a real Cloud vetting submission; (3) decide whether the light dashboard canvas around a dark Atlas page is acceptable, or whether Phase 1 should make Atlas fill the panel edge to edge. GO-builtin would need its own live bootstrap check on 10.6 before it could be compared on runtime evidence.

## Gate summary

| Gate                                     | Result                                        | Evidence                                                                                                                                                        |
| ---------------------------------------- | --------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1. Peer dependencies                     | PASS                                          | `npm ls --all` exits 0 after removing `@splunk/react-page`; React/ReactDOM 18.3.1, styled-components 5.3.11.                                                    |
| 2. Bundle ceiling                        | PASS (gzip budget)                            | HYBRID `pages/atlas.js` 1,059,561 raw / 267,139 gzip. 350 KB gzip is the shipping comparison; the 1.2 MB raw figure was our own estimate, not a Splunk limit.   |
| 3. AppInspect Cloud precert              | FAIL — **not Toolkit-attributable**           | Worktree HYBRID package and clean main both give 112 success / 2 failure / 0 error / 7 warning / 124 n/a / 1 skipped, with the same failed checks and messages. |
| 4. Viewer render + Toolkit search + CSRF | **PASS on HYBRID** (and custom-template host) | HYBRID run 4: mounted in `#atlas-root`, 46 rows, 10 edge cells; viewer's SearchJob POST returned 201.                                                           |
| 5. User theme                            | **PASS on HYBRID** after fix (run 1 FAIL)     | Run 1 always rendered light. With `resolveUserTheme()`, dark → dark (`rgb(23,29,33)`) and light → light; text inherits the theme colour.                        |
| 6. User timezone                         | **PASS on HYBRID**                            | `Pacific/Honolulu` read from the signed-in user's REST record.                                                                                                  |
| 7. Canvas PNG under Splunk policy        | **PASS on HYBRID**                            | HYBRID: 6,517 (dark) / 6,456 (light) byte PNGs, download initiated, 0 blob/canvas/CSP errors.                                                                   |

## Implementation (HYBRID, in this worktree)

- `default/data/ui/views/map.xml` is a Simple XML 1.1 dashboard: `script="pages/atlas.js"`, `hideTitle`, `hideEdit`, and one `<html>` panel containing `<div id="atlas-root">`. There's no app stylesheet; the Toolkit's styled-components handle styling.
- `frontend/src/spike/main.tsx` checks the URL path against the allowlist (`spikePage`). It waits for `#atlas-root` with a `MutationObserver` (30-second timeout), resolves the theme with `resolveUserTheme()`, and mounts `createRoot(node)` under `SplunkThemeProvider` with `getThemeOptions(preference)`. A `data-mounted` guard prevents a double mount. It uses neither `splunkjs/mvc/simplexml/ready!` nor any SplunkJS module.
- `frontend/src/spike/theme.ts` (`resolveUserTheme`): when the page has an AMD loader (`window.require` plus `define.amd`), it loads Splunk's `build/api/get_theme.js` through RequireJS and calls its `getTheme()`. Otherwise, or on any failure or empty result, it falls back to splunk-utils' `getUserTheme()`. `theme.test.ts` covers the AMD module, global API, failure/empty fallbacks and the no-AMD path.
- `vite.toolkit.config.ts` adds `rolldownOptions.output.intro: "var define;"`. This shadows RequireJS's global `define` inside the IIFE, so UMD dependencies (lodash) take their CommonJS path. The bundle has 0 reachable global `define`/`define.amd` references; the only `define` lookup left is `theme.ts`'s explicit `window.define?.amd`.
- `SpikePage.tsx`'s container adds `&&& :is(h1, h2, h3, p) { color: inherit; }` so classic dashboard HTML-panel colours don't override Toolkit text colours. It otherwise matches the earlier live-qualified page. It makes one `SearchJob.create` of the validated `adm_graph(...)`, passing `getDefaultFetchInit()` to `SearchJob.setBaseFetchInit`. It reads the timezone from the signed-in user's REST record, caps results at the pilot limit, and cancels the job on unmount or after a 120-second timeout.
- No app-owned Mako template ships. The old `appserver/templates/atlas.html` was moved out of the tree to `/tmp/adm-uitk-retired-template/` (reversible). `@splunk/react-page` was uninstalled because the Simple XML host provides the chrome.
- `tools/check_release.py` no longer requires the template. It now **rejects** any `appserver/templates/` or `appserver/modules/` member (case-insensitive), covered by `tests/test_release.py::test_rejects_custom_mako_template`. `tools/package-app.mjs` no longer requires the template either.
- Unchanged from the spike: `.npmrc` (public registry for `@splunk` and the default registry), React 18 / Toolkit pins, `interop.ts`, and verified license fallbacks (`tools/licenses/`).

## Gate 1

```sh
npm uninstall @splunk/react-page --registry=https://registry.npmjs.org
npm ls --all
```

Exit 0, 0 vulnerabilities. Top level: `@splunk/react-ui@5.17.0`, `@splunk/search-job@3.1.0`, `@splunk/splunk-utils@4.1.0`, `@splunk/themes@1.13.0`, `react@18.3.1`, `react-dom@18.3.1`, `styled-components@5.3.11`. `search-job` installs a nested `splunk-utils` 3.4.0; that's duplication, not a peer conflict.

## Gate 2 — bundle evidence

All sizes are Node `zlib` gzip level 6.

| Build                                                |     Raw bytes |  Gzip bytes | Status                       |
| ---------------------------------------------------- | ------------: | ----------: | ---------------------------- |
| Original Toolkit, interactive Table (react-page)     |     1,293,410 |     328,593 | measured                     |
| Trimmed, SimpleTable (react-page)                    |     1,076,220 |     272,633 | measured                     |
| Dynamic-split experiment, first-load static closure  |       603,056 |     153,012 | measured, not runtime-tested |
| Dynamic-split experiment, selected lazy page         |      +473,454 |    +121,919 | measured                     |
| Dynamic-split total code for that page               |     1,076,510 |     274,931 | measured                     |
| HYBRID IIFE experiment (`/tmp`, `ready!` mount)      |     1,058,787 |     266,817 | measured                     |
| Existing `adm.css` (added only if a page loads it)   |        25,184 |       5,353 | measured                     |
| HYBRID worktree, before runtime fixes                |     1,059,060 |     266,884 | measured                     |
| **HYBRID as shipped in worktree (`pages/atlas.js`)** | **1,059,561** | **267,139** | measured                     |
| Legacy `adm.bundle.js` (full SVG map, React 18)      |       323,023 |      93,400 | measured                     |

The 1.2 MB raw ceiling was **our planning estimate**. **350 KB gzip** is the comparison that matters for shipping. The split experiment does not reduce time to first usable map, because the selected page must also load. It needs an ES-module loader before it could ship.

### Ten largest modules in `pages/atlas.js` (HYBRID)

`node /tmp/adm-uitk-analyze.mjs /tmp/adm-uitk-hybrid-analysis` builds `vite.toolkit.config.ts` into a temporary directory. A diagnostic plugin writes Rolldown's per-module `renderedLength` to `/tmp/adm-uitk-hybrid-analysis-modules.json`. The analysis build was the same size as the bundle shipped at the time (1,059,060 / 266,884), before the three runtime fixes added 501 raw / 255 gzip bytes. These are rendered bytes **before final minification**, so they rank modules but don't add up to the bundle size. The total across 816 modules is 1,927,310, and project-owned `frontend/src` code is 12,784.

|   # | Module                                                             | Rendered bytes |
| --: | ------------------------------------------------------------------ | -------------: |
|   1 | `react-dom/cjs/react-dom.production.min.js`                        |        190,670 |
|   2 | `lodash/lodash.js`                                                 |        185,882 |
|   3 | `colorjs.io/dist/color.cjs`                                        |        126,988 |
|   4 | `@react-spring/core/dist/cjs/react-spring_core.production.min.cjs` |         42,810 |
|   5 | `@splunk/react-ui/Popover.js`                                      |         38,554 |
|   6 | `fixtures/demo-rows-aci.json`                                      |         35,361 |
|   7 | `@splunk/themes/enterprise/light.js`                               |         33,038 |
|   8 | `@splunk/themes/splunk-magnetic/magneticTokensLight.js`            |         30,398 |
|   9 | `@splunk/themes/splunk-magnetic/magneticTokensDark.js`             |         30,394 |
|  10 | `styled-components/dist/styled-components.browser.esm.js`          |         27,329 |

Earlier react-page builds (`/tmp/adm-uitk-bundle-analysis-modules.json`, `/tmp/adm-uitk-trimmed-analysis-modules.json`) have the same top three. The pre-trim build also had `@splunk/react-ui/Table.js` (177,311) and `@dnd-kit/core` (92,464), which SimpleTable removed. Item 6 is demo data pulled in through `provider.ts` → `fixtures/*.json`. All four demo fixtures together are 71,742 raw / 7,034 gzip, so splitting demo data out of the Splunk bundle saves raw bytes but little gzip. `lodash` and `colorjs.io` come in through Toolkit internals; our imports are all deep imports. lodash's UMD wrapper is also what emitted the anonymous `define()` on the Simple XML page (see HYBRID runtime qualification).

### Estimate: HYBRID plus the full SVG map (not measured)

- React runtime, measured standalone (`react-dom`, `react`, `scheduler`, `jsx-runtime` production files concatenated): 143,709 raw / 46,269 gzip.
- Legacy app code without React ≈ 323,023 − 143,709 ≈ **179 KB raw**, and 93,400 − 46,269 ≈ **47 KB gzip**.
- HYBRID + full map ≈ 1,059,561 + 179,314 ≈ **1.24 MB raw**, and 267,139 + 47,131 ≈ **314 KB gzip**. Some code is already in both bundles (demo fixtures, `provider.ts`, `rows.ts`), and the legacy chrome is replaced, so the real figure should be somewhat lower.
- Upper bound: concatenating both current bundles (React included twice) gives 1,382,083 raw / **359,840 gzip**.

**Estimate:** about 300–315 KB gzip, under 350 KB with roughly 35–50 KB headroom. Raw would likely exceed our own 1.2 MB estimate. Phase 1 must measure the real merged build. The cheapest reductions are moving demo fixtures out of the Splunk bundle and checking whether `lodash`/`colorjs.io` can be deduplicated.

## Gate 3 — AppInspect Cloud precert

```sh
/tmp/adm-uitk-appinspect311/bin/splunk-appinspect inspect dist/splunk_adm-0.2.0.tar.gz \
  --mode precert --included-tags cloud --output-file /tmp/adm-uitk-hybrid-worktree-appinspect.json
```

AppInspect 4.3.1 under Python 3.11. The CLI exits 0 even when checks fail, so the result comes from the report. Worktree install archive SHA-256: `533e4ce90d430b1613c66106522cd765e46a13138911401d8997537dd8c5679d` (final package, after the runtime fixes; same AppInspect result as every earlier HYBRID package).

### Clean-main baseline

Built in a detached temporary worktree at `/tmp/adm-main-baseline`, main commit `79a6fa38e52ab0dfb995dd6b9015854515b2094b`:

```sh
npm ci --ignore-scripts --registry=https://registry.npmjs.org
npm run package
/tmp/adm-uitk-appinspect311/bin/splunk-appinspect inspect dist/splunk_adm-0.2.0.tar.gz \
  --mode precert --included-tags cloud --output-file /tmp/adm-main-baseline-appinspect.json
```

Both npm steps succeeded. The temporary worktree was then removed with `git worktree remove --force /tmp/adm-main-baseline` and `git worktree prune`. It had no tracked changes; `--force` was needed only for ignored `node_modules`/`dist`. The main checkout's `git status --short` was identical before and after; its unrelated untracked files were not touched.

### Structured comparison

`/tmp/adm-compare-reports.py` reads each report's `reports[].groups[].checks[]`. It compares check names, results and message text.

| Package                               | Success | Failure | Error | Warning |     N/A | Skipped |   Total |
| ------------------------------------- | ------: | ------: | ----: | ------: | ------: | ------: | ------: |
| Clean main (`79a6fa3`)                |     112 |       2 |     0 |       7 |     124 |       1 |     246 |
| Original custom-Mako spike            |     110 |       2 |     0 |      10 |     123 |       1 |     246 |
| HYBRID diagnostic (`/tmp`)            |     112 |       2 |     0 |       7 |     124 |       1 |     246 |
| Built-in full-page candidate (`/tmp`) |     111 |       2 |     0 |       8 |     124 |       1 |     246 |
| **HYBRID worktree package**           | **112** |   **2** | **0** |   **7** | **124** |   **1** | **246** |

- Failures, identical in name and message in every report:
  - `check_limits_conf`: "Changes to 'limits.conf' are not allowed. Memory limits should be left to Splunk Administrators. Please remove this file. File: default/limits.conf"
  - `check_reload_trigger_for_all_custom_confs`: "App contains one or more custom configs but does not have a `[triggers]` stanza in app.conf. File: default/app.conf"
- HYBRID worktree vs main: **no check has a different result.** The warning set is the same seven checks: `check_collections_conf`, `check_custom_conf_replication`, `check_for_python_script_existence`, `check_for_splunk_js`, `check_hostnames_and_ips`, `check_python_sdk_version`, `check_reload_trigger_for_meta`. The only message differences are line numbers inside the legacy `adm.bundle.js` (`splunkjs/mvc` at line 12 → 11; fixture IPs at line 9 → 8), caused by its React 19 → 18 rebuild. No message mentions `pages/atlas.js` or `map.xml`.
- `check_for_custom_mako_templates`: **not_applicable** ("No custom Mako template files found."). `check_for_existence_of_python_code_block_in_mako_template` and `check_for_splunk_js_header_and_footer_view` both pass. **No new warnings.**
- The original spike's three extra warnings came from its custom template and `react-page`, not from Toolkit components or SearchJob.
- The remaining `check_for_splunk_js` warning ("telemetry … no impact") comes from the legacy `adm.bundle.js`. Since `pages/atlas.js` has no `splunkjs/` reference, it should disappear once Phase 1 retires the legacy bundle.

Local precert is not Cloud vetting approval.

## Gates 4–7 — earlier runtime evidence (custom-template host)

Lab: Splunk 10.6.0.5, image `sha256:9280f9ce267b212e5596aa1832cdfd3f9be886c378da35ebc87499323ee447a4`, run under `ADM_LAB=1 python3 tools/lab_lock.py`. The ephemeral viewer's role had only `search` plus fixture-index access. Query: `adm_graph("frontend","demo","demo-cluster","shop")`, earliest `1791373500`, latest `1791374400`.

- Gate 4: for the restricted viewer, REST returned 46 rows, matching the admin reference. The page rendered the SimpleTable with 10 edge cells in both dark and light. Successful SearchJob POST/results under the search-only role, with the `getDefaultFetchInit()` → `setBaseFetchInit()` path, is the CSRF evidence. The form key was never printed.
- Gate 5: the viewer's `user-prefs` theme was switched between dark and light; each reload rendered the matching Toolkit scheme.
- Gate 6: the viewer's `tz` was set to `Pacific/Honolulu` (host zone America/New_York), and the page displayed it.
- Gate 7: a 480 × 100 SVG went through a blob image and canvas to `image/png`, giving 5,602 bytes (dark) and 5,731 bytes (light), with 0 blob/canvas/CSP errors.

## HYBRID runtime qualification (Splunk 10.6.0.5)

Driver: `ADM_LAB=1 python3 tools/lab_lock.py --root . -- python3 /tmp/adm-hybrid-qual/driver.py`, started through `/tmp/adm-hybrid-qual/run.sh`. Each run refuses to adopt an existing container. It holds the cooperative lock, runs `lab.sh up` and `lab.sh install` (source app, so the current `pages/atlas.js`), and creates the ephemeral search-only viewer from `RestrictedViewerTest`, checking its REST graph against the admin's (46 rows). It sets `tz=Pacific/Honolulu`, then signs in through headless Chromium (the project's Playwright). For each of dark and light it sets the viewer's `user-prefs` theme, loads `map?earliest=1791373500&latest=1791374400`, and records page evidence and a screenshot, then clicks Export PNG. `finally` deletes the viewer and role, runs `lab.sh down` (container and volumes; the cached image is kept) and removes the temporary `research/extracted` symlink. Credentials reach the browser process only through its environment; no log or evidence file contains them. Evidence: `/tmp/adm-hybrid-qual/evidence-run{2,3,4}.json`, `run{2,3,4}.log`, `map-{dark,light}-run{2,3,4}.png` (run 1: `map-{dark,light}.png` and the log above).

| Run | Bundle                  | Result                                                                                                                                                                                                                                                                                                |
| --: | ----------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
|   1 | HYBRID as first built   | Render, 46 rows, CSRF (201), timezone and PNG pass. **Theme FAIL:** both preferences reported `enterprise` and rendered light. Exit 1 only because the browser helper didn't exit after `quit`; cleanup completed.                                                                                    |
|   2 | + `resolveUserTheme()`  | **Theme pass** (dark → `rgb(23,29,33)`). New: a RequireJS "Mismatched anonymous define()" error and Splunk's user-visible banner _"A custom JavaScript error caused an issue loading your dashboard."_ Dark-mode headings and paragraphs were unreadable. A diagnostic pass found the causes (below). |
|   3 | + `var define;` intro   | No mismatch error and no banner; theme, rows, timezone, PNG pass. Text colours measured `rgb(60,68,77)` on `rgb(23,29,33)` (the CSS fix wasn't in this build yet).                                                                                                                                    |
|   4 | + CSS isolation (final) | **All gates pass.** Dark: theme dark, text `rgb(225,230,235)` on `rgb(23,29,33)`, PNG 6,517 B. Light: theme light, text `rgb(92,103,115)`, PNG 6,456 B. Both: 46 rows, 10 edge cells, `Pacific/Honolulu`, SearchJob POST 201, `requireMismatch: false`, 0 CSP/canvas errors.                          |

Root causes, from the run 2 diagnostic pass:

- **Theme API vs RequireJS.** `build/api/get_theme.js` is a UMD bundle that checks `define.amd` before falling back to a global. On Splunk's launcher (React, no AMD loader) it sets `window.__get_theme__`, and the page renders dark (`rgb(23,29,33)`). On the Simple XML `map` page (`define.amd` is true) it registers as an AMD module instead, so `window.__get_theme__` is undefined and splunk-utils' `getUserTheme()` falls back to `enterprise` (light). Loading it through RequireJS fixes this.
- **lodash vs RequireJS.** lodash's UMD wrapper (pulled in by Toolkit internals) prefers AMD: on the Simple XML page it called an anonymous `define(function(){return _})`, which RequireJS reports as a mismatch, and assigned the global `_`. Shadowing `define` inside the IIFE sends it down its CommonJS path. Splunk's own page global `_` is also lodash 4.18.1 (measured on the legacy `dependency_map` page), so version alone can't show which copy is present; the static bundle check is the evidence that ours no longer writes it.
- **Dashboard CSS.** Classic HTML-panel rules set `h1`/`p` colours (`rgb(60,68,77)`), overriding the Toolkit container's colour. Phase 1 needs a scoped style reset for every page, not just this probe.
- **Dashboard canvas.** Classic dashboards don't follow the user's dark preference: the `map` body and the legacy `dependency_map` body are both `rgb(242,244,245)` with the viewer set to dark. The Atlas page itself renders dark.
- **403s in the console.** These are Splunk Web chrome requests the search-only role can't make: `configs/conf-web/settings`, `configs/conf-limits/structured_data_service`, `conf-limits/federated_analytics`, and every app's `static/appIcon.png` (including `search`). They also occur on Splunk's own launcher page, so Atlas doesn't cause them.

HYBRID's 10.6 runtime gates therefore pass with the three fixes. GO-builtin and the Cloud runtime remain untested.

## Validation

| Command                                                    | Result                                                                              |
| ---------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| `npm ls --all`                                             | PASS, exit 0                                                                        |
| `npm run lint`                                             | PASS, exit 0 (ESLint, `tsc`, Prettier)                                              |
| `npm test -- --maxWorkers=1`                               | PASS: 16 files, 287 tests (includes 4 new `theme.test.ts` tests)                    |
| `npm run package`                                          | PASS, exit 0; `pages/atlas.js` 1,059,561 B (Node measure)                           |
| `python3 tools/check_release.py --dist dist`               | PASS: `Release archives verified in dist`                                           |
| `python3 -m unittest discover -s tests -p test_release.py` | PASS: 10 tests, including the new Mako-rejection test                               |
| `npm run typecheck:browser`                                | PASS, exit 0                                                                        |
| `npm run test:browser`                                     | PASS: 4 existing legacy scenarios. Not evidence for the Toolkit host.               |
| `ruff check tools tests`                                   | PASS                                                                                |
| `ruff format --check tools tests`                          | FAIL, exit 1: untouched `tests/splunk/test_aci.py` only (pre-existing on main)      |
| `git diff --check`                                         | PASS                                                                                |
| AppInspect Cloud precert (final worktree package)          | 2 failures, both identical to main; no new warnings; no Mako warning                |
| HYBRID lab runs 1–4 (Splunk 10.6.0.5)                      | Run 4: all gates 4–7 PASS; every run cleaned up (exit 0 except run 1's helper exit) |

## Local changes

- `docs/SPIKE-UITK.md`
- `docs/DATA_LAYER.md`: documented floor changed from Splunk Enterprise 10.x to 10.6 or later
- `.npmrc`, `package.json`, `package-lock.json`: React 18, Toolkit pins; `@splunk/react-page` removed
- `vite.toolkit.config.ts` (adds the `var define;` IIFE intro)
- `frontend/src/spike/`: `main.tsx` (HYBRID mount), `theme.ts`, `theme.test.ts`, `SpikePage.tsx`, `settings.ts`, `settings.test.ts`, `search-job.d.ts`, `export.ts`, `interop.ts`
- `splunk_app/splunk_adm/default/data/ui/views/map.xml` (Simple XML HYBRID host)
- `tools/package-app.mjs`, `tools/check_release.py`, `tests/test_release.py`
- `tools/licenses/` (verified license fallbacks and provenance)

`tests/splunk/lab.sh` is **unchanged from main**. An orchestration-specific Docker label added during the spike was removed, because this project doesn't use that tooling. Ignored outputs: `dist/`, `appserver/static` bundles, `node_modules`. Nothing was committed, pushed or published.
