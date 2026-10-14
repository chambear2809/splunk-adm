# Browser regression tests

The browser suite exercises the user-visible Application Atlas flow with
Playwright and a Vite-only test harness. The harness injects a small fake
SearchClient backed by the captured ACI demo rows; it is a mock SDK,
not a real Splunk HTTP server. This keeps permission and finalized-result
paths deterministic and avoids requiring Splunk credentials or a lab.

Run the checks locally:

```sh
npx playwright install chromium
npm run typecheck:browser
npm run build
npm run test:browser
```

The suite covers these paths:

- demo highlight filtering, endpoint inspection, selection clearing, and
  clearing the highlight query;
- live service, environment, cluster, namespace, and time-range submission,
  including the exact `adm_graph` macro string and rendered scope heading;
- live permission errors with bounded Splunk detail;
- finalized/incomplete result warnings;
- the five foundation pages and validated deep-link reloads;
- injected URL rejection before search dispatch;
- executing the built bundle with dashboard AMD globals, preserving the host lodash global.

Playwright writes `test-results/` and `playwright-report/` on failures. These
paths are local diagnostics and should not be committed. A browser job runs in
CI after installing Chromium.

The live viewer smoke test is `tests/splunk/test_views_viewer.py`, using
`tests/splunk/viewer-browser.mjs`. It runs inside the parent-owned lab lifecycle
under `tools/lab_lock.py`, reuses an ephemeral search-only viewer, and cleans up
that viewer in class cleanup. Credentials reach Chromium only through a child
process environment; error output is bounded and sanitized. It checks live
scope/counts and reload, both themes, the signed-in user timezone, demo mode,
readable page hosts, and denial of the admin-only Setup view. It deliberately
blocks demo asset requests during live mode.
