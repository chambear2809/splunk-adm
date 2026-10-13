# Browser regression tests

The browser suite exercises the user-visible Application Atlas flow with
Playwright and a Vite-only test harness. The harness injects a small fake
SplunkJS SearchManager backed by the captured ACI demo rows; it is a mock SDK,
not a real Splunk HTTP server. This keeps permission and finalized-result
paths deterministic and avoids requiring Splunk credentials or a lab.

Run the checks locally:

```sh
npx playwright install chromium
npm run typecheck:browser
npm run test:browser
```

The suite covers these paths:

- demo highlight filtering, endpoint inspection, selection clearing, and
  clearing the highlight query;
- live service, environment, cluster, namespace, and time-range submission,
  including the exact `adm_graph` macro string and rendered scope heading;
- live permission errors with bounded Splunk detail;
- finalized/incomplete result warnings.

Playwright writes `test-results/` and `playwright-report/` on failures. These
paths are local diagnostics and should not be committed. A browser job runs in
CI after installing Chromium.
