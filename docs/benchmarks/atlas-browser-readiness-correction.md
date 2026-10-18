# Browser interaction readiness correction

Subsequent status: the coordinator approved this correction and the new accepted
main was measured with it. See [corrected results](atlas-browser-d686-results.md).
The development and bounded smoke record below is preserved.

At development handoff: implementation and bounded correctness checks had passed;
coordinator review and controlled measurement had not yet run. Existing schema 1 raw reports,
numbers and checksum history remain preserved. Their interaction intervals
include Playwright completion before the readiness loop. They are not replaced
by the smoke artifacts below.

## Design

`tests/performance/readiness.ts` owns a browser-side action promise. Arming checks
the old DOM precondition and installs the capture listener before the test
dispatches its input. At capture, the helper timestamps the event and immediately
starts browser frame sampling, independently of Playwright's trigger promise.

The intended DOM postcondition must hold before stable frames count. Losing the
postcondition, invalid geometry or a changed signature resets the count. Three
unchanged comparisons after the first committed frame are required. The real
application gates include:

- Highlight input, rendered matches and match-position text after Enter.
- The expected highlighted card selected with its inspector controls present;
  clearing selection removes those controls and selected state. The Details
  aside itself always exists, including its unselected summary state.
- The requested filter value and rendered filter status; clearing removes status.
- The requested tab's pressed state and actual table, Devices or map contents.
- The selected conversation row and inspector, including the explicit partial or
  unresolved handoff warning where applicable.

The input target must belong to the armed control. Full node/edge counts and
existing finite geometry/readiness conditions remain required. Existing export,
PNG allocation, every CSV evidence row, full graph JSON equality, authority
ambiguity, handoff and Devices-cap checks remain intact. Mount and export
generation retain their original timing boundaries; summary expansion retains
its browser-dispatched action/settling loop.

The test still awaits trigger success and then reads the browser promise.
Readiness cannot turn a failed trigger into success. Missing events or committed
postconditions time out; failures cancel pending frame work. Raw schema 2 records
event-to-ready duration, Node's complete `playwrightTriggerDurationMs`, and the
browser's `triggerCompletionObservedAt` separately. That browser timestamp is
sampled after Playwright returns and includes the following evaluation delay;
it is an upper bound on trigger completion. The report script retains separate
distributions and labels schema 1 versus schema 2 semantics.

## Checks performed

```sh
node_modules/.bin/playwright test --config tests/performance/readiness.config.ts
node_modules/.bin/tsc -p tests/performance/tsconfig.json --noEmit
node --check tests/performance/report.mjs
```

Eight helper checks passed: failed precondition, old stable DOM before commit,
lost postcondition/invalid geometry/signature resets, readiness before trigger
completion, missing capture event, missing postcondition, failed trigger after
ready and cancellation of pending frame work. Typecheck and report syntax checks
passed.

Bounded browser smoke ran sequentially against baseline `510754c` and candidate
`7999d3a`, using one repetition per cache state for Catalyst realistic, realistic
partial handoff and near-limit cases. Each source passed 3/3 cases with six
measured samples plus discarded warmups. Every recorded corrected action passed
its committed postcondition and had finite separate trigger-clock metadata.
Source and harness bytes stayed unchanged within each run; both used harness
hash `95506ec1e1a812ad1629136486e6776342711549496b4e0beff9efe0bf306fb6` and
identical workload fingerprints. The local Splunk verification was active:
these are correctness smokes, not comparative performance evidence. No full
14-case corrected benchmark has been run.

An initial development smoke failed before collecting any sample because its new
precondition assumed the Details aside was absent when unselected. The gate was
corrected to check the selection control/state instead. Its incomplete raw/log
artifacts are preserved and excluded from comparison.

Raw/log locations and checksums are recorded under `methodologyCorrection` in
the evidence index. Smoke commands used:

```sh
ADM_PERF_SOURCE_ROOT=<baseline-or-candidate-checkout> \
  ADM_PERF_OUTPUT=dist/performance/atlas-browser-<role>-readiness-smoke-v2.json \
  ADM_PERF_REPETITIONS=1 ADM_PERF_SCENARIOS=catalyst-aci \
  ADM_PERF_SIZES=realistic,near-limit \
  node_modules/.bin/playwright test --config tests/performance/playwright.config.ts
```
