# Final qualification: browser selection investigation

The renewed comparison measures accepted baseline
`64473e54d1fca4311ac592bc34c4a96a022efd48` against final frozen source
`6ebbf0dae3bd9ff0a2d982fe9f3b561687764eca`, after the deployment-client stale-read
repair. Candidate primary browser-input tree SHA-256 is
`340ef7883a0340fc069fc2148943a8a37a0826bc84f546e725890a38420c6285`; harness SHA-256 is
`75a82d0198e5214c4b48fa37988f3c38f823e68f38175e923ee48b217ab612a7`. Baseline product source remained untouched.

All four fresh runs use the same corrected capture-started protocol and harness.
Source, imported JSON and every actual built/served asset are fingerprinted
before/after each run. All guards pass, and each role’s input/served fingerprints
match between its 20/cache selection run and full matrix. Earlier reports remain
unchanged; they are not substituted for this final-source acceptance.

## Renewed selection distributions

The candidate ran first, accepted baseline second, with **20 measured repetitions
per cache state and 40/40 samples per build**. Each retains mount, highlight,
keyboard highlight jump and card selection preconditions, exact graph counts,
finite geometry, intended DOM and three unchanged frames after the first valid
committed frame. The selected element must be the actual input target even when
labels repeat. Tracing, injected CSS and screenshot-drain controls were disabled.

| Catalyst 500 nodes / 2,000 edges | Baseline median / p95 | Candidate median / p95 | Median / p95 change |
| -------------------------------- | --------------------: | ---------------------: | ------------------: |
| Cold browser context             |    352.20 / 370.00 ms |     274.40 / 301.00 ms |     -22.1% / -18.6% |
| Warm browser context             |    366.85 / 382.80 ms |     276.35 / 286.90 ms |     -24.7% / -25.1% |

At n=20 nearest-rank p95 is the nineteenth ordered observation, not the maximum.
Every value is retained in `final09-selection-summary.json`. Observed maxima
were cold 384.5 → 317.4 ms; warm 386.0 → 302.4 ms. These samples do not estimate population tail latency or establish an SLO.

First intended DOM medians remained 35.7–36.1 ms after capture, React render
medians 29.5–30.1 ms, and integrated selection graph/topology conversions zero.
The inspector retained exactly 34,601 text characters throughout. Maximum frame
read cost was 2.2 ms baseline and 1.6 ms candidate. The gain did not remove
inspector evidence or accelerate parsing. The historical 260.9 → 367.9 ms result
used other revisions and five samples; it is not this comparison’s baseline.

## Diagnosis and product change

Native Chromium traces located the previously unattributed late task in
`LayerTreeHost::WaitForCommitCompletion`, waiting for raster work from the
preceding map frame. The interaction prelude includes the keyboard highlight
jump and pointer/focus events before the captured click. In a representative baseline trace, two expensive
frame-17 raster tasks ran at input +24.2 ms for 205.9 ms and input +230.8 ms for
101.2 ms. First selection DOM state arrived at +38.3 ms; these tasks were already
processing the preceding frame. This does not assign all of that frame's work
to a single earlier event. The later main-thread compositor task waited
234.8 ms. JavaScript profiles alone classified much of this interval as native
program time. Selection's subsequent raster tiles took approximately 1–2 ms.

The product change adds `will-change: transform` to the existing SVG map content
group. It lets Chromium retain and schedule the transformed content separately
without changing graph rows, rendered hit targets, opacity, markers, evidence
or export content. In the corresponding diagnostic experiment, the two large
raster tasks overlapped (+20.0 ms / 210.4 ms and +21.1 ms / 111.2 ms), and the
compositor wait fell to approximately 140 ms. Their CPU durations did not fall;
the observed benefit concerns raster/compositor scheduling and synchronization.
This trace supports the intervention on the measured Chromium implementation,
not a universal claim about other browsers' layer allocation.

A same-source CSS intervention preceded the earlier integrated candidate run: 20 samples per
cache state changed warm median/p95 from 367.7/384.7 ms to 281.8/301.6 ms. The
later reversed candidate/baseline order reproduced the gain, reducing the risk
that simple run order explains it. Paint containment, primitive opacity and
invisible-hit-stroke experiments failed to remove the wait and were discarded.
No such styles were added to the product.

A separately labelled screenshot-drain control, performed before input capture,
reduced representative selection observations to 110.3 ms cold and 115.4 ms warm
and removed the expensive preceding-frame raster tail. This establishes the
importance of prior-action scheduling. It is an experimental intervention,
not the final metric or product improvement. Animation-frame DOM/geometry
stability is not an independent compositor-presentation timestamp; the final
comparison deliberately preserves the original interaction sequence.

## Renewed complete acceptance matrix

Both runs passed **14/14 cases and 140/140 measured samples**, using five
repetitions per cache state. Baseline ran before candidate; its provisional
investigation budgets were generated before the candidate matrix. Coverage:
all four captured scenarios (ACI, NXOS, Catalyst→ACI, Meraki→NXOS), each controlled
100-node/400-edge and 500-node/2,000-edge workload, and the two Cisco 100/400
partial-handoff variants. Every workload fingerprint and evidence count matched.

The dense table shows baseline → candidate medians in milliseconds. Complete
median/p95/min/max distributions for all 28 workload/cache groups and every
operation remain in `final09-comparison.summary.json`; its generated readable
comparison is `final09-comparison.md`. At n=5, p95 is the maximum.

| 500 nodes / 2,000 edges |  Mount usable | Card selection |        Filter | PNG generation |
| ----------------------- | ------------: | -------------: | ------------: | -------------: |
| aci / cold              | 322.2 → 335.1 |    73.2 → 71.9 |   80.5 → 78.6 |  537.2 → 574.9 |
| aci / warm              | 315.2 → 328.4 |    72.7 → 72.3 |   76.6 → 81.3 |  557.5 → 570.6 |
| nxos / cold             | 313.9 → 312.3 |    67.0 → 68.3 |   75.5 → 68.7 |  519.9 → 531.2 |
| nxos / warm             | 312.7 → 339.2 |    67.4 → 68.2 |   79.8 → 75.2 |  538.5 → 548.9 |
| catalyst-aci / cold     | 395.7 → 399.4 |  367.3 → 299.0 | 199.5 → 219.8 |  355.2 → 350.6 |
| catalyst-aci / warm     | 398.2 → 396.8 |  368.1 → 268.8 | 199.9 → 218.1 |  358.6 → 366.4 |
| meraki-nxos / cold      | 371.4 → 392.8 |  368.1 → 384.8 | 202.4 → 232.6 |  355.9 → 373.2 |
| meraki-nxos / warm      | 390.3 → 405.7 |  367.2 → 399.5 | 203.2 → 229.9 |  344.5 → 354.6 |

The targeted Catalyst benefit is evaluated alongside all slower observations;
this is not a general speedup claim. The following dense median changes are
retained explicitly (other distributions remain in the summary):

- meraki-nxos card selection: cold 368.1 → 384.8 ms (+4.5%); warm 367.2 → 399.5 ms (+8.8%).
- meraki-nxos filtering: cold 202.4 → 232.6 ms (+14.9%); warm 203.2 → 229.9 ms (+13.1%).
- catalyst-aci filtering: cold 199.5 → 219.8 ms (+10.2%); warm 199.9 → 218.1 ms (+9.1%).

Five observations do not distinguish CSS effects, other integrated differences,
run order or workstation variation. The provisional investigation budget is
baseline p95 × 1.25 + 10 ms (+2 ms for isolated operations). These are local
engineering prompts, not CI gates, service objectives or permission to relax
correctness. Candidate median exceedances: 0.

Individual/p95 exceedances (n=5 p95 is maximum):

- catalyst-aci/captured/warm `mountLongTaskMs`: median 0.0, p95 52.0 ms versus budget 10.0 ms.
- meraki-nxos/near-limit/cold `filterMs`: median 232.6, p95 272.1 ms versus budget 267.1 ms.
- meraki-nxos/near-limit/cold `filter.eventToTriggerObservedMs`: median 165.5, p95 202.0 ms versus budget 186.8 ms.

Trigger-observed upper bounds, React, browser layout/script, long tasks and
raster observations overlap and must not be summed. The summary preserves all
phase and isolated transform/index/layout/path/device-summary distributions.

All samples retained exact counts, finite layout/edge geometry, full normalized
JSON equality, PNG signature/allocation and required-flow CSV. Every original
attachment/traffic CSV record was counted and parsed. Qualified client identity,
ambiguous/mismatched authority rejection, partial/unresolved warnings and the
Devices reference-cap disclosure remained asserted. Dense Catalyst evidence
retained 412 clients, 2,853 attachment records, 4,278 unique traffic records and
317 handoff records; Meraki retained 417 / 2,870 / 4,304 / 313. Partial variants
preserved their original records and declined unsupported backend assignment.
No page errors were recorded. No assertion or action/readiness timeout changed.

Final-source ordinary browser correctness is independently supported by CI
job `117782073158`, run `39163678286`, bound to `6ebbf0d`: **94 passed (2.2m)**.
The retained `dist/final-qualification/ci-6ebbf0d-browser.log` and adjacent
`ci-6ebbf0d-browser-binding.json` bind the exact source and log checksum. CI is
correctness evidence, not a same-hardware performance comparison. Deployment-client
race unit/installed qualification is coordinated separately. Earlier nine
readiness passes remain retained; no new readiness run is claimed.

## Earlier native diagnostics supporting unchanged CSS

No new final-source trace was run. The following matched diagnostics belong to
the earlier frozen candidate with primary tree `d89f2c0d45a1fc9816a182e3a6e1417c8c13bb82d10843b2e05c4767cb0d523c`.
They support attribution for unchanged CSS; they are not final-package traces.

Separate broad-category native traces used three measured repetitions per cache
state on each frozen build: **6/6** samples each, plus one discarded warmup trace.
These timings include tracing overhead and are excluded from the untraced
20/cache and full-matrix distributions. `qualified-native-summary.json` binds
each measured trace to its capture marker, DOM commit, raster tasks and wait.
The earlier baseline compositor waits ranged from 227.6 to 256.4 ms; candidate
waits ranged from 125.2 to 180.0 ms. Readiness frame reads remained at most
approximately 2 ms, too small to explain the native wait difference.

In that first cold baseline trace, preceding-frame raster tasks ran at
input +19.6 ms for 211.1 ms and +231.5 ms for 103.5 ms; first intended DOM was
+40.2 ms and the compositor wait was 227.6 ms. Candidate tasks overlapped at
+8.6 ms / 219.6 ms and +9.8 ms / 115.9 ms, first intended DOM was +40.5 ms,
and the wait was 125.2 ms. The raster CPU work persisted; its overlap changed.
Both were source frame 16, with distinct layer IDs. This repeats the earlier
same-source diagnostic using the same harness and earlier integrated candidate.

## Environment, exclusions and package binding

Apple M3 Pro, 12 logical CPUs, 18 GiB; Darwin 27.0.0 arm64; Node v26.10.0,
Playwright 1.64.0, Chromium 156.0.8078.4. Headless production React profiling
build, 1440×1000/DPR1, UTC/en-US/light; no CPU/network throttling. Cold means a
fresh browser context. Warm uses one discarded full-sequence warmup and shared
context with fresh pages. Browser process, server and OS caches remain warm.
The coordinator paused sustained competing local builds/browser/tests; light
remote RPC and file/SSH work continued. A worker reported 19 Python pure tests
(0.048 seconds) plus Ruff before the pause reached them, during the candidate
full matrix. Exact command start/end and Ruff duration were not supplied. These
files are outside measured inputs, so source guards remain valid; brief CPU
overlap remains a timing limitation. No samples were excluded or edited, and
untraced observations cannot attribute any individual outlier to this overlap.
`final09-concurrency-note.json` retains the report. Desktop/thermal/GPU activity is not independently
controlled, and unrelated OTel containers remain untouched.

The standalone benchmark uses real map/parser/layout/inspector/export code with
a production profiling bundle. It excludes Splunk dispatch, server execution,
result download and artifact filesystem reads from browser interaction timing.
Module/download startup is separate from mount. Stable animation-frame DOM and
geometry checks are not an independent compositor-presentation timestamp.
These synthetic graph-contract workloads do not establish production capacity,
20,000-row topology performance, alternate-browser behavior, long-running GPU
memory or production SLOs.

Earlier incomplete runs remain unchanged: `baseline-selection-10.json` retained
13 samples before its whole-case timeout; `final-candidate-matrix.json` retained
13/14 cases and 138/140 samples before timeout, while imported pipeline JSON
changed. The static production preview had no HMR, but source provenance was
still invalid. These and earlier experimental CSS/screenshot-drain runs remain
excluded from final distributions. Full CSV parsing still checks every record
inside one assertion, avoiding reporter-step overhead outside browser timing;
Node wall-stage telemetry remains separate. Earlier raw/index snapshots survive.

Final package09 is `dist/final-qualification/packages/candidate-09.tar.gz`, SHA-256
`024d11c83ae9cb21a19259b57038d0e4a68414d1b2d3dde82cad527d789a0097`.
The coordinator’s `dist/final-qualification/candidate-09-package.json` binds
source `6ebbf0d` and every packaged file. Packaged `atlas.js` changed for the
stale-read repair; no package07/08/09 JavaScript equality is claimed. The actual
standalone MapPage profiling assets from final09 happen to be byte-identical to
the prior candidate’s assets, although the primary source hash changed. Thus
renewed measurements qualify the unchanged imported map path; they do not
exercise or validate the asynchronous deployment-client race. Packaged bundle
and standalone profiling bundle hashes are separate evidence.

The [evidence index](atlas-final-browser-evidence-index.json) binds actual source,
imports, served assets, package09 and all retained checksums. New authoritative
reports are `final09-{baseline,candidate}-selection-20.json` and
`final09-{baseline,candidate}-matrix.json`, with summaries, logs, exact commands
and served-asset snapshots under ignored `dist/final-qualification/performance/`.
Preserve that directory when archiving this worktree. Historical native traces,
failed attempts and all previous qualification reports remain unchanged.

See [measurement methodology](../BROWSER_PERFORMANCE.md).
