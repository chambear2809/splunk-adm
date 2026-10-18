# Final qualification: browser selection investigation

The accepted baseline is `64473e54d1fca4311ac592bc34c4a96a022efd48`.
The integrated measured candidate has primary browser-input tree SHA-256
`d89f2c0d45a1fc9816a182e3a6e1417c8c13bb82d10843b2e05c4767cb0d523c`;
the harness SHA-256 is
`75a82d0198e5214c4b48fa37988f3c38f823e68f38175e923ee48b217ab612a7`.
These effective-byte hashes bind the measurements made before the integration
commit. The evidence index records these inputs; the coordinator’s release
manifest separately binds the final package and revision.
Raw reports additionally bind imported configuration/research JSON and every
production served asset before/after each run; all freeze checks must pass.

## Matched selection distributions

The final supplemental investigation used 20 repetitions per cache state,
running the candidate first and accepted baseline second. Both completed
40/40 samples with identical instrumentation, workloads and runtime, and
unchanged source/harness hashes. Neither tracing, experimental CSS nor the
compositor-drain control was enabled. The retained capture-started protocol and
all selection preconditions, full graph counts, finite geometry and intended
DOM/stable-frame assertions remained enabled. The selected element must be the
actual input target, including when labels are duplicated.

| Catalyst 500 nodes / 2,000 edges | Baseline median / p95 | Candidate median / p95 | Median / p95 change |
| -------------------------------- | --------------------: | ---------------------: | ------------------: |
| Cold browser context             |      367.6 / 384.8 ms |       275.0 / 301.0 ms |     −25.2% / −21.8% |
| Warm browser context             |      367.9 / 384.7 ms |       285.1 / 300.1 ms |     −22.5% / −22.0% |

At n=20, nearest-rank p95 is the nineteenth ordered observation, rather than
the maximum. This remains a workstation sample, not a population tail estimate
or an approved production SLO. The historical 260.9 → 367.9 ms observation used
different revisions and five samples; it is not substituted for this current
accepted-baseline comparison.

All observations remain retained, including a 416.6 ms baseline warm outlier.
Observed maxima were 385.0 → 301.1 ms cold and 416.6 → 300.6 ms warm. Neither
the median nor p95 describes every sample, and isolated outliers do not have
individual trace attribution in these untraced runs.

First intended DOM state remained approximately 36–38 ms after input capture,
and React render medians remained approximately 31 ms. Neither build performed
an integrated graph/topology transformation during selection. The inspector
retained exactly 34,601 text characters in every selection sample. Maximum
individual readiness-frame read cost was 1.8 ms for baseline and 2.0 ms for
candidate. The improvement therefore does not represent faster parsing or
removed inspector evidence.

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

A same-source CSS intervention preceded the final candidate run: 20 samples per
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

## Complete acceptance matrix

Both final complete runs passed **14/14 cases and 140/140 measured samples**,
using five repetitions per cache state. The accepted baseline ran before the
candidate. All four captured scenarios, each 100/400 and 500/2,000 controlled
workload, and both Cisco 100/400 partial-handoff variants were included. Every
workload fingerprint and evidence count matched across builds. Source, harness,
imported JSON and all built served bytes were unchanged before/after each run;
each role’s fingerprints also matched its final 20/cache and native runs.
The baseline’s provisional budgets were generated before the candidate matrix.

The dense cases below show baseline → candidate medians in milliseconds.
Complete distributions for all 28 workload/cache groups are retained in
`qualified-comparison.summary.json`, with the generated readable comparison in
`qualified-comparison.md`. At n=5, nearest-rank p95 is the maximum.

| 500 nodes / 2,000 edges |  Mount usable | Card selection |        Filter | PNG generation |
| ----------------------- | ------------: | -------------: | ------------: | -------------: |
| aci / cold              | 323.9 → 331.9 |    72.6 → 71.3 |   76.4 → 82.0 |  554.8 → 580.6 |
| aci / warm              | 325.6 → 338.0 |    72.4 → 71.9 |   76.2 → 75.7 |  564.5 → 572.0 |
| nxos / cold             | 324.9 → 326.3 |    67.3 → 69.4 |   75.9 → 72.8 |  550.4 → 534.0 |
| nxos / warm             | 326.6 → 331.2 |    67.0 → 68.3 |   82.8 → 71.8 |  542.7 → 553.0 |
| catalyst-aci / cold     | 409.1 → 398.1 |  367.7 → 283.2 | 202.8 → 216.2 |  357.9 → 359.4 |
| catalyst-aci / warm     | 395.4 → 397.0 |  367.9 → 299.9 | 200.1 → 220.8 |  354.6 → 362.1 |
| meraki-nxos / cold      | 391.7 → 402.2 |  367.7 → 384.4 | 204.3 → 231.5 |  379.8 → 359.2 |
| meraki-nxos / warm      | 388.4 → 406.5 |  368.3 → 384.7 | 201.8 → 228.3 |  362.7 → 364.2 |

The targeted Catalyst benefit reproduced in the complete workflow. This is not
a general speedup claim: dense Meraki card selection increased from 367.7 to
384.4 ms cold and 368.3 to 384.7 ms warm (approximately 4.5%). Dense Meraki
filtering increased from 204.3 to 231.5 ms cold and 201.8 to 228.3 ms warm
(approximately 13%); dense Catalyst warm filtering increased from 200.1 to
220.8 ms (10.3%). These changes are retained without attributing them uniquely
to CSS, other integrated candidate changes or workstation variation. Five
observations do not distinguish those causes. The isolated synthetic workloads
do not establish performance for the separate 20,000-row topology ceiling.

No candidate **median** exceeded the provisional baseline-p95 × 1.25 + 10 ms
investigation budgets (+2 ms for isolated operations). Individual observations
and therefore five-sample p95 did exceed them: ACI 100/400 warm card selection
111.4 ms versus 87.3 ms; ACI 500/2,000 warm Devices rendering 366.2 ms versus
323.6 ms; and one Meraki captured cold mount long task of 52 ms versus the
10 ms budget derived from a baseline without a long task. The separate Devices
event-to-trigger-observed upper bound was 343.9 ms versus 304.4 ms; it overlaps
the rendering interval and is not an additional browser phase. These are local
investigation observations, not CI gates or production SLO violations.

Dense candidate mount React render medians ranged from 168.3 to 299.5 ms and
browser layout medians from 29.7 to 44.0 ms; these overlap mount and cannot be
summed. Dense candidate mount long-task medians were one task (166–175 ms) for
ACI/NXOS and two tasks (280–294 ms total) for Cisco workloads. Integrated row
conversion remained one call per mount. The summary retains all script, layout,
long-task and isolated transform/index/layout/path/device-summary values.

All samples retained exact counts, finite layout/edge geometry, full normalized
JSON equality, PNG signature/allocation, required-flow CSV, and every original
attachment/traffic CSV record. Qualified client identity, ambiguous/mismatched
authority rejection, partial/unresolved warnings and the Devices reference-cap
disclosure remained asserted. Catalyst dense evidence retained 412 clients,
2,853 attachment records, 4,278 unique traffic records and 317 handoff records;
Meraki retained 417 / 2,870 / 4,304 / 313 respectively. The partial variants
retained their original records and declined unsupported backend assignment.

The final ordinary browser regression suite also passed **94/94** tests, including
keyboard/focus, map lifecycle, warnings, evidence/export and settings coverage.
Its log is `qualified-browser.log`. The narrow readiness suite passed **9/9**
(`provenance-readiness.log`). No product changes followed these measurements.

## Final matched native diagnostics

Separate broad-category native traces used three measured repetitions per cache
state on each frozen build: **6/6** samples each, plus one discarded warmup trace.
These timings include tracing overhead and are excluded from the untraced
20/cache and full-matrix distributions. `qualified-native-summary.json` binds
each measured trace to its capture marker, DOM commit, raster tasks and wait.
The final baseline compositor waits ranged from 227.6 to 256.4 ms; candidate
waits ranged from 125.2 to 180.0 ms. Readiness frame reads remained at most
approximately 2 ms, too small to explain the native wait difference.

In the final first cold baseline trace, preceding-frame raster tasks ran at
input +19.6 ms for 211.1 ms and +231.5 ms for 103.5 ms; first intended DOM was
+40.2 ms and the compositor wait was 227.6 ms. Candidate tasks overlapped at
+8.6 ms / 219.6 ms and +9.8 ms / 115.9 ms, first intended DOM was +40.5 ms,
and the wait was 125.2 ms. The raster CPU work persisted; its overlap changed.
Both were source frame 16, with distinct layer IDs. This repeats the earlier
same-source diagnostic using the final harness and integrated candidate.

## Environment and retained evidence

Apple M3 Pro, 12 logical CPUs, 18 GiB RAM; macOS kernel 27.0.0 arm64; Node
v26.10.0, Playwright 1.64.0, Chromium 156.0.8078.4. Production React profiling
build, headless, 1440×1000/DPR1, UTC/en-US/light. Cold uses a fresh context; warm
uses one discarded full-sequence warmup and a shared context with fresh pages.
Browser process, server and OS caches remain warm. Other heavy local builds and
browser tests were paused, and no owned local Splunk/Docker lab was running.
Remote qualification continued through light local RPC/log commands; its Splunk
and AppInspect preparation ran remotely. Unrelated OTel containers remained untouched.
Desktop, thermal activity and GPU residency were not independently controlled
or capacity-qualified.

Raw evidence remains under ignored `dist/final-qualification/performance/`:
`qualified-baseline-selection-20.json`, `qualified-candidate-selection-20.json`, their
command logs, and `qualified-selection-summary.json` retain every matched value.
`selection-intervention-summary.json` binds the earlier same-source intervention.
Separate diagnostic directories retain native traces and rejected experiments.
The earlier 10-repetition full-validation attempt hit its 300-second case timeout;
its 13 samples and `complete:false` report/log remain retained and excluded from
accepted distributions. The supplemental mode avoids repeating unrelated CSV
validation; the complete matrix remains the export/evidence acceptance check.

See [measurement methodology](../BROWSER_PERFORMANCE.md). No Splunk search
dispatch, server execution, result download or artifact filesystem reads are
part of browser interaction latency. Main-thread, React, layout, raster and
long-task observations overlap and must not be summed.

## Excluded runs, provenance repair and package binding

An earlier candidate complete-matrix attempt finished 13/14 cases and 138/140
samples before its whole-case timeout. It remains `complete:false` in
`final-candidate-matrix.json`, with failure logs and copied error artifacts.
During that attempt, the imported pipeline-interface JSON changed. The server
was a prebuilt production preview without HMR, so this did not hot-reload the
running application; nevertheless its complete source provenance was invalid.
A post-run served-asset snapshot is retained as an audit, not a retroactive
before/after freeze proof. Neither that run nor its earlier target distributions
are used for the final qualified comparison.

The revised harness fingerprints imported JSON and actual served assets before
and after every run. It also removed reporter overhead outside browser timing:
one assertion now wraps a loop parsing **every** CSV evidence record, preserving
the same row-count and parse-failure semantics without tens of thousands of
retained assertion steps. Node wall-stage telemetry separates this validation
from browser phases. Only the whole-case budget increased; the action and
readiness deadlines and all DOM/geometry/evidence gates stayed unchanged. The
fresh qualified baseline and candidate matrices both completed with this exact
same harness. Earlier raw files, failures and the pre-change harness snapshot
remain retained; no recorded metric was edited or discarded.

The browser measurements use a dedicated production React profiling bundle;
its served-asset hashes do not claim byte equality with the packaged Splunk
bundle. The measured candidate’s primary/imported inputs are bound in the raw
reports. The coordinator separately retained package 07 at
`dist/final-qualification/packages/candidate-07.tar.gz`, SHA-256
`cb37e69e0eb6670a85d11f176346aac750b08e937acbdcc7855306817ffb3005`.
The archived `dist/final-qualification/candidate-05-to-07-archive-comparison.json`
proves all packaged static assets, including demo assets, were byte-identical
between packages 05 and 07; later runtime/build/documentation changes therefore
do not alter the frontend bytes associated with this qualification. Backend,
installed-platform and deployment qualification are separate evidence.

The committed [evidence index](atlas-final-browser-evidence-index.json) records
raw paths, SHA-256 checksums, eligibility and source guards. Raw traces, served
asset snapshots, exact harness snapshots and command records remain in ignored
`dist/final-qualification/performance/`; preserve that directory when archiving
this worktree. The CSS hint can affect browser layer allocation and memory;
long-running GPU memory, alternate browsers, thermal variation and actual
compositor presentation latency were not independently qualified.
