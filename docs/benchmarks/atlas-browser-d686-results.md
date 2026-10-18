# Corrected accepted-main browser performance results

Accepted baseline `d6863dd326099acb892e1eebaa6c43d4f4410947` versus integrated candidate `8813eb534f907ac9c95d6673ed02fdbdf1008673`. Both passed **14/14 cases with 140 measured samples each**, all correctness assertions enabled. Source trees and harness stayed unchanged; both measured source trees were clean. The comparison verified identical runtime, harness, workload fingerprints/counts and repetition matrices. Baseline wall time was 13.9 minutes; candidate 11.2 minutes including warmups and correctness/artifact validation. Wall time is not browser latency.

This is the schema 2 capture-started browser readiness protocol. It requires the intended committed DOM state and stable frames independently of Playwright completion, with trigger completion recorded separately. Original `510754c`/`7999d3a` numbers remain [historical and superseded](atlas-browser-results.md); they are not mixed into this comparison.

## Browser results

Cells are median / nearest-rank p95 in milliseconds, five samples per cache state. At n=5 p95 is the maximum, not a population tail estimate. Cold means a fresh browser context; browser process/OS caches are reused.

| Near-limit workload/cache (500 nodes / 2000 edges) |  Baseline mount | Candidate mount | Median change | Baseline filter | Candidate filter |
| -------------------------------------------------- | --------------: | --------------: | ------------: | --------------: | ---------------: |
| aci/near-limit/cold                                |   377.4 / 386.1 |   310.6 / 324.1 |        -17.7% |   107.2 / 110.0 |      78.3 / 79.3 |
| aci/near-limit/warm                                |   381.2 / 398.0 |   314.5 / 316.6 |        -17.5% |   108.7 / 111.3 |      78.5 / 80.0 |
| nxos/near-limit/cold                               |   363.8 / 385.1 |   313.3 / 327.7 |        -13.9% |    92.2 / 103.4 |      72.7 / 81.7 |
| nxos/near-limit/warm                               |   364.7 / 365.9 |   316.2 / 331.3 |        -13.3% |    94.8 / 102.8 |      74.5 / 78.8 |
| catalyst-aci/near-limit/cold                       | 1159.2 / 1164.2 |   389.4 / 414.2 |        -66.4% |   520.5 / 530.7 |    197.4 / 201.2 |
| catalyst-aci/near-limit/warm                       | 1162.9 / 1185.0 |   394.5 / 411.5 |        -66.1% |   528.5 / 532.3 |    191.6 / 202.7 |
| meraki-nxos/near-limit/cold                        | 1159.9 / 1171.7 |   389.0 / 409.2 |        -66.5% |   530.7 / 542.4 |    201.9 / 204.6 |
| meraki-nxos/near-limit/warm                        | 1154.8 / 1160.0 |   389.2 / 414.6 |        -66.3% |   526.2 / 541.6 |    196.1 / 205.3 |

Cisco near-limit mount medians fell about 66%; 100-node/400-edge normal/partial handoff variants fell 47–51%. Captured mount medians changed between −12.7% and +8.1%; Catalyst captured cold increased 112.9 → 122.1 ms. Small cases are sensitive to the frame-settling floor. Integrated graph-transform calls during mount fell from 16 to 1 in every group. Cisco near-limit cold integrated graph-transform medians fell 838.2 → 63.0 ms and 843.0 → 63.8 ms, while isolated parsing slightly increased 48.6 → 50.9 ms and 48.8 → 51.5 ms. The gain is consistent with avoiding repeated integrated work; it does not show faster parsing.

| Cisco near-limit cold metric              | Catalyst baseline | Catalyst candidate | Meraki baseline | Meraki candidate |
| ----------------------------------------- | ----------------: | -----------------: | --------------: | ---------------: |
| Mount React render                        |     899.9 / 903.9 |      289.6 / 304.5 |   900.9 / 904.0 |    289.3 / 300.4 |
| Mount browser script                      |   1072.5 / 1077.3 |      308.2 / 322.4 | 1072.4 / 1082.3 |    308.3 / 320.8 |
| Mount browser layout                      |       32.7 / 32.9 |        30.0 / 30.2 |     32.1 / 32.7 |      28.8 / 32.3 |
| Mount overlapping long-task duration      |   1108.0 / 1113.0 |      279.0 / 342.0 | 1109.0 / 1118.0 |    278.0 / 343.0 |
| Partial/unresolved conversation selection |     197.2 / 199.0 |        65.7 / 66.1 |   198.9 / 200.5 |      65.6 / 65.8 |
| Devices rendering                         |     433.0 / 433.4 |      168.5 / 170.3 |   416.6 / 432.9 |    166.4 / 168.0 |
| Flows CSV generation                      |         3.9 / 4.1 |          4.1 / 4.8 |       3.7 / 3.8 |        3.8 / 4.0 |
| Context CSV generation                    |       30.2 / 30.4 |        31.5 / 32.4 |     31.1 / 32.4 |      31.4 / 32.9 |
| JSON generation                           |       33.5 / 34.4 |        32.3 / 37.4 |     21.2 / 23.1 |      22.3 / 25.4 |
| PNG generation                            |     497.5 / 520.4 |      357.3 / 371.7 |   503.2 / 523.7 |    352.2 / 362.0 |

## Unfavorable results and card-selection investigation

Highlighted-card selection is **not solved** by the methodology correction. The corrected event-to-committed/stable-ready observations are:

| Near-limit card selection    | Baseline median/p95 | Candidate median/p95 | Median change | p95 change | Provisional budget |
| ---------------------------- | ------------------: | -------------------: | ------------: | ---------: | -----------------: |
| catalyst-aci/near-limit/cold |       360.6 / 360.8 |        367.4 / 368.8 |          1.9% |       2.2% |           461.0 ms |
| catalyst-aci/near-limit/warm |       260.9 / 359.3 |        367.9 / 368.7 |         41.0% |       2.6% |           459.1 ms |
| meraki-nxos/near-limit/cold  |       358.7 / 377.0 |        383.4 / 385.4 |          6.9% |       2.2% |           481.3 ms |
| meraki-nxos/near-limit/warm  |       360.3 / 376.0 |        368.2 / 370.0 |          2.2% |      -1.6% |           480.0 ms |

Catalyst warm baseline samples were **359.3, 358.8, 251.0, 260.9, 260.4 ms**; candidate samples were **366.7, 351.8, 368.7, 368.5, 367.9 ms**. The +41.0% median increase is larger than the +2.6% observed p95 increase because three baseline samples were in the lower range. This does not establish a population tail result or explain the cause. Both median and p95 remain below their provisional investigation budget; that does not negate the observed regression.

The [retained selection telemetry](atlas-browser-d686-selection-telemetry.json) shows lower aggregate React render work (~177–185 → 30–33 ms for Catalyst warm), alongside an additional candidate long task lasting 262–286 ms starting about 57–60 ms after click. Baseline had a second 116–117 ms task in two warm samples; three lower-latency samples lacked that separate later task. Some baseline overlapping tasks begin hundreds of milliseconds before the click; their full durations cannot be treated as action-only CPU time. Longtask entries have no stacks/attribution. Per-action CDP layout/script time, individual React commits, first-postcondition time and per-frame snapshots were not retained. Mount layout metrics cannot explain a selection action. The evidence supports an observed change and different task timing, **not a proven React/layout/browser/protocol cause**. No new diagnostic run or product fix was performed.

Other unfavorable observations include NXOS near-limit warm Devices median 250.5 → 282.9 ms (+12.9%), while p95 improved 316.4 → 313.6 ms; ACI realistic cold card selection 61.1 → 76.8 ms (p95 61.7 → 77.8 ms); Cisco isolated collapsed-layout medians around 20 → 25 ms; and modest context-CSV/JSON increases (for example Meraki realistic cold context CSV 6.6 → 9.4 ms, near-limit warm JSON 20.8 → 24.8 ms). Complete distributions retain every group and metric, including smaller changes.

## Both median and p95 versus provisional budgets

Budgets were derived from the completed baseline before candidate completion: baseline p95 × 1.25 + 10 ms (isolated operations +2 ms). They are local investigation prompts, not approved SLOs or enforced gates. Both candidate median and p95 were checked across 1416 metric/group budgets. No event-to-ready, export, startup or isolated-operation median/p95 exceeded these budgets. The three exceedances concern separately recorded automation clocks:

| Workload / automation metric                            | Budget | Candidate median | Candidate p95 | Exceeds        |
| ------------------------------------------------------- | -----: | ---------------: | ------------: | -------------- |
| nxos/captured/warm / selection.playwrightTriggerMs      |   67.3 |             79.6 |          83.0 | median and p95 |
| nxos/captured/warm / selection.eventToTriggerObservedMs |   21.5 |             42.3 |          46.5 | median and p95 |
| nxos/captured/warm / devices.playwrightTriggerMs        |   52.9 |             38.8 |          57.0 | p95 only       |

These trigger clocks include automation actionability/completion; the browser observation also includes the following evaluation delay. They are not substituted for browser-ready duration. [Machine-readable budget observations](atlas-browser-d686-budget-observations.json) preserve the checks.

## Environment, scope and evidence

- Apple M3 Pro, 12 logical CPUs, 18 GiB RAM; macOS kernel 27.0.0 arm64; Node v26.10.0, Playwright 1.64.0, Chromium 156.0.8078.4. Production React profiling build, headless, 1440×1000/DPR1, UTC/en-US/light.
- Baseline command-log creation → raw report completion: `2026-10-18T07:01:49.613Z` → `2026-10-18T07:15:41.324Z`; candidate: `2026-10-18T07:16:36.178Z` → `2026-10-18T07:27:47.817Z`. These bound full runs, not individual browser phases.
- Coordinator-owned Splunk lab was stopped under its exclusive lock and other local checks paused throughout the sequential runs. Unrelated OTel containers remained untouched. OS/desktop/thermal activity was uncontrolled; this is a workstation, not a dedicated benchmark host. [Environment and source hashes](atlas-browser-d686-environment.json).
- [Full comparison](atlas-browser-d686-comparison.md), [all distributions](atlas-browser-d686-comparison.summary.json), and [evidence index](atlas-browser-evidence-index.json). Full raw JSON/logs remain locally under ignored `dist/performance`; preserve separately when archiving the checkout. Historical reports/index are also archived locally, not overwritten.
- [Supplemental imported-source manifest](atlas-browser-d686-imported-source-manifest.json) binds configuration/research bytes outside the primary tree hash to the two measured commits and verifies them again after both runs.
- All four captured scenarios, controlled 100/400 and 500/2000 graph sizes, and both realistic partial-handoff variants retain original evidence and graph limits. Largest Cisco cases contain 412/417 clients, 2,853/2,870 attachment records, 4,278/4,304 unique traffic records and 1,337/1,349 topology rows. The separate 20,000-row topology bound was not capacity-tested. Synthetic additions exercise browser graph contracts, not actual TA collection or deployment capacity.
- Splunk dispatch/server execution/result download and artifact filesystem reading are excluded. Profiling/automation add overhead; render/transform/script/layout overlap and must not be summed. These observations do not establish LCP/INP or an approved service objective.

[Methodology and reproduction commands](../BROWSER_PERFORMANCE.md).
