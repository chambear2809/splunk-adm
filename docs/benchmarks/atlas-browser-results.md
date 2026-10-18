# Retained browser performance results

Historical comparison: its schema 1 interaction intervals include automation
completion. A [corrected readiness protocol](atlas-browser-readiness-correction.md)
has passed bounded correctness smoke; a new controlled comparison remains
pending. Original observations below are preserved.

Accepted baseline `510754c17391e548309dd68ddac3f8b99e0b75c6` versus candidate `7999d3a8b27ee3c786f5bb43345b06273966a675`. Both runs passed 14/14 cases and retained 140 measured samples each, with no correctness failures. Source and harness hashes stayed unchanged. The comparison script verified identical runtime/hardware, harness, workload fingerprints/counts and repetition matrices. Baseline took 15.4 minutes; candidate took 12.9 minutes including assertions, warmups and artifact validation. Wall time is not a browser latency metric.

## Measured outcome

Cells are median / nearest-rank p95 in milliseconds, five samples per cache state. With five samples p95 is the maximum. “Cold” means a fresh browser context; the browser process and OS cache are reused. These workstation observations do not establish population tail latency or an approved service objective.

| Near-limit workload/cache (500 nodes/2000 edges) |  Baseline mount | Candidate mount | Median change | Baseline filter | Candidate filter |
| ------------------------------------------------ | --------------: | --------------: | ------------: | --------------: | ---------------: |
| aci/near-limit/cold                              |   376.6 / 388.0 |   334.4 / 349.1 |        -11.2% |   104.1 / 116.9 |      73.5 / 84.5 |
| aci/near-limit/warm                              |   378.3 / 393.6 |   331.5 / 339.8 |        -12.4% |   111.0 / 118.9 |      77.3 / 96.7 |
| nxos/near-limit/cold                             |   375.2 / 384.1 |   325.8 / 352.6 |        -13.2% |   107.9 / 115.7 |      88.2 / 90.0 |
| nxos/near-limit/warm                             |   390.7 / 398.3 |   313.3 / 320.2 |        -19.8% |   110.6 / 117.2 |      86.8 / 88.3 |
| catalyst-aci/near-limit/cold                     | 1182.3 / 1212.4 |   397.7 / 430.5 |        -66.4% |   541.5 / 542.7 |    189.7 / 202.8 |
| catalyst-aci/near-limit/warm                     | 1184.1 / 1224.3 |   402.1 / 412.9 |        -66.0% |   538.9 / 562.4 |    201.2 / 202.8 |
| meraki-nxos/near-limit/cold                      | 1213.5 / 1223.9 |   411.9 / 423.5 |        -66.1% |   556.3 / 562.1 |    204.7 / 211.4 |
| meraki-nxos/near-limit/warm                      | 1192.6 / 1218.9 |   401.9 / 404.5 |        -66.3% |   546.8 / 563.5 |    193.6 / 206.8 |

Evidence-heavy Cisco near-limit mount medians fell about 66%; at 100 nodes/400 edges, normal and partial handoff variants fell about 49–53% across cache states. Captured workload mount medians changed between −6.7% and +7.4%, around a 110–128 ms baseline range; these small cases are sensitive to the three-frame settling floor.

Integrated graph-transform call counts during mount fell from 16 to 1 in every workload/cache group. For Cisco near-limit cold mounts, graph-transform time changed from 851.7 to 65.0 ms (Catalyst) and 876.1 to 66.8 ms (Meraki). Isolated parsing did not improve: its cold medians changed from 50.2 to 52.0 ms and 50.8 to 52.9 ms respectively. The observed gain is consistent with avoiding repeated integrated work; it does not show that parsing itself became faster.

| Cisco near-limit cold metric      | Catalyst baseline | Catalyst candidate | Meraki baseline | Meraki candidate |
| --------------------------------- | ----------------: | -----------------: | --------------: | ---------------: |
| React render                      |     916.0 / 934.2 |      300.3 / 312.7 |   941.4 / 951.1 |    306.3 / 311.5 |
| Browser script                    |   1093.1 / 1121.9 |      320.6 / 330.5 | 1129.3 / 1132.3 |    329.0 / 332.9 |
| Browser layout                    |       33.1 / 33.6 |        30.3 / 31.7 |     33.6 / 34.5 |      31.2 / 32.3 |
| Mount long-task duration          |   1130.0 / 1159.0 |      341.0 / 353.0 | 1167.0 / 1172.0 |    350.0 / 356.0 |
| Partial/unresolved edge selection |     231.7 / 232.8 |        81.8 / 82.6 |   232.2 / 232.8 |      82.2 / 82.7 |
| Highlighted card selection        |     293.2 / 293.5 |      383.4 / 384.8 |   308.2 / 390.3 |    383.0 / 400.4 |
| Devices render                    |     466.6 / 482.3 |      198.9 / 199.8 |   466.0 / 482.5 |    198.7 / 200.3 |
| Flows CSV generation              |         4.0 / 4.1 |          4.1 / 4.2 |       3.9 / 4.2 |        4.0 / 4.3 |
| Context CSV generation            |       31.5 / 34.4 |        32.7 / 33.7 |     32.6 / 38.9 |      32.5 / 38.0 |
| JSON generation                   |       34.5 / 36.3 |        33.3 / 36.9 |     26.1 / 31.6 |      23.3 / 29.3 |
| PNG generation                    |     511.7 / 518.3 |      360.5 / 365.0 |   515.5 / 572.5 |    368.1 / 379.0 |

## Regression retained for investigation

Highlighted-card selection on evidence-heavy near-limit Cisco maps became slower. Catalyst cold median rose 293.2 → 383.4 ms (+30.8%), with p95 293.5 → 384.8 ms; warm rose 292.2 → 368.2 ms (+26.0%). Meraki cold rose 308.2 → 383.0 ms (+24.3%); warm rose 292.9 → 367.8 ms (+25.6%). This action clicks the first highlighted `checkout` map card and waits for stable map/details rendering. It is separate from table conversation selection, which improved. The run does not identify the cause.

Catalyst cold card selection is the only candidate median that exceeds the provisional baseline-p95 investigation budget: 383.4 ms versus 376.9 ms (293.5 × 1.25 + 10). The budget was derived after measuring the baseline and is not an enforced SLO or permission to weaken evidence/correctness. Other smaller changes and full min/median/p95/max distributions remain in the JSON summary.

## Non-comparative selection diagnostic

A bounded follow-up used an instrumented copy under ignored `dist/performance`,
one Catalyst near-limit case per source with one cold and one warm measured
sample plus a discarded warmup. Full correctness assertions passed. The local
Splunk verification was active, so these timings are diagnostic observations,
not replacement comparative evidence. Original harness and retained raw bytes
remain unchanged; the evidence index records copy/trace artifact checksums.

The retained protocol captures the click timestamp, awaits Playwright's click
completion, then invokes the browser readiness loop. The copied instrumentation
separates those boundaries:

| Source/cache   | Click capture → trigger returned | Trigger returned → settling invoked | Settling → end | React render |
| -------------- | -------------------------------: | ----------------------------------: | -------------: | -----------: |
| Baseline cold  |                         274.9 ms |                              0.9 ms |        46.2 ms |     192.5 ms |
| Baseline warm  |                         339.9 ms |                              1.1 ms |        50.6 ms |     190.9 ms |
| Candidate cold |                         325.7 ms |                              0.6 ms |        52.1 ms |      33.8 ms |
| Candidate warm |                         326.7 ms |                              1.8 ms |        55.0 ms |      31.2 ms |

All four traces clicked and selected the same `checkout-api` Kubernetes Service
card, with matching final root transform, viewport, bounds and 2,364 hit targets.
Every sampled settling frame was valid; the signature remained unchanged after
its initial sample. The candidate residual occurs before the settling loop,
not in a longer three-frame settling sequence. No readiness frames were sampled
before Playwright returned, so this does **not** prove when visual readiness
first occurred or that the residual is entirely automation overhead. The
retained action metric includes automation completion and cannot alone establish
a regression in user-visible responsiveness. The measured regression remains
reported; its product/browser/protocol cause is unresolved.

## Evidence and limitations

- [Full comparison tables](atlas-browser-comparison.md) and [machine-readable distributions](atlas-browser-comparison.summary.json) cover all 28 workload/cache groups and every measured operation.
- [Evidence index](atlas-browser-evidence-index.json) records local raw JSON/log locations and SHA-256 checksums; full raws remain under ignored `dist/performance` and must be archived separately when preserving this checkout. Obsolete exploratory/interrupted generic workloads are excluded.
- [Environment](atlas-browser-environment.md) records the idle local lab and paused local checks; OS/desktop activity and unrelated OTel containers remain uncontrolled. Production React profiling, headless Chromium and automation add overhead.
- [Imported-source manifest](atlas-browser-imported-source-manifest.json) binds configuration/research dependencies outside the primary source-tree hash to each commit.
- Synthetic additions preserve captured graph rows and scale authority-qualified client identities, independent attachments/traffic observations, authority ambiguity, complete/partial/unresolved handoffs and topology associations. They are deterministic graph-contract browser workloads, not collected TA events or deployment-capacity measurements.
- The largest Cisco cases contain 412/417 clients, 2,853/2,870 attachment records and 4,278/4,304 unique traffic records. Topology reaches 1,337/1,349 rows; the separate 20,000-row topology limit was not capacity-tested. Existing graph limits and complete evidence checks were retained.
- Search dispatch, Splunk server execution, polling/result download and artifact filesystem reads are excluded. Mount transforms/render/script/layout overlap and must not be added together.

See [methodology and reproduction commands](../BROWSER_PERFORMANCE.md).
