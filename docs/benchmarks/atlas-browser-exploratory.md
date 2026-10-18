# Atlas browser performance evidence

This is the exploratory run. It overlapped other focused checks, browser tests,
and local lab startup. Its 140 samples are retained for diagnostic context and
are excluded from the controlled baseline/candidate comparison.

The full raw and detailed summary are retained under ignored `dist/performance`;
`atlas-browser-evidence-index.json` records the raw location and checksum. This
earlier harness scaled generic traffic rather than Cisco evidence cardinality.

Baseline source: `510754c17391e548309dd68ddac3f8b99e0b75c6`; tree hash `10ac9dc39cec749ece12703d845d9872f0d6d3b28848a49f1ab480224954224e`.

Harness: `4a6a417354f0b43b66df3b062d24b63a287c88e46da96ac4b15b4a15d060fc7d`. Chromium 156.0.8078.4; Node v26.10.0; Apple M3 Pro, 12 logical CPUs, 18 GiB; darwin/arm64.

140 baseline samples; 5 repetitions per workload/cache state. One discarded warmup per warm context. Production ReactDOM profiling build; 1440×1000, DPR 1, headless, UTC. Browser process and OS cache are reused; “cold” means a fresh browser context. Concurrent local activity was not controlled.

Each cell below is median / p95 in milliseconds. With five samples, nearest-rank p95 is the maximum; these values do not estimate population tail latency. Mount usability includes fonts and three stable animation frames. Module/download startup is reported separately in raw evidence. React render, row transforms and browser script/layout overlap and must not be added together.

| Workload/cache                      | Nodes/edges |         Mount | Row transforms |  React render | Browser layout | PNG generation |
| ----------------------------------- | ----------: | ------------: | -------------: | ------------: | -------------: | -------------: |
| aci/captured/cold                   |       25/33 | 115.5 / 143.9 |      4.7 / 5.4 |   50.8 / 65.1 |    13.2 / 15.0 |    43.1 / 55.1 |
| aci/captured/warm                   |       25/33 | 110.8 / 124.3 |      4.5 / 4.6 |   47.6 / 48.4 |    11.7 / 12.2 |    45.3 / 45.4 |
| aci/realistic/cold                  |     100/400 | 158.1 / 178.9 |    17.9 / 19.7 |   83.4 / 94.3 |    18.3 / 21.4 |  160.3 / 179.5 |
| aci/realistic/warm                  |     100/400 | 158.8 / 168.5 |    18.1 / 18.9 |   86.1 / 89.5 |    18.7 / 19.5 |  162.0 / 171.5 |
| aci/near-limit/cold                 |    500/2000 | 394.6 / 421.1 |    70.2 / 73.5 | 227.2 / 247.7 |    45.0 / 51.9 |  551.9 / 597.2 |
| aci/near-limit/warm                 |    500/2000 | 392.7 / 420.1 |    71.1 / 73.9 | 226.0 / 241.2 |    45.1 / 48.2 |  564.6 / 615.4 |
| nxos/captured/cold                  |       21/24 | 122.8 / 128.4 |      3.6 / 3.9 |   47.7 / 52.0 |    12.8 / 13.2 |    39.8 / 42.1 |
| nxos/captured/warm                  |       21/24 | 113.5 / 119.4 |      3.5 / 3.6 |   44.3 / 49.7 |    12.1 / 14.3 |    39.8 / 45.0 |
| nxos/realistic/cold                 |     100/400 | 155.6 / 166.3 |    16.1 / 17.1 |   83.1 / 90.9 |    17.7 / 20.1 |  164.6 / 168.6 |
| nxos/realistic/warm                 |     100/400 | 149.5 / 161.2 |    15.8 / 17.7 |   81.1 / 90.6 |    17.4 / 19.6 |  160.0 / 172.7 |
| nxos/near-limit/cold                |    500/2000 | 387.8 / 399.5 |    68.3 / 70.0 | 224.0 / 231.9 |    45.0 / 46.9 |  522.7 / 538.0 |
| nxos/near-limit/warm                |    500/2000 | 387.2 / 405.4 |    69.0 / 70.6 | 226.0 / 237.8 |    45.1 / 47.2 |  528.9 / 551.0 |
| catalyst-aci/captured/cold          |       25/36 | 121.8 / 124.0 |      7.5 / 7.6 |   50.6 / 53.0 |    13.0 / 13.2 |    43.7 / 46.4 |
| catalyst-aci/captured/warm          |       25/36 | 124.0 / 127.6 |      7.3 / 7.7 |   50.7 / 53.2 |    13.0 / 13.2 |    43.2 / 44.8 |
| catalyst-aci/realistic/cold         |     100/400 | 158.3 / 166.0 |    20.3 / 21.3 |   87.6 / 90.7 |    18.7 / 19.5 |  160.7 / 168.6 |
| catalyst-aci/realistic/warm         |     100/400 | 158.4 / 163.2 |    20.4 / 21.1 |   88.5 / 92.2 |    19.2 / 19.3 |  163.8 / 167.5 |
| catalyst-aci/realistic/partial/cold |     100/400 | 158.9 / 164.7 |    20.1 / 21.5 |   88.0 / 91.8 |    18.4 / 19.5 |  154.8 / 160.1 |
| catalyst-aci/realistic/partial/warm |     100/400 | 161.8 / 163.6 |    20.3 / 21.0 |   87.5 / 88.5 |    18.4 / 18.8 |  159.4 / 163.8 |
| catalyst-aci/near-limit/cold        |    500/2000 | 404.6 / 423.6 |    80.1 / 83.5 | 241.7 / 252.4 |    46.2 / 48.1 |  581.5 / 603.9 |
| catalyst-aci/near-limit/warm        |    500/2000 | 394.2 / 395.2 |    78.0 / 79.1 | 232.0 / 234.1 |    45.5 / 46.2 |  534.5 / 580.5 |
| meraki-nxos/captured/cold           |       21/23 | 135.2 / 137.0 |      5.9 / 6.1 |   49.0 / 49.6 |    12.9 / 13.3 |    40.7 / 43.1 |
| meraki-nxos/captured/warm           |       21/23 | 126.0 / 132.1 |      5.7 / 6.0 |   47.8 / 48.5 |    12.7 / 13.0 |    40.1 / 40.9 |
| meraki-nxos/realistic/cold          |     100/400 | 157.8 / 166.5 |    19.6 / 20.5 |   85.8 / 91.1 |    17.7 / 18.2 |  158.1 / 160.8 |
| meraki-nxos/realistic/warm          |     100/400 | 160.4 / 165.1 |    19.7 / 20.2 |   84.5 / 88.0 |    17.6 / 19.7 |  154.0 / 173.4 |
| meraki-nxos/realistic/partial/cold  |     100/400 | 156.9 / 174.3 |    19.9 / 21.9 |   85.8 / 94.4 |    18.2 / 20.4 |  154.1 / 158.6 |
| meraki-nxos/realistic/partial/warm  |     100/400 | 157.9 / 170.8 |    20.1 / 20.8 |   87.1 / 89.2 |    18.5 / 20.3 |  161.4 / 169.4 |
| meraki-nxos/near-limit/cold         |    500/2000 | 413.2 / 415.1 |    81.5 / 84.1 | 236.3 / 241.9 |    46.1 / 46.8 |  530.5 / 546.4 |
| meraki-nxos/near-limit/warm         |    500/2000 | 392.9 / 416.9 |    81.1 / 82.7 | 234.4 / 242.1 |    45.6 / 46.3 |  522.7 / 549.3 |

The JSON summary retains distributions for highlight/jump, card/edge selection, filters, expansion, table rendering, CSV/JSON/PNG export, browser script/layout/task time, long tasks, and isolated transforms/indexes/layout/path batches. Each isolated operation has one unrecorded warmup and five repetitions; summaries aggregate each sample’s median.

Correctness checks preserve full graph export equality, exact input counts, finite geometry, PNG signature/allocation, attachment and traffic evidence CSVs, and visible partial/unresolved client handoff warnings. Partial records remain in the graph/export while backend assignment stays unavailable. Controlled additions preserve every captured input row; they are browser workloads, not claims about real telemetry volume.

Provisional investigation budgets in the summary are measured baseline p95 × 1.25 + 10 ms (isolated operations: +2 ms). These are local engineering prompts for investigation, not CI gates or service objectives. Long-task counts/durations are retained directly; browser long-task entries use the browser’s 50 ms definition. Search dispatch, Splunk execution/result download, filesystem artifact reading, and microbenchmark batches are excluded from mount/interaction/export-generation timing.
