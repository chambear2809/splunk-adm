# Atlas browser performance evidence

Baseline source: `d6863dd326099acb892e1eebaa6c43d4f4410947`; tree hash `44d013c9d234acbc4e530bea6f5586af2cc32f0d16c68312311783f6dd773a93`.

Harness: `95506ec1e1a812ad1629136486e6776342711549496b4e0beff9efe0bf306fb6`. Chromium 156.0.8078.4; Node v26.10.0; Apple M3 Pro, 12 logical CPUs, 18 GiB; darwin/arm64.

140 baseline samples; 5 repetitions per workload/cache state. One discarded warmup per warm context. Production ReactDOM profiling build; 1440×1000, DPR 1, headless, UTC. Browser process and OS cache are reused; “cold” means a fresh browser context. OS/desktop background activity remains uncontrolled; consult the environment note for agent workload and idle-lab state.

Each cell below is median / p95 in milliseconds. With five samples, nearest-rank p95 is the maximum; these values do not estimate population tail latency. Mount usability includes fonts and three stable animation frames. Module/download startup is reported separately in raw evidence. React render, row transforms and browser script/layout overlap and must not be added together.

Interaction readiness starts in the browser at event capture. Action-specific preconditions and expected committed DOM state gate three unchanged frames after the first valid committed frame. Playwright trigger duration and the browser timestamp observed after trigger completion are separate measurements; they do not extend event-to-ready duration. Mount and export-generation boundaries retain their original definitions.

| Workload/cache                      | Nodes/edges |           Mount | Row transforms |  React render | Browser layout | PNG generation |
| ----------------------------------- | ----------: | --------------: | -------------: | ------------: | -------------: | -------------: |
| aci/captured/cold                   |       25/33 |   122.5 / 130.9 |      4.4 / 5.2 |   50.1 / 53.1 |    12.9 / 13.4 |    43.4 / 45.8 |
| aci/captured/warm                   |       25/33 |   115.8 / 122.4 |      4.4 / 4.6 |   46.8 / 49.5 |    11.4 / 12.5 |    43.7 / 48.1 |
| aci/realistic/cold                  |     100/400 |   147.1 / 159.8 |    17.3 / 17.6 |   79.4 / 80.9 |    17.1 / 17.6 |  155.2 / 159.2 |
| aci/realistic/warm                  |     100/400 |   149.4 / 151.0 |    17.1 / 18.6 |   80.8 / 82.2 |    17.3 / 17.6 |  161.1 / 171.1 |
| aci/near-limit/cold                 |    500/2000 |   377.4 / 386.1 |    67.6 / 69.3 | 217.4 / 227.0 |    43.6 / 44.9 |  562.9 / 572.8 |
| aci/near-limit/warm                 |    500/2000 |   381.2 / 398.0 |    68.0 / 70.5 | 217.6 / 232.4 |    43.5 / 45.9 |  564.6 / 589.5 |
| nxos/captured/cold                  |       21/24 |   114.5 / 123.1 |      3.2 / 3.3 |   44.1 / 46.5 |    11.0 / 12.2 |    42.6 / 45.5 |
| nxos/captured/warm                  |       21/24 |   115.8 / 127.7 |      3.4 / 3.4 |   44.3 / 50.5 |    12.1 / 13.3 |    41.0 / 46.3 |
| nxos/realistic/cold                 |     100/400 |   147.2 / 156.7 |    15.4 / 16.0 |   78.3 / 82.5 |    16.9 / 17.7 |  153.3 / 154.3 |
| nxos/realistic/warm                 |     100/400 |   150.4 / 152.1 |    15.3 / 15.6 |   77.0 / 79.4 |    16.8 / 17.0 |  149.1 / 153.8 |
| nxos/near-limit/cold                |    500/2000 |   363.8 / 385.1 |    66.2 / 69.6 | 211.3 / 225.8 |    42.5 / 44.9 |  537.6 / 564.4 |
| nxos/near-limit/warm                |    500/2000 |   364.7 / 365.9 |    65.6 / 66.9 | 211.2 / 213.2 |    42.4 / 42.8 |  530.7 / 537.2 |
| catalyst-aci/captured/cold          |       25/36 |   112.9 / 125.9 |      6.8 / 7.1 |   48.4 / 49.1 |    11.8 / 11.9 |    44.5 / 45.2 |
| catalyst-aci/captured/warm          |       25/36 |   114.7 / 117.9 |      6.9 / 7.0 |   49.1 / 50.9 |    12.1 / 12.6 |    43.1 / 45.7 |
| catalyst-aci/realistic/cold         |     100/400 |   296.3 / 298.9 |  179.4 / 181.0 | 213.8 / 215.7 |    14.7 / 14.8 |  147.7 / 158.4 |
| catalyst-aci/realistic/warm         |     100/400 |   298.0 / 323.5 |  181.5 / 193.3 | 215.1 / 235.1 |    14.9 / 16.6 |  148.9 / 156.8 |
| catalyst-aci/realistic/partial/cold |     100/400 |   296.7 / 303.8 |  179.5 / 184.0 | 213.7 / 223.0 |    14.8 / 14.9 |  150.9 / 154.1 |
| catalyst-aci/realistic/partial/warm |     100/400 |   284.2 / 297.8 |  180.0 / 185.7 | 213.3 / 219.0 |    14.9 / 15.1 |  150.6 / 158.9 |
| catalyst-aci/near-limit/cold        |    500/2000 | 1159.2 / 1164.2 |  838.2 / 846.1 | 899.9 / 903.9 |    32.7 / 32.9 |  497.5 / 520.4 |
| catalyst-aci/near-limit/warm        |    500/2000 | 1162.9 / 1185.0 |  842.3 / 854.5 | 904.4 / 919.8 |    32.9 / 33.0 |  498.8 / 531.1 |
| meraki-nxos/captured/cold           |       21/23 |   127.2 / 129.8 |      5.5 / 5.6 |   44.7 / 46.7 |    11.4 / 11.5 |    41.7 / 42.5 |
| meraki-nxos/captured/warm           |       21/23 |   117.3 / 131.6 |      5.3 / 5.8 |   44.2 / 45.5 |    11.5 / 11.6 |    42.1 / 43.1 |
| meraki-nxos/realistic/cold          |     100/400 |   297.4 / 298.8 |  185.4 / 186.9 | 218.8 / 219.7 |    14.4 / 14.5 |  151.4 / 159.8 |
| meraki-nxos/realistic/warm          |     100/400 |   300.7 / 311.3 |  183.7 / 194.5 | 216.1 / 228.1 |    14.6 / 16.1 |  154.4 / 168.1 |
| meraki-nxos/realistic/partial/cold  |     100/400 |   297.0 / 320.0 |  188.5 / 191.7 | 219.4 / 229.7 |    15.0 / 16.9 |  154.9 / 159.0 |
| meraki-nxos/realistic/partial/warm  |     100/400 |   301.1 / 302.2 |  184.3 / 186.0 | 217.2 / 219.0 |    14.5 / 15.0 |  151.9 / 154.5 |
| meraki-nxos/near-limit/cold         |    500/2000 | 1159.9 / 1171.7 |  843.0 / 851.2 | 900.9 / 904.0 |    32.1 / 32.7 |  503.2 / 523.7 |
| meraki-nxos/near-limit/warm         |    500/2000 | 1154.8 / 1160.0 |  842.6 / 843.1 | 902.4 / 903.1 |    32.1 / 32.8 |  498.9 / 517.3 |

| Evidence workload              | Clients / authorities | Attachment records | Traffic records | Handoff records (complete/partial/unresolved edges) | Topology rows |
| ------------------------------ | --------------------: | -----------------: | --------------: | --------------------------------------------------: | ------------: |
| aci/captured                   |                 0 / 0 |                  0 |               0 |                                           0 (0/0/0) |            18 |
| aci/realistic                  |                 0 / 0 |                  0 |               0 |                                           0 (0/0/0) |            18 |
| aci/near-limit                 |                 0 / 0 |                  0 |               0 |                                           0 (0/0/0) |            18 |
| nxos/captured                  |                 0 / 0 |                  0 |               0 |                                           0 (0/0/0) |            15 |
| nxos/realistic                 |                 0 / 0 |                  0 |               0 |                                           0 (0/0/0) |            15 |
| nxos/near-limit                |                 0 / 0 |                  0 |               0 |                                           0 (0/0/0) |            15 |
| catalyst-aci/captured          |                 1 / 1 |                  3 |               3 |                                           8 (7/0/1) |            64 |
| catalyst-aci/realistic         |                64 / 5 |                557 |             834 |                                       56 (28/21/22) |           293 |
| catalyst-aci/realistic/partial |                64 / 5 |                557 |             834 |                                       55 (22/32/17) |           293 |
| catalyst-aci/near-limit        |               412 / 5 |               2853 |            4278 |                                   317 (144/137/138) |          1337 |
| meraki-nxos/captured           |                 2 / 1 |                  2 |               2 |                                           1 (1/0/0) |            64 |
| meraki-nxos/realistic          |                69 / 5 |                574 |             860 |                                       52 (24/22/22) |           305 |
| meraki-nxos/realistic/partial  |                69 / 5 |                574 |             860 |                                       51 (17/34/17) |           305 |
| meraki-nxos/near-limit         |               417 / 5 |               2870 |            4304 |                                   313 (140/138/138) |          1349 |

Candidate source: `8813eb534f907ac9c95d6673ed02fdbdf1008673`; tree hash `65847e91461b32039123e36da921efadc1d8c4c415b13180a822ad9ac50799da`; 140 samples. Dirty-source details and complete measurements are retained in JSON.

| Workload/cache                      | Baseline mount median | Candidate mount median | Change | Baseline edge selection | Candidate edge selection | Baseline PNG | Candidate PNG |
| ----------------------------------- | --------------------: | ---------------------: | -----: | ----------------------: | -----------------------: | -----------: | ------------: |
| aci/captured/cold                   |                 122.5 |                  113.7 |  -7.2% |                    63.9 |                     64.6 |         43.4 |          45.3 |
| aci/captured/warm                   |                 115.8 |                  118.1 |   2.0% |                    65.1 |                     64.5 |         43.7 |          44.1 |
| aci/realistic/cold                  |                 147.1 |                  145.8 |  -0.9% |                    65.9 |                     65.9 |        155.2 |         154.3 |
| aci/realistic/warm                  |                 149.4 |                  134.9 |  -9.7% |                    65.9 |                     65.9 |        161.1 |         152.8 |
| aci/near-limit/cold                 |                 377.4 |                  310.6 | -17.7% |                    82.3 |                     66.3 |        562.9 |         547.3 |
| aci/near-limit/warm                 |                 381.2 |                  314.5 | -17.5% |                    66.6 |                     66.3 |        564.6 |         551.5 |
| nxos/captured/cold                  |                 114.5 |                  113.0 |  -1.3% |                    64.7 |                     64.6 |         42.6 |          42.5 |
| nxos/captured/warm                  |                 115.8 |                  110.8 |  -4.3% |                    63.5 |                     64.5 |         41.0 |          42.7 |
| nxos/realistic/cold                 |                 147.2 |                  145.3 |  -1.3% |                    65.9 |                     66.3 |        153.3 |         147.1 |
| nxos/realistic/warm                 |                 150.4 |                  135.9 |  -9.6% |                    65.0 |                     65.8 |        149.1 |         147.6 |
| nxos/near-limit/cold                |                 363.8 |                  313.3 | -13.9% |                    66.3 |                     66.3 |        537.6 |         480.1 |
| nxos/near-limit/warm                |                 364.7 |                  316.2 | -13.3% |                    66.1 |                     65.9 |        530.7 |         495.0 |
| catalyst-aci/captured/cold          |                 112.9 |                  122.1 |   8.1% |                    64.7 |                     63.6 |         44.5 |          41.5 |
| catalyst-aci/captured/warm          |                 114.7 |                  115.1 |   0.3% |                    64.8 |                     64.7 |         43.1 |          45.7 |
| catalyst-aci/realistic/cold         |                 296.3 |                  145.9 | -50.8% |                    64.9 |                     65.4 |        147.7 |         124.9 |
| catalyst-aci/realistic/warm         |                 298.0 |                  148.8 | -50.1% |                    65.5 |                     65.3 |        148.9 |         126.0 |
| catalyst-aci/realistic/partial/cold |                 296.7 |                  147.4 | -50.3% |                    65.6 |                     65.2 |        150.9 |         121.6 |
| catalyst-aci/realistic/partial/warm |                 284.2 |                  150.5 | -47.0% |                    65.4 |                     65.4 |        150.6 |         122.0 |
| catalyst-aci/near-limit/cold        |                1159.2 |                  389.4 | -66.4% |                   197.2 |                     65.7 |        497.5 |         357.3 |
| catalyst-aci/near-limit/warm        |                1162.9 |                  394.5 | -66.1% |                   197.3 |                     65.7 |        498.8 |         349.6 |
| meraki-nxos/captured/cold           |                 127.2 |                  111.1 | -12.7% |                    64.6 |                     64.7 |         41.7 |          41.4 |
| meraki-nxos/captured/warm           |                 117.3 |                  111.8 |  -4.7% |                    64.8 |                     64.7 |         42.1 |          42.1 |
| meraki-nxos/realistic/cold          |                 297.4 |                  148.2 | -50.2% |                    65.6 |                     65.1 |        151.4 |         125.5 |
| meraki-nxos/realistic/warm          |                 300.7 |                  149.6 | -50.2% |                    65.6 |                     65.5 |        154.4 |         127.7 |
| meraki-nxos/realistic/partial/cold  |                 297.0 |                  147.7 | -50.3% |                    65.7 |                     65.3 |        154.9 |         131.1 |
| meraki-nxos/realistic/partial/warm  |                 301.1 |                  153.2 | -49.1% |                    65.7 |                     65.5 |        151.9 |         125.5 |
| meraki-nxos/near-limit/cold         |                1159.9 |                  389.0 | -66.5% |                   198.9 |                     65.6 |        503.2 |         352.2 |
| meraki-nxos/near-limit/warm         |                1154.8 |                  389.2 | -66.3% |                   198.9 |                     65.7 |        498.9 |         349.4 |

The JSON summary retains distributions for highlight/jump, card/edge selection, filters, expansion, table/Devices rendering, CSV/JSON/PNG export, browser script/layout/task time, long tasks, and isolated transforms/indexes/layout/path/device-summary batches. Each isolated operation has one unrecorded warmup and five repetitions; summaries aggregate each sample’s median.

Correctness checks preserve full graph export equality, exact input counts, finite geometry, PNG signature/allocation, every attachment/traffic CSV record, qualified identity resolution, rejection of ambiguous/mismatched authority evidence, the Devices reference-cap disclosure, and visible partial/unresolved client handoff warnings. Partial records remain in the graph/export while backend assignment stays unavailable. Controlled additions preserve every captured node/edge row; they are graph-contract browser workloads, not claims about collected telemetry or deployment capacity.

Provisional investigation budgets in the summary are measured baseline p95 × 1.25 + 10 ms (isolated operations: +2 ms). These are local engineering prompts for investigation, not CI gates or service objectives. Long-task counts/durations are retained directly; browser long-task entries use the browser’s 50 ms definition. Search dispatch, Splunk execution/result download, filesystem artifact reading, and microbenchmark batches are excluded from mount/interaction/export-generation timing.
