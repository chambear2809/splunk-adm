# Atlas browser performance evidence

Historical schema 1 interaction intervals include Playwright completion before
the readiness loop. This comparison preserves those observations; it is not a
comparison using the corrected capture-started readiness protocol. See
[results and diagnostic boundaries](atlas-browser-results.md).

This `510754c`/`7999d3a` source pair is also superseded for current acceptance by
accepted main `d6863dd`; preserve it as historical evidence.

Baseline source: `510754c17391e548309dd68ddac3f8b99e0b75c6`; tree hash `10ac9dc39cec749ece12703d845d9872f0d6d3b28848a49f1ab480224954224e`.

Harness: `7a3829bfdf2daf3f9340c5fc23a3a4f793d11c0ee4ceeb4c2d04df6aeb41b14e`. Chromium 156.0.8078.4; Node v26.10.0; Apple M3 Pro, 12 logical CPUs, 18 GiB; darwin/arm64.

140 baseline samples; 5 repetitions per workload/cache state. One discarded warmup per warm context. Production ReactDOM profiling build; 1440×1000, DPR 1, headless, UTC. Browser process and OS cache are reused; “cold” means a fresh browser context. OS/desktop background activity remains uncontrolled; consult the environment note for agent workload and idle-lab state.

Each cell below is median / p95 in milliseconds. With five samples, nearest-rank p95 is the maximum; these values do not estimate population tail latency. Mount usability includes fonts and three stable animation frames. Module/download startup is reported separately in raw evidence. React render, row transforms and browser script/layout overlap and must not be added together.

| Workload/cache                      | Nodes/edges |           Mount | Row transforms |  React render | Browser layout | PNG generation |
| ----------------------------------- | ----------: | --------------: | -------------: | ------------: | -------------: | -------------: |
| aci/captured/cold                   |       25/33 |   109.6 / 144.1 |      4.4 / 4.9 |   46.4 / 65.3 |    11.7 / 14.7 |    43.6 / 48.1 |
| aci/captured/warm                   |       25/33 |   115.1 / 115.4 |      4.5 / 5.0 |   45.9 / 53.0 |    11.4 / 13.1 |    43.1 / 48.1 |
| aci/realistic/cold                  |     100/400 |   155.9 / 166.7 |    18.1 / 18.5 |   82.9 / 87.7 |    17.9 / 18.6 |  162.0 / 167.0 |
| aci/realistic/warm                  |     100/400 |   148.3 / 158.5 |    17.7 / 18.1 |   81.8 / 84.0 |    17.7 / 19.4 |  160.6 / 163.3 |
| aci/near-limit/cold                 |    500/2000 |   376.6 / 388.0 |    67.9 / 69.5 | 220.7 / 223.7 |    43.8 / 44.7 |  574.0 / 611.9 |
| aci/near-limit/warm                 |    500/2000 |   378.3 / 393.6 |    69.0 / 72.3 | 221.7 / 229.8 |    44.4 / 45.2 |  579.5 / 601.8 |
| nxos/captured/cold                  |       21/24 |   117.2 / 121.6 |      3.4 / 3.9 |   44.5 / 46.4 |    11.3 / 12.1 |    41.4 / 42.5 |
| nxos/captured/warm                  |       21/24 |   111.2 / 124.1 |      3.4 / 3.6 |   44.6 / 47.0 |    11.9 / 12.9 |    41.6 / 43.2 |
| nxos/realistic/cold                 |     100/400 |   151.6 / 157.7 |    15.9 / 16.2 |   80.4 / 87.3 |    17.7 / 18.3 |  156.1 / 160.3 |
| nxos/realistic/warm                 |     100/400 |   147.9 / 158.9 |    15.5 / 15.7 |   81.0 / 81.3 |    17.4 / 18.0 |  157.2 / 158.4 |
| nxos/near-limit/cold                |    500/2000 |   375.2 / 384.1 |    68.3 / 69.9 | 219.0 / 225.0 |    44.0 / 45.3 |  548.5 / 574.8 |
| nxos/near-limit/warm                |    500/2000 |   390.7 / 398.3 |    68.7 / 70.8 | 226.6 / 234.9 |    45.4 / 46.3 |  580.0 / 616.3 |
| catalyst-aci/captured/cold          |       25/36 |   124.5 / 132.0 |      6.9 / 7.2 |   51.2 / 54.2 |    12.9 / 13.6 |    45.1 / 48.5 |
| catalyst-aci/captured/warm          |       25/36 |   119.5 / 124.7 |      7.1 / 7.3 |   51.8 / 53.9 |    13.4 / 14.1 |    42.9 / 43.7 |
| catalyst-aci/realistic/cold         |     100/400 |   304.0 / 307.3 |  185.0 / 190.8 | 220.2 / 229.1 |    15.6 / 16.0 |  155.8 / 157.2 |
| catalyst-aci/realistic/warm         |     100/400 |   294.4 / 335.0 |  189.6 / 198.7 | 225.2 / 240.4 |    15.5 / 17.5 |  154.0 / 160.3 |
| catalyst-aci/realistic/partial/cold |     100/400 |   305.6 / 316.9 |  186.5 / 193.5 | 222.4 / 232.8 |    15.9 / 16.9 |  158.3 / 164.8 |
| catalyst-aci/realistic/partial/warm |     100/400 |   295.5 / 320.5 |  185.0 / 197.8 | 222.3 / 238.7 |    15.8 / 17.9 |  152.3 / 159.5 |
| catalyst-aci/near-limit/cold        |    500/2000 | 1182.3 / 1212.4 |  851.7 / 871.4 | 916.0 / 934.2 |    33.1 / 33.6 |  511.7 / 518.3 |
| catalyst-aci/near-limit/warm        |    500/2000 | 1184.1 / 1224.3 |  856.3 / 877.6 | 917.2 / 947.8 |    33.8 / 34.4 |  511.1 / 517.9 |
| meraki-nxos/captured/cold           |       21/23 |   121.7 / 124.3 |      5.8 / 6.0 |   46.4 / 48.5 |    12.1 / 12.9 |    39.8 / 40.7 |
| meraki-nxos/captured/warm           |       21/23 |   127.6 / 129.3 |      6.0 / 6.2 |   46.8 / 48.5 |    12.0 / 12.6 |    41.6 / 42.4 |
| meraki-nxos/realistic/cold          |     100/400 |   304.4 / 307.3 |  191.3 / 197.5 | 222.0 / 229.2 |    15.3 / 15.8 |  155.0 / 162.5 |
| meraki-nxos/realistic/warm          |     100/400 |   297.2 / 311.7 |  188.9 / 191.5 | 222.0 / 223.4 |    15.0 / 15.9 |  155.7 / 157.0 |
| meraki-nxos/realistic/partial/cold  |     100/400 |   304.0 / 309.1 |  189.8 / 193.6 | 223.7 / 227.0 |    15.1 / 16.0 |  156.7 / 171.2 |
| meraki-nxos/realistic/partial/warm  |     100/400 |   310.1 / 316.2 |  194.2 / 197.8 | 230.6 / 231.5 |    15.4 / 16.4 |  163.0 / 180.9 |
| meraki-nxos/near-limit/cold         |    500/2000 | 1213.5 / 1223.9 |  876.1 / 883.5 | 941.4 / 951.1 |    33.6 / 34.5 |  515.5 / 572.5 |
| meraki-nxos/near-limit/warm         |    500/2000 | 1192.6 / 1218.9 |  871.7 / 880.5 | 932.3 / 946.1 |    33.7 / 34.5 |  521.6 / 564.5 |

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

Candidate source: `7999d3a8b27ee3c786f5bb43345b06273966a675`; tree hash `be5316041dcbbb3e6d5bd34c9a079da84be294961c4da56a46a315f76f62adb8`; 140 samples. Dirty-source details and complete measurements are retained in JSON.

| Workload/cache                      | Baseline mount median | Candidate mount median | Change | Baseline edge selection | Candidate edge selection | Baseline PNG | Candidate PNG |
| ----------------------------------- | --------------------: | ---------------------: | -----: | ----------------------: | -----------------------: | -----------: | ------------: |
| aci/captured/cold                   |                 109.6 |                  117.7 |   7.4% |                    64.4 |                     64.8 |         43.6 |          42.5 |
| aci/captured/warm                   |                 115.1 |                  118.2 |   2.7% |                    64.2 |                     64.9 |         43.1 |          43.6 |
| aci/realistic/cold                  |                 155.9 |                  145.1 |  -6.9% |                    81.9 |                     65.6 |        162.0 |         160.5 |
| aci/realistic/warm                  |                 148.3 |                  146.0 |  -1.6% |                    82.0 |                     65.3 |        160.6 |         170.9 |
| aci/near-limit/cold                 |                 376.6 |                  334.4 | -11.2% |                    99.0 |                     82.3 |        574.0 |         568.7 |
| aci/near-limit/warm                 |                 378.3 |                  331.5 | -12.4% |                    98.9 |                     99.0 |        579.5 |         584.7 |
| nxos/captured/cold                  |                 117.2 |                  118.6 |   1.2% |                    64.6 |                     64.8 |         41.4 |          39.9 |
| nxos/captured/warm                  |                 111.2 |                  111.6 |   0.4% |                    64.5 |                     64.4 |         41.6 |          41.2 |
| nxos/realistic/cold                 |                 151.6 |                  152.7 |   0.7% |                    81.9 |                     65.4 |        156.1 |         157.2 |
| nxos/realistic/warm                 |                 147.9 |                  141.0 |  -4.7% |                    81.9 |                     65.4 |        157.2 |         151.9 |
| nxos/near-limit/cold                |                 375.2 |                  325.8 | -13.2% |                    97.3 |                     82.3 |        548.5 |         535.5 |
| nxos/near-limit/warm                |                 390.7 |                  313.3 | -19.8% |                    98.4 |                     98.4 |        580.0 |         531.5 |
| catalyst-aci/captured/cold          |                 124.5 |                  118.9 |  -4.5% |                    65.1 |                     64.8 |         45.1 |          44.4 |
| catalyst-aci/captured/warm          |                 119.5 |                  111.5 |  -6.7% |                    64.8 |                     64.5 |         42.9 |          43.9 |
| catalyst-aci/realistic/cold         |                 304.0 |                  144.3 | -52.5% |                    82.0 |                     65.1 |        155.8 |         130.1 |
| catalyst-aci/realistic/warm         |                 294.4 |                  149.0 | -49.4% |                    98.4 |                     65.3 |        154.0 |         126.4 |
| catalyst-aci/realistic/partial/cold |                 305.6 |                  142.5 | -53.4% |                    98.4 |                     64.9 |        158.3 |         129.0 |
| catalyst-aci/realistic/partial/warm |                 295.5 |                  146.1 | -50.6% |                    98.7 |                     65.2 |        152.3 |         124.8 |
| catalyst-aci/near-limit/cold        |                1182.3 |                  397.7 | -66.4% |                   231.7 |                     81.8 |        511.7 |         360.5 |
| catalyst-aci/near-limit/warm        |                1184.1 |                  402.1 | -66.0% |                   232.0 |                     82.0 |        511.1 |         370.0 |
| meraki-nxos/captured/cold           |                 121.7 |                  118.8 |  -2.4% |                    65.2 |                     64.4 |         39.8 |          40.2 |
| meraki-nxos/captured/warm           |                 127.6 |                  122.2 |  -4.2% |                    64.3 |                     64.4 |         41.6 |          39.9 |
| meraki-nxos/realistic/cold          |                 304.4 |                  156.4 | -48.6% |                    98.7 |                     65.0 |        155.0 |         132.6 |
| meraki-nxos/realistic/warm          |                 297.2 |                  152.8 | -48.6% |                    98.6 |                     65.1 |        155.7 |         146.1 |
| meraki-nxos/realistic/partial/cold  |                 304.0 |                  155.3 | -48.9% |                    98.3 |                     65.2 |        156.7 |         145.2 |
| meraki-nxos/realistic/partial/warm  |                 310.1 |                  147.6 | -52.4% |                    98.8 |                     65.2 |        163.0 |         128.8 |
| meraki-nxos/near-limit/cold         |                1213.5 |                  411.9 | -66.1% |                   232.2 |                     82.2 |        515.5 |         368.1 |
| meraki-nxos/near-limit/warm         |                1192.6 |                  401.9 | -66.3% |                   231.5 |                     81.9 |        521.6 |         370.1 |

The JSON summary retains distributions for highlight/jump, card/edge selection, filters, expansion, table/Devices rendering, CSV/JSON/PNG export, browser script/layout/task time, long tasks, and isolated transforms/indexes/layout/path/device-summary batches. Each isolated operation has one unrecorded warmup and five repetitions; summaries aggregate each sample’s median.

Correctness checks preserve full graph export equality, exact input counts, finite geometry, PNG signature/allocation, every attachment/traffic CSV record, qualified identity resolution, rejection of ambiguous/mismatched authority evidence, the Devices reference-cap disclosure, and visible partial/unresolved client handoff warnings. Partial records remain in the graph/export while backend assignment stays unavailable. Controlled additions preserve every captured node/edge row; they are graph-contract browser workloads, not claims about collected telemetry or deployment capacity.

Provisional investigation budgets in the summary are measured baseline p95 × 1.25 + 10 ms (isolated operations: +2 ms). These are local engineering prompts for investigation, not CI gates or service objectives. Long-task counts/durations are retained directly; browser long-task entries use the browser’s 50 ms definition. Search dispatch, Splunk execution/result download, filesystem artifact reading, and microbenchmark batches are excluded from mount/interaction/export-generation timing.
