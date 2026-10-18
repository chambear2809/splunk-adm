# Browser performance measurements

The standalone `tests/performance` harness builds the real `MapPage`, parsers,
indexes, layout, filters, inspector and export code into a production Vite bundle.
It uses the ReactDOM production profiling build so React commit/render durations
are available. The same harness can load an untouched baseline checkout and the
candidate checkout through `ADM_PERF_SOURCE_ROOT`. It does not require Splunk,
credentials, Docker or a lab.

## Repeat a measurement

Install dependencies from each source checkout's lockfile with `npm ci`; install
the matching Playwright Chromium with `npx playwright install chromium` if needed.
Run from the checkout containing this harness:

```sh
npx tsc -p tests/performance/tsconfig.json --noEmit
ADM_PERF_SOURCE_ROOT=/absolute/path/to/baseline-checkout \
  ADM_PERF_OUTPUT=dist/performance/baseline.json \
  npx playwright test --config tests/performance/playwright.config.ts
ADM_PERF_SOURCE_ROOT="$PWD" \
  ADM_PERF_OUTPUT=dist/performance/candidate.json \
  npx playwright test --config tests/performance/playwright.config.ts
node tests/performance/report.mjs \
  dist/performance/baseline.json dist/performance/candidate.json \
  dist/performance/comparison.md
```

The dedicated server uses port 4187 and refuses to reuse an existing server.
Do not run two performance suites concurrently. Build output and failure artifacts
are under ignored `dist/`; the ordinary browser regression suite has its own
server and artifacts. Avoid competing browser/build jobs for comparative runs.
Keep source and harness files unchanged during a recorded run: source/harness
hashes before and after measurement must agree. The report tool rejects incomplete
runs, differing workload fingerprints, differing instrumentation and differing
runtime/hardware settings.

For harness development, `ADM_PERF_REPETITIONS=1` shortens the run. Optional
`ADM_PERF_SCENARIOS=aci,nxos,catalyst-aci,meraki-nxos` and
`ADM_PERF_SIZES=captured,realistic,near-limit` select subsets. Retained baseline and
candidate evidence must use the same complete matrix and repetition count.

## Workloads and correctness

All four captured scenarios run unchanged. Their node/edge counts are ACI 25/33,
NXOS 21/24, Catalyst→ACI 25/36, and Meraki→NXOS 21/23. Each also runs controlled
100-node/400-edge and 500-node/2,000-edge workloads. The generator retains every
captured node and edge row. ACI/NXOS add deterministic workload/endpoint nodes,
ownership edges and mixed directed/unknown-direction conversations. The Cisco
scenarios add evidence rather than scaling generic traffic alone:

| Scenario / graph size             | Network clients | Client authorities | Attachment records | Unique traffic records | Handoff records | Topology rows |
| --------------------------------- | --------------: | -----------------: | -----------------: | ---------------------: | --------------: | ------------: |
| Catalyst / 100 nodes, 400 edges   |              64 |                  5 |                557 |                    834 |              56 |           293 |
| Catalyst / 500 nodes, 2,000 edges |             412 |                  5 |              2,853 |                  4,278 |             317 |         1,337 |
| Meraki / 100 nodes, 400 edges     |              69 |                  5 |                574 |                    860 |              52 |           305 |
| Meraki / 500 nodes, 2,000 edges   |             417 |                  5 |              2,870 |                  4,304 |             313 |         1,349 |

Four generated authorities intentionally share native MACs, client IPs, device
names and access aliases while retaining distinct SHA-256 identities qualified
by source/authority/native ID. Every generated client has two independent
attachment snapshots/associations and inventory links. Observation edges have
three independently fingerprinted exporter/domain records; client handoffs mix
complete, partial and unresolved coverage, including multiple backend choices.
Attachment references include exact IDs, noncanonical ambiguous aliases and IDs
whose authority disagrees with the client evidence. The checks verify qualified
resolution and rejection of ambiguous or mismatched evidence.

Two further 100/400 cases increase the proportion of generated partial handoffs;
their handoff record counts are 55 (Catalyst) and 51 (Meraki). Every original
captured node/edge remains unchanged. The inspector must show partial coverage
and decline backend assignment while exports retain the determined records.
Topology inventory, access/exporter devices and client association links grow
with the client population. These graph-contract workloads do not establish
performance at the separate 20,000-row topology limit and are explicitly synthetic;
they do not simulate collected TA events or claim measured deployment capacity.

Every sample checks exact graph counts, finite layout geometry and routed edge
membership, full JSON equality against the normalized graph, required-flow CSV,
attachment/traffic context CSV where applicable, and PNG signature and allocation
bounds. CSV checks count and parse every original attachment/observation record.
Devices rendering is timed, its existing 32-reference display cap must disclose
every omitted reference, and full records remain in CSV/JSON exports. Normal
automatic pod collapse is measured first; the public expansion
interaction then expands all summaries before map export. No limits or evidence
are removed to improve a measurement.

## Timing boundaries

Five samples use fresh contexts (cold browser HTTP cache); five use a shared
context after one discarded full warmup (warm browser cache). Each sample uses a
fresh page. Chromium process, OS filesystem cache and local server caches remain
warm across contexts. Record this distinction when interpreting results.

Navigation/resource timing covers local bundle download and module startup.
The timed mount starts after modules, fixture generation and fingerprinting are
ready. Integrated row/topology conversion occurs inside the real `demoData`
callback, including every invocation the component makes. Usability requires
fonts ready, a loaded graph, positive SVG viewport/content geometry, rendered hit
targets and stable counts, geometry and fit transform for three consecutive
animation frames. This is an application settling measurement, not LCP or INP.

Interaction measurements start in a capture listener on the actual input event
and end at the same settling condition. They include highlighting, keyboard
highlight jump, card selection/clearing, filtering/clearing, summary expansion,
table rendering and selection of an unresolved/partial conversation. Table
settling checks loaded counts, rendered rows and inspector text without requiring
an SVG. Export generation starts at click capture and ends when the generated
blob link dispatches its download; Playwright's download notification and file
reads are retained separately or performed outside that interval.

React Profiler actual durations, CDP script/layout/style/task durations, heap/DOM
metrics and supported browser long-task entries accompany mount timing. They
overlap and must not be summed into a phase total. Workload generation and
fingerprinting finish before the CDP snapshots and mount timer start;
`preparationMs` is retained separately. Isolated graph/topology
transforms, indexing, network/collapsed/services layout, filtering and batches of
all conversation paths and device/attachment summaries use one warmup plus five
browser repetitions. Those
microbenchmarks run after user interactions and exports; their cost is excluded
from interaction timings. Long-task support is explicit in every sample.

No Splunk search dispatch, polling, server execution or result download is part
of this browser-only benchmark. Live backend measurements require independent
evidence. Raw JSON records source commit and effective tree hash, harness hash,
input hash/bytes/counts, browser/runtime/hardware, cache state, repetitions,
individual values, correctness outcomes and incomplete-run failures. It contains
synthetic/captured repository data only; do not substitute customer data.

## Interpreting results

Measure the baseline before setting budgets. The report derives provisional local
investigation budgets from baseline p95 × 1.25 + 10 ms (isolated operations: +2 ms).
These are prompts to investigate candidate changes, not enforced CI thresholds,
service objectives, or permission to weaken correctness. Five samples make
nearest-rank p95 the maximum; they do not establish population tail latency.
Retain all samples and inspect variation, long tasks and runtime differences
before attributing a change to source code. Repeated frame settling imposes a
rough 50–67 ms floor at 60 Hz. React profiling and browser automation add overhead
consistently to both builds.
