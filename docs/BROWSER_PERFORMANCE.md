# Browser performance measurements

The Splunk production build writes `dist/atlas-bundle-report.json` outside the
app archive. It reports final gzip bytes at level 9, remaining headroom against
the existing 670 KiB release gate, and per-module rendered-byte attribution.
The release checker explicitly uses level 9, preserving its established CI
calculation across Python versions whose default compression levels differ.
Module contributions are uncompressed attribution estimates, not additive gzip
costs. Module identifiers omit absolute workspace paths. CI retains the report
separately for 90 days; the release checker remains authoritative for the exact
packaged bundle and its gzip ceiling.

The current map changes cache routed-edge membership and pill presentation
metadata across unrelated renders. Routed-edge focus preserves the first matching
route, and pill classification retains every evidence member. These changes do
not remove graph rows, inspector evidence or export content. No new browser timing
or benchmark was executed for this change; the historical measurements below
remain historical evidence rather than a measured speedup for this revision.

## Map search waterfall (0.8.4)

Splunk Cloud 10.6, `teastore-webui`, 2026-11-04, logged-in browser; per-job
waterfall in [benchmarks/2026-11-map-waterfall.md](benchmarks/2026-11-map-waterfall.md).
0.8.2 ran its four map jobs serially (summary graph, inventory, full graph,
inventory again). 0.8.4:

- **Pinned window.** Relative bounds are resolved once in the browser
  (`pinRequest`), so the summary read, inventory and full read share one exact
  window. Inventory for the expected graph window (start on a 300 s summary
  slice) is dispatched beside the graph. If the returned window differs, that
  speculative read is cancelled and inventory is read again for the returned window.
- **Split inventory.** `adm_topology` and `adm_map_vsphere_inventory` (the VMM
  half of `adm_topology_with_vsphere`, without the uplink append the map
  always filtered out) run side by side. Rows are concatenated in the macro's
  order (row-equal live at 15 min, 24 h and 7 d).
- **Full read** starts once the summary graph returns. It reuses the
  exact-window inventory instead of reading it again. At most 3 browser jobs run at
  once.
- `performance.measure`: `atlas:graph:deferred|full`, `atlas:inventory`,
  `atlas:map:first|full`.

| Window | Draw 0.8.2 | Draw 0.8.4 | In-app draw 0.8.4 | Full 0.8.2 | Full 0.8.4  |
| ------ | ---------- | ---------- | ----------------- | ---------- | ----------- |
| 15 min | 12.0 s¹    | 8.8 s      | 4.5 s             | 23.0 s     | 17.8 s      |
| 1 h    | 8.7 s      | 6.9–7.4 s  | 4.2–4.5 s         | 21.9 s     | 14.8–19.8 s |
| 4 h    | 10.7 s     | 6.3–7.2 s  | 3.8–4.7 s         | 26.0 s     | 13.8–17.6 s |
| 24 h   | 9.7 s      | 7.2–8.7 s  | 4.3–5.6 s         | 26.2 s     | 18.7–20.1 s |
| 7 d    | 13.7 s     | 7.8–9.4 s  | 5.4–6.0 s         | 32.2 s     | 18.7–21.8 s |

Draw and Full are measured from navigation, which includes 2.4–3.1 s of Splunk
Web page load before the app mounts. In-app draw is `atlas:map:first`, from
dispatch to publication. ¹ Cold cache. Totals are unchanged ("Exact totals",
read coverage 100). The remaining time is server-side: three concurrent jobs
slow the summary graph from 2.2 s to 3–4.7 s, `adm_topology` takes 3.4–3.9 s at
7 d, and the toolkit polls job status every 1 s.

## Map inventory read (0.8.1)

Splunk Cloud 10.6, 2026-11-04, server `runDuration` of `| search \`adm_topology_with_vsphere\``
(two runs each; the browser session had expired, so no navigation timing was taken):
15 min 2.4–2.6 s, 1 h 2.8–3.0 s, 4 h 3.1 s, 24 h 3.3–5.7 s, 7 d 6.7 s (0.8.0: 3.8 s at 4 h, 6.0 s at 24 h,
25.7 s at 7 d). Rows are unchanged (55: 12 devices, 42 links, 1 meta at 15 min and 7 d). The
deferred graph read for the same windows took 1.4–3.0 s.

## Live map windows (0.8.0, qualified summaries)

Splunk Cloud 10.6, `teastore-webui`, 2026-11-04, after a 7-day summary
backfill. Same script and metric as 0.7.3 (navigation to rendered map). First
render shows summarized totals; the newest unsummarized minutes then merge
(**Full**). Graph read alone (server, `tail=deferred`): 2.7 s (24 h) – 3.9 s
(7 d); the rest of First is the unchanged inventory read
(`adm_topology_with_vsphere`: 5 s at 4 h, 7 s at 24 h, 26 s at 7 d).

| Window | Read             | First  | Full | Relationships | Lines |
| ------ | ---------------- | ------ | ---- | ------------- | ----- |
| 15 min | exact, 7 min raw | 9.8 s  | 25 s | 134           | 16    |
| 1 h    | exact, 7 min raw | 8.6 s  | 27 s | 174           | 16    |
| 4 h    | exact, 7 min raw | 10.6 s | 36 s | 285           | 23    |
| 24 h   | exact, 3 min raw | 13.7 s | 29 s | 367           | 32    |
| 7 d    | exact, 4 min raw | 35.8 s | 74 s | 367           | 32    |

Exactness: summary manifests accounted for 7,751,110 native events over 24 h
(288/288 slices), equal to `tstats count`; a 10-minute summary graph equalled
an independent per-slice qualification of the same raw events (20 nodes, 145
relationships, 8,280 records). Screenshots: `live-map-teastore-webui-*-080.png`.

## Live map windows (0.7.3)

Splunk Cloud 10.6, `teastore-webui`, qualified identity, `slice_workers=2`,
2026-11-04. Time from Build map to rendered map; lines are drawn card-pair lines.
Windows over 5 minutes read at most 6 qualified 5-minute slices (all up to 30
minutes, else evenly spaced including the newest); the map warns how many.

| Window | Slices read | Render | Relationships | Lines |
| ------ | ----------- | ------ | ------------- | ----- |
| 15 min | 3 of 3      | 29 s   | 183           | 20    |
| 1 h    | 6 of 12     | 54 s   | 194           | 20    |
| 4 h    | 6 of 48     | 55 s   | 205           | 20    |
| 24 h   | 6 of 288    | 61 s   | 191           | 21    |
| 7 d    | 6 of 2016   | 45 s   | 138           | 20    |

Before (0.7.2, 5 min): 182 relationships drawn as 181 lines; over 5 min failed.
Live screenshots are kept out of the repo (they include the Splunk Cloud header and account); cropped demo-guide images are in `docs/demos/live/`.

## Map and table scale

Large scopes degrade instead of failing. The graph read is a ranked top-N
search (meta row, nodes, then relationships by relationship kind, bytes and
connections); the browser keeps at most 4,000 nodes and 10,000 relationships
and shows "Top N of M connections". Past 300 cards the layout summarizes the
largest groups (namespace, EPG, endpoints, nodes, workloads) into expandable
cards, bundles lines per card pair with counts, and sets line width from volume
on a log scale. Past 1,500 lines routing is straight; past 1,000 lines they are
drawn on a canvas with grid hit-testing, while cards stay focusable SVG and the
Table view is the keyboard-accessible list. Tables are windowed, sortable and
filterable. Details: [2026-11-03 scale benchmark](benchmarks/2026-11-03-scale.md).

| case (default LOD) | initial | pan/zoom p95 |
| ------------------ | ------- | ------------ |
| 500 nodes / 2k     | 84 ms   | 23 ms        |
| 4k nodes / 10k     | 124 ms  | 23 ms        |
| 4k nodes / 100k    | 599 ms  | 46 ms        |
| table 100k rows    | 18 ms   | 18 ms scroll |

Repeat: `ADM_SCALE_BENCH=1 ADM_SCALE_OUTPUT=dist/scale.json npx playwright test
tests/browser/perf-scale.spec.ts` (opt-in; it asserts the 4k/10k and 100k-row
budgets unless `ADM_SCALE_NO_ASSERT=1`).

The standalone `tests/performance` harness builds the real `MapPage`, parsers,
indexes, layout, filters, inspector and export code into a production Vite bundle.
It uses the ReactDOM production profiling build so React commit/render durations
are available. The same harness can load an untouched baseline checkout and the
candidate checkout through `ADM_PERF_SOURCE_ROOT`. It does not require Splunk,
credentials, Docker or a lab.

The current accepted-baseline follow-up is in
[final selection results](benchmarks/atlas-final-selection-results.md), with the
[raw evidence index](benchmarks/atlas-final-browser-evidence-index.json). It uses
accepted baseline `64473e5`, final frozen inputs, a complete 14-case matrix and
separate repeated selection/native diagnostics. The historical
[corrected accepted-main results](benchmarks/atlas-browser-d686-results.md) compare
baseline `d6863dd` versus candidate `8813eb5`, including unfavorable observations,
median/p95 checks and raw evidence checksums. The
[earlier comparison](benchmarks/atlas-browser-results.md) is preserved as
historical evidence; its original interaction intervals include automation
completion and must not be mixed with corrected results. The
[preparation note](benchmarks/atlas-browser-d686-preparation.md) records the
accepted-main transition. Comparative runs require the coordinator's source
freeze and explicit measurement GO.

## Repeat a measurement

Install dependencies from each source checkout's lockfile with `npm ci`; install
the matching Playwright Chromium with `npx playwright install chromium` if needed.
Run from the checkout containing this harness:

```sh
npx tsc -p tests/performance/tsconfig.json --noEmit
npx playwright test --config tests/performance/readiness.config.ts
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

Raw reports also fingerprint the imported deployment-health configuration and
pipeline-interface JSON, plus every file in the built `dist/performance-app`
directory, before and after each run. The source-freeze guard requires all of
these bytes to remain unchanged. The server runs `vite build` followed by
`vite preview`, with no HMR; source changes after building do not hot-reload the
served bundle, but still invalidate source provenance. The asset fingerprints
bind the actual production JavaScript/CSS/HTML served to the browser.

Complete CSV validation still parses every evidence record. One assertion wraps
the full parse loop, avoiding thousands of retained reporter steps per sample.
Node wall-stage telemetry records workflow and full-record validation separately
from browser timings. The whole-workload timeout scales with repetitions
(15 minutes at five repetitions per cache state); per-action automation and
browser-readiness deadlines remain 10 and 15 seconds respectively.

For harness development, `ADM_PERF_REPETITIONS=1` shortens the run. Optional
`ADM_PERF_SCENARIOS=aci,nxos,catalyst-aci,meraki-nxos` and
`ADM_PERF_SIZES=captured,realistic,near-limit` select subsets. Retained baseline and
candidate evidence must use the same complete matrix and repetition count.

For a **supplemental selection investigation**, set
`ADM_PERF_SELECTION_DIAGNOSTIC=1`. This retains preparation, mount, highlighting,
keyboard highlight jump and card selection with their normal preconditions,
intended DOM state, full graph counts, finite geometry and frame-settling checks.
It returns before filtering, exports and isolated operations, and explicitly
records this limited scope. It cannot replace the complete matrix or be passed
to the complete-matrix report tool. Use identical settings and harness bytes for
baseline and candidate. Twenty repetitions per cache state permit a
nearest-rank p95 distinct from the maximum; this still is a small local sample.

`ADM_PERF_TRACE_SELECTION=1` enables a separate CDP trace around selection;
`ADM_PERF_TRACE_DIR` chooses its ignored output directory. Optional
`ADM_PERF_TRACE_CATEGORIES` overrides the categories. Broad native diagnostic
categories such as `*,disabled-by-default-devtools.timeline` expose raster and
compositor waits that JavaScript profiles alone do not explain. Trace settings
are recorded; traced observations are kept separate from untraced distributions.
Two further diagnostic controls are deliberately excluded from normal acceptance:
`ADM_PERF_EXPERIMENT_CSS` injects explicitly recorded experimental styles, and
`ADM_PERF_DRAIN_SELECTION=1` requests a compositor screenshot before selection to
drain the preceding action's work. The screenshot is a scheduling intervention,
outside the timed action; its result must not replace the unchanged interaction
sequence or be presented as a product improvement.

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

Corrected interaction measurements (raw schema 2) start a browser-side readiness
promise in the capture listener on the actual input event. Each action verifies
its precondition before dispatch and requires its intended DOM update before
counting three unchanged frames after the first committed frame. Gates include
the expected selected card and inspector controls, the highlight jump's match
position, filter status, requested tab content, selected conversation row and
partial/unresolved handoff warning. Full graph counts and geometry remain
required. They include highlighting, keyboard
highlight jump, card selection/clearing, filtering/clearing, summary expansion,
table rendering and selection of an unresolved/partial conversation. Table
settling checks loaded counts, rendered rows and inspector text without requiring
an SVG. Export generation starts at click capture and ends when the generated
blob link dispatches its download; Playwright's download notification and file
reads are retained separately or performed outside that interval.

The test still awaits Playwright trigger success, then retrieves the already
running or resolved browser readiness promise. Failed triggers fail even when
the DOM became ready; missing events/postconditions and unstable geometry time
out. The browser's event-to-ready end is independent of trigger completion.
`playwrightTriggerDurationMs` records Node's complete trigger wait, including
actionability before dispatch. `triggerCompletionObservedAt` is a browser
timestamp sampled by an evaluation after that wait, so its corresponding event
interval is an upper bound on trigger completion. These clocks/intervals must
not be subtracted to infer a browser phase.

Each action also retains the actual input timestamp/target, first intended DOM
state observed by a mutation callback, individual React commits, integrated
transform calls, and each readiness frame's time, geometry, postcondition and
read cost. Mutation observation does not read geometry or establish presentation.
Per-action CDP deltas cover the surrounding automation/evaluation envelope;
they are not exact event-to-ready CPU intervals. Native trace timestamps are
needed to attribute work to that interval. These measurements overlap and must
not be added into a phase total.

The stable-frame protocol observes main-thread animation callbacks and DOM/SVG
geometry; it does not independently observe compositor presentation. A preceding
action can have raster work still in flight, even after these checks, and that
work can block a later action's compositor commit. Investigate task/frame
provenance before attributing the entire overlapping task to the new action.
The retained protocol and its checks remain unchanged during such diagnostics.

In the original retained interaction protocol (raw schema 1), the test awaits Playwright's trigger
completion before invoking the browser's settling loop. The recorded interval
therefore includes that automation completion wait as well as browser work and
subsequent stable frames. It does not independently identify the earliest visual
readiness time. A bounded follow-up trace locates the dense card-selection
residual before settling starts; see the historical results' diagnostic section.
That diagnostic does not explain the unfavorable card-selection observations in
the completed corrected comparison.

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

The effective tree hash covers `frontend/src`, `fixtures` and `package-lock.json`.
The harness hash covers its browser entry, workload generators, specification and
standalone build/test/TypeScript configurations. Imported configuration and
research data outside that tree are fingerprinted before/after each current run.
The historical `benchmarks/atlas-browser-d686-imported-source-manifest.json` binds
only its earlier comparison. The current evidence index
records raw report locations and checksums; unchanged hashes alone do not claim
that every repository file was measured.

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
