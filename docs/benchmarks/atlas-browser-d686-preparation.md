# Accepted-main browser benchmark preparation

Preparation is complete. The subsequently authorized full corrected comparison
against committed candidate `8813eb5` is in
[accepted-main results](atlas-browser-d686-results.md). The bounded smoke record
below remains correctness-only evidence.

Accepted baseline: `d6863dd326099acb892e1eebaa6c43d4f4410947` in the clean
isolated baseline checkout. The earlier `510754c`/`7999d3a` comparison and its
original automation-inclusive interaction numbers are preserved as historical
evidence, superseded for current acceptance. The corrected interaction protocol
is implemented at `400c681`.

## Fixture inspection

All four imported graph fixtures and their arguments matched byte-for-byte
between the accepted baseline and integrated candidate during preparation.
Captured graph sizes remain ACI 25/33, NXOS 21/24, Catalyst ACI 25/36 and Meraki
NXOS 21/23 nodes/edges. Captured topology remains 18, 15, 64 and 64 rows.
Catalyst retains 3 attachment, 3 traffic and 8 handoff records; Meraki retains
2 attachment, 2 traffic and 1 handoff record.

Recapture timestamps and provenance changed. The controlled Cisco generator
derives its epoch from each captured meta row's `window_start`, so it follows the
new window deterministically. No harness count, identity, warning or export
expectations required changes. The Catalyst near-limit workload still contains
500 nodes/2,000 edges, 412 authority-qualified clients, 2,853 attachment records,
4,278 unique traffic records, 317 handoff records and 1,337 topology rows.

## Bounded correctness verification

- Readiness helper checks: 8/8 passed.
- Catalyst captured and near-limit smoke: 2/2 cases passed against each checkout,
  four measured samples per source plus discarded warmups.
- Full graph/evidence export equality, every CSV record, finite geometry,
  authority ambiguity, complete/partial/unresolved handoffs, reference-cap
  disclosure and committed-DOM readiness assertions remained enabled.
- Source and harness hashes stayed unchanged within each smoke. Both used
  harness `95506ec1e1a812ad1629136486e6776342711549496b4e0beff9efe0bf306fb6`
  and identical workload fingerprints.
- The candidate smoke used the integrated working tree at HEAD `400c681`, before
  the coordinator's integration commit. Its effective source-tree hash was
  `65847e91461b32039123e36da921efadc1d8c4c415b13180a822ad9ac50799da`;
  the accepted baseline hash was
  `44d013c9d234acbc4e530bea6f5586af2cc32f0d16c68312311783f6dd773a93`.

Other frontend/build/Splunk verification could run concurrently. These are
correctness smoke artifacts, **not comparative performance evidence**. At the
end of preparation no full corrected matrix had run. No acceptance issue was found
in this bounded preparation; it does not replace the final full matrix.

```sh
node_modules/.bin/playwright test --config tests/performance/readiness.config.ts
ADM_PERF_SOURCE_ROOT=<baseline-or-integrated-checkout> \
  ADM_PERF_OUTPUT=dist/performance/atlas-browser-d686-<role>-preparation-smoke.json \
  ADM_PERF_REPETITIONS=1 ADM_PERF_SCENARIOS=catalyst-aci \
  ADM_PERF_SIZES=captured,near-limit \
  node_modules/.bin/playwright test --config tests/performance/playwright.config.ts
```

The evidence index records exact raw/log paths, fixture inspection data,
checksums and source metadata under `acceptedMainPreparation`.

## Final artifacts

The coordinator froze and committed candidate `8813eb5`, the supplemental
imported-source manifest was refreshed, owned lab/local CPU checks were paused
and the full matrix was explicitly authorized. These distinct names were used
so historical evidence was never overwritten:

- `dist/performance/atlas-browser-d686-baseline-retained-v2.json` and matching log.
- `dist/performance/atlas-browser-d686-integrated-candidate-retained-v2.json` and
  matching log, with its actual final commit embedded in raw metadata.
- `docs/benchmarks/atlas-browser-d686-comparison.md` and `.summary.json`.
- `docs/benchmarks/atlas-browser-d686-results.md`.

Both completed final runs used the same full 14-case matrix, five cold/five warm
samples plus discarded warmups, frozen corrected harness and matching input
fingerprints.
