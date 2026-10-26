# ThousandEyes qualification

Implementation status: optional evidence, unselected and unqualified by default.
**Production qualification is not granted.** The reviewed Cisco package is
0.9.0; package inspection, synthetic tests, AppInspect and a merge do not prove a
live producer, supported deployment or complete history.

Baseline: `1e4f2043ffc095ed0d87a090f572178bd204b134`.
[PR 23](https://github.com/chambear2809/splunk-adm/pull/23) is the delivery record
for final candidate SHA, gate outcomes, archive hashes, independent review and
merge status. Use its final head and retained evidence, rather than treating a
static document as approval of a later revision.

## Coverage and acceptance

The [design](THOUSANDEYES_DESIGN.md),
[capability matrix](research/thousandeyes-capabilities.md), and
[operating constraints](research/thousandeyes-operating-constraints.md) record
exact producer fields, units, versions, unsupported combinations and workflow
boundaries. All rows below require genuine target qualification before enabling
the corresponding family.

| Capability and user question | Implemented behavior and acceptance files | Qualification boundary |
| --- | --- | --- |
| Network, HTTP and DNS: did the identified test reach its target? | Typed native measurements, failures, missing values, units and intervals; adapters/attribution tests and installed exact raw query | Emitted layers, HEC envelope, clocks and historical bindings must be verified |
| Page, transaction and API: which synthetic step failed? | Typed metric and span detail, source outcome and hierarchy; adapter and panel tests | API trace support conflicts across Cisco documents; keep that combination unqualified pending real readback or Cisco confirmation |
| BGP: what did a monitor report? | Monitor identity and measurements remain source context without a fabricated agent, test or application binding; BGP fixture and installed query | BGP is not an agent-to-application probe; it was not included in the local timing benchmark |
| Voice and endpoint: what did the selected producer measure? | Known metric/unit contracts and explicit test domains; strict parsing and attribution tests | RTP packet-delay variation units remain unresolved; Endpoint Local Network is excluded by the 0.9.0 app filter |
| Paths: which route did this probe round report? | Ordered measured hops/iterations, native times, missing-hop uncertainty and source provenance; path tests and panel | Anonymous CEA vendor rows cannot establish test identity. Optional exporter adds request identity and retrieves hop detail; live API, parsing-tier truncation and indexed readback remain unqualified |
| Events, alerts and activity: what lifecycle/change did ThousandEyes report? | Separate native lifecycle and audit context, IDs and completeness; six-family fixtures and installed query | No inference of complete incident history, infrastructure change history or health from silence |
| Application, endpoint and SaaS/API investigation | Explicit authority, scope, target and historical configuration bindings; existing observed dependency selection, without creating edges/counters; attribution, browser and regression suites | Shared addresses, proxy/NAT/CDN targets, configuration changes and IP reuse retain uncertainty |
| Branch/site/agent and before/after validation | Agent/location filters, native interval grouping, compatible scalar means and blockers; comparator/panel tests and benchmark | Failed or excluded readings prevent biased means. Unknown producer-version continuity is disclosed; no causal network-change claim |
| Selected segmentation path | Agent-to-target protocol/port/location/time evidence alongside the selected Atlas context | A successful probe validates only that covered path and interval, not universal policy correctness or another connection's route |

## Reproducible local gates

- `npm run lint`, `npm test`, `npm run typecheck:browser`, and `npm run test:browser`.
- Pinned Ruff 0.13.2 check/format, Python unit suites, distributed-interface tests
  and upgrade static tests, with the pinned optional SignalFlow runtime.
- `npm run package`, `tools/check_release.py`, packaged bundle tests, AppInspect
  4.3.1 Cloud precert and `tools/check_appinspect.py`.
- Task-owned Splunk 10.6.0.5 lab under a lifetime `tools/lab_lock.py` lock,
  installing the retained exact archive. Run the full applicable suite, real
  baseline upgrade/rollback, and dedicated `test_thousandeyes.py` with
  `ADM_LAB=1 ADM_THOUSANDEYES_LAB=1` when the optional search-time TA is present.
- `tests/splunk/thousandeyes-browser.mjs` verifies actual packaged main/optional
  assets, no eager source dispatch, matching asset versions, viewer access,
  seven synthetic observations and monitor-only context. Its outcome belongs to
  the exact installed candidate record; the development harness is separate.
- `tools/benchmark_thousandeyes.mjs` measures local builder/parser/attribution
  costs and query text size with exact source hashes. It does not execute SPL
  or measure HEC throughput, index scans, distributed search or tenant scale.

The main bundle retains its existing 670 KiB gzip ceiling. The explicitly
loaded ThousandEyes asset is bounded to 48 KiB gzip, with a 16 KiB raw CSS limit.
The operator guide records the measured local envelope and its limitations.

## Compatibility and external gates

The unmodified Cisco TA 0.9.0 co-install reports `btool check` exit 1 on the lab's
Splunk 10.6.0.5: `default/app.conf:27`, `[triggers] notable_event_actions=reload`
is an invalid key. Static inspection also found the trace response-time EVAL at
`default/props.conf:45` missing a closing parenthesis. No vendor file is patched.
An Atlas package gate or raw-field query pass does not establish clean vendor
compatibility. Retain the failed diagnostic and qualify a supported vendor/target
combination before enabling the source.

Remaining production gates include sanitized received payloads for every enabled
family, actual account/account-group mapping, native and outer HEC timestamp
basis, deployed ingestion/readback, event/history completeness, supported
version/runtime compatibility, parsing-tier props and a path event over 10 KiB,
credential/role review, actual API quotas/retention, realistic search/ingest cost,
and each claimed Cloud, distributed or SHC topology. The exporter is mock-tested;
no live Cisco API call, paid test, alert/collection change, production deployment
or AWS/customer mutation is part of this delivery.

## Evidence, review and lifecycle

The ignored `dist/thousandeyes-qualification/` record contains commands and
outcomes, original failures and corrections, package and source hashes,
AppInspect/bundle reports, screenshots, benchmarks, model assignments and the
task-resource ledger. Preserve its sanitized packet outside a worktree before
archiving that worktree. CI-skipped licensed-lab checks are not installed proof.

The verified coordinator is `gpt-6.1-sol / medium`; all six workstreams use
`gpt-6-luna / max` per the user's correction. The independent read-only reviewer
is `gpt-6-astra / medium`. Metadata verification retains these assignments, not
unrestricted transcripts or secrets. Project-wide model preferences are unchanged.

Review remediation covers comparison cohorts/round eligibility, native query
admission and SPL typing/quoting, empty-page pagination and producer-version
provenance. Final review must bind to the delivered candidate after affected
checks pass. Conditional safe-disabled assessment does not confer production
qualification or substitute for hosting-platform approvals.

Disable by unselecting ThousandEyes, setting qualification to `0` and restoring
the placeholder selector; cancel active inspections. Roll back Atlas and its
configuration separately from the Cisco app and exporter. Preserve indexed
history and private delivery spool. Removal/reinstall and task-resource cleanup
follow the [operator guide](operators/thousandeyes.md) and the final ledger.
