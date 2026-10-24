# Five-source supplemental evidence candidate qualification

## Candidate identity

- Task branch: `codex/atlas-five-evidence`.
- Tested source commit: `5770e1cd0ca874e7614598e5a2c9e0b9a40882ec`.
- DNS prerequisite commit in its ancestry: `738cb916770b3c9eb6946e716c21e7194d9d1a92`.
- Package: `dist/splunk_adm-0.4.0.tar.gz`, SHA-256 `23d94926d42136e304c16dcd90628a5997cb17f058468799319d3347e3cb78e6`.
- Installed target: task-owned `adm-atlas-five-evidence` disposable Splunk Enterprise 10.6.0.5 lab. No production deployment or source collectors were changed.

This record covers the exact commit and package above. The synthetic source fixtures and direct HEC ingestion checks establish adapter and Splunk runtime behavior only; they do not qualify live producers, collection paths, tenant dimensions, or production capacity.

## Completed checks

| Check | Result |
| --- | --- |
| Frontend Vitest | 736 passed |
| Browser Playwright | 110 passed |
| Non-lab Python unittest discovery | 647 passed |
| ESLint, TypeScript, browser TypeScript, Prettier | Passed |
| Ruff check and format, `git diff --check` | Passed |
| Frontend/package build, release archive verification, build tests | Passed; build tests 2/2 |
| Splunk AppInspect cloud precert | 0 errors, 0 failures, 5 warnings |
| Installed app `btool check` | Passed |
| Focused installed-app asset history | 7/7 passed |
| Focused installed-app AWS flow, Envoy, Observability health | 1/1, 1/1, 2/2 passed |
| Focused existing catalog regression | 16/16 passed in the task lab |
| Consolidated installed-app suite | 418 run in 2,399.963 seconds: 409 passed, 9 expected opt-in skips, 0 failures/errors |
| Independent integrated diff review | GPT-6 Astra/max; no remaining actionable findings after timestamp, browser-fixture and task-lab target fixes |

The final run used `python3.13 tools/lab_lock.py --root . -- python3.13 -m unittest discover -s tests/splunk -v` with `ADM_LAB=1`, the task-owned lab name/ports, and `ADM_LAB_PACKAGE` pointing to the exact archive above. The test process exited 0. The suite covered installed-app SPL, REST, UI/browser, permission, ingestion, recovery and regression cases together. Its 9 skips require separate explicit Cisco prune/migration, distributed search-head-cluster, or upgrade-package campaigns; none is a five-source acceptance case. Those unrelated campaigns were not run for this change.

The first combined lab rehearsal against the preceding archive `cd6a85b7df807ad7a7da4da85f50ec9f823ca8ddce243cefdc96a4e1ca448fac` exposed REST-formatted timestamps, direct HEC receipt-time assignment, custom lab-target assumptions in a Cisco helper, and a catalog fixture failure. The timestamp and helper fixes were checked in focused installed-app runs. The catalog suite passed in isolation and in this final combined run. That rehearsal is not counted as a passing gate for the final archive.

## Source-specific qualification boundaries

| Source | Implemented and locally exercised | Remaining external qualification |
| --- | --- | --- |
| Stream DNS 8.1.6 / Hubble DNS L7 | Endpoint-scoped resolution and failure inspection, answer timing and candidate names, with separate observed traffic semantics. The inherited DNS lab and browser checks run in the combined suite. | Transaction-level Stream configuration or Hubble L7 export, capture vantage, real request/response fields, clock agreement, access, and capacity. |
| Envoy v1.40.0 HTTP terminal access JSON | Separate reported downstream/upstream legs, selected remote backend, bounded scope and producer-time agreement. Direct HEC test supplies envelope `time`. | Actual Envoy logger/sink configuration, missing-upstream/retry samples, per-observer scope, access, and production timestamp extraction. The HEC test does not exercise parsing-tier `TIME_PREFIX`/`TIME_FORMAT`. |
| AWS VPC Flow Logs v5 fixed 29-field custom format | Scoped account/Region/VPC/interface aggregate flow status and action with strict event-time agreement. Direct HEC test supplies producer `start` as envelope `time`. | Real custom-format delivery, parsing-tier timestamp assignment if used, clock/delivery delay, viewer access, and historical ENI-to-resource bindings. No current-only ENI attribution. |
| Versioned CSV/JSON asset history import | Historical intervals, current-only snapshots, retirement and conflicting scoped owner candidates. Import output is deterministic HEC NDJSON. | Completeness and authority of actual CMDB/IPAM exports, explicit retirement semantics, retention, freshness, and production ingestion. |
| Splunk Observability Cloud SignalFlow export | Server-side bounded export of exact custom APM MMS request/error/p90 and optional runtime signals; completed capture and identity fields are checked in Splunk. | Live realm/API query and `sf_mms_id`, required dimensions and units, approved token delivery, collector scheduling, and source-product drill-through. Detector alerts are not queried. |

No source is automatically enabled by this package. Routing scope is attribution context, not a permission boundary. Empty or denied optional searches remain unknown, and the supplemental sources do not alter core conversation totals or turn inventory, health, DNS, or flow status into a proven application dependency.
