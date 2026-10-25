# Optional integrations qualification

This qualification covers Application Atlas 0.5.0 against baseline
`b8f05490f3df8352ff88f9b803ca39d7df3a14d5` (0.4.0). New sources remain
unselected and schema-unqualified by default. No live/customer collector,
Observability organization, Controller, processor or production configuration
was activated. AppInspect precertification is not a Cloud certification claim.

## Qualification matrix

| Workstream | Implemented and offline tested | Installed Splunk evidence | Real source / processor |
| --- | --- | --- | --- |
| Historical health and durable HEC delivery | Five original signals; scheduled contiguous captures; stable new record IDs with legacy v1 reader compatibility; bounded private spool; crash/replay, corruption, exhaustion, mode drift, strict JSON, TLS and cancellation checks | Actual verified TLS HEC transport, Enterprise acknowledgment and separate indexed readback; legacy and new health captures through the exact Atlas SPL/normalizer | Observability realm, custom MMS dimensions/units/resolution and production delivery topology remain unqualified |
| Detector event history | Selected detector IDs; REST v2 pagination; inclusive millisecond event times; raw lifecycle/dimensions; explicit empty completion; exact replay/conflict handling; documented 10,000-event source ceiling fails closed; <=9,999 events plus completion; 64-row inspection cap | Indexed complete/empty/partial/conflicting/replayed captures through the exact Atlas query and normalizer | UI-created, API-created and AutoDetect origins each remain unqualified; no historical incident-state reconstruction |
| AppDynamics | Documented Application Model XML collection, OAuth, verified bounded HTTPS, safe backend properties, complete current snapshots, node-IP Asset History and backend candidates; no retirement/name joins/core traffic edges | Synthetic official-shape XML collection → validation/import → HEC → exact Atlas query/normalizer and existing current-only asset path | Live Controller versions/deployments and property availability remain unqualified; checked SaaS API documentation is 26.10.0 |
| Edge Processor / Ingest Processor v1 | Four SPL2 templates; separate transport/fallback/destination profiles; strict fixtures and golden semantic checks (42 NetFlow facts, five health metrics plus completion, explicit nulls, outer HEC fields fixture) | Direct/golden expected representations compared with installed Stream TA and Atlas searches | Neither processor runtime was available or executed. Product preview, persistence, fallback/counters and indexed equivalence remain mandatory; profiles are unqualified and disabled |
| Product navigation | Validated tenant/realm origins, visible/copyable exact identity/time/native IDs, manual APM/infrastructure/logs/detector/incident navigation and reciprocal APM Data Link instructions | Frontend unit/browser checks; no external UI or tenant data-link setup was performed | Stable identity/time deep-filter URL formats were not documented and are not invented. Detector lifecycle incident IDs are not assumed to identify entries in newer cross-alert Incidents dashboards |

The processor compatibility descriptors cite Edge control planes on Enterprise
10.0+ or Cloud 9.0.2209+, and Ingest Processor on Cloud 9.1.2308+. These are
reviewed documentation constraints, not tested product-runtime versions.

## Local acceptance gates

| Gate | Runtime / result |
| --- | --- |
| Lint and frontend types | Node 22.13.0; ESLint, TypeScript, browser TypeScript and Prettier passed |
| Frontend unit | 68 files, 787 tests passed |
| Browser regression | Chromium / Playwright; 111 tests passed |
| Python unit | Python 3.13.14; 773 tests passed |
| Distributed contract unit | 125 tests passed; no live SHC runtime claimed |
| Upgrade offline discovery | 18 tests, 15 passed / three expected live-only skips |
| Python style | Ruff 0.13.2 check and format passed |
| Build / release | Both packages built; app release/archive checks passed |
| AppInspect | 4.3.1 on Python 3.11.15; Cloud precert: 246 checks, zero errors/failures, five baseline warning checks |
| Broad installed regression | 434 tests, 428 passed / six expected opt-in skips; prior UI archive, explicitly bound below |
| Final-archive fresh source / permissions / actual upgrade | 52 tests passed on the retained final archive in 437.359 seconds; includes native production-bundle browser, verified HEC ACK/readback, full permissions and genuine upgrade/CSV migration/rollback |
| Corrected optional-index permission probe | Passed on the final archive: viewer sees an allowed-index positive control, cannot read optional indexes, can read mapping fields and cannot write/delete mappings |
| Independent review / remote CI | Recorded against the final PR candidate; merge requires all mandatory checks to pass |

The installed topology is one disposable Splunk Enterprise 10.6.0.5 Linux
amd64 container, image digest
`sha256:9280f9ce267b212e5596aa1832cdfd3f9be886c378da35ebc87499323ee447a4`.
The Stream Wire Data TA is 8.1.6. Each worker was assigned its own container name,
ports, private secret file and cooperative lab lock. The final integration
lab was recreated before installing the retained exact candidate archive.
The private test CA verified the HEC certificate and IP hostname; production
collector/sender TLS verification was never disabled.

SignalFlow uses `signalflow-client-python==1.3.9` with the verified bounded SSE
transport. Tested dependency versions were urllib3 2.8.0, ws4py 0.6.0,
sseclient-py 1.9.0, certifi 2026.10.23 and six 1.17.0. This SDK and all external
collectors are distributed separately from the Splunk app. Unpacked-toolkit
smoke checks execute every external CLI and the actual processor validator
outside the repository; the validator reports `processors_executed=false`.

AppInspect's warning checks are identical to the baseline:
`check_collections_conf`, `check_custom_conf_replication`,
`check_for_python_script_existence`, `check_hostnames_and_ips`, and
`check_python_sdk_version`. Their presence is not relabelled as zero warnings.

## Artifact and revision binding

The final app runtime inputs were frozen at
`fec50c54333f07158821260a7babaa65bbe13302`. Final archive SHA-256:

`a1062823a03ecbfe48d17109d6e2481407c8a0c45639f73eeb15678a1b5f2acf`.

The broad installed regression run used app-input revision
`059e1e1db6e6a9a9f6339f8d7e3200d69af93c5a`, archive SHA-256
`87a0b160083b30bb92bc93c02dde0b11d65b0b803637199230870e99de7c6aa2`.
A later presentation-only fix separates detector alert-lifecycle IDs from the
independent newer Incidents dashboard. The app member-hash comparison verifies
that only `appserver/static/pages/atlas.js` and the `app.conf` build value differ.
The final archive receives fresh installed source suites, full viewer/admin
permissions and the genuine baseline upgrade/rollback tests, plus repeated
frontend/browser, release and AppInspect checks. Broad-regression and final-
archive outcomes are retained separately; they are not relabelled as one run.

The genuine 0.4.0 baseline archive SHA-256 is:

`91b1b81b0246122e9b8f44f3c0691e750f71b3b36592544a48c47ece024eccd2`.

The final Atlas IIFE measures 678,648 gzip bytes using the release check's
Python calculation; the hard ceiling is 686,080 bytes (670 KiB). The same
baseline source rebuilt with Node 22.13.0 measured 666,623 bytes. Growth is
12,025 bytes (1.80%); the modest ceiling adjustment is documented in the
[supplemental evidence contract](SUPPLEMENTAL_EVIDENCE_CONTRACT.md).

Exact commands, outcomes, archive checksums, AppInspect JSON, baseline report,
sanitized model metadata, runtime versions, review references and the resource
ledger are retained in ignored `dist/integrations-qualification/` and the
final preserved evidence packet. The external toolkit's checksum is in its
adjacent `.sha256` file and release evidence, avoiding a self-referential hash
inside its packaged qualification document. PR CI's skipped lab job is not
installed-app evidence.

## Models, limits and rollback

The user explicitly changed the requested settings to coordinator GPT-6.1
Sol/High, three GPT-6 Luna/Max workers, and independent reviewer GPT-6
Astra/Medium. Sanitized actual session metadata confirms these settings. The
replaced Astra/Max agent performed release preflight only. No shared agent
profile was changed. Review was read-only behavior within the effective
unrestricted task permissions, not a separate sandbox claim.

All real-source/processor checks above remain external gates. Follow the
[source guides and toolkit instructions](OPTIONAL_INTEGRATIONS_TOOLKIT.md)
before selecting or qualifying a source. Routing scope attributes evidence;
caller index permissions remain the authorization boundary. Neither HTTP
acceptance nor Enterprise acknowledgment alone proves complete searchable
evidence. Retries are at-least-once and may duplicate delivery.

Rollback stops external schedules/sending, preserves private captures and
pending state for recovery, unselects the affected source and clears its
qualification flag. Processor rollback restores the previously qualified
input/destination route. Existing indexed observations are retained under
operator policy. Core traffic, connection counts and graph identity do not
depend on these optional integrations.
