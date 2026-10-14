# Application Atlas — Phase 3 findings and actions

2026-10-14. Phase 2 is committed locally as `12392db` on `codex/atlas-phase-2`. Phase 3 is committed locally on `codex/atlas-phase-3` in the attached `atlas-phase-1` worktree. No push, PR, merge or publication was performed.

## Delivered

- The default Details inspector now shows evidence-derived findings: fabric drops, unknown or ambiguous owners, no permitting contract, inferred backends, and stale/unavailable source evidence after a live pipeline-health check. The pure helper reuses existing glossary and health rules, keeps stable references, and does not mutate the graph.
- Findings and selected edges offer **Open in Search**, **Copy request**, and **Show path** when their evidence supports the action. Request CSV includes actual addresses, port, direction, policy, ACL action and evidence, with existing spreadsheet-formula protection. Clipboard failures are explained. Inferred-backend paths select their collected conversation and backend through the existing candidate-path builder.
- Evidence links accept strict IPv4/IPv6 literals, integer ports 1–65535, TCP/UDP/SCTP, lowercase hexadecimal trace/span identifiers, and ordered bounded integer epoch windows. URLs are built with `URLSearchParams`, preserving locale and deployment root. Only validated evidence macro calls can be emitted; arbitrary SPL and appended commands are rejected.
- New read-only `adm_flow_evidence` queries stored conversation summaries for the exact tuple; `adm_trace_evidence` reads actual OTel spans. Both validate arguments on the server. Searches retain the Atlas app namespace because its macros are intentionally not globally exported. Flow searches disclose that matching records can span observation scopes; traced calls open the first collected trace in the displayed window.
- Demo findings reuse the existing captured ACI/NXOS macro fixtures. Synthetic Search actions are disabled with an explanation. Missing/multiple addresses, unknown direction, invalid references and unsupported transports prevent an exact evidence search. No invented evidence fixture or live search success is shown.
- The standard dashboard panel boundary remains in place. On narrow screens, default findings sit below the map; selected details use the existing overlay.

## Verification

| Command | Result |
| --- | --- |
| `npm run lint` | Passed. |
| `npm test` | 283 passed across 23 files, including 30 findings/drilldown checks. |
| `npm run package` | Passed; one archive and checksum. |
| `python3 tools/check_release.py --dist dist` | Passed. |
| `npm run test:browser` | 18 passed: findings, CSV clipboard, inferred-backend paths, exact flow/trace links, source-health navigation, narrow-screen access, and existing scope/theme/routing checks. |
| `npm run typecheck:browser` | Passed. |
| `ruff check tools tests` / `ruff format --check tools tests` | Passed. |
| `python3 -m unittest discover -s tests -p 'test_*.py'` | 158 passed. |
| Python 3.11 AppInspect Cloud precert | Python 3.11, AppInspect 4.3.1: 0 failures, 0 errors, same 5 warnings; `python3 tools/check_appinspect.py dist/appinspect-cloud.json` passed. |
| Locked full Splunk 10.6 lab suite, macro equivalence/injection and actual viewer popup | 176 ran in 1,230.669 seconds: 175 passed; the new flow-comparison test selected a partial summary row without `client_ip` and errored. All viewer, trace and server-rejection checks passed. The corrected evidence suite passed in a fresh lab: 4 tests in 3.539 seconds. |

Demo screenshots were inspected in dark and light themes. Independent review caught and verified fixes for conversation action rendering, private macro namespace, nested deployment-root URLs and actual viewer fixture selection. The source-health finding text distinguishes missing evidence from a confirmed outage and explains its app-wide scope.

The full-suite run itself was not completely green: the new test initially chose a retained summary row that had a port/protocol but no endpoint addresses, causing `KeyError: client_ip` before calling the macro. Its selection now requires both addresses, matching the macro’s exact-tuple contract. No production search or assertion was relaxed. A fresh locked lab initialized the same TA-shaped fixtures and passed all four evidence tests. The existing supervisor alert-tracking case that timed out in Phase 2 passed in this full run.

The full lifecycle used `ADM_LAB=1 python3 tools/lab_lock.py --root . -- python3 /tmp/atlas-phase3-lab.py`, running `tests/splunk/lab.sh up`, `tests/splunk/lab.sh install`, and `ADM_LAB=1 ADM_UPGRADE_PACKAGE=dist/splunk_adm-0.2.0.tar.gz python3 -m unittest discover -s tests/splunk -v` before cleanup. The focused lifecycle used `ADM_LAB=1 python3 tools/lab_lock.py --root . -- python3 -u /tmp/atlas-phase3-qualify.py`; after fixture initialization, `python3 -m unittest tests.splunk.test_drilldown -v` passed, then the driver purged its owned resources. Both drivers refuse an existing lab container and hold the cooperative lock throughout.

## Limits

Live Splunk Cloud runtime and formal Cloud vetting remain unverified. The final Atlas bundle is 2,081,110 raw / 515,253 gzip bytes, above the original 350 KB gzip comparison budget from Phase 2. Both owned lab lifecycles were purged successfully, including containers, volumes, image, secrets and the temporary research link. Ephemeral viewer accounts/roles were cleaned up by the harness. No user decision is required.
