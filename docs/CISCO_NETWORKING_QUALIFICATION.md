# Cisco networking qualification status

## Current qualification record

The Catalyst Center and Meraki integration is an optional, source-scoped enrichment for Application Atlas. The authorized execution boundary for this work is the isolated local Splunk Enterprise lab with TA-grounded synthetic events. Vendor packages were downloaded, checksummed, and inspected statically; no vendor input scripts were executed as part of that inspection.

An earlier deployment-shape check passed against the isolated standalone Splunk Enterprise 10.6.0.5 target over TLS, with SHC explicitly disabled and no remote peers. After replacing the lab TLS certificate and restarting, the first requalification attempt failed the unchanged standalone-shape guard; a subsequent verified TLS request passed. The initial failure cause is not established. The migration helper and pure regression suite are implemented, with passing local disabled-origin stage/cutover/rollback and enabled-origin missed-window recovery runs. Vendor packages were publisher/checksum verified and statically inspected; their input scripts were not executed. Interim AppInspect reported zero errors, zero failures, and five warnings.

The local synthetic lab can check parsing, mapping, history, and display behavior for documented event shapes. It does not establish actual Catalyst Center or Meraki API collection, a tenant’s effective API permissions, real exporter-template decoding, production traffic coverage, or behavior at the intended scale. No customer, SHC, or Splunk Cloud deployment is qualified.

The current positive SD-WAN scenario preserves flow-level overlay session references for investigation. It does not derive router or tunnel topology, and TLOC option-envelope parsing and correlation are unsupported. Do not interpret the retained references as validated topology or use them to infer a TLOC relationship.

## Qualification gates

All deployment gates remain open until evidence is collected and reviewed for the intended target:

- [ ] Actual Catalyst client collection from the target controller with sufficient read permissions, representative raw events, stable event-time handling, and an observed poll/checkpoint history.
- [ ] Actual Meraki association-event collection for the target organization and networks, verified account access, actual optional-field coverage, interval validation, retention limits, pagination behavior, duplicate behavior, and late-event gaps.
- [ ] Explicit, unambiguous source-authority and routing-domain profiles for each source, with no cross-organization or cross-cluster fallback. Ambiguous, stale, missing, or conflicting evidence must remain unresolved.
- [ ] Raw-field schema validation against real events. Native vendor field names must remain distinct from CIM claims unless separately mapped and validated.
- [ ] Source-history qualification across moves, replay, restart, partial pagination, outages, and bounded retention. Do not imply continuity across missing intervals.
- [ ] Stream Forwarder 8.1.7 compatibility on Splunk Enterprise 10.6. The available compatibility listing reaches 10.5; verify the supported deployment placement and qualify the selected IPFIX template before relying on Catalyst SD-WAN traffic.
- [ ] Supported deployment qualification for distributed Enterprise, search head clustering, checkpoint/state persistence, upgrades and rollback. The local standalone deployment-shape check is not this gate.
- [ ] Splunk Cloud support and operational behavior, if Cloud is in scope.
- [ ] Production capacity, request pacing, index volume, search cost, and failure recovery at the intended scale.
- [ ] Independent review and target-environment evidence captured before promoting beyond draft PR status.

## Full local integration suite

The complete local Splunk suite passed 308 tests in 2,160.603 seconds, with zero failures or errors and one intentional migration opt-in skip (`dist/cisco-full-splunk-final-v24.log`). The destructive migration path was exercised separately for both recorded origins. This run includes native browser, permissions, source handling, topology, history, recovery, and archive upgrade/rollback checks. Legacy and combined Cisco fixtures were recaptured from the implemented pipeline; all 22 fixture checks passed. The refreshed package passed 18 upgrade checks (including three live checks) and the AppInspect error/failure gate. After lab cleanup, all 398 Python tests passed; frontend checks passed 459 unit tests and 69 browser tests.

## Local permission and topology evidence

Four restricted-viewer checks passed, including full topology row parity with the administrator and denied protected writes/dispatch. The combined fixture deliberately retains two unresolved ESXi `vmnic2` LLDP peers: Kubernetes host inventory cannot establish these hypervisor identities. Their links remain absent. The expected topology metadata reports incomplete inventory links, unresolved LLDP host matches, and uncorrelated Nexus Dashboard fabric labels; these warnings are not suppressed.

## Search invocation regression

The V2 graph-input and topology macros now preserve the same implicit-search contract as their V1 public counterparts. The browser search client supplies the initial `search` command; explicit pipeline callers use `| search`. Restricted-viewer coverage compares both forms for each application graph and topology. An independent Astra static review found no actionable issues in this fix. The migration unit suite passed 123 checks after the scheduling-alias, search-metadata recovery, strict SID reconciliation, bounded artifact-reader, and scheduler job-list identity corrections. Independent Astra review closed those findings; both local migration origins have passed with the diagnostic retention limitations below. Static networking checks, frontend lint, build, and packaging completed. Live browser and migration qualification remain separate gates; static review does not establish their results.

## Native browser evidence

The restricted-viewer browser check passed for both TA-grounded synthetic paths, with no demo fallback and normal browser shutdown. Catalyst → ACI returned 25 nodes and 36 edges; Meraki wireless → NX-OS returned 21 nodes and 23 edges. Reload preserved those counts. Both paths exposed attachment devices and live Find evidence. Meraki displayed association-based attribution and the SSID number without inventing an SSID name. See [recorded browser evidence](benchmarks/cisco-networking-native-browser.json). This validates the local synthetic pipeline and UI, not collection from real devices.

## Package upgrade and rollback evidence

The local archive tests passed against the 0.2.0 baseline and 0.3.0 candidate: 15 unit checks and three live checks covered archive update, lookup migration, and archive rollback. These checks preserve local saved-search configuration and restore the candidate after an interrupted update. They are separate from the V1-to-V2 data-contract migration gate below.

## Live migration dispatch finding

The first nonempty live backfill prepared 59 expected conversation records, then Splunk returned HTTP 400 when dispatching the disabled V2 saved search. No writer SID was returned; the journal records a known rejection. Readback confirmed the V1 and V2 writers remained disabled. Splunk documents that [disabled saved searches cannot run](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.2/configuration-file-reference/10.2.8-configuration-file-reference/savedsearches.conf). A journaled temporary manual-execution state, with scheduling disabled and exact configuration restoration, is implemented and independently reviewed. Live resumption verified 59 conversation and 39 traffic records against persisted copies, and completed history and catalog staging. Public-surface validation then exposed an inconsistent manifest: conversation evidence required traffic-only fields. The stopped journal was retained unchanged after live reconciliation confirmed the original configuration, restored temporary writer states, no active or ambiguous jobs, and no cutover. The corrected manifest was tested with a fresh journal that captured the existing staged data as its baseline. A separate read-only live probe passed all 14 public result contracts, including mixed graph/topology row types and nested traffic observations. The subsequent disabled-origin run passed staging, scheduled-cycle validation, public cutover, and rollback; the separate enabled-origin run subsequently verified missed-window recovery.

## Versioned migration status

The helper stages `adm_summary_v2`, additive `adm_network_client_history`, and separate `adm_app_catalog_v2` while retaining v1 readers and data. It validates bounded source coverage and complete readbacks, then requires scheduler-owned, log-confirmed contiguous writer cycles through an independent observation boundary and public wrapper smoke results before selector changes. The helper also has a bounded enabled-origin rollback path that resumes V1 first, verifies raw-source retention, fills missed windows, and compares stable IDs and material summary rows before restoring public selectors. The disabled-origin path passed the resumed local synthetic run (`dist/cisco-disabled-migration-live-v22.log`, two tests, 204.220 seconds for the successful resumption). The original configuration was restored. Four existing scheduler job artifacts were retained for 7,200 seconds during diagnosis, with exact SID and TTL readback; no replacement jobs were dispatched. The enabled-origin run also passed after session refresh and same-journal resumption (`dist/cisco-enabled-migration-live-v8.log`, two tests, 28.963 seconds for the successful resumption). It recovered one deliberately missed rollup with identical expected and retained fingerprints and restored the original selectors. Its first resumed V1 scheduler artifact was retained for 7,200 seconds with readback during diagnosis. A legitimate 74-second scheduler dispatch delay exposed an overly strict timestamp equality check; the correction retains exact scheduled time, SID, bounds and success validation while accepting dispatch within the observed interval. No distributed, Cloud, or general automatic history recovery qualification is claimed.

The successful disabled-origin resumption is recorded in `dist/cisco-disabled-migration-live-v22.log`. Its retained journal uses bounded secure immutable external result artifacts after the v19 journal exceeded the 16 MiB limit. The earlier result-artifact unit log records 121 passing tests (`dist/cisco-result-artifact-unit-v3.log`); the current migration suite records 123 (`dist/cisco-scheduler-identity-unit-v2.log`). Job-list identity now comes from `content.sid`, with the REST URL identifier checked separately, because observed `entry.name` values contain search text. The phase-aware upgrade harness records 10 runs with one opt-in skip (`dist/cisco-upgrade-harness-unit-v2.log`).

## AppInspect warning review

The refreshed-fixture archive passed the automated error/failure gate with five warnings and one skipped check (`dist/cisco-appinspect-v28.json`). Its exact hash is recorded with the upgrade evidence. Later qualification-document updates require the normal package/CI checks; they do not change runtime files. This is not Cloud acceptance.

| Check                                  | Finding and disposition                                                                                                                                                                            |
| -------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `check_for_python_script_existence`    | Python files trigger the generic Python compatibility review. Runtime checks target the selected Splunk 10.6 standalone lab; this warning does not establish compatibility with other targets.     |
| `check_custom_conf_replication`        | Custom configuration has no SHC replication declaration. SHC placement and replication remain unqualified; do not enable standalone recovery on SHC.                                               |
| `check_collections_conf`               | KV Store collections are present. Replication and permissions require target-specific validation.                                                                                                  |
| `check_python_sdk_version`             | Bundled SDK 2.1.1 is flagged as outdated; the checker recommends 3.0.0 or later. SDK compatibility and an upgrade remain an open release review item.                                              |
| `check_hostnames_and_ips`              | Reported values include synthetic fixture addresses and the Splunk version string. These are example/test values, not customer endpoints; review the complete final-archive report before release. |
| `check_for_valid_package_id` (skipped) | No `app.manifest` is present. The skipped check is not evidence of a validated package identifier.                                                                                                 |

## Evidence references

- [Cisco integration contract](../research/cisco-integration-contract.json)
- [Catalyst package evidence](../research/cisco-catalyst-evidence.json)
- [Meraki package evidence](../research/cisco-meraki-evidence.json)
- [Package versions, provenance, and checksums](../research/package-manifest.json)
- [V2 staging, cutover, and rollback procedure](CISCO_CONTRACT_MIGRATION.md)
- Standalone TLS deployment requalification passed on retry after restart (`dist/cisco-tls-requalification-v2.log`); the initial failed attempt is retained in `dist/cisco-tls-requalification.log`.
- [Operator handout](operators/cisco-enterprise-networking.md)
