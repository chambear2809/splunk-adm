# NetFlow qualification trial — 2026-10-31

The approved trial was applied to the shared UCS group `vpc-1-21-UCS-FI` and stopped early by its runtime completeness guard. The original IPv4 monitor relation was restored and independently verified. The full six-minute observation window did not complete. No permanent attachment or second-group change was made.

## Execution and restoration

APIC initially rejected the trial description text with HTTP 400/code 801. Both rejected attempts were read back as not applied. A reviewed metadata-only revision used a short description containing the same transaction nonce; the record, monitor and trial relation were then created successfully. Monitoring scope, match fields and restoration operations were unchanged.

The complete configuration reads and expected-state transitions passed. Operational verification of the group subtree reported `totalCount=27` but returned 26 objects. The executor retained the count check and restored the original relation. A read-only follow-up reproduced this discrepancy even with all properties requested. Exact-DN reads returned complete one-object results; a narrower runtime verification contract still needs review before another deployment.

Independent replay verified all six intent/confirmation transitions, both complete group trees against their original baselines, the exact original IPv4 relation attributes, and absence of the trial group relation. Only the approved trial record, monitor and the monitor's two child relations remain. Their deletion is deferred because global reverse-reference absence has not been qualified.

The reviewed R6 plan SHA-256 is `d36c5716d0fc42eecd08f7ac766ed15bb222adca8331c1cfc6cca19f5b3a7f40`. Its executor, state engine, diagnostic capture and watcher passed independent review and 25 focused offline tests. R5 source and both rejected-attempt receipts were preserved.

## What the Stream data establishes

The finite diagnostic search selected native event times from 22:42:16 UTC to before 22:43:17 UTC, with a fixed index-receipt cutoff. The native search completed with matching returned counts, no finalization, reported event truncation or drops, and no warnings. It returned 720 actual Stream records through the existing TA/collector route. These are diagnostic records, not distinct conversations or a qualified path.

| Check | Result |
| --- | ---: |
| Nonzero address pair and protocol fields | 706 records |
| Usable unicast source/destination fields | 700 records |
| TCP/UDP unicast tuples with valid nonzero ports | 698 records |
| Unique raw record contents | 360; each appears twice |
| Unique raw contents with usable TCP/UDP fields | 349 |
| Unique raw contents with usable tuple fields and non-inverted intervals overlapping the selected window | 321 |
| Unique raw contents with usable tuple fields and non-inverted intervals wholly inside the selected window | 269 |

The baseline diagnostic sample had zero nonzero address pairs/protocols. The selected post-trial sample contains useful tuple fields absent from the baseline sample; causality is unqualified. This does not establish a qualified physical device path or complete six-minute comparison.

All native event times match raw `endtime`. The raw `timestamp` is currently interpreted as a separate start-time field; that source semantic still needs qualification and must not be treated as interchangeable with native event time. Fifty-eight record rows have raw start times later than end times by up to one second; 56 otherwise field-usable TCP/UDP rows are affected. Do not silently correct or admit these intervals. Exporter-clock authority remains unqualified. Index receipt time has integer-second resolution and must be evaluated with that granularity.

Identical raw content appearing twice has not been traced to a cause. Raw-content uniqueness is not a qualified deduplication identity or conversation count. Preserve source/exporter/sequence/record provenance before deriving traffic metrics.

Both exporters report observation domain 1. Usable tuples also carry VLAN 341 and one of two interface indexes. These are source fields, not yet trusted fabric, VRF, interface or application bindings; domain 1 is not a globally unique routing identifier.

## Health and remaining work

Post-restoration native exporter diagnostics showed no increase in drops, destination-unreachable or buffer errors. All eight TeaStore deployments, including the load generator, and the modified cluster receiver reported one ready replica each.

The collection path remained the existing Stream TA/collector; no synthetic flow records or recurring custom collection script were introduced. The temporary operator tools only applied the reviewed change and captured one-shot qualification diagnostics.

Next work is to qualify the narrower operational read shape, trace duplicate content and interval semantics through the TA, and establish trusted exporter/domain/interface/VLAN-to-routing-domain bindings. Continuous workload and host ownership evidence is still required before application-to-device joins. The existing finite Pod interval producer also needs migration into a reviewed native collector component before it can be retired.

Protected raw results, journal, state, exact artifact hashes and independent review receipts are retained under `~/.splunk/labs/atlas-deployment/20261031-device-path/`, principally `apic-trial-reviewed-artifacts-v6.private.json`, `apic-trial-v6-final-readback.private.json`, `apic-trial-v6-flow-independent-review.private.json` and `apic-trial-v6-after-restoration-health.private.json`. They contain lab evidence and are not checked into the project.

**Qualification scope: usable tuple fields observed; cause, ownership, routing attribution and observed traversal remain unqualified.**
