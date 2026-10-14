# Recovery claim insert gate — qualified on standalone Splunk

On October 14, 2026, the disposable standalone Splunk 10.6.0.5 lab completed
25 trials of eight concurrent insert attempts against the same KV Store key.
Every trial had one winner, seven HTTP 409 rejections, one confirmed harmless
search dispatch, zero losing dispatches, and an unchanged winning record.
There were 200 attempts, 25 winners, and 175 duplicate-key rejections in total.

This qualifies the insert-only claim primitive **on standalone Splunk only**.
It does not qualify search head clustering, cross-member races, or failover.
It is not evidence that the recovery action itself is complete or qualified.

The permanent regression is `tests/splunk/test_recovery_claim_gate.py`. It reuses
`tools/fault_pipeline.py::wait_kv_ready` (engine status and data read), then
waits for the new collection's own data endpoint. Only HTTP 409 counts as a
loser. Readiness or other environment errors are inconclusive and non-passing;
observed invariant violations are failures. The earlier attempt returned
initialization HTTP 503s and was inconclusive.

The successful run held `tools/lab_lock.py` through setup, installation, test,
and purge. The lab container, volumes, image, and generated secrets were removed.

[Structured per-trial evidence](2026-10-14-recovery-claim-gate.json) includes all
contender outcomes and dispatch SIDs. The test ran in 75.654 seconds.
