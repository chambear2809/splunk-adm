# Native automatic catch-up validation — failed

Fresh validation of commit `4be084b` on October 13, 2026 (America/New_York;
run timestamps below are October 14 UTC). Disposable standalone Splunk
10.6.0.5, freshly pulled and installed, with shipped app defaults and the
cooperative lab lock held through setup and the entire rehearsal.

```sh
python3 tools/scheduler_pipeline.py --reset-lab --recovery native --timeout 1800 --output dist/scheduler/native-validation.json
```

The output was copied from `dist/scheduler/` into `docs/benchmarks/` for durable storage.

## Result

**Native automatic catch-up failed.** This reproduces the earlier failure with
the final harness and a fresh installation. No target saved search was manually
dispatched, and no assisted replay or experimental scheduler override was used.

- Baseline: all four target schedules succeeded; exactly 6 flow records were
  summarized. A complete cycle followed the shipped dispatch order.
- The second batch's 6 flow records were indexed at 00:41:15 UTC. Its required
  closed-window rollup slot was 00:50:00 UTC.
- Shutdown began at 00:45:11 UTC. The configured downtime target was 330
  seconds (the `--downtime` default in `tools/scheduler_pipeline.py`), but the
  measured gap between shutdown and the restart request was approximately 344
  seconds. Restart was requested at 00:50:55 UTC; startup and KV data-read
  readiness completed at 00:52:34 UTC.
- At the 30-minute deadline after reset, the summary remained **6/12**.
  There were **zero successful missed-slot executions**. Nine future-slot
  successes were recorded after restart, covering all four targets.
- Read-only diagnostics confirmed both raw batches remained present (12 flow
  records total), all target schedules were enabled in continuous mode,
  persisted history existed, and the effective continuous-search lookback was
  24 hours with a two-minute history load timeout.
- The harness exited with failure (`scheduled convergence/catch-up evidence
  deadline exceeded`).

[Native report](2026-10-13-native-validation.json) preserves the outcome,
configuration fingerprints, scheduler rows, history snapshots, and search jobs.
[Diagnostics](2026-10-13-native-validation-diagnostics.json) preserve enabled
settings during observation, raw-batch counts, limits, and execution ordering.

## Qualification and follow-up

The evidence qualifies normal scheduling, and confirms that native outage
catch-up does **not** work in this tested environment. It does not establish
behavior for another Splunk version or deployment topology. It is consistent
with the [earlier startup-history probes](2026-10-13-scheduler-startup.json).
Do not describe automatic recovery as merely untested or treat resumed future
jobs as proof that missed data recovered.

Keep the [absolute-slice recovery procedure](../RECOVERY.md) as the operational
fallback. Native recovery remains a release qualification failure until a
platform/configuration correction passes this same test without manual replay.

Ten planner unit tests (`tests/test_scheduler_recovery.py`) and 21 scheduler
unit tests (`tests/test_scheduler_pipeline.py`) passed. One earlier unit-test
invocation was blocked by the active lab lock; it passed after the rehearsal
released ownership. The disposable container, image, volumes, and generated
credentials were purged after evidence capture. No application configuration
or implementation was changed for this validation.
