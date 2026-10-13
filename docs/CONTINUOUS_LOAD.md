# Continuous-load correctness soak

`tools/soak_pipeline.py` is a bounded correctness exercise for the disposable
localhost Splunk lab. It is separate from `tools/benchmark_pipeline.py`: the
benchmark measures workload and query timings, while this soak checks that
paced ingestion, overlapping map reads, scheduled-search-equivalent dispatch,
replay, and one skipped rollup cycle converge to the expected result.

The script imports the deterministic workload from
`tools/benchmark_fixtures.py`, posts events through the lab HEC helper, and
uses the REST search runner in `tools/benchmark_pipeline.py`. It requires the
explicit `--reset-lab` flag. Preflight rejects non-local Docker endpoints and
unexpected lab configuration; reset clears the disposable lab's indexes,
collections, and observer scope through the shared benchmark helpers. It does
not install the app, enable saved-search schedules, contact a production
Splunk, or test a real HEC/network outage.

Run it only against an already prepared, idle local lab:

```sh
python3 tools/soak_pipeline.py --reset-lab --batches 3 --interval 1 \
  --flow-copies 2 --pause-cycle 2 \
  --output dist/soak/local.json
```

The bounds enforced by the CLI are 3–20 batches, 0.1–10 seconds between
producer chunks, 1–100 flow copies, 2–100 pods, a 10–1,800 second search
timeout, and a pause cycle inside the batch range. Each wave posts three
chunks concurrently with builder searches and repeated graph reads. The
paused wave deliberately skips rollup; the following wave processes the
backlog and repeats the closed slice to check replay suppression.

The JSON report is written even when the run fails. A successful report has
`status: "complete"`, `summary_flow_records` equal to
`expected_flow_records`, no remaining backlog, and per-wave fields including
`submitted`, `searchable`, `sha256`, `overlapping_submissions`, index-time
boundaries, processing state, and backlog size. Search job records are stored
under `jobs`; failures are summarized under `error`. The command returns zero
only for a complete report and does not purge the lab afterward.

The soak proves convergence for this deterministic fixture and bounded local
workload. It does not establish scheduler cadence, sustainable throughput,
capacity, production service levels, collector behavior, network transport,
or resilience to an indexer/HEC outage. Use the normal lab cleanup procedure
when the disposable environment is no longer needed.

A completed local run is recorded in [the October 13 evidence](benchmarks/2026-10-13-soak.md).
