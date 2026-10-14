# Synthetic pipeline benchmarks

Use this harness before a live environment is available to measure the searches that build and read the application map. It exercises the shipped NetFlow normalizer, identity builder, service binding, conversation rollup and graph searches in the disposable Splunk lab. It does not require or contact AWS, Kubernetes, APIC, switches or production Splunk.

Current seeding uses the ACL-protected `adm_observer_scope` KV lookup. Historical reports retain fingerprints of the former `default/limits.conf` and CSV-era setup; those archived fingerprints are not a requirement to restore either runtime control.

The first measured baseline is recorded in [local results, 2026-10-13](benchmarks/2026-10-13-local.md), with raw per-query evidence.

## Run

The lab requires Docker and the licensed TA archives already described in [PILOT.md](PILOT.md#synthetic-fixtures-and-the-splunk-lab). Install the current app before measuring it. The harness rejects remote Docker endpoints, unexpected port bindings, mismatched installed defaults, and pipeline configuration overrides. It pins Docker to the validated local Unix socket for the whole run.

```sh
(
  set -e
  # Reject remote Docker contexts before setup or cleanup can touch a daemon.
  ADM_BENCH_DOCKER_HOST="$(PYTHONPATH=tools python3 -c 'import os; from benchmark_pipeline import local_docker_endpoint; local_docker_endpoint(); print(os.environ["DOCKER_HOST"])')"
  export DOCKER_HOST="$ADM_BENCH_DOCKER_HOST"
  unset DOCKER_CONTEXT
  trap 'tests/splunk/lab.sh purge' EXIT
  tests/splunk/lab.sh up
  tests/splunk/lab.sh install
  python3 tools/benchmark_pipeline.py --reset-lab \
    --cases baseline flow-volume one-device many-devices identity-history \
      shared-observers unique-connections \
    --concurrency 1 2 4 --repeats 3 \
    --output dist/benchmarks/capacity.json
)
```

For a quick correctness check, use `--cases smoke --concurrency 1 --repeats 1`. The explicit `--reset-lab` flag authorizes clearing **the disposable lab's** indexes, identity collections and observer mapping before each case. Do not share this lab with another test process or store useful data in it. The harness leaves the final case loaded for inspection; the shell trap above removes the container, image and generated credentials afterwards.

JSON and a Markdown summary are written after each completed case. A failed case is retained and stops the run. Incomplete graph or search results produce a nonzero exit and remain visible in the report. To probe boundaries deliberately, run `--cases wide-graph connection-cap`. The wide graph has 802 nodes, exceeding the shipped 500-node warning threshold; the connection case exceeds the connection-list cap. Both are expected to produce incomplete results and a nonzero exit. Do not treat these cases as successful capacity measurements.

## Workload dimensions

All cases use a single synthetic Kubernetes namespace: one frontend calls one service on each backend pod. Event envelopes are grounded in the checked-in NetFlow, Kubernetes and OTel fixtures and their [field provenance](../fixtures/raw/FIELDS.md). The manifest records exact expected counts and template checksums; generation is deterministic and streams events to HEC in bounded batches.

| Case | Backend pods | Records per pair per observer | Exporters | Observers per pair | Incarnations per backend IP | Distinct connections per pair |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| smoke | 3 | 2 | 1 | 1 | 1 | 1 |
| baseline | 10 | 100 | 1 | 1 | 1 | 1 |
| flow-volume | 10 | 10,000 | 1 | 1 | 1 | 1 |
| one-device | 100 | 100 | 1 | 1 | 1 | 1 |
| many-devices | 100 | 100 | 100 | 1 | 1 | 1 |
| identity-history | 100 | 100 | 100 | 1 | 10 | 1 |
| shared-observers | 100 | 100 | 100 | 3 | 1 | 1 |
| unique-connections | 100 | 100 | 100 | 1 | 1 | 50 |
| wide-graph | 400 | 250 | 100 | 1 | 10 | 1 |
| connection-cap | 10 | 100 | 10 | 1 | 1 | 100 |

A *flow record* is an indexed NetFlow export, not necessarily a new connection. Most cases hold the connection tuple and time fixed while increasing physical observations, to isolate record volume from connection cardinality. `unique-connections` varies client ports; `connection-cap` intentionally exceeds the default list of 50 connections per summary row. Each observation contributes 300 bytes before observer reconciliation. Shared-observer cases triple raw records and summary bytes while the graph must retain the single-observer byte total.

`one-device` versus `many-devices` holds pods and record count constant. `many-devices` versus `identity-history` isolates retained IP ownership history. Prior pod incarnations occur before the graph window and reuse backend IPs with distinct UIDs; the builder also creates one node identity from the shared node address. This is intentionally a concentrated search workload, not a representative distribution of an entire network.

## Measurement and acceptance

Each case clears the lab, ingests its events, waits for the exact indexed count, closes the index-time slice and dispatches the real saved builders and rollup. The synthetic event timestamps are fixed; dispatch uses explicit event-time bounds rather than the production schedule's relative 24-hour window. Indexing submit and visibility times are recorded separately from saved-search and graph times.

The harness verifies exact rollup record and byte totals, replay identity coverage, identity and binding counts, graph node and edge counts, graph connection counts, and graph bytes after observer reconciliation. Search warnings, early finalization, missing result rows and graph warnings disqualify a result from being complete. It performs one first graph request, followed by repeated synchronized waves at each requested concurrency. These are direct graph searches, not browser sessions.

Reports retain each query's client wall time, server-reported runtime, scan count, result count, status and warnings. Wall time includes dispatch, polling and result download. Small samples are summarized with median and maximum, not a statistically meaningful tail percentile. The first request is separate; subsequent searches use warmed caches. A reset does not guarantee a cold host filesystem cache.

Memory is sampled approximately once per second from the container's cgroup v2 `memory.current`. It includes Splunk, supporting processes and filesystem cache; it is **not per-query memory or an exact peak**. Missing samples are reported rather than replaced with zero. Docker CPU and memory allocation, architecture, image ID, source/configuration hashes, workload fingerprints and run parameters accompany the results. The x86 Splunk image may run under emulation on Apple Silicon; use the reported platform when comparing runs.

A rollup finishing within 300 seconds passes only that batch's five-minute processing check. It does not establish sustainable ingestion throughput, a maximum supported deployment, or a production service-level objective. No acceptance budget is invented for map latency: compare the recorded times with the pilot's eventual target.

## What remains for the live pilot

These measurements exclude network transport, actual exporter and collector behavior, real sampling patterns, mixed Cisco source formats at scale, distributed search/indexer topology, scheduler contention with unrelated workloads, and browser layout/rendering. Repeat the benchmarks on the intended Splunk hardware, then validate them against observed pilot traffic when that environment is available. The existing functional lab suite remains the broader check for ACI, Hubble and hand-off correctness.


## Scope-fixture correction

Later mixed-source validation on October 13 found that the lab helper's
JSON-escaped CSV input could write an empty observer lookup without a search
error. The helper now uses JSON records and verifies every stored mapping.
Earlier benchmark reports remain the measurements recorded at the time; they
should not be used as evidence that non-default observer scopes were exercised.
The [mixed-source baseline](benchmarks/2026-10-13-mixed.json) uses the corrected
setup and checks scope and source/observer attribution explicitly.
