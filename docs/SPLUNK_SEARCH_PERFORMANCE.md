# Splunk search scale boundaries and measurements

This note records the application limits traced for this task and the narrow
local workload used to measure topology-search behavior. It distinguishes
offline contract checks, local Docker/Splunk measurements, and production
qualification. The included workload is NX-OS-only and must not be read as a
mixed-source or production capacity claim.

## Limits and paging traced in the application

| Surface | Contract in this revision | Source |
| --- | --- | --- |
| Graph parser | At most 500 nodes and 2,000 edges, plus one metadata row (2,501 rows total). | [`frontend/src/rows.ts`](../frontend/src/rows.ts) |
| Topology parser | Rejects more than 20,000 rows before assembly. | [`frontend/src/topology.ts`](../frontend/src/topology.ts) |
| Live search client | Fetches `maxRows + 1` as an overflow sentinel; requires final `resultCount` to match received rows and rejects unfinished, finalized, truncated, dropped, or over-limit searches. | [`frontend/src/data/searchClient.ts`](../frontend/src/data/searchClient.ts) |
| Observer setup read | 1,000-row pages through offset 19,000, then a one-row sentinel at 20,000; over 20,000 is incomplete. | [`frontend/src/data/setupClient.ts`](../frontend/src/data/setupClient.ts) |
| Read-only setup collections | 250-row pages up to 1,000 rows, then a one-row sentinel at 1,000; duplicate keys and partial reads are rejected. | [`frontend/src/data/setupClient.ts`](../frontend/src/data/setupClient.ts) |
| Topology sampling | `adm_topology_sample=10000` caps FTD connection samples and Nexus Dashboard flow records used to name firewalls and label fabrics. It is not an overall topology row cap. | [`splunk_app/splunk_adm/default/macros.conf`](../splunk_app/splunk_adm/default/macros.conf) |
| Topology time bounds | The V2 inventory helper looks back one hour from the selected query start, through the selected end. The boundary workload calls V1 `adm_topology` with explicit fixed event-time bounds. | [`splunk_app/splunk_adm/default/macros.conf`](../splunk_app/splunk_adm/default/macros.conf) |
| Identity history | The shipped `adm_identity_retention` is 604,800 seconds (seven days). `adm_identity_max_matches=1000` is the per-identity lookup cap; reads at the cap are treated as potentially truncated and suppress incomplete history writes/correlations. | [`splunk_app/splunk_adm/default/macros.conf`](../splunk_app/splunk_adm/default/macros.conf) |
| Application KV reads | `adm_kv_read_all` requests 10,000-row pages across its fixed offsets and checks page completeness, including an offset-1 probe for the first page; `adm_kv_max_rows=50000` must match the effective KVStore per-query limit. Incomplete or capped reads remain flagged. | [`splunk_app/splunk_adm/default/macros.conf`](../splunk_app/splunk_adm/default/macros.conf) |

The Splunk result endpoint supports bounded `count` and zero-based `offset`
parameters, while search-job metadata exposes final result count, dispatch
state, scan/event counts, runtime, disk usage and truncation/drop indicators.
The REST API reference documents those endpoint parameters and fields in
[Search endpoint descriptions](https://help.splunk.com/en/splunk-enterprise/rest-api-reference/10.6/search-endpoints/search-endpoint-descriptions).
Splunk's [REST search tutorial](https://help.splunk.com/en/splunk-enterprise/leverage-rest-apis/rest-api-tutorials/10.6/rest-api-tutorials/creating-searches-using-the-rest-api)
also explains retrieving completed results. The harness pages with explicit
offsets and stops at the configured limit plus one sentinel row; it does not
request `count=0`.

Splunk's 10.6 [`limits.conf` reference](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.6/configuration-file-reference/10.6.0-configuration-file-reference/limits.conf)
documents a 50,000-row default for `searchresults::maxresultrows`, which
controls only commands that create or grow result sets, plus a separate
`restapi::maxresultrows` default for `/results` and `/events` getters. These
are server settings, may be overridden, and are not the application's 20,000
topology-row contract. Do not infer an effective deployment limit from a
documented default. Splunk's [Search Job Inspector guide](https://help.splunk.com/en/splunk-enterprise/search/search-manual/10.6/manage-jobs/view-search-job-properties)
describes job execution-cost details and indexer timing; some panels require
access to `_introspection`.

## Deterministic NX-OS boundary workload

`tools/benchmark_topology.py` creates three static workload configurations
from the reviewed `nxhostname` and `nxinterface` shapes in
[`fixtures/raw/nexus9k.ndjson`](../fixtures/raw/nexus9k.ndjson), whose field
contract is recorded in [`fixtures/raw/FIELDS.md`](../fixtures/raw/FIELDS.md).
No generator or downloaded vendor script is run. Each manifest fixes an event
time, caller search window, source mix, input count, expected device and
interface identity hashes, and hashes of both source files. The exact expected
output rows, including one metadata row, are:

| Case | Devices | Interfaces | Total topology rows | 20,000-row contract |
| --- | ---: | ---: | ---: | --- |
| below | 9,999 | 9,999 | 19,999 | accepted |
| at | 9,999 | 10,000 | 20,000 | accepted |
| above | 9,999 | 10,001 | 20,001 | rejected |

The workload contains only `cisco_dc` / `cisco:dc:nexus9k` records. It does not
exercise ACI, FTD, Nexus Dashboard, LLDP, Kubernetes attachment resolution,
other inventory sources, mixed-source collisions, or distributed search. The
`above` run fetches exactly one sentinel row beyond the 20,000-row limit; the
search job is reported as limit-exceeded while the benchmark records the
expected over-limit outcome as a successful boundary check if every other
correctness and completion condition passes. `application_accepts_rows` is a
static comparison of retrieved row count with the source-defined parser
constant. This benchmark does not run the React parser or browser, so it does
not directly test live UI rejection.

Because the reviewed fixture shapes contain no CDP/ACI/LLDP adjacency and no
`show interface snmp-ifindex` output, the expected metadata warning set has
exactly two entries: no switch links collected, and SNMP ifIndex known only for
CDP-connected ports. The correctness oracle requires this exact set and rejects
extra or changed warnings; it does not suppress warnings generally.

The runner accepts only a local Docker Unix socket and localhost Splunk
management/HEC bindings. It verifies the task lab's ownership label when
`ADM_LAB_TASK` is set, binds installed app defaults to the source or selected
immutable package, and records the lab container and image IDs, package SHA,
resource limits, and non-task Docker activity before and after each measured
search. Non-task containers are left untouched. Native host-process collector
activity, process CPU attribution, per-search CPU/RSS, and per-indexer I/O are
not available from this harness and are recorded as limits. Container memory
is sampled from cgroup v2 `memory.current` about once per second; this is a
whole-container sample that includes Splunk processes and cache, not an exact
per-search peak.

Preflight also makes a read-only GET to Splunk's `server/info` REST endpoint,
with a 15-second request timeout and a 64 KiB response cap. It retains only
`version`, `build`, and `product_type`; endpoint errors, missing fields, and
oversized or malformed responses are reported as unavailable without stopping
preflight. The endpoint can return other instance details, including license
and host identifiers, which the report does not retain. See Splunk's
[`server/info` endpoint documentation](https://help.splunk.com/en/splunk-enterprise/leverage-rest-apis/rest-api-reference/10.6/introspection-endpoints/introspection-endpoint-descriptions).

The retained boundary and graph reports produced before this field was added
include the Splunk image tag and image ID, but did not capture native server
version, build, or product type. Those reports remain unchanged.

Each job records client wall time; Splunk `runDuration`, `scanCount`,
`eventCount`, `resultCount`, `diskUsage`, `dropCount`, truncation/streaming
flags and the `performance` object when present; dispatch/finalization state;
warnings; result-page offsets/counts; and unavailable metric names. Missing
metrics remain `null`, never zero. A failed page, short page, bad final count,
preview, early finalization, event/result truncation, drops, row mismatch or
unexpected dispatch state leaves the attempt visible as failed or incomplete.
Each run also records attempted and acknowledged HEC batches so a failed ingest
does not disappear from the evidence. Here “acknowledged” means the HEC request
returned HTTP success with HEC `code=0`; it does not mean indexer
acknowledgment was enabled or polled. Separate Splunk visibility searches
record the indexed event count and identities.

## Running offline checks and local measurements

Offline checks validate deterministic manifests, correctness oracles, hard
workload bounds, pagination behavior, failure retention and local-target
guards. They make no Splunk performance claim:

```sh
ruff check tools/benchmark_pipeline.py tools/benchmark_fixtures.py \
  tools/benchmark_topology.py tests/test_benchmark_pipeline.py \
  tests/test_benchmark_topology.py tests/test_benchmark_fixtures.py
python3 -m unittest discover -s tests -p 'test_benchmark_*.py'
```

For a local search measurement, use a dedicated task lab as described in
[`docs/TASK_LABS.md`](TASK_LABS.md), and set `ADM_LAB_PACKAGE` to the exact
immutable package under review if it is the package intended for measurement.
The JSON report and Markdown summary are written after each case; preserve
them outside the disposable lab before cleanup.

```sh
bash tests/splunk/lab.sh up
ADM_LAB_PACKAGE=/absolute/path/to/splunk_adm-<version>.tar.gz \
  bash tests/splunk/lab.sh install
python3 tools/benchmark_topology.py --reset-lab \
  --cases below at above --output dist/benchmarks/topology-boundary.json
bash tests/splunk/lab.sh down
```

Only run measurements when this task's lab owns the configured name, ports,
network and volumes; `--reset-lab` clears its indexed events before each case.
The default per-search deadline is 300 seconds and the result-fetch limit is
20,000 plus one sentinel, in pages no larger than 10,000. The report is local
Docker/Splunk evidence for the exact recorded image, package, source, workload
and host conditions. Filesystem and Splunk caches are not flushed; other
containers and host collectors remain active, so contention is uncontrolled.

Reset setup is separately bounded: `lab.sh reset` has a 900-second deadline
and the benchmark's Docker macro-override cleanup command has a 30-second
deadline. A timeout triggers host process-group termination; the case report
records whether the host group disappearance was confirmed. That confirmation
does not prove that the Docker daemon stopped a `docker exec` already running
inside the container. Since a reset can stop Splunk or clear only some indexes
before timing out, the lab state is marked uncertain. The run does not retry or
proceed to another case; verify and reinitialize the disposable lab before
starting a new run. The benchmark's cooperative lab lock remains held by the
parent runner while it records the failed case.

## Production qualification remains separate

Offline correctness is not a benchmark. A local Docker run is not a production
capacity test. Production qualification requires the intended Splunk version,
license, search-head/indexer topology, effective limits, retention, role and
index access, real source mix/cardinality, historical depth, concurrency,
collector and scheduler activity, and agreed latency/resource targets. Repeat
the deterministic workload alongside representative pilot traffic, capture
per-indexer and job-inspector data where available, and compare repeated
cold/warm runs under declared conditions. This task has not established a
production capacity ceiling, supported topology size, SLO, or performance
budget.
