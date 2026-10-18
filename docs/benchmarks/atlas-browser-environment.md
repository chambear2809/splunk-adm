# Atlas browser measurement environment

The exploratory run (`dist/performance/atlas-browser-exploratory.json`) passed all 14 workload
cases and retained 140 measured samples. It overlapped other focused checks,
browser tests and local Splunk lab startup. Those values are diagnostic evidence,
not the baseline used to assess the candidate.

The first controlled attempt (`dist/performance/atlas-browser-interrupted-baseline.json`) was
stopped after 74 completed samples to address independent review: its synthetic
graphs scaled generic nodes/edges while Cisco client evidence and topology stayed
at captured cardinality. Its report retains `complete: false` and the interrupted
case. The revised workloads scale authority-qualified identities, attachment and
traffic records, client handoff coverage and topology/association inventory. The
exploratory and interrupted runs use the earlier harness hash and are excluded
from the revised comparison.

`atlas-browser-evidence-index.json` records retained raw paths and SHA-256 checksums.
Large obsolete raw artifacts stay under ignored `dist/performance`; they remain
available locally without increasing the repository diff.

For the retained comparison, the coordinator completed integrated checks, froze
frontend/fixture sources and paused other agent browser/build/test work. The
coordinator gracefully stopped its own local Splunk lab through its exclusive
lock session before both runs; the performance harness neither starts nor
operates it. Unrelated OTel containers remain untouched. Baseline and candidate
run sequentially under this same arrangement. OS services and unrelated desktop
activity remain uncontrolled; this is a developer workstation, not a dedicated
benchmark host.

Both retained comparison runs use the same production profiling harness, all four
captured scenarios, both controlled graph sizes, both partial client handoff
variants, five cold-context samples and five warm-context samples, with one
discarded full warmup per warm context. Source, harness, workload, lockfile,
runtime and hardware fingerprints accompany every raw report. See
`../BROWSER_PERFORMANCE.md` for timing boundaries and limitations.
