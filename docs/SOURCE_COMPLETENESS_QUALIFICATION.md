# Selected historical source completeness

Completeness of the selected real-source population is **not qualified**. The
prior installed comparison and the non-admin revocation exercise establish
specific retained capture behavior for `coreapi` in `tenant-jobs`, lab cluster
`k8s-01.uktme.cisco.com`, over the adjacent 2026-11-16 15:55–15:56 and
15:56–15:57 UTC windows. They do not establish how many identity intervals or
spans should have existed, whether every producer record was received, or bounds
on collection loss, sampling and lateness. The retained graph itself records 87
and 90 excluded spans in those windows. Those exclusions are not a denominator
for the original source population.

The recorded source context associates the identity feed with producer
`uktme-atlas-identity` and producer configuration revision
`0b0d18412ba0d8c424ca1d0abe7603612edd66a48a9501eb82d6a288208266fc`.
Catalog agreement is attribution evidence, not a complete producer history.
The operator record describes a memory-backed collector retry queue, which does
not establish lossless delivery across collector restarts or destination outages.
A current restart count or current configuration cannot reconstruct that past.

`tools/qualify_source_completeness.py` checks a bounded evidence document for
internal consistency: the exact selected scope and revision; separately
identified identity and span populations; expected, indexed and accounted
excluded counts; continuous producer receipts for each window; independently
identified loss, sampling and lateness evidence; and indexed watermarks beyond
the required lateness interval. It never declares qualification. Even when all
fields are present it returns only `eligible_for_independent_review`: the source,
population method, receipts and evidence authenticity still need independent
verification. Synthetic tests exercise missing receipts, unaccounted exclusions,
insufficient watermarks and changed scope. The tool's input is not itself proof.

A separately reviewed, metadata-only current Kubernetes probe is prepared. Its
allowlist covers the existing `atlas-telemetry` ConfigMap and Deployment and
matching collector pods in `tenant-jobs`. It reports configuration and object
hashes, deployment and image metadata, current collector restart counts, and
whether storage-related terms are declared. It does not request Secrets or pod
logs, and it does not output or retain environment values that may occur in a
Deployment response. It does not establish past queue durability.

The first read-only run failed before observing the selected ConfigMap. A
subsequent read-only diagnostic identified the ConfigMap GET as the failing
stage; a bounded client-error text classifier returned `tls_or_certificate`.
That classification is not an authoritative HTTP status or proof that the
object is absent. Current collector configuration and deployment state remain
unobserved. The original and diagnostic failures are preserved; no TLS
verification was disabled and no source deployment, grant or runtime
configuration was changed. The private classifier output
`source-readonly-k8s-classifier-output.json` has SHA-256
`82572be1ef076019d144715a3afc272b143f0b42152a3883cbf82d2533a91e96`.
A separate public-certificate-only inspection found that the configured client
certificate expired at 2026-11-16 16:04:53 UTC; the configured CA was within
its validity period through 2035-11-14. Strict TLS verification of the fixed API
peer failed with certificate-expired code 10. That failed handshake did not
identify which peer-chain certificate failed, and it did not read a Kubernetes
resource. Its private `source-public-certificate-output.json` has SHA-256
`e57540108ce4c3c598f50a5e5737367645a5a797dc09d94203a73341c3b048c0`.

A prospective completeness claim would require an independently reviewed
population definition for both identity intervals and spans, durable
producer-side receipts or sequence evidence covering the exact windows, measured
sampling and loss, and an indexed watermark after the agreed lateness bound.
The historical in-memory queue limitation must remain explicit where such
records were not retained. Instrumentation or a durable queue would require a
separately scoped implementation and authorization; it would establish future
coverage only after validation, not retroactively repair historical evidence.

A concrete future increment would first define stable producer-instance and
monotonic sequence identifiers for identity intervals and accepted spans, along
with an explicit population and sampling contract for each family. Persist
producer batch receipts, sequence gaps, rejected and retried counts, and an
immutable configuration revision outside the collector's memory queue. Pair
those receipts with a durable collector queue, monitored enqueue/export/drop
counters and indexed-ingestion acknowledgements. A watermark for each producer
and window would advance only after the configured lateness interval and all
receipts through that boundary have been reconciled. Qualification would compare
producer counts and identifiers against indexed observations and account for
each exclusion, including scope and clock failures, with independently reviewed
measurement and retention limits.

This is a proposed future design, not an installed implementation. Its
resource ownership, retention budget, access model, deployment and failure tests
need separate review and authorization before any collector or producer changes.
It cannot supply missing evidence for the November 16 historical windows.
