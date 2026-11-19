# Prospective producer-to-index reconciliation contract

This is an offline consistency check for **attestations**, not a collection
system or a completeness qualification. It cannot establish the truth,
authenticity, independence or exhaustiveness of any input. A passing result is
only `eligible_for_independent_review`, with `qualified: false`. Synthetic tests
establish behavior of the checker alone and are not qualification evidence. No
instrumentation, queue, cluster, grant or deployment is authorized here; no
historical evidence is reconstructed.

## Inputs and interpretation

Run `python3 tools/reconcile_prospective_source.py POLICY.json EVIDENCE.json`.
Each input is an offline regular file containing UTF-8 JSON, at most 262,144
bytes, with no duplicate object keys. The final path component must not be a
symlink; nonblocking open and descriptor inspection refuse FIFOs and other
nonregular files. Parent directories and file contents must be trusted against
concurrent replacement or modification; this is not a secure file-custody
mechanism or a deadline guarantee for slow filesystems.
The output contains fixed diagnostic codes, input SHA-256 hashes on parsed
inputs, and no input values. Exit 0 means eligible for independent review; 1
means insufficient evidence. Schemas are closed: extra or missing keys fail.
Digest fields are lowercase 64-character SHA-256 strings; their presence does
not verify their referenced content. Identifiers are 1–128 ASCII letters,
digits, `.`, `_`, `:`, `/` or `-`, beginning with a letter or digit.
Times and sequences are nonnegative integer JSON numbers up to 2^53-1, never
booleans. Each run covers one nonempty half-open UTC window `[start,end)`, one
producer epoch and two families, `identity` and `spans`.

The independently selected policy has exactly these keys:

- `version`: integer 1.
- `binding`: exact `cluster`, `scope`, `producer`, `epoch`, and
  `config_sha256`. These identifiers must identify immutable cluster and scope,
  the actual producer instance, its restart/reset epoch and configuration.
- `window`: `start` and `end` as UTC Unix seconds.
- `clock`: `basis` equal to `utc_unix_seconds`, `max_error_seconds`, and
  `evidence_sha256` identifying an independent clock-error measurement.
- `lateness_seconds`: agreed maximum delivery lateness.
- `families`: exactly `identity` and `spans`. Each has `population_sha256`,
  `signal_semantics_sha256`, and `sampling` equal to `none`. The referenced
  documents define eligibility, event-time assignment, and signal meaning,
  including precisely what an identity interval or span represents. Unknown or
  nonzero sampling is not supported by this version.

Evidence has exactly `version`, `binding`, `window`, and `families`; binding and
window must match the policy exactly, including JSON types. Each family contains:

- `contract`: the exact corresponding policy family.
- `first_sequence`, `last_sequence`: inclusive authoritative sequence bounds,
  with 1–2,000 records. Allocate a distinct monotonic contiguous sequence space
  per producer epoch, family and window; ordering must follow sequence. Closure
  evidence must attest the complete population and bounds, including no hidden
  allocations, late additions, resets or omitted producers. Empty windows and
  multiple producers/epochs need separate reviewed handling and cannot pass this
  version.
- `records`: exactly one entry per sequence, in order, each with `sequence`,
  `event_time`, `receipt_sha256`, `outcome`, `attempts`, and
  `index_ack_sha256`. The unique receipt identifies the immutable producer
  record and binding; the unique index acknowledgement identifies that same
  record as durably searchable in the selected destination. `event_time` must
  fall in the window. `outcome` must be `accepted`; `attempts` is a positive
  integer including the initial attempt. Each retry must refer to the same
  immutable sequence and settle in that one acknowledgement. No rejected,
  dropped, pending or duplicate record can pass.
- `rejected`, `dropped`, `retried`: integer aggregate counters; rejected and
  dropped must be zero, and retried must equal the sum of `attempts - 1`.
  `loss_evidence_sha256` and `sampling_evidence_sha256` identify independent
  measurements covering the entire bound population and collection path.
- `closure_sha256`: authoritative producer closure attestation for the window,
  sequence boundaries and population. `watermark` is a UTC Unix second indexed
  watermark attesting all records through the window have settled; it must be
  at least `end + lateness_seconds + max_error_seconds`.

Receipts and acknowledgements must be distinct within and across families.
The checker compares identities through their attestations, not actual payloads
or a live index. A digest is an identifier, not a signature, and the checker
does not fetch or verify referenced documents. A malicious or incomplete
producer can supply consistent fabricated claims. Independent review must verify
provenance, signatures/custody, record-to-ack matching, population and epoch
coverage, clock and lateness bounds, counter meaning, and measurement methods.
Policy selection must itself be independently reviewed; merely copying the
producer's claims into both files does not establish independence.

## Proposal for separately authorized future instrumentation

Before implementation, name the exact cluster, namespace/scope, destination
index, producer instances and two signal populations; assign accountable
producer, collector, index and evidence custodians. Agree event-time and clock
error measurement, sampling policy, expected cardinality/volume, allowed
lateness, immutable config and epoch identity, and how epoch transitions, empty
windows, exclusions and missing producers are independently enumerated.

The bounded implementation proposal is: instrument only those named producers
to allocate durable per-window family sequences and emit immutable receipts;
use a durable collector queue with persisted enqueue/export/retry/drop counters;
record index acknowledgements tied to the same IDs; persist closure and
watermarks only after all receipts settle. Retain signed or otherwise verifiable
provenance, the referenced evidence, configuration revisions, queue and index
records under a specified retention period, encryption and least-privilege access
policy. Specify storage capacity, backpressure, alert thresholds, ownership,
rollback and failure handling before deployment. Verify through controlled
restart, retry, rejection, drop, duplicate, out-of-order, clock-skew, lateness,
queue-full and index-outage tests, and independently audit observed counts and
IDs against the authoritative producer population. A separate review must
approve the exact implementation, resources, permissions, deployment window,
rollback and test plan before any mutation. Subsequent evidence applies only to
windows covered after verified installation; it cannot repair prior gaps.

## Concrete next candidate and authorization proposal

A small candidate is the `kube-system/coredns` Deployment on the selected
`isovalent-demo` context. The retained prospective metadata names that
Deployment; it does not establish any active identity-interval or span emitter,
its population, traffic, collector route, or destination. The candidate
population would be the identity intervals for exactly one independently selected
CoreDNS Pod and spans for DNS requests handled by that same Pod during one
2-minute half-open emission window. The two signal definitions and population
selection must be reviewed before implementation; if the Pod cannot emit both,
this candidate cannot pass and another scope needs a new review. This proposal
is not evidence that these signals exist.

The selection must bind the cluster immutable identity, namespace UID,
Deployment UID and revision, exact Pod UID, container imageID, producer process
instance and restart epoch, and immutable producer and collector configuration
hashes. Compare these through selection, emission and closure, reject any change
or unenumerated instance, and bind destination index and signal definitions in
the reviewed policy. The Pod UID, imageID, process/epoch, effective running
configuration, destination binding, and actual window are **unobserved and
pending**; no runtime values or historical results are inferred from the
retained declaration. A separately reviewed read-only identity inspection and configuration
validation must establish them before a concrete run can be approved. The
existing read-only inventory authorization persists; instrumentation and
configuration changes still need their own narrow authorization.

For a future controlled test, propose a 120-second window and a 600-second
lateness allowance, with a separately measured and added clock-error bound.
Ten minutes is a proposed allowance, not a measured maximum. Cap at 2,000
records per family and 16 MiB total retained receipt/ack evidence; establish
capacity before emission and stop and mark the window insufficient if any cap,
queue limit, identity change, sampling, loss, missing acknowledgement or clock
bound is reached. The checker also imposes its 262,144-byte per-input limit;
any larger evidence requires a separately reviewed schema, not truncation.
The review must specify the exact time, producer and collector changes, scoped
permissions, isolated destination, evidence custodian, retention period, storage
location, alerts, cost, rollback and cleanup, and require explicit authorization
before any deployment or emission.

Each producer receipt must bind the same family, epoch, sequence and immutable
record digest to the selected policy. Persist collector enqueue and export
receipts with that identity, attempt number, stage outcome and durable custody;
retain independent counters for rejection, retry and drops. An export or HEC
acknowledgement proves only its documented transport acceptance, not that a
specific record is searchable. A separate caller-authorized indexed query must
verify each immutable sequence and digest in the selected index, with unique
indexed-record acknowledgements and duplicate detection. Reconcile every stage,
then close only after the window, measured clock bound and lateness allowance,
with no unsettled or missing record. Independently verify enumeration, receipts,
query coverage and custody before any completeness determination. The present
checker accepts compact attestation digests; it does not perform these stage
queries or authenticate their evidence.


## Offline Pod projection boundary

`tools/project_prospective_pods.py EXPECTED_DEPLOYMENT_UID FIRST.json SECOND.json`
checks paired offline CoreDNS Deployment/ReplicaSet/Pod claims. It validates the
explicit Deployment UID and controller chain, duplicate identities, revisions,
container/status cardinality and projected state. Inputs are regular JSON files
limited to 1 MiB each and twenty Pods; output hashes names, UIDs, revisions and
images and omits environment, arguments and raw settings. A matching projection
is not a live observation. Init/ephemeral containers, nonprojected configuration,
process identity and effective configuration are outside this projection. No
live Kubernetes entrypoint is included: a future exact read-only packet still
needs pinned authentication, endpoint/CA and namespace identities, an enforced
request allowlist and bounded child retirement. No new EKS read was dispatched
for this increment.
