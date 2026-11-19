# Prospective CoreDNS runtime provenance candidate

The prepared read-only candidate targets `isovalent-demo`, namespace
`kube-system`, Deployment `coredns`. It pins the namespace and Deployment UIDs
from retained earlier workload metadata and refuses replacements. Its purpose is
to compare current declarations and reported Pod status across two reads; it
cannot establish processes, effective configuration, emission, delivery or
source completeness.

The runner permits only kubeconfig minified view and its CA data; caller identity;
`get namespace kube-system`; `get deployment coredns -n kube-system`; and
`get replicasets` and `get pods` in `kube-system` with exact selector
`k8s-app=kube-dns` and `--chunk-size=0`. Resource reads use JSON and are paired;
namespace revision and caller identity bracket both rounds. It rejects list
continuation, empty or over-20 lists, changed identities or revisions, duplicate
Pods or owners, incomplete or ambiguous container status, and owner chains not
ending at the pinned Deployment. It requires the selector on every Pod and
compares imageID hashes, readiness and state. It projects ConfigMap **volume**
references by hash from the Deployment template; it neither reads ConfigMaps nor
claims this represents all configuration references. Pods may be unready or
terminated: these states are reported, not qualification.

The private candidate reuses the prior pin-checked framework: exact context,
endpoint and CA, `default` AWS profile, reviewed CLI/interpreter hashes and
kubeconfig exec shape, fixed noninteractive environment and strict TLS. It
permits no SSO login, Secrets, logs, exec, mutation, extra namespace or cluster
requests. Command output is capped at 1 MiB per request and JSON nesting at 64;
the existing framework applies per-command deadlines and process-group
retirement. A separate supervisor enforces a 240-second probe deadline and
signals the worker on timeout, TERM or HUP; it allows up to ten additional
seconds for cleanup. The worker signal handler unwinds through the helper
cleanup, which retires its command process group. This is not a guarantee
against descendants escaping the group, interrupted cleanup, uninterruptible
processes, or successful retirement after the cleanup deadline. The supervisor
checks the fixed output schema and suppresses malformed child output. Raw Pod and
Deployment responses can include sensitive values in memory. The output retains
only hashes and fixed status categories; it does not output raw environment,
arguments, configuration, names, image identifiers, or identity details.

The public assembly accepts an injected caller and can be exercised offline; it
is not by itself a network or security boundary. Its passing fixtures are not
live observations. The private launcher embeds the exact pinned projector, assembly and transitive
helper source bytes; it does not load helper sources from mutable paths. The
private launcher and its module pins require independent
prelaunch review and a new immutable review packet before any read. Review the
complete helper chain, active executables, profile, credentials state, request
allowlist, output handling, limits and child retirement; independently verify
that pinned resources still represent the intended selection. If any guard
fails, stop without adopting a changed UID or relaxing TLS. No instrumentation,
configuration, permission or deployment change is authorized by this candidate.

## Read-only observation on 2026-11-19

A separately reviewed and frozen candidate completed one read-only run. The
retained primary output is 3,066 bytes, with SHA-256
`ea913eb46302253128de3d92e05d445900ad3b0bc44d024bb5cc2958c03e1d43`;
stderr was empty. The namespace and Deployment UID pins matched. The paired
projection contained two Pods and three ReplicaSets. Both Pod status entries
were `Running`, their reported containers were ready with zero restarts, and
the observations contained one distinct imageID hash and one selected owner
ReplicaSet hash. The Deployment template contained one ConfigMap volume
reference. These are paired current Kubernetes API declarations and status,
not a census of processes or evidence of effective configuration, telemetry
emission, loss, sampling, index delivery, historical coverage or completeness.
A ConfigMap reference does not attest its contents or runtime use. No source
qualification follows from this observation.

The existing Duo session was valid for this read; the run did not initiate a
new sign-in or change grants or settings. A separate retained local postcheck
is 162 bytes, SHA-256
`452e33d67418a1604749eb323adfd94a8419feae53af40c6c8927ce431308e62`.
It reported zero candidate, cluster-token and kubectl-context matching processes
in its current bounded command-line snapshot. This is not a general descendant
or future-process guarantee. Neither receipt establishes process attestation,
effective configuration, collector receipts, emitted spans or indexed spans.

## Next read-only validation contract

For a prospective candidate, select the observed Pod whose UID SHA-256 is
`2ddca949ee83f1673528b32445ea26fa33b5fbef9694ec7df45e80f2ae74f8ca`.
This is a selection of one of the two observed UIDs, not a claim that the Pod
is still present or supports either proposed signal. Do not substitute the
other Pod, a replacement UID, or a historical `k8s-01` identity. A new,
independently reviewed read-only packet must revalidate the exact cluster,
namespace and Deployment immutable identities, the selected Pod UID and its
controller chain, and the current imageID, state, readiness and restart epoch
at selection and closure. A mismatch, replacement, incomplete response or
unresolved transition makes the window ineligible; it is not repaired by
adopting a new identity. The observed imageID and owner hashes are status and
metadata, not process or binary attestation.

Before a run can be proposed, establish by a separately reviewed, scoped
read-only method the actual producer process instance and epoch, the effective
producer and collector configuration and their immutable revisions, the route
from that instance to a named destination index, and independent evidence
custody. The existing projection cannot establish these facts. Specify the
exact permitted resources and operations, authentication and endpoint pins,
limits, sensitive-output handling and retirement checks in the new packet;
stop if any cannot be verified. No additional read is performed or authorized by
this document. Process inspection, configuration contents or collector evidence
may require operations beyond the existing allowlist and must not be assumed
available under it.

Define and independently review two separate populations: identity intervals
for the exact selected Pod and DNS-request spans for requests actually handled
by that Pod. For each, define eligibility, start/end or event-time assignment,
units, boundaries, exclusions, duplicate/retry semantics, epoch changes and
how the complete population is independently enumerated. Verify whether a
suitable emitter and a trustworthy interface exist for each family, including
how the same Pod and process are bound to every record. No emitter capability,
request coverage or collector route has been observed. If either family or its
population cannot be established, this candidate cannot satisfy the existing
both-family checker; choose a separately reviewed scope rather than infer it.

## Future instrumentation design inputs

Only after the read-only validation, prepare a concrete change proposal that
names the components and versions, interfaces and schemas for producer
sequences and immutable receipts, collector enqueue/export/retry/drop custody,
record-level indexed acknowledgements, and authoritative closure. Bind each to
the selected Pod UID, process epoch, configuration, family, window and named
index. Demonstrate independently how record identity survives retries and how
missing or duplicate records are detected; transport acceptance alone is not
proof of searchable indexing. The offline reconciler checks supplied claims and
hashes, not their authenticity or truth.

The proposal must specify and independently measure sampling and loss across
all relevant stages, clock error and delivery lateness, and the method for
closing a watermark. Unknown sampling or loss is insufficient; neither the
proposed 120-second window nor 600-second allowance is a measured bound. Set
retention, evidence access and custody, expected and peak volumes, storage and
queue capacity, backpressure and alerts, and an explicit stop/fail-closed
response to overflow, resets, missing data or changed identity. Address the
existing checker's 2,000 records per family and 262,144-byte per-input limits;
the proposed 16 MiB receipt/ack budget is not a substitute for those limits or
permission to truncate. Specify owners, scoped permissions, cost, test cases,
rollback and cleanup before seeking separate authorization for changes. No
instrumentation, configuration change, deployment or emission is authorized
here. Even successful future evidence would cover only its independently
validated prospective scope and window; it would not prove production-wide
completeness or recover historical `k8s-01` evidence.
