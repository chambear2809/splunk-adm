# Prospective source qualification

A replacement cluster can support a future source-completeness exercise, but it
cannot supply missing historical evidence from `k8s-01.uktme.cisco.com`. No
producer population, collection configuration or comparable telemetry windows
have been qualified for completeness. The previous cluster's source identifiers,
configuration revisions, results and hashes must not be carried into a new
qualification as evidence of this cluster's producer population.

The user selected the existing `isovalent-demo` EKS context for a bounded
read-only inventory. The initial caller-identity request failed before namespace
inventory, with an independently expired cached session. After the user returned
and completed the established Duo sign-in on November 19, the exact-context
inventory passed with a stable caller identity and verified endpoint and CA.
The first post-login namespace request succeeded, but its valid Kubernetes
`v1/List` response was rejected by a fixture that expected `NamespaceList`.
A separately reviewed shape probe established that all 15 items were valid
Namespaces. A versioned fixture correction then accepted both response shapes
while still validating every Namespace and rejecting duplicates. The original
failed outputs remain retained.

The current inventory observed 15 namespaces. A separately reviewed metadata
probe read Deployment, DaemonSet and StatefulSet declarations only in
`otel-splunk` and `kube-system`, bracketing each namespace's UID/resource version
and the caller identity. It observed declared Splunk OTel collector version
0.148.0, OBI v0.4.1, and Cilium/Hubble v1.18.8-cee.1. These are workload
declarations; no Pod image, process, health or effective running configuration
was attested.

A further reviewed probe read exactly four referenced ConfigMaps twice: the
Splunk OTel collector, agent and Kubernetes cluster receiver maps, plus
`kube-system/cilium-config`. Paired projections matched under stable namespace
and caller identities. The retained evidence contains map UIDs/resource
versions, key counts and value hashes, with no raw values. Each OTel map had
one data key, and the Cilium map had 189. The three OTel configuration values
were not parsed by the first JSON-only probe; receiver,
processor, exporter, queue, retry, storage and sampling structure remain unknown
in that observation. No Secrets, logs or process execution were requested, and
no collection, grant or cluster configuration changed.

A subsequent independently reviewed probe used the existing, hash-pinned
pure-Python PyYAML 6.0.3 sources with bounded parsing and unsafe constructs
refused. It parsed the three OTel values without retaining raw settings. All
four map identities, resource versions, key counts and value hashes matched the
first observation. The collector and agent declarations contained logs, metrics
and traces pipelines; the cluster receiver contained logs and metrics pipelines.
Recognized queue fields were present in the collector and cluster receiver
values. Retry, storage and sampling field names were not observed by this
projection. Field non-observation does not establish default policy, disabled
behavior or applicability, and queue presence does not establish durability or
runtime binding. Unknown component types remain counted as unknown. The parser
establishes literal declaration structure only.

The inventory accepts only the reviewed EKS
`aws eks get-token` command shape for that exact cluster and region; it uses a
fixed executable-resolution path, checks the local launcher, its resolved Python
interpreter and kubectl hashes,
passes no secrets in arguments, validates the selected AWS profile and
source-profile chain against unsupported external credential providers, disables
interactive prompting and does not perform an SSO login. Those executable
hashes do not attest all AWS CLI or Python dependency files. The established Duo SSO workflow
supplied the renewed session; subsequent reads still require a valid session and all endpoint, identity and executable checks.

The resource steps read effective caller identity, a bounded namespace inventory
and the explicitly selected workload declarations and ConfigMaps. The Deployment
response may contain environment values in memory, but the inventory does not output or
retain them; it does not request Secrets or logs. ConfigMap values are reported
only as hashes and the fixed structural vocabulary described above. Output caps, deadlines and child retirement bound the probe. A
namespace name or collector configuration is current metadata, not historical
coverage, a validated telemetry population or evidence of delivery completeness.
No collection, grant, agent, runtime or infrastructure change is authorized by
this read-only inventory.

Any future qualification must bind independently verified producer and collector
configuration revisions to the selected cluster and scope, define both identity
and span populations, and retain producer receipts, loss/sampling measurements,
indexed acknowledgements and lateness watermarks for explicitly chosen windows.
Those records and their provenance must be reviewed separately before any
completeness claim. A new durable queue or producer instrumentation is a future
change requiring its own design, operational review and authorization.


## Offline prospective contract — November 19 continuation

The [producer contract](SOURCE_PRODUCER_CONTRACT.md) now defines a bounded
prospective candidate and an offline reconciler for exact policy/epoch/window
bindings, continuous sequences, receipts, indexed-record acknowledgements,
delivery counters and clock/lateness watermarks. A separate paired offline Pod
projection checks a fixed controller chain and hash/status metadata. Both tools
check supplied claims; neither reads Kubernetes nor authenticates evidence.
No new running configuration, producer population or delivery was observed.

The CoreDNS candidate still needs exact Pod/process/configuration/destination
bindings and supported emitters. The proposed window and lateness allowance
are not measured bounds. Existing read-only inventory authorization persists;
new instrumentation, queues or collection changes require a concrete reviewed
proposal and narrow authorization. No historical source identity is transferred.
See `source_contract_recovery_admission_20261119` in `FEATURE_QUALIFICATION.json`.
