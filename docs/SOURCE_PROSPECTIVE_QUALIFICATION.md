# Prospective source qualification

A replacement cluster can support a future source-completeness exercise, but it
cannot supply missing historical evidence from `k8s-01.uktme.cisco.com`. No
prospective producer, namespace, collection configuration or time window
has yet been selected or qualified. The previous cluster's source identifiers,
configuration revisions, results and hashes must not be carried into a new
qualification as evidence of this cluster's producer population.

The user selected the existing `isovalent-demo` EKS context for a bounded
read-only inventory. The prepared inventory validates that local kubeconfig
context, exact HTTPS endpoint and CA fingerprint before contacting the API. The
initial read-only inventory failed at the caller-identity step before any namespace
inventory was obtained. A bounded diagnostic classified the failure as
authorization or authentication; independently, the existing cached session was
expired. The user is away and can complete the established Duo approval on
return. Namespace and collector selection have not yet been made, and no further
authentication or cluster read is being attempted while approval is pending.

The inventory accepts only the reviewed EKS
`aws eks get-token` command shape for that exact cluster and region; it uses a
fixed executable-resolution path, checks the local launcher, its resolved Python
interpreter and kubectl hashes,
passes no secrets in arguments, validates the selected AWS profile and
source-profile chain against unsupported external credential providers, disables
interactive prompting and does not perform an SSO login. Those executable
hashes do not attest all AWS CLI or Python dependency files. The operator must
coordinate the existing Duo SSO credential renewal before a new inventory attempt.

The first resource step reads effective caller identity and a bounded namespace
inventory. A later explicitly selected namespace and collector name can narrow
reads to that exact namespace, Deployment and ConfigMap. The Deployment response
may contain environment values in memory, but the inventory does not output or
retain them; it does not request Secrets or logs. ConfigMap values are reported
only as hashes. Output caps, deadlines and child retirement bound the probe. A
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
