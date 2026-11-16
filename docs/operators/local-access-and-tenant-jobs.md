# Local access and tenant-jobs collection

This is a retained **lab runbook**, not a portable deployment contract. The
telemetry YAML is a render-required example: replace every `__REQUIRED_*__`
placeholder for the target namespace, cluster, source, HEC address/port and TLS
name; create its token Secret and CA ConfigMap separately; then validate the
rendered YAML before applying. Do not copy the lab values below into another
environment.

This workstation's operator configuration lives outside Git. Do not paste or
commit the files below. Configuration validation prints booleans and error codes,
never passwords, tokens, certificates or raw events.

| File                                                    | Purpose                                                            |
| ------------------------------------------------------- | ------------------------------------------------------------------ |
| `~/.kube/splunk-adm/config`                             | Supplied cluster-admin kubeconfig, mode 0600, directory 0700       |
| `fixtures/kubeconfig`                                   | Gitignored compatibility symlink to that external kubeconfig       |
| `~/.splunk/splunk-adm/credentials`                      | Mode-0600 profiled credentials; Enterprise is the explicit default |
| `~/.splunk/splunk-adm/enterprise-tenant-jobs-hec.token` | Enterprise-only token, restricted to `otel_traces`                 |

`fixtures/` is for synthetic test data. A real kubeconfig is runtime access
configuration. The supplied file was initially mode 0644 and unignored; it has
been secured, moved outside the checkout, and its original path ignored.

## Select the environment explicitly

The canonical file uses the vendored helper's `PROFILE_<name>__KEY=value` format.
Values are static data, not shell code. Select it explicitly rather than relying
on an older worktree's vendored `credentials` file:

```sh
export KUBECONFIG="$HOME/.kube/splunk-adm/config"
export SPLUNK_CREDENTIALS_FILE="$HOME/.splunk/splunk-adm/credentials"
export SPLUNK_PROFILE=enterprise
python3 tools/check_local_access.py
```

For target-specific assertions, pass an owner-only nonsecret JSON file explicitly:

```sh
python3 tools/check_local_access.py --expectations /path/to/target-expectations.json
```

Without `--expectations`, the checker performs only portable profile and security
validation; it does not assume a host, certificate name, CA path or HEC address.

Run vendored setup commands from `vendor/splunk-cisco-skills`, as documented in
the repository guidelines. Do not `source` the credential file. Change only
`SPLUNK_PROFILE` to select another target. The helper command above validates
local structure and file protections; it does not authenticate or establish
network reachability.

### Historical lab validation (2026-11-02)

The following values describe the original lab run only; they are not defaults
or portable requirements:

| Profile      | Target                                                                     | Historical result                                                                                                                                    |
| ------------ | -------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| `enterprise` | Standalone `10.237.100.70`, API over pinned SSH and verified localhost TLS | Authentication passed; HEC TLS verified directly from the cluster                                                                                    |
| `cloud`      | `<stack>.splunkcloud.com:8089`                              | Authentication passed over verified HTTPS; trace destination forbidden                                                                               |
| `hf`         | Heavy forwarder `10.110.253.20`                                            | Recovered target/password and existing SSH host-key record; live authentication and certificate validation deferred until the other VPN is available |

Cloud and HF are separate targets even though HF forwards to Cloud. Do not set
`SPLUNK_SEARCH_PROFILE=hf` while attempting a Cloud-only operation on the current
VPN. The prior ACS bearer returned 401 and was omitted from the canonical file;
Cloud REST authentication works, but ACS provisioning is not qualified. An older
vendor file's disabled TLS verification and malformed trailing-dot stack name
were not copied into the canonical profiles. Original custody files were retained.

The Enterprise API URI's certificate name is `SplunkServerDefaultCert`. Access
it on the server through pinned SSH; its CA path is remote, not a local file.
Never disable verification to make an IP-address connection succeed.

## Enterprise-only application traces

In that historical run, the selected application was `tenant-jobs` and
`retail-store` remained unchanged. The cluster context was
`kubernetes-admin@kubernetes`, API server
`https://k8s-01.uktme.cisco.com:6443`. The existing shared collector is 0.140.0
and was not upgraded or reconfigured.

The remaining collection and certificate details in this section are likewise
historical lab evidence, not portable defaults.

[The collector manifest](../../templates/tenant-jobs-telemetry.yaml) creates an
isolated collector, namespaced pod-read RBAC, a ClusterIP service, and narrowly
scoped Cilium telemetry egress rules. Its image is pinned to the exact digest
already running in the cluster. It accepts OTLP only from the same namespace,
filters other namespaces from trace processing, and exports only to
`10.237.100.70:8088` with the server CA and verified certificate name. There is
no Cloud exporter or Cloud egress rule. The service account's effective checks
denied secret reads and pod patches in `retail-store`.

The `atlas-enterprise-ca` ConfigMap contains the public CA fetched over pinned
SSH. `atlas-telemetry-hec` contains the dedicated Enterprise HEC credential;
its value never appears in the manifest. Create/update it only from the protected
token file. The Enterprise index has a 1,024-MB cap and seven-day retention for
this lab collection. The existing Enterprise HEC inputs were preserved.

The original HEC leaf had only a legacy Common Name. Python 3.12 accepted it,
but the Collector's Go TLS verifier correctly rejected its missing SAN. A new
90-day RSA-3072 HEC-only leaf was signed by the same existing lab CA, with DNS
SANs `SplunkServerDefaultCert` and `ubuntu24-splunk`, plus IP SANs `10.237.100.70`
and `198.18.134.124`. It expires **2027-01-31 19:13:03 UTC**. Its private key
stayed on Enterprise in a mode-0600 bundle under a mode-0700 directory.

Only `[http] serverCert` and the empty passphrase setting for that unencrypted,
protected key were added to HEC configuration. All other original configuration
bytes were preserved. The documented
[HEC certificate reload](https://help.splunk.com/en/splunk-enterprise/administer/manage-users-and-security/10.4/secure-splunk-platform-communications-with-transport-layer-security-certificates/renew-existing-tls-certificates)
returned HTTP 200; the served leaf fingerprint matched the prepared leaf and
the Splunk daemon PIDs were unchanged. No full Splunk restart occurred. Existing
HEC input enablement and index restrictions remained unchanged. Management TLS,
the original server certificate and CA were not replaced.

The new leaf bundle is
`/opt/splunk/etc/auth/atlas-tenant-jobs-hec-20261102/hec.pem`; the protected
original configuration, proposed configuration and activation receipt are in
`/opt/splunk/var/atlas-tenant-jobs-hec-20261102/`. Certificate rollback must first
check for later configuration edits, restore only the two managed settings, then
repeat the documented HEC reload and verify the served certificate. Do not
blindly restore the full backup over later token changes. Renew this lab leaf
before its stated expiry; no renewal automation was installed.

The manifest defaults to **zero replicas** so applying it alone cannot silently
start collection. Validate its embedded configuration in the exact pinned image
with the CA mounted, verify HEC TLS from the cluster, then explicitly scale the
reviewed deployment to one replica. Kubernetes server-side dry-run checks resource
schemas; it does not validate the embedded Collector configuration.

The six application deployments are `coreapi`, `crawler`, `jobposting`, `loader`,
`recruiter` and `resumes`. Only their tracing configuration is managed: existing
tracing/export flags, collector endpoint/protocol, explicit service/environment
attributes and downward-API namespace/pod UID. `LOG_SPANS` stays false. Other
environment values, images, application traffic settings, databases and operators
are preserved. The selected environment label is explicitly `lab`.

The trace source is `atlas:k8s:uktme:tenant-jobs`, sourcetype `otel:traces`, index
`otel_traces`. The collector copies source resource identity into raw span
attributes prefixed `atlas.resource.` so HEC metadata extraction is not the only
retained identity evidence. This collection does not establish historical pod-IP
ownership, enable Atlas schedules, or qualify the application map. The qualified
identity producer and its bindings require separate deployment and validation.
The collector's retry queue is memory-backed; this lab setup does not guarantee
lossless delivery across collector restarts or prolonged destination outages.

## Recovery and evidence

Protected original workload environments, guarded JSON patches, apply/restore
receipts and validation configuration are retained under
`~/.splunk/splunk-adm/runs/20261102-tenant-jobs/`, mode 0700. Do not copy these
runtime artifacts into Git. Workload updates test UID, resourceVersion and prior
environment state before applying. Kubernetes adds `apiVersion: v1` defaults to
downward-API references; normalize only that default when comparing snapshots.

To stop collection immediately, scale `deployment/atlas-telemetry` in
`tenant-jobs` to zero. Restore only the managed environment keys from the protected
snapshot after verifying workload UID and current managed values; preserve any
later unrelated edits. Remove only this task's owned resources and Cilium rules
after confirming their UIDs. Do not delete indexed data, shared collectors,
existing HEC inputs, or the existing Cloud token. Revoke the dedicated Enterprise
HEC token only when permanently retiring this collection.

The initial destination selection was Cloud. The collector was stopped and all
six application environments restored when the operator corrected the destination.
No Cloud egress rules were applied. A bounded Cloud search then returned zero
events from this source. The task's collector Secret was replaced with the
Enterprise token and its configuration changed to Enterprise before collection
was enabled again. Cloud is not an application trace destination for this task.

## Validation results

On 2026-11-02, local validation passed for all three profile structures and the
kubeconfig. Ten synthetic Python tests passed, including literal-secret parsing,
profile isolation, conflicting endpoint aliases, strict HTTPS, permissions,
unsafe kubeconfig authentication providers, and rejection of a Cloud HEC URL in
the Enterprise profile. Ruff check and formatting passed. The manifest passed
server-side dry-run and exact-image native configuration validation with the CA
mounted. Independent review found no remaining actionable findings.

At the 14:19 EST checkpoint, all six application deployments and the collector
were ready; tracing/export flags were enabled, raw-span logging was disabled,
the live collector had no Cloud exporter, and its Secret matched the dedicated
Enterprise token. A completed bounded Enterprise search observed **14,768 span
events**: `coreapi` 2,768; `crawler` 2,368; `loader` 4,736; `resumes` 4,896. These
are event counts, not unique trace counts or complete application coverage.
`jobposting` and `recruiter` were enabled but had no indexed spans at that check.
Thirty sampled raw spans retained `start_time`/`end_time` and the expected
`atlas.resource.*` service, environment, cluster, namespace and pod UID fields.

Queries checked HTTP status, non-preview completion and warning/time-limit
messages before interpreting results. A later bounded read confirmed fresh
Hypershield receipts after the HEC reload. This does not qualify every original
feed's continuity. No Atlas schedule, identity binding or catalog/map projection
was enabled by this task. Temporary validation pods and ConfigMaps were removed
with UID-preconditioned deletes; the running collection resources were retained.
