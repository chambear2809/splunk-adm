# Disposable task labs

New disposable labs require an explicit task identity and a protected runtime
directory outside every Git checkout. Set **all** of these variables consistently
for shell commands, Python tests, loaders and qualification tooling:

```sh
export ADM_LAB_TASK=my-task
export ADM_LAB_NAME=adm-my-task-worker
export ADM_LAB_WEB_PORT=28000
export ADM_LAB_MGMT_PORT=28089
export ADM_LAB_HEC_PORT=28088
export ADM_LAB_SECRETS=/absolute/private/runtime/credentials
export ADM_LAB_EXTRACTED=/absolute/read-only/research/extracted
```

Use distinct available ports and a protected runtime directory for each lab.
The generated credential file is mode 0600. Its adjacent `.tls` directory is
mode 0700, with mode-0600 identity, public CA, private server bundle and recorded
container ID. Never copy credential or private key contents into evidence.
Worktree-local `dist/` outputs and explicit migration journal/report paths keep
runtime and evidence independent. Shared downloaded archives may be read as
immutable input; extraction and generated fixture output must stay task-local.

Task operations require a local Docker Unix socket. The effective context takes
precedence over `DOCKER_HOST`; after verification, shell and Python operations
pin the same endpoint and refuse remote TCP/SSH contexts.

`lab.sh up` creates a network `<name>-net` and named volumes `<name>-etc` and
`<name>-var`. Container, network and volumes carry `org.splunk-adm.task` and
`org.splunk-adm.lab` labels. Existing resources with different labels are refused.
Lifecycle operations and REST/HEC access check the recorded exact container ID,
labels, namespace mounts, pinned image and all three loopback bindings. A renamed
or replaced peer is refused. Named labs use separate cross-checkout
locks; using a different name does not waive the same-lab ownership lock.

Hold the same lab lock across the entire lifecycle, including installation,
qualification and cleanup. For example, save the following body in a protected
external task script and run it through
`python3 tools/lab_lock.py --root . -- bash /absolute/private/runtime/run.sh`
with the environment above:

```sh
set -euo pipefail
trap 'bash tests/splunk/lab.sh purge' EXIT
bash tests/splunk/lab.sh up
bash tests/splunk/lab.sh install
ADM_LAB=1 python3 -m unittest discover -s tests/splunk -p test_baselines_endpoint.py
```

Select tests whose data, configuration and identity prerequisites have been
prepared. The example checks the baseline host's disabled/source-unavailable
contract. Other suites require different fixtures; the protected evidence suite
also requires its explicitly named qualification task. Honor those guards rather
than changing a generic lab's identity after creation.

`down` removes the verified container and its labelled network/volumes. `purge`
also removes that lab's credential file and exact validated TLS material. Task
labs retain the shared Docker image. `up` can resume an existing recorded peer;
after `down` removed it, purge the retained identity before creating a fresh
peer. Missing, expired or mismatched trust never triggers automatic replacement.
Do not use Docker prune, broad name matches, or another lab's environment.
Retain qualification reports and exact package checksums outside disposable
volumes before cleanup. Record container/image IDs and resource labels in the
task manifest, and verify them before removal.

Resource limits and timing conditions belong in each measurement record. Separate
namespaces still share the Docker daemon, CPU, memory and disk. Queue labs on a
small host and disclose other host activity; namespace isolation does not imply
performance isolation. Local Docker measurements do not establish production or
Splunk Cloud qualification.

## Verified qualification traffic

The lab pins the reviewed Splunk 10.6.0.5 image digest. Before initial startup,
it creates a private two-day CA and a certificate with loopback, localhost and
the task container name as subject alternatives. The CA signing key and scratch
files are erased. Fixed management and HEC certificate configuration is copied
into the newly created, verified container through stdin; private leaves are
0600, owned by the pinned image's Splunk UID. A failed pre-start copy must succeed
on retry before the container may start.

The image's default health check skips certificate verification, so task labs
disable that image check, wait for the pinned image's fixed startup marker through
the recorded local container, and then use the verified management API for
readiness. A management listener alone does not prove bootstrap is complete.
The shared lab transport and dedicated case/baseline endpoint checks require
the private CA and hostname verification,
ignore proxy environment settings, reject redirects, and accept only the exact
loopback HTTPS ports. No insecure fallback is provided. Existing labs without
this task-bound material are not automatically reconfigured. This qualifies the
explicit test traffic; it does not assert that every vendor bootstrap-internal
operation has been audited for TLS behavior.

Check management and HEC handshakes separately before and after installation,
and demonstrate rejection of a wrong CA and hostname. Record those outcomes,
the exact package hash and the installed tests. Direct management endpoint tests
do not qualify Splunk Web proxy or CSRF behavior. Keep those checks separate.
