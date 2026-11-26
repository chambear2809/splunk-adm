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

This shell example covers normal exit only. The lock wrapper terminates a
cancelled child process group after five seconds, which can interrupt its EXIT
trap before purge finishes. It does not establish cleanup-before-unlock on
cancellation. For cancellation/deadline exercises, the lifecycle driver must own
a direct `with lab_lock.LabLock(root)` block, retire its child process groups,
and complete cleanup plus durable final receipts before leaving that block.
`run_main` also supervises a child; calling it alone does not remove this caveat.
A crash or forced termination can still require explicit owned-resource recovery.

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

New task containers enforce fixed limits: **4 CPUs, 8 GiB memory, 8 GiB
memory plus swap (no additional swap), 1,024 processes**, and Docker `json-file`
logs capped at 10 MiB per file with two files. Creation and subsequent operations
check the exact effective Docker limits. Existing containers missing those limits
cannot resume installation or testing. `down`/`purge` waive only the resource-limit
check so a legacy lab can still be cleaned up; exact image, recorded ID, labels,
network, mounts, TLS identity and loopback-port guards remain required.

These caps do not impose a named-volume disk quota or a container lifetime.
Declare a task disk budget and lifetime separately, record how each is enforced,
and retain cleanup under the same lock. Cooperative phase checks are not a hard
filesystem quota. A Mac ARM64 Docker engine can support emulated development and
installed functionality checks; it does not establish native AMD64 resource-limit
qualification. Native resource qualification is deferred by the user's current
scope decision (2026-11-17); no remote engine installation is required.

Resource limits and timing conditions belong in each measurement record. Separate
namespaces still share the Docker daemon, CPU, memory and disk. Queue labs on a
small host and disclose other host activity; namespace isolation does not imply
performance isolation. Local Docker measurements do not establish production or
Splunk Cloud qualification.

The test-only [cold case recovery rehearsal](BACKUP_RESTORE.md#installed-cold-case-recovery-rehearsal)
uses `tools/rehearse_case_recovery.py` to hold three direct parent locks across
source, occupied negative target and fresh restore target. It supplies each child
the matching task environment and lock token, runs one heavy container at a time,
retains a verified private archive copy, and attempts every owned cleanup even if
receipt or log storage fails. Its fixed identities, ports, lifetime and disk
budget are documented with that workflow. Do not substitute the older KV reset
driver or rename an existing lab to satisfy its guards.

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


## Opt-in Splunk Web HTTPS qualification

Set `ADM_LAB_WEB_TLS=1` consistently before creation and for installation,
clients, tests and cleanup. New containers then receive fixed Web HTTPS settings
using the same task-bound leaf/CA as management and HEC, following the
[Splunk 10.6 Web TLS settings](https://help.splunk.com/en/splunk-enterprise/administer/admin-manual/10.6/configuration-file-reference/10.6.0-configuration-file-reference/web.conf).
The private bundle stays in the protected host runtime and the owned container
until their verified cleanup; no operating-system/browser trust store, CSRF bypass
or remote host is changed. Default legacy labs keep their existing Web behavior.
The shared client admits the exact Web HTTPS loopback port only with this opt-in
and task identity. Redirect following and proxy-environment use remain refused.

The notes Web HTTP suite additionally requires exactly:

```text
ADM_LAB_TASK=cases-web-20261117
ADM_LAB_NAME=adm-cases-web-20261117
ADM_LAB=1
ADM_LAB_WEB_TLS=1
ADM_LAB_WEB_RECEIPT=/absolute/private/runtime/web-journal.json
```

Choose available loopback ports and set all the ordinary variables above; the
current exercise uses Web 28900, management 28989 and HEC 28988. Run only the
selected `test_cases_web.py` suite in that lab. Other labs skip this explicitly
opted-in suite; an opted-in lab with the wrong identity is refused before fixture
mutation. The journal destination must be new, private and outside every checkout.
It retains exact synthetic case request bodies/idempotency keys, response status,
case IDs/revisions and hashes, but never login bodies, session cookies or CSRF
values. A transport failure preserves unresolved request state. Raw journals
stay outside Git.

This suite authenticates through the installed Web login and uses its cookie
sessions and `/splunkd/__raw` proxy. It exercises native HTTP behavior rather
than rendered-browser interaction. Keep protected-source capture, real-source
access, browser rendering/accessibility, whole-endpoint deadlines and native
resource qualification separate. Check management, HEC and Web TLS independently
before/after installation, including wrong-CA and wrong-hostname rejection.
Retain exact package/container provenance, fixture cleanup and final resource
absence under the same lock. A short bounded port-release wait after container
removal can account for teardown, without treating an occupied port as free.

## Rendered cases UI exercise

`tests/splunk/test_cases_ui.py` is an explicitly opted-in installed Firefox
scenario for the exact `cases-ui-20261117` / `adm-cases-ui-20261117` lab. It
requires `ADM_LAB=1`, `ADM_LAB_WEB_TLS=1`, `ADM_LAB_CASES_UI=1`, the ordinary
consistent task variables, and private external paths in `ADM_LAB_UI_RUNTIME`,
`ADM_LAB_UI_OUTPUT`, and `ADM_LAB_WEB_RECEIPT`. Supply the pinned project Node and
Playwright Firefox executables using `ADM_LAB_NODE`, `ADM_LAB_FIREFOX`, and
`PLAYWRIGHT_BROWSERS_PATH`. `NODE_EXTRA_CA_CERTS` must name only the task's public
CA for Node's forwarded-request transport. The browser uses a new private NSS
profile importing that same public CA; certificate/hostname validation remains
on and operating-system/browser-global trust is unchanged.

The parent lifecycle must hold the direct lab lock throughout execution,
evidence retention and cleanup. Firefox launches detached processes on macOS:
killing only the Python/Node process group does not prove browser exit. The
scenario checkpoints exact browser executable/profile, launch intent, PID,
process group and start identity in a private `browser-processes.json`. The
parent must validate and retire those exact owned groups, prove absence, and
only then remove authenticated profiles. Incomplete or mismatched ownership
must retain uncertainty and refuse a cleanup-success claim. The shell-wrapper
example above alone does not meet this cancellation contract.

The rendered scenario uses real case responses. Its one injected fault forwards
a note write to the installed backend, durably records its successful response,
then drops that response before the page receives it. The UI must retry the same
body/key and show one stored immutable note. No login body, cookie, CSRF value,
authentication trace or HAR is retained. Screenshots and synthetic JSON/Markdown
downloads stay outside Git. Viewport fit is recorded separately from app-internal
containment; native Splunk chrome overflow must not be reported as mobile fit.

The exact-task [case request rehearsal](CASE_REQUEST_SUPERVISION.md#disposable-installed-rehearsal)
uses `tools/rehearse_case_requests.py` for installed notes, deadline and interrupted
write tests. It owns one disposable container and retains the archive, runtime
hashes, TLS checks, private outcome journals and verified cleanup under one parent
lock. Its platform fault hook belongs only to that disposable container and is
excluded from the app archive. Run it with a new empty private runtime directory;
retain failed attempts as evidence. It does not establish native AMD64 resource
enforcement or source-capture qualification.

## Host-wide resource reservations (opt-in)

When coordinating multiple concurrent or queued disposable task labs on one host,
use `tools/lab_resources.py` alongside `tools/lab_lock.py`. It maintains a
per-user host registry at `/tmp/splunk-adm-resource-registry-<uid>.json` (mode
0600, serialized through a `.lock` sidecar with atomic replace and `fsync`) that
reserves unique allocation IDs, task/lab names, five ports, and private paths
across checkouts, and caps active concurrent labs (default capacity 1, override
with `--capacity N` or `ADM_LAB_RESOURCE_CAPACITY=N` only while no active lease
remains).

`python3 tools/lab_resources.py run <manifest> -- <command>` acquires both the
host capacity lease and the per-lab lock (`tools/lab_lock.py`), injects the
manifest's task/lab/port/credentials/runtime/evidence variables and pinned
`DOCKER_HOST` (clearing `DOCKER_CONTEXT`), and exports the active lease identity.
When `SPLUNK_ADM_RESOURCE_LEASE_ID` or `SPLUNK_ADM_RESOURCE_LEASE_TOKEN` is set,
`tests/splunk/lab.sh` runs `python3 tools/lab_resources.py verify-active` before
any lifecycle command and fails closed if the lease is expired, unlocked, or
mismatched against the current task, lab name, ports, or credentials path. Labs
without an active resource lease retain their existing `tools/lab_lock.py` and
`tests/splunk/lab.sh` behavior unchanged. `release <manifest>` removes only the
registry reservation after the operator has separately verified lab cleanup and
retained evidence; it never deletes Docker resources, credentials, or evidence.
