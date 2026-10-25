# Disposable task labs

The default `tests/splunk/lab.sh` workflow retains its existing name, ports and
lock. A task lab sets **all** of these variables consistently for shell commands,
Python tests, loaders, benchmarks, capture, fault and recovery tooling:

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
The generated credential file is mode 0600. Never copy its contents into evidence.
Worktree-local `dist/` outputs and explicit migration journal/report paths keep
runtime and evidence independent. Shared downloaded archives may be read as
immutable input; extraction and generated fixture output must stay task-local.

`lab.sh up` creates a network `<name>-net` and named volumes `<name>-etc` and
`<name>-var`. Container, network and volumes carry `org.splunk-adm.task` and
`org.splunk-adm.lab` labels. Existing resources with different labels are refused.
Lifecycle operations and REST/HEC access check the container labels, namespace
mounts and all three loopback bindings. Named labs use separate cross-checkout
locks; using a different name does not waive the same-lab ownership lock.

Run tests through the lock with the same environment:

```sh
bash tests/splunk/lab.sh up
bash tests/splunk/lab.sh install
ADM_LAB=1 python3 tools/lab_lock.py --root . -- \
  python3 -m unittest discover -s tests/splunk
bash tests/splunk/lab.sh purge
```

`down` removes the verified container and its labelled network/volumes. `purge`
also removes that lab's credential file. Task labs retain the shared Docker image.
Do not use Docker prune, broad name matches, or another lab's environment.
Retain qualification reports and exact package checksums outside disposable
volumes before cleanup. Record container/image IDs and resource labels in the
task manifest, and verify them before removal.

Resource limits and timing conditions belong in each measurement record. Separate
namespaces still share the Docker daemon, CPU, memory and disk. Queue labs on a
small host and disclose other host activity; namespace isolation does not imply
performance isolation. Local Docker measurements do not establish production or
Splunk Cloud qualification.
