"""Offline resource registry and lease tests; these tests never contact Docker."""

import gc
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from unittest.mock import patch

from tools import lab_resources


class LabResourcesTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.worktree = self.root / "worktree"
        self.worktree.mkdir(mode=0o700)
        self.registry = self.root / "resource-registry.json"

    def manifest(self, *, suffix="one", name=None, ports=None, lease=None):
        lab_name = name or f"adm-resource-test-{suffix}-{uuid.uuid4().hex[:8]}"
        base_port = 24000 + (len(suffix) * 10)
        selected_ports = ports or {
            "web_port": base_port,
            "management_port": base_port + 1,
            "hec_port": base_port + 2,
            "preview_port": base_port + 3,
            "browser_harness_port": base_port + 4,
        }
        runtime = self.root / f"private-{suffix}" / "runtime"
        evidence = self.root / f"private-{suffix}" / "evidence"
        manifest = {
            "program_id": "change-correlation",
            "workstream_id": suffix,
            "agent_id": "/root/" + suffix,
            "model": "gpt-6-luna",
            "reasoning_effort": "max",
            "base_commit": "a" * 40,
            "branch": "codex/change-" + suffix,
            "absolute_worktree_path": str(self.worktree),
            "allowed_write_paths": ["tools/lab_resources.py", "docs/TASK_LABS.md"],
            "lab_task": "change-correlation-" + suffix,
            "lab_name": lab_name,
            "docker_endpoint": "unix:///tmp/fake-docker.sock",
            **selected_ports,
            "runtime_directory": str(runtime),
            "credentials_path": str(runtime / "credentials"),
            "network_name": lab_name + "-net",
            "volume_names": [lab_name + "-etc", lab_name + "-var"],
            "container_id": None,
            "image_digest": None,
            "package_sha256": None,
            "fixture_manifest_sha256": None,
            "evidence_directory": str(evidence),
            "resource_lease": lease or f"lease-{suffix}-{uuid.uuid4().hex}",
        }
        path = self.root / f"allocation-{suffix}-{uuid.uuid4().hex}.json"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        path.chmod(0o600)
        return path, manifest

    def allocation(self, **kwargs):
        path, _ = self.manifest(**kwargs)
        return lab_resources.validate_allocation(path)

    @staticmethod
    def cleanup_process(process):
        try:
            if process.poll() is None:
                process.kill()
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=10)
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None and not stream.closed:
                stream.close()

    @staticmethod
    def cleanup_quarantined_lease(registry_path, lease_id):
        retained = lab_resources._QUARANTINED_ACTIVE_LOCKS.pop(lease_id, None)
        if retained is None:
            return
        try:
            with lab_resources._RegistryFile(registry_path) as file:
                state = file.read()
                entry = next(
                    (
                        item
                        for item in state["allocations"]
                        if item["reservation"]["resource_lease"] == lease_id
                    ),
                    None,
                )
                if entry is not None and entry["active"] is not None:
                    entry["active"] = None
                    file.write(state)
        finally:
            retained.release()

    def test_manifest_validates_all_five_ports_and_private_paths(self):
        path, _ = self.manifest()
        allocation = lab_resources.validate_allocation(path)
        self.assertEqual(len(allocation.ports), 5)
        self.assertFalse(allocation.runtime_directory.exists())
        self.assertFalse(allocation.evidence_directory.exists())

    def test_manifest_rejects_port_alias_and_invalid_resource_names(self):
        path, manifest = self.manifest()
        manifest["preview_port"] = manifest["web_port"]
        path.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaisesRegex(
            lab_resources.LabResourceError, "five allocated ports"
        ):
            lab_resources.validate_allocation(path)

        path, manifest = self.manifest(suffix="bad")
        manifest["network_name"] = "another-net"
        path.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaisesRegex(lab_resources.LabResourceError, "network_name"):
            lab_resources.validate_allocation(path)

    def test_distinct_allocations_reserve_disjoint_names_ports_and_paths(self):
        first = self.allocation(suffix="first")
        second = self.allocation(
            suffix="second",
            ports={
                "web_port": 24100,
                "management_port": 24101,
                "hec_port": 24102,
                "preview_port": 24103,
                "browser_harness_port": 24104,
            },
        )
        self.assertEqual(
            lab_resources.reserve_allocation(
                first, registry_path=self.registry, capacity=2
            ),
            2,
        )
        self.assertEqual(
            lab_resources.reserve_allocation(second, registry_path=self.registry), 2
        )
        registry = json.loads(self.registry.read_text(encoding="utf-8"))
        self.assertEqual(len(registry["allocations"]), 2)
        self.assertEqual(registry["capacity"], 2)
        for allocation in (first, second):
            self.assertEqual(allocation.runtime_directory.stat().st_mode & 0o777, 0o700)
            self.assertEqual(
                allocation.evidence_directory.stat().st_mode & 0o777, 0o700
            )

    def test_reservation_refuses_same_name_and_preview_port_collisions(self):
        first = self.allocation(suffix="first")
        lab_resources.reserve_allocation(first, registry_path=self.registry, capacity=2)

        second_path, second_manifest = self.manifest(
            suffix="second", name=first.lab_name
        )
        second_manifest["resource_lease"] = "different-lease-id"
        second_path.write_text(json.dumps(second_manifest), encoding="utf-8")
        second = lab_resources.validate_allocation(second_path)
        with self.assertRaisesRegex(lab_resources.LabResourceError, "lab name"):
            lab_resources.reserve_allocation(second, registry_path=self.registry)

        third_ports = {
            "web_port": 25000,
            "management_port": 25001,
            "hec_port": 25002,
            "preview_port": first.values["preview_port"],
            "browser_harness_port": 25004,
        }
        third = self.allocation(suffix="third", ports=third_ports)
        with self.assertRaisesRegex(lab_resources.LabResourceError, "port"):
            lab_resources.reserve_allocation(third, registry_path=self.registry)

    def test_active_capacity_is_shared_and_reservations_survive_release(self):
        first = self.allocation(suffix="first")
        second = self.allocation(
            suffix="second",
            ports={
                "web_port": 25100,
                "management_port": 25101,
                "hec_port": 25102,
                "preview_port": 25103,
                "browser_harness_port": 25104,
            },
        )
        third = self.allocation(
            suffix="third",
            ports={
                "web_port": 25200,
                "management_port": 25201,
                "hec_port": 25202,
                "preview_port": 25203,
                "browser_harness_port": 25204,
            },
        )
        lab_resources.reserve_allocation(third, registry_path=self.registry)
        with lab_resources.resource_lease(
            first, registry_path=self.registry, capacity=2
        ) as first_lease:
            self.assertEqual(first_lease["capacity"], 2)
            with lab_resources.resource_lease(second, registry_path=self.registry):
                with self.assertRaisesRegex(
                    lab_resources.LabResourceError, "capacity is full"
                ):
                    with lab_resources.resource_lease(
                        third, registry_path=self.registry
                    ):
                        self.fail("third active lease exceeded capacity")

        state = json.loads(self.registry.read_text(encoding="utf-8"))
        self.assertEqual(len(state["allocations"]), 3)
        self.assertTrue(all(item["active"] is None for item in state["allocations"]))
        lab_resources.release_allocation(first, registry_path=self.registry)
        self.assertTrue(first.runtime_directory.exists())
        self.assertTrue(first.evidence_directory.exists())

    def test_same_allocation_active_in_an_independent_context_is_refused(self):
        allocation = self.allocation()
        with lab_resources.resource_lease(allocation, registry_path=self.registry):
            with patch.dict(os.environ):
                for key in (
                    lab_resources.ENV_LEASE_ID,
                    lab_resources.ENV_LEASE_TOKEN,
                    lab_resources.ENV_LEASE_PID,
                    lab_resources.ENV_LEASE_START,
                    lab_resources.ENV_REGISTRY,
                ):
                    os.environ.pop(key, None)
                with self.assertRaisesRegex(
                    lab_resources.LabResourceError, "already has an active"
                ):
                    with lab_resources.resource_lease(
                        allocation, registry_path=self.registry
                    ):
                        self.fail("same allocation acquired twice")

    def test_stale_lease_recovery_keeps_persistent_reservation(self):
        allocation = self.allocation()
        lab_resources.reserve_allocation(
            allocation, registry_path=self.registry, capacity=2
        )
        token = "f" * 32
        active = {
            "pid": os.getpid(),
            "start_time": "old-process-start",
            "token": token,
            "capacity": 2,
            "started_at": "2026-10-27T00:00:00+00:00",
        }
        state = json.loads(self.registry.read_text(encoding="utf-8"))
        state["allocations"][0]["active"] = active
        self.registry.write_text(json.dumps(state), encoding="utf-8")
        sidecar = lab_resources._active_lock_path(self.registry, allocation.lease_id)
        sidecar.write_text(
            json.dumps(
                {
                    "pid": active["pid"],
                    "start_time": active["start_time"],
                    "token": token,
                }
            ),
            encoding="utf-8",
        )
        sidecar.chmod(0o600)

        with patch.object(
            lab_resources, "_process_start_time", return_value="new-process-start"
        ):
            lab_resources.reserve_allocation(allocation, registry_path=self.registry)
        state = json.loads(self.registry.read_text(encoding="utf-8"))
        self.assertEqual(len(state["allocations"]), 1)
        self.assertIsNone(state["allocations"][0]["active"])

    def test_stale_lease_token_mismatch_fails_closed(self):
        allocation = self.allocation()
        lab_resources.reserve_allocation(allocation, registry_path=self.registry)
        active = {
            "pid": 99999999,
            "start_time": "old-process-start",
            "token": "f" * 32,
            "capacity": 1,
            "started_at": "2026-10-27T00:00:00+00:00",
        }
        state = json.loads(self.registry.read_text(encoding="utf-8"))
        state["allocations"][0]["active"] = active
        self.registry.write_text(json.dumps(state), encoding="utf-8")
        sidecar = lab_resources._active_lock_path(self.registry, allocation.lease_id)
        sidecar.write_text(
            json.dumps(
                {
                    "pid": active["pid"],
                    "start_time": active["start_time"],
                    "token": "0" * 32,
                }
            ),
            encoding="utf-8",
        )
        sidecar.chmod(0o600)

        with self.assertRaisesRegex(lab_resources.LabResourceError, "token/start"):
            lab_resources.reserve_allocation(allocation, registry_path=self.registry)
        state = json.loads(self.registry.read_text(encoding="utf-8"))
        self.assertIsNotNone(state["allocations"][0]["active"])

    def test_active_lease_metadata_symlink_is_refused(self):
        allocation = self.allocation()
        victim = self.root / "victim"
        victim.write_text("preserve", encoding="utf-8")
        sidecar = lab_resources._active_lock_path(self.registry, allocation.lease_id)
        sidecar.symlink_to(victim)

        with self.assertRaisesRegex(
            lab_resources.LabResourceError, "unsafe active lease"
        ):
            with lab_resources.resource_lease(allocation, registry_path=self.registry):
                self.fail("symlinked active metadata was accepted")
        self.assertEqual(victim.read_text(encoding="utf-8"), "preserve")

    def test_registry_rejects_symlink_and_hardlink_metadata(self):
        allocation = self.allocation()
        victim = self.root / "victim"
        victim.write_text("preserve", encoding="utf-8")
        symlink_registry = self.root / "symlink-registry.json"
        symlink_registry.symlink_to(victim)
        with self.assertRaisesRegex(
            lab_resources.LabResourceError, "unsafe resource registry"
        ):
            lab_resources.reserve_allocation(allocation, registry_path=symlink_registry)
        self.assertEqual(victim.read_text(encoding="utf-8"), "preserve")

        lock_path = self.root / "protected-registry.json.lock"
        lock_path.symlink_to(victim)
        with self.assertRaisesRegex(
            lab_resources.LabResourceError, "unsafe resource registry lock"
        ):
            lab_resources.reserve_allocation(
                allocation,
                registry_path=self.root / "protected-registry.json",
            )
        self.assertEqual(victim.read_text(encoding="utf-8"), "preserve")

        linked_lock = self.root / "hardlinked-registry.json.lock"
        os.link(victim, linked_lock)
        with self.assertRaisesRegex(
            lab_resources.LabResourceError, "unsafe resource registry lock"
        ):
            lab_resources.reserve_allocation(
                allocation,
                registry_path=self.root / "hardlinked-registry.json",
            )
        self.assertEqual(victim.read_text(encoding="utf-8"), "preserve")

        hardlink_registry = self.root / "hardlink-registry.json"
        os.link(victim, hardlink_registry)
        with self.assertRaisesRegex(
            lab_resources.LabResourceError, "unsafe resource registry"
        ):
            lab_resources.reserve_allocation(
                allocation, registry_path=hardlink_registry
            )
        self.assertEqual(victim.read_text(encoding="utf-8"), "preserve")

    def test_existing_empty_registry_fails_closed(self):
        allocation = self.allocation()
        self.registry.write_bytes(b"")

        with self.assertRaisesRegex(lab_resources.LabResourceError, "empty"):
            lab_resources.reserve_allocation(allocation, registry_path=self.registry)

        self.assertEqual(self.registry.read_bytes(), b"")

    def test_subprocess_atomic_write_failure_preserves_committed_registry(self):
        first = self.allocation(suffix="first")
        second = self.allocation(
            suffix="second",
            ports={
                "web_port": 25300,
                "management_port": 25301,
                "hec_port": 25302,
                "preview_port": 25303,
                "browser_harness_port": 25304,
            },
        )
        lab_resources.reserve_allocation(first, registry_path=self.registry, capacity=2)
        committed = self.registry.read_bytes()
        script = "\n".join(
            [
                "import sys",
                "from tools import lab_resources",
                "allocation = lab_resources.validate_allocation(sys.argv[1])",
                "def fail_replace(*args):",
                "    raise OSError('injected interrupted atomic replace')",
                "lab_resources.os.replace = fail_replace",
                "try:",
                "    lab_resources.reserve_allocation(",
                "        allocation, registry_path=sys.argv[2], capacity=2",
                "    )",
                "except lab_resources.LabResourceError as exc:",
                "    print(exc)",
                "else:",
                "    raise SystemExit('fault injection did not fail')",
            ]
        )
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                script,
                str(second.manifest_path),
                str(self.registry),
            ],
            cwd=Path(__file__).parents[1],
            capture_output=True,
            text=True,
            timeout=10,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("unable to atomically write resource registry", result.stdout)
        self.assertEqual(self.registry.read_bytes(), committed)
        registry = json.loads(self.registry.read_text(encoding="utf-8"))
        self.assertEqual(
            [item["reservation"]["resource_lease"] for item in registry["allocations"]],
            [first.lease_id],
        )

    def test_subprocesses_serialize_across_registry_atomic_replace(self):
        first = self.allocation(suffix="first")
        second = self.allocation(
            suffix="second",
            ports={
                "web_port": 25400,
                "management_port": 25401,
                "hec_port": 25402,
                "preview_port": 25403,
                "browser_harness_port": 25404,
            },
        )
        script = "\n".join(
            [
                "import sys",
                "from tools import lab_resources",
                "allocation = lab_resources.validate_allocation(sys.argv[1])",
                "registry_path = sys.argv[2]",
                "with lab_resources._RegistryFile(registry_path, initial_capacity=2) as file:",
                "    registry = file.read()",
                "    registry['capacity'] = 2",
                "    registry['allocations'].append({",
                "        'reservation': allocation.reservation(), 'active': None",
                "    })",
                "    file.write(registry)",
                "    print('committed-and-still-locked', flush=True)",
                "    sys.stdin.readline()",
            ]
        )
        first_process = subprocess.Popen(
            [
                sys.executable,
                "-c",
                script,
                str(first.manifest_path),
                str(self.registry),
            ],
            cwd=Path(__file__).parents[1],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.addCleanup(self.cleanup_process, first_process)
        self.assertEqual(
            first_process.stdout.readline().strip(), "committed-and-still-locked"
        )

        second_process = subprocess.Popen(
            [
                sys.executable,
                str(Path(__file__).parents[1] / "tools/lab_resources.py"),
                "reserve",
                str(second.manifest_path),
                "--registry",
                str(self.registry),
                "--capacity",
                "2",
            ],
            cwd=Path(__file__).parents[1],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.addCleanup(self.cleanup_process, second_process)
        try:
            time.sleep(0.15)
            self.assertIsNone(
                second_process.poll(),
                "second writer bypassed the stable sidecar lock after registry replace",
            )
        finally:
            first_process.stdin.write("continue\n")
            first_process.stdin.flush()
            first_process.stdin.close()

        first_stdout, first_stderr = first_process.communicate(timeout=10)
        second_stdout, second_stderr = second_process.communicate(timeout=10)
        self.assertEqual(first_process.returncode, 0, first_stderr or first_stdout)
        self.assertEqual(second_process.returncode, 0, second_stderr or second_stdout)
        registry = json.loads(self.registry.read_text(encoding="utf-8"))
        self.assertEqual(
            {item["reservation"]["resource_lease"] for item in registry["allocations"]},
            {first.lease_id, second.lease_id},
        )

    def test_registry_contention_timeout_restores_environment_and_keeps_lock_safe(self):
        allocation = self.allocation(suffix="contended")
        registry_lock_path = self.registry.with_name(self.registry.name + ".lock")
        saved_environment = {
            key: f"before-{key}"
            for key in (
                lab_resources.ENV_LEASE_ID,
                lab_resources.ENV_LEASE_TOKEN,
                lab_resources.ENV_LEASE_PID,
                lab_resources.ENV_LEASE_START,
                lab_resources.ENV_REGISTRY,
            )
        }
        lock_script = "\n".join(
            [
                "import fcntl, sys, time",
                "with open(sys.argv[1], 'r+b') as stream:",
                "    fcntl.flock(stream.fileno(), fcntl.LOCK_EX)",
                "    print('locked', flush=True)",
                "    time.sleep(0.6)",
            ]
        )
        with patch.dict(os.environ, saved_environment):
            with self.assertRaisesRegex(RuntimeError, "command failed"):
                with patch.object(lab_resources, "REGISTRY_LOCK_TIMEOUT_SECONDS", 0.08):
                    with lab_resources.resource_lease(
                        allocation, registry_path=self.registry
                    ):
                        holder = subprocess.Popen(
                            [
                                sys.executable,
                                "-c",
                                lock_script,
                                str(registry_lock_path),
                            ],
                            stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            text=True,
                        )
                        self.addCleanup(self.cleanup_process, holder)
                        self.assertEqual(holder.stdout.readline().strip(), "locked")
                        raise RuntimeError("command failed")

            self.assertEqual(
                {key: os.environ.get(key) for key in saved_environment},
                saved_environment,
            )
            self.assertIn(allocation.lease_id, lab_resources._QUARANTINED_ACTIVE_LOCKS)

        holder.wait(timeout=10)
        # The timeout is intentionally fail-closed. Reset only this test's
        # private registry entry, then release its retained OS lock.
        with lab_resources._RegistryFile(self.registry) as file:
            registry = file.read()
            entry = next(
                item
                for item in registry["allocations"]
                if item["reservation"]["resource_lease"] == allocation.lease_id
            )
            entry["active"] = None
            file.write(registry)
        retained = lab_resources._QUARANTINED_ACTIVE_LOCKS.pop(allocation.lease_id)
        retained.release()

    def test_process_control_during_cleanup_quarantines_live_lease_lock(self):
        for exception_type in (KeyboardInterrupt, SystemExit):
            with self.subTest(exception=exception_type.__name__):
                suffix = exception_type.__name__.lower()
                allocation = self.allocation(suffix=suffix)
                other = self.allocation(
                    suffix=f"{suffix}-other",
                    ports={
                        "web_port": 25500,
                        "management_port": 25501,
                        "hec_port": 25502,
                        "preview_port": 25503,
                        "browser_harness_port": 25504,
                    },
                )
                registry_path = self.root / f"{suffix}-registry.json"
                self.addCleanup(
                    self.cleanup_quarantined_lease, registry_path, allocation.lease_id
                )
                registry = lab_resources.ResourceRegistry(registry_path, capacity=2)
                original_locked = registry._locked
                attempts = 0
                injected = exception_type(f"injected {suffix} during cleanup")

                def interrupt_cleanup(*, initial_capacity=1):
                    nonlocal attempts
                    attempts += 1
                    if attempts == 2:
                        raise injected
                    return original_locked(initial_capacity=initial_capacity)

                saved_environment = {
                    key: f"restore-{suffix}-{key}"
                    for key in (
                        lab_resources.ENV_LEASE_ID,
                        lab_resources.ENV_LEASE_TOKEN,
                        lab_resources.ENV_LEASE_PID,
                        lab_resources.ENV_LEASE_START,
                        lab_resources.ENV_REGISTRY,
                    )
                }
                with patch.dict(os.environ, saved_environment):
                    with patch.object(
                        registry, "_locked", side_effect=interrupt_cleanup
                    ):
                        try:
                            with registry.active(allocation):
                                raise RuntimeError("enclosed command failed")
                        except BaseException as caught:
                            self.assertIs(caught, injected)
                        else:
                            self.fail(
                                "cleanup process-control exception was suppressed"
                            )

                    self.assertEqual(
                        {key: os.environ.get(key) for key in saved_environment},
                        saved_environment,
                    )
                    self.assertIn(
                        allocation.lease_id,
                        lab_resources._QUARANTINED_ACTIVE_LOCKS,
                    )
                    gc.collect()

                    state = json.loads(registry_path.read_text(encoding="utf-8"))
                    active_entry = next(
                        item
                        for item in state["allocations"]
                        if item["reservation"]["resource_lease"] == allocation.lease_id
                    )
                    self.assertIsNotNone(active_entry["active"])
                    probe = lab_resources._ProcessLeaseLock(
                        lab_resources._active_lock_path(
                            registry_path, allocation.lease_id
                        )
                    )
                    self.assertFalse(probe.acquire())

                    # The quarantined lease keeps one capacity slot occupied,
                    # while a distinct allocation can still use slot two.
                    registry.reserve(other)
                    with registry.active(other) as other_lease:
                        self.assertEqual(other_lease["capacity"], 2)
                        state = json.loads(registry_path.read_text(encoding="utf-8"))
                        self.assertEqual(
                            sum(
                                item["active"] is not None
                                for item in state["allocations"]
                            ),
                            2,
                        )

                # Remove only this test's registry entry while the retained
                # lock is still held, then release the quarantined descriptor.
                with lab_resources._RegistryFile(registry_path) as file:
                    state = file.read()
                    active_entry = next(
                        item
                        for item in state["allocations"]
                        if item["reservation"]["resource_lease"] == allocation.lease_id
                    )
                    active_entry["active"] = None
                    file.write(state)
                retained = lab_resources._QUARANTINED_ACTIVE_LOCKS.pop(
                    allocation.lease_id
                )
                retained.release()

    def test_manifest_rejects_symlinked_private_directory(self):
        path, manifest = self.manifest()
        target = self.root / "real-runtime"
        target.mkdir(mode=0o700)
        symlink = self.root / "linked-runtime"
        symlink.symlink_to(target)
        manifest["runtime_directory"] = str(symlink)
        manifest["credentials_path"] = str(symlink / "credentials")
        manifest["evidence_directory"] = str(self.root / "separate-evidence")
        path.write_text(json.dumps(manifest), encoding="utf-8")
        with self.assertRaisesRegex(
            lab_resources.LabResourceError, "cannot be symlinks"
        ):
            lab_resources.validate_allocation(path)

    def test_run_allocated_injects_manifest_environment_and_releases_slot(self):
        allocation = self.allocation(suffix="runner")
        script = (
            "import os; "
            "assert os.environ['ADM_LAB_NAME'] == '" + allocation.lab_name + "'; "
            "assert os.environ['ADM_LAB_WEB_PORT'] == '24060'; "
            "assert os.environ['ADM_LAB_SECRETS'] == '"
            + str(allocation.credentials_path)
            + "'; "
            "assert os.environ['DOCKER_HOST'] == 'unix:///tmp/fake-docker.sock'; "
            "assert 'DOCKER_CONTEXT' not in os.environ; print('allocation-ok')"
        )
        result = subprocess.run(
            [
                sys.executable,
                str(Path(__file__).parents[1] / "tools/lab_resources.py"),
                "run",
                str(allocation.manifest_path),
                "--registry",
                str(self.registry),
                "--",
                sys.executable,
                "-c",
                script,
            ],
            capture_output=True,
            text=True,
            env={
                key: value
                for key, value in os.environ.items()
                if key != "DOCKER_CONTEXT"
            },
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("allocation-ok", result.stdout)
        self.assertIn("capacity 1", result.stderr)
        state = json.loads(self.registry.read_text(encoding="utf-8"))
        self.assertIsNone(state["allocations"][0]["active"])

    def test_verify_active_succeeds_inside_run_allocated_and_fails_on_mismatch(self):
        allocation = self.allocation(suffix="verify")
        tool = str(Path(__file__).parents[1] / "tools/lab_resources.py")
        check_script = (
            "import os, subprocess, sys; "
            f"ok = subprocess.run([sys.executable, {tool!r}, 'verify-active'], "
            "capture_output=True, text=True); "
            "assert ok.returncode == 0, ok.stderr; "
            "bad_port = dict(os.environ, ADM_LAB_WEB_PORT='29999'); "
            f"r1 = subprocess.run([sys.executable, {tool!r}, 'verify-active'], "
            "env=bad_port, capture_output=True, text=True); "
            "assert r1.returncode == 75, (r1.returncode, r1.stdout, r1.stderr); "
            "bad_token = dict(os.environ, SPLUNK_ADM_RESOURCE_LEASE_TOKEN='forged'); "
            f"r2 = subprocess.run([sys.executable, {tool!r}, 'verify-active'], "
            "env=bad_token, capture_output=True, text=True); "
            "assert r2.returncode == 75, (r2.returncode, r2.stdout, r2.stderr); "
            "print('verify-active-ok')"
        )
        result = subprocess.run(
            [
                sys.executable,
                tool,
                "run",
                str(allocation.manifest_path),
                "--registry",
                str(self.registry),
                "--",
                sys.executable,
                "-c",
                check_script,
            ],
            capture_output=True,
            text=True,
            env={
                key: value
                for key, value in os.environ.items()
                if key != "DOCKER_CONTEXT"
            },
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("verify-active-ok", result.stdout)
        # After run exits, verify-active fails closed when called outside an active lease.
        outside = subprocess.run(
            [sys.executable, tool, "verify-active"],
            capture_output=True,
            text=True,
            env={
                **os.environ,
                "SPLUNK_ADM_RESOURCE_LEASE_ID": allocation.lease_id,
                "SPLUNK_ADM_RESOURCE_LEASE_TOKEN": "expired",
                "SPLUNK_ADM_RESOURCE_LEASE_PID": str(os.getpid()),
                "SPLUNK_ADM_RESOURCE_LEASE_START": "stale",
                "SPLUNK_ADM_RESOURCE_REGISTRY": str(self.registry),
            },
            timeout=10,
        )
        self.assertEqual(outside.returncode, 75)


if __name__ == "__main__":
    unittest.main()
