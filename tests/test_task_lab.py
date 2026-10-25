"""Ownership and routing boundaries for disposable task labs."""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import shutil
import sys
import tempfile
import unittest
import uuid
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location(
    "task_lab_client", Path(__file__).parent / "splunk/lab.py"
)
lab = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lab)


class TaskLabTest(unittest.TestCase):
    def setUp(self):
        self.environment = patch.dict(
            os.environ,
            DOCKER_HOST="unix:///synthetic-task-docker.sock",
            DOCKER_CONTEXT="",
            ADM_LAB_TASK="test-task",
            ADM_LAB_NAME="adm-test-task-one",
            ADM_LAB_WEB_PORT="28000",
            ADM_LAB_MGMT_PORT="28089",
            ADM_LAB_HEC_PORT="28088",
        )
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.target = {
            "Config": {
                "Labels": {
                    "org.splunk-adm.task": "test-task",
                    "org.splunk-adm.lab": "adm-test-task-one",
                }
            },
            "Mounts": [
                {
                    "Destination": destination,
                    "Name": "adm-test-task-one-" + suffix,
                    "Type": "volume",
                }
                for destination, suffix in (
                    ("/opt/splunk/etc", "etc"),
                    ("/opt/splunk/var", "var"),
                )
            ],
            "HostConfig": {
                "NetworkMode": "adm-test-task-one-net",
                "PortBindings": {
                    key: [{"HostIp": "127.0.0.1", "HostPort": value}]
                    for key, value in (
                        ("8000/tcp", "28000"),
                        ("8089/tcp", "28089"),
                        ("8088/tcp", "28088"),
                    )
                },
            },
        }

    def verify(self):
        with patch.object(
            lab.subprocess,
            "run",
            return_value=subprocess.CompletedProcess([], 0, json.dumps([self.target])),
        ):
            lab.verify_target()

    def test_owned_target_and_loopback_bindings(self):
        self.verify()

    def test_other_lab_or_task_is_refused(self):
        for label in ("org.splunk-adm.task", "org.splunk-adm.lab"):
            with self.subTest(label=label):
                previous = self.target["Config"]["Labels"][label]
                self.target["Config"]["Labels"][label] = "other"
                with self.assertRaisesRegex(lab.LabError, "unowned"):
                    self.verify()
                self.target["Config"]["Labels"][label] = previous

    def test_wrong_port_or_public_interface_is_refused(self):
        for binding in (
            {"HostIp": "0.0.0.0", "HostPort": "28089"},
            {"HostIp": "127.0.0.1", "HostPort": "8089"},
        ):
            with self.subTest(binding=binding):
                self.target["HostConfig"]["PortBindings"]["8089/tcp"] = [binding]
                with self.assertRaisesRegex(lab.LabError, "loopback"):
                    self.verify()

    def test_other_network_or_volume_is_refused(self):
        self.target["HostConfig"]["NetworkMode"] = "bridge"
        with self.assertRaisesRegex(lab.LabError, "network"):
            self.verify()
        self.target["HostConfig"]["NetworkMode"] = "adm-test-task-one-net"
        self.target["Mounts"][0]["Name"] = "another-lab-etc"
        with self.assertRaisesRegex(lab.LabError, "volumes"):
            self.verify()

    def test_cleanup_refuses_foreign_resource_before_removal(self):
        result = subprocess.CompletedProcess(
            [], 0, json.dumps([{"Labels": {"org.splunk-adm.task": "other"}}])
        )
        with patch.object(
            lab.subprocess,
            "run",
            side_effect=[
                subprocess.CompletedProcess([], 0, "adm-test-task-one-net\n"),
                result,
            ],
        ) as run:
            with self.assertRaisesRegex(lab.LabError, "unowned"):
                lab.task_resources(remove=True)
            self.assertEqual(run.call_count, 2)
            self.assertEqual(run.call_args.args[0][1:3], ["network", "inspect"])

    def test_remote_daemon_is_refused_before_resource_access(self):
        with (
            patch.dict(os.environ, DOCKER_HOST="tcp://remote:2376"),
            patch.object(lab.subprocess, "run") as run,
        ):
            with self.assertRaisesRegex(lab.LabError, "local Docker"):
                lab.task_resources()
            run.assert_not_called()

    def test_context_takes_precedence_and_is_pinned(self):
        with (
            patch.dict(
                os.environ, DOCKER_CONTEXT="selected", DOCKER_HOST="tcp://ignored:2376"
            ),
            patch.object(
                lab.subprocess, "check_output", return_value="unix:///local.sock\n"
            ) as output,
        ):
            self.assertEqual(lab.local_docker_endpoint(), "unix:///local.sock")
            self.assertIn("selected", output.call_args.args[0])
            self.assertNotIn("DOCKER_CONTEXT", os.environ)
            self.assertEqual(os.environ["DOCKER_HOST"], "unix:///local.sock")

    def test_invalid_identity_never_reaches_docker(self):
        for name in ("adm-splunk-lab", "other", "adm-../foreign"):
            with (
                patch.dict(os.environ, ADM_LAB_NAME=name),
                patch.object(lab.subprocess, "run") as run,
            ):
                with self.assertRaisesRegex(lab.LabError, "identity"):
                    lab.task_resources(remove=True)
                run.assert_not_called()

    def test_daemon_failure_does_not_count_as_absent_resources(self):
        with patch.object(
            lab.subprocess,
            "run",
            side_effect=subprocess.CalledProcessError(1, "docker"),
        ) as run:
            with self.assertRaises(subprocess.CalledProcessError):
                lab.task_resources(remove=True)
            self.assertEqual(run.call_count, 1)

    def test_failed_ownership_check_precedes_authentication(self):
        with (
            patch.object(lab, "verify_target", side_effect=lab.LabError("unowned")),
            patch.object(lab, "read_secrets") as read,
        ):
            with self.assertRaises(lab.LabError):
                lab._mgmt("POST", "/services/server/control/restart")
            read.assert_not_called()


class TaskLabShellTest(unittest.TestCase):
    def test_every_lifecycle_refuses_foreign_task_before_docker_mutation(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            here = workspace / "tests/splunk"
            here.mkdir(parents=True)
            (workspace / "tools").mkdir()
            for filename in ("lab.sh", "lab.py"):
                shutil.copy2(root / "tests/splunk" / filename, here / filename)
            shutil.copy2(root / "tools/lab_lock.py", workspace / "tools/lab_lock.py")
            fake_bin = workspace / "bin"
            fake_bin.mkdir()
            docker = fake_bin / "docker"
            docker.write_text(
                f"#!{sys.executable}\n"
                "import json,os,sys\n"
                "from pathlib import Path\n"
                "with Path(os.environ['TEST_DOCKER_LOG']).open('a') as out:\n"
                " out.write(json.dumps(sys.argv[1:])+'\\n')\n"
                "if sys.argv[1:] != ['inspect',os.environ['ADM_LAB_NAME']]:\n"
                " raise SystemExit('Docker mutation must never be reached')\n"
                "print(json.dumps([{'Config':{'Labels':{'org.splunk-adm.task':'actual-owner','org.splunk-adm.lab':os.environ['ADM_LAB_NAME']}}}]))\n"
            )
            docker.chmod(0o755)
            secret = workspace / "credentials"
            secret.write_text("synthetic-placeholder")
            secret.chmod(0o600)
            environment = dict(
                os.environ,
                PATH=str(fake_bin) + os.pathsep + os.environ["PATH"],
                ADM_LAB_NAME="adm-shell-refusal-" + uuid.uuid4().hex,
                DOCKER_HOST="unix:///synthetic-task-docker.sock",
                DOCKER_CONTEXT="",
                ADM_LAB_TASK="foreign-task",
                ADM_LAB_SECRETS=str(secret),
                TEST_DOCKER_LOG=str(workspace / "docker.jsonl"),
            )
            for key in (
                "SPLUNK_ADM_LAB_LOCK_PATH",
                "SPLUNK_ADM_LAB_LOCK_PID",
                "SPLUNK_ADM_LAB_LOCK_TOKEN",
            ):
                environment.pop(key, None)
            try:
                for action in (
                    "up",
                    "install",
                    "reset",
                    "down",
                    "purge",
                    "btool",
                    "search",
                ):
                    with self.subTest(action=action):
                        args = ["bash", str(here / "lab.sh"), action]
                        if action == "search":
                            args.append("| makeresults")
                        result = subprocess.run(
                            args,
                            env=environment,
                            capture_output=True,
                            text=True,
                            timeout=15,
                        )
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn("refusing unowned task lab", result.stderr)
                        self.assertEqual(secret.read_text(), "synthetic-placeholder")
                operations = [
                    json.loads(line)
                    for line in (workspace / "docker.jsonl").read_text().splitlines()
                ]
                self.assertTrue(operations)
                self.assertTrue(
                    all(
                        op == ["inspect", environment["ADM_LAB_NAME"]]
                        for op in operations
                    )
                )
            finally:
                lock = (
                    Path("/tmp")
                    / f"splunk-adm-lab-{os.getuid()}-{environment['ADM_LAB_NAME']}.lock"
                )
                lock.unlink(missing_ok=True)
