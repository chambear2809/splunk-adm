"""Mock-only guard tests for the task lab client; no Docker or HTTP I/O."""

import copy
import importlib.util
import io
import json
import os
import stat
import sys
import tarfile
import tempfile
import unittest
import urllib.request
from pathlib import Path
from unittest import mock

SPLUNK_TESTS = Path(__file__).resolve().parent / "splunk"
sys.path.insert(0, str(SPLUNK_TESTS))
import lab  # noqa: E402
import lab_tls  # noqa: E402

TASK = "guard-test"
NAME = "adm-guard-test"
ID = "a" * 64
ENV = {
    "ADM_LAB_TASK": TASK,
    "ADM_LAB_NAME": NAME,
    "ADM_LAB_WEB_PORT": "18100",
    "ADM_LAB_MGMT_PORT": "18189",
    "ADM_LAB_HEC_PORT": "18188",
}


def target():
    return {
        "Id": ID,
        "Config": {
            "Image": lab.IMAGE,
            "Healthcheck": {"Test": ["NONE"]},
            "Labels": {"org.splunk-adm.task": TASK, "org.splunk-adm.lab": NAME},
        },
        "HostConfig": {
            "NetworkMode": NAME + "-net",
            "PortBindings": {
                "8000/tcp": [{"HostIp": "127.0.0.1", "HostPort": "18100"}],
                "8089/tcp": [{"HostIp": "127.0.0.1", "HostPort": "18189"}],
                "8088/tcp": [{"HostIp": "127.0.0.1", "HostPort": "18188"}],
            },
        },
        "Mounts": [
            {"Destination": "/opt/splunk/etc", "Name": NAME + "-etc", "Type": "volume"},
            {"Destination": "/opt/splunk/var", "Name": NAME + "-var", "Type": "volume"},
        ],
    }


class LabClientTests(unittest.TestCase):
    def test_secret_initialization_checks_location_before_creating_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fake_git = root / "repository"
            fake_git.mkdir(mode=0o700)
            (fake_git / ".git").mkdir()
            path = fake_git / "credentials"
            with (
                mock.patch.object(lab, "SECRETS", path),
                self.assertRaises(lab_tls.LabTLSError),
            ):
                lab.init_secrets()
            self.assertFalse(path.exists())
            public = root / "public"
            public.mkdir(mode=0o755)
            public.chmod(0o755)
            path = public / "credentials"
            with (
                mock.patch.object(lab, "SECRETS", path),
                self.assertRaises(lab_tls.LabTLSError),
            ):
                lab.init_secrets()
            self.assertFalse(path.exists())
            private = root / "private"
            private.mkdir(mode=0o700)
            path = private / "credentials"
            with mock.patch.object(lab, "SECRETS", path):
                lab.init_secrets()
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertEqual(
                    set(lab.read_secrets()), {"SPLUNK_PASSWORD", "HEC_TOKEN"}
                )

    def test_secret_reads_fail_closed_on_unsafe_files_and_invalid_contents(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "credentials"
            good = "SPLUNK_PASSWORD=synthetic\nHEC_TOKEN=synthetic\n"
            with mock.patch.object(lab, "SECRETS", path):
                for bad in (
                    "SPLUNK_PASSWORD=synthetic\nSPLUNK_PASSWORD=synthetic\n",
                    "SPLUNK_PASSWORD=\nHEC_TOKEN=synthetic\n",
                    "SPLUNK_PASSWORD=synthetic\nHEC_TOKEN=synthetic\nEXTRA=value\n",
                    "SPLUNK_PASSWORD=" + "x" * 65536 + "\nHEC_TOKEN=synthetic\n",
                    "SPLUNK_PASSWORD=" + "é" * 33000 + "\nHEC_TOKEN=synthetic\n",
                ):
                    path.write_text(bad, encoding="utf-8")
                    path.chmod(0o600)
                    with self.subTest(length=len(bad)), self.assertRaises(lab.LabError):
                        lab.read_secrets()
                path.write_text(good)
                path.chmod(0o644)
                with self.assertRaises(lab.LabError):
                    lab.read_secrets()
                path.chmod(0o600)
                hardlink = root / "hardlink"
                os.link(path, hardlink)
                try:
                    with self.assertRaises(lab.LabError):
                        lab.read_secrets()
                finally:
                    hardlink.unlink()
                target = root / "target"
                path.rename(target)
                path.symlink_to(target)
                with self.assertRaises(lab.LabError):
                    lab.read_secrets()
                with self.assertRaises(lab.LabError):
                    lab.init_secrets()
                self.assertTrue(path.is_symlink())

    def test_bootstrap_waits_for_bound_running_container_and_started_marker(self):
        markers = [
            mock.Mock(returncode=0, stdout=b"starting\n"),
            mock.Mock(returncode=1, stdout=b"started\n"),
            mock.Mock(returncode=0, stdout=b"started\n"),
        ]
        with (
            mock.patch.object(lab, "task_identity", return_value=(TASK, NAME)),
            mock.patch.object(lab, "verify_target") as verify,
            mock.patch.object(lab.lab_tls, "read_container", return_value=ID),
            mock.patch.object(
                lab.subprocess,
                "check_output",
                return_value=json.dumps([{"State": {"Status": "running"}}]),
            ) as inspect,
            mock.patch.object(lab.subprocess, "run", side_effect=markers) as command,
            mock.patch.object(lab.time, "monotonic", side_effect=[0, 0, 1, 2]),
            mock.patch.object(lab.time, "sleep") as sleep,
            mock.patch.object(lab, "_context") as context,
            mock.patch.object(lab, "_json") as api,
            mock.patch.object(lab, "urlopen") as network,
        ):
            lab.wait_bootstrap(timeout=10)
            self.assertEqual(verify.call_count, 3)
            self.assertEqual(inspect.call_count, 3)
            self.assertEqual(command.call_count, 3)
            self.assertEqual(
                command.call_args.args[0],
                [
                    "docker",
                    "exec",
                    ID,
                    "cat",
                    "/opt/container_artifact/splunk-container.state",
                ],
            )
            self.assertEqual(sleep.call_args_list, [mock.call(5), mock.call(5)])
            context.assert_not_called()
            api.assert_not_called()
            network.assert_not_called()

    def test_bootstrap_rejects_stopped_container_and_times_out(self):
        with (
            mock.patch.object(lab, "task_identity", return_value=(TASK, NAME)),
            mock.patch.object(lab, "verify_target"),
            mock.patch.object(lab.lab_tls, "read_container", return_value=ID),
            mock.patch.object(
                lab.subprocess,
                "check_output",
                return_value=json.dumps([{"State": {"Status": "exited"}}]),
            ) as inspect,
            mock.patch.object(lab.subprocess, "run") as command,
            mock.patch.object(lab.time, "monotonic", side_effect=[0, 0]),
            mock.patch.object(lab.time, "sleep") as sleep,
            mock.patch.object(lab, "_context") as context,
        ):
            with self.assertRaises(lab.LabError):
                lab.wait_bootstrap(timeout=5)
            command.assert_not_called()
            sleep.assert_not_called()
            context.assert_not_called()
            self.assertEqual(inspect.call_count, 1)
        with (
            mock.patch.object(lab, "task_identity", return_value=(TASK, NAME)),
            mock.patch.object(lab, "verify_target"),
            mock.patch.object(lab.lab_tls, "read_container", return_value=ID),
            mock.patch.object(
                lab.subprocess,
                "check_output",
                return_value=json.dumps([{"State": {"Status": "running"}}]),
            ),
            mock.patch.object(
                lab.subprocess,
                "run",
                return_value=mock.Mock(returncode=0, stdout=b"starting"),
            ) as command,
            mock.patch.object(lab.time, "monotonic", side_effect=[0, 0, 6]),
            mock.patch.object(lab.time, "sleep"),
            mock.patch.object(lab, "_context") as context,
        ):
            with self.assertRaises(lab.LabError):
                lab.wait_bootstrap(timeout=5)
            self.assertEqual(command.call_count, 1)
            context.assert_not_called()

    def test_bootstrap_accepts_running_marker_without_api(self):
        with (
            mock.patch.object(lab, "task_identity", return_value=(TASK, NAME)),
            mock.patch.object(lab, "verify_target"),
            mock.patch.object(lab.lab_tls, "read_container", return_value=ID),
            mock.patch.object(
                lab.subprocess,
                "check_output",
                return_value=json.dumps([{"State": {"Status": "running"}}]),
            ),
            mock.patch.object(
                lab.subprocess,
                "run",
                return_value=mock.Mock(returncode=0, stdout=b"running\n"),
            ),
            mock.patch.object(lab.time, "monotonic", side_effect=[0, 0]),
            mock.patch.object(lab, "_context") as context,
        ):
            lab.wait_bootstrap(timeout=5)
            context.assert_not_called()

    def test_lab_shell_waits_for_bootstrap_before_https_readiness(self):
        script = (SPLUNK_TESTS / "lab.sh").read_text()
        up = script.split("cmd_up() {", 1)[1].split("\ncopy_ta()", 1)[0]
        self.assertLess(up.index("py wait-bootstrap"), up.index("py wait\n"))

    def test_remote_docker_endpoint_is_rejected_before_inspection(self):
        with (
            mock.patch.dict(
                os.environ, {"DOCKER_HOST": "tcp://127.0.0.1:2375"}, clear=True
            ),
            mock.patch.object(lab.subprocess, "check_output") as inspect,
        ):
            with self.assertRaises(lab.LabError):
                lab.local_docker_endpoint()
            inspect.assert_not_called()

    def test_import_and_secret_setup_do_not_construct_tls_context(self):
        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.object(lab_tls, "tls_context") as tls,
        ):
            with mock.patch.dict(
                os.environ,
                {**ENV, "ADM_LAB_SECRETS": str(Path(directory) / "secrets")},
                clear=False,
            ):
                spec = importlib.util.spec_from_file_location(
                    "isolated_lab_guard_test", SPLUNK_TESTS / "lab.py"
                )
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                tls.assert_not_called()
                module.init_secrets()
                tls.assert_not_called()
                self.assertTrue(module.SECRETS.exists())

    def test_rejects_untrusted_url_before_open(self):
        bad_urls = [
            "http://127.0.0.1:8089/path",
            "https://localhost:8089/path",
            "https://127.0.0.2:8089/path",
            "https://127.0.0.1:443/path",
            "https://127.0.0.1:badport/path",
            "https://name@127.0.0.1:8089/path",
            "https://127.0.0.1:8089/path#fragment",
        ]
        with (
            mock.patch.object(lab, "verify_target") as verify,
            mock.patch.object(lab.urllib.request, "build_opener") as build,
        ):
            for url in bad_urls:
                with self.subTest(url=url), self.assertRaises(lab.LabError):
                    lab.urlopen(urllib.request.Request(url))
            verify.assert_not_called()
            build.assert_not_called()

    def test_valid_url_uses_no_proxy_no_redirect_and_verified_context(self):
        context = object()
        opener = mock.Mock()
        response = object()
        opener.open.return_value = response
        with (
            mock.patch.object(lab, "verify_target") as verify,
            mock.patch.object(lab, "_context", return_value=context),
            mock.patch.object(
                lab.urllib.request, "build_opener", return_value=opener
            ) as build,
        ):
            req = urllib.request.Request(lab.MGMT + "/services/server/info")
            self.assertIs(lab.urlopen(req, timeout=7), response)
            verify.assert_called_once_with()
            opener.open.assert_called_once_with(req, timeout=7)
            handlers = build.call_args.args
            proxy = next(
                h for h in handlers if isinstance(h, urllib.request.ProxyHandler)
            )
            self.assertEqual(proxy.proxies, {})
            self.assertTrue(any(isinstance(h, lab._NoRedirect) for h in handlers))
            tls = next(
                h for h in handlers if isinstance(h, urllib.request.HTTPSHandler)
            )
            self.assertIs(tls._context, context)
            with self.assertRaises(lab.LabError):
                next(
                    h for h in handlers if isinstance(h, lab._NoRedirect)
                ).redirect_request(None, None, 302, None, {}, "https://example.invalid")

    def test_verify_target_rejects_replaced_or_misconfigured_container(self):
        good = target()

        def docker_inspect(*args, **kwargs):
            return mock.Mock(stdout=json.dumps([self.inspected]))

        with (
            mock.patch.dict(os.environ, ENV, clear=False),
            mock.patch.object(lab, "local_docker_endpoint"),
            mock.patch.object(lab.lab_tls, "read_container", return_value=ID),
            mock.patch.object(lab.subprocess, "run", side_effect=docker_inspect),
        ):
            self.inspected = copy.deepcopy(good)
            lab.verify_target()
            for edit in (
                lambda t: t.update(Id="b" * 64),
                lambda t: t["Config"].update(Image="splunk/splunk:10.6.0.5"),
                lambda t: t["Config"].update(Healthcheck={"Test": ["CMD", "probe"]}),
                lambda t: t["Config"].pop("Healthcheck"),
                lambda t: t["Config"].update(Healthcheck=None),
                lambda t: t["Config"]["Labels"].update(
                    {"org.splunk-adm.task": "other"}
                ),
                lambda t: t["Config"]["Labels"].update(
                    {"org.splunk-adm.lab": "adm-other"}
                ),
                lambda t: t["HostConfig"].update(NetworkMode="other"),
                lambda t: t["HostConfig"]["PortBindings"]["8089/tcp"][0].update(
                    HostIp="0.0.0.0"
                ),
                lambda t: t["HostConfig"]["PortBindings"]["8088/tcp"][0].update(
                    HostPort="8088"
                ),
                lambda t: t["Mounts"][0].update(Name="other"),
                lambda t: t["Mounts"][1].update(Type="bind"),
            ):
                self.inspected = copy.deepcopy(good)
                edit(self.inspected)
                with self.assertRaises(lab.LabError):
                    lab.verify_target()
            self.inspected = copy.deepcopy(good)
            with self.assertRaises(lab.LabError):
                lab.verify_target(expected_id="b" * 64)
            with self.assertRaises(lab.LabError):
                lab.verify_target(registering=True, expected_id="bad")

    def test_prestart_tar_staging_uses_private_members_and_stdin(self):
        with tempfile.TemporaryDirectory() as temp:
            secrets_path = Path(temp) / "secret"
            directory = Path(str(secrets_path) + ".tls")
            directory.mkdir()
            (directory / "ca.pem").write_bytes(b"public-test-ca")
            fake_bundle = b"private-test-bundle"
            with (
                mock.patch.object(lab, "SECRETS", secrets_path),
                mock.patch.object(lab, "verify_target") as verify,
                mock.patch.object(lab, "task_identity", return_value=(TASK, NAME)),
                mock.patch.object(lab.lab_tls, "read_container", return_value=ID),
                mock.patch.object(lab.lab_tls, "tls_context"),
                mock.patch.object(
                    lab.lab_tls, "server_bundle", return_value=fake_bundle
                ),
                mock.patch.object(
                    lab.subprocess,
                    "check_output",
                    return_value=json.dumps([{"State": {"Status": "created"}}]),
                ),
                mock.patch.object(lab.subprocess, "run") as execute,
            ):
                lab.stage_tls()
                self.assertEqual(verify.call_count, 2)
                args, kwargs = execute.call_args
                self.assertEqual(args[0], ["docker", "cp", "-", ID + ":/opt/splunk"])
                self.assertNotIn(fake_bundle.decode(), str(args))
                with tarfile.open(
                    fileobj=io.BytesIO(kwargs["input"]), mode="r:"
                ) as archive:
                    files = {m.name: m for m in archive.getmembers() if m.isfile()}
                    self.assertEqual(
                        set(files),
                        {
                            "etc/auth/adm_lab_tls/server.pem",
                            "etc/auth/adm_lab_tls/ca.pem",
                            "etc/system/local/server.conf",
                            "etc/system/local/inputs.conf",
                        },
                    )
                    self.assertTrue(
                        all(
                            m.mode == 0o600 and m.uid == 41812 and m.gid == 41812
                            for m in files.values()
                        )
                    )
                    self.assertEqual(
                        archive.extractfile(
                            files["etc/auth/adm_lab_tls/server.pem"]
                        ).read(),
                        fake_bundle,
                    )
                    self.assertIn(
                        b"cliVerifyServerName = true",
                        archive.extractfile(
                            files["etc/system/local/server.conf"]
                        ).read(),
                    )
                execute.reset_mock()
                lab.subprocess.check_output.return_value = json.dumps(
                    [{"State": {"Status": "running"}}]
                )
                with self.assertRaises(lab.LabError):
                    lab.stage_tls()
                execute.assert_not_called()

    def test_created_container_is_staged_before_start_and_failure_never_starts(self):
        order = []
        with (
            mock.patch.object(lab, "task_identity", return_value=(TASK, NAME)),
            mock.patch.object(
                lab,
                "verify_target",
                side_effect=lambda **kwargs: order.append(("verify", kwargs)),
            ),
            mock.patch.object(lab.lab_tls, "read_container", return_value=ID),
            mock.patch.object(
                lab.subprocess,
                "check_output",
                return_value=json.dumps([{"State": {"Status": "created"}}]),
            ),
            mock.patch.object(
                lab, "stage_tls", side_effect=lambda: order.append(("stage", {}))
            ) as stage,
            mock.patch.object(
                lab.subprocess,
                "run",
                side_effect=lambda *args, **kwargs: order.append(("start", args[0])),
            ) as start,
        ):
            lab.start_container()
            self.assertEqual(
                order,
                [
                    ("verify", {}),
                    ("stage", {}),
                    ("verify", {"expected_id": ID}),
                    ("start", ["docker", "start", ID]),
                ],
            )
            stage.side_effect = lab.LabError("stage failed")
            start.reset_mock()
            with self.assertRaises(lab.LabError):
                lab.start_container()
            start.assert_not_called()

    def test_running_and_exited_containers_start_only_recorded_id(self):
        with (
            mock.patch.object(lab, "task_identity", return_value=(TASK, NAME)),
            mock.patch.object(lab, "verify_target") as verify,
            mock.patch.object(lab.lab_tls, "read_container", return_value=ID),
            mock.patch.object(lab.subprocess, "check_output") as inspect,
            mock.patch.object(lab, "stage_tls") as stage,
            mock.patch.object(lab.subprocess, "run") as start,
        ):
            for state in ("running", "exited"):
                inspect.return_value = json.dumps([{"State": {"Status": state}}])
                lab.start_container()
                start.assert_called_with(
                    ["docker", "start", ID],
                    stdout=lab.subprocess.DEVNULL,
                    stderr=lab.subprocess.DEVNULL,
                    timeout=30,
                    check=True,
                )
                verify.assert_called_with(expected_id=ID)
            stage.assert_not_called()
            start.reset_mock()
            inspect.return_value = json.dumps([{"State": {"Status": "paused"}}])
            with self.assertRaises(lab.LabError):
                lab.start_container()
            start.assert_not_called()
