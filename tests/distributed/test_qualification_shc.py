"""Small offline safety/coordination tests; no Docker, SSH, or Splunk operations."""

import configparser
from datetime import datetime, timezone
import hashlib
import io
import importlib.util
import json
import os
from pathlib import Path
import signal
import ssl
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import urllib.parse

TOOLS = Path(__file__).resolve().parents[2] / "tools"
sys.path.insert(0, str(TOOLS))
import qualification_shc as client  # noqa: E402
import qualification_shc_lab as lifecycle  # noqa: E402
import qualification_shc_run as runner  # noqa: E402


class SafetyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.task = "adm-shc-offline"
        self.state = {
            "task": self.task,
            "created": {
                role: {
                    "name": f"{self.task}-{role}",
                    "url": f"https://localhost:{22009 + i * 10}",
                    "id": str(i) * 64,
                }
                for i, role in enumerate(client.ROLES)
            },
        }

    def test_bootstrap_and_bundle_use_supported_global_confirmation_flag(self):
        lab = lifecycle.Lab(
            self.directory, self.task, lock_file=self.directory / "lock"
        )
        with (
            lab.locked(),
            patch.object(lab, "login") as login,
            patch.object(lab, "cli") as cli,
        ):
            lab.bootstrap()
            lab.apply_bundle()
        self.assertEqual(
            [call.args[0] for call in login.call_args_list], ["sh1", "deployer"]
        )
        self.assertEqual(cli.call_count, 2)
        for call in cli.call_args_list:
            with self.subTest(role=call.args[0]):
                arguments = call.args[1]
                self.assertEqual(arguments.count("--answer-yes"), 1)
                self.assertNotIn("-answer-yes", arguments)
                self.assertNotIn("-auth", arguments)

    def state_file(self, value):
        path = self.directory / "state.json"
        path.write_text(json.dumps(value))
        path.chmod(0o600)
        return path

    def test_valid_task_local_https_state(self):
        self.assertEqual(client.load_state(self.state_file(self.state)), self.state)

    def test_state_refuses_public_or_credential_bearing_urls(self):
        for endpoint in (
            "http://localhost:8089",
            "https://customer.example:8089",
            "https://admin:password@localhost:8089",
            "https://localhost:8089/x",
        ):
            with self.subTest(endpoint=endpoint):
                self.state["created"]["sh1"]["url"] = endpoint
                with self.assertRaises(client.Refused):
                    client.load_state(self.state_file(self.state))

    def test_state_refuses_role_or_name_drift(self):
        self.state["created"]["sh1"]["name"] = "unrelated-sh1"
        with self.assertRaises(client.Refused):
            client.load_state(self.state_file(self.state))

    def test_state_refuses_world_readable_or_symlink(self):
        path = self.state_file(self.state)
        path.chmod(0o644)
        with self.assertRaises(client.Refused):
            client.load_state(path)
        path.chmod(0o600)
        link = self.directory / "link.json"
        link.symlink_to(path)
        with self.assertRaises(client.Refused):
            client.load_state(link)

    def test_api_uses_verifying_context_without_proxies(self):
        ca = self.directory / "ca.pem"
        ca.write_text("test placeholder")
        ca.chmod(0o600)
        self.state["ca_file"] = str(ca)
        context = ssl.create_default_context()
        with patch.object(
            client.ssl, "create_default_context", return_value=context
        ) as factory:
            api = client.Api("sh1", state=self.state)
        factory.assert_called_once_with(cafile=str(ca))
        self.assertTrue(api.context.check_hostname)
        self.assertEqual(api.context.verify_mode, ssl.CERT_REQUIRED)

    def test_no_redirect_fallback(self):
        with self.assertRaises(client.Refused):
            client.NoRedirect().redirect_request(
                None, None, 302, "", {}, "https://elsewhere"
            )

    def test_search_warnings_are_not_success(self):
        for kind in ("WARN", "WARNING", "ERROR", "FATAL"):
            with self.subTest(kind=kind), self.assertRaises(client.Refused):
                client.reject_messages([{"type": kind, "text": "private detail"}])

    def test_base_macro_search_normalization_preserves_generating_commands(self):
        self.assertEqual(
            client.search_query(" `adm_topology_v2` "), "search `adm_topology_v2`"
        )
        self.assertEqual(client.search_query("`adm_topology`"), "search `adm_topology`")
        self.assertEqual(
            client.search_query("search index=netflow"), "search index=netflow"
        )
        self.assertEqual(
            client.search_query("| makeresults | eval value=1"),
            "| makeresults | eval value=1",
        )

    def test_member_replication_listener_is_its_own_enabled_stanza(self):
        pki = self.directory / "pki"
        pki.mkdir()
        (self.directory / "shc.secret").write_text("test-secret")
        (pki / "sh1.pem").write_bytes(b"test certificate")
        (pki / "ca.pem").write_bytes(b"test CA")
        lab = lifecycle.Lab(self.directory, self.task)
        lab.state = self.state
        with patch.object(lab, "copy_files") as copied:
            lab._copy_config("sh1")
        rendered = copied.call_args.args[1]["etc/system/local/server.conf"].decode()
        config = configparser.RawConfigParser()
        config.read_string(rendered)
        self.assertEqual(config["replication_port://9887"]["disabled"], "0")
        self.assertNotIn("replication_port", config["shclustering"])
        self.assertEqual(config["shclustering"]["replication_factor"], "3")
        self.assertEqual(config["sslConfig"]["cliVerifyServerName"], "true")
        self.assertEqual(
            config["sslConfig"]["sslRootCAPath"],
            "/opt/splunk/etc/auth/adm_qualification/ca.pem",
        )
        self.assertNotIn("sslVerifyServerCert", config["sslConfig"])

    def test_error_does_not_echo_server_body(self):
        self.assertEqual(
            str(client.ApiError(403)), "qualification request rejected (HTTP 403)"
        )

    def test_failed_command_records_metadata_without_output_or_input(self):
        evidence = self.directory / "evidence"
        evidence.mkdir()
        token = lifecycle.DIAGNOSTICS.set(evidence)
        self.addCleanup(lifecycle.DIAGNOSTICS.reset, token)
        result = subprocess.CompletedProcess(
            ["docker", "exec"],
            7,
            b"private-secret-password",
            b"permission denied; private-secret-password",
        )
        with patch.object(lifecycle.subprocess, "run", return_value=result):
            with self.assertRaisesRegex(client.Refused, "status=7"):
                lifecycle.command(
                    ["docker", "exec", "task-id", "tool"], data=b"secret-input"
                )
        files = list(evidence.glob("*.json"))
        self.assertEqual(len(files), 1)
        raw = files[0].read_text()
        self.assertNotIn("private-secret-password", raw)
        self.assertNotIn("secret-input", raw)
        record = json.loads(raw)
        self.assertEqual(record["status"], 7)
        self.assertEqual(record["categories"], ["permission denied"])

    def test_mutation_requires_host_lock(self):
        lab = lifecycle.Lab(self.directory / "task", self.task)
        for operation in (lab.create, lab.bootstrap, lab.cleanup):
            with (
                self.subTest(operation=operation.__name__),
                self.assertRaises(client.Refused),
            ):
                operation()

    def test_lock_covers_entire_driver(self):
        lock = self.directory / "host.lock"
        first = lifecycle.Lab(self.directory / "first", self.task, lock_file=lock)
        second = lifecycle.Lab(self.directory / "second", self.task, lock_file=lock)
        with first.locked():
            first._owned()
            with self.assertRaises(BlockingIOError), second.locked():
                self.fail("second lifecycle acquired the exclusive lock")
        with second.locked():
            second._owned()

    def test_identity_mismatch_blocks_cleanup_before_any_removal(self):
        lab = lifecycle.Lab(
            self.directory / "task", self.task, lock_file=self.directory / "lock"
        )
        lab.state = self.state
        fake = {"Id": "0" * 64, "Name": "/unrelated", "Config": {"Labels": {}}}
        with (
            lab.locked(),
            patch.object(
                lifecycle, "command", return_value=json.dumps([fake]).encode()
            ) as run,
        ):
            with self.assertRaises(client.Refused):
                lab.cleanup()
        self.assertTrue(
            all(call.args[0][1] == "inspect" for call in run.call_args_list)
        )

    def test_copy_archive_preserves_safe_owner_and_executable(self):
        lab = lifecycle.Lab(
            self.directory / "task", self.task, lock_file=self.directory / "lock"
        )
        with (
            lab.locked(),
            patch.object(lab, "identity", return_value="1" * 64),
            patch.object(lifecycle, "command") as run,
        ):
            lab.copy_files(
                "sh1",
                {
                    "etc/apps/example/bin/run.py": (b"pass\n", 0o700),
                    "etc/system/local/server.conf": b"private fixture\n",
                },
            )
        content = run.call_args.kwargs["data"]
        with tarfile.open(fileobj=io.BytesIO(content)) as archive:
            item = archive.getmember("etc/apps/example/bin/run.py")
            self.assertEqual((item.uid, item.gid, item.mode), (41812, 41812, 0o700))
            self.assertTrue(archive.getmember("etc/apps/example/bin").isdir())
            self.assertTrue(
                all(item.mode == 0o755 for item in archive.getmembers() if item.isdir())
            )
            self.assertEqual(
                archive.getmember("etc/system/local/server.conf").mode, 0o600
            )

    def test_archive_refuses_path_traversal_and_links(self):
        for name, kind in (
            ("../escape", tarfile.REGTYPE),
            ("splunk_adm/link", tarfile.SYMTYPE),
            ("other/file", tarfile.REGTYPE),
        ):
            with self.subTest(name=name):
                path = self.directory / "candidate.tgz"
                with tarfile.open(path, "w:gz") as archive:
                    item = tarfile.TarInfo(name)
                    item.type = kind
                    item.linkname = "/etc/passwd"
                    archive.addfile(item)
                with self.assertRaises(client.Refused):
                    lifecycle.safe_extract(path, self.directory / "stage")

    def test_evidence_is_exclusive_owner_only_and_hashed(self):
        result = client.write_evidence(self.directory, "result", {"passed": True})
        path = self.directory / result["file"]
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(
            result["sha256"], hashlib.sha256(path.read_bytes()).hexdigest()
        )
        with self.assertRaises(FileExistsError):
            client.write_evidence(self.directory, "result", {})

    def candidate_check(self, installed, *, baseline=None, other=b"unchanged\n"):
        baseline = (
            baseline
            or b"[install]\nstate = enabled\nbuild = 8\n[launcher]\nversion = 1.0.0\n"
        )
        app = self.directory / "stage/splunk_adm/default"
        app.mkdir(parents=True, exist_ok=True)
        (app / "app.conf").write_bytes(baseline)
        lab = lifecycle.Lab(self.directory, self.task)
        lab.state["candidate_files"] = {
            "default/app.conf": hashlib.sha256(baseline).hexdigest(),
            "default/macros.conf": hashlib.sha256(b"unchanged\n").hexdigest(),
        }

        def command(args):
            return installed if args[-1].endswith("/app.conf") else other

        with (
            patch.object(lab, "identity", return_value="a" * 64),
            patch.object(lifecycle, "command", side_effect=command),
        ):
            return lab.verify_candidate(), baseline

    def test_candidate_allows_only_documented_generated_install_source_checksum(self):
        checksum = "2bcb4b2aa985a382e071bd61e826a3041c153142"
        installed = (
            "[install]\nstate=enabled\nbuild=8\ninstall_source_checksum="
            + checksum
            + "\n[launcher]\nversion=1.0.0\n"
        ).encode()
        results, baseline = self.candidate_check(installed)
        for role in client.MEMBERS:
            item = results[role]["default/app.conf"]
            self.assertEqual(item["sha256"], hashlib.sha256(installed).hexdigest())
            self.assertEqual(
                item["archive_file_sha256"], hashlib.sha256(baseline).hexdigest()
            )
            self.assertEqual(
                item["generated_install_fields"], {"install_source_checksum": checksum}
            )
            self.assertTrue(results[role]["default/macros.conf"]["byte_exact"])

    def test_candidate_refuses_bad_generated_checksum_or_unrelated_changes(self):
        base = b"[install]\nstate = enabled\nbuild = 8\n[launcher]\nversion = 1.0.0\n"
        cases = [
            base.replace(b"build = 8", b"build = 9"),
            base.replace(b"state = enabled", b"state = disabled"),
            base.replace(b"version = 1.0.0", b"version = 2.0.0"),
            base.replace(b"build = 8", b"build = 8\nchecksum = " + b"a" * 40),
            base.replace(
                b"build = 8", b"build = 8\ninstall_source_local_checksum = " + b"a" * 40
            ),
            base + b"extra = modified\n",
            base + b"[extra]\nvalue = modified\n",
        ]
        for value in (b"", b"a" * 39, b"g" * 40, b"A" * 40, b"a" * 41):
            cases.append(
                base.replace(
                    b"build = 8", b"build = 8\ninstall_source_checksum = " + value
                )
            )
        for installed in cases:
            with self.subTest(installed=installed), self.assertRaises(client.Refused):
                self.candidate_check(installed)
        with self.assertRaises(client.Refused):
            self.candidate_check(base, other=b"changed macro\n")
        declared = base.replace(
            b"build = 8", b"build = 8\ninstall_source_checksum = " + b"a" * 40
        )
        with self.assertRaises(client.Refused):
            self.candidate_check(
                declared.replace(b"a" * 40, b"b" * 40), baseline=declared
            )


class ApiResponseTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        secret = Path(self.temp.name) / "fixture-account.json"
        lifecycle.private_write(
            secret,
            client.canonical(
                {"username": "fixture-user", "password": "fixture-password"}
            ),
        )
        self.api = object.__new__(client.Api)
        self.api.state = {"account_files": {"admin": str(secret)}}
        self.api.account = "admin"
        self.api.url = "https://localhost:22009"
        self.api.opener = Mock()

    def respond(self, body, status=200):
        response = io.BytesIO(body)
        response.status = status
        self.api.opener.open.return_value = response

    def test_empty_successful_delete_and_json_responses_are_supported(self):
        for status in (200, 204):
            with self.subTest(status=status):
                self.respond(b"", status)
                self.assertEqual(self.api.json("DELETE", "/services/fixture"), {})
        for method in ("GET", "POST", "DELETE"):
            with self.subTest(method=method):
                self.respond(b'{"result":"fixture"}')
                self.assertEqual(
                    self.api.json(method, "/services/fixture"), {"result": "fixture"}
                )

    def test_empty_get_post_and_malformed_nonempty_delete_fail_closed(self):
        for method, body, status in (
            ("GET", b"", 200),
            ("POST", b"", 200),
            ("DELETE", b" ", 200),
            ("DELETE", b"not JSON", 200),
            ("DELETE", b"", 500),
        ):
            with self.subTest(method=method, body=body, status=status):
                self.respond(body, status)
                with self.assertRaises(client.Refused):
                    self.api.json(method, "/services/fixture")

    def test_delete_http_errors_retain_status_and_close_response(self):
        for status in (403, 404, 500):
            with self.subTest(status=status):
                body = io.BytesIO(b"private server response")
                self.api.opener.open.side_effect = client.urllib.error.HTTPError(
                    "https://localhost:22009/services/fixture",
                    status,
                    "fixture",
                    {},
                    body,
                )
                with self.assertRaises(client.ApiError) as caught:
                    self.api.json("DELETE", "/services/fixture")
                self.assertEqual(caught.exception.status, status)
                self.assertTrue(body.closed)
                self.assertNotIn("private server response", str(caught.exception))

    def test_original_interface_cleanup_continues_after_empty_success_then_404s(self):
        path = TOOLS.parent / "tests/splunk/test_distributed_interfaces.py"
        spec = importlib.util.spec_from_file_location(
            "offline_distributed_interfaces", path
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        test = module.DistributedInterfacesTest(
            "test_02_populated_inventory_resolves_interface_name"
        )
        test.client = SimpleNamespace(Api=Mock(return_value=self.api))
        self.respond(b"", 200)
        response = self.api.opener.open.return_value
        self.api.opener.open.side_effect = [
            response,
            client.urllib.error.HTTPError(
                "https://localhost:22009/services/fixture",
                404,
                "fixture",
                {},
                io.BytesIO(),
            ),
            client.urllib.error.HTTPError(
                "https://localhost:22009/services/fixture",
                404,
                "fixture",
                {},
                io.BytesIO(),
            ),
        ]
        test.remove_probe("fixture-owned-key")
        self.assertEqual(
            [call.args[0] for call in test.client.Api.call_args_list],
            list(client.MEMBERS),
        )
        self.assertEqual(self.api.opener.open.call_count, 3)
        for call in self.api.opener.open.call_args_list:
            request = call.args[0]
            self.assertEqual(request.get_method(), "DELETE")
            self.assertIn("/adm_interfaces/fixture-owned-key?", request.full_url)
        self.api.opener.open.reset_mock()
        self.api.opener.open.side_effect = client.urllib.error.HTTPError(
            "https://localhost:22009/services/fixture", 403, "fixture", {}, io.BytesIO()
        )
        with self.assertRaises(client.ApiError) as caught:
            test.remove_probe("fixture-owned-key")
        self.assertEqual(caught.exception.status, 403)
        self.api.opener.open.assert_called_once()


class SettingsDefaultVerificationTests(unittest.TestCase):
    BASELINE = b"[persistence]\nwrite_mode = disabled\nplatform = unqualified\nother = keep\n[other]\nvalue = keep\n"
    OVERRIDE = {"write_mode": "qualified_shc", "platform": "enterprise"}

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)

    def check(self, installed, *, recorded=False, override=None):
        path = self.directory / "stage/splunk_adm/default/adm_settings.conf"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(self.BASELINE)
        lab = lifecycle.Lab(self.directory, "adm-shc-settings-default")
        lab.state["candidate_files"] = {
            "default/adm_settings.conf": hashlib.sha256(self.BASELINE).hexdigest()
        }
        if recorded:
            lab.state["settings_override"] = override
        with (
            patch.object(lab, "identity", return_value="a" * 64),
            patch.object(lifecycle, "command", return_value=installed),
        ):
            return lab.verify_candidate()

    def merged(self):
        return self.BASELINE.replace(b"disabled", b"qualified_shc").replace(
            b"unqualified", b"enterprise"
        )

    def test_records_byte_exact_or_exact_merged_variant_without_assuming_push_mode(
        self,
    ):
        for installed, recorded, variant in (
            (self.BASELINE, False, "archive_byte_exact"),
            (self.BASELINE, True, "archive_byte_exact"),
            (self.merged(), True, "task_overlay_merged_to_default"),
        ):
            with self.subTest(recorded=recorded, variant=variant):
                result = self.check(
                    installed, recorded=recorded, override=self.OVERRIDE
                )
                for role in client.MEMBERS:
                    item = result[role]["default/adm_settings.conf"]
                    self.assertEqual(item["observed_variant"], variant)
                    self.assertEqual(
                        item["sha256"], hashlib.sha256(installed).hexdigest()
                    )
                    self.assertEqual(
                        item["archive_file_sha256"],
                        hashlib.sha256(self.BASELINE).hexdigest(),
                    )
                    self.assertEqual(
                        item["expected_overlay"],
                        {"persistence": self.OVERRIDE} if recorded else None,
                    )

    def test_rejects_unrecorded_or_malformed_override_even_with_original_bytes(self):
        with self.assertRaises(client.Refused):
            self.check(self.merged())
        for override in (
            None,
            {},
            [],
            {"write_mode": "qualified_standalone", "platform": "enterprise"},
            {"write_mode": "qualified_shc", "platform": "cloud"},
            {**self.OVERRIDE, "extra": "unexpected"},
        ):
            for installed in (self.BASELINE, self.merged()):
                with (
                    self.subTest(override=override, merged=installed != self.BASELINE),
                    self.assertRaises(client.Refused),
                ):
                    self.check(installed, recorded=True, override=override)

    def test_rejects_any_change_beyond_two_existing_persistence_keys(self):
        merged = self.merged()
        for installed in (
            merged.replace(b"qualified_shc", b"qualified_standalone"),
            merged.replace(b"enterprise", b"unqualified"),
            merged.replace(b"other = keep", b"other = changed"),
            merged.replace(b"value = keep", b"value = changed"),
            merged.replace(
                b"platform = enterprise", b"platform = enterprise\nextra = changed"
            ),
            merged + b"[extra]\nvalue = changed\n",
            merged.replace(b"[other]\nvalue = keep\n", b""),
            merged.replace(b"write_mode", b"Write_mode"),
            merged + b"[DEFAULT]\nextra = changed\n",
            merged.replace(
                b"platform = enterprise",
                b"platform = enterprise\nplatform = enterprise",
            ),
        ):
            with self.subTest(installed=installed), self.assertRaises(client.Refused):
                self.check(installed, recorded=True, override=self.OVERRIDE)

    def test_override_cannot_introduce_a_key_absent_from_archived_baseline(self):
        self.BASELINE = self.BASELINE.replace(b"platform = unqualified\n", b"")
        with self.assertRaises(client.Refused):
            self.check(self.merged(), recorded=True, override=self.OVERRIDE)


class ShcReadinessTests(unittest.TestCase):
    def setUp(self):
        self.state = {
            "created": {
                role: {"name": "adm-shc-readiness-" + role} for role in client.MEMBERS
            }
        }
        self.uris = {
            role: "https://" + item["name"] + ":8089"
            for role, item in self.state["created"].items()
        }
        flags = {
            "initialized_flag": True,
            "min_peers_joined_flag": True,
            "service_ready_flag": True,
        }
        self.responses = {
            role: {
                "/services/shcluster/member/info": {
                    "status": "Up",
                    "is_registered": True,
                    "maintenance_mode": False,
                },
                "/services/shcluster/status?advanced=1": {
                    "captain": {
                        "mgmt_uri": self.uris["sh1"],
                        "id": "cluster-guid",
                        "stable_captain": True,
                        "rolling_restart_flag": False,
                        "rolling_upgrade_flag": False,
                        "kvstore_maintenance_status": "disabled",
                        **flags,
                    },
                    "peers": {
                        "guid-" + member: {
                            "mgmt_uri": uri,
                            "status": "Up",
                            "out_of_sync_node": False,
                            "manual_detention": "off",
                            "restart_required": "0",
                        }
                        for member, uri in self.uris.items()
                    },
                },
                "/services/shcluster/captain/info": dict(flags),
            }
            for role in client.MEMBERS
        }

    def check_ready(self, responses, *, kv=True):
        def api(role):
            return SimpleNamespace(
                json=lambda method, path: {
                    "entry": [{"content": responses[role][path]}]
                }
            )

        with (
            patch.object(client, "STATE", self.state),
            patch.object(client, "Api", side_effect=api),
            patch.object(client, "kv_ready", return_value=kv),
        ):
            return client.verify_shc_ready()

    def test_native_status_schema_requires_no_captain_field_in_member_info(self):
        result = self.check_ready(self.responses)
        self.assertEqual(result["captain"]["role"], "sh1")
        self.assertEqual(result["captain"]["id"], "cluster-guid")
        for role in client.MEMBERS:
            self.assertEqual(result[role]["captain_uri"], self.uris["sh1"])
            self.assertEqual(
                set(result[role]["members"].values()), set(self.uris.values())
            )

    def test_native_status_refuses_unready_unowned_or_disagreeing_evidence(self):
        def member(responses):
            return responses["sh2"]["/services/shcluster/member/info"]

        def status(responses):
            return responses["sh2"]["/services/shcluster/status?advanced=1"]

        mutations = [
            lambda r: member(r).pop("is_registered"),
            lambda r: member(r).update(is_registered=False),
            lambda r: member(r).update(status="Down"),
            lambda r: member(r).update(maintenance_mode=True),
            lambda r: member(r).pop("maintenance_mode"),
            lambda r: status(r).update(captain=None),
            lambda r: status(r).update(peers=[]),
            lambda r: status(r)["peers"].pop("guid-sh3"),
            lambda r: status(r)["peers"].update(
                {"extra": {"mgmt_uri": "https://other:8089", "status": "Up"}}
            ),
            lambda r: status(r)["peers"]["guid-sh3"].update(mgmt_uri=self.uris["sh2"]),
            lambda r: status(r)["peers"]["guid-sh3"].update(
                mgmt_uri=self.uris["sh3"] + ".unrelated"
            ),
            lambda r: status(r)["peers"]["guid-sh3"].update(status="Down"),
            lambda r: status(r)["peers"]["guid-sh3"].update(out_of_sync_node=True),
            lambda r: status(r)["peers"]["guid-sh3"].update(manual_detention="on"),
            lambda r: status(r)["peers"]["guid-sh3"].update(restart_required="1"),
            lambda r: status(r)["peers"]["guid-sh3"].pop("out_of_sync_node"),
            lambda r: status(r)["peers"].update(
                {"different-guid": status(r)["peers"].pop("guid-sh3")}
            ),
            lambda r: status(r)["captain"].update(
                mgmt_uri=self.uris["sh1"] + ".unrelated"
            ),
            lambda r: status(r)["captain"].update(id="different-cluster-guid"),
            lambda r: status(r)["captain"].update(id=""),
            lambda r: status(r)["captain"].update(mgmt_uri=self.uris["sh2"]),
            lambda r: status(r)["captain"].update(initialized_flag=False),
            lambda r: status(r)["captain"].update(min_peers_joined_flag=False),
            lambda r: status(r)["captain"].update(service_ready_flag=False),
            lambda r: status(r)["captain"].update(stable_captain=False),
            lambda r: status(r)["captain"].pop("stable_captain"),
            lambda r: status(r)["captain"].update(rolling_restart_flag=True),
            lambda r: status(r)["captain"].update(rolling_upgrade_flag=True),
            lambda r: status(r)["captain"].update(kvstore_maintenance_status="enabled"),
            lambda r: r["sh1"]["/services/shcluster/captain/info"].update(
                service_ready_flag=False
            ),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(case=index):
                responses = json.loads(json.dumps(self.responses))
                mutate(responses)
                with self.assertRaises(client.Refused):
                    self.check_ready(responses)
        with self.assertRaisesRegex(client.Refused, "KV Store is not ready"):
            self.check_ready(self.responses, kv=False)

    def test_pdl_kv_ready_accepts_native_cohosted_schema_without_mongo_peers(self):
        value = {
            "current": {"status": "ready", "disabled": False, "standalone": False},
            "cohosted": {"status": "ready", "serviceInfo": {"type": "Pdl"}},
            "peers": None,
        }
        with patch.object(client, "Api") as api:
            api.return_value.json.return_value = {"entry": [{"content": value}]}
            self.assertTrue(client.kv_ready("sh1"))

    def test_pdl_kv_ready_refuses_missing_or_unready_cohosted_even_if_current_ready(
        self,
    ):
        base = {
            "current": {"status": "ready", "disabled": False, "standalone": False},
            "cohosted": {"status": "ready", "serviceInfo": {"type": "Pdl"}},
            "peers": None,
        }
        mutations = [
            lambda v: v.pop("cohosted"),
            lambda v: v.update(cohosted=None),
            lambda v: v["cohosted"].update(status="failed"),
            lambda v: v["cohosted"].update(status="starting"),
            lambda v: v["cohosted"].pop("serviceInfo"),
            lambda v: v["cohosted"]["serviceInfo"].update(type="Mongo"),
            lambda v: v["current"].update(status="starting"),
            lambda v: v["current"].update(disabled=True),
            lambda v: v["current"].pop("disabled"),
            lambda v: v["current"].update(standalone=True),
            lambda v: v["current"].pop("standalone"),
        ]
        for index, mutate in enumerate(mutations):
            with self.subTest(case=index), patch.object(client, "Api") as api:
                value = json.loads(json.dumps(base))
                mutate(value)
                api.return_value.json.return_value = {"entry": [{"content": value}]}
                self.assertFalse(client.kv_ready("sh1"))


class ConcurrencyTests(unittest.TestCase):
    @staticmethod
    def settings_read(revision):
        return {
            "canWrite": True,
            "namespace": "namespace",
            "state": "absent" if revision is None else "configured",
            "settings": None if revision is None else {"revision": revision},
        }

    def race_with_convergence_reads(
        self, reads, response_mutator=None, expected_revision=None
    ):
        pending = list(reads)
        state = {"winner": None, "retried": False, "reads": 0, "requests": []}
        self.race_state = state
        lock = __import__("threading").Lock()
        snapshot = self.settings_read

        class FakeApi:
            def __init__(self, role):
                self.role = role

            def json(self, method, path, raw=None):
                if method == "GET":
                    if not state["retried"]:
                        return snapshot(expected_revision)
                    state["reads"] += 1
                    if pending:
                        value = pending.pop(0)
                        return value(state) if callable(value) else value
                    return {
                        **snapshot(state["settings"]["revision"]),
                        "settings": state["settings"],
                    }
                request = json.loads(raw)
                with lock:
                    state["requests"].append(request)
                    if state["winner"] is None:
                        state["winner"] = request["requestId"]
                        state["winning_request"] = request
                        settings = json.loads(client.canonical(request["settings"]))
                        fingerprint = client.digest(
                            [
                                request["expectedRevision"],
                                request["requestId"],
                                settings["schemaVersion"],
                                settings["sources"],
                            ]
                        )
                        settings["revision"] = client.digest(["revision", fingerprint])
                        state["settings"] = settings
                    elif state["winner"] != request["requestId"]:
                        raise client.ApiError(409)
                    else:
                        state["retried"] = True
                response = {
                    **snapshot(state["settings"]["revision"]),
                    "settings": json.loads(client.canonical(state["settings"])),
                    "committedRevision": state["settings"]["revision"],
                    "requestId": state["winner"],
                }
                return (
                    response_mutator(response, state["retried"])
                    if response_mutator
                    else response
                )

        wait = client.wait_for
        with (
            patch.object(client, "Api", FakeApi),
            patch.object(
                client,
                "wait_for",
                side_effect=lambda check: wait(check, timeout=0.2, interval=0.001),
            ),
        ):
            result = client.settings_race(
                expected_revision,
                [
                    {
                        "schemaVersion": 1,
                        "revision": "draft-a",
                        "sources": {
                            "netflow": {
                                "state": "active",
                                "cadenceSeconds": 300,
                                "staleAfterSeconds": 1200,
                            }
                        },
                    },
                    {
                        "schemaVersion": 1,
                        "revision": "draft-b",
                        "sources": {
                            "netflow": {
                                "state": "staged",
                                "cadenceSeconds": 300,
                                "staleAfterSeconds": 1200,
                            }
                        },
                    },
                ],
                "namespace",
            )
        return result, state

    def test_settings_race_waits_through_null_and_old_revision_for_exact_winner(self):
        result, state = self.race_with_convergence_reads(
            [
                self.settings_read(None),
                self.settings_read("older"),
            ]
        )
        self.assertEqual(sorted(result["statuses"]), [200, 409])
        self.assertTrue(state["retried"])
        self.assertEqual(state["reads"], 5)

    def test_settings_convergence_rejects_malformed_state_settings_and_revision(self):
        malformed = [
            None,
            [],
            {},
            {"canWrite": True, "namespace": "namespace", "state": "absent"},
        ]
        for settings in ([], "invalid", 1):
            malformed.append({**self.settings_read("winner"), "settings": settings})
        malformed.extend(
            [
                {**self.settings_read("winner"), "settings": None},
                {**self.settings_read("winner"), "state": "absent"},
                {**self.settings_read("winner"), "canWrite": False},
                {**self.settings_read("winner"), "namespace": "other"},
                {**self.settings_read("winner"), "settings": {}},
            ]
        )
        for revision in (None, 1, [], "", " ", "bad revision", "x" * 81):
            malformed.append(
                {**self.settings_read("winner"), "settings": {"revision": revision}}
            )
        for response in malformed:
            with self.subTest(response=response), self.assertRaises(client.Refused):
                self.race_with_convergence_reads([response])

    def test_settings_commit_and_retry_require_valid_revision_and_winning_request_id(
        self,
    ):
        mutations = [
            lambda r: None,
            lambda r: [],
            lambda r: {
                key: value for key, value in r.items() if key != "committedRevision"
            },
            lambda r: {key: value for key, value in r.items() if key != "requestId"},
            lambda r: {**r, "requestId": None},
            lambda r: {**r, "requestId": "different-request"},
        ]
        for value in (None, 1, [], {}, "", " ", "bad revision", "x" * 81):
            mutations.append(lambda r, value=value: {**r, "committedRevision": value})
        for retry in (False, True):
            for index, mutate in enumerate(mutations):
                with self.subTest(retry=retry, case=index):
                    with self.assertRaises(client.Refused):
                        self.race_with_convergence_reads(
                            [self.settings_read(None)],
                            response_mutator=lambda r, is_retry: (
                                mutate(r) if is_retry == retry else r
                            ),
                        )
                    self.assertEqual(self.race_state["retried"], retry)
                    self.assertEqual(self.race_state["reads"], 0)

    def test_settings_retry_cannot_change_a_valid_committed_revision(self):
        with self.assertRaisesRegex(client.Refused, "retry changed"):
            self.race_with_convergence_reads(
                [],
                response_mutator=lambda r, retry: (
                    {**r, "committedRevision": "different-revision"} if retry else r
                ),
            )

    def test_original_commit_cannot_choose_a_different_valid_revision(self):
        with self.assertRaisesRegex(client.Refused, "commit revision differs"):
            self.race_with_convergence_reads(
                [],
                response_mutator=lambda value, retry: {
                    **value,
                    "committedRevision": "unrequested-valid-revision",
                },
            )
        self.assertFalse(self.race_state["retried"])

    def test_original_and_retry_must_return_exact_expected_committed_payload(self):
        def wrong_sources(value):
            settings = json.loads(client.canonical(value["settings"]))
            settings["sources"]["netflow"]["cadenceSeconds"] = 600
            return {**value, "settings": settings}

        mutations = [
            wrong_sources,
            lambda value: {
                **value,
                "settings": {**value["settings"], "schemaVersion": True},
            },
            lambda value: {
                **value,
                "settings": {**value["settings"], "extra": "unrequested"},
            },
            lambda value: {
                **value,
                "settings": {
                    **value["settings"],
                    "revision": "different-valid-revision",
                },
            },
        ]
        for retry in (False, True):
            for index, mutate in enumerate(mutations):
                with (
                    self.subTest(retry=retry, case=index),
                    self.assertRaises(client.Refused),
                ):
                    self.race_with_convergence_reads(
                        [],
                        response_mutator=lambda value, is_retry: (
                            mutate(value) if is_retry == retry else value
                        ),
                    )

    def test_member_with_winning_revision_but_wrong_full_payload_is_rejected(self):
        def response(state, wrong=False):
            settings = json.loads(client.canonical(state["settings"]))
            if wrong:
                settings["sources"]["netflow"]["state"] = "not_selected"
            return {**self.settings_read(settings["revision"]), "settings": settings}

        with self.assertRaisesRegex(client.Refused, "exact winning operation"):
            self.race_with_convergence_reads(
                [response, lambda state: response(state, True)]
            )
        self.assertEqual(self.race_state["reads"], 2)

    def test_members_race_then_retry_winning_commit(self):
        result, state = self.race_with_convergence_reads([])
        self.assertEqual(sorted(result["statuses"]), [200, 409])
        self.assertTrue(result["retry_identical"])
        self.assertEqual(len(state["requests"]), 3)
        self.assertTrue(
            all(
                "settings" in request and "payload" not in request
                for request in state["requests"]
            )
        )
        self.assertNotEqual(
            result["committed_revision"],
            state["winning_request"]["settings"]["revision"],
        )
        self.assertEqual(result["committed_revision"], state["settings"]["revision"])
        self.assertEqual(
            result["submitted_settings_sha256"],
            client.digest(state["winning_request"]["settings"]),
        )
        self.assertEqual(
            result["expected_committed_settings_sha256"],
            client.digest(state["settings"]),
        )
        self.assertTrue(result["all_member_settings_agree"])

    def test_server_revision_derivation_binds_nonempty_prior_revision(self):
        result, state = self.race_with_convergence_reads(
            [], expected_revision="prior-revision"
        )
        request = state["winning_request"]
        operation = [
            "prior-revision",
            request["requestId"],
            request["settings"]["schemaVersion"],
            request["settings"]["sources"],
        ]

        def sha(value):
            return hashlib.sha256(
                json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
            ).hexdigest()

        fingerprint = sha(operation)
        self.assertEqual(result["operation_fingerprint"], fingerprint)
        self.assertEqual(result["committed_revision"], sha(["revision", fingerprint]))
        self.assertNotEqual(
            result["committed_revision"], sha(["revision", sha([None, *operation[1:]])])
        )

    def test_settings_race_refuses_different_namespaces_before_writes(self):
        class FakeApi:
            def __init__(self, role):
                pass

            def json(self, method, path):
                self.assert_get = method == "GET"
                return {"canWrite": True, "namespace": "different", "settings": None}

        with patch.object(client, "Api", FakeApi), self.assertRaises(client.Refused):
            client.settings_race(None, [{}, {}], "namespace")


class CollectionScanTests(unittest.TestCase):
    def api(self, documents, cap=None):
        class FakeApi:
            def __init__(self):
                self.queries = []

            def json(self, method, path):
                self.assert_get = method == "GET"
                query = __import__("urllib.parse", fromlist=["parse_qs"]).parse_qs(
                    path.split("?", 1)[1]
                )
                self.queries.append(query)
                skip, limit = int(query["skip"][0]), int(query["limit"][0])
                return documents[
                    skip : skip + min(limit, cap if cap is not None else limit)
                ]

        return FakeApi()

    def test_hidden_lower_server_cap_never_becomes_a_complete_snapshot(self):
        api = self.api([{"_key": key} for key in ("a", "b", "c", "d")], cap=2)
        with self.assertRaisesRegex(client.Refused, "capped or unstable"):
            runner.complete_collection_rows(api, "/services/collection")
        self.assertEqual(len(api.queries), 4)
        self.assertTrue(
            all(
                query["limit"] == ["10000"] and query["sort"] == ["_key:1"]
                for query in api.queries
            )
        )

    def test_complete_scan_requires_shifted_overlap_and_unchanged_confirmation(self):
        documents = [{"_key": key, "value": key} for key in ("a", "b", "c")]
        api = self.api(documents)
        self.assertEqual(
            runner.complete_collection_rows(api, "/services/collection"), documents
        )
        self.assertEqual(
            [query["skip"] for query in api.queries], [["0"], ["1"], ["0"]]
        )

    def test_unstable_first_row_fails_even_when_shifted_tail_matches(self):
        class ChangingApi:
            def __init__(self):
                self.calls, self.version = 0, 0

            def json(self, method, path):
                self.calls += 1
                if "skip=1" in path:
                    return [{"_key": "b"}]
                self.version += 1
                return [{"_key": "a", "value": self.version}, {"_key": "b"}]

        api = ChangingApi()
        with self.assertRaisesRegex(client.Refused, "capped or unstable"):
            runner.complete_collection_rows(api, "/services/collection")
        self.assertEqual(api.calls, 6)

    def test_malformed_unordered_duplicate_or_bound_reaching_scan_is_refused(self):
        for documents in (
            [{"_key": "b"}, {"_key": "a"}],
            [{"_key": "a"}, {"_key": "a"}],
            [{"value": "missing key"}],
            [{"_key": "a"}, {"_key": "b"}, {"_key": "c"}],
        ):
            with self.subTest(documents=documents), self.assertRaises(client.Refused):
                runner.complete_collection_rows(
                    self.api(documents), "/services/collection", limit=3
                )


class PtyLoginTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        namespace = {"__name__": "qualification_offline_test"}
        exec(
            compile(lifecycle.LOGIN_PTY_HELPER, "qualification_cli_pty", "exec"),
            namespace,
        )
        self.login = namespace["login_pty"]
        self.namespace = namespace

    def program(self, source):
        path = self.directory / "fake_cli.py"
        path.write_text(source)
        return (sys.executable, str(path))

    def interactive_program(self, ending):
        return self.program(
            """import os, sys, termios
assert all(os.isatty(fd) for fd in (0,1,2))
os.close(os.open("/dev/tty", os.O_RDWR))
print("Splunk username: ", end="", flush=True)
username = sys.stdin.readline().strip()
print("Password: ", end="", flush=True)
password = sys.stdin.readline().strip()
assert not termios.tcgetattr(0)[3] & (termios.ECHO | termios.ECHONL)
assert username == "fixture-admin" and password == "fixture-password"
"""
            + ending
        )

    def test_real_controlling_tty_prompt_flow_has_no_transcript_or_secret_output(self):
        result = self.login(
            "fixture-admin",
            "fixture-password",
            argv=self.interactive_program(
                'print(username, password, "private-transcript-marker", flush=True)\n'
            ),
            timeout=2,
        )
        self.assertEqual(result["status"], "completed")
        self.assertTrue(
            result["username_prompt"]
            and result["password_prompt"]
            and result["child_reaped"]
        )
        self.assertNotIn("fixture-password", json.dumps(result))
        self.assertNotIn("private-transcript-marker", json.dumps(result))

    def test_successful_cached_login_needs_no_prompts(self):
        result = self.login(
            "fixture-admin",
            "fixture-password",
            argv=self.program('print("cached session accepted")\n'),
            timeout=2,
        )
        self.assertEqual(result["status"], "completed")
        self.assertFalse(result["username_prompt"] or result["password_prompt"])
        self.assertTrue(result["child_reaped"])

    def test_child_scrubs_bootstrap_credentials_without_changing_parent_environment(
        self,
    ):
        bootstrap = {
            "SPLUNK_USERNAME": "fixture-env-user",
            "SPLUNK_PASSWORD": "fixture-env-password",
            "SPLUNK_PASSCODE": "fixture-env-passcode",
        }
        program = self.interactive_program('print("interactive login accepted")\n')
        path = Path(program[1])
        path.write_text(
            "import os\n"
            "assert not any(key in os.environ for key in "
            + repr(tuple(bootstrap))
            + ")\n"
            + path.read_text()
        )
        with patch.dict(os.environ, bootstrap):
            result = self.login(
                "fixture-admin", "fixture-password", argv=program, timeout=2
            )
            self.assertEqual({key: os.environ[key] for key in bootstrap}, bootstrap)
        self.assertEqual(result["status"], "completed")
        self.assertTrue(result["username_prompt"] and result["password_prompt"])
        self.assertTrue(result["child_reaped"])

    def exited_child(self, chunks, *, waiting=None):
        """Deterministically expose queued output after waitpid reports exit."""
        selector = Mock()
        selector.__enter__ = Mock(return_value=selector)
        selector.__exit__ = Mock(return_value=False)
        selector.select.return_value = [True]
        operating = SimpleNamespace(
            WNOHANG=1,
            waitpid=Mock(side_effect=(waiting or [(123, 0)]) + [(123, -9)]),
            waitstatus_to_exitcode=lambda status: status,
            set_blocking=Mock(),
            read=Mock(side_effect=chunks),
            write=Mock(side_effect=lambda fd, data: len(data)),
            close=Mock(),
            killpg=Mock(),
        )
        terminal = SimpleNamespace(
            ECHO=1,
            ECHONL=2,
            TCSANOW=0,
            tcgetattr=lambda fd: [0, 0, 0, 0],
            tcsetattr=Mock(),
        )
        with patch.dict(
            self.namespace,
            {
                "os": operating,
                "pty": SimpleNamespace(fork=lambda: (123, 456)),
                "termios": terminal,
                "selectors": SimpleNamespace(
                    DefaultSelector=lambda: selector, EVENT_READ=1
                ),
            },
        ):
            result = self.login("fixture-admin", "fixture-password", timeout=2)
        return result, operating

    def test_exit_before_drain_rejects_queued_invalid_prompts(self):
        for chunk, status in (
            (b"Splunk username: ", "incomplete_prompt"),
            (b"Password: ", "unexpected_prompt"),
            (b"Password: \r\ntrailing message", "unexpected_prompt"),
        ):
            with self.subTest(chunk=chunk):
                result, operating = self.exited_child([chunk, b""])
                self.assertEqual(result["status"], status)
                self.assertTrue(result["child_reaped"])
                operating.read.assert_called()
                operating.write.assert_not_called()
        result, operating = self.exited_child(
            [b"Splunk username: ", b"Password: ", b"Password: \r\ntrailing message"],
            waiting=[(0, 0), (0, 0), (123, 0)],
        )
        self.assertEqual(result["status"], "unexpected_prompt")
        self.assertTrue(result["child_reaped"])
        self.assertEqual(operating.write.call_count, 2)
        result, operating = self.exited_child(
            [b"Splunk username: \r\nPassword: \r\nPassword: \r\ntrailing message"],
            waiting=[(0, 0)],
        )
        self.assertEqual(result["status"], "unexpected_prompt")
        self.assertEqual(operating.write.call_count, 2)

    def test_exit_before_drain_enforces_output_bound_and_eof(self):
        result, operating = self.exited_child([b"x" * 4096] * 17 + [b""])
        self.assertEqual(result["status"], "output_limit")
        self.assertTrue(result["child_reaped"])
        self.assertEqual(operating.read.call_count, 17)
        for eof in (b"", OSError(5, "fixture EIO")):
            with self.subTest(eof=type(eof)):
                result, operating = self.exited_child([b"cached session accepted", eof])
                self.assertEqual(result["status"], "completed")
                self.assertTrue(result["child_reaped"])
                self.assertEqual(operating.read.call_count, 2)

    def test_partial_out_of_order_and_repeated_prompt_flows_fail_closed(self):
        cases = [
            (
                'print("Splunk username: ",end="",flush=True)\nsys.stdin.readline()\n',
                "incomplete_prompt",
            ),
            (
                'print("Password: ",end="",flush=True)\nsys.stdin.readline()\n',
                "unexpected_prompt",
            ),
        ]
        for source, status in cases:
            with self.subTest(status=status):
                result = self.login(
                    "fixture-admin",
                    "fixture-password",
                    argv=self.program("import sys\n" + source),
                    timeout=2,
                )
                self.assertEqual(result["status"], status)
                self.assertFalse(result["password_prompt"])
                self.assertTrue(result["child_reaped"])
        result = self.login(
            "fixture-admin",
            "fixture-password",
            argv=self.interactive_program(
                'print("Password: ",end="",flush=True)\nsys.stdin.readline()\n'
            ),
            timeout=2,
        )
        self.assertEqual(result["status"], "unexpected_prompt")
        self.assertTrue(result["child_reaped"])

    def test_rejected_login_is_not_retried(self):
        marker = self.directory / "invocations"
        ending = (
            "from pathlib import Path\np=Path("
            + repr(str(marker))
            + ")\n"
            + 'p.write_text(p.read_text()+"x" if p.exists() else "x")\nsys.exit(3)\n'
        )
        result = self.login(
            "fixture-admin",
            "fixture-password",
            argv=self.interactive_program(ending),
            timeout=2,
        )
        self.assertEqual((result["status"], result["exit_code"]), ("rejected", 3))
        self.assertEqual(marker.read_text(), "x")
        self.assertTrue(result["child_reaped"])

    def test_timeout_and_output_overflow_kill_and_reap_child(self):
        result = self.login(
            "fixture-admin",
            "fixture-password",
            argv=self.program("import time\ntime.sleep(10)\n"),
            timeout=0.15,
        )
        self.assertEqual((result["status"], result["exit_code"]), ("timeout", -9))
        self.assertTrue(result["child_reaped"])
        result = self.login(
            "fixture-admin",
            "fixture-password",
            argv=self.program(
                'import sys,time\nsys.stdout.write("x"*70000)\nsys.stdout.flush()\ntime.sleep(10)\n'
            ),
            timeout=2,
        )
        self.assertEqual(result["status"], "output_limit")
        self.assertTrue(result["child_reaped"])

    def test_docker_login_keeps_credentials_in_stdin_only(self):
        (self.directory / "evidence").mkdir()
        credentials = {"username": "fixture-admin", "password": "fixture-cli-secret"}
        lifecycle.private_write(
            self.directory / "admin.json", client.canonical(credentials)
        )
        lab = lifecycle.Lab(
            self.directory, "adm-shc-pty-test", lock_file=self.directory / "lock"
        )
        metadata = {
            "status": "completed",
            "exit_code": 0,
            "username_prompt": False,
            "password_prompt": False,
            "child_reaped": True,
        }
        with (
            lab.locked(),
            patch.object(lab, "identity", return_value="a" * 64),
            patch.object(
                lifecycle, "command", return_value=client.canonical(metadata)
            ) as command,
        ):
            self.assertEqual(lab.login("sh1"), metadata)
        args = command.call_args.args[0]
        self.assertIn("/opt/splunk/bin/python3.13", args)
        self.assertNotIn(credentials["password"], " ".join(args))
        self.assertEqual(json.loads(command.call_args.kwargs["data"]), credentials)
        self.assertEqual(command.call_args.kwargs["timeout"], 70)
        self.assertNotIn(
            credentials["password"], (self.directory / "state.json").read_text()
        )
        metadata["status"], metadata["exit_code"] = "rejected", 3
        with (
            lab.locked(),
            patch.object(lab, "identity", return_value="a" * 64),
            patch.object(lifecycle, "command", return_value=client.canonical(metadata)),
        ):
            with self.assertRaisesRegex(client.Refused, "interactive CLI login failed"):
                lab.login("sh1")
        records = list((self.directory / "evidence").glob("cli-login-*.json"))
        self.assertEqual(len(records), 2)
        self.assertEqual(
            {json.loads(path.read_text())["status"] for path in records},
            {"completed", "rejected"},
        )
        for path in records:
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertNotIn(credentials["password"], path.read_text())


class IndexedSourcetypeOracleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.source = Path(self.temp.name)
        self.addon = self.source / "reviewed/CiscoSecurityCloud"
        default = self.addon / "default"
        default.mkdir(parents=True)
        (default / "props.conf").write_text(
            "[cisco:isovalent]\n"
            "TRANSFORMS-set_isovalent_sourcetype = set_sourcetype_processConnect, "
            "set_sourcetype_processExec, set_sourcetype_alert, "
            "set_sourcetype_telemetry_network, set_sourcetype_telemetry_process\n"
        )
        (default / "transforms.conf").write_text(
            '[set_sourcetype_processConnect]\nREGEX = \\"process_connect\\"\n'
            "DEST_KEY = MetaData:Sourcetype\nFORMAT = sourcetype::cisco:isovalent:processConnect\n"
            '[set_sourcetype_processExec]\nREGEX = \\"process_exec\\"\n'
            "DEST_KEY = MetaData:Sourcetype\nFORMAT = sourcetype::cisco:isovalent:processExec\n"
            '[set_sourcetype_alert]\nREGEX = "event"\n'
            "DEST_KEY = MetaData:Sourcetype\nFORMAT = sourcetype::cisco:isovalent:alert\n"
            "[set_sourcetype_telemetry_network]\n"
            'REGEX = \\"event_type\\":\\s*\\"(TELEMETRY_TYPE_NETWORK_CONNECT)\\"\n'
            "DEST_KEY = MetaData:Sourcetype\nFORMAT = sourcetype::cisco:isovalent:telemetry:network\n"
            "[set_sourcetype_telemetry_process]\n"
            'REGEX = \\"event_type\\":\\s*\\"(TELEMETRY_TYPE_PROCESS)\\"\n'
            "DEST_KEY = MetaData:Sourcetype\nFORMAT = sourcetype::cisco:isovalent:telemetry:process\n"
        )
        self.hashes = {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in default.iterdir()
        }
        # The test uses small literal TA stanzas, not downloaded runtime inputs.
        # Semantic guards are exercised independently of the full-file hash pin.
        pin = patch.object(runner, "ISOVALENT_CONFIG_SHA256", self.hashes)
        pin.start()
        self.addCleanup(pin.stop)

    def contract(self):
        return runner.isovalent_indexed_sourcetype_contract(self.source, [self.addon])

    def envelope(self):
        return {
            "index": "cisco_isovalent",
            "sourcetype": "cisco:isovalent",
            "event": {"process_connect": {"source_ip": "192.0.2.1"}},
        }

    def test_exact_ta_rule_rewrites_only_declared_process_connect(self):
        contract = self.contract()
        self.assertEqual(
            runner.expected_indexed_sourcetype(self.envelope(), contract),
            "cisco:isovalent:processConnect",
        )
        self.assertEqual(contract["props_stanza"], "cisco:isovalent")
        self.assertEqual(
            contract["transform_order"][0], "set_sourcetype_processConnect"
        )
        self.assertEqual(
            contract["transforms"]["set_sourcetype_processConnect"],
            {
                "REGEX": r"\"process_connect\"",
                "DEST_KEY": "MetaData:Sourcetype",
                "FORMAT": "sourcetype::cisco:isovalent:processConnect",
            },
        )
        for name, expected in self.hashes.items():
            self.assertEqual(
                contract["source_files"]["reviewed/CiscoSecurityCloud/default/" + name],
                expected,
            )
            self.assertEqual(
                contract["support_files"]["CiscoSecurityCloud/default/" + name],
                expected,
            )

    def test_unknown_declared_subtypes_wrong_index_and_malformed_payload_refuse(self):
        contract = self.contract()
        for field, value in (
            ("sourcetype", "cisco:isovalent:processExec"),
            ("sourcetype", "cisco:isovalent:processConnect"),
            ("sourcetype", "cisco:isovalent:anything"),
            ("sourcetype", "cisco:isovalentBogus"),
            ("index", "other"),
            ("event", {}),
            ("event", {"process_exec": {"pid": 1}}),
            ("event", {"process_connect": {}}),
            ("event", {"process_connect": []}),
            ("event", {"process_connect": "wrong"}),
            ("event", "not a JSON object"),
        ):
            envelope = self.envelope()
            envelope[field] = value
            with (
                self.subTest(field=field, value=value),
                self.assertRaises(client.Refused),
            ):
                runner.expected_indexed_sourcetype(envelope, contract)
        for envelope in (
            None,
            [],
            {},
            {"index": "cisco_isovalent", "sourcetype": None},
        ):
            with self.subTest(envelope=envelope), self.assertRaises(client.Refused):
                runner.expected_indexed_sourcetype(envelope, contract)

    def test_conflicting_native_transform_discriminators_refuse(self):
        contract = self.contract()
        for key, value in (
            ("process_exec", {"pid": 1}),
            ("event", {}),
            ("event_type", "TELEMETRY_TYPE_NETWORK_CONNECT"),
            ("event_type", "TELEMETRY_TYPE_PROCESS"),
        ):
            envelope = self.envelope()
            envelope["event"][key] = value
            with (
                self.subTest(key=key, value=value),
                self.assertRaisesRegex(client.Refused, "conflicting"),
            ):
                runner.expected_indexed_sourcetype(envelope, contract)

    def test_non_isovalent_fixture_sourcetype_is_unchanged(self):
        self.assertEqual(
            runner.expected_indexed_sourcetype(
                {
                    "index": "cisco_dc",
                    "sourcetype": "cisco:dc:nexus9k",
                    "event": "native raw text",
                },
                self.contract(),
            ),
            "cisco:dc:nexus9k",
        )

    def test_configuration_missing_duplicate_changed_or_outside_source_refuses(self):
        for roots in ([], [self.addon, self.addon]):
            with self.subTest(roots=roots), self.assertRaises(client.Refused):
                runner.isovalent_indexed_sourcetype_contract(self.source, roots)
        with self.assertRaises(client.Refused):
            runner.isovalent_indexed_sourcetype_contract(
                self.source / "other", [self.addon]
            )
        props = self.addon / "default/props.conf"
        data = props.read_bytes()
        props.write_bytes(data + b"\n#changed\n")
        with self.assertRaisesRegex(client.Refused, "hash differs"):
            self.contract()
        props.unlink()
        with self.assertRaisesRegex(client.Refused, "missing"):
            self.contract()

    def test_rehashed_wrong_order_regex_format_destination_or_missing_rule_refuses(
        self,
    ):
        for case in ("order", "regex", "format", "destination", "missing", "malformed"):
            name = "props.conf" if case == "order" else "transforms.conf"
            path = self.addon / "default" / name
            original = path.read_bytes()
            changed = original
            if case == "order":
                changed = changed.replace(
                    b"set_sourcetype_processConnect, set_sourcetype_processExec",
                    b"set_sourcetype_processExec, set_sourcetype_processConnect",
                )
            elif case == "regex":
                changed = changed.replace(b"process_connect", b"process_close")
            elif case == "format":
                changed = changed.replace(
                    b"sourcetype::cisco:isovalent:processConnect",
                    b"sourcetype::cisco:isovalent:processExec",
                )
            elif case == "destination":
                changed = changed.replace(b"MetaData:Sourcetype", b"MetaData:Host")
            elif case == "missing":
                changed = changed.replace(
                    b"[set_sourcetype_processConnect]", b"[missing]"
                )
            else:
                changed = b"not a config file\n"
            path.write_bytes(changed)
            self.hashes[name] = hashlib.sha256(changed).hexdigest()
            with self.subTest(case=case), self.assertRaises(client.Refused):
                self.contract()
            path.write_bytes(original)
            self.hashes[name] = hashlib.sha256(original).hexdigest()

    def test_complete_fixture_classification_records_exact_declared_and_indexed_types(
        self,
    ):
        expected, evidence = runner.base_input_classification(
            TOOLS.parent, runner.base_input_paths(TOOLS.parent), self.contract()
        )
        self.assertEqual(sum(expected.values()), 963)
        self.assertEqual(len(expected), 16)
        self.assertEqual(expected[("cisco_dc", "cisco:dc:nexus9k")], 105)
        self.assertEqual(
            expected[("cisco_isovalent", "cisco:isovalent:processConnect")], 4
        )
        self.assertNotIn(("cisco_isovalent", "cisco:isovalent"), expected)
        self.assertEqual(
            evidence["declared_to_indexed"],
            [
                {
                    "index": "cisco_isovalent",
                    "input_sourcetype": "cisco:isovalent",
                    "indexed_sourcetype": "cisco:isovalent:processConnect",
                    "count": 4,
                }
            ],
        )
        self.assertEqual(sum(row["count"] for row in evidence["declared"]), 963)
        self.assertEqual(
            evidence["sourcetype_transform_contract"]["source_files"],
            self.contract()["source_files"],
        )

    def test_fixture_loss_added_row_or_malformed_ndjson_refuses(self):
        paths = runner.base_input_paths(TOOLS.parent)
        original = TOOLS.parent / "fixtures/raw-aci/isovalent.ndjson"
        for case in ("missing-row", "added-row", "malformed"):
            rows = original.read_text().splitlines()
            data = "\n".join(rows[:-1] if case == "missing-row" else rows + [rows[0]])
            if case == "malformed":
                data = "{not-json}"
            changed = self.source / "fixtures/raw-aci/isovalent.ndjson"
            changed.parent.mkdir(parents=True, exist_ok=True)
            changed.write_text(data + "\n")
            # Preserve source-relative paths while changing only one read.
            read_text = Path.read_text

            def fixture_read(path, *args, **kwargs):
                return data if path == original else read_text(path, *args, **kwargs)

            with (
                self.subTest(case=case),
                patch.object(Path, "read_text", fixture_read),
                self.assertRaises(client.Refused),
            ):
                runner.base_input_classification(TOOLS.parent, paths, self.contract())


class DriverTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        directory = Path(self.temp.name)
        self.lab = lifecycle.Lab(
            directory / "lab", "adm-shc-driver", lock_file=directory / "lock"
        )
        self.driver = runner.Driver(
            self.lab,
            TOOLS.parent,
            directory / "candidate.tgz",
            "a" * 40,
            [directory / "reviewed-addon"],
        )

    def indexed_contract(self):
        contract = {
            "source_files": {},
            "support_files": {
                "CiscoSecurityCloud/default/" + name: value
                for name, value in runner.ISOVALENT_CONFIG_SHA256.items()
            },
            "transform_order": list(runner.ISOVALENT_TRANSFORMS),
            "transforms": runner.ISOVALENT_TRANSFORMS,
            "input_sourcetype": "cisco:isovalent",
            "indexed_sourcetype": "cisco:isovalent:processConnect",
            "fixture_event_key": "process_connect",
        }
        self.lab.state["support_files"] = contract["support_files"]
        return contract

    def bootstrap_state(self):
        self.lab.directory.mkdir()
        (self.lab.directory / "evidence").mkdir()
        self.lab.state.update(
            {
                "source_sha": self.driver.source_sha,
                "archive_sha256": "b" * 64,
                "network": {"id": "c" * 64, "name": self.lab.task + "-network"},
                "test_hashes": {
                    "tools/qualification_shc_run.py": hashlib.sha256(
                        (TOOLS / "qualification_shc_run.py").read_bytes()
                    ).hexdigest()
                },
                "created": {
                    role: {
                        "id": str(index + 1) * 64,
                        "name": self.lab.task + "-" + role,
                        "url": "https://localhost:" + str(22009 + index * 10),
                    }
                    for index, role in enumerate(client.ROLES)
                },
            }
        )
        self.driver.completed = list(runner.Driver.ORDER[:4])
        return json.loads(client.canonical(self.lab.state))

    def test_bootstrap_acknowledged_timeout_retry_only_rechecks_native_readiness(self):
        configured = self.bootstrap_state()
        native = {role: {"native_gate": "ready"} for role in client.MEMBERS}
        waits = []

        def wait(check, *, timeout):
            self.assertIs(check, client.verify_shc_ready)
            self.assertEqual(timeout, 1200)
            waits.append(timeout)
            value = check()
            if len(waits) == 1:
                raise client.Refused("readiness deadline")
            return value

        def bootstrap():
            saved = json.loads((self.lab.directory / "state.json").read_text())
            self.assertEqual(saved["bootstrap_dispatch"]["state"], "started")
            self.assertNotIn("acknowledged_utc", saved["bootstrap_dispatch"])

        with (
            self.lab.locked(),
            patch.dict(client.STATE, configured, clear=True),
            patch.object(
                self.lab,
                "identity",
                side_effect=lambda role: configured["created"][role]["id"],
            ),
            patch.object(self.lab, "bootstrap", side_effect=bootstrap) as dispatch,
            patch.object(client, "verify_shc_ready", return_value=native) as gate,
            patch.object(self.driver, "_wait", side_effect=wait),
        ):
            with self.assertRaisesRegex(client.Refused, "readiness deadline"):
                self.driver.run_phase("bootstrap")
            failures = list(
                (self.lab.directory / "evidence").glob("bootstrap-failed-*.json")
            )
            self.assertEqual(len(failures), 1)
            first_failure = failures[0].read_bytes()
            with self.assertRaisesRegex(client.Refused, "explicit rerun"):
                self.driver.run_phase("bootstrap")
            result = self.driver.run_phase("bootstrap", rerun=True)
            self.assertEqual(result["result"], native)
            self.assertEqual(failures[0].read_bytes(), first_failure)
            dispatch.assert_called_once()
            self.assertEqual(gate.call_count, 2)
        saved = json.loads((self.lab.directory / "state.json").read_text())
        journal = saved["bootstrap_dispatch"]
        self.assertEqual(journal["state"], "acknowledged")
        self.assertEqual(journal["readiness_attempts"], 2)
        self.assertEqual(len(journal["readiness_failures"]), 1)
        records = [
            json.loads(path.read_text())
            for path in (self.lab.directory / "evidence").glob(
                "bootstrap-readiness-attempt-*.json"
            )
        ]
        self.assertEqual(
            {row["mode"] for row in records},
            {"initial", "acknowledged_readiness_retry"},
        )
        self.assertEqual(
            {row["binding_sha256"] for row in records},
            {client.digest(journal["binding"])},
        )
        for record in records:
            self.assertEqual(datetime.fromisoformat(record["utc"]).tzinfo, timezone.utc)

    def test_bootstrap_manifest_records_detached_persisted_journal_without_credentials(
        self,
    ):
        configured = self.bootstrap_state()
        native = {"sh1": {"captain_id": "native-cluster-guid", "kv": "ready"}}
        self.lab.state["account_files"] = {"admin": "/private/admin.json"}
        self.lab.state["nonjournal_secret"] = "must-not-be-exported"
        with (
            self.lab.locked(),
            patch.dict(client.STATE, configured, clear=True),
            patch.object(
                self.lab,
                "identity",
                side_effect=lambda role: configured["created"][role]["id"],
            ),
            patch.object(self.lab, "bootstrap"),
            patch.object(self.driver, "_wait", return_value=native),
        ):
            before = self.driver.phase_manifest()
            self.assertNotIn("bootstrap_dispatch", before)
            outcome = self.driver.run_phase("bootstrap")
            persisted = json.loads((self.lab.directory / "state.json").read_text())
            manifest = self.driver.run_phase("manifest")["result"]
            records = list(
                (self.lab.directory / "evidence").glob("manifest-passed-*.json")
            )
            self.assertEqual(len(records), 1)
            recorded = json.loads(records[0].read_text())["result"]
            self.assertEqual(
                recorded["bootstrap_dispatch"], persisted["bootstrap_dispatch"]
            )
            self.assertEqual(
                manifest["bootstrap_dispatch"], persisted["bootstrap_dispatch"]
            )
            self.assertNotIn("must-not-be-exported", json.dumps(recorded))
            self.assertNotIn("/private/admin.json", json.dumps(recorded))
            self.assertEqual(outcome["result"], native)
            manifest["bootstrap_dispatch"]["binding"]["created"]["sh1"]["id"] = (
                "changed"
            )
            manifest["bootstrap_dispatch"]["readiness_failures"].append(
                {"changed": True}
            )
            self.assertEqual(
                self.lab.state["bootstrap_dispatch"], persisted["bootstrap_dispatch"]
            )
            self.assertEqual(self.driver.results["bootstrap"]["result"], native)
            self.assertEqual(json.loads(records[0].read_text())["result"], recorded)

    def test_bootstrap_uncertain_cli_response_never_redispatches(self):
        configured = self.bootstrap_state()
        with (
            self.lab.locked(),
            patch.dict(client.STATE, configured, clear=True),
            patch.object(
                self.lab,
                "identity",
                side_effect=lambda role: configured["created"][role]["id"],
            ),
            patch.object(
                self.lab, "bootstrap", side_effect=client.ApiError(400)
            ) as dispatch,
            patch.object(self.driver, "_wait") as wait,
        ):
            with self.assertRaises(client.ApiError):
                self.driver.run_phase("bootstrap")
            self.assertEqual(
                json.loads((self.lab.directory / "state.json").read_text())[
                    "bootstrap_dispatch"
                ]["state"],
                "started",
            )
            for state in ("started", "failed", "lost_response"):
                self.lab.state["bootstrap_dispatch"]["state"] = state
                with (
                    self.subTest(state=state),
                    self.assertRaisesRegex(client.Refused, "do not redispatch"),
                ):
                    self.driver.run_phase("bootstrap", rerun=True)
            dispatch.assert_called_once()
            wait.assert_not_called()

    def test_bootstrap_retry_rejects_changed_binding_and_malformed_journal(self):
        configured = self.bootstrap_state()
        with (
            self.lab.locked(),
            patch.dict(client.STATE, configured, clear=True),
            patch.object(
                self.lab,
                "identity",
                side_effect=lambda role: configured["created"][role]["id"],
            ),
            patch.object(self.lab, "bootstrap") as dispatch,
            patch.object(self.driver, "_wait", return_value={}) as wait,
        ):
            self.driver.run_phase("bootstrap")
            original = json.loads(
                client.canonical(self.lab.state["bootstrap_dispatch"])
            )
            mutations = {
                "task": "adm-shc-foreign",
                "source_sha": "f" * 40,
                "source": "/foreign/source",
                "archive_sha256": "f" * 64,
                "directory": "/foreign/task",
                "network": {"id": "f" * 64},
                "image": "foreign-image",
            }
            for key, value in mutations.items():
                journal = json.loads(client.canonical(original))
                journal["binding"][key] = value
                self.lab.state["bootstrap_dispatch"] = journal
                with self.subTest(key=key), self.assertRaises(client.Refused):
                    self.driver.run_phase("bootstrap", rerun=True)
            for key in ("id", "name", "url"):
                journal = json.loads(client.canonical(original))
                journal["binding"]["created"]["sh2"][key] = "foreign"
                self.lab.state["bootstrap_dispatch"] = journal
                with self.subTest(key=key), self.assertRaises(client.Refused):
                    self.driver.run_phase("bootstrap", rerun=True)
            for journal in (
                None,
                {},
                {"state": "acknowledged"},
                {**original, "readiness_attempts": True},
            ):
                self.lab.state["bootstrap_dispatch"] = journal
                with self.subTest(journal=journal), self.assertRaises(client.Refused):
                    self.driver.run_phase("bootstrap", rerun=True)
            dispatch.assert_called_once()
            wait.assert_called_once()

    def test_bootstrap_retry_revalidates_actual_owned_ids_and_current_source(self):
        configured = self.bootstrap_state()
        with (
            self.lab.locked(),
            patch.dict(client.STATE, configured, clear=True),
            patch.object(
                self.lab,
                "identity",
                side_effect=lambda role: configured["created"][role]["id"],
            ) as identity,
            patch.object(self.lab, "bootstrap") as dispatch,
            patch.object(self.driver, "_wait", return_value={}) as wait,
        ):
            self.driver.run_phase("bootstrap")
            identity.side_effect = lambda role: (
                "f" * 64 if role == "sh2" else configured["created"][role]["id"]
            )
            with self.assertRaisesRegex(client.Refused, "owned container identity"):
                self.driver.run_phase("bootstrap", rerun=True)
            identity.side_effect = lambda role: configured["created"][role]["id"]
            self.driver.source_sha = "f" * 40
            with self.assertRaisesRegex(client.Refused, "source or configured task"):
                self.driver.run_phase("bootstrap", rerun=True)
            self.driver.source_sha = configured["source_sha"]
            self.lab.state["test_hashes"]["tools/qualification_shc_run.py"] = "f" * 64
            with self.assertRaisesRegex(client.Refused, "source/test file changed"):
                self.driver.run_phase("bootstrap", rerun=True)
            dispatch.assert_called_once()
            wait.assert_called_once()

    def test_bootstrap_failed_started_state_persistence_prevents_cli_dispatch(self):
        configured = self.bootstrap_state()
        with (
            self.lab.locked(),
            patch.dict(client.STATE, configured, clear=True),
            patch.object(
                self.lab,
                "identity",
                side_effect=lambda role: configured["created"][role]["id"],
            ),
            patch.object(self.lab, "save", side_effect=OSError("disk failure")),
            patch.object(self.lab, "bootstrap") as dispatch,
            patch.object(self.driver, "_wait") as wait,
            self.assertRaises(OSError),
        ):
            self.driver.run_phase("bootstrap")
        dispatch.assert_not_called()
        wait.assert_not_called()

    def test_bootstrap_failed_acknowledgment_save_cannot_authorize_retry(self):
        configured = self.bootstrap_state()
        save = self.lab.save
        saves = []

        def failing_ack_save():
            saves.append(self.lab.state["bootstrap_dispatch"]["state"])
            if len(saves) == 2:
                raise OSError("acknowledgment persistence failed")
            save()

        with (
            self.lab.locked(),
            patch.dict(client.STATE, configured, clear=True),
            patch.object(
                self.lab,
                "identity",
                side_effect=lambda role: configured["created"][role]["id"],
            ),
            patch.object(self.lab, "save", side_effect=failing_ack_save),
            patch.object(self.lab, "bootstrap") as dispatch,
            patch.object(self.driver, "_wait") as wait,
        ):
            with self.assertRaises(OSError):
                self.driver.run_phase("bootstrap")
            persisted = json.loads((self.lab.directory / "state.json").read_text())
            self.assertEqual(persisted["bootstrap_dispatch"]["state"], "started")
            with self.assertRaisesRegex(client.Refused, "not durably recorded"):
                self.driver.run_phase("bootstrap", rerun=True)
        dispatch.assert_called_once()
        wait.assert_not_called()

    @staticmethod
    def local_saved_response(api, path, disabled=False, scheduled="0"):
        return {
            "entry": [
                {
                    "name": urllib.parse.unquote(path.rsplit("/", 1)[1]),
                    "id": api.url + path,
                    "content": {
                        "disabled": disabled,
                        "enableSched": scheduled,
                        "eai:appName": "splunk_adm",
                        "eai:userName": "nobody",
                    },
                }
            ]
        }

    def saved_api(
        self, *, converge=True, dispatch_error=None, config_error=None, scheduled=False
    ):
        state = {
            "reads": 0,
            "round_reads": 0,
            "dispatches": 0,
            "config_posts": 0,
            "desired": None,
            "read_paths": [],
        }

        class FakeApi:
            def __init__(self, role):
                self.role = role
                self.url = "https://localhost:" + str(
                    22009 + 10 * client.ROLES.index(role)
                )

            def json(inner, method, path, data=None, timeout=None):
                if path.endswith("/dispatch"):
                    state["dispatches"] += 1
                    if dispatch_error:
                        raise dispatch_error
                    return {"sid": "fixture_sid"}
                if method == "POST":
                    state["config_posts"] += 1
                    if config_error:
                        raise config_error
                    state["desired"] = {
                        key: value == "1" for key, value in data.items()
                    }
                    state["round_reads"] = 0
                    return {}
                state["reads"] += 1
                state["read_paths"].append(path)
                if state["desired"] is None:
                    flags = {"disabled": True, "is_scheduled": scheduled}
                else:
                    flags = dict(state["desired"])
                    if inner.role == "sh2" and (
                        not converge or state["round_reads"] < 3
                    ):
                        flags["disabled"] = not flags["disabled"]
                    state["round_reads"] += 1
                if "/configs/conf-savedsearches/" in path:
                    return self.local_saved_response(
                        inner, path, flags["disabled"], str(int(flags["is_scheduled"]))
                    )
                return {"entry": [{"content": flags}]}

        return FakeApi, state

    def virtual_saved_wait(self):
        clock = [0.0]

        def advance(seconds):
            clock[0] += seconds

        return (
            patch.object(client.time, "monotonic", side_effect=lambda: clock[0]),
            patch.object(client.time, "sleep", side_effect=advance),
        )

    def test_v1_dispatch_waits_for_all_member_flags_and_records_sid_before_job(self):
        api, state = self.saved_api()
        timing, sleeping = self.virtual_saved_wait()

        def job(_api, sid):
            self.assertEqual(state["reads"], 6)
            record = self.lab.state["builder_dispatch"][runner.BUILDERS[1]]
            self.assertEqual(record["sid"], sid)
            self.assertEqual(record["state"], "dispatched")
            return [], {"sid": sid}

        with (
            timing,
            sleeping,
            patch.object(client, "Api", api),
            patch.object(self.lab, "save"),
            patch.object(self.driver, "_record") as evidence,
            patch.object(self.driver, "_job", side_effect=job),
        ):
            self.driver._saved("sh2", runner.BUILDERS[1], index_window=(10, 20))
        self.assertEqual(state["dispatches"], 1)
        self.assertEqual(state["config_posts"], 1)
        self.assertTrue(
            all("/configs/conf-savedsearches/" in path for path in state["read_paths"])
        )
        names = [call.args[0] for call in evidence.call_args_list]
        self.assertIn("saved-search-predispatch", names)
        self.assertIn("saved-search-dispatched", names)

    def test_unconverged_flags_timeout_without_dispatch(self):
        api, state = self.saved_api(converge=False)
        timing, sleeping = self.virtual_saved_wait()
        with (
            timing,
            sleeping,
            patch.object(client, "Api", api),
            patch.object(self.driver, "_record") as evidence,
            patch.object(self.driver, "_job") as job,
        ):
            with self.assertRaises(client.Refused):
                self.driver._saved("sh2", runner.BUILDERS[1])
        self.assertEqual(state["dispatches"], 0)
        self.assertEqual(state["config_posts"], 1)
        job.assert_not_called()
        configs = [
            call.args[1]
            for call in evidence.call_args_list
            if call.args[0] == "saved-search-config"
        ]
        self.assertFalse(configs[-1]["converged"])
        self.assertEqual(configs[-1]["members"]["sh2"]["disabled"], True)

    def test_dispatch_http400_does_not_authorize_a_second_dispatch(self):
        api, state = self.saved_api(dispatch_error=client.ApiError(400))
        timing, sleeping = self.virtual_saved_wait()
        with (
            timing,
            sleeping,
            patch.object(client, "Api", api),
            patch.object(self.lab, "save"),
            patch.object(self.driver, "_record"),
        ):
            with self.assertRaises(client.ApiError):
                self.driver._saved("sh2", runner.BUILDERS[1])
            with self.assertRaisesRegex(client.Refused, "uncertain"):
                self.driver._saved("sh2", runner.BUILDERS[1])
        self.assertEqual(state["dispatches"], 1)
        self.assertNotIn("sid", self.lab.state["builder_dispatch"][runner.BUILDERS[1]])

    def test_failed_configuration_post_never_dispatches(self):
        api, state = self.saved_api(config_error=client.ApiError(403))
        with (
            patch.object(client, "Api", api),
            patch.object(self.driver, "_record"),
            patch.object(self.driver, "_job") as job,
        ):
            with self.assertRaises(client.ApiError):
                self.driver._saved("sh2", runner.BUILDERS[1])
        self.assertEqual(state["dispatches"], 0)
        job.assert_not_called()

    def test_uncertain_dispatch_is_not_repeated_and_known_sid_is_resumable(self):
        api, state = self.saved_api(
            dispatch_error=client.Refused("lost dispatch response")
        )
        timing, sleeping = self.virtual_saved_wait()
        with (
            timing,
            sleeping,
            patch.object(client, "Api", api),
            patch.object(self.lab, "save"),
            patch.object(self.driver, "_record"),
        ):
            with self.assertRaisesRegex(client.Refused, "lost dispatch"):
                self.driver._saved("sh2", runner.BUILDERS[1])
            with self.assertRaisesRegex(client.Refused, "uncertain"):
                self.driver._saved("sh2", runner.BUILDERS[1])
        self.assertEqual(state["dispatches"], 1)
        self.assertEqual(state["config_posts"], 1)
        self.lab.state["builder_dispatch"] = {}
        api, state = self.saved_api()
        timing, sleeping = self.virtual_saved_wait()
        with (
            timing,
            sleeping,
            patch.object(client, "Api", api),
            patch.object(self.lab, "save"),
            patch.object(self.driver, "_record"),
            patch.object(
                self.driver,
                "_job",
                side_effect=[
                    client.Refused("job failed"),
                    ([], {"sid": "fixture_sid"}),
                ],
            ),
        ):
            with self.assertRaisesRegex(client.Refused, "job failed"):
                self.driver._saved("sh2", runner.BUILDERS[1])
            self.driver._saved("sh2", runner.BUILDERS[1])
        self.assertEqual(state["dispatches"], 1)

    def test_v2_enable_and_restore_both_wait_for_all_members(self):
        api, state = self.saved_api()
        self.lab.state.update(fixture_index_earliest=10, fixture_index_latest=20)
        timing, sleeping = self.virtual_saved_wait()
        with (
            timing,
            sleeping,
            patch.object(client, "Api", api),
            patch.object(self.lab, "save"),
            patch.object(self.driver, "_record"),
            patch.object(
                self.driver, "_job", return_value=([], {"sid": "fixture_sid"})
            ),
        ):
            self.driver._staged_v2_writer("sh2", runner.V2_WRITERS[0])
        self.assertEqual(state["dispatches"], 1)
        self.assertEqual(state["config_posts"], 2)
        self.assertEqual(state["desired"], {"disabled": True, "is_scheduled": False})
        self.assertEqual(state["round_reads"], 6)

    def test_base_phase_retry_reuses_frozen_window_and_prior_sids(self):
        contract = self.indexed_contract()
        self.lab.state.update(
            fixture_index_earliest=10,
            base_ingestion={"state": "acknowledged", "events": 1},
        )
        dispatches = []
        failed = False

        class Api:
            def __init__(inner, role):
                inner.role = role

            def search(inner, *args):
                return [{"count": "1"}], {"sid": "readback"}

            def json(inner, method, path, data=None):
                self.assertEqual(method, "POST")
                self.assertEqual(self.lab.state["base_index_window"], [10, 101])
                self.assertEqual(data["dispatch.index_earliest"], "10")
                self.assertEqual(data["dispatch.index_latest"], "101")
                dispatches.append(path)
                return {"sid": "sid-" + str(len(dispatches))}

        def job(_api, sid):
            nonlocal failed
            if sid == "sid-2" and not failed:
                failed = True
                raise client.Refused("later builder polling failed")
            return [], {"sid": sid}

        with (
            patch.object(
                runner, "isovalent_indexed_sourcetype_contract", return_value=contract
            ),
            patch.object(client, "Api", Api),
            patch.object(self.lab, "save"),
            patch.object(self.driver, "_record"),
            patch.object(self.driver, "_wait", return_value=True),
            patch.object(self.driver, "_set_saved_flags", return_value={}),
            patch.object(self.driver, "_job", side_effect=job),
            patch.object(runner.time, "sleep"),
            patch.object(runner.time, "time", return_value=100) as clock,
        ):
            with self.assertRaisesRegex(client.Refused, "later builder"):
                self.driver.phase_base()
            clock.return_value = 1000
            result = self.driver.phase_base()
            count = len(dispatches)
            with self.assertRaisesRegex(client.Refused, "arguments changed"):
                self.driver._saved("sh1", runner.BUILDERS[0], index_window=(10, 1001))
            self.assertEqual(len(dispatches), count)
        self.assertEqual(result["index_window"], (10, 101))
        self.assertEqual(self.lab.state["fixture_index_latest"], 101)
        self.assertEqual(len(dispatches), len(runner.BUILDERS) + 1)
        self.assertEqual(len(set(dispatches)), len(dispatches))
        self.assertEqual(result["jobs"][runner.BUILDERS[0]]["sid"], "sid-1")

    def test_reviewed_nxos_fixture_has_exact_independent_rows_and_separate_event_time(
        self,
    ):
        result = runner.nxos_interface_fixture(
            TOOLS.parent, (self.driver.window, self.driver.topology_window)
        )
        self.assertEqual(result["events"], 105)
        self.assertEqual(
            result["sha256"],
            "753a7c58f7db489d2a575474ca207d0cab03383d140bb5c01b7a58528b3d0062",
        )
        self.assertEqual(result["event_window"], [1792293814, 1792295615])
        self.assertEqual(
            [row["_key"] for row in result["expected_interfaces"]],
            ["192.0.2.11|436232192", "192.0.2.12|436232192"],
        )
        with self.assertRaisesRegex(client.Refused, "overlaps"):
            runner.nxos_interface_fixture(TOOLS.parent, (runner.NXOS_EVENT_WINDOW,))

    def test_nxos_preflight_rejects_missing_hash_changed_fields_and_event_time(self):
        source = Path(self.temp.name) / "fixtures-source"
        target = source / runner.NXOS_FIXTURE
        target.parent.mkdir(parents=True)
        with self.assertRaisesRegex(client.Refused, "missing"):
            runner.nxos_interface_fixture(source, (self.driver.window,))
        original = (TOOLS.parent / runner.NXOS_FIXTURE).read_bytes()
        target.write_bytes(original + b"\n")
        with self.assertRaisesRegex(client.Refused, "hash differs"):
            runner.nxos_interface_fixture(source, (self.driver.window,))
        for change in ("ifindex", "interface", "time", "source"):
            rows = [json.loads(line) for line in original.splitlines()]
            for row in rows:
                event = json.loads(row["event"])
                if (
                    event["component"] == "nxneighbor"
                    and "ifindex" in event["Row_info"]
                ):
                    if change == "ifindex":
                        del event["Row_info"]["ifindex"]
                    elif change == "interface":
                        event["Row_info"]["intf_id"] = "Ethernet1/48"
                    elif change == "time":
                        row["time"] = int(self.driver.window[0])
                    else:
                        row["sourcetype"] = "cisco:dc:aci:class"
                    row["event"] = json.dumps(event)
                    break
            data = b"\n".join(client.canonical(row) for row in rows) + b"\n"
            target.write_bytes(data)
            # Exercise semantic guards independently of the pinned-byte guard.
            with (
                self.subTest(change=change),
                patch.object(
                    runner, "NXOS_FIXTURE_SHA256", hashlib.sha256(data).hexdigest()
                ),
                self.assertRaises(client.Refused),
            ):
                runner.nxos_interface_fixture(source, (self.driver.window,))

    def test_prepare_rejects_missing_nxos_before_any_lab_mutation(self):
        with (
            patch.object(
                runner,
                "nxos_interface_fixture",
                side_effect=client.Refused("missing fixture"),
            ),
            patch.object(self.lab, "prepare") as prepare,
            self.assertRaisesRegex(client.Refused, "missing fixture"),
        ):
            self.driver.phase_prepare()
        prepare.assert_not_called()

    def test_base_ingests_nxos_and_requires_all_963_events_classified_by_sourcetype(
        self,
    ):
        contract = self.indexed_contract()
        expected = {}
        for path in [
            *(TOOLS.parent / "fixtures/raw-aci").glob("*.ndjson"),
            TOOLS.parent / runner.NXOS_FIXTURE,
        ]:
            for line in path.read_text().splitlines():
                event = json.loads(line)
                indexed_type = event["sourcetype"]
                if indexed_type == "cisco:isovalent":
                    self.assertIn("process_connect", event["event"])
                    indexed_type = "cisco:isovalent:processConnect"
                key = (event["index"], indexed_type)
                expected[key] = expected.get(key, 0) + 1
        raw = [
            {"index": index, "sourcetype": sourcetype, "count": str(count)}
            for (index, sourcetype), count in expected.items()
        ]
        self.assertEqual(sum(expected.values()), 963)
        api = Mock()
        api.search.return_value = (raw, {"sid": "classification_sid"})

        def check_classification(check, **_kwargs):
            isovalent = next(row for row in raw if row["index"] == "cisco_isovalent")
            for wrong in (
                "cisco:isovalent",
                "cisco:isovalent:processExec",
                "cisco:isovalent:anything",
            ):
                isovalent["sourcetype"] = wrong
                self.assertFalse(check())
            isovalent["sourcetype"] = "cisco:isovalent:processConnect"
            for malformed in (4.9, True, "4.0", None):
                isovalent["count"] = malformed
                self.assertFalse(check())
            del isovalent["count"]
            self.assertFalse(check())
            isovalent["count"] = "4"
            nxos = next(row for row in raw if row["sourcetype"] == "cisco:dc:nexus9k")
            nxos["count"] = "104"
            self.assertFalse(check())
            nxos["count"] = "105"
            self.assertTrue(check())
            raw.append(dict(isovalent))
            self.assertFalse(check())
            raw.pop()
            raise client.Refused("stop after classification proof")

        with (
            patch.object(
                runner, "isovalent_indexed_sourcetype_contract", return_value=contract
            ),
            patch.object(client, "Api", return_value=api),
            patch.object(self.lab, "save"),
            patch.object(self.driver, "_record"),
            patch.object(
                self.driver, "_ingest", return_value={"events": 930}
            ) as ingest,
            patch.object(self.driver, "_wait", side_effect=check_classification),
            self.assertRaisesRegex(client.Refused, "classification proof"),
        ):
            self.driver.phase_base()
        self.assertIn(TOOLS.parent / runner.NXOS_FIXTURE, ingest.call_args.args[0])
        self.assertNotIn(
            TOOLS.parent / "fixtures/raw-aci/stream_netflow.ndjson",
            ingest.call_args.args[0],
        )
        self.assertEqual(self.lab.state["base_ingestion"]["events"], 930)
        self.assertEqual(
            self.lab.state["base_ingestion"]["nxos_interface_fixture"]["events"], 105
        )

    def test_base_refuses_wrong_installed_transform_hash_before_ingestion(self):
        contract = self.indexed_contract()
        self.lab.state["support_files"] = {}
        with (
            patch.object(
                runner, "isovalent_indexed_sourcetype_contract", return_value=contract
            ),
            patch.object(self.driver, "_ingest") as ingest,
            self.assertRaisesRegex(client.Refused, "installed Isovalent support"),
        ):
            self.driver.phase_base()
        ingest.assert_not_called()
        self.assertNotIn("base_ingestion", self.lab.state)

    def test_prepare_refuses_config_or_fixture_oracle_failure_before_lab_mutation(self):
        for stage in ("configuration", "fixture"):
            with (
                self.subTest(stage=stage),
                patch.object(
                    runner,
                    "isovalent_indexed_sourcetype_contract",
                    side_effect=client.Refused("configuration differs")
                    if stage == "configuration"
                    else None,
                    return_value=self.indexed_contract(),
                ),
                patch.object(
                    runner,
                    "base_input_classification",
                    side_effect=client.Refused("fixture malformed"),
                ),
                patch.object(self.lab, "prepare") as prepare,
                self.assertRaises(client.Refused),
            ):
                self.driver.phase_prepare()
            prepare.assert_not_called()

    def test_exact_interface_oracle_is_required_on_every_member(self):
        rows = json.loads(json.dumps(runner.INTERFACE_ORACLE))
        for row in rows:
            row["_user"] = "nobody"
        with (
            patch.object(
                client, "Api", side_effect=lambda role: SimpleNamespace(role=role)
            ),
            patch.object(runner, "complete_collection_rows", return_value=rows) as read,
        ):
            result = self.driver._interface_inventory()
        self.assertEqual(
            [call.args[0].role for call in read.call_args_list], list(client.MEMBERS)
        )
        self.assertEqual(set(result["members"]), set(client.MEMBERS))
        bad_member = json.loads(json.dumps(rows))
        bad_member[1]["neighbor_interface"] = "Ethernet1/99"
        with (
            patch.object(client, "Api"),
            patch.object(
                runner, "complete_collection_rows", side_effect=[rows, rows, bad_member]
            ),
            self.assertRaisesRegex(client.Refused, "independent oracle"),
        ):
            self.driver._interface_inventory()
        for mutation in (
            "missing",
            "duplicate",
            "interface",
            "neighbor",
            "updated",
            "extra",
        ):
            invalid = json.loads(json.dumps(rows))
            if mutation == "missing":
                invalid.pop()
            elif mutation == "duplicate":
                invalid[1] = invalid[0]
            elif mutation == "updated":
                invalid[0][mutation] += 1
            else:
                invalid[0][mutation] = "wrong"
            with self.subTest(mutation=mutation), self.assertRaises(client.Refused):
                runner.semantic_interfaces(invalid)

    def test_terminal_job_warnings_errors_and_failure_escape_polling_immediately(self):
        for state, severity in (
            ("DONE", "WARN"),
            ("RUNNING", "ERROR"),
            ("FAILED", None),
            ("QUIT", None),
        ):
            api = Mock()
            api.json.return_value = {
                "entry": [
                    {
                        "content": {
                            "dispatchState": state,
                            "isDone": state == "DONE",
                            "messages": [
                                {"type": severity, "text": "native terminal message"}
                            ]
                            if severity
                            else [],
                        }
                    }
                ]
            }
            with (
                self.subTest(state=state, severity=severity),
                patch.object(self.driver, "_record") as evidence,
                patch.object(client.time, "sleep") as sleep,
                self.assertRaises(client.Refused),
            ):
                self.driver._job(api, "known_sid")
            self.assertEqual(api.json.call_count, 1)
            sleep.assert_not_called()
            self.assertEqual(evidence.call_args.args[1]["sid"], "known_sid")

    def test_healthy_job_polls_then_rejects_result_warning_without_repolling(self):
        api = Mock()
        api.json.side_effect = [
            {"entry": [{"content": {"dispatchState": "RUNNING", "isDone": False}}]},
            {"entry": [{"content": {"dispatchState": "DONE", "isDone": True}}]},
            {"messages": [{"type": "WARN", "text": "result warning"}], "results": []},
        ]
        with (
            patch.object(self.driver, "_record"),
            patch.object(client.time, "sleep") as sleep,
            self.assertRaises(client.Refused),
        ):
            self.driver._job(api, "known_sid")
        self.assertEqual(api.json.call_count, 3)
        self.assertEqual(sleep.call_count, 1)

    def test_completed_healthy_job_keeps_real_sid_and_result_evidence(self):
        api = Mock()
        api.json.side_effect = [
            {
                "entry": [
                    {
                        "content": {
                            "dispatchState": "DONE",
                            "isDone": True,
                            "resultCount": 1,
                            "messages": [{"type": "INFO", "text": "Results written"}],
                        }
                    }
                ]
            },
            {"results": [{"rows_written": "2"}]},
        ]
        with (
            patch.object(self.driver, "_record"),
            patch.object(client.time, "sleep") as sleep,
        ):
            rows, job = self.driver._job(api, "known_sid")
        self.assertEqual(rows, [{"rows_written": "2"}])
        self.assertEqual(
            job, {"sid": "known_sid", "dispatchState": "DONE", "resultCount": 1}
        )
        self.assertEqual(api.json.call_count, 2)
        sleep.assert_not_called()

    def test_v2_known_sid_retry_restores_original_true_true_after_restore_failure(self):
        api, state = self.saved_api(scheduled=True)
        self.lab.state.update(fixture_index_earliest=10, fixture_index_latest=20)
        original_set = self.driver._set_saved_flags
        restores = []

        def configure(role, name, **flags):
            if flags["disabled"]:
                restores.append(flags)
                if len(restores) == 1:
                    raise client.Refused("restore timed out")
            return original_set(role, name, **flags)

        timing, sleeping = self.virtual_saved_wait()
        with (
            timing,
            sleeping,
            patch.object(client, "Api", api),
            patch.object(self.lab, "save"),
            patch.object(self.driver, "_record"),
            patch.object(self.driver, "_set_saved_flags", side_effect=configure),
            patch.object(
                self.driver, "_job", return_value=([], {"sid": "fixture_sid"})
            ),
        ):
            with self.assertRaisesRegex(client.Refused, "restore timed out"):
                self.driver._staged_v2_writer("sh2", runner.V2_WRITERS[0])
            self.assertEqual(
                self.lab.state["v2_writer_dispatch"][runner.V2_WRITERS[0]]["state"],
                "dispatched",
            )
            self.driver._staged_v2_writer("sh2", runner.V2_WRITERS[0])
        self.assertEqual(state["dispatches"], 1)
        self.assertEqual(restores, [{"disabled": True, "is_scheduled": True}] * 2)
        self.assertEqual(state["desired"], restores[-1])
        self.assertEqual(state["round_reads"], 6)

    def test_v2_resume_refuses_missing_or_malformed_persisted_original_flags(self):
        for flags in (
            {},
            {"original_disabled": True},
            {"original_disabled": True, "original_scheduled": "invalid"},
            {"original_disabled": False, "original_scheduled": True},
        ):
            with self.subTest(flags=flags):
                self.lab.state["v2_writer_dispatch"] = {
                    runner.V2_WRITERS[0]: {"sid": "known_sid", "role": "sh2", **flags}
                }
                with (
                    patch.object(client, "Api"),
                    patch.object(self.driver, "_set_saved_flags") as configure,
                    patch.object(self.driver, "_job") as job,
                    self.assertRaises(client.Refused),
                ):
                    self.driver._staged_v2_writer("sh2", runner.V2_WRITERS[0])
                configure.assert_not_called()
                job.assert_not_called()

    def test_scheduler_enable_and_failure_restore_both_use_converged_flags(self):
        api_class, state = self.saved_api()

        def api(role):
            value = api_class(role)
            original_json = value.json

            def json_response(method, path, **kwargs):
                response = original_json(method, path, **kwargs)
                if method == "GET":
                    response["entry"][0]["content"]["cron_schedule"] = "*/5 * * * *"
                return response

            value.json = json_response
            value.url = "https://localhost:22049"
            value.opener = Mock()
            value.opener.open.return_value = io.BytesIO(b'{"code":0}')
            return value

        wait = self.driver._wait

        def config_only_wait(check, **kwargs):
            if check.__name__ != "agrees":
                raise client.Refused("stop after scheduler configuration")
            return wait(check, **kwargs)

        timing, sleeping = self.virtual_saved_wait()
        with (
            timing,
            sleeping,
            patch.object(client, "Api", side_effect=api),
            patch.object(
                client,
                "protected_file",
                return_value=SimpleNamespace(read_text=lambda: "fixture-token"),
            ),
            patch.object(self.driver, "_record") as evidence,
            patch.object(self.lab, "save"),
            patch.object(self.driver, "_wait", side_effect=config_only_wait),
        ):
            with self.assertRaisesRegex(client.Refused, "stop after scheduler"):
                self.driver.phase_scheduler()
        configs = [
            call.args[1]
            for call in evidence.call_args_list
            if call.args[0] == "saved-search-config"
        ]
        self.assertEqual(
            [row["desired"] for row in configs],
            [
                {"disabled": False, "is_scheduled": True},
                {"disabled": True, "is_scheduled": False},
            ],
        )
        self.assertTrue(all(row["converged"] for row in configs))
        self.assertEqual(state["config_posts"], 2)
        self.assertEqual(state["dispatches"], 0)
        self.assertEqual(state["round_reads"], 6)

    def test_saved_search_flag_readback_rejects_missing_and_malformed_values(self):
        for content in (
            None,
            {},
            {"disabled": False},
            {"disabled": "unknown", "is_scheduled": False},
            {"disabled": 0.0, "is_scheduled": False},
        ):
            with self.subTest(content=content), self.assertRaises(client.Refused):
                self.driver._saved_flags(content)
        self.assertEqual(
            self.driver._saved_flags({"disabled": "0", "is_scheduled": 1}),
            {"disabled": False, "is_scheduled": True},
        )

    def test_matching_last_member_response_after_deadline_cannot_converge(self):
        clock = [0.0]
        desired = {"disabled": False, "is_scheduled": False}

        class Api:
            def __init__(inner, role):
                inner.role = role
                inner.url = "https://localhost:" + str(
                    22009 + 10 * client.MEMBERS.index(role)
                )

            def json(inner, method, path, **kwargs):
                if method == "GET" and inner.role == "sh3":
                    clock[0] = 125.0
                if method == "GET":
                    return self.local_saved_response(inner, path)
                return {"entry": [{"content": desired}]}

        with (
            patch.object(client, "Api", Api),
            patch.object(runner.time, "monotonic", side_effect=lambda: clock[0]),
            patch.object(self.driver, "_record") as evidence,
            patch.object(self.driver, "_job") as job,
            self.assertRaises(runner.SavedSearchDeadline),
        ):
            self.driver._saved("sh1", runner.BUILDERS[0])
        job.assert_not_called()
        configs = [
            call.args[1]
            for call in evidence.call_args_list
            if call.args[0] == "saved-search-config"
        ]
        self.assertFalse(configs[-1]["converged"])
        self.assertEqual(self.lab.state["builder_dispatch"], {})

    def test_local_saved_config_rejects_captain_proxy_before_dispatch(self):
        api_class, state = self.saved_api()

        def api(role):
            value = api_class(role)
            original_json = value.json

            def json_response(method, path, **kwargs):
                response = original_json(method, path, **kwargs)
                if method == "GET":
                    response["entry"][0]["id"] = "https://localhost:22009" + path
                return response

            value.json = json_response
            return value

        timing, sleeping = self.virtual_saved_wait()
        with (
            timing,
            sleeping,
            patch.object(client, "Api", side_effect=api),
            patch.object(self.driver, "_record") as evidence,
            patch.object(self.driver, "_job") as job,
            self.assertRaises(client.Refused),
        ):
            self.driver._saved("sh2", runner.BUILDERS[1])
        self.assertEqual(state["config_posts"], 1)
        self.assertEqual(state["dispatches"], 0)
        job.assert_not_called()
        configs = [
            call.args[1]
            for call in evidence.call_args_list
            if call.args[0] == "saved-search-config"
        ]
        self.assertFalse(configs[-1]["converged"])

    def test_local_saved_config_matches_native_identity_namespace_and_flags(self):
        name = runner.BUILDERS[1]
        path = (
            client.APP
            + "/configs/conf-savedsearches/"
            + urllib.parse.quote(name, safe="")
        )
        api = SimpleNamespace(url="https://localhost:22019")
        for disabled, scheduled in ((False, "0"), (True, "1")):
            value = self.local_saved_response(api, path, disabled, scheduled)
            self.assertEqual(
                self.driver._local_saved_flags(api, value, path, name),
                {
                    "uri": api.url + path,
                    "disabled": disabled,
                    "is_scheduled": scheduled == "1",
                },
            )

    def test_local_saved_config_refuses_malformed_flags_namespaces_and_identity(self):
        name = runner.BUILDERS[1]
        path = (
            client.APP
            + "/configs/conf-savedsearches/"
            + urllib.parse.quote(name, safe="")
        )
        api = SimpleNamespace(url="https://localhost:22019")
        invalid = []
        for field, values in {
            "disabled": (None, "unknown", 0.0),
            "enableSched": (None, True, 0, "false", "2"),
            "eai:appName": (None, "other_app"),
            "eai:userName": (None, "admin"),
        }.items():
            for bad in values:
                value = self.local_saved_response(api, path)
                value["entry"][0]["content"][field] = bad
                invalid.append(value)
            value = self.local_saved_response(api, path)
            del value["entry"][0]["content"][field]
            invalid.append(value)
        for uri in (
            "https://localhost:22009" + path,
            "https://foreign.example:22019" + path,
            "http://localhost:22019" + path,
            "https://user@localhost:22019" + path,
            api.url + path.replace("/nobody/", "/admin/"),
            api.url + path.replace("/splunk_adm/", "/other_app/"),
            api.url + path.replace("conf-savedsearches", "saved/searches"),
            api.url + path.replace("Service%20binding", "Identity%20builder"),
            api.url + path.replace("%20", " "),
            api.url + path.replace("nobody", "%6eobody"),
            api.url + path + "%2520",
            api.url + path + "?foreign=1",
            api.url + path + "#fragment",
            "https://[invalid" + path,
            "https://local\nhost:22019" + path,
        ):
            value = self.local_saved_response(api, path)
            value["entry"][0]["id"] = uri
            invalid.append(value)
        value = self.local_saved_response(api, path)
        value["entry"][0]["name"] = runner.BUILDERS[0]
        invalid.extend([value, {}, {"entry": []}, {"entry": [{}, {}]}])
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(client.Refused):
                self.driver._local_saved_flags(api, value, path, name)

    def test_configuration_total_timer_interrupts_blocked_body_and_cleans_up(self):
        old_handler = signal.getsignal(signal.SIGALRM)
        old_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))
        api = Mock()

        def blocked_body(*args, **kwargs):
            # The real timer must interrupt a response body stalled within json().
            signal.pause()
            self.fail("blocked body returned without a deadline")

        api.json.side_effect = blocked_body
        with (
            patch.object(client, "Api", return_value=api),
            patch.object(self.driver, "_record") as evidence,
            self.assertRaises(runner.SavedSearchDeadline),
        ):
            self.driver._set_saved_flags(
                "sh1",
                runner.BUILDERS[0],
                disabled=False,
                is_scheduled=False,
                timeout=0.02,
            )
        self.assertEqual(api.json.call_count, 1)
        self.assertFalse(evidence.call_args.args[1]["converged"])
        self.assertEqual(signal.getsignal(signal.SIGALRM), old_handler)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))
        self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, set()), old_mask)

    def test_configuration_refuses_shared_timer_or_worker_thread_before_post(self):
        api = Mock()
        for condition in ("timer", "thread", "blocked"):
            with self.subTest(condition=condition):
                patches = {
                    "timer": patch.object(
                        runner.signal, "getitimer", return_value=(5.0, 0.0)
                    ),
                    "thread": patch.object(
                        runner.threading, "current_thread", return_value=object()
                    ),
                    "blocked": patch.object(
                        runner.signal, "pthread_sigmask", return_value={signal.SIGALRM}
                    ),
                }
                with (
                    patches[condition],
                    patch.object(client, "Api", return_value=api),
                    patch.object(self.driver, "_record"),
                    self.assertRaises(client.Refused),
                ):
                    self.driver._set_saved_flags(
                        "sh1", runner.BUILDERS[0], disabled=False, is_scheduled=False
                    )
        api.json.assert_not_called()

    def test_configuration_discards_alarm_queued_during_disarm(self):
        old_handler = signal.getsignal(signal.SIGALRM)
        old_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        real_setitimer = signal.setitimer

        def queue_on_disarm(which, delay):
            result = real_setitimer(which, delay)
            if delay == 0:
                signal.raise_signal(signal.SIGALRM)
                self.assertIn(signal.SIGALRM, signal.sigpending())
            return result

        with patch.object(runner.signal, "setitimer", side_effect=queue_on_disarm):
            with runner.saved_search_deadline(runner.time.monotonic() + 10):
                pass
        self.assertNotIn(signal.SIGALRM, signal.sigpending())
        self.assertEqual(signal.getsignal(signal.SIGALRM), old_handler)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))
        self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, set()), old_mask)

    def test_configuration_timer_arming_failure_restores_signal_state(self):
        old_handler = signal.getsignal(signal.SIGALRM)
        old_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
        real_setitimer = signal.setitimer
        api = Mock()

        def fail_arming(which, delay):
            if delay:
                raise OSError("timer arming failed")
            return real_setitimer(which, delay)

        with (
            patch.object(runner.signal, "setitimer", side_effect=fail_arming),
            patch.object(client, "Api", return_value=api),
            patch.object(self.driver, "_record"),
            self.assertRaisesRegex(OSError, "timer arming failed"),
        ):
            self.driver._set_saved_flags(
                "sh1", runner.BUILDERS[0], disabled=False, is_scheduled=False
            )
        api.json.assert_not_called()
        self.assertEqual(signal.getsignal(signal.SIGALRM), old_handler)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))
        self.assertEqual(signal.pthread_sigmask(signal.SIG_BLOCK, set()), old_mask)

    def test_scheduler_retry_restores_durable_origin_without_reingestion(self):
        flags = {"disabled": False, "is_scheduled": False}
        origin = dict(flags)
        api = Mock()
        api.url = "https://localhost:22049"
        api.opener.open.return_value = io.BytesIO(b'{"code":0}')
        api.json.side_effect = lambda *args, **kwargs: {
            "entry": [{"content": {**flags, "cron_schedule": "*/5 * * * *"}}]
        }
        restorations = []

        def configure(role, name, **desired):
            if desired == origin:
                restorations.append(desired)
                if len(restorations) == 1:
                    raise client.Refused("restore timed out")
            flags.update(desired)
            return {"converged": True}

        with (
            patch.object(client, "Api", return_value=api),
            patch.object(
                client,
                "protected_file",
                return_value=SimpleNamespace(read_text=lambda: "fixture-token"),
            ),
            patch.object(self.lab, "save"),
            patch.object(self.driver, "_record"),
            patch.object(self.driver, "_set_saved_flags", side_effect=configure),
            patch.object(
                self.driver, "_wait", side_effect=client.Refused("later check failed")
            ),
        ):
            with self.assertRaisesRegex(client.Refused, "restore timed out"):
                self.driver.phase_scheduler()
            self.assertEqual(flags, {"disabled": False, "is_scheduled": True})
            with self.assertRaisesRegex(client.Refused, "later check failed"):
                self.driver.phase_scheduler()
        self.assertEqual(restorations, [origin, origin])
        self.assertEqual(flags, origin)
        self.assertEqual(api.opener.open.call_count, 1)
        self.assertEqual(self.lab.state["scheduler_original_flags"], origin)

    def test_scheduler_uncertain_ingestion_is_not_repeated(self):
        api = Mock()
        api.url = "https://localhost:22049"
        api.json.return_value = {
            "entry": [
                {
                    "content": {
                        "disabled": False,
                        "is_scheduled": False,
                        "cron_schedule": "*/5 * * * *",
                    }
                }
            ]
        }
        api.opener.open.side_effect = OSError("lost response")
        with (
            patch.object(client, "Api", return_value=api),
            patch.object(
                client,
                "protected_file",
                return_value=SimpleNamespace(read_text=lambda: "fixture-token"),
            ),
            patch.object(self.lab, "save"),
            patch.object(self.driver, "_record"),
            patch.object(self.driver, "_set_saved_flags") as configure,
        ):
            with self.assertRaisesRegex(client.Refused, "ingestion failed"):
                self.driver.phase_scheduler()
            with self.assertRaisesRegex(client.Refused, "uncertain"):
                self.driver.phase_scheduler()
        configure.assert_not_called()
        self.assertEqual(api.opener.open.call_count, 1)

    def test_scheduler_missing_or_malformed_durable_origin_fails_before_ingestion(self):
        api = Mock()
        api.json.return_value = {
            "entry": [
                {
                    "content": {
                        "disabled": False,
                        "is_scheduled": True,
                        "cron_schedule": "*/5 * * * *",
                    }
                }
            ]
        }
        for origin in (None, {}, {"disabled": False, "is_scheduled": "bad"}):
            with self.subTest(origin=origin):
                self.lab.state["scheduler_probe"] = {"state": "acknowledged"}
                self.lab.state.pop("scheduler_original_flags", None)
                if origin is not None:
                    self.lab.state["scheduler_original_flags"] = origin
                with (
                    patch.object(client, "Api", return_value=api),
                    patch.object(self.driver, "_set_saved_flags") as configure,
                    self.assertRaises(client.Refused),
                ):
                    self.driver.phase_scheduler()
                configure.assert_not_called()
        api.opener.open.assert_not_called()

    def test_settings_bundle_checks_files_before_endpoint_or_ledger_writes(self):
        with (
            patch.object(self.lab, "opt_in_settings") as opt_in,
            patch.object(self.lab, "apply_bundle") as apply,
            patch.object(self.driver, "_wait"),
            patch.object(
                self.lab,
                "verify_candidate",
                side_effect=client.Refused("unexpected file"),
            ) as verify,
            patch.object(client, "Api") as api,
        ):
            with self.assertRaisesRegex(client.Refused, "unexpected file"):
                self.driver.phase_settings()
        opt_in.assert_called_once()
        apply.assert_called_once()
        verify.assert_called_once()
        api.assert_not_called()

    def test_failed_phase_retains_lock_and_does_not_cleanup_or_complete(self):
        with (
            self.lab.locked(),
            patch.object(
                self.driver, "phase_prepare", side_effect=client.Refused("test failure")
            ),
            patch.object(self.lab, "cleanup") as cleanup,
        ):
            with self.assertRaises(client.Refused):
                self.driver.run_phase("prepare")
            self.lab._owned()
            self.assertNotIn("prepare", self.driver.completed)
            self.assertEqual(self.driver.results["prepare"]["outcome"], "failed")
            cleanup.assert_not_called()

    def test_startup_wait_stops_immediately_for_an_exited_owned_container(self):
        def status(role):
            return {
                "role": role,
                "id": "a" * 64,
                "name": "adm-shc-driver-" + role,
                "status": "exited" if role == "sh2" else "running",
                "exit_code": 2 if role == "sh2" else 0,
            }

        with (
            patch.object(self.lab, "container_status", side_effect=status),
            patch.object(self.driver, "_record") as recorded,
            patch.object(client.time, "sleep") as sleep,
        ):
            ready = unittest.mock.Mock(return_value=True)
            with self.assertRaises(lifecycle.OwnedContainerStopped):
                self.driver._wait(ready, running_roles=client.ROLES)
            ready.assert_not_called()
            sleep.assert_not_called()
            self.assertEqual(recorded.call_args.args[0], "startup-stopped")
            self.assertTrue(
                any(
                    row["role"] == "sh2" and row["exit_code"] == 2
                    for row in recorded.call_args.args[1]["containers"]
                )
            )

    def test_running_container_state_does_not_replace_actual_readiness(self):
        with patch.object(
            self.lab, "container_status", return_value={"status": "running"}
        ) as status:
            ready = unittest.mock.Mock(return_value={"verified_tls": True})
            self.assertEqual(
                self.driver._wait(ready, running_roles=client.ROLES),
                {"verified_tls": True},
            )
            ready.assert_called_once()
            self.assertEqual(status.call_count, len(client.ROLES))

    def test_phase_prerequisites_prevent_unprepared_mutations(self):
        with self.lab.locked(), patch.object(self.driver, "phase_settings") as settings:
            with self.assertRaises(client.Refused):
                self.driver.run_phase("settings")
            settings.assert_not_called()

    def test_graph_macro_uses_base_search_shape(self):
        self.assertTrue(self.driver.graph_query.startswith("`adm_graph("))
        self.assertTrue(
            client.search_query(self.driver.graph_query).startswith(
                "search `adm_graph("
            )
        )

    def test_rerun_invalidates_later_qualification(self):
        self.driver.completed = list(runner.Driver.ORDER[:4])
        with (
            self.lab.locked(),
            patch.object(self.driver, "phase_support", return_value={}),
        ):
            self.driver.run_phase("support", rerun=True)
        self.assertEqual(self.driver.completed, ["prepare", "create", "support"])

    def test_semantic_graph_rejects_missing_evidence_and_warnings(self):
        expected = {
            "nodes": {"a": {"kind": "service"}, "b": {"kind": "endpoint"}},
            "edges": [
                {"relationship": "calls", "source": "a", "target": "b", "count": "1"}
            ],
            "edge_counts": {"calls": 1},
            "meta": {"status": "complete"},
        }
        rows = [
            {"row_type": "node", "id": "a", "kind": "service"},
            {"row_type": "node", "id": "b", "kind": "endpoint"},
            {
                "row_type": "edge",
                "id": "e",
                "relationship": "calls",
                "source": "a",
                "target": "b",
                "count": "1",
            },
            {"row_type": "meta", "status": "complete"},
        ]
        self.assertEqual(runner.semantic_graph(rows, expected)["edges"], 1)
        with self.assertRaises(client.Refused):
            runner.semantic_graph(rows[:-2] + rows[-1:], expected)
        rows[-1]["warnings"] = ["missing evidence"]
        with self.assertRaises(client.Refused):
            runner.semantic_graph(rows, expected)

    def topology_fixture(self):
        expected = self.driver.expected_topology
        rows = [
            {"row_type": "device", "device_id": name, **attributes}
            for name, attributes in expected["devices"].items()
        ]
        rows += [
            {
                "row_type": "link",
                "link_source": source,
                "a_device": a,
                "a_interface": ai,
                "b_device": b,
                "b_interface": bi,
            }
            for source, a, ai, b, bi in expected["links"]
        ]
        rows.append({"row_type": "meta", **expected["meta"]})
        return rows

    def test_actual_topology_client_checks_every_member_and_preserves_rows(self):
        rows, calls = self.topology_fixture(), []
        self.lab.state["archive_sha256"] = "a" * 64
        drift = False

        class FakeApi:
            def __init__(self, role, account):
                self.role, self.account = role, account

            def search(self, query, *window):
                calls.append((self.role, self.account, query, window))
                result = json.loads(json.dumps(rows))
                result[-1]["generated_at"] = self.role
                if drift and self.role == "sh3":
                    result[0]["additional_evidence"] = "member-specific"
                return result, {"sid": "sid-" + self.role}

        with (
            patch.object(client, "Api", FakeApi),
            patch.object(self.driver, "_record") as recorded,
        ):
            result, canonical_rows = self.driver._topologies()
            self.assertEqual(set(result), set(client.MEMBERS))
            self.assertEqual(recorded.call_count, 3)
            self.assertTrue(
                all(
                    value["devices"] == 6 and value["links"] == 11
                    for value in result.values()
                )
            )
            self.assertEqual(canonical_rows, runner.normalized(rows))
            self.assertEqual([call[0] for call in calls], list(client.MEMBERS))
            self.assertTrue(
                all(
                    call[2] == "`adm_topology`"
                    and call[3] == self.driver.topology_window
                    for call in calls
                )
            )
            drift = True
            with self.assertRaisesRegex(
                client.Refused, "member topology semantic rows differ"
            ):
                self.driver._topologies()

    def test_topology_rejects_empty_or_incomplete_inventory(self):
        expected = self.driver.expected_topology
        rows = self.topology_fixture()
        with self.assertRaises(client.Refused):
            runner.semantic_topology([], expected)
        with self.assertRaises(client.Refused):
            runner.semantic_topology(rows[1:], expected)
        rows[-1]["warnings"] = ["inventory incomplete"]
        with self.assertRaises(client.Refused):
            runner.semantic_topology(rows, expected)

    def v2_graph_fixture(self):
        expected = self.driver.expected
        labels = {value.get("label"): key for key, value in expected["nodes"].items()}
        same_node = (
            labels["frontend-7d9c6b5f4-q4m9z"],
            labels["checkout-5f8b9c7d6-m4n7q"],
        )
        edges = [
            row
            for row in expected["edges"]
            if row["relationship"] == "calls"
            or (
                row["relationship"] == "communicates_with"
                and (row["source"], row["target"]) == same_node
            )
        ]
        owners = {value for row in edges for value in (row["source"], row["target"])}
        owners.update(
            key
            for key, value in expected["nodes"].items()
            if value.get("kind") == "service"
        )
        rows = [
            {"row_type": "node", "id": key, **expected["nodes"][key]}
            for key in sorted(owners)
        ]
        rows += [
            {
                "row_type": "edge",
                "id": "edge-" + str(i),
                **{key: value for key, value in row.items() if value is not None},
            }
            for i, row in enumerate(edges)
        ]
        rows.append(
            {
                "row_type": "meta",
                "root_present": "1",
                "spans": expected["meta"]["spans"],
                "nodes": str(len(owners)),
                "edges": str(len(edges)),
            }
        )
        return rows

    def test_v2_graph_requires_independent_span_and_owner_provenance(self):
        rows = self.v2_graph_fixture()
        self.assertGreaterEqual(
            runner.semantic_v2_graph(rows, self.driver.expected)[
                "independent_witnesses"
            ],
            2,
        )
        witness = next(
            row for row in rows if row.get("relationship") == "communicates_with"
        )
        witness.pop("span_ids")
        with self.assertRaisesRegex(client.Refused, "provenance differs"):
            runner.semantic_v2_graph(rows, self.driver.expected)
        with self.assertRaises(client.Refused):
            runner.semantic_v2_graph([], self.driver.expected)

    def test_v2_topology_preserves_unmapped_authority_and_suppresses_adjacency(self):
        inventory = self.driver.v2_inventory
        rows = [
            {"row_type": "device", "device_id": identity, **value}
            for identity, value in inventory.items()
        ]
        rows.append(
            {
                "row_type": "meta",
                "devices": str(len(inventory)),
                "links": "0",
                "warnings": [
                    "No retained Catalyst client history is available; fixture has none.",
                    "Some inventory records, links, or interfaces have missing cluster evidence.",
                    "Nexus Dashboard fabric labels are not yet correlated into V2 inventory.",
                ],
            }
        )
        result = runner.semantic_v2_topology(rows, inventory)
        self.assertEqual(result["devices"], 9)
        self.assertEqual(sum(key.startswith("aci:") for key in inventory), 6)
        self.assertEqual(sum(key.startswith("host:") for key in inventory), 3)
        aci = next(row for row in rows if row.get("device_id", "").startswith("aci:"))
        aci["cluster"] = "invented-cluster"
        with self.assertRaisesRegex(client.Refused, "invented a cluster"):
            runner.semantic_v2_topology(rows, inventory)
        aci.pop("cluster")
        rows.append({"row_type": "link", "a_device": "a", "b_device": "b"})
        with self.assertRaisesRegex(client.Refused, "invented adjacency"):
            runner.semantic_v2_topology(rows, inventory)

    def test_v2_traffic_requires_raw_tuple_parity_and_unknown_counters(self):
        raw = [
            json.loads(line)
            for line in (TOOLS.parent / "fixtures/raw-aci/stream_netflow.ndjson")
            .read_text()
            .splitlines()
        ]
        self.driver.v2_exporters = sorted({row["event"]["exporter_ip"] for row in raw})
        self.driver.v2_traffic_count = len(raw)
        self.driver.v2_raw_fingerprints = runner.Counter(
            runner.traffic_projection(row["event"], raw=True) for row in raw
        )
        rows = [
            {
                "source": "adm:conversation",
                "contract_version": "2",
                "rollup_id": "conversation",
                "flow_source": "hubble",
            }
        ]
        for i, envelope in enumerate(raw):
            event = envelope["event"]
            observation = {
                "counter_semantics": "unknown",
                "metrics_authoritative": "0",
                "records": 1,
                "profile": "standard_netflow",
                "source": "stream_ipfix",
                "source_authority": event["exporter_ip"],
                "scope": "prod",
                "cluster": "demo-cluster",
                "observation_domain_present": "0",
            }
            rows.append(
                {
                    "source": "adm:traffic_observation",
                    "contract_version": "2",
                    "rollup_id": str(i),
                    "counter_semantics": "unknown",
                    "metrics_authoritative": "0",
                    "records": "1",
                    "adm_scope_source": "stream_ipfix",
                    "adm_scope_authority": event["exporter_ip"],
                    "adm_scope_domain_kind": "exporter",
                    "adm_scope_observation_domain_present": "0",
                    "adm_profile_status": "mapped",
                    "scope": "prod",
                    "cluster": "demo-cluster",
                    "source_ip": event.get("src_ip"),
                    "destination_ip": event.get("dest_ip"),
                    "source_port": event.get("src_port"),
                    "destination_port": event.get("dest_port"),
                    "raw_bytes": event.get("bytes"),
                    "raw_packets": event.get("packets"),
                    "traffic_observations": json.dumps([observation]),
                }
            )

        class FakeApi:
            def __init__(self, role, account):
                pass

            def search(self, query, *window):
                return rows, {"sid": "stored-summary-query"}

        with patch.object(client, "Api", FakeApi):
            result, _ = self.driver._v2_summaries("sh1", "admin")
            self.assertEqual(result["traffic_rows"], len(raw))
            rows[1]["metrics_authoritative"] = "1"
            with self.assertRaises(client.Refused):
                self.driver._v2_summaries("sh1", "admin")
            rows[1]["metrics_authoritative"] = "0"
            rows[1]["raw_bytes"] += 1
            with self.assertRaisesRegex(client.Refused, "raw counters"):
                self.driver._v2_summaries("sh1", "admin")

    def test_v2_seed_inserts_exact_profiles_and_settings_without_scope_changes(self):
        stores, posts = {}, []

        class FakeApi:
            def __init__(self, role):
                pass

            def json(self, method, path, raw=None):
                base = path.split("?", 1)[0]
                collection = next(
                    name
                    for name in (
                        "adm_network_source_scope",
                        "adm_cilium_cluster_settings",
                    )
                    if "/" + name in base
                )
                rows = stores.setdefault(collection, [])
                if method == "POST":
                    row = json.loads(raw)
                    rows.append(row)
                    posts.append((collection, row))
                    return {"_key": row["_key"]}
                if "?" in path:
                    query = __import__("urllib.parse", fromlist=["parse_qs"]).parse_qs(
                        path.split("?", 1)[1]
                    )
                    return sorted(rows, key=lambda row: row["_key"])[
                        int(query["skip"][0]) :
                    ]
                return next(
                    row for row in rows if row["_key"] == base.rsplit("/", 1)[1]
                )

        with (
            patch.object(client, "Api", FakeApi),
            patch.object(self.driver, "_wait", return_value=True),
        ):
            first = self.driver._v2_seed()
            self.assertEqual(len(first["exporters"]), 3)
            self.assertEqual(len(posts), 4)
            self.assertTrue(
                all(
                    row["profile"] == "standard_netflow"
                    and row["observation_domain_present"] == "0"
                    and row["observation_domain_id"] == ""
                    for name, row in posts
                    if name == "adm_network_source_scope"
                )
            )
            self.assertEqual(first["cluster_settings"]["lb_mode"], "snat")
            self.driver._v2_seed()
            self.assertEqual(
                len(posts), 4, "same source seed must never be inserted twice"
            )


if __name__ == "__main__":
    unittest.main()
