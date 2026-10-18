"""Small offline safety/coordination tests; no Docker, SSH, or Splunk operations."""

import configparser
import hashlib
import io
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

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

    def race_with_convergence_reads(self, reads, response_mutator=None):
        pending = list(reads)
        state = {"winner": None, "retried": False, "reads": 0}
        self.race_state = state
        lock = __import__("threading").Lock()
        snapshot = self.settings_read

        class FakeApi:
            def __init__(self, role):
                self.role = role

            def json(self, method, path, raw=None):
                if method == "GET":
                    if not state["retried"]:
                        return snapshot(None)
                    state["reads"] += 1
                    return pending.pop(0) if pending else snapshot("winner")
                request = json.loads(raw)
                with lock:
                    if state["winner"] is None:
                        state["winner"] = request["requestId"]
                    elif state["winner"] != request["requestId"]:
                        raise client.ApiError(409)
                    else:
                        state["retried"] = True
                response = {"committedRevision": "winner", "requestId": state["winner"]}
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
            result = client.settings_race(None, [{}, {}], "namespace")
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

    def test_members_race_then_retry_winning_commit(self):
        response = {"committedRevision": "winner", "requestId": "winning-request"}
        calls = []
        lock = __import__("threading").Lock()

        class FakeApi:
            def __init__(self, role):
                self.role = role

            def json(self, method, path, raw=None):
                if method == "GET":
                    return {
                        "canWrite": True,
                        "namespace": "namespace",
                        "state": "configured" if calls else "absent",
                        "settings": {"revision": "winner"} if calls else None,
                    }
                with lock:
                    request = json.loads(raw)
                    if calls and request["requestId"] == calls[0]["requestId"]:
                        return {**response, "requestId": request["requestId"]}
                    calls.append(request)
                    if len(calls) == 1:
                        return {**response, "requestId": request["requestId"]}
                    raise client.ApiError(409)

        with patch.object(client, "Api", FakeApi):
            result = client.settings_race(None, [{"a": 1}, {"a": 2}], "namespace")
        self.assertEqual(sorted(result["statuses"]), [200, 409])
        self.assertTrue(result["retry_identical"])
        self.assertEqual(len(calls), 2)
        self.assertTrue(
            all("settings" in request and "payload" not in request for request in calls)
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
