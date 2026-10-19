"""Deterministic concurrency and authorization tests for immutable settings slots.

The lock in FakeKV models KV Store's documented unique insert primitive. It is
not an application lock and no application instance shares a process/mutex.
"""

import copy
import json
from pathlib import Path
import sys
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "splunk_app/splunk_adm/bin"))
from adm_settings_lib import (  # noqa: E402
    SettingsError,
    SettingsService,
    canonical,
    successor_key,
)
from adm_settings_lib.rest import handle_request  # noqa: E402


def settings(revision="draft", state="active"):
    return {
        "schemaVersion": 1,
        "revision": revision,
        "sources": {
            "netflow": {"state": state, "cadenceSeconds": 60, "staleAfterSeconds": 600}
        },
    }


def operation(request_id="request_a", expected=None, state="active"):
    return {
        "settings": settings(state=state),
        "requestId": request_id,
        "expectedRevision": expected,
    }


class FakeKV:
    def __init__(self):
        self.rows = {}
        self.lock = threading.Lock()
        self.barrier = None
        self.attempts = []
        self.authorized = True
        self.enabled = True
        self.fail_after_insert = False
        self.hide_reads = False

    def scan(self, limit):
        with self.lock:
            return (
                []
                if self.hide_reads
                else copy.deepcopy(list(self.rows.values())[:limit])
            )

    def insert(self, document):
        if self.barrier:
            self.barrier.wait(timeout=3)
        with self.lock:
            self.attempts.append(document["_key"])
            if document["_key"] in self.rows:
                raise RuntimeError("duplicate key")
            self.rows[document["_key"]] = copy.deepcopy(document)
            if self.fail_after_insert:
                raise RuntimeError("response lost")

    def authorization(self):
        return self.authorized

    def persistence(self):
        if not self.enabled:
            raise SettingsError(
                503,
                "unsupported",
                "Writes are disabled pending topology qualification.",
            )
        return "namespace_a"


class AtomicSettingsTests(unittest.TestCase):
    def setUp(self):
        self.store = FakeKV()
        self.service = SettingsService(self.store, {"netflow"})

    def compete(self, expected):
        self.store.barrier = threading.Barrier(2)

        def save(request_id):
            # Two independent instances share only the KV namespace.
            try:
                result = SettingsService(self.store, {"netflow"}).write(
                    operation(request_id, expected)
                )
                return result
            except SettingsError as exc:
                return exc.code

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(save, ("request_b", "request_c")))
        self.store.barrier = None
        self.assertEqual(sum(isinstance(result, dict) for result in results), 1)
        self.assertEqual(results.count("conflict"), 1)
        self.assertEqual(len(self.store.attempts[-2:]), 2)
        self.assertEqual(len(set(self.store.attempts[-2:])), 1)

    def test_competing_creation_has_one_winner(self):
        self.compete(None)
        self.assertEqual(len(self.store.rows), 1)

    def test_competing_same_revision_has_one_winner(self):
        revision = self.service.write(operation())["committedRevision"]
        self.compete(revision)
        self.assertEqual(len(self.store.rows), 2)

    def test_concurrent_duplicate_request_recovers_one_logical_commit(self):
        self.store.barrier = threading.Barrier(2)
        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(
                pool.map(
                    lambda _: SettingsService(self.store, {"netflow"}).write(
                        operation()
                    ),
                    range(2),
                )
            )
        self.store.barrier = None
        self.assertEqual(len(self.store.rows), 1)
        self.assertEqual(
            outcomes[0]["committedRevision"], outcomes[1]["committedRevision"]
        )
        self.assertEqual(len(self.store.attempts), 2)

    def test_stale_revision_is_rejected_without_insert(self):
        self.service.write(operation())
        before = len(self.store.attempts)
        with self.assertRaises(SettingsError) as caught:
            self.service.write(operation("request_b"))
        self.assertEqual(caught.exception.code, "conflict")
        self.assertEqual(len(self.store.attempts), before)

    def test_retry_recovers_exact_operation_after_later_successor(self):
        first = operation()
        saved = self.service.write(first)
        newer = self.service.write(
            operation("request_b", saved["committedRevision"], "staged")
        )
        recovered = self.service.write(first)
        self.assertTrue(recovered["superseded"])
        self.assertEqual(recovered["committedRevision"], saved["committedRevision"])
        self.assertEqual(recovered["settings"], newer["settings"])
        self.assertEqual(len(self.store.rows), 2)
        changed = operation(state="not_selected")
        with self.assertRaises(SettingsError) as caught:
            self.service.write(changed)
        self.assertEqual(caught.exception.code, "conflict")

    def test_lost_insert_response_is_resolved_without_second_insert(self):
        self.store.fail_after_insert = True
        result = self.service.write(operation())
        self.assertFalse(result["superseded"])
        self.service.write(operation())
        self.assertEqual(len(self.store.attempts), 1)

    def test_unverified_write_is_uncertain_and_retry_recovers(self):
        original = self.store.insert

        def insert_then_hide(document):
            original(document)
            self.store.hide_reads = True

        self.store.insert = insert_then_hide
        with self.assertRaises(SettingsError) as caught:
            self.service.write(operation())
        self.assertEqual(caught.exception.code, "uncertain")
        self.store.hide_reads = False
        self.service.write(operation())
        self.assertEqual(len(self.store.attempts), 1)

    def test_legacy_migrates_without_mutating_original_and_detects_old_writer(self):
        legacy = settings("legacy")
        row = {
            "_key": "deployment",
            "revision": "legacy",
            "settings_json": canonical(legacy),
        }
        self.store.rows["deployment"] = copy.deepcopy(row)
        self.assertEqual(self.service.read()["settings"], legacy)
        saved = self.service.write(operation(expected="legacy"))
        self.assertEqual(self.store.rows["deployment"], row)
        self.assertIn("legacy", self.service.read()["observedRevisions"])
        self.assertEqual(saved["settings"]["sources"], legacy["sources"])
        self.store.rows["deployment"]["settings_json"] = canonical(
            settings("legacy", "staged")
        )
        with self.assertRaises(SettingsError) as caught:
            self.service.read()
        self.assertEqual(caught.exception.code, "unavailable")

    def test_legacy_creation_after_atomic_creation_is_fail_closed(self):
        self.service.write(operation())
        self.store.rows["deployment"] = {
            "_key": "deployment",
            "revision": "old",
            "settings_json": canonical(settings("old")),
        }
        with self.assertRaises(SettingsError):
            self.service.read()

    def test_invalid_history_and_cap_never_fall_back_to_legacy(self):
        self.service.write(operation())
        root = self.store.rows["atomic_root"]
        self.store.rows[successor_key("unknown")] = copy.deepcopy(root)
        with self.assertRaises(SettingsError):
            self.service.read()
        self.store.rows.pop(successor_key("unknown"))
        with patch("adm_settings_lib.MAX_RECORDS", 1):
            # The final accepted slot stays readable and exactly retryable.
            self.assertEqual(self.service.write(operation())["state"], "configured")
            with self.assertRaises(SettingsError):
                self.service.write(operation("next", root["revision"]))
            self.assertEqual(len(self.store.rows), 1)
        self.store.rows["extra"] = {"_key": "extra"}
        with patch("adm_settings_lib.MAX_RECORDS", 1):
            with self.assertRaises(SettingsError):
                self.service.read()

    def request(self, method="POST", **changes):
        payload = {**operation(), "namespace": "namespace_a", **changes}
        return handle_request(
            {"method": method, "payload": json.dumps(payload)}, self.store, {"netflow"}
        )

    def test_unauthorized_server_write_fails_before_persistence(self):
        self.store.authorized = False
        with self.assertRaises(SettingsError) as caught:
            self.request()
        self.assertEqual(caught.exception.status, 403)
        self.assertEqual(self.store.attempts, [])
        self.assertFalse(self.request("GET")["canWrite"])

    def test_disabled_default_preserves_reader_access_and_blocks_writes(self):
        self.service.write(operation())
        self.store.enabled = False
        read = self.request("GET")
        self.assertEqual(read["state"], "configured")
        self.assertFalse(read["canWrite"])
        self.assertIn("disabled", read["writeUnavailableReason"])
        with self.assertRaises(SettingsError) as caught:
            self.request()
        self.assertEqual(caught.exception.code, "unsupported")
        self.assertEqual(len(self.store.attempts), 1)

    def test_cross_namespace_write_is_rejected_before_insert(self):
        with self.assertRaises(SettingsError) as caught:
            self.request(namespace="other_search_head")
        self.assertEqual(caught.exception.code, "conflict")
        self.assertFalse(self.store.attempts)

    def test_invalid_expectations_do_not_commit(self):
        for change in (
            {"unknown": {}},
            {
                "netflow": {
                    "state": "active",
                    "cadenceSeconds": True,
                    "staleAfterSeconds": 600,
                }
            },
        ):
            payload = operation()
            payload["settings"]["sources"] = change
            with self.assertRaises(SettingsError):
                self.service.write(payload)
        self.assertFalse(self.store.attempts)

    def test_config_enforces_session_auth_capability_and_csrf(self):
        import configparser

        app = ROOT / "splunk_app/splunk_adm/default"
        config = configparser.ConfigParser()
        config.read(app / "restmap.conf")
        endpoint = config["script:adm_deployment_settings"]
        self.assertEqual(endpoint["capability.post"], "admin_all_objects")
        self.assertEqual(endpoint["python.required"], "3.13")
        self.assertEqual(endpoint["python.version"], "python3")
        self.assertTrue(endpoint.getboolean("requireAuthentication"))
        self.assertTrue(endpoint.getboolean("passSession"))
        self.assertFalse(endpoint.getboolean("passSystemAuth"))
        config.read(app / "web.conf")
        self.assertEqual(
            set(config["expose:adm_deployment_settings"]), {"pattern", "methods"}
        )
        config.read(app / "app.conf")
        self.assertEqual(config["triggers"]["reload.adm_settings"], "simple")
        config.read(app / "adm_settings.conf")
        self.assertEqual(config["persistence"]["write_mode"], "disabled")
        self.assertEqual(config["persistence"]["platform"], "unqualified")


class PersistentHandlerTests(unittest.TestCase):
    def test_importlib_loader_finds_real_adjacent_library_from_unrelated_cwd(self):
        import importlib.util
        import os
        import types
        from tempfile import TemporaryDirectory

        app_bin = ROOT / "splunk_app/splunk_adm/bin"
        application = types.ModuleType("splunk.persistconn.application")
        application.PersistentServerConnectionApplication = object
        original_cwd = Path.cwd()
        with (
            TemporaryDirectory() as unrelated,
            patch.object(
                sys, "path", [value for value in sys.path if value != str(app_bin)]
            ),
            patch.dict(
                sys.modules,
                {
                    "splunk": types.ModuleType("splunk"),
                    "splunk.persistconn": types.ModuleType("splunk.persistconn"),
                    "splunk.persistconn.application": application,
                },
            ),
        ):
            for name in list(sys.modules):
                if name == "adm_settings_lib" or name.startswith("adm_settings_lib."):
                    sys.modules.pop(name)
            try:
                os.chdir(unrelated)
                spec = importlib.util.spec_from_file_location(
                    "test_native_importlib_settings", app_bin / "adm_settings.py"
                )
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                library = sys.modules["adm_settings_lib"]
                self.assertEqual(
                    Path(library.__file__).resolve(),
                    app_bin / "adm_settings_lib/__init__.py",
                )
                self.assertEqual(sys.path[0], str(app_bin))
                self.assertEqual(
                    module.SettingsHandler("native-command", "native-argument").handle(
                        json.dumps({"method": "GET"})
                    )["status"],
                    401,
                )
            finally:
                os.chdir(original_cwd)

    def test_native_handler_constructor_and_sanitized_authorization_error(self):
        import importlib.util
        import types

        application = types.ModuleType("splunk.persistconn.application")
        application.PersistentServerConnectionApplication = object
        with patch.dict(
            sys.modules,
            {
                "splunk": types.ModuleType("splunk"),
                "splunk.persistconn": types.ModuleType("splunk.persistconn"),
                "splunk.persistconn.application": application,
            },
        ):
            spec = importlib.util.spec_from_file_location(
                "test_adm_settings_handler",
                ROOT / "splunk_app/splunk_adm/bin/adm_settings.py",
            )
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            handler = module.SettingsHandler("native-command", "native-argument")
            self.assertEqual(
                handler.handle(json.dumps({"method": "GET"}))["status"], 401
            )
            store = FakeKV()
            store.authorized = False
            with (
                patch.object(module, "source_ids", return_value={"netflow"}),
                patch.object(module, "SplunkStore", return_value=store),
            ):
                result = handler.handle(
                    json.dumps(
                        {
                            "method": "POST",
                            "session": {"authtoken": "synthetic-session-value"},
                            "payload": "{}",
                        }
                    )
                )
            self.assertEqual(result["status"], 403)
            self.assertNotIn("synthetic-session-value", json.dumps(result))
            self.assertEqual(result["headers"]["Cache-Control"], "no-store")


class ScanCompletenessTests(unittest.TestCase):
    def store(self, rows, cap=None):
        from adm_settings_lib.rest import SplunkStore

        class Store(SplunkStore):
            calls = 0

            def request(self, method, path, body=None, query=None):
                self.calls += 1
                self.last_query = query
                count = min(query["limit"], cap) if cap is not None else query["limit"]
                return copy.deepcopy(rows[query["skip"] : query["skip"] + count])

        return Store("synthetic-session")

    def test_complete_empty_and_nonempty_scans_prove_sorted_overlap(self):
        for rows in ([], [{"_key": "a"}], [{"_key": "a"}, {"_key": "b"}]):
            with self.subTest(rows=rows):
                store = self.store(rows)
                self.assertEqual(store.scan(5), rows)
                self.assertEqual(store.calls, 2)
                self.assertEqual(
                    store.last_query, {"limit": 5, "skip": 1, "sort": "_key:1"}
                )

    def test_lower_hard_query_cap_does_not_publish_valid_prefix(self):
        store = self.store([{"_key": "a"}, {"_key": "b"}, {"_key": "c"}], cap=2)
        with self.assertRaises(SettingsError) as caught:
            store.scan(5)
        self.assertEqual(caught.exception.code, "unavailable")
        self.assertEqual(store.calls, 4)

    def test_insert_during_overlap_can_settle_on_one_bounded_rescan(self):
        from adm_settings_lib.rest import SplunkStore

        old = [{"_key": "a"}]
        new = old + [{"_key": "b"}]
        with patch.object(
            SplunkStore, "request", side_effect=[old, new[1:], new, new[1:]]
        ):
            self.assertEqual(SplunkStore("synthetic-session").scan(5), new)

    def test_unknown_malformed_order_and_overflow_are_not_silently_truncated(self):
        for rows in (
            [{"_key": "b"}, {"_key": "a"}],
            [{"_key": "a"}, {"_key": "a"}],
            [{"bad": "row"}],
        ):
            with self.subTest(rows=rows), self.assertRaises(SettingsError):
                self.store(rows).scan(5)
        # A bound+one result is explicitly returned to SettingsService, which
        # rejects it before interpreting any prefix as a history head.
        rows = [{"_key": str(value)} for value in range(5)]
        store = self.store(rows)
        self.assertEqual(store.scan(5), rows)
        self.assertEqual(store.calls, 1)


class TopologyGateTests(unittest.TestCase):
    def cluster(self):
        return {
            "captain": {
                "id": "cluster-guid",
                "mgmt_uri": "https://head-one:8089",
                "initialized_flag": True,
                "min_peers_joined_flag": True,
                "service_ready_flag": True,
                "stable_captain": True,
                "rolling_restart_flag": False,
                "rolling_upgrade_flag": False,
                "kvstore_maintenance_status": "disabled",
            },
            "peers": {
                guid: {
                    "mgmt_uri": f"https://{guid}:8089",
                    "status": "Up",
                    "splunk_version": "10.6.0.5",
                    "manual_detention": "off",
                    "out_of_sync_node": False,
                    "restart_required": "0",
                }
                for guid in ("head-one", "head-two", "head-three")
            },
        }

    def member(self):
        return {
            "status": "Up",
            "is_registered": True,
            "maintenance_mode": False,
            "restart_state": "NoRestart",
        }

    def store(
        self,
        mode="single_namespace",
        platform="enterprise",
        cohosted_status="ready",
        cohosted_type="Pdl",
        service_address="https://127.0.0.1:36527/",
        server_guid="head-one",
        cluster=None,
        member=None,
        **current,
    ):
        from adm_settings_lib.rest import SplunkStore

        cluster = self.cluster() if cluster is None else cluster
        member = self.member() if member is None else member

        class Store(SplunkStore):
            def request(self, method, path, body=None, query=None):
                self.requests.append((method, path, query))
                if "conf-adm_settings" in path:
                    value = {"write_mode": mode, "platform": platform}
                elif "server/info" in path:
                    value = {
                        "version": "10.6.0.5",
                        "product_type": "enterprise",
                        "guid": server_guid,
                    }
                elif "kvstore/status" in path:
                    value = {
                        "cohosted": {
                            "status": cohosted_status,
                            "serviceInfo": {
                                "type": cohosted_type,
                                "service": service_address,
                            },
                        },
                        "current": {
                            "status": "ready",
                            "disabled": "0",
                            "backupRestoreStatus": "Ready",
                            "guid": "head-one",
                            "migrationStatus": "NotStarted",
                            "versionUpgradeInProgress": "0",
                            "standalone": "1",
                            **current,
                        },
                        "peers": None,
                    }
                elif "shcluster/status" in path:
                    value = cluster
                elif "shcluster/member/info" in path:
                    value = member
                else:
                    raise AssertionError(f"Unexpected request: {path}")
                return {"entry": [{"content": value}]}

        store = Store("unused-test-session")
        store.requests = []
        return store

    def test_single_namespace_is_stable_and_shc_is_rejected_in_single_mode(self):
        self.assertEqual(self.store().persistence(), self.store().persistence())
        with self.assertRaises(SettingsError):
            self.store(standalone="0").persistence()

    def test_captured_standalone_shape_uses_matching_instance_guids_without_replica_set(
        self,
    ):
        self.assertEqual(
            self.store(replicaSet=None).persistence(), self.store().persistence()
        )
        from adm_settings_lib.rest import SplunkStore

        snapshot = {
            "server": {
                "version": "10.6.0.5",
                "product_type": "enterprise",
                "guid": "8455208E-5F3F-4182-A69F-FC605884C07C",
            }
        }
        runtime = {
            "status": "ready",
            "disabled": False,
            "backupRestoreStatus": "Ready",
            "standalone": True,
            "storageEngine": "wiredTiger",
            "port": 8191,
            "guid": snapshot["server"]["guid"],
            "migrationStatus": "NotStarted",
            "versionUpgradeInProgress": "0",
        }
        with patch.object(
            SplunkStore,
            "request",
            side_effect=[
                {
                    "entry": [
                        {
                            "content": {
                                "write_mode": "single_namespace",
                                "platform": "enterprise",
                            }
                        }
                    ]
                },
                {"entry": [{"content": snapshot["server"]}]},
                {
                    "entry": [
                        {
                            "content": {
                                "current": runtime,
                                "cohosted": {
                                    "status": "ready",
                                    "serviceInfo": {
                                        "type": "Pdl",
                                        "service": "https://127.0.0.1:36527/",
                                    },
                                },
                            }
                        }
                    ]
                },
            ],
        ):
            self.assertIsInstance(SplunkStore("synthetic-session").persistence(), str)

    def test_ephemeral_pdl_service_address_is_not_namespace_identity(self):
        self.assertEqual(
            self.store(service_address="https://127.0.0.1:36527/").persistence(),
            self.store(service_address="https://127.0.0.1:45678/").persistence(),
        )

    def test_cluster_uses_pdl_shape_and_explicit_shc_health_endpoints(self):
        store = self.store("qualified_shc", standalone=False)
        self.assertIsInstance(store.persistence(), str)
        self.assertIn(
            (
                "GET",
                "/services/shcluster/status",
                {"advanced": 1, "output_mode": "json"},
            ),
            store.requests,
        )
        self.assertIn(
            ("GET", "/services/shcluster/member/info", {"output_mode": "json"}),
            store.requests,
        )
        with self.assertRaises(SettingsError):
            self.store("qualified_shc").persistence()

    def test_shc_namespace_agrees_across_members_and_captain_changes(self):
        namespaces = set()
        for guid in self.cluster()["peers"]:
            cluster = self.cluster()
            cluster["captain"]["mgmt_uri"] = cluster["peers"][guid]["mgmt_uri"]
            namespaces.add(
                self.store(
                    "qualified_shc",
                    standalone=False,
                    guid=guid,
                    server_guid=guid,
                    cluster=cluster,
                    service_address=f"https://127.0.0.1:{30000 + len(guid)}/",
                ).persistence()
            )
        self.assertEqual(len(namespaces), 1)
        original = namespaces.pop()
        for field in ("cluster", "membership"):
            cluster = self.cluster()
            if field == "cluster":
                cluster["captain"]["id"] = "another-cluster"
            else:
                cluster["peers"]["head-four"] = {
                    **cluster["peers"]["head-three"],
                    "mgmt_uri": "https://head-four:8089",
                }
            self.assertNotEqual(
                original,
                self.store(
                    "qualified_shc", standalone=False, cluster=cluster
                ).persistence(),
            )

    def test_shc_captain_health_evidence_is_required_and_fail_closed(self):
        invalid = {
            "id": (None, "", "head-one"),
            "mgmt_uri": (None, "https://other-head:8089"),
            "initialized_flag": (None, False),
            "min_peers_joined_flag": (None, False),
            "service_ready_flag": (None, False),
            "stable_captain": (None, False),
            "rolling_restart_flag": (None, True),
            "rolling_upgrade_flag": (None, True),
            "kvstore_maintenance_status": (None, "enabled"),
        }
        for key, values in invalid.items():
            for value in values:
                cluster = self.cluster()
                cluster["captain"][key] = value
                with (
                    self.subTest(key=key, value=value),
                    self.assertRaises(SettingsError),
                ):
                    self.store(
                        "qualified_shc", standalone=False, cluster=cluster
                    ).persistence()

    def test_shc_local_member_binding_and_registration_are_required(self):
        for changes in (
            {"guid": "different"},
            {"guid": None},
            {"server_guid": None},
            {"server_guid": "other", "guid": "other"},
            {"cluster": {}},
            {"member": {}},
        ):
            with self.subTest(changes=changes), self.assertRaises(SettingsError):
                self.store("qualified_shc", standalone=False, **changes).persistence()
        for key, values in {
            "status": (None, "Down", "ManualDetention"),
            "is_registered": (None, False),
            "maintenance_mode": (None, True),
            "restart_state": (None, "Restart"),
        }.items():
            for value in values:
                member = {**self.member(), key: value}
                with (
                    self.subTest(key=key, value=value),
                    self.assertRaises(SettingsError),
                ):
                    self.store(
                        "qualified_shc", standalone=False, member=member
                    ).persistence()

    def test_shc_peer_identity_and_ready_state_are_required(self):
        invalid = {
            "status": (None, "Down"),
            "splunk_version": (None, "10.4.0"),
            "manual_detention": (None, "on"),
            "out_of_sync_node": (None, True),
            "restart_required": (None, "1"),
            "mgmt_uri": (
                None,
                "",
                "https://head-one:8089",
                "http://head-two:8089",
                "https://head-two",
                "https://head-two:invalid",
                "https://user:secret@head-two:8089",
                "https://head-two:8089/path",
                "https://head-two:8089?query",
                "https://head-two:8089#fragment",
            ),
        }
        for key, values in invalid.items():
            for value in values:
                cluster = self.cluster()
                cluster["peers"]["head-two"][key] = value
                with (
                    self.subTest(key=key, value=value),
                    self.assertRaises(SettingsError),
                ):
                    self.store(
                        "qualified_shc", standalone=False, cluster=cluster
                    ).persistence()
        for peers in (None, [], {}, {"head-one": {}}, {"head-one": None}):
            cluster = {**self.cluster(), "peers": peers}
            with self.subTest(peers=peers), self.assertRaises(SettingsError):
                self.store(
                    "qualified_shc", standalone=False, cluster=cluster
                ).persistence()
        for malformed in (None, [], "peer"):
            cluster = self.cluster()
            cluster["peers"]["head-two"] = malformed
            with self.subTest(malformed=malformed), self.assertRaises(SettingsError):
                self.store(
                    "qualified_shc", standalone=False, cluster=cluster
                ).persistence()

    def test_disabled_unknown_cloud_and_unready_fail_closed(self):
        for values in (
            {"mode": "disabled"},
            {"mode": "arbitrary"},
            {"platform": "cloud"},
            {"cohosted_status": "starting"},
            {"cohosted_status": None},
            {"cohosted_type": "Mongo"},
            {"cohosted_type": None},
            {"service_address": None},
            {"status": "failed"},
            {"disabled": "1"},
            {"backupRestoreStatus": "in_progress"},
            {"guid": None},
            {"guid": "other-instance"},
            {"standalone": None},
            {"backupRestoreStatus": None},
            {"migrationStatus": "InProgress"},
            {"migrationStatus": None},
            {"versionUpgradeInProgress": "1"},
            {"versionUpgradeInProgress": None},
        ):
            with self.subTest(values=values), self.assertRaises(SettingsError):
                self.store(**values).persistence()


if __name__ == "__main__":
    unittest.main()
