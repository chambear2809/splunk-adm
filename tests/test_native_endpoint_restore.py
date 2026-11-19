import importlib.util
import hashlib
import sqlite3
import json
import subprocess
from contextlib import closing
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "splunk_app/splunk_adm/bin"))
sys.path.insert(0, str(REPO / "tools"))
from adm_cases_lib.splunk_host import HostUnavailable, SplunkHost  # noqa: E402
import case_recovery_snapshot as snapshot  # noqa: E402
from adm_cases_lib.job_ledger import JobLedger, QuotaExceeded  # noqa: E402
from adm_cases_lib.store import CaseStore  # noqa: E402
from adm_cases_lib.api import CaseAPI  # noqa: E402
from adm_cases_lib.native import NativeComparisonSearch, CaptureUnavailable  # noqa: E402

SPEC = importlib.util.spec_from_file_location(
    "endpoint_restore_fixture", REPO / "tools/qualify_native_endpoint_restore.py"
)
fixture = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(fixture)


class IsolatedRouteTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve() / "fixture"
        self.root.mkdir(mode=0o700)
        for name in ("source", "restored"):
            (self.root / name).mkdir(mode=0o700)
        self.live = Path(self.temp.name).resolve() / "live"
        self.live.mkdir(mode=0o700)
        self.users = ("atlas_er_0123456789a", "atlas_er_0123456789b")
        self.generation = "1" * 32
        self.original = SplunkHost.database
        self.old_path = list(sys.path)
        self.root_patch = mock.patch.object(fixture, "ROOT", self.root)
        self.root_patch.start()
        source = fixture.build_hook(self.users, self.generation)
        with mock.patch.object(sys, "argv", [fixture.WORKER]):
            exec(compile(source, "<hook>", "exec"), {"__name__": "sitecustomize"})

    def tearDown(self):
        SplunkHost.database = self.original
        sys.path[:] = self.old_path
        self.root_patch.stop()
        self.temp.cleanup()

    def host(self, principal):
        return SplunkHost(
            "token",
            request=lambda path: {
                "username": principal,
                "capabilities": ["adm_investigate"],
            },
            database_root=str(self.live),
        )

    def test_exact_principal_routes_through_original_database_safety(self):
        fixture.write_control(self.root, self.generation, "blocked")
        with self.assertRaises(HostUnavailable):
            self.host(self.users[0]).database()
        fixture.write_control(self.root, self.generation, "source", expected="blocked")
        host = self.host(self.users[0])
        self.assertEqual(
            host.database(), self.root / "source/splunk_adm_investigations/cases.sqlite"
        )
        self.assertEqual(host.database_root, str(self.live))
        self.assertEqual(
            self.host("another_user").database(),
            self.live / "splunk_adm_investigations/cases.sqlite",
        )
        fixture.write_control(self.root, self.generation, "blocked", expected="source")
        fixture.write_control(
            self.root, self.generation, "restored", expected="blocked"
        )
        self.assertEqual(
            self.host(self.users[1]).database(),
            self.root / "restored/splunk_adm_investigations/cases.sqlite",
        )

    def test_route_marker_attests_principal_generation_and_private_root(self):
        fixture.write_control(self.root, self.generation, "blocked")
        fixture.write_control(self.root, self.generation, "source", expected="blocked")
        self.host(self.users[0]).database()
        paths = list(self.root.glob("route-*.json"))
        self.assertEqual(len(paths), 1)
        record = json.loads(paths[0].read_text())
        self.assertEqual(record["principal"], self.users[0])
        self.assertEqual(record["generation"], self.generation)
        self.assertEqual(record["mode"], "source")
        self.assertEqual(record["root"], str(self.root / "source"))
        self.assertEqual(paths[0].stat().st_mode & 0o777, 0o600)

    def test_worker_startup_patch_failure_exits_instead_of_falling_through(self):
        source = fixture.build_hook(self.users, self.generation)
        code = (
            "import sys\n"
            "class Blocker:\n"
            " def find_spec(self,fullname,path=None,target=None):\n"
            "  if fullname=='adm_cases_lib': raise ImportError('forced failure')\n"
            "sys.meta_path.insert(0,Blocker())\n"
            "sys.argv=[" + repr(fixture.WORKER) + "]\n"
            "exec(sys.stdin.read(),{'__name__':'sitecustomize'})"
        )
        result = subprocess.run(
            [sys.executable, "-I", "-c", code],
            input=source,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
        self.assertEqual(result.returncode, 78)

    def test_missing_stale_and_ambiguous_control_never_fall_back(self):
        with self.assertRaises(HostUnavailable):
            self.host(self.users[0]).database()
        fixture.write_control(self.root, self.generation, "blocked")
        (self.root / "control.json").write_text(
            '{"generation":"' + self.generation + '","mode":"source","mode":"restored"}'
        )
        with self.assertRaises(HostUnavailable):
            self.host(self.users[0]).database()
        self.assertFalse((self.live / "splunk_adm_investigations").exists())
        self.assertEqual(
            self.host("another_user").database(),
            self.live / "splunk_adm_investigations/cases.sqlite",
        )

    def test_unsafe_private_root_fails_closed(self):
        fixture.write_control(self.root, self.generation, "blocked")
        fixture.write_control(self.root, self.generation, "source", expected="blocked")
        os.chmod(self.root / "source", 0o755)
        with self.assertRaises(HostUnavailable):
            self.host(self.users[0]).database()

    def test_invalid_generation_and_illegal_transitions_refused(self):
        fixture.write_control(self.root, self.generation, "blocked")
        with self.assertRaises(RuntimeError):
            fixture.write_control(self.root, "2" * 32, "source", expected="blocked")
        fixture.write_control(self.root, self.generation, "source", expected="blocked")
        with self.assertRaises(RuntimeError):
            fixture.write_control(
                self.root, self.generation, "restored", expected="source"
            )


class IsolatedSnapshotTests(unittest.TestCase):
    def test_case_api_notes_capture_acl_and_old_retry_survive_private_copy(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / "source"
            source.mkdir(mode=0o700)
            access = [True]

            def make_store(path):
                return CaseStore(
                    path,
                    lambda *_: True,
                    capture_resolver=lambda _p, ref: {
                        "captured_at": "2026-01-01T03:00:00Z",
                        "data": {"value": ref},
                        "source": {"dataset": ref},
                    },
                    source_entitlement=lambda *_: access[0],
                )

            api = CaseAPI(make_store(source / "cases.sqlite"))

            def call(
                client,
                method,
                path,
                data=None,
                *,
                principal="alice",
                key="key",
                query=None,
            ):
                headers = (
                    {"Content-Type": "application/json", "Idempotency-Key": key}
                    if data is not None
                    else {}
                )
                status, result, _ = client.handle(
                    method,
                    path,
                    principal=principal,
                    query=query,
                    headers=headers,
                    body=json.dumps(data).encode() if data is not None else b"",
                )
                return status, result

            body = {
                "schema_version": 1,
                "title": "Synthetic",
                "window": {
                    "start": "2026-01-01T00:00:00Z",
                    "end": "2026-01-02T00:00:00Z",
                },
            }
            status, case = call(api, "POST", "/cases", body, key="create")
            self.assertEqual(status, 201)
            path = "/cases/" + case["id"]
            _, noted = call(
                api,
                "POST",
                path + "/entries",
                {"expected_revision": 1, "item": {"type": "note", "text": "original"}},
                key="note",
            )
            note = noted["entries"][0]["id"]
            self.assertEqual(
                call(
                    api,
                    "POST",
                    path + "/entries",
                    {
                        "expected_revision": 2,
                        "item": {
                            "type": "note",
                            "text": "revised",
                            "supersedes_entry_id": note,
                        },
                    },
                    key="revise",
                )[0],
                200,
            )
            capture = {
                "expected_revision": 3,
                "reference": "source",
                "label": "synthetic",
            }
            status, captured = call(
                api, "POST", path + "/captures", capture, key="capture"
            )
            self.assertEqual(status, 200)
            capture_id = captured["capture_ids"][0]
            self.assertEqual(
                call(
                    api,
                    "POST",
                    path + "/attachments",
                    {
                        "expected_revision": 4,
                        "entry_id": note,
                        "capture_id": capture_id,
                    },
                    key="attach",
                )[0],
                200,
            )
            self.assertEqual(
                call(
                    api,
                    "POST",
                    path + "/share",
                    {"expected_revision": 5, "member": "bob", "grant": True},
                    key="share",
                )[0],
                200,
            )
            before = call(api, "GET", path, query={"capture_id": capture_id})
            audit = call(api, "GET", path + "/audit")
            os.chmod(source / "cases.sqlite", 0o600)
            JobLedger(source / "capture_jobs.sqlite")
            schemas = {
                name: snapshot.schema_identity(source / name)
                for name in snapshot.ALLOWLIST
            }
            provenance = {"scope": "test"}
            digest = snapshot.create_snapshot(
                source, root / "bundle", expected_schemas=schemas, provenance=provenance
            )
            snapshot.prepare_restore(
                root / "bundle",
                root / "restored",
                expected_manifest_sha256=digest,
                expected_schemas=schemas,
                expected_provenance=provenance,
            )
            receipts = []
            for db_path in (source / "cases.sqlite", root / "restored/cases.sqlite"):
                with closing(sqlite3.connect(db_path)) as connection:
                    receipts.append(
                        connection.execute(
                            "SELECT action,case_id,digest,result FROM requests WHERE principal=? AND request_id=?",
                            ("alice", "capture"),
                        ).fetchall()
                    )
            self.assertEqual(receipts[0], receipts[1])
            self.assertEqual(len(receipts[0]), 1)
            action, stored_id, stored_digest, stored_result = receipts[0][0]
            mutation = {
                "action": "write",
                "case_id": case["id"],
                "payload": {
                    "kind": "trusted_capture",
                    "reference": capture["reference"],
                    "label": capture["label"],
                },
                "expected": capture["expected_revision"],
            }
            expected_digest = hashlib.sha256(
                json.dumps(
                    mutation, sort_keys=True, separators=(",", ":"), allow_nan=False
                ).encode()
            ).hexdigest()
            self.assertEqual(
                (action, stored_id, stored_digest),
                ("write", case["id"], expected_digest),
            )
            self.assertEqual(json.loads(stored_result)["captures"][0]["id"], capture_id)
            restored = CaseAPI(make_store(root / "restored/cases.sqlite"))
            self.assertEqual(
                call(restored, "GET", path, query={"capture_id": capture_id}), before
            )
            self.assertEqual(call(restored, "GET", path + "/audit"), audit)
            self.assertEqual(
                call(restored, "POST", path + "/captures", capture, key="capture"),
                (200, captured),
            )
            self.assertEqual(call(restored, "GET", path, principal="bob")[0], 200)
            access[0] = False
            status, redacted = call(
                restored, "POST", path + "/captures", capture, key="capture"
            )
            self.assertEqual(status, 200)
            self.assertEqual(redacted["captures"], [])
            access[0] = True
            self.assertEqual(
                call(restored, "POST", path + "/captures", capture, key="capture"),
                (200, captured),
            )

    def test_one_archived_unknown_survives_copy_and_global_quota(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            source = root / "source"
            source.mkdir(mode=0o700)
            store = CaseStore(source / "cases.sqlite", lambda *_: True)
            body = {
                "schema_version": 1,
                "title": "Synthetic",
                "window": {
                    "start": "2026-01-01T00:00:00Z",
                    "end": "2026-01-02T00:00:00Z",
                },
            }
            case = store.create("owner", "create", body)
            os.chmod(source / "cases.sqlite", 0o600)
            ledger = JobLedger(source / "capture_jobs.sqlite", clock=lambda: 100)
            ident = "adm-capture-" + "1" * 32
            owner = "a" * 32
            digest = "c" * 64
            ledger.reserve(
                "archived_fixture", ident, digest, 1, 2, owner, transport_hash=digest
            )
            ledger.transition(
                "archived_fixture",
                ident,
                owner,
                "creation_unknown",
                expected_revision=1,
            )
            before = ledger.outstanding("archived_fixture")
            schemas = {
                name: snapshot.schema_identity(source / name)
                for name in snapshot.ALLOWLIST
            }
            provenance = {"scope": "synthetic-test"}
            manifest = snapshot.create_snapshot(
                source, root / "bundle", expected_schemas=schemas, provenance=provenance
            )
            snapshot.prepare_restore(
                root / "bundle",
                root / "restored",
                expected_manifest_sha256=manifest,
                expected_schemas=schemas,
                expected_provenance=provenance,
            )
            restored = JobLedger(
                root / "restored/capture_jobs.sqlite", clock=lambda: 10**8
            )
            self.assertEqual(restored.outstanding("archived_fixture"), before)
            (root / "fresh").mkdir(mode=0o700)
            result = fixture.snapshot_and_restore(
                source,
                root / "second-bundle",
                root / "fresh/splunk_adm_investigations",
                expected_schemas=schemas,
                provenance=provenance,
            )
            self.assertTrue(
                all(
                    result[key]
                    for key in (
                        "occupied_rejected",
                        "corrupt_rejected",
                        "partial_rejected",
                        "logical_pair_equal",
                    )
                )
            )

            request = mock.Mock()
            native = NativeComparisonSearch(
                "synthetic", request=request, ledger=restored, transport_hash=digest
            )
            with self.assertRaises(CaptureUnavailable):
                native._reconcile("archived_fixture")
            request.assert_not_called()

            restored.reserve(
                "normal_a",
                "adm-capture-" + "2" * 32,
                digest,
                1,
                2,
                owner,
                transport_hash=digest,
            )
            restored.reserve(
                "normal_b",
                "adm-capture-" + "3" * 32,
                digest,
                1,
                2,
                owner,
                transport_hash=digest,
            )
            with self.assertRaises(QuotaExceeded):
                restored.reserve(
                    "normal_c",
                    "adm-capture-" + "4" * 32,
                    digest,
                    1,
                    2,
                    owner,
                    transport_hash=digest,
                )
            self.assertEqual(
                CaseStore(root / "restored/cases.sqlite", lambda *_: True).get(
                    "owner", case["id"]
                )["id"],
                case["id"],
            )


if __name__ == "__main__":
    unittest.main()
