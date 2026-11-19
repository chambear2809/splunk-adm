import json
import sqlite3
from contextlib import closing
from unittest import mock
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(
    0, str(Path(__file__).resolve().parents[1] / "splunk_app/splunk_adm/bin")
)
from adm_cases_lib.transport import TransportError  # noqa: E402
from adm_cases_lib.job_ledger import JobLedger  # noqa: E402
from tools import qualify_native_job_outcomes as module  # noqa: E402
import hashlib
from tools.qualify_native_job_outcomes import run_fixture  # noqa: E402

QUERY = '| admqualified mode=graph service="checkout" environment="lab" cluster="cluster-a" namespace="shop" start=100 as_of=200'


class NativeFake:
    def __init__(self):
        self.sid = "server.1"
        self.created = None
        self.created_count = 0
        self.deleted = False
        self.calls = []

    def __call__(self, method, path, data, timeout):
        self.calls.append((method, path))
        if method == "POST":
            self.created_count += 1
            self.sid = "server." + str(self.created_count)
            self.deleted = False
            self.created = dict(data)
            return {"sid": self.sid}
        if method == "DELETE":
            self.deleted = True
            return {}
        if self.deleted:
            raise TransportError(status=404)
        if "/results?" in path:
            return {"preview": False, "results": [{"row_type": "meta"}]}
        info = {
            "sid": self.sid,
            "request": self.created,
            "search": self.created["search"],
            "dispatchState": "DONE",
            "isDone": True,
            "isFinalized": False,
            "eventIsTruncated": False,
            "resultIsTruncated": False,
            "dropCount": 0,
            "resultCount": 1,
        }
        return {
            "entry": [{"acl": {"owner": "alice", "app": "splunk_adm"}, "content": info}]
        }


class JobOutcomeFixtureTests(unittest.TestCase):
    def test_real_library_lost_create_and_delete_acknowledgements(self):
        for mode in ("create", "delete"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as tmp:
                fake = NativeFake()
                stage = Path(tmp) / mode
                result = run_fixture(
                    stage,
                    "alice",
                    "private-token",
                    fake,
                    QUERY,
                    100,
                    200,
                    mode,
                    "f" * 64,
                )
                self.assertEqual(result["status"], "passed_fixture_checks")
                self.assertEqual(
                    result["uncertain_state"],
                    "creation_unknown" if mode == "create" else "cleanup_unknown",
                )
                self.assertTrue(result["caller_sid_404"])
                self.assertTrue(result["authoritative_absence_unverified"])
                self.assertTrue(fake.deleted)
                events = [
                    json.loads(line)
                    for line in (stage / "events.jsonl").read_text().splitlines()
                ]
                self.assertEqual(sum(call[0] == "POST" for call in fake.calls), 1)
                self.assertEqual(
                    sum(event["state"] == "native_ack_hidden" for event in events), 1
                )
                self.assertTrue(
                    next(
                        event
                        for event in events
                        if event["state"] == "retry_and_quota_verified"
                    )["held_lease_protected"]
                )
                observed = next(
                    event
                    for event in events
                    if event["state"] == "uncertainty_observed"
                )
                if mode == "create":
                    self.assertIsNone(observed["ledger"]["server_sid"])
                else:
                    self.assertEqual(observed["ledger"]["server_sid"], fake.sid)
                self.assertNotIn("private-token", (stage / "events.jsonl").read_text())

    def test_lost_sid_journal_failure_preserves_unknown_without_guessing(self):
        from tools import qualify_native_job_outcomes as module

        with tempfile.TemporaryDirectory() as tmp:
            fake = NativeFake()
            stage = Path(tmp) / "create"
            original = module.journal

            def interrupted(directory, event):
                if event["state"] == "native_ack_hidden":
                    raise OSError("injected journal failure")
                return original(directory, event)

            with mock.patch.object(module, "journal", interrupted):
                with self.assertRaises(AssertionError):
                    run_fixture(
                        stage,
                        "alice",
                        "private-token",
                        fake,
                        QUERY,
                        100,
                        200,
                        "create",
                        "f" * 64,
                    )
            self.assertFalse(fake.deleted)
            with closing(sqlite3.connect(stage / "capture_jobs.sqlite")) as db:
                state, server_sid = db.execute(
                    "SELECT state,server_sid FROM jobs"
                ).fetchone()
            self.assertEqual((state, server_sid), ("creation_unknown", None))
            self.assertNotIn(fake.sid, (stage / "events.jsonl").read_text())

    def test_wrong_native_owner_refuses_observer_cleanup(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake = NativeFake()
            original = fake.__call__

            def foreign(method, path, data, timeout):
                result = original(method, path, data, timeout)
                if method == "GET" and "entry" in result:
                    result["entry"][0]["acl"]["owner"] = "other"
                return result

            with self.assertRaises(Exception):
                run_fixture(
                    Path(tmp) / "create",
                    "alice",
                    "private-token",
                    foreign,
                    QUERY,
                    100,
                    200,
                    "create",
                    "f" * 64,
                )
            self.assertFalse(fake.deleted)


class AdminObserverRouteTests(unittest.TestCase):
    def test_real_worker_rejects_role_path_without_network(self):
        from adm_cases_lib import transport_worker

        request = {
            "token": "token",
            "origin": "https://127.0.0.1:8089",
            "ca_length": 1,
            "method": "GET",
            "path": "/services/authorization/roles/admin",
            "data": None,
            "timeout": 3,
        }
        with mock.patch.object(
            transport_worker.http.client, "HTTPSConnection"
        ) as connection:
            with self.assertRaises(ValueError):
                transport_worker.request(request, b"x")
            connection.assert_not_called()

    def test_only_fresh_context_roles_and_fixed_readonly_paths_allowed(self):
        underlying = mock.Mock()
        underlying.ca_bytes = b"ca"
        underlying.trust_digest = "d" * 64
        underlying.return_value = {"entry": [{"content": {"roles": ["admin"]}}]}
        observer = module.AdminObserver(underlying, "token")
        with self.assertRaises(AssertionError):
            observer("GET", "/services/authorization/roles/admin", None, 3)
        observer("GET", "/services/authentication/current-context", None, 3)
        with mock.patch.object(
            observer, "_read_role", return_value={"entry": []}
        ) as read:
            observer("GET", "/services/authorization/roles/admin", None, 3)
            read.assert_called_once_with("admin", 3.0)
        for method, path in (
            ("POST", "/services/authorization/roles/admin"),
            ("GET", "/services/authorization/roles/other"),
            ("GET", "/services/authentication/users"),
            ("DELETE", "/services/search/jobs/a"),
            ("GET", "/services/search/jobs/../a"),
        ):
            with (
                self.subTest(method=method, path=path),
                self.assertRaises(AssertionError),
            ):
                observer(method, path, None, 3)

    def test_role_tls_is_pinned_bounded_and_rejects_redirect(self):
        underlying = mock.Mock()
        underlying.ca_bytes = b"ca"
        underlying.trust_digest = "d" * 64
        observer = module.AdminObserver(underlying, "private-token")
        sock = mock.Mock()
        context = mock.Mock()
        context.wrap_socket.return_value = sock
        response = mock.Mock()
        response.status = 200
        response.read1.side_effect = [b'{"entry":[]}', b""]
        with (
            mock.patch("adm_cases_lib.transport._read_ca", return_value=b"ca"),
            mock.patch.object(
                module.ssl, "create_default_context", return_value=context
            ),
            mock.patch.object(module.socket, "create_connection", return_value=sock),
            mock.patch.object(
                module.http.client, "HTTPResponse", return_value=response
            ),
        ):
            self.assertEqual(observer._read_role("admin", 3), {"entry": []})
            context.wrap_socket.assert_called_once_with(
                sock, server_hostname="127.0.0.1", do_handshake_on_connect=False
            )
            sent = sock.sendall.call_args.args[0]
            self.assertIn(
                b"GET /services/authorization/roles/admin?output_mode=json HTTP/1.1",
                sent,
            )
            self.assertIn(b"Authorization: Splunk private-token", sent)
            response.status = 302
            with self.assertRaises(AssertionError):
                observer._read_role("admin", 3)


class OperatorObserver:
    trust_digest = "e" * 64
    ca_bytes = b"test-ca"

    def __init__(self, native=None):
        self.native = native
        self.roles = ["admin"]
        self.caps = ["search", "admin_all_objects"]
        self.role_value = "original"
        self.status = 404

    def __call__(self, method, path, data, timeout):
        if path == "/services/server/info":
            return {
                "entry": [
                    {
                        "content": {
                            "guid": "test-guid",
                            "version": "10.6.0.5",
                            "activeLicenseGroup": "Enterprise",
                        }
                    }
                ]
            }
        if path == "/services/authentication/current-context":
            return {
                "entry": [
                    {
                        "content": {
                            "username": "operator",
                            "roles": self.roles,
                            "capabilities": self.caps,
                        }
                    }
                ]
            }
        if path.startswith("/services/authorization/roles/"):
            return {"entry": [{"name": "admin", "content": {"value": self.role_value}}]}
        if self.native is not None and not self.native.deleted:
            return self.native(method, path, data, timeout)
        raise TransportError(status=self.status)


class OperatorReconciliationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.stage = Path(self.temp.name)
        self.guid = mock.patch.object(
            module, "GUID_HASH", hashlib.sha256(b"test-guid").hexdigest()
        )
        self.guid.start()
        self.addCleanup(self.guid.stop)
        self.ca = mock.patch(
            "adm_cases_lib.transport._read_ca", return_value=b"test-ca"
        )
        self.ca.start()
        self.addCleanup(self.ca.stop)
        self.observer = OperatorObserver()
        self.marker = lambda: {
            "pid": 123,
            "start_ticks": "456",
            "exe": "/opt/splunk/bin/splunkd",
        }
        self.before = module.observer_snapshot(self.observer, "operator", self.marker)
        self.ledger = JobLedger(self.stage / "capture_jobs.sqlite")
        self.sid = "adm-capture-" + "1" * 32
        rec = self.ledger.reserve(
            "alice",
            self.sid,
            "a" * 64,
            1,
            2,
            "c" * 32,
            transport_hash=self.before["transport_hash"],
        )
        rec = self.ledger.bind_created(
            "alice", self.sid, "c" * 32, "native.1", expected_revision=rec["revision"]
        )
        self.record = self.ledger.transition(
            "alice",
            self.sid,
            "c" * 32,
            "cleanup_unknown",
            expected_revision=rec["revision"],
        )

        module.journal(
            self.stage,
            {
                "state": "operator_predelete_proof",
                "observer": self.before,
                "principal": "alice",
                "native_metadata_sha256": "f" * 64,
                "sid": self.sid,
                "server_sid": "native.1",
                "query_sha256": "a" * 64,
                "window": [1, 2],
            },
        )
        module.journal(
            self.stage,
            {"state": "native_ack_hidden", "method": "DELETE", "sid": "native.1"},
        )

    def run_clear(self, *, original=None, marker=None):
        return module.operator_clear_bound(
            self.stage,
            self.ledger,
            "alice",
            original or self.record,
            self.observer,
            "operator",
            marker or self.marker,
            self.before,
            "d" * 32,
        )

    def test_verified_bound_job_clears_only_original_record(self):
        terminal = self.run_clear()
        self.assertEqual(terminal["state"], "deleted")
        self.assertEqual(self.ledger.outstanding("alice"), [])
        events = [
            json.loads(line)
            for line in (self.stage / "events.jsonl").read_text().splitlines()
        ]
        self.assertEqual(
            [event["state"] for event in events],
            [
                "operator_predelete_proof",
                "native_ack_hidden",
                "operator_absence_proof",
                "operator_terminal",
            ],
        )

    def test_changed_observer_or_service_refuses_clearance(self):
        self.observer.role_value = "changed"
        with self.assertRaises(AssertionError):
            self.run_clear()
        self.observer.role_value = "original"
        self.observer.caps = ["search"]
        with self.assertRaises(AssertionError):
            self.run_clear()
        self.observer.caps = ["search", "admin_all_objects"]
        with self.assertRaises(AssertionError):
            self.run_clear(
                marker=lambda: {
                    "pid": 123,
                    "start_ticks": "457",
                    "exe": "/opt/splunk/bin/splunkd",
                }
            )
        self.assertEqual(
            self.ledger.outstanding("alice")[0]["state"], "cleanup_unknown"
        )

    def test_bad_absence_or_unbound_job_never_clears(self):
        self.observer.status = 403
        with self.assertRaises(AssertionError):
            self.run_clear()
        self.observer.status = 404
        original = dict(self.record, server_sid=None, state="creation_unknown")
        with self.assertRaises(AssertionError):
            self.run_clear(original=original)
        original = dict(self.record, server_sid="different")
        with self.assertRaises(AssertionError):
            self.run_clear(original=original)
        self.assertEqual(
            self.ledger.outstanding("alice")[0]["state"], "cleanup_unknown"
        )

    def test_observer_permissions_change_after_404_refuses_clearance(self):
        original = self.observer.__class__.__call__

        def changed(observer, method, path, data, timeout):
            if path.startswith("/services/search/jobs/"):
                observer.role_value = "changed-after-404"
                raise TransportError(status=404)
            return original(observer, method, path, data, timeout)

        with (
            mock.patch.object(OperatorObserver, "__call__", changed),
            self.assertRaises(AssertionError),
        ):
            self.run_clear()
        self.assertEqual(
            self.ledger.outstanding("alice")[0]["state"], "cleanup_unknown"
        )

    def test_absence_uncertainty_or_missing_preproof_refuses_clearance(self):
        original = self.observer.__class__.__call__

        def uncertain(observer, method, path, data, timeout):
            if path.startswith("/services/search/jobs/"):
                raise TransportError(status=404, uncertain=True)
            return original(observer, method, path, data, timeout)

        with (
            mock.patch.object(OperatorObserver, "__call__", uncertain),
            self.assertRaises(AssertionError),
        ):
            self.run_clear()
        (self.stage / "events.jsonl").unlink()
        with self.assertRaises(FileNotFoundError):
            self.run_clear()
        self.assertEqual(
            self.ledger.outstanding("alice")[0]["state"], "cleanup_unknown"
        )

    def test_concurrent_revision_prevents_terminal_transition(self):
        real_claim = self.ledger.claim

        def racing(principal, sid, owner, *, expected_revision):
            real_claim(principal, sid, owner, expected_revision=expected_revision)
            return real_claim(
                principal, sid, owner, expected_revision=expected_revision
            )

        with (
            mock.patch.object(self.ledger, "claim", racing),
            self.assertRaises(Exception),
        ):
            self.run_clear()
        self.assertEqual(
            self.ledger.outstanding("alice")[0]["state"], "cleanup_unknown"
        )

    def test_full_delete_fixture_uses_separate_admin_observer(self):
        fake = NativeFake()
        observer = OperatorObserver(fake)
        result = run_fixture(
            self.stage / "delete",
            "alice",
            "token",
            fake,
            QUERY,
            100,
            200,
            "delete",
            self.before["transport_hash"],
            observer=observer,
            admin_principal="operator",
            marker=self.marker,
        )
        self.assertTrue(result["operator_bound_cleanup_cleared"])
        self.assertTrue(result["exact_capture_converged"])
        self.assertFalse(result["authoritative_absence_unverified"])
        self.assertEqual(sum(method == "POST" for method, _ in fake.calls), 2)
        records = [
            json.loads(line)
            for line in (self.stage / "delete" / "events.jsonl")
            .read_text()
            .splitlines()
        ]
        converged = next(
            record for record in records if record["state"] == "convergence_verified"
        )
        self.assertEqual(converged["receipt_count"], 1)
        self.assertTrue(converged["admin_sid_404"])
        with closing(
            sqlite3.connect(self.stage / "delete" / "capture_jobs.sqlite")
        ) as db:
            self.assertEqual(
                db.execute("SELECT state FROM jobs ORDER BY seq LIMIT 1").fetchone()[0],
                "deleted",
            )
            self.assertEqual(
                db.execute(
                    "SELECT count(*) FROM jobs WHERE state != 'deleted'"
                ).fetchone()[0],
                2,
            )


class RetainedMetadataTests(unittest.TestCase):
    def setUp(self):
        self.principal = "alice"
        self.record = {
            "server_sid": "server.1",
            "query_hash": hashlib.sha256(QUERY.encode()).hexdigest(),
            "window_start": 100,
            "window_end": 200,
        }
        self.proof = {
            "entry": [
                {
                    "acl": {"owner": "alice", "app": "splunk_adm"},
                    "content": {
                        "sid": "server.1",
                        "search": QUERY,
                        "dispatchState": "PARSING",
                        "isDone": False,
                        "request": {
                            "id": None,
                            "search": QUERY,
                            "earliest_time": "100",
                            "latest_time": "200",
                        },
                    },
                }
            ]
        }

    def event(self, proof):
        return {"observer": "caller", "response_sha256": "a" * 64, "proof": proof}

    def test_initial_parsing_missing_search_then_full_proof_is_retained(self):
        import copy

        initial = copy.deepcopy(self.proof)
        initial["entry"][0]["content"]["search"] = None
        original = copy.deepcopy(initial)
        result = module.verify_retained_metadata(
            [self.event(initial), self.event(self.proof)], self.principal, self.record
        )
        self.assertEqual(result, {"partial": 1, "full": 1})
        self.assertEqual(initial, original)

    def test_missing_full_and_other_incomplete_states_fail(self):
        import copy

        initial = copy.deepcopy(self.proof)
        initial["entry"][0]["content"]["search"] = None
        for events in (
            [self.event(initial)],
            [self.event(self.proof), self.event(initial)],
        ):
            with (
                self.subTest(events=events),
                self.assertRaises((AssertionError, RuntimeError)),
            ):
                module.verify_retained_metadata(events, self.principal, self.record)
        initial["entry"][0]["content"]["dispatchState"] = "RUNNING"
        with self.assertRaises(RuntimeError):
            module.verify_retained_metadata(
                [self.event(initial), self.event(self.proof)],
                self.principal,
                self.record,
            )

    def test_populated_identity_contradictions_fail(self):
        import copy

        changes = (
            ("owner", "other"),
            ("app", "search"),
            ("sid", "server.2"),
            ("query", QUERY + " | head 1"),
            ("start", "101"),
            ("end", "201"),
            ("request_id", "unexpected"),
        )
        for field, value in changes:
            with self.subTest(field=field):
                initial = copy.deepcopy(self.proof)
                entry = initial["entry"][0]
                content = entry["content"]
                content["search"] = None
                if field in {"owner", "app"}:
                    entry["acl"][field] = value
                elif field == "sid":
                    content["sid"] = value
                else:
                    key = {
                        "query": "search",
                        "start": "earliest_time",
                        "end": "latest_time",
                        "request_id": "id",
                    }[field]
                    content["request"][key] = value
                with self.assertRaises(RuntimeError):
                    module.verify_retained_metadata(
                        [self.event(initial), self.event(self.proof)],
                        self.principal,
                        self.record,
                    )

    def test_completed_but_contradictory_observation_fails(self):
        import copy

        bad = copy.deepcopy(self.proof)
        bad["entry"][0]["content"]["search"] = "different"
        with self.assertRaises(RuntimeError):
            module.verify_retained_metadata(
                [self.event(bad), self.event(self.proof)], self.principal, self.record
            )


if __name__ == "__main__":
    unittest.main()
