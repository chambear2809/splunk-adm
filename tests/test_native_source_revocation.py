import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "splunk_app/splunk_adm/bin"))
from adm_cases_lib.store import CaseStore  # noqa: E402
import qualify_native_source_revocation as rev  # noqa: E402


class FixtureOps:
    def __init__(self, root):
        self.principal = "investigator"
        self.filter = rev.BASE_FILTER
        self.role_data = {
            "capabilities": ["search", "adm_investigate"],
            "imported_roles": [],
            "srchFilter": self.filter,
            "srchIndexesAllowed": ["atlas_identity", "otel_traces"],
            "srchIndexesDefault": [],
        }
        self.user = {
            "username": self.principal,
            "roles": ["dedicated"],
            "last_successful_login": 1,
            "capabilities": ["search", "adm_investigate"],
        }
        self.users = {self.principal}
        self.calls = []
        self.fail_narrow = False
        source = {"reference": "real-source-fixture"}
        data = {
            "scope": rev.SCOPE,
            "windows": [dict(w, rows=[]) for w in rev.WINDOWS],
            "evidence_digest": rev.EVIDENCE_HASH,
            "configuration_fingerprint": rev.FINGERPRINT,
            "source_contract": "admqualified-comparison-v1",
        }
        self.store = CaseStore(
            root / "cases.sqlite",
            lambda p, *_: p == self.principal,
            capture_resolver=lambda *_: {
                "captured_at": "2026-01-01T00:00:00Z",
                "data": data,
                "source": source,
            },
            source_entitlement=lambda *_: self.role_data["srchFilter"] == self.filter,
        )
        self.case_id = self.store.create(
            self.principal,
            "create",
            {
                "schema_version": 1,
                "title": "fixture",
                "window": {
                    "start": "2026-01-01T00:00:00Z",
                    "end": "2026-01-02T00:00:00Z",
                },
            },
        )["id"]
        self.store.append(
            self.principal,
            "note",
            self.case_id,
            1,
            "entry",
            {"type": "note", "text": "retained"},
        )
        self.body = {
            "expected_revision": 2,
            "reference": "real-source-fixture",
            "label": "fixture",
        }
        saved = self.store.append_capture(
            self.principal,
            "original-key",
            self.case_id,
            2,
            self.body["reference"],
            self.body["label"],
        )
        self.capture_id = saved["capture_ids"][0]
        self.original = "original-operation"
        self.events = [
            {
                "state": "dispatching",
                "action": "capture",
                "operation": self.original,
                "caller": self.principal,
                "method": "POST",
                "path": "/cases/" + self.case_id + "/captures",
                "key": "original-key",
                "body": json.dumps(self.body),
            },
            {"state": "response", "operation": self.original, "status": 200},
        ]

    def admin_principal(self):
        return "administrator"

    def user_context(self):
        return copy.deepcopy(self.user)

    def role(self, role):
        return copy.deepcopy(self.role_data)

    def members(self, role):
        return set(self.users)

    def profile_sha256(self):
        return rev.PROFILE_HASH

    def original_events(self):
        return copy.deepcopy(self.events)

    def set_filter(self, role, value):
        self.calls.append(value)
        self.role_data["srchFilter"] = value
        if self.fail_narrow and value != self.filter:
            raise TimeoutError("lost response")

    def case_action(self, action, case_id, capture_id, original):
        if action == "read":
            result = self.store.get(self.principal, case_id, capture_id=capture_id)
        elif action == "export":
            result = self.store.export(self.principal, case_id, capture_id=capture_id)
        else:
            result = self.store.append_capture(
                self.principal,
                "original-key",
                case_id,
                2,
                self.body["reference"],
                self.body["label"],
            )
        return {"status": 200, "operation": action, "result": result}


class RevocationFixtureTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.stage = self.root / "stage"
        self.stage.mkdir(mode=0o700)
        self.ops = FixtureOps(self.root)

    def exercise(self):
        return rev.run_exercise(
            self.ops,
            self.stage,
            self.ops.principal,
            "dedicated",
            self.ops.case_id,
            self.ops.capture_id,
            self.ops.original,
        )

    def test_changing_login_timestamp_preserves_revocation_flow(self):
        original_context = self.ops.user_context

        def changing_context():
            self.ops.user["last_successful_login"] += 1
            return original_context()

        self.ops.user_context = changing_context
        result = self.exercise()
        self.assertEqual(result["status"], "passed_fixture_checks")
        events = [
            json.loads(line)
            for line in (self.stage / "operations.jsonl").read_text().splitlines()
        ]
        comparisons = [
            event for event in events if event.get("state") == "context_comparison"
        ]
        self.assertTrue(comparisons)
        self.assertTrue(
            all(
                event["equal"]
                and event["excluded_field"] == "last_successful_login"
                and type(event["before"]["last_successful_login"]) is int
                and type(event["after"]["last_successful_login"]) is int
                for event in comparisons
            )
        )

    def test_actual_store_redaction_and_exact_original_retry(self):
        result = self.exercise()
        self.assertEqual(result["status"], "passed_fixture_checks")
        self.assertEqual(set(result["phase"]), {"allowed", "revoked", "restored"})
        self.assertEqual(self.ops.role_data["srchFilter"], self.ops.filter)
        self.assertEqual(
            self.ops.calls, [rev.scoped_filter(self.ops.filter), self.ops.filter]
        )

    def test_lost_change_ack_still_restores_but_never_passes(self):
        self.ops.fail_narrow = True
        result = self.exercise()
        self.assertEqual(result["status"], "failed_or_uncertain")
        self.assertTrue(result["restoration"]["verified"])
        self.assertEqual(self.ops.role_data["srchFilter"], self.ops.filter)

    def test_shared_role_or_privileged_caller_never_mutates(self):
        for change in ("shared", "admin", "imported"):
            with self.subTest(change=change):
                original = copy.deepcopy(self.ops.role_data)
                if change == "shared":
                    self.ops.users.add("other")
                elif change == "admin":
                    self.ops.user["capabilities"].append("admin_all_objects")
                else:
                    self.ops.role_data["imported_roles"] = ["admin"]
                with self.assertRaises(ValueError):
                    self.exercise()
                self.assertEqual(self.ops.calls, [])
                self.ops.users = {self.ops.principal}
                self.ops.user["capabilities"] = ["search", "adm_investigate"]
                self.ops.role_data = original

    def test_unrelated_concurrent_role_change_blocks_blind_restore(self):
        original = self.ops.set_filter

        def change(role, value):
            original(role, value)
            if value != self.ops.filter:
                self.ops.role_data["srchIndexesAllowed"] = ["changed"]
                raise TimeoutError()

        self.ops.set_filter = change
        result = self.exercise()
        self.assertEqual(result["status"], "failed_or_uncertain")
        self.assertFalse(result["restoration"]["verified"])
        self.assertEqual(len(self.ops.calls), 1)

    def test_wrong_original_identity_or_stale_profile_refused(self):
        self.ops.events[0]["caller"] = "other"
        with self.assertRaises(ValueError):
            self.exercise()
        self.ops.events[0]["caller"] = self.ops.principal
        self.ops.profile_sha256 = lambda: "0" * 64
        with self.assertRaises(ValueError):
            self.exercise()
        self.assertEqual(self.ops.calls, [])

    def test_preexisting_revocation_journal_refuses_reuse(self):
        (self.stage / "operations.jsonl").write_text("uncertain prior state")
        with self.assertRaises(ValueError):
            self.exercise()
        self.assertEqual(self.ops.calls, [])

    def test_restore_attempts_even_if_restore_journal_fails(self):
        original_journal = rev.journal_append

        def broken(directory, event):
            if event.get("state") == "restore_intent":
                raise OSError("journal unavailable")
            return original_journal(directory, event)

        with mock.patch.object(rev, "journal_append", broken):
            result = self.exercise()
        self.assertTrue(result["restoration"]["verified"])
        self.assertFalse(result["restoration"]["journal_ok"])
        self.assertEqual(result["status"], "failed_or_uncertain")
        self.assertEqual(self.ops.role_data["srchFilter"], self.ops.filter)

    def test_note_change_prevents_revocation_pass(self):
        original = self.ops.case_action

        def changed(action, *args):
            value = original(action, *args)
            if self.ops.role_data["srchFilter"] != self.ops.filter:
                value["result"]["entries"][0]["text"] = "unexpected"
            return value

        self.ops.case_action = changed
        result = self.exercise()
        self.assertEqual(result["status"], "failed_or_uncertain")
        self.assertTrue(result["restoration"]["verified"])

    def test_fixed_admin_adapter_rejects_other_routes_and_role_changes(self):
        transport = mock.Mock()
        adapter = rev.FixedAdminTransport(transport, "token", "dedicated")
        for method, path, data in [
            ("POST", "/services/authorization/roles/other", {"srchFilter": "x"}),
            (
                "POST",
                "/services/authorization/roles/dedicated",
                {"capabilities": "admin"},
            ),
            ("DELETE", "/services/authorization/roles/dedicated", None),
            ("GET", "/services/authentication/users?count=999", None),
        ]:
            with self.subTest(path=path), self.assertRaises(ValueError):
                adapter(method, path, data, 3)
        transport.assert_not_called()


class AdminTransportContractTests(unittest.TestCase):
    def test_actual_supervised_worker_rejects_role_mutation(self):
        from adm_cases_lib import transport_worker

        request = {
            "token": "token",
            "origin": "https://127.0.0.1:8089",
            "ca_length": 1,
            "method": "POST",
            "path": "/services/authorization/roles/dedicated",
            "data": {"srchFilter": "x"},
            "timeout": 3,
        }
        with mock.patch.object(
            transport_worker.http.client, "HTTPSConnection"
        ) as connection:
            with self.assertRaises(ValueError):
                transport_worker.request(request, b"x")
            connection.assert_not_called()

    def test_bounded_adapter_uses_exact_role_and_rejects_redirect(self):
        transport = mock.Mock()
        transport.ca_bytes = b"ca"
        adapter = rev.FixedAdminTransport(transport, "private-token", "dedicated")
        sock = mock.Mock()
        context = mock.Mock()
        context.wrap_socket.return_value = sock
        response = mock.Mock()
        response.status = 200
        response.read1.side_effect = [b'{"entry":[]}', b""]
        with (
            mock.patch("adm_cases_lib.transport._read_ca", return_value=b"ca"),
            mock.patch.object(rev.ssl, "create_default_context", return_value=context),
            mock.patch.object(rev.socket, "create_connection", return_value=sock),
            mock.patch.object(rev.http.client, "HTTPResponse", return_value=response),
        ):
            self.assertEqual(
                adapter(
                    "POST",
                    "/services/authorization/roles/dedicated",
                    {"srchFilter": "NOT source=example"},
                    3,
                ),
                {"entry": []},
            )
            context.wrap_socket.assert_called_once_with(
                sock, server_hostname="127.0.0.1", do_handshake_on_connect=False
            )
            sent = sock.sendall.call_args.args[0]
            self.assertIn(
                b"POST /services/authorization/roles/dedicated?output_mode=json HTTP/1.1",
                sent,
            )
            self.assertIn(b"srchFilter=NOT+source%3Dexample", sent)
            response.status = 302
            with self.assertRaises(ValueError):
                adapter("GET", "/services/authorization/roles/dedicated", None, 3)


if __name__ == "__main__":
    unittest.main()


class CountObservationTests(unittest.TestCase):
    def setUp(self):
        self.query = 'search index="atlas_identity" | stats count'
        self.start, self.end = 1794844500, 1794844620
        self.data = {
            "preview": False,
            "results": [{"count": "336"}],
            "messages": [{"type": "INFO", "text": rev.COUNT_INFO}],
        }
        self.job = {
            "entry": [
                {
                    "acl": {"owner": "investigator", "app": "splunk_adm"},
                    "content": {
                        "sid": "abc.123",
                        "dispatchState": "DONE",
                        "isDone": True,
                        "isFailed": False,
                        "isFinalized": False,
                        "eventIsTruncated": False,
                        "resultIsTruncated": False,
                        "dropCount": 0,
                        "resultCount": 1,
                        "search": self.query,
                        "earliestTime": str(self.start),
                        "latestTime": str(self.end),
                        "request": {
                            "search": self.query,
                            "earliest_time": str(self.start),
                            "latest_time": str(self.end),
                        },
                    },
                }
            ]
        }

    def validate(self, *, task=True):
        return rev.validate_count_observation(
            self.data,
            self.job,
            "investigator",
            "abc.123",
            self.query,
            self.start,
            self.end,
            task_role=task,
        )

    def test_exact_info_and_window(self):
        result = self.validate()
        self.assertEqual(result["count"], 336)
        self.assertEqual(result["message_sha256"], rev.COUNT_INFO_SHA256)

    def test_unexpected_message_rejected(self):
        for message in (
            {"type": "WARN", "text": rev.COUNT_INFO},
            {"type": "INFO", "text": "different"},
            {"type": "ERROR", "text": rev.COUNT_INFO},
        ):
            self.data["messages"] = [message]
            with self.assertRaises(ValueError):
                self.validate()

    def test_known_info_in_each_native_location_and_replay(self):
        info = {"type": "INFO", "text": rev.COUNT_INFO}
        for location in ("job", "job_content", "results"):
            with self.subTest(location=location):
                self.data["messages"] = []
                self.job.pop("messages", None)
                self.job["entry"][0]["content"].pop("messages", None)
                if location == "job":
                    self.job["messages"] = [info]
                elif location == "job_content":
                    self.job["entry"][0]["content"]["messages"] = [info]
                else:
                    self.data["messages"] = [info]
                result = self.validate()
                self.assertEqual(result["message_locations"], [location])
                replay = rev.validate_count_observation(
                    self.data,
                    result["native_job"],
                    "investigator",
                    "abc.123",
                    self.query,
                    self.start,
                    self.end,
                    task_role=True,
                )
                self.assertEqual(result, replay)

    def test_unknown_and_malformed_message_each_location(self):
        for location in ("job", "job_content", "results"):
            for messages in (
                [{"type": "WARN", "text": rev.COUNT_INFO}],
                [{"type": "INFO", "text": "unknown"}],
                [{"type": "INFO", "text": rev.COUNT_INFO, "other": "unexpected"}],
                {},
                [None],
                [1, 2],
            ):
                with self.subTest(location=location, messages=messages):
                    self.data["messages"] = []
                    self.job.pop("messages", None)
                    self.job["entry"][0]["content"].pop("messages", None)
                    if location == "job":
                        self.job["messages"] = messages
                    elif location == "job_content":
                        self.job["entry"][0]["content"]["messages"] = messages
                    else:
                        self.data["messages"] = messages
                    with self.assertRaises(ValueError):
                        self.validate()

    def test_known_info_does_not_mask_incomplete_or_wrong_window(self):
        self.job["entry"][0]["content"]["messages"] = [
            {"type": "INFO", "text": rev.COUNT_INFO}
        ]
        content = self.job["entry"][0]["content"]
        for key, invalid in (
            ("isDone", False),
            ("isFinalized", True),
            ("eventIsTruncated", True),
            ("dropCount", 1),
            ("earliestTime", "1794844499"),
            ("resultCount", 2),
        ):
            with self.subTest(key=key):
                old = content[key]
                content[key] = invalid
                with self.assertRaises(Exception):
                    self.validate()
                content[key] = old

    def test_effective_window_mismatch_and_missing_fail(self):
        for value in ("1794844499", None):
            self.job["entry"][0]["content"]["earliestTime"] = value
            with self.assertRaises(ValueError):
                self.validate()

    def test_conflicting_sid_and_bad_count_fail(self):
        self.job["entry"][0]["sid"] = "other"
        with self.assertRaises(ValueError):
            self.validate()
        del self.job["entry"][0]["sid"]
        self.data["results"] = [{"count": "not-count"}]
        with self.assertRaises(ValueError):
            self.validate()

    def test_broader_task_window_requires_role_intersection(self):
        self.start -= 3600
        self.end += 3600
        content = self.job["entry"][0]["content"]
        content["request"]["earliest_time"] = str(self.start)
        content["request"]["latest_time"] = str(self.end)
        content["searchEarliestTime"] = self.start
        content["searchLatestTime"] = self.end
        self.assertEqual(self.validate()["count"], 336)
        with self.assertRaises(ValueError):
            self.validate(task=False)

    def test_incomplete_job_never_allows_info(self):
        for key, value in (
            ("isFinalized", True),
            ("eventIsTruncated", True),
            ("resultIsTruncated", True),
            ("dropCount", 1),
            ("messages", [{"type": "WARN"}]),
            ("resultCount", 2),
        ):
            with self.subTest(key=key):
                original = self.job["entry"][0]["content"].get(key)
                self.job["entry"][0]["content"][key] = value
                with self.assertRaises(ValueError):
                    self.validate()
                self.job["entry"][0]["content"][key] = original

    def test_retained_metadata_replays_without_optional_truncation_field(self):
        del self.job["entry"][0]["content"]["resultIsTruncated"]
        observation = self.validate()
        replay = rev.validate_count_observation(
            self.data,
            observation["native_job"],
            "investigator",
            "abc.123",
            self.query,
            self.start,
            self.end,
            task_role=True,
        )
        self.assertEqual(replay, observation)


class ContextComparisonTests(unittest.TestCase):
    def setUp(self):
        self.before = {
            "username": "investigator",
            "roles": ["dedicated"],
            "capabilities": ["search", "adm_investigate"],
            "last_successful_login": 10,
            "security_metadata": {"realm": "local"},
        }

    def test_login_timestamp_changes_are_allowed(self):
        after = copy.deepcopy(self.before)
        after["last_successful_login"] = 11
        self.assertTrue(rev.same_user_context(self.before, after))

    def test_identity_role_capability_and_security_changes_fail(self):
        for key, value in (
            ("username", "other"),
            ("roles", ["admin"]),
            ("capabilities", ["search"]),
            ("security_metadata", {"realm": "other"}),
        ):
            after = copy.deepcopy(self.before)
            after[key] = value
            self.assertFalse(rev.same_user_context(self.before, after))

    def test_timestamp_missing_boolean_negative_or_wrong_type_fails(self):
        for value in (None, True, -1, "11"):
            after = copy.deepcopy(self.before)
            if value is None:
                del after["last_successful_login"]
            else:
                after["last_successful_login"] = value
            self.assertFalse(rev.same_user_context(self.before, after))
