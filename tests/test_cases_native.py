"""Synthetic native-job lifecycle tests; no live Splunk access."""

import copy
from contextlib import closing
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(
    0, str(Path(__file__).resolve().parents[1] / "splunk_app/splunk_adm/bin")
)
from adm_cases_lib import native  # noqa: E402
from adm_cases_lib.job_ledger import JobLedger  # noqa: E402

QUERY = '| admqualified mode=graph service="checkout" environment="lab" cluster="cluster-a" namespace="shop" start=100 as_of=200'


class Fake:
    temps = []

    def __init__(self):
        self.calls = []
        self.temp = tempfile.TemporaryDirectory()
        self.temps.append(self.temp)
        self.ledger = JobLedger(
            Path(self.temp.name) / "capture_jobs.sqlite", clock=lambda: self.time
        )
        self.time = 0
        self.job = None
        self.server_sid = None
        self.status = {
            "dispatchState": "DONE",
            "isDone": True,
            "isFinalized": False,
            "eventIsTruncated": False,
            "resultIsTruncated": False,
            "dropCount": 0,
            "resultCount": 1,
        }
        self.results = {"preview": False, "results": [{"row_type": "meta"}]}
        self.fail_cleanup = False

    def clock(self):
        return self.time

    def sleep(self, seconds):
        self.time += seconds

    def request(self, method, path, data, timeout):
        self.calls.append((method, path, data, timeout))
        if method == "POST":
            self.job = dict(data)
            self.server_sid = "server_" + str(len(self.calls))
            return {"sid": self.server_sid}
        if method == "DELETE":
            if self.fail_cleanup:
                raise ValueError("private exception")
            return {}
        if "/results?" in path:
            return copy.deepcopy(self.results)
        info = copy.deepcopy(self.status)
        info.update(
            {
                "sid": self.server_sid,
                "request": dict(self.job),
                "search": self.job["search"],
            }
        )
        return {
            "entry": [
                {
                    "name": "not-the-sid",
                    "acl": {"owner": "alice", "app": "splunk_adm"},
                    "content": info,
                }
            ]
        }

    def runner(self):
        return native.NativeComparisonSearch(
            "token",
            request=self.request,
            ledger=self.ledger,
            transport_hash="f" * 64,
            clock=self.clock,
            sleep=self.sleep,
        )


class NativeTests(unittest.TestCase):
    def setUp(self):
        self.fake = Fake()
        self.runner = self.fake.runner()

    def tearDown(self):
        for directory in Fake.temps:
            directory.cleanup()
        Fake.temps.clear()

    def run_query(self, principal="alice", query=QUERY, start=100, end=200):
        return self.runner.run(principal, query, start, end)

    def test_late_creation_retains_sid_for_cleanup_without_memo(self):
        original = self.fake.request

        def late(method, path, data, timeout):
            result = original(method, path, data, timeout)
            if method == "POST":
                self.fake.time = 25
            return result

        self.runner.request = late
        with self.assertRaises(native.CaptureUnavailable):
            self.run_query()
        self.assertEqual(
            [call[0] for call in self.fake.calls], ["POST", "GET", "DELETE"]
        )
        self.assertEqual(
            self.fake.calls[-1][1], "/services/search/jobs/" + self.fake.server_sid
        )
        self.assertEqual({}, self.runner.memo)

    def test_complete_cleanup_then_memo_is_per_caller_and_request(self):
        self.assertEqual(self.run_query(), [{"row_type": "meta"}])
        self.assertEqual(
            [c[0] for c in self.fake.calls], ["POST", "GET", "GET", "GET", "DELETE"]
        )
        data = self.fake.calls[0][2]
        self.assertEqual(
            (data["max_time"], data["auto_cancel"], data["ttl"]), ("5", "10", "30")
        )
        self.assertIn("count=2000", self.fake.calls[2][1])
        self.run_query()
        self.assertEqual(len(self.fake.calls), 5)
        with self.assertRaises(native.CaptureUnavailable):
            self.run_query(principal="bob")
        another = self.fake.runner()
        another.run("alice", QUERY, 100, 200)
        self.assertEqual(len(self.fake.calls), 10)
        self.fake.time = 26
        with self.assertRaises(native.CaptureUnavailable):
            self.run_query()

    def test_only_exact_whitelisted_query_and_window_are_accepted(self):
        bad = [
            QUERY + ' extra="foo"',
            QUERY + " | head 1",
            QUERY.replace('service="checkout"', 'service="x$foo$"'),
            QUERY.replace("start=100", "start=99"),
            QUERY.replace('namespace="shop"', 'namespace="UPPER"'),
            QUERY.replace("as_of=200", "as_of=201"),
            QUERY.replace('service="checkout"', 'service="x\\"bad"'),
        ]
        for query in bad:
            with (
                self.subTest(query=query),
                self.assertRaises(native.CaptureUnavailable),
            ):
                self.run_query(query=query)
        with self.assertRaises(native.CaptureUnavailable):
            self.run_query(start=True)
        self.assertEqual(self.fake.calls, [])

    def test_warnings_failed_finalized_truncated_and_preview_are_refused(self):
        for field, value in (
            ("messages", [{"type": "WARN"}]),
            ("isFinalized", True),
            ("eventIsTruncated", True),
            ("isFailed", True),
            ("dispatchState", "FINALIZED"),
            ("dropCount", 1),
            ("resultCount", 2001),
        ):
            with self.subTest(field=field):
                fake = Fake()
                fake.status[field] = value
                with self.assertRaises(native.CaptureUnavailable):
                    fake.runner().run("alice", QUERY, 100, 200)
                self.assertEqual(fake.calls[-1][0], "DELETE")
        self.fake.results["preview"] = True
        with self.assertRaises(native.CaptureUnavailable):
            self.run_query()
        self.assertEqual(self.fake.calls[-1][0], "DELETE")

    def test_oversize_timeout_and_cleanup_failure_never_memoize(self):
        self.fake.results["results"] = [
            {"row_type": "meta", "value": "x" * (512 * 1024)}
        ]
        with self.assertRaises(native.CaptureUnavailable):
            self.run_query()
        self.assertEqual(self.fake.calls[-1][0], "DELETE")
        self.assertFalse(self.runner.memo)
        fake = Fake()
        fake.status.update(dispatchState="RUNNING", isDone=False)
        with self.assertRaises(native.CaptureUnavailable):
            fake.runner().run("alice", QUERY, 100, 200)
        self.assertEqual(fake.calls[-1][0], "DELETE")
        fake = Fake()
        fake.fail_cleanup = True
        runner = fake.runner()
        with self.assertRaises(native.CaptureUnavailable):
            runner.run("alice", QUERY, 100, 200)
        self.assertFalse(runner.memo)

    def test_concurrency_and_job_budget_fail_closed(self):
        self.assertTrue(native._slots.acquire(blocking=False))
        try:
            with self.assertRaises(native.CaptureUnavailable):
                self.run_query()
        finally:
            native._slots.release()
        self.runner.jobs = 3
        with self.assertRaises(native.CaptureUnavailable):
            self.run_query()
        self.assertFalse(self.fake.calls)

    def test_no_fourth_distinct_job_and_returned_data_are_independent(self):
        rows = self.run_query()
        rows[0]["row_type"] = "tampered"
        self.assertEqual(self.run_query()[0]["row_type"], "meta")
        for start in (200, 300):
            query = QUERY.replace("start=100", f"start={start}").replace(
                "as_of=200", f"as_of={start + 100}"
            )
            self.run_query(query=query, start=start, end=start + 100)
        query = QUERY.replace("start=100", "start=400").replace(
            "as_of=200", "as_of=500"
        )
        with self.assertRaises(native.CaptureUnavailable):
            self.run_query(query=query, start=400, end=500)
        self.assertEqual(sum(call[0] == "POST" for call in self.fake.calls), 3)

    def test_lost_creation_response_is_never_guessed_or_retried(self):
        original = self.fake.request

        def delayed(method, path, data, timeout):
            if method == "POST":
                original(method, path, data, timeout)  # Server accepted; reply lost.
                raise TimeoutError()
            return original(method, path, data, timeout)

        self.runner.request = delayed
        with self.assertRaises(native.CaptureUnavailable):
            self.run_query()
        records = self.fake.ledger.outstanding("alice")
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["state"], "creation_unknown")
        self.assertIsNone(records[0]["server_sid"])
        self.assertNotIn("id", self.fake.job)
        self.assertEqual([call[0] for call in self.fake.calls], ["POST"])
        self.assertEqual(self.fake.ledger.outstanding("bob"), [])
        self.fake.time = 36
        reopened = JobLedger(
            Path(self.fake.temp.name) / "capture_jobs.sqlite", clock=self.fake.clock
        )
        retry = native.NativeComparisonSearch(
            "token",
            request=delayed,
            ledger=reopened,
            transport_hash="f" * 64,
            clock=self.fake.clock,
            sleep=self.fake.sleep,
        )
        with self.assertRaises(native.CaptureUnavailable):
            retry.run("alice", QUERY, 100, 200)
        self.assertEqual([call[0] for call in self.fake.calls], ["POST"])
        self.assertEqual(reopened.outstanding("alice")[0]["state"], "creation_unknown")

    def test_malformed_server_id_is_unknown_without_cleanup(self):
        original = self.fake.request

        def malformed(method, path, data, timeout):
            response = original(method, path, data, timeout)
            if method == "POST":
                return {"sid": "../../invalid"}
            return response

        self.runner.request = malformed
        with self.assertRaises(native.CaptureUnavailable):
            self.run_query()
        self.assertEqual([call[0] for call in self.fake.calls], ["POST"])
        record = self.fake.ledger.outstanding("alice")[0]
        self.assertEqual(record["state"], "creation_unknown")
        self.assertIsNone(record["server_sid"])

    def test_known_sid_cleanup_404_stays_unknown_until_same_caller_reconciles(self):
        original = self.fake.request
        fail = [True]

        def missing_on_cleanup(method, path, data, timeout):
            if (
                method == "GET"
                and "/results?" not in path
                and self.fake.calls
                and self.fake.calls[-1][1].find("/results?") >= 0
                and fail[0]
            ):
                self.fake.calls.append((method, path, data, timeout))
                fail[0] = False
                raise FileNotFoundError()
            return original(method, path, data, timeout)

        self.runner.request = missing_on_cleanup
        with self.assertRaises(native.CaptureUnavailable):
            self.run_query()
        record = self.fake.ledger.outstanding("alice")[0]
        self.assertEqual(record["state"], "cleanup_unknown")
        self.assertEqual(record["server_sid"], self.fake.server_sid)
        self.assertNotIn("DELETE", [call[0] for call in self.fake.calls])
        retry = self.fake.runner()
        self.assertEqual(retry.run("alice", QUERY, 100, 200), [{"row_type": "meta"}])
        self.assertEqual(self.fake.ledger.outstanding("alice"), [])

    def test_foreign_or_mismatched_ownership_never_deleted(self):
        for field in ("owner", "app", "content_sid", "request_id", "query", "window"):
            with self.subTest(field=field):
                fake = Fake()
                original = fake.request

                def mismatch(method, path, data, timeout):
                    result = original(method, path, data, timeout)
                    if method == "GET" and "/results?" not in path:
                        info = result["entry"][0]["content"]
                        if field == "owner":
                            result["entry"][0]["acl"]["owner"] = "bob"
                        elif field == "app":
                            result["entry"][0]["acl"]["app"] = "other"
                        elif field == "content_sid":
                            info["sid"] = "other"
                        elif field == "request_id":
                            info["request"]["id"] = "other"
                        elif field == "query":
                            info["request"]["search"] += " | head 1"
                        else:
                            info["request"]["earliest_time"] = "99"
                    return result

                runner = fake.runner()
                runner.request = mismatch
                with self.assertRaises(native.CaptureUnavailable):
                    runner.run("alice", QUERY, 100, 200)
                self.assertNotIn("DELETE", [call[0] for call in fake.calls])
                self.assertEqual(
                    fake.ledger.outstanding("alice")[0]["state"], "cleanup_unknown"
                )
                self.assertEqual(runner.memo, {})

    def test_fresh_two_window_cleanup_uses_primary_deadline_before_reserve(self):
        original = self.fake.request
        proof_phase = [False]

        def slow(method, path, data, timeout):
            response = original(method, path, data, timeout)
            if "/results?" in path:
                proof_phase[0] = True
            elif method == "GET" and proof_phase[0]:
                self.fake.time += 1.1
            elif method == "DELETE":
                self.fake.time += 0.5
                proof_phase[0] = False
            return response

        self.runner.request = slow
        self.run_query()
        query = QUERY.replace("start=100", "start=200").replace(
            "as_of=200", "as_of=300"
        )
        self.assertEqual(
            self.runner.run("alice", query, 200, 300), [{"row_type": "meta"}]
        )
        self.assertEqual(self.fake.ledger.outstanding("alice"), [])
        self.assertEqual(len(self.runner.memo), 2)

    def test_fresh_cleanup_crossing_deadline_is_limited_to_emergency_reserve(self):
        original = self.fake.request
        result_seen = [False]

        def late_delete(method, path, data, timeout):
            response = original(method, path, data, timeout)
            if "/results?" in path:
                result_seen[0] = True
                self.fake.time = 24
            elif method == "GET" and result_seen[0]:
                self.fake.time += 1.1
            elif method == "DELETE":
                self.fake.time += 3
            return response

        self.runner.request = late_delete
        with self.assertRaises(native.CaptureUnavailable):
            self.run_query()
        self.assertEqual(
            self.fake.ledger.outstanding("alice")[0]["state"], "cleanup_unknown"
        )
        self.assertEqual(self.runner.memo, {})

    def test_acknowledged_cleanup_after_deadline_still_withholds_rows(self):
        original = self.fake.request

        def slow(method, path, data, timeout):
            response = original(method, path, data, timeout)
            if "/results?" in path:
                self.fake.time = 24.5
            elif method == "DELETE":
                self.fake.time += 1
            return response

        self.runner.request = slow
        with self.assertRaises(native.CaptureUnavailable):
            self.run_query()
        self.assertEqual(self.fake.ledger.outstanding("alice"), [])
        self.assertEqual(self.runner.memo, {})

    def test_incomplete_search_cleanup_only_uses_the_reserve(self):
        original = self.fake.request
        self.fake.status["eventIsTruncated"] = True
        delete_timeouts = []

        def slow(method, path, data, timeout):
            response = original(method, path, data, timeout)
            if method == "GET":
                self.fake.time += 2
            elif method == "DELETE":
                delete_timeouts.append(timeout)
                self.fake.time += 1.1
            return response

        self.runner.request = slow
        with self.assertRaises(native.CaptureUnavailable):
            self.run_query()
        self.assertEqual(delete_timeouts, [1])
        self.assertEqual(
            self.fake.ledger.outstanding("alice")[0]["state"], "cleanup_unknown"
        )
        self.assertEqual(self.runner.memo, {})

    def test_executed_search_must_match_request_before_results_or_cleanup(self):
        original = self.fake.request

        def changed(method, path, data, timeout):
            result = original(method, path, data, timeout)
            if method == "GET" and "/results?" not in path:
                result["entry"][0]["content"]["search"] = "search index=other"
            return result

        self.runner.request = changed
        with self.assertRaises(native.CaptureUnavailable):
            self.run_query()
        self.assertFalse(any("/results?" in call[1] for call in self.fake.calls))
        self.assertNotIn("DELETE", [call[0] for call in self.fake.calls])
        self.assertEqual(
            self.fake.ledger.outstanding("alice")[0]["state"], "cleanup_unknown"
        )
        self.assertEqual(self.runner.memo, {})

    def test_incomplete_cleanup_proof_and_expired_lease_withhold_results(self):
        for mode in ("incomplete", "expired"):
            with self.subTest(mode=mode):
                fake = Fake()
                original = fake.request
                read_results = [False]

                def changed(method, path, data, timeout):
                    result = original(method, path, data, timeout)
                    if "/results?" in path:
                        read_results[0] = True
                        if mode == "expired":
                            fake.time = 36
                    elif method == "GET" and read_results[0] and mode == "incomplete":
                        content = result["entry"][0]["content"]
                        content["search"] = "search index=other"
                    return result

                runner = fake.runner()
                runner.request = changed
                with self.assertRaises(native.CaptureUnavailable):
                    runner.run("alice", QUERY, 100, 200)
                self.assertNotIn("DELETE", [call[0] for call in fake.calls])
                self.assertEqual(runner.memo, {})
                self.assertEqual(len(fake.ledger.outstanding("alice")), 1)

    def test_callbacks_run_outside_ledger_write_transactions(self):
        original = self.fake.request

        def check(method, path, data, timeout):
            with closing(sqlite3.connect(self.fake.ledger.path, timeout=0.1)) as db:
                db.execute("BEGIN IMMEDIATE")
                db.rollback()
            return original(method, path, data, timeout)

        self.runner.request = check
        self.assertEqual(self.run_query(), [{"row_type": "meta"}])

    def test_foreign_jobs_exhaust_global_budget_without_disclosure(self):
        for index in range(3):
            self.fake.ledger.reserve(
                "other",
                "adm-capture-" + str(index) * 32,
                "a" * 64,
                100,
                200,
                "a" * 32,
                transport_hash="f" * 64,
            )
        with self.assertRaises(native.CaptureUnavailable):
            self.run_query()
        self.assertEqual(self.fake.calls, [])
        self.assertEqual(self.fake.ledger.outstanding("alice"), [])

    def test_iso_window_proof_and_invalid_absolute_time(self):
        self.assertTrue(native._absolute("1970-01-01T00:01:40Z", 100))
        self.assertTrue(native._absolute("100.000", 100))
        self.assertFalse(native._absolute("1970-01-01T00:01:40", 100))
        self.assertFalse(native._absolute("100.001", 100))
        self.assertFalse(native._absolute("nan", 100))

    def test_changed_or_legacy_peer_blocks_before_claim_or_network(self):
        for stored in ("e" * 64, None):
            with self.subTest(stored=stored):
                fake = Fake()
                first = fake.ledger.reserve(
                    "alice",
                    "adm-capture-" + "1" * 32,
                    "a" * 64,
                    100,
                    200,
                    "a" * 32,
                    transport_hash="f" * 64,
                )
                second = fake.ledger.reserve(
                    "alice",
                    "adm-capture-" + "2" * 32,
                    "b" * 64,
                    100,
                    200,
                    "b" * 32,
                    transport_hash="f" * 64,
                )
                first = fake.ledger.bind_created(
                    "alice",
                    first["sid"],
                    "a" * 32,
                    "server_1",
                    expected_revision=first["revision"],
                )
                second = fake.ledger.bind_created(
                    "alice",
                    second["sid"],
                    "b" * 32,
                    "server_2",
                    expected_revision=second["revision"],
                )
                with closing(sqlite3.connect(fake.ledger.path)) as db:
                    db.execute(
                        "UPDATE jobs SET transport_hash=? WHERE sid=?",
                        (stored, second["sid"]),
                    )
                    db.commit()
                before = fake.ledger.outstanding("alice")
                runner = fake.runner()
                with self.assertRaises(native.CaptureUnavailable):
                    runner.run("alice", QUERY, 100, 200)
                self.assertEqual(fake.calls, [])
                self.assertEqual(fake.ledger.outstanding("alice"), before)
                self.assertEqual(before[0]["revision"], first["revision"])
                self.assertEqual(before[1]["transport_hash"], stored)

    def test_peer_binding_is_required_and_proof_fails_before_network(self):
        with self.assertRaises(native.CaptureUnavailable):
            native.NativeComparisonSearch(
                "token", request=self.fake.request, ledger=self.fake.ledger
            )
        with self.assertRaises(native.CaptureUnavailable):
            native.NativeComparisonSearch(
                "token",
                request=self.fake.request,
                ledger=self.fake.ledger,
                transport_hash="invalid",
            )
        with self.assertRaises(native.CaptureUnavailable):
            self.runner._proof("alice", {"sid": "unused", "transport_hash": None})
        self.assertEqual(self.fake.calls, [])

    def test_constructor_requires_requester_and_ledger(self):
        with self.assertRaises(native.CaptureUnavailable):
            native.NativeComparisonSearch("token")
        with self.assertRaises(native.CaptureUnavailable):
            native.NativeComparisonSearch("token", request=self.fake.request)
