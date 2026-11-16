"""Synthetic native-job lifecycle tests; no live Splunk access."""

import copy
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(
    0, str(Path(__file__).resolve().parents[1] / "splunk_app/splunk_adm/bin")
)
from adm_cases_lib import native  # noqa: E402

QUERY = '| admqualified mode=graph service="checkout" environment="lab" cluster="cluster-a" namespace="shop" start=100 as_of=200'


class Fake:
    def __init__(self):
        self.calls = []
        self.time = 0
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
            return {"sid": "job-1"}
        if method == "DELETE":
            if self.fail_cleanup:
                raise ValueError("private exception")
            return {}
        if "/results?" in path:
            return copy.deepcopy(self.results)
        return {"entry": [{"content": copy.deepcopy(self.status)}]}

    def runner(self):
        return native.NativeComparisonSearch(
            "token", request=self.request, clock=self.clock, sleep=self.sleep
        )


class NativeTests(unittest.TestCase):
    def setUp(self):
        self.fake = Fake()
        self.runner = self.fake.runner()

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
        self.assertEqual([call[0] for call in self.fake.calls], ["POST", "DELETE"])
        self.assertEqual(self.fake.calls[-1][1], "/services/search/v2/jobs/job-1")
        self.assertEqual({}, self.runner.memo)

    def test_complete_cleanup_then_memo_is_per_caller_and_request(self):
        self.assertEqual(self.run_query(), [{"row_type": "meta"}])
        self.assertEqual(
            [c[0] for c in self.fake.calls], ["POST", "GET", "GET", "DELETE"]
        )
        data = self.fake.calls[0][2]
        self.assertEqual(
            (data["max_time"], data["auto_cancel"], data["ttl"]), ("5", "10", "30")
        )
        self.assertIn("count=2000", self.fake.calls[2][1])
        self.run_query()
        self.assertEqual(len(self.fake.calls), 4)
        with self.assertRaises(native.CaptureUnavailable):
            self.run_query(principal="bob")
        another = self.fake.runner()
        another.run("alice", QUERY, 100, 200)
        self.assertEqual(len(self.fake.calls), 8)
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

    def test_transport_body_checked_after_sdk_read(self):
        fake_rest = mock.Mock()
        fake_rest.simpleRequest.return_value = (
            mock.Mock(status=200),
            "é" * (1024 * 1024 + 1),
        )
        fake_splunk = mock.Mock(rest=fake_rest)
        with mock.patch.dict(
            sys.modules, {"splunk": fake_splunk, "splunk.rest": fake_rest}
        ):
            with self.assertRaises(native.CaptureUnavailable):
                self.runner._request("GET", "/services/search/v2/jobs/x", None, 2)
