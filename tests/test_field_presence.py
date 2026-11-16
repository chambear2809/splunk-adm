import json
import unittest
from unittest import mock

from tools import discover_field_presence as probe
from tools.discover_feature_sources import Refused


class Client:
    def __init__(self, family="hubble", failure=False):
        self.calls = []
        self.family = family
        self.failure = failure

    def call(self, method, path, data=None, timeout=10):
        self.calls.append((method, path, data, timeout))
        if method == "POST":
            return {"sid": "safe.123"}
        if method == "DELETE":
            if self.failure:
                raise Refused("http_500")
            return {}
        if "/results?" in path:
            fields = {
                f"{name}_{kind}": "1"
                for name in probe.SPECS[self.family][2]
                for kind in ("present", "numeric", "string")
            }
            if self.family == "pods":
                fields["ready_type_found"] = "1"
            return {"preview": False, "results": [{"sample_count": "2", **fields}]}
        return {
            "entry": [
                {"content": {"dispatchState": "DONE", "isDone": True, "resultCount": 1}}
            ]
        }


class FieldPresenceTests(unittest.TestCase):
    def test_both_queries_project_only_fixed_presence_counts(self):
        for family in probe.SPECS:
            with self.subTest(family=family):
                client = Client(family)
                result = probe.probe(client, family, "safe_idx", 100000)
                self.assertEqual(result["status"], "ok")
                self.assertEqual(result["cleanup"], "ok")
                self.assertEqual(result["counts"]["sample_count"], 2)
                data = client.calls[0][2]
                self.assertIn("| head 16 | eval ", data["search"])
                self.assertIn(" | stats count AS sample_count ", data["search"])
                self.assertEqual(
                    (data["earliest_time"], data["latest_time"]), ("99100", "100000")
                )
                self.assertEqual(
                    (data["max_time"], data["ttl"], data["auto_cancel"]),
                    ("20", "60", "30"),
                )
                self.assertLessEqual(client.calls[0][3], 35)
                self.assertEqual(client.calls[-1][0], "DELETE")
                self.assertNotIn("safe_idx", json.dumps(result))

    def test_invalid_or_unexpected_result_never_prints_values_and_cleans(self):
        client = Client()
        original = client.call

        def call(method, path, data=None, timeout=10):
            if "/results?" in path:
                return {
                    "preview": False,
                    "results": [{"sample_count": "PRIVATE_VALUE"}],
                }
            return original(method, path, data, timeout)

        client.call = call
        result = probe.probe(client, "hubble", "safe_idx", 100000)
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["cleanup"], "ok")
        self.assertNotIn("PRIVATE_VALUE", json.dumps(result))

    def test_cleanup_failure_and_query_injection_fail_closed(self):
        self.assertEqual(
            probe.probe(Client(failure=True), "pods", "safe_idx", 100000)["cleanup"],
            "failed",
        )
        with self.assertRaises(Refused):
            probe.query_for("pods", 'x" | delete')
        with mock.patch.object(probe.signal, "getitimer", return_value=(1, 0)):
            with self.assertRaises(Refused):
                probe.probe(Client(), "pods", "safe_idx", 100000)
