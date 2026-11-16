"""Synthetic qualified graph response fixtures; no live data is used."""

import copy
import datetime as dt
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(
    0, str(Path(__file__).resolve().parents[1] / "splunk_app/splunk_adm/bin")
)
from adm_cases_lib.source import ComparisonSource, SourceError  # noqa: E402


SCOPE = {
    "service": "checkout",
    "environment": "lab",
    "cluster": "cluster-a",
    "namespace": "shop",
}
WINDOWS = [{"start": 100, "end": 200}, {"start": 200, "end": 300}]
NOW = dt.datetime.fromtimestamp(400, dt.timezone.utc)


def reference(scope=None, windows=None):
    return json.dumps(
        {
            "schema": 1,
            "scope": SCOPE if scope is None else scope,
            "windows": WINDOWS if windows is None else windows,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def graph(start, end):
    return [
        {
            "row_type": "node",
            "id": "service:cluster-a/shop/checkout/lab",
            "label": "checkout",
            "kind": "service",
            "cluster": "cluster-a",
            "namespace": "shop",
            "attr_environment": "lab",
        },
        {
            "row_type": "meta",
            "window_start": str(start),
            "window_end": str(end),
            "generated_at": str(end),
            "warnings": ["partial synthetic"],
        },
    ]


class Tests(unittest.TestCase):
    def setUp(self):
        self.calls = []
        self.rows = graph
        self.config = "config-1"

        def run(principal, query, start, end):
            self.calls.append((principal, query, start, end))
            return self.rows(start, end)

        self.source = ComparisonSource(run, lambda: self.config, lambda: NOW)

    def test_fixed_query_capture_and_recheck_as_caller(self):
        result = self.source.resolve("alice", reference())
        self.assertEqual(
            result["data"]["configuration_fingerprint"], result["source"]["fingerprint"]
        )
        self.assertEqual(
            result["data"]["evidence_digest"], result["source"]["rows_digest"]
        )
        self.assertEqual(
            self.calls[0][1],
            '| admqualified mode=graph service="checkout" environment="lab" cluster="cluster-a" namespace="shop" start=100 as_of=200',
        )
        self.assertEqual(
            result["data"]["windows"][0]["rows"][1]["warnings"], ["partial synthetic"]
        )
        self.assertTrue(self.source.entitled("bob", "capture", result))
        self.assertEqual(
            [call[0] for call in self.calls], ["alice", "alice", "bob", "bob"]
        )
        self.config = "config-2"
        self.assertFalse(self.source.entitled("bob", "capture", result))

    def test_generated_time_only_is_ignored_and_original_retained(self):
        result = self.source.resolve("alice", reference())

        def later(start, end):
            rows = graph(start, end)
            rows[-1]["generated_at"] = "999"
            return list(reversed(rows))

        self.rows = later
        self.assertTrue(self.source.entitled("bob", "capture", result))
        self.assertEqual(
            result["data"]["windows"][0]["rows"][-1]["generated_at"], "200"
        )

        def changed(start, end):
            rows = graph(start, end)
            rows[-1]["warnings"].append("another partial condition")
            return rows

        self.rows = changed
        self.assertFalse(self.source.entitled("bob", "capture", result))

    def test_tampering_or_revoked_source_fails_closed(self):
        result = self.source.resolve("alice", reference())
        tampered = copy.deepcopy(result)
        tampered["data"]["windows"][0]["rows"][-1]["warnings"] = []
        self.assertFalse(self.source.entitled("bob", "capture", tampered))

        def denied(_start, _end):
            raise PermissionError()

        self.rows = denied
        self.assertFalse(self.source.entitled("bob", "capture", result))
        self.assertFalse(self.source.entitled("bob", "attachment", result))

    def test_reference_validation_and_injection(self):
        cases = [
            reference(scope={**SCOPE, "service": 'x" | delete'}),
            reference(windows=[{"start": 0, "end": 301}, {"start": 301, "end": 302}]),
            reference(windows=[{"start": 0, "end": 100}, {"start": 99, "end": 200}]),
            reference(windows=[{"start": 0, "end": 100}, {"start": 100, "end": 500}]),
            reference() + " ",
            '{"schema":1,"schema":1}',
        ]
        for bad in cases:
            with self.subTest():
                with self.assertRaises(SourceError):
                    self.source.resolve("alice", bad)
        self.assertEqual(self.calls, [])

    def test_graph_bounds_shape_and_boundary(self):
        def variant(change):
            def rows(start, end):
                result = graph(start, end)
                change(result)
                return result

            return rows

        deep = 1
        for _ in range(21):
            deep = {"x": deep}
        cases = [
            lambda r: r.append({"row_type": "unexpected"}),
            lambda r: r.pop(),
            lambda r: r.append(copy.deepcopy(r[-1])),
            lambda r: r[-1].update(window_start="0"),
            lambda r: r[0].update(namespace="other"),
            lambda r: r.append({"row_type": "edge", "payload": "x" * (512 * 1024)}),
            lambda r: r.extend({"row_type": "node"} for _ in range(2000)),
            lambda r: r[-1].update(payload=float("nan")),
            lambda r: r[-1].update(payload=deep),
        ]
        for change in cases:
            with self.subTest():
                self.rows = variant(change)
                with self.assertRaises(SourceError):
                    self.source.resolve("alice", reference())

    def test_fingerprint_change_during_capture_fails(self):
        fingerprints = iter(("a", "b"))
        source = ComparisonSource(
            lambda _p, _q, s, e: graph(s, e), lambda: next(fingerprints), lambda: NOW
        )
        with self.assertRaises(SourceError):
            source.resolve("alice", reference())
