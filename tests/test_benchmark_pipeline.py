"""Safety and evidence-quality checks; no Docker or Splunk required."""

import tempfile
import os
import unittest
from pathlib import Path
from unittest.mock import patch

from tools import benchmark_pipeline as bench


class BenchmarkPipelineTest(unittest.TestCase):
    def test_remote_or_wildcard_bindings_are_rejected(self):
        local = {
            f"{p}/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(p)}]
            for p in (8088, 8089)
        }
        bench.validate_ports(local)
        for ip in ("0.0.0.0", "::", "192.0.2.1"):
            with self.subTest(ip=ip), self.assertRaises(ValueError):
                bench.validate_ports(
                    {**local, "8089/tcp": [{"HostIp": ip, "HostPort": "8089"}]}
                )
        with self.assertRaises(ValueError):
            bench.validate_ports({})

    def test_docker_endpoint_precedence_and_pinning(self):
        with (
            patch.dict(
                os.environ,
                {"DOCKER_CONTEXT": "local", "DOCKER_HOST": "ssh://remote"},
                clear=True,
            ),
            patch.object(bench, "command", return_value="unix:///test.sock") as docker,
        ):
            bench.local_docker_endpoint()
            self.assertEqual(os.environ["DOCKER_HOST"], "unix:///test.sock")
            self.assertNotIn("DOCKER_CONTEXT", os.environ)
            self.assertIn("local", docker.call_args.args)
        with (
            patch.dict(os.environ, {"DOCKER_HOST": "ssh://remote"}, clear=True),
            self.assertRaises(ValueError),
        ):
            bench.local_docker_endpoint()
        with (
            patch.dict(os.environ, {}, clear=True),
            patch.object(bench, "command", return_value="tcp://remote:2376"),
            self.assertRaises(ValueError),
        ):
            bench.local_docker_endpoint()

    def test_saved_search_overrides_cannot_change_queries(self):
        bench.validate_saved_overrides(
            "[ADM - Identity builder]\ndisabled=0\nenableSched=0\n"
        )
        with self.assertRaises(ValueError):
            bench.validate_saved_overrides(
                "[ADM - Identity builder]\nsearch=| makeresults\n"
            )

    def test_late_dispatch_response_is_cancelled_and_not_complete(self):
        clock = [0]

        def api(method, path, data=None, timeout=120):
            if path.endswith("/control"):
                return {}
            self.assertEqual(timeout, 10)
            clock[0] = 25
            return {"sid": "late"}

        runner = bench.Runner(10)
        with (
            patch.object(bench.time, "monotonic", side_effect=lambda: clock[0]),
            patch.object(bench, "request", side_effect=api) as request,
        ):
            with self.assertRaises(TimeoutError):
                runner.search("test", "| makeresults")
        self.assertEqual(request.call_args.args[-1], {"action": "cancel"})
        self.assertEqual(runner.jobs[0]["sid"], "late")
        self.assertEqual(runner.jobs[0]["status"], "failed")

    def test_reset_opt_in_is_required_before_preflight(self):
        with patch.object(bench, "preflight") as probe:
            with self.assertRaises(SystemExit):
                bench.main([])
            probe.assert_not_called()

    def test_graph_checks_catch_truncation_and_double_counted_observers(self):
        expected = {
            "graph_nodes": 1,
            "graph_edges": 1,
            "graph_bytes": 300,
            "graph_connections": 1,
        }
        rows = [
            {"row_type": "meta"},
            {"row_type": "node"},
            {
                "row_type": "edge",
                "relationship": "communicates_with",
                "bytes": "300",
                "count": "1",
            },
        ]
        self.assertEqual(bench.graph_check(rows, expected), [])
        rows[-1]["bytes"] = "900"
        self.assertTrue(any("bytes" in n for n in bench.graph_check(rows, expected)))
        rows[0]["warnings"] = "Identity lookup capped"
        self.assertIn("Identity lookup capped", bench.graph_check(rows, expected))
        self.assertTrue(bench.graph_check(rows[:-1], expected))

    def test_finalization_and_missing_rows_cannot_be_complete(self):
        responses = [
            {"sid": "test"},
            {
                "entry": [
                    {
                        "content": {
                            "isDone": True,
                            "isFinalized": True,
                            "resultCount": 2,
                            "runDuration": 1,
                        }
                    }
                ]
            },
            {"results": [{}]},
        ]
        with patch.object(bench, "request", side_effect=responses):
            _, job = bench.Runner(10).search("test", "| makeresults")
        self.assertEqual(job["status"], "incomplete")
        self.assertIn("Search was finalized early", job["warnings"])
        self.assertIn(
            "Fetched row count differs from final result count", job["warnings"]
        )

    def test_search_errors_are_recorded_and_cancelled(self):
        responses = [
            {"sid": "test"},
            {
                "entry": [
                    {
                        "content": {
                            "dispatchState": "FAILED",
                            "messages": [{"type": "ERROR", "text": "failure"}],
                        }
                    }
                ]
            },
            {},
        ]
        runner = bench.Runner(10)
        with patch.object(bench, "request", side_effect=responses) as api:
            with self.assertRaises(RuntimeError):
                runner.search("test", "| makeresults")
        self.assertEqual(runner.jobs[0]["status"], "failed")
        self.assertEqual(api.call_args.args[-1], {"action": "cancel"})

    def test_report_does_not_invent_missing_measurements(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            bench.write_report(
                path,
                {
                    "generated_at": "test",
                    "cases": [
                        {
                            "name": "failed",
                            "manifest": {"expected": {"flows": 2}},
                            "workload": {},
                            "status": "failed",
                            "jobs": [],
                        }
                    ],
                },
            )
            self.assertIn("—", path.with_suffix(".md").read_text())
            self.assertIsNone(bench.summary([]))


if __name__ == "__main__":
    unittest.main()


class ScopeSeedRegressionTest(unittest.TestCase):
    def test_empty_lookup_is_not_successful_setup(self):
        with (
            patch.object(
                bench.Runner, "search", return_value=([], {"status": "complete"})
            ),
            self.assertRaisesRegex(ValueError, "retain"),
        ):
            bench.seed_scope(
                [
                    {
                        "observer_kind": "exporter",
                        "observer": "192.0.2.11",
                        "scope": "demo",
                        "cluster": "demo",
                    }
                ]
            )

    def test_scope_uses_json_records_and_verifies_round_trip(self):
        rows = [
            {
                "observer_kind": "exporter",
                "observer": "192.0.2.11",
                "scope": "demo",
                "cluster": "demo",
            }
        ]
        with patch.object(
            bench.Runner,
            "search",
            side_effect=[([], {"status": "complete"}), (rows, {"status": "complete"})],
        ) as search:
            bench.seed_scope(rows)
        self.assertIn("format=json", search.call_args_list[0].args[1])
        self.assertIn("inputlookup", search.call_args_list[1].args[1])
