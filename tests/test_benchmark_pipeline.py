"""Safety and evidence-quality checks; no Docker or Splunk required."""

import tempfile
import hashlib
import io
import json
import tarfile
from types import SimpleNamespace
import os
import signal
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

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

    def test_task_owned_lab_ports_require_exact_local_bindings(self):
        ports = {
            "8088/tcp": [{"HostIp": "127.0.0.1", "HostPort": "18088"}],
            "8089/tcp": [{"HostIp": "127.0.0.1", "HostPort": "18089"}],
        }
        with patch.dict(
            os.environ, {"ADM_LAB_HEC_PORT": "18088", "ADM_LAB_MGMT_PORT": "18089"}
        ):
            bench.validate_ports(ports)
            with self.assertRaises(ValueError):
                bench.validate_ports(
                    {**ports, "8089/tcp": [{"HostIp": "0.0.0.0", "HostPort": "18089"}]}
                )
            with self.assertRaises(ValueError):
                bench.validate_ports(
                    {**ports, "8088/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8088"}]}
                )

    def test_task_owned_lab_target_rejects_remote_and_invalid_port(self):
        with (
            patch.dict(
                os.environ, {"ADM_LAB_HEC_PORT": "18088", "ADM_LAB_MGMT_PORT": "18089"}
            ),
            patch.object(bench.lab, "MGMT", "https://127.0.0.1:18089"),
            patch.object(bench.lab, "HEC", "https://127.0.0.1:18088"),
        ):
            bench.validate_lab_target()
            with patch.object(bench.lab, "MGMT", "https://192.0.2.1:18089"):
                with self.assertRaises(ValueError):
                    bench.validate_lab_target()
            with patch.dict(os.environ, {"ADM_LAB_MGMT_PORT": "-1"}):
                with self.assertRaises(ValueError):
                    bench.validate_lab_target()
            with patch.object(bench, "CONTAINER", "production-splunk"):
                with self.assertRaises(ValueError):
                    bench.validate_lab_target()

    def test_task_owned_lab_target_verifies_resource_ownership_before_use(self):
        with (
            patch.dict(os.environ, {"ADM_LAB_TASK": "nat-scale-20261025"}),
            patch.object(bench.lab, "verify_target") as verify_target,
        ):
            bench.validate_lab_target()
            verify_target.assert_called_once_with()

    def test_task_owned_lab_target_fails_closed_when_ownership_check_fails(self):
        with (
            patch.dict(os.environ, {"ADM_LAB_TASK": "nat-scale-20261025"}),
            patch.object(
                bench.lab, "verify_target", side_effect=RuntimeError("unowned")
            ),
        ):
            with self.assertRaisesRegex(RuntimeError, "unowned"):
                bench.validate_lab_target()

    def test_server_info_parser_keeps_only_native_identity_fields(self):
        parsed = bench.parse_server_info(
            {
                "entry": [
                    {
                        "name": "server-info",
                        "content": {
                            "version": "10.6.0.5",
                            "build": "abc123",
                            "product_type": "enterprise",
                            "licenseKeys": ["private-license"],
                            "host": "internal-host",
                            "guid": "private-guid",
                        },
                    }
                ]
            }
        )
        self.assertEqual(
            parsed,
            {
                "available": True,
                "version": "10.6.0.5",
                "build": "abc123",
                "product_type": "enterprise",
                "unavailable_fields": [],
                "availability_reason": None,
            },
        )

    def test_server_info_parser_reports_missing_fields_and_invalid_shapes(self):
        partial = bench.parse_server_info(
            {"entry": [{"name": "server-info", "content": {"version": "10.6"}}]}
        )
        self.assertFalse(partial["available"])
        self.assertEqual(partial["version"], "10.6")
        self.assertEqual(partial["build"], None)
        self.assertEqual(partial["product_type"], None)
        self.assertEqual(partial["unavailable_fields"], ["build", "product_type"])
        self.assertEqual(partial["availability_reason"], "fields_missing")
        self.assertEqual(
            bench.parse_server_info({"entry": []})["availability_reason"],
            "server_info_entry_missing",
        )
        self.assertEqual(
            bench.parse_server_info([])["availability_reason"], "invalid_response"
        )

    def test_server_info_capture_uses_finite_read_only_request_and_byte_cap(self):
        payload = json.dumps(
            {
                "entry": [
                    {
                        "name": "server-info",
                        "content": {
                            "version": "10.6.0.5",
                            "build": "abc123",
                            "product_type": "enterprise",
                            "licenseKeys": ["private-license"],
                        },
                    }
                ]
            }
        ).encode()

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, amount):
                self.amount = amount
                return payload

        response = Response()
        with patch.object(bench.lab, "_mgmt", return_value=response) as mgmt:
            parsed = bench.capture_server_info()
        mgmt.assert_called_once_with(
            "GET",
            "/services/server/info?output_mode=json&count=1",
            timeout=bench.SERVER_INFO_TIMEOUT_SECONDS,
        )
        self.assertEqual(response.amount, bench.MAX_SERVER_INFO_RESPONSE_BYTES + 1)
        self.assertTrue(parsed["available"])
        self.assertNotIn("licenseKeys", json.dumps(parsed))

    def test_server_info_capture_retains_safe_unavailable_reasons(self):
        with patch.object(
            bench.lab, "_mgmt", side_effect=TimeoutError("private response text")
        ) as mgmt:
            timed_out = bench.capture_server_info()
        mgmt.assert_called_once()
        self.assertEqual(timed_out["availability_reason"], "request_timeout")
        self.assertNotIn("private response text", json.dumps(timed_out))

        with patch.object(
            bench.lab, "_mgmt", side_effect=RuntimeError("sensitive body")
        ):
            failed = bench.capture_server_info()
        self.assertEqual(failed["availability_reason"], "request_failed")
        self.assertNotIn("sensitive body", json.dumps(failed))

        class InvalidResponse:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, _amount):
                return b"not-json"

        with patch.object(bench.lab, "_mgmt", return_value=InvalidResponse()):
            invalid = bench.capture_server_info()
        self.assertEqual(invalid["availability_reason"], "invalid_json")

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, amount):
                self.amount = amount
                return b"x" * amount

        response = Response()
        with patch.object(bench.lab, "_mgmt", return_value=response):
            oversized = bench.capture_server_info()
        self.assertEqual(oversized["availability_reason"], "response_too_large")
        self.assertEqual(response.amount, bench.MAX_SERVER_INFO_RESPONSE_BYTES + 1)

    def test_preflight_records_native_server_info_separately_from_image_identity(self):
        ports = {
            "8088/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8088"}],
            "8089/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8089"}],
        }
        docker_info = {"Architecture": "aarch64", "NCPU": 12, "MemTotal": 8192}
        formats = {
            "{{json .NetworkSettings.Ports}}": ports,
            "{{json .HostConfig}}": {"Memory": 0, "NanoCpus": 0},
            "{{json .Config.Labels}}": {},
            "{{json .Mounts}}": [],
            "{{json .NetworkSettings.Networks}}": {"test-net": {}},
            "{{.HostConfig.NetworkMode}}": "test-net",
            "{{.Config.Image}}": "splunk/splunk:10.6.0.5",
            "{{.Image}}": "sha256:test-image",
            "{{.Id}}": "test-container",
        }

        def fake_command(*args):
            if args[:2] == ("docker", "info"):
                return json.dumps(docker_info)
            if args[:2] == ("docker", "inspect"):
                return (
                    json.dumps(formats[args[3]])
                    if args[3].startswith("{{json")
                    else formats[args[3]]
                )
            raise AssertionError(f"Unexpected command: {args}")

        server_info = {
            "available": True,
            "version": "10.6.0.5",
            "build": "abc123",
            "product_type": "enterprise",
            "unavailable_fields": [],
            "availability_reason": None,
        }
        with (
            patch.dict(
                os.environ,
                {
                    "ADM_LAB_PACKAGE": "",
                    "ADM_LAB_HEC_PORT": "8088",
                    "ADM_LAB_MGMT_PORT": "8089",
                },
            ),
            patch.object(bench, "local_docker_endpoint"),
            patch.object(bench, "validate_lab_target"),
            patch.object(bench, "command", side_effect=fake_command),
            patch.object(bench, "non_task_docker_activity", return_value=[]),
            patch.object(bench, "installed_fingerprints", return_value={}),
            patch.object(bench, "capture_server_info", return_value=server_info),
        ):
            result = bench.preflight()
        self.assertEqual(result["image"], "splunk/splunk:10.6.0.5")
        self.assertEqual(result["image_id"], "sha256:test-image")
        self.assertEqual(result["splunk_server_info"], server_info)
        self.assertEqual(
            result["splunk_server_info_capture"],
            {
                "request_timeout_seconds": bench.SERVER_INFO_TIMEOUT_SECONDS,
                "max_response_bytes": bench.MAX_SERVER_INFO_RESPONSE_BYTES,
            },
        )

    def test_bounded_reset_subprocess_timeout_terminates_only_its_process_group(self):
        process = SimpleNamespace(pid=4321, returncode=-signal.SIGTERM)
        process.communicate = Mock(
            side_effect=[
                bench.subprocess.TimeoutExpired("reset", 10),
                (None, None),
                (None, None),
            ]
        )

        def signal_group(_process_group, signum):
            if signum == 0:
                raise ProcessLookupError

        with (
            patch.object(bench.subprocess, "Popen", return_value=process) as popen,
            patch.object(bench.os, "killpg", side_effect=signal_group) as killpg,
            self.assertRaises(bench.LabResetTimeout) as raised,
        ):
            bench._run_bounded_subprocess(
                ["reset"], timeout=10, operation="lab.sh reset"
            )
        self.assertEqual(raised.exception.operation, "lab.sh reset")
        self.assertEqual(raised.exception.timeout_seconds, 10)
        self.assertTrue(raised.exception.host_process_group_stopped)
        self.assertIn("state is uncertain", str(raised.exception))
        popen.assert_called_once_with(["reset"], start_new_session=True)
        self.assertEqual(process.communicate.call_args_list[0].kwargs, {"timeout": 10})
        self.assertEqual(
            process.communicate.call_args_list[1].kwargs,
            {"timeout": bench.PROCESS_TERMINATION_GRACE_SECONDS},
        )
        self.assertEqual(
            process.communicate.call_args_list[2].kwargs,
            {"timeout": bench.PROCESS_TERMINATION_GRACE_SECONDS},
        )
        self.assertEqual(
            [call.args[1] for call in killpg.call_args_list], [signal.SIGTERM, 0, 0]
        )

    def test_timed_out_parent_cannot_leave_term_ignoring_child_in_process_group(self):
        with tempfile.TemporaryDirectory() as directory:
            child_pid_path = Path(directory) / "child.pid"
            child_code = (
                "import signal, time; "
                "signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)"
            )
            parent_code = (
                "import pathlib, signal, subprocess, sys, time; "
                f"child = subprocess.Popen([sys.executable, '-c', {child_code!r}]); "
                f"pathlib.Path({str(child_pid_path)!r}).write_text(str(child.pid)); "
                "signal.signal(signal.SIGTERM, lambda *_: sys.exit(0)); "
                "time.sleep(60)"
            )
            timed_out = None
            try:
                with self.assertRaises(bench.LabResetTimeout) as raised:
                    bench._run_bounded_subprocess(
                        [sys.executable, "-c", parent_code],
                        timeout=1,
                        operation="test reset parent",
                        stdout=bench.subprocess.DEVNULL,
                        stderr=bench.subprocess.DEVNULL,
                    )
                timed_out = raised.exception
                child_pid = int(child_pid_path.read_text())
                status = bench.subprocess.run(
                    ["ps", "-o", "stat=", "-p", str(child_pid)],
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=2,
                ).stdout.strip()
                self.assertFalse(status and not status.startswith("Z"))
            finally:
                if child_pid_path.exists():
                    child_pid = int(child_pid_path.read_text())
                    status = bench.subprocess.run(
                        ["ps", "-o", "stat=", "-p", str(child_pid)],
                        check=False,
                        capture_output=True,
                        text=True,
                        timeout=2,
                    ).stdout.strip()
                    if status and not status.startswith("Z"):
                        os.kill(child_pid, signal.SIGKILL)
            self.assertIsNotNone(timed_out)
            self.assertTrue(timed_out.host_process_group_stopped)

    def test_reset_subprocesses_have_finite_phase_deadlines(self):
        with (
            patch.object(bench, "_run_bounded_subprocess") as run_process,
            patch.object(bench.lab, "_json", side_effect=[{}, {"entry": []}]),
            patch.object(bench, "COLLECTIONS", ()),
            patch.object(bench, "seed_scope") as seed_scope,
        ):
            bench.reset_lab([])
        self.assertEqual(run_process.call_count, 2)
        self.assertEqual(
            run_process.call_args_list[0].kwargs["timeout"],
            bench.LAB_RESET_TIMEOUT_SECONDS,
        )
        self.assertEqual(
            run_process.call_args_list[1].kwargs["timeout"],
            bench.LAB_RESET_DOCKER_TIMEOUT_SECONDS,
        )
        seed_scope.assert_called_once_with([])

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

    def test_non_task_activity_snapshot_excludes_owned_container(self):
        entries = [
            {"Names": bench.CONTAINER, "Image": "task-splunk", "Status": "Up"},
            {
                "Names": "other-collector",
                "Image": "collector-image:tag",
                "Status": "Up 1 day",
            },
        ]
        output = "\n".join(json.dumps(entry) for entry in entries)
        with patch.object(bench, "command", return_value=output):
            self.assertEqual(
                bench.non_task_docker_activity(),
                [
                    {
                        "name": "other-collector",
                        "image": "collector-image:tag",
                        "status": "Up 1 day",
                    }
                ],
            )

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
        with tempfile.TemporaryDirectory() as directory:
            lock_path = Path(directory) / "lab.lock"
            # The decorator imports top-level lab_lock; ENV_PATH only carries
            # inherited ownership, so patch its actual default-path resolver.
            with (
                patch("lab_lock.default_lock_path", return_value=lock_path),
                patch.object(bench, "preflight") as probe,
            ):
                with self.assertRaises(SystemExit):
                    bench.main([])
                probe.assert_not_called()
            self.assertTrue(lock_path.is_file())
            self.assertEqual(lock_path.read_text(), "")

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
                            "dispatchState": "DONE",
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

    def test_result_retrieval_is_bounded_with_one_sentinel_row(self):
        responses = [
            {"sid": "bounded"},
            {
                "entry": [
                    {
                        "content": {
                            "dispatchState": "DONE",
                            "isDone": True,
                            "isFailed": False,
                            "isFinalized": False,
                            "resultCount": 3,
                            "runDuration": "2.5",
                            "scanCount": "7",
                            "eventCount": 3,
                            "dropCount": 0,
                            "eventIsTruncated": False,
                            "resultIsTruncated": False,
                            "diskUsage": 128,
                            "performance": {"command.search": {"duration_secs": 1.5}},
                        }
                    }
                ]
            },
            {"results": [{"row": 1}, {"row": 2}, {"row": 3}]},
        ]
        with patch.object(bench, "request", side_effect=responses) as api:
            rows, job = bench.Runner(10, result_limit=2).search("test", "| makeresults")
        self.assertEqual(len(rows), 3)
        self.assertIn("count=3", api.call_args_list[-1].args[1])
        self.assertEqual(job["status"], "incomplete")
        self.assertTrue(job["result_limit_exceeded"])
        self.assertEqual(job["result_limit"], 2)
        self.assertEqual(job["fetched_rows"], 3)
        self.assertEqual(job["result_count"], 3)
        self.assertEqual(job["scan_count"], 7)
        self.assertEqual(job["run_seconds"], 2.5)
        self.assertEqual(job["disk_usage_bytes"], 128)
        self.assertEqual(
            job["metrics"]["performance"]["command.search"]["duration_secs"], 1.5
        )

    def test_result_retrieval_pages_all_rows_with_bounded_offsets(self):
        content = {
            "dispatchState": "DONE",
            "isDone": True,
            "isFailed": False,
            "isFinalized": False,
            "resultCount": 5,
            "runDuration": 1,
            "scanCount": 5,
        }
        responses = [
            {"sid": "pages"},
            {"entry": [{"content": content}]},
            {"results": [{"row": 0}, {"row": 1}]},
            {"results": [{"row": 2}, {"row": 3}]},
            {"results": [{"row": 4}]},
        ]
        with patch.object(bench, "request", side_effect=responses) as api:
            rows, job = bench.Runner(10, result_limit=6, page_size=2).search(
                "pages", "| makeresults"
            )
        self.assertEqual([row["row"] for row in rows], list(range(5)))
        self.assertEqual(job["status"], "complete")
        self.assertEqual(job["result_page_size"], 2)
        self.assertEqual(job["result_page_count"], 3)
        self.assertEqual(
            [
                (page["offset"], page["requested_count"], page["returned_count"])
                for page in job["result_pages"]
            ],
            [(0, 2, 2), (2, 2, 2), (4, 1, 1)],
        )
        urls = [call.args[1] for call in api.call_args_list]
        self.assertIn("count=2&offset=0", urls[2])
        self.assertIn("count=2&offset=2", urls[3])
        self.assertIn("count=1&offset=4", urls[4])

    def test_failed_result_page_preserves_partial_metrics_and_rows(self):
        content = {
            "dispatchState": "DONE",
            "isDone": True,
            "resultCount": 5,
            "runDuration": 1,
        }
        responses = [
            {"sid": "page-failure"},
            {"entry": [{"content": content}]},
            {"results": [{"row": 0}, {"row": 1}]},
            RuntimeError("page transport failure"),
            {},
        ]
        runner = bench.Runner(10, result_limit=6, page_size=2)
        with patch.object(bench, "request", side_effect=responses):
            with self.assertRaisesRegex(RuntimeError, "page transport failure"):
                runner.search("page-failure", "| makeresults")
        job = runner.jobs[0]
        self.assertEqual(job["status"], "failed")
        self.assertEqual(job["fetched_rows"], 2)
        self.assertEqual(job["metrics"]["result_count"], 5)
        self.assertEqual(len(job["result_pages"]), 1)
        self.assertEqual(job["result_pages"][0]["offset"], 0)

    def test_short_page_and_unknown_count_are_explicitly_incomplete(self):
        responses = [
            {"sid": "short"},
            {"entry": [{"content": {"dispatchState": "DONE", "isDone": True}}]},
            {"results": [{"row": 0}]},
        ]
        with patch.object(bench, "request", side_effect=responses):
            _, job = bench.Runner(10, result_limit=5, page_size=2).search(
                "short", "| makeresults"
            )
        self.assertEqual(job["status"], "incomplete")
        self.assertIn("Final result count is unavailable or invalid", job["warnings"])
        self.assertIn(
            "Result pagination ended before the requested row count", job["warnings"]
        )
        self.assertEqual(job["fetched_rows"], 1)

    def test_invalid_result_page_size_is_rejected(self):
        for value in (0, -1, True, bench.MAX_RESULT_PAGE_SIZE + 1):
            with self.subTest(value=value), self.assertRaises(ValueError):
                bench.Runner(10, page_size=value)

    def test_index_visibility_poll_is_bounded_by_remaining_deadline(self):
        class VisibilityRunner:
            timeout = 120

            def search(inner_self, *_args):
                self.assertLessEqual(inner_self.timeout, 10)
                return ([{"count": "1"}], {"status": "complete"})

        runner = VisibilityRunner()
        bench.wait_count(runner, "index=example", expected=1, timeout=10)
        self.assertEqual(runner.timeout, 120)

    def test_index_visibility_failure_restores_search_timeout(self):
        class FailedVisibilityRunner:
            timeout = 120

            def search(inner_self, *_args):
                self.assertLessEqual(inner_self.timeout, 10)
                raise TimeoutError("search timeout")

        runner = FailedVisibilityRunner()
        with self.assertRaisesRegex(TimeoutError, "search timeout"):
            bench.wait_count(runner, "index=example", expected=1, timeout=10)
        self.assertEqual(runner.timeout, 120)

    def test_unavailable_search_metrics_are_null_and_listed(self):
        responses = [
            {"sid": "metrics"},
            {
                "entry": [
                    {
                        "content": {
                            "dispatchState": "DONE",
                            "isDone": True,
                            "resultCount": 1,
                        }
                    }
                ]
            },
            {"results": [{"row": 1}]},
        ]
        with patch.object(bench, "request", side_effect=responses):
            _, job = bench.Runner(10, result_limit=5).search("test", "| makeresults")
        self.assertEqual(job["status"], "complete")
        self.assertIsNone(job["scan_count"])
        self.assertIsNone(job["event_count"])
        self.assertIsNone(job["disk_usage_bytes"])
        self.assertIn("scan_count", job["metrics_unavailable"])
        self.assertIn("performance", job["metrics_unavailable"])

    def test_non_done_terminal_dispatch_is_incomplete(self):
        responses = [
            {"sid": "cancelled"},
            {
                "entry": [
                    {
                        "content": {
                            "dispatchState": "USER_CANCEL",
                            "isDone": True,
                            "resultCount": 0,
                            "dropCount": 0,
                        }
                    }
                ]
            },
            {"results": []},
        ]
        with patch.object(bench, "request", side_effect=responses):
            rows, job = bench.Runner(10, result_limit=5).search(
                "cancelled", "| makeresults"
            )
        self.assertEqual(rows, [])
        self.assertEqual(job["status"], "incomplete")
        self.assertIn("Search dispatch state is USER_CANCEL", job["warnings"])

    def test_invalid_result_limit_is_rejected(self):
        for value in (0, -1, True, bench.MAX_RESULT_LIMIT + 1):
            with self.subTest(value=value), self.assertRaises(ValueError):
                bench.Runner(10, result_limit=value)

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
        self.assertIn(
            "outputlookup adm_observer_scope", search.call_args_list[0].args[1]
        )
        self.assertNotIn("adm_observer_scope.csv", search.call_args_list[0].args[1])

    def test_scope_matching_keys_normalize_without_lowercasing_outputs(self):
        source = [
            {
                "observer_kind": "Cluster",
                "observer": "MixedCase",
                "scope": "Prod",
                "cluster": "MixedCase",
            }
        ]
        stored = [{**source[0], "observer_kind": "cluster", "observer": "mixedcase"}]
        with patch.object(
            bench.Runner,
            "search",
            side_effect=[
                ([], {"status": "complete"}),
                (stored, {"status": "complete"}),
            ],
        ):
            bench.seed_scope(source)


class PackageFingerprintRegressionTest(unittest.TestCase):
    """The installed candidate is exact, and its defaults still bind to source."""

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.app = self.root / "splunk_app/splunk_adm"
        (self.app / "default").mkdir(parents=True)
        self.source = {
            "app.conf": b"[id]\nname = splunk_adm\nversion = 0.3.0\n",
            "macros.conf": b"[adm_test]\ndefinition = index=synthetic\n",
        }
        for name, content in self.source.items():
            (self.app / "default" / name).write_bytes(content)
        self.packaged = dict(self.source)
        self.packaged["app.conf"] = (
            b"[install]\nbuild = 1792340274\n" + self.source["app.conf"]
        )
        self.archive = self.root / "candidate.tgz"

    def write_archive(self, configs=None, unsafe=False):
        with tarfile.open(self.archive, "w:gz") as archive:
            for name, content in (
                self.packaged if configs is None else configs
            ).items():
                info = tarfile.TarInfo("splunk_adm/default/" + name)
                info.size = len(content)
                info.mode = 0o644
                archive.addfile(info, io.BytesIO(content))
            if unsafe:
                info = tarfile.TarInfo("splunk_adm/default/escape.conf")
                info.type = tarfile.SYMTYPE
                info.linkname = "/etc/passwd"
                archive.addfile(info)
        digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        Path(f"{self.archive}.sha256").write_text(
            f"{digest}  {self.archive.name}\n", encoding="utf-8"
        )

    def fingerprints(self, installed=None, *, supplied=True):
        installed = self.packaged if installed is None else installed

        def docker(args, **_kwargs):
            if "find" in args:
                return "".join(
                    "/opt/splunk/etc/apps/splunk_adm/default/" + name + "\n"
                    for name in sorted(installed)
                ).encode()
            return installed[args[-1].split("/default/", 1)[1]]

        with (
            patch.object(bench, "ROOT", self.root),
            patch.dict(
                os.environ,
                {"ADM_LAB_PACKAGE": str(self.archive)} if supplied else {},
                clear=True,
            ),
            patch.object(bench.subprocess, "check_output", side_effect=docker),
            patch.object(
                bench.subprocess, "run", return_value=SimpleNamespace(returncode=1)
            ),
        ):
            return bench.installed_fingerprints()

    def test_generated_build_metadata_matches_exact_installed_archive(self):
        self.write_archive()
        result = self.fingerprints()
        self.assertEqual(
            result["splunk_app/splunk_adm/default/app.conf"],
            hashlib.sha256(self.packaged["app.conf"]).hexdigest(),
        )
        self.assertEqual(len(result), 2)
        self.assertNotEqual(self.packaged["app.conf"], self.source["app.conf"])

    def test_archive_pipeline_drift_is_refused_before_installed_read(self):
        changed = dict(
            self.packaged, **{"macros.conf": b"[adm_test]\ndefinition = index=other\n"}
        )
        self.write_archive(changed)
        with patch.object(bench.subprocess, "check_output") as docker:
            with self.assertRaisesRegex(ValueError, "differs from source"):
                bench._package_default_configs(self.app, self.archive)
            docker.assert_not_called()

    def test_only_generated_build_metadata_is_exempt(self):
        for content in (
            self.packaged["app.conf"].replace(b"0.3.0", b"0.4.0"),
            b"[install]\nbuild = 1792340274\nstate = disabled\n"
            + self.source["app.conf"],
            b"[install]\nbuild = -1\n" + self.source["app.conf"],
        ):
            with self.subTest(content=content):
                self.write_archive(dict(self.packaged, **{"app.conf": content}))
                with self.assertRaisesRegex(ValueError, "app.conf differs from source"):
                    bench._package_default_configs(self.app, self.archive)

    def test_archive_missing_or_extra_defaults_are_refused(self):
        for configs in (
            {"app.conf": self.packaged["app.conf"]},
            dict(self.packaged, **{"props.conf": b"[extra]\n"}),
        ):
            with self.subTest(configs=sorted(configs)):
                self.write_archive(configs)
                with self.assertRaisesRegex(
                    ValueError, "config set differs from source"
                ):
                    bench._package_default_configs(self.app, self.archive)

    def test_installed_bytes_must_match_the_supplied_archive(self):
        self.write_archive()
        for name in ("app.conf", "macros.conf"):
            with self.subTest(name=name):
                installed = dict(self.packaged)
                installed[name] += b"# changed installed bytes\n"
                with self.assertRaisesRegex(
                    ValueError, "differs from provided package"
                ):
                    self.fingerprints(installed)

    def test_installed_missing_or_extra_defaults_are_refused(self):
        self.write_archive()
        for installed in (
            {"app.conf": self.packaged["app.conf"]},
            dict(self.packaged, **{"props.conf": b"[extra]\n"}),
        ):
            with self.subTest(installed=sorted(installed)):
                with self.assertRaisesRegex(
                    ValueError, "config set differs from provided package"
                ):
                    self.fingerprints(installed)

    def test_unsafe_archive_is_refused_by_the_shared_stager(self):
        self.write_archive(unsafe=True)
        with self.assertRaisesRegex(ValueError, "links or special files"):
            bench._package_default_configs(self.app, self.archive)

    def test_unsupplied_package_keeps_source_only_byte_exact_behavior(self):
        self.assertEqual(len(self.fingerprints(self.source, supplied=False)), 2)
        with self.assertRaisesRegex(ValueError, "app.conf differs from source"):
            self.fingerprints(self.packaged, supplied=False)
