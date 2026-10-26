"""Read-only, bounded ThousandEyes CEA path export contract tests."""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch
from urllib.parse import urlencode

from tools import export_thousandeyes_paths as export
from tools import hec_delivery


def request(**changes) -> export.PathExportRequest:
    values = {
        "authority": "te-example",
        "account_group_id": "1234",
        "test_ids": ("17",),
        "target_index": "te_paths",
        "start": 1_700_000_000,
        "end": 1_700_000_900,
        "timeout_seconds": 5,
    }
    values.update(changes)
    return export.PathExportRequest(**values)


def summary(
    test_id="17", agent_id="9", round_id=None, *, path_ids=("path-1",), **changes
):
    active = request()
    round_value = active.start + 15 if round_id is None else round_id
    row = {
        "aid": 1234,
        "testId": test_id,
        "agentId": agent_id,
        "roundId": round_value,
        "date": datetime.fromtimestamp(round_value, timezone.utc)
        .isoformat()
        .replace("+00:00", "Z"),
        "pathTraces": [{"pathId": path_id} for path_id in path_ids],
    }
    row.update(changes)
    return row


def detail(agent_id="9", round_id=None, *, path_ids=("path-1",), **changes):
    active = request()
    round_value = active.start + 15 if round_id is None else round_id
    row = {
        "aid": 1234,
        "testId": "17",
        "agentId": agent_id,
        "roundId": round_value,
        "date": datetime.fromtimestamp(round_value, timezone.utc)
        .isoformat()
        .replace("+00:00", "Z"),
        "startTime": round_value,
        "endTime": round_value,
        "agent": {"agentId": agent_id, "location": "East office"},
        "pathTraces": [
            {
                "pathId": path_id,
                "numberOfHops": 3,
                "hops": [
                    {"hop": 1, "ipAddress": "192.0.2.1", "responseTime": 1.2},
                    {"hop": 3, "ipAddress": "198.51.100.20", "responseTime": 3.4},
                ],
            }
            for path_id in path_ids
        ],
    }
    row.update(changes)
    return row


def response(value, status=200, headers=None):
    return export._HTTPResponse(status, json.dumps(value).encode(), headers)


class PathExportTest(unittest.TestCase):
    def test_builds_exact_bounded_list_and_constructed_detail_routes(self):
        active = request()
        self.assertEqual(
            export.build_results_url(
                "17", "1234", active.start, active.end, cursor="cursor-1"
            ),
            "https://api.thousandeyes.com/v7/test-results/17/path-vis?aid=1234&startDate="
            + urlencode(
                {
                    "startDate": export._utc_date(active.start),
                    "endDate": export._utc_date(active.end),
                    "cursor": "cursor-1",
                }
            )[len("startDate=") :],
        )
        self.assertEqual(
            export.build_detail_url("17", "9", active.start + 15, "1234"),
            f"https://api.thousandeyes.com/v7/test-results/17/path-vis/agent/9/round/{active.start + 15}?aid=1234",
        )
        with self.assertRaises(export.ThousandEyesPathExportError):
            export.build_results_url("../other", "1234", active.start, active.end)
        with self.assertRaises(export.ThousandEyesPathExportError):
            export.build_detail_url("17", "../other", active.start + 15, "1234")
        with self.assertRaises(ValueError):
            export.build_results_url("17", "1234 OR *", active.start, active.end)

    def test_request_requires_literal_identity_index_and_whole_second_window(self):
        with self.assertRaisesRegex(ValueError, "literal account-group"):
            request(account_group_id="1234 OR *").validate()
        with self.assertRaisesRegex(ValueError, "literal Splunk index"):
            request(target_index="te_paths OR index=*").validate()
        with self.assertRaisesRegex(ValueError, "unique literal IDs"):
            request(test_ids=("17", "17")).validate()
        with self.assertRaisesRegex(ValueError, "at most 24h"):
            active = request()
            request(start=active.start, end=active.start + 86_401).validate()
        with self.assertRaisesRegex(ValueError, "future"):
            now = int(time.time())
            request(start=now + 100, end=now + 200).validate()
        with self.assertRaisesRegex(ValueError, "whole UTC seconds"):
            active = request()
            export.build_results_url("17", "1234", active.start + 0.5, active.end)

    def test_pagination_link_cannot_change_host_identity_or_date_bounds(self):
        active = request()
        for bad in (
            "https://evil.example/v7/test-results/17/path-vis?aid=1234&startDate="
            + export._utc_date(active.start)
            + "&endDate="
            + export._utc_date(active.end)
            + "&cursor=x",
            export.build_results_url(
                "18", "1234", active.start, active.end, cursor="x"
            ),
            export.build_results_url(
                "17", "9999", active.start, active.end, cursor="x"
            ),
            export.build_results_url(
                "17", "1234", active.start - 1, active.end, cursor="x"
            ),
            export.build_results_url("17", "1234", active.start, active.end, cursor="x")
            + "&aid=1234",
        ):
            with (
                self.subTest(url=bad),
                self.assertRaises(export.ThousandEyesPathExportError),
            ):
                export._validated_page_url(bad, active, "17")
        good_relative = export.build_results_url(
            "17", "1234", active.start, active.end, cursor="next"
        ).removeprefix(export.API_ORIGIN)
        self.assertEqual(
            export._validated_page_url(
                export.urljoin(export.API_ORIGIN, good_relative), active, "17"
            ),
            export.build_results_url(
                "17", "1234", active.start, active.end, cursor="next"
            ),
        )

    def test_capture_fetches_every_detail_route_and_preserves_path_iterations(self):
        active = request()
        first = summary(path_ids=("path-1", "path-2"))
        second = detail(path_ids=("path-1", "path-2"))
        seen = []

        def get_json(url, token, timeout, context):
            seen.append((url, token, timeout, context))
            if "/agent/" in url:
                return response(second)
            return response({"results": [first]})

        wrappers, capture_id, completed = export.collect_path_results(
            active, "secret-test-token", get_json=get_json, captured_at=1_700_000_010
        )
        self.assertEqual(len(seen), 2)
        self.assertTrue(all(call[1] == "secret-test-token" for call in seen))
        self.assertTrue(all(call[2] <= active.timeout_seconds for call in seen))
        self.assertTrue(
            all(call[3].verify_mode == export.ssl.CERT_REQUIRED for call in seen)
        )
        self.assertEqual(len(wrappers), 1)
        wrapper = wrappers[0]
        self.assertEqual(wrapper["schema"], export.PATH_SCHEMA)
        self.assertEqual(wrapper["schema_version"], 1)
        self.assertEqual(wrapper["capture_id"], capture_id)
        self.assertEqual(wrapper["authority"], active.authority)
        self.assertEqual(wrapper["account_group_id"], active.account_group_id)
        self.assertEqual(wrapper["test_id"], "17")
        self.assertEqual(wrapper["test_domain"], "cea")
        self.assertEqual(wrapper["collection_started_at"], 1_700_000_010)
        self.assertEqual(wrapper["collection_completed_at"], completed)
        self.assertEqual(
            [row["pathId"] for row in wrapper["result"]["pathTraces"]],
            ["path-1", "path-2"],
        )
        self.assertEqual(
            [hop["hop"] for hop in wrapper["result"]["pathTraces"][0]["hops"]],
            [1, 3],
        )

    def test_collection_completion_time_is_after_all_detail_reads(self):
        active = request()
        clock = [1_800_000_000]

        def delayed_detail(url, *_):
            if "/agent/" in url:
                clock[0] += 12
                return response(detail())
            return response({"results": [summary()]})

        with patch.object(export.time, "time", side_effect=lambda: clock[0]):
            wrappers, _, completed = export.collect_path_results(
                active,
                "token",
                get_json=delayed_detail,
                captured_at=1_700_000_010,
            )
        self.assertEqual(completed, 1_800_000_012)
        self.assertEqual(wrappers[0]["collection_completed_at"], completed)

    def test_constructs_canonical_hec_rows_with_explicit_index_and_queues_them(self):
        active = request()
        path_result = detail()
        wrapper = {
            "schema": export.PATH_SCHEMA,
            "schema_version": 1,
            "capture_id": "capture-1",
            "record_id": "record-1",
            "authority": active.authority,
            "account_group_id": active.account_group_id,
            "test_id": "17",
            "test_domain": "cea",
            "collection_started_at": active.start,
            "collection_completed_at": active.end,
            "result": path_result,
        }
        content = export.render_hec_ndjson(
            active,
            [wrapper],
            capture_id="capture-1",
            captured_at=active.end,
        )
        envelope = json.loads(content.splitlines()[0])
        self.assertEqual(envelope["index"], active.target_index)
        self.assertEqual(envelope["source"], export.ATLAS_PATH_SOURCE)
        self.assertEqual(envelope["sourcetype"], export.ATLAS_PATH_SOURCETYPE)
        self.assertEqual(envelope["time"], active.end)
        self.assertEqual(envelope["event"], wrapper)

        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            output = directory / "capture" / "path.ndjson"
            spool = directory / "queue"
            export._publish_new(output, content)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            receipt = hec_delivery.enqueue_capture(
                output, spool, source_id="thousandeyes_path"
            )
            self.assertEqual(receipt.record_count, 1)
            self.assertFalse(receipt.duplicate)
            self.assertTrue(Path(receipt.queued_path).is_file())
            with self.assertRaises(FileExistsError):
                export._publish_new(output, content)

    def test_capture_rejects_identity_round_and_path_iteration_mismatches(self):
        active = request()
        for mismatch in (
            detail(agent_id="10"),
            detail(round_id=active.start + 16),
            detail(path_ids=("other-path",)),
            detail(pathTraces=[{"pathId": "path-1"}]),
            detail(agent_id="10", agentId="9"),
        ):

            def get_json(url, *_):
                if "/agent/" in url:
                    return response(mismatch)
                return response({"results": [summary()]})

            with (
                self.subTest(mismatch=mismatch),
                self.assertRaises(export.ThousandEyesPathExportError),
            ):
                export.collect_path_results(active, "token", get_json=get_json)

    def test_capture_rejects_out_of_window_summaries_and_changed_page_scope(self):
        active = request()

        def out_of_window(url, *_):
            return response({"results": [summary(round_id=active.end + 1)]})

        with self.assertRaisesRegex(export.ThousandEyesPathExportError, "outside"):
            export.collect_path_results(active, "token", get_json=out_of_window)

        def in_window_date_outside_round(url, *_):
            conflicting = summary(
                round_id=active.end + 1,
                date=export._utc_date(active.start + 10),
            )
            return response({"results": [conflicting]})

        with self.assertRaisesRegex(
            export.ThousandEyesPathExportError, "round outside"
        ):
            export.collect_path_results(
                active, "token", get_json=in_window_date_outside_round
            )

        def conflicting_agent_alias(url, *_):
            conflicting = summary()
            conflicting["agent_id"] = "10"
            return response({"results": [conflicting]})

        with self.assertRaisesRegex(export.ThousandEyesPathExportError, "conflicting"):
            export.collect_path_results(
                active, "token", get_json=conflicting_agent_alias
            )

        def changed_page(url, *_):
            return response(
                {
                    "results": [summary()],
                    "_links": {
                        "next": {
                            "href": export.build_results_url(
                                "17", "9999", active.start, active.end, cursor="next"
                            )
                        }
                    },
                }
            )

        with self.assertRaisesRegex(export.ThousandEyesPathExportError, "identity"):
            export.collect_path_results(active, "token", get_json=changed_page)

    def test_empty_intermediate_page_follows_validated_next_cursor(self):
        active = request()
        pages = []

        def get_json(url, *_):
            if "/agent/" in url:
                round_id = int(url.split("/round/", 1)[1].split("?", 1)[0])
                return response(detail(round_id=round_id))
            pages.append(url)
            if len(pages) == 1:
                return response(
                    {
                        "results": [summary(round_id=active.start + 15)],
                        "_links": {
                            "next": {
                                "href": export.build_results_url(
                                    "17",
                                    active.account_group_id,
                                    active.start,
                                    active.end,
                                    cursor="empty",
                                )
                            }
                        },
                    }
                )
            if len(pages) == 2:
                return response(
                    {
                        "results": [],
                        "_links": {
                            "next": {
                                "href": export.build_results_url(
                                    "17",
                                    active.account_group_id,
                                    active.start,
                                    active.end,
                                    cursor="populated",
                                )
                            }
                        },
                    }
                )
            if len(pages) == 3:
                return response({"results": [summary(round_id=active.start + 30)]})
            raise AssertionError("unexpected path API request")

        wrappers, _, _ = export.collect_path_results(active, "token", get_json=get_json)
        self.assertEqual(len(pages), 3)
        self.assertEqual(len(wrappers), 2)

    def test_retries_only_transient_status_and_never_follows_redirects(self):
        active = request()
        calls = []
        delays = []

        def transient(url, *_):
            calls.append(url)
            if len(calls) == 1:
                return response({}, status=429, headers={"retry-after": "1"})
            if "/agent/" in url:
                return response(detail())
            return response({"results": [summary()]})

        wrappers, _, _ = export.collect_path_results(
            active,
            "token",
            get_json=transient,
            sleep=delays.append,
        )
        self.assertEqual(len(wrappers), 1)
        self.assertEqual(len(calls), 3)
        self.assertEqual(delays, [1.0])

    def test_rate_limit_uses_vendor_reset_and_fails_if_it_exceeds_deadline(self):
        with patch.object(export.time, "time", return_value=1_700_000_000):
            self.assertEqual(
                export._rate_limit_delay_seconds(
                    {"x-organization-rate-limit-reset": "1700000003"}
                ),
                3.0,
            )

        active = request(timeout_seconds=5)

        def rate_limited(url, *_):
            return response({}, status=429, headers={"retry-after": "10"})

        with self.assertRaisesRegex(
            export.ThousandEyesPathExportError, "reset exceeds"
        ):
            export.collect_path_results(
                active,
                "token",
                get_json=rate_limited,
                monotonic=lambda: 100.0,
            )

    def test_rate_limit_without_supported_reset_hint_is_not_retried(self):
        active = request()
        calls = []

        def rate_limited(url, *_):
            calls.append(url)
            return response({}, status=429)

        with self.assertRaisesRegex(
            export.ThousandEyesPathExportError, "omitted a supported reset delay"
        ):
            export.collect_path_results(active, "token", get_json=rate_limited)
        self.assertEqual(len(calls), 1)

        with self.assertRaises(export._HTTPFailure) as redirect:
            export._decode_object(response({}, status=302))
        self.assertFalse(redirect.exception.retryable)

        calls.clear()

        def unauthorized(url, *_):
            calls.append(url)
            return response({}, status=401)

        with self.assertRaisesRegex(
            export.ThousandEyesPathExportError, "request failed"
        ):
            export.collect_path_results(active, "token", get_json=unauthorized)
        self.assertEqual(len(calls), 1)

    def test_page_deadline_request_response_and_capture_limits_are_visible(self):
        active = request()
        cursor_index = 0

        def endless_pages(url, *_):
            nonlocal cursor_index
            cursor_index += 1
            current = active.start + cursor_index
            return response(
                {
                    "results": [summary(round_id=current)],
                    "_links": {
                        "next": {
                            "href": export.build_results_url(
                                "17",
                                "1234",
                                active.start,
                                active.end,
                                cursor=f"cursor-{cursor_index}",
                            )
                        }
                    },
                }
            )

        with patch.object(export, "MAX_PAGES_PER_TEST", 2):
            with self.assertRaisesRegex(export.ThousandEyesPathExportError, "page cap"):
                export.collect_path_results(active, "token", get_json=endless_pages)

        def too_large(url, *_):
            return export._HTTPResponse(200, b"{" + b" " * export.MAX_RESPONSE_BYTES)

        with self.assertRaisesRegex(export.ThousandEyesPathExportError, "byte limit"):
            export.collect_path_results(active, "token", get_json=too_large)

        with patch.object(export, "MAX_RESPONSE_BYTES_PER_CAPTURE", 1):
            with self.assertRaisesRegex(
                export.ThousandEyesPathExportError, "total response byte cap"
            ):
                export.collect_path_results(
                    active,
                    "token",
                    get_json=lambda *_: response({"results": []}),
                )

        with patch.object(export, "MAX_HTTP_REQUESTS", 0):
            with self.assertRaisesRegex(
                export.ThousandEyesPathExportError, "request cap"
            ):
                export.collect_path_results(
                    active,
                    "token",
                    get_json=lambda *_: response({"results": []}),
                )

        with patch.object(export, "MAX_ROUNDS_PER_CAPTURE", 0):
            with self.assertRaisesRegex(
                export.ThousandEyesPathExportError, "round cap"
            ):
                export.collect_path_results(
                    active,
                    "token",
                    get_json=lambda *_: response({"results": [summary()]}),
                )

        fake_clock = iter((10.0, 200.0))
        with self.assertRaisesRegex(export.ThousandEyesPathExportError, "time limit"):
            export.collect_path_results(
                active,
                "token",
                get_json=lambda *_: response({"results": []}),
                monotonic=lambda: next(fake_clock),
            )

    def test_transport_enforces_fixed_tls_host_headers_and_rejects_bad_routes(self):
        context = export._context(None)
        self.assertTrue(context.check_hostname)
        self.assertEqual(context.verify_mode, export.ssl.CERT_REQUIRED)
        for bad_url in (
            "http://api.thousandeyes.com/v7/test-results/17/path-vis?aid=1234",
            "https://evil.example/v7/test-results/17/path-vis?aid=1234",
            "https://api.thousandeyes.com/v7/test-results/17/path-vis/../users?aid=1234",
            "https://api.thousandeyes.com:444/v7/test-results/17/path-vis?aid=1234",
        ):
            with (
                self.subTest(url=bad_url),
                self.assertRaises(export.ThousandEyesPathExportError),
            ):
                export._valid_api_url(bad_url)
        self.assertEqual(export._parse_time("2023-11-14T22:13:20Z"), 1_700_000_000)
        with self.assertRaises(export.argparse.ArgumentTypeError):
            export._parse_time("2023-11-14T22:13:20")

        observed = {}

        class RedirectResponse:
            status = 302

            def getheader(self, _name, default=None):
                return default

        class FakeConnection:
            sock = None

            def __init__(self, host, *, port, timeout, context):
                observed.update(host=host, port=port, timeout=timeout, context=context)

            def request(self, method, path, *, headers):
                observed.update(method=method, path=path, headers=headers)

            def getresponse(self):
                return observed.get("response", RedirectResponse())

            def close(self):
                pass

        address = (
            export.socket.AF_INET,
            export.socket.SOCK_STREAM,
            0,
            "",
            ("127.0.0.1", 443),
        )
        active = request()
        with (
            patch.object(export.socket, "getaddrinfo", return_value=[address]),
            patch.object(export.http.client, "HTTPSConnection", FakeConnection),
        ):
            with self.assertRaises(export._HTTPFailure) as redirect:
                export._get_json(
                    export.build_results_url("17", "1234", active.start, active.end),
                    "credential-only-in-memory",
                    2,
                    context,
                )
        self.assertEqual(observed["host"], export.API_HOST)
        self.assertEqual(observed["method"], "GET")
        self.assertEqual(
            observed["headers"]["Authorization"],
            "Bearer credential-only-in-memory",
        )
        self.assertFalse(redirect.exception.retryable)

        class RateLimitResponse:
            status = 429

            def getheader(self, name, default=None):
                if name.lower() == "x-organization-rate-limit-reset":
                    return "1700000060"
                return default

        observed["response"] = RateLimitResponse()
        with (
            patch.object(export.socket, "getaddrinfo", return_value=[address]),
            patch.object(export.http.client, "HTTPSConnection", FakeConnection),
        ):
            with self.assertRaises(export._HTTPFailure) as rate_limited:
                export._get_json(
                    export.build_results_url("17", "1234", active.start, active.end),
                    "credential-only-in-memory",
                    2,
                    context,
                )
        self.assertTrue(rate_limited.exception.retryable)
        self.assertEqual(
            rate_limited.exception.headers,
            {"x-organization-rate-limit-reset": "1700000060"},
        )

    def test_json_and_output_checks_reject_duplicate_keys_and_checkout_paths(self):
        with self.assertRaises(export.ThousandEyesPathExportError):
            export._decode_object(
                export._HTTPResponse(200, b'{"results":[],"results":[]}')
            )
        with self.assertRaises(export.ThousandEyesPathExportError):
            export._outside_checkouts(Path(__file__).resolve())
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            symlink = directory / "link.ndjson"
            target = directory / "target.ndjson"
            target.write_bytes(b"existing")
            symlink.symlink_to(target)
            with self.assertRaises(FileExistsError):
                export._publish_new(symlink, b"new\n")

    def test_cli_reads_token_only_from_environment_and_never_starts_live_work_without_it(
        self,
    ):
        with tempfile.TemporaryDirectory() as temporary:
            now = int(time.time())
            args = [
                "--authority",
                "te-example",
                "--aid",
                "1234",
                "--test-id",
                "17",
                "--index",
                "te_paths",
                "--start",
                datetime.fromtimestamp(now - 300, timezone.utc).isoformat(),
                "--end",
                datetime.fromtimestamp(now - 60, timezone.utc).isoformat(),
                "--output",
                str(Path(temporary) / "out" / "capture.ndjson"),
                "--spool-dir",
                str(Path(temporary) / "spool"),
            ]
            with patch.dict(os.environ, {}, clear=True):
                with patch.object(export, "_get_json") as network:
                    self.assertEqual(export.main(args), 1)
                    network.assert_not_called()

    def test_script_help_runs_from_outside_repository_checkout(self):
        script = (
            Path(__file__).resolve().parents[1]
            / "tools"
            / "export_thousandeyes_paths.py"
        )
        with tempfile.TemporaryDirectory() as temporary:
            result = subprocess.run(
                [sys.executable, str(script), "--help"],
                cwd=temporary,
                capture_output=True,
                text=True,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--test-id TEST_ID", result.stdout)


if __name__ == "__main__":
    unittest.main()
