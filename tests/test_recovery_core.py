"""Focused unit regressions for the milestone-one recovery core."""

from __future__ import annotations

import sys
import socket
from copy import deepcopy
import unittest
import urllib.error
from io import BytesIO
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "splunk_app/splunk_adm/bin"
LIB = BIN / "lib"
if str(BIN) not in sys.path:
    sys.path.insert(0, str(BIN))
if str(LIB) not in sys.path:
    sys.path.insert(0, str(LIB))

from adm_recovery_lib.core import Refused, Recovery, Settings, Uncertain  # noqa: E402
from adm_recovery_lib.planner import TARGET_WINDOWS  # noqa: E402
from adm_recovery_lib.rest import Rest  # noqa: E402


TARGET = "ADM - Identity builder"
WINDOW = TARGET_WINDOWS[TARGET]


def aligned(value: int) -> int:
    return value - ((value - WINDOW["offset"]) % WINDOW["period"])


class NullApi:
    def __init__(self):
        self.calls = []

    def request(self, method, path, data=None, json_body=False, timeout=30):
        self.calls.append((method, path, data))
        if method == "GET" and "adm_recovery_state" in path:
            return []
        if method == "POST" and "adm_recovery_audit" in path:
            return {}
        raise AssertionError(f"unexpected API request: {method} {path}")


class RecoveryDeploymentTest(unittest.TestCase):
    def responses(self):
        return {
            "/services/server/info": {
                "entry": [
                    {
                        "content": {
                            "version": "10.6.0.5",
                            "product_type": "enterprise",
                            "mode": "normal",
                            "isForwarding": False,
                            "server_roles": [
                                "indexer",
                                "license_master",
                                "license_manager",
                                "kv_store",
                            ],
                        }
                    }
                ],
            },
            "/servicesNS/nobody/system/configs/conf-server/shclustering": {
                "entry": [{"content": {"disabled": True}}],
            },
            "/servicesNS/nobody/system/configs/conf-server/clustering": {
                "entry": [{"content": {"mode": "disabled"}}],
            },
            "/services/search/distributed/peers?count=0": {
                "entry": [],
                "paging": {"total": 0},
            },
        }

    def qualify(self, responses):
        class ReadOnlyApi:
            def request(self, method, path, **kwargs):
                if method != "GET":
                    raise AssertionError("qualification must be read-only")
                return deepcopy(responses[path])

        return Recovery(ReadOnlyApi()).qualify_deployment()

    def test_observed_standalone_shape_is_qualified(self):
        self.qualify(self.responses())

    def test_any_numeric_10_6_patch_release_is_qualified(self):
        for version in ("10.6.0.5", "10.6.1", "10.6.2.3"):
            with self.subTest(version=version):
                responses = self.responses()
                responses["/services/server/info"]["entry"][0]["content"]["version"] = (
                    version
                )
                self.qualify(responses)

    def test_other_or_malformed_versions_are_refused(self):
        for version in (
            "10.7.0",
            "10.5.9",
            "9.4.3",
            "10.60.0",
            "10.6",
            "10.6.",
            "10.6.0.5.1",
            "10.6.0.5-beta",
            "10.6.0.5\n",
            "10.6.x",
            "10.6.\u0660",
            "",
            None,
            10.6,
        ):
            with self.subTest(version=version):
                responses = self.responses()
                responses["/services/server/info"]["entry"][0]["content"]["version"] = (
                    version
                )
                with self.assertRaisesRegex(Refused, "10.6.x"):
                    self.qualify(responses)

    def test_unknown_cloud_forwarder_and_remote_search_head_are_refused(self):
        for key, value in (
            ("version", "10.7.0"),
            ("product_type", "cloud"),
            ("instance_type", "cloud"),
            ("instance_type", "unknown"),
            ("mode", "unknown"),
            ("isForwarding", True),
            ("server_roles", ["search_head", "kv_store"]),
            ("server_roles", "indexer"),
        ):
            with self.subTest(key=key, value=value), self.assertRaises(Refused):
                responses = self.responses()
                responses["/services/server/info"]["entry"][0]["content"][key] = value
                self.qualify(responses)
        for key in ("version", "product_type", "mode", "isForwarding", "server_roles"):
            with self.subTest(missing=key), self.assertRaises(Refused):
                responses = self.responses()
                del responses["/services/server/info"]["entry"][0]["content"][key]
                self.qualify(responses)

    def test_clustering_and_incomplete_evidence_are_refused(self):
        for path, replacement in (
            ("/services/server/info", {"entry": []}),
            ("/services/server/info", {"entry": [{"content": None}]}),
            (
                "/servicesNS/nobody/system/configs/conf-server/shclustering",
                {"entry": [{"content": {}}]},
            ),
            (
                "/servicesNS/nobody/system/configs/conf-server/shclustering",
                {"entry": [{"content": {"disabled": False}}]},
            ),
            (
                "/servicesNS/nobody/system/configs/conf-server/clustering",
                {"entry": [{"content": {"mode": "searchhead"}}]},
            ),
            (
                "/services/search/distributed/peers?count=0",
                {"entry": [{"content": {"disabled": True}}], "paging": {"total": 1}},
            ),
            (
                "/services/search/distributed/peers?count=0",
                {"entry": [], "paging": {"total": 1}},
            ),
            ("/services/search/distributed/peers?count=0", {"entry": []}),
        ):
            with (
                self.subTest(path=path, replacement=replacement),
                self.assertRaises(Refused),
            ):
                responses = self.responses()
                responses[path] = replacement
                self.qualify(responses)


class RecoveryPlanTest(unittest.TestCase):
    def recovery(self, now=2_000_000):
        recovery = Recovery(
            NullApi(), settings=Settings(enabled=True), wall=lambda: now
        )
        recovery.configuration_value = "qualified-config"
        return recovery, now

    def rows(self, *slots):
        return [
            {
                "savedsearch_name": TARGET,
                "status": "success",
                "scheduled_time": slot,
                "sid": "scheduler__unit",
            }
            for slot in slots
        ]

    def test_oldest_checkpoint_at_1445_minutes_and_recent_gap_is_plannable(self):
        recovery, now = self.recovery()
        boundary = aligned((now // 60) * 60 - 86400)
        checkpoint = boundary - WINDOW["period"]
        recovery.state = lambda key: None
        through = aligned(now - 1)
        slots = list(range(boundary, through + 1, WINDOW["period"]))
        gap = slots[-2]
        plan = recovery.plan(
            TARGET, self.rows(checkpoint, *(slot for slot in slots if slot != gap))
        )
        self.assertEqual([item["scheduled_time"] for item in plan], [gap])

    def test_last_checkpoint_exactly_through_is_a_noop(self):
        recovery, now = self.recovery()
        through = aligned(now - 1)
        checkpoint = through
        self.assertEqual(recovery.plan(TARGET, self.rows(checkpoint)), [])

    def test_stale_preceding_checkpoint_is_refused(self):
        recovery, now = self.recovery()
        boundary = aligned((now // 60) * 60 - 86400)
        with self.assertRaisesRegex(ValueError, "stale"):
            recovery.plan(TARGET, self.rows(boundary - 2 * WINDOW["period"]))

    def test_manual_sid_does_not_create_checkpoint(self):
        recovery, _ = self.recovery()
        rows = [
            {
                "savedsearch_name": TARGET,
                "status": "success",
                "scheduled_time": 1_999_700,
                "sid": "manual_replay",
            }
        ]
        with self.assertRaisesRegex(Refused, "no_successful_checkpoint"):
            recovery.plan(TARGET, rows)

    def test_backlog_over_budget_is_refused_before_pause(self):
        now = 2_000_000
        first = aligned(now - 1_500)
        slots = [
            {
                "name": TARGET,
                "scheduled_time": first + (index * 300),
                "earliest": first + (index * 300) - 86400,
                "latest": first + (index * 300) + 900,
                "index_earliest": first + (index * 300) - 600,
                "index_latest": first + (index * 300),
            }
            for index in range(6)
        ]

        class TooLarge(Recovery):
            def preflight(self, name):
                return {"is_scheduled": "1", "disabled": "0"}, "qualified-config"

            def state(self, key):
                return None

            def history(self, name):
                return []

            def plan(self, name, history):
                return slots

        api = NullApi()
        result = TooLarge(api, settings=Settings(enabled=True), wall=lambda: now).run(
            TARGET
        )
        self.assertEqual(result["status"], "refused")
        self.assertIn("backlog exceeds", result["reason"])
        self.assertTrue(api.calls)
        self.assertTrue(all("adm_recovery_audit" in call[1] for call in api.calls))

    def test_rollup_prior_failure_sid_is_refused(self):
        slot = 1_999_800
        plan = [self.rollup_slot(slot)]
        for row in (
            {"status": "failed", "sid": "scheduler__failed"},
            {"status": "success", "sid": "manual_replay"},
            {"status": "running", "sid": ""},
            {"status": "failed", "sid": ""},
        ):
            history = [
                {
                    "savedsearch_name": "ADM - Conversation rollup",
                    "scheduled_time": slot,
                    **row,
                }
            ]
            with (
                self.subTest(row=row),
                self.assertRaisesRegex(Refused, "manual reconciliation"),
            ):
                Recovery.require_unattempted_rollups(plan, history)

    def test_rollup_sidless_skip_is_allowed(self):
        plan = [self.rollup_slot(1_999_800)]
        history = [
            {
                "savedsearch_name": "ADM - Conversation rollup",
                "scheduled_time": 1_999_800,
                "status": "skipped",
            }
        ]
        Recovery.require_unattempted_rollups(plan, history)

    def test_builder_prior_execution_evidence_does_not_block(self):
        slot = 1_999_800
        plan = [{"name": TARGET, "scheduled_time": slot}]
        history = [
            {
                "savedsearch_name": "ADM - Identity builder",
                "scheduled_time": slot,
                "status": "failed",
                "sid": "manual",
            }
        ]
        Recovery.require_unattempted_rollups(plan, history)

    @staticmethod
    def rollup_slot(slot):
        return {
            "name": "ADM - Conversation rollup",
            "scheduled_time": slot,
            "earliest": slot - 86400,
            "latest": slot + 900,
            "index_earliest": slot - 600,
            "index_latest": slot - 300,
        }

    def test_total_budget_cannot_be_smaller_than_initial_budget(self):
        with self.assertRaisesRegex(Refused, "cover the initial backlog"):
            Settings(
                enabled=True, initial_backlog_limit=4, total_slot_limit=3
            ).validate()

    def test_summary_missing_rows_is_uncertain_without_retrying_dispatch(self):
        class Missing(Recovery):
            def search(self, *args, **kwargs):
                return []

        def fail_sleep(_seconds):
            raise Uncertain("summary did not converge")

        recovery = Missing(NullApi(), settings=Settings(enabled=True), sleep=fail_sleep)
        with self.assertRaises(Uncertain):
            manifest = {
                "accepted_records": 1,
                "rows": {"a" * 64: {"records": 1, "time": 10}},
            }
            recovery.verify_summary(manifest)

    def test_summary_changed_count_is_uncertain(self):
        class Changed(Recovery):
            def search(self, *args, **kwargs):
                return [
                    {
                        "rollup_id": "a" * 64,
                        "copies": "1",
                        "copies_with_records": "1",
                        "min_records": "2",
                        "max_records": "2",
                    }
                ]

        recovery = Changed(NullApi(), settings=Settings(enabled=True))
        manifest = {
            "accepted_records": 1,
            "rows": {"a" * 64: {"records": 1, "time": 10}},
        }
        with self.assertRaises(Uncertain):
            recovery.verify_summary(manifest)


class RestValidationTest(unittest.TestCase):
    def test_requires_local_https_origin_and_token(self):
        for uri in (
            "http://localhost:8089",
            "https://example.test:8089",
            "https://localhost:8089/path",
        ):
            with self.subTest(uri=uri), self.assertRaises(ValueError):
                Rest("token", uri=uri)
        with self.assertRaises(ValueError):
            Rest("", uri="https://localhost:8089")

    def test_request_rejects_non_local_paths(self):
        client = Rest("token")
        with self.assertRaises(ValueError):
            client.request("GET", "https://example.test/services/server/info")
        with self.assertRaises(ValueError):
            client.request("PATCH", "/services/server/info")

    def test_socket_timeout_at_tight_request_deadline_has_clear_recovery_reason(self):
        class TimeoutRecovery(Recovery):
            def preflight(self, _name):
                return {"is_scheduled": "1"}, "qualified-config"

        for label, transport_error, deadline, expected_reason in (
            (
                "socket.timeout at invocation deadline",
                socket.timeout("transport timeout"),
                0.05,
                "invocation deadline reached",
            ),
            (
                "URLError wrapping socket.timeout",
                urllib.error.URLError(socket.timeout("transport timeout")),
                0.05,
                "invocation deadline reached",
            ),
            (
                "30-second request cap before invocation deadline",
                socket.timeout("transport timeout"),
                60,
                "management request timed out",
            ),
        ):
            with self.subTest(transport=label):
                clock = [0.0]
                calls = []

                def fake_handler(**kwargs):
                    calls.append(kwargs["timeout"])

                    def transport(_url, _message, **_unused):
                        # The socket expires just after the bounded request
                        # timeout, as the vendored SDK's HTTPS handler does.
                        clock[0] += kwargs["timeout"] + 0.001
                        raise transport_error

                    return transport

                with patch("adm_recovery_lib.rest.binding.handler", fake_handler):
                    recovery = TimeoutRecovery(
                        Rest("unit-test-token"),
                        settings=Settings(enabled=True),
                        wall=lambda: 2_000_000,
                        monotonic=lambda: clock[0],
                    )
                    recovery.deadline = deadline
                    result = recovery.run(TARGET)

                self.assertEqual(result["status"], "refused")
                self.assertEqual(result["reason"], expected_reason)
                self.assertGreaterEqual(len(calls), 1)
                self.assertGreater(calls[0], 0)
                self.assertLessEqual(calls[0], min(30, deadline))

    def test_request_builds_json_post_without_retries(self):
        class Body:
            def read(self):
                return b"{}"

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        class Response:
            status = 200
            body = Body()

        class Context:
            instances = []

            def __init__(self, **kwargs):
                self.kwargs = kwargs
                self.instances.append(self)

            def post(self, path, **kwargs):
                self.call = (path, kwargs)
                return Response()

        with patch("adm_recovery_lib.rest.binding.Context", Context):
            result = Rest("token").request(
                "POST", "/services/foo?count=10", {"x": 1}, json_body=True
            )
        self.assertEqual(result, {})
        self.assertEqual(Context.instances[0].kwargs["retries"], 0)
        self.assertEqual(Context.instances[0].call[0], "/services/foo")
        self.assertEqual(Context.instances[0].call[1]["count"], "10")
        self.assertEqual(Context.instances[0].call[1]["output_mode"], "json")

    def test_real_sdk_transport_preserves_prequoted_saved_search_path(self):
        captured = []

        def fake_handler(**kwargs):
            self.assertTrue(kwargs["verify"])

            def transport(url, message, **_unused):
                captured.append((url, message))
                return {
                    "status": 200,
                    "reason": "OK",
                    "headers": [],
                    "body": BytesIO(b"{}"),
                }

            return transport

        path = (
            "/servicesNS/nobody/splunk_adm/saved/searches/"
            "ADM%20-%20Identity%20builder/dispatch"
        )
        with patch("adm_recovery_lib.rest.binding.handler", fake_handler):
            client = Rest("token")
            client.request("GET", path)
            client.request("POST", path, {"x": 1}, json_body=True)
            client.request("DELETE", path)

        self.assertEqual(len(captured), 3)
        for url, _message in captured:
            self.assertIn("ADM%20-%20Identity%20builder", url)
            self.assertNotIn("ADM%2520-%2520Identity%2520builder", url)
        self.assertEqual(captured[1][1]["body"], b'{"x": 1}')


if __name__ == "__main__":
    unittest.main()
