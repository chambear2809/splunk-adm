import json
import signal
import subprocess
import sys
import time
from pathlib import Path
from unittest import TestCase, mock

from tools import discover_feature_sources as discovery


class FakeClient:
    def __init__(self, cleanup_fails=False):
        self.calls = []
        self.cleanup_fails = cleanup_fails

    def call(self, method, path, data=None, timeout=10):
        self.calls.append((method, path, data, timeout))
        if method == "DELETE":
            if self.cleanup_fails:
                raise discovery.Refused("http_500")
            return {}
        if method == "POST":
            return {"sid": "123.abc"}
        if "/results?" in path:
            return {
                "preview": False,
                "results": [
                    {
                        "index": "safe_idx",
                        "sourcetype": "otel:traces",
                        "count": "3",
                        "first": "99900",
                        "last": "99999",
                    },
                    {
                        "index": "safe_idx",
                        "sourcetype": "private-source",
                        "count": "1",
                        "first": "99900",
                        "last": "99999",
                    },
                ],
            }
        return {
            "entry": [
                {"content": {"isDone": True, "dispatchState": "DONE", "resultCount": 2}}
            ]
        }


class DiscoveryTests(TestCase):
    def test_direct_script_help_works(self):
        root = Path(__file__).resolve().parents[1]
        for script in ("discover_feature_sources.py", "discover_field_presence.py"):
            result = subprocess.run(
                [sys.executable, str(root / "tools" / script), "--help"],
                cwd=root,
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("--profile", result.stdout)

    def test_wall_deadline_interrupts_slow_body_and_restores_outer_timer(self):
        client = discovery.Client("https://unit.splunkcloud.com:8089", "u", "p")
        response = mock.MagicMock()
        response.__enter__.return_value = response

        def stalled_read(_limit):
            time.sleep(0.3)
            return b"{}"

        response.read.side_effect = stalled_read
        old_handler = signal.getsignal(signal.SIGALRM)
        old_timer = signal.getitimer(signal.ITIMER_REAL)
        self.assertEqual(old_timer[0], 0)

        def outer(_signum, _frame):
            pass

        try:
            signal.signal(signal.SIGALRM, outer)
            signal.setitimer(signal.ITIMER_REAL, 2)
            with mock.patch.object(client.opener, "open", return_value=response):
                with self.assertRaisesRegex(discovery.Refused, "deadline"):
                    client.call("GET", "/services/server/info", timeout=0.03)
            self.assertIs(signal.getsignal(signal.SIGALRM), outer)
            remaining, _interval = signal.getitimer(signal.ITIMER_REAL)
            self.assertGreater(remaining, 1)
            self.assertLess(remaining, 2)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, old_handler)

    def test_shorter_outer_alarm_is_not_extended(self):
        old_handler = signal.getsignal(signal.SIGALRM)
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL)[0], 0)

        def outer(_signum, _frame):
            raise discovery.Refused("outer_deadline")

        try:
            signal.signal(signal.SIGALRM, outer)
            signal.setitimer(signal.ITIMER_REAL, 0.03)
            with self.assertRaisesRegex(discovery.Refused, "outer_deadline"):
                with discovery.wall_deadline(2):
                    time.sleep(0.3)
            self.assertIs(signal.getsignal(signal.SIGALRM), outer)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, old_handler)

    def test_fixed_query_and_cleanup_and_redacted_results(self):
        client = FakeClient()
        result = discovery.discover(client, ["safe_idx"], now=100000)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["cleanup"], "ok")
        self.assertEqual(result["families"]["otel"]["count"], 3)
        self.assertEqual(result["unknown_rows"], 1)
        self.assertNotIn("private-source", json.dumps(result))
        self.assertEqual(
            client.calls[0][2],
            {
                "search": '| tstats count min(_time) AS first max(_time) AS last WHERE index IN("safe_idx") BY index sourcetype',
                "earliest_time": "13600",
                "latest_time": "100000",
                "max_time": "20",
                "ttl": "60",
                "auto_cancel": "30",
                "exec_mode": "normal",
            },
        )
        self.assertLessEqual(client.calls[0][3], 35)
        self.assertIn("count=100", client.calls[2][1])
        self.assertEqual(client.calls[-1][0], "DELETE")

    def test_cleanup_failure_invalidates_success(self):
        result = discovery.discover(
            FakeClient(cleanup_fails=True), ["safe_idx"], now=100000
        )
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["cleanup"], "failed")

    def test_failed_job_still_cleans_up(self):
        client = FakeClient()
        original = client.call

        def call(method, path, data=None, timeout=10):
            if method == "GET":
                raise discovery.Refused("deadline")
            return original(method, path, data, timeout)

        client.call = call
        result = discovery.discover(client, ["safe_idx"], now=100000)
        self.assertEqual(result["reason"], "deadline")
        self.assertEqual(result["cleanup"], "ok")
        self.assertEqual(client.calls[-1][0], "DELETE")

    def test_profile_is_validated_before_constructing_client(self):
        path = Path.home() / ".splunk/splunk-adm/credentials"
        profiles = {
            "cloud": {
                "SPLUNK_URI": "https://unit.splunkcloud.com:8089",
                "SPLUNK_CLOUD_STACK": "unit",
                "SPLUNK_USER": "u",
                "SPLUNK_PASS": "p",
            }
        }
        with (
            mock.patch.object(
                discovery, "parse_credentials", return_value=(profiles, [])
            ),
            mock.patch.object(discovery, "_profile_errors", return_value=[]),
            mock.patch.object(discovery, "Client") as client,
        ):
            discovery.cloud_client(path, "cloud")
            client.assert_called_once_with(
                "https://unit.splunkcloud.com:8089", "u", "p"
            )
            profiles["cloud"]["SPLUNK_URI"] = "https://wrong.example:8089"
            with self.assertRaisesRegex(discovery.Refused, "target_mismatch"):
                discovery.cloud_client(path, "cloud")

    def test_reject_query_injection_and_unexpected_target(self):
        with self.assertRaises(discovery.Refused):
            discovery.discover(FakeClient(), ['bad") | delete'])
        with self.assertRaises(discovery.Refused):
            discovery.cloud_client(Path("/tmp/credentials"), "cloud")

    def test_client_blocks_proxies_redirects_and_oversize(self):
        client = discovery.Client("https://unit.splunkcloud.com:8089", "u", "p")
        self.assertTrue(
            any(isinstance(h, discovery.NoRedirect) for h in client.opener.handlers)
        )
        self.assertFalse(
            any(
                isinstance(h, discovery.request.ProxyHandler)
                for h in client.opener.handlers
            )
        )
        self.assertIsNone(
            discovery.NoRedirect().redirect_request(None, None, 302, None, None, None)
        )
        https = next(
            h
            for h in client.opener.handlers
            if isinstance(h, discovery.request.HTTPSHandler)
        )
        self.assertTrue(https._context.check_hostname)
        self.assertEqual(https._context.verify_mode, discovery.ssl.CERT_REQUIRED)
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.read.return_value = b"x" * (discovery.LIMIT + 1)
        with mock.patch.object(client.opener, "open", return_value=response):
            with self.assertRaisesRegex(discovery.Refused, "body_limit"):
                client.call("GET", "/services/server/info")
        response.read.assert_called_once_with(discovery.LIMIT + 1)

    def test_deep_json_is_redacted(self):
        client = discovery.Client("https://unit.splunkcloud.com:8089", "u", "p")
        response = mock.MagicMock()
        response.__enter__.return_value = response
        response.read.return_value = b"[" * 2000 + b"]" * 2000
        with (
            mock.patch.object(client.opener, "open", return_value=response),
            mock.patch.object(discovery.json, "loads", side_effect=RecursionError),
        ):
            with self.assertRaisesRegex(discovery.Refused, "request_failed"):
                client.call("GET", "/services/server/info")

    def test_macro_definition_cannot_insert_query(self):
        class MacroClient:
            def call(self, method, path):
                name = path.split("/")[-1].split("?")[0]
                return {
                    "entry": [
                        {"name": name, "content": {"definition": "index=safe | delete"}}
                    ]
                }

        with self.assertRaisesRegex(discovery.Refused, "macro_definition_unsupported"):
            discovery.indexes(MacroClient())
