"""Local action adapter checks; not an installed Splunk invocation qualification."""

import copy
import io
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock

sys.path.insert(
    0, str(Path(__file__).resolve().parents[1] / "splunk_app/splunk_adm/bin")
)
from adm_dependency_watch import MAX_INPUT_BYTES, main  # noqa: E402
from adm_baselines_lib.splunk_host import HostUnavailable, SplunkHost  # noqa: E402


class WatchActionTests(unittest.TestCase):
    def setUp(self):
        self.payload = {
            "app": "splunk_adm",
            "session_key": "private-test-token",
            "result": {
                "binding_id": "11111111-1111-1111-1111-111111111111",
                "start": 10,
                "end": 20,
                "request_id": "stable-delivery-key",
            },
        }
        self.host = Mock()
        self.host.watch_executor.return_value.execute.return_value = {
            "id": "22222222-2222-2222-2222-222222222222",
            "revision": 3,
            "resultWithheld": True,
        }
        self.factory = Mock(return_value=self.host)

    def invoke(self, payload=None, raw=None, enabled=True):
        self.output = io.StringIO()
        code = main(
            stdin=io.BytesIO(
                raw if raw is not None else json.dumps(payload or self.payload).encode()
            ),
            stdout=self.output,
            configuration=lambda: {"enabled": enabled},
            host_factory=self.factory,
        )
        return code, json.loads(self.output.getvalue())

    def test_disabled_does_not_consume_input_or_construct_host(self):
        stream = Mock()
        output = io.StringIO()
        self.assertEqual(
            main(
                stdin=stream,
                stdout=output,
                configuration=lambda: {"enabled": False},
                host_factory=self.factory,
            ),
            1,
        )
        stream.read.assert_not_called()
        self.factory.assert_not_called()
        self.assertEqual(json.loads(output.getvalue()), {"status": "disabled"})

    def test_one_window_and_generic_acknowledgment(self):
        self.assertEqual(self.invoke(), (0, {"status": "committed"}))
        self.factory.assert_called_once_with("private-test-token")
        self.host.watch_executor.return_value.execute.assert_called_once_with(
            self.payload["result"]["binding_id"],
            {"start": 10, "end": 20},
            "stable-delivery-key",
        )
        self.assertNotIn("private-test-token", self.output.getvalue())
        self.assertNotIn("revision", self.output.getvalue())

    def test_bounded_strict_input_never_dispatches(self):
        invalid = [
            b"x" * (MAX_INPUT_BYTES + 1),
            b'{"app":"one","app":"two"}',
            b'{"app":NaN}',
            b"\xff",
        ]
        for field, value in (
            ("start", True),
            ("start", "010"),
            ("start", " 10"),
            ("start", "1e1"),
            ("start", "+10"),
            ("start", "10.0"),
            ("start", 10.0),
            ("start", -1),
            ("end", 400),
            ("request_id", "x\n"),
        ):
            payload = copy.deepcopy(self.payload)
            payload["result"][field] = value
            invalid.append(json.dumps(payload).encode())
        for key in ("principal", "capture", "query"):
            payload = copy.deepcopy(self.payload)
            payload["result"][key] = "forged"
            invalid.append(json.dumps(payload).encode())
        for raw in invalid:
            with self.subTest(raw_length=len(raw)):
                self.assertEqual(
                    self.invoke(raw=raw), (1, {"status": "invalid_request"})
                )
        self.factory.assert_not_called()

    def test_wire_metadata_is_ignored_and_decimal_timestamps_are_normalized(self):
        payload = copy.deepcopy(self.payload)
        payload.update(
            {
                "configuration": {"enabled": True, "provider": "hostile"},
                "owner": "another-principal",
                "search_name": "test",
                "sid": "unused",
                "results_file": "/must/not/read",
                "results_link": "https://must-not-connect.invalid/",
                "server_uri": "https://must-not-connect.invalid/",
                "server_host": "unused",
            }
        )
        payload["result"].update({"start": "10", "end": "20"})
        self.assertEqual(self.invoke(payload=payload), (0, {"status": "committed"}))
        self.factory.assert_called_once_with("private-test-token")
        self.host.watch_executor.return_value.execute.assert_called_once_with(
            self.payload["result"]["binding_id"],
            {"start": 10, "end": 20},
            "stable-delivery-key",
        )

    def test_post_dispatch_error_remains_uncertain_and_private(self):
        for error in (
            TimeoutError("private-test-token"),
            ValueError("secret reference"),
        ):
            self.host.watch_executor.return_value.execute.side_effect = error
            self.assertEqual(self.invoke(), (1, {"status": "unavailable_or_uncertain"}))
            self.assertNotIn(str(error), self.output.getvalue())

    def test_default_provider_and_disabled_host_refuse_before_database(self):
        host = SplunkHost(
            "private-test-token", execution_configuration=lambda: {"enabled": True}
        )
        host.database = Mock(side_effect=AssertionError("must not open database"))
        host.qualify = Mock(side_effect=AssertionError("must not use runtime"))
        with self.assertRaises(HostUnavailable):
            host.watch_executor()
        host.source_provider = Mock()
        host.execution_configuration = lambda: {"enabled": False}
        with self.assertRaises(HostUnavailable):
            host.watch_executor()
        host.database.assert_not_called()
        host.qualify.assert_not_called()


if __name__ == "__main__":
    unittest.main()
