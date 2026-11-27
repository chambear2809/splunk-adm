"""Envelope size limits, recursion bounds, and response headers for persistent REST handlers."""

import importlib.util
import json
from pathlib import Path
import sys
import types
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
APP_BIN = ROOT / "splunk_app/splunk_adm/bin"

EXPECTED_HEADERS = {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
}


def load_handler(script, module_name):
    application = types.ModuleType("splunk.persistconn.application")
    application.PersistentServerConnectionApplication = object
    stubs = {
        "splunk": types.ModuleType("splunk"),
        "splunk.persistconn": types.ModuleType("splunk.persistconn"),
        "splunk.persistconn.application": application,
    }
    with patch.dict(sys.modules, stubs):
        spec = importlib.util.spec_from_file_location(module_name, APP_BIN / script)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    return module


def _handler_specs():
    collaboration = load_handler("adm_collaboration.py", "envlim_collaboration")
    observer = load_handler("adm_observer_mapping.py", "envlim_observer")
    settings = load_handler("adm_settings.py", "envlim_settings")
    baselines = load_handler("adm_baselines.py", "envlim_baselines")
    return [
        (
            "adm_collaboration",
            collaboration,
            collaboration.CollaborationHandler,
            256 * 1024,
            {"code": "body_too_large"},
            lambda: patch.object(
                collaboration, "handle_request", return_value={"state": "absent"}
            ),
            lambda: patch.object(
                collaboration, "handle_request", side_effect=RuntimeError("boom")
            ),
        ),
        (
            "adm_observer_mapping",
            observer,
            observer.ObserverMappingHandler,
            256 * 1024,
            {"code": "body_too_large"},
            lambda: patch.object(
                observer, "handle_request", return_value={"state": "absent"}
            ),
            lambda: patch.object(
                observer, "handle_request", side_effect=RuntimeError("boom")
            ),
        ),
        (
            "adm_settings",
            settings,
            settings.SettingsHandler,
            256 * 1024,
            {"code": "body_too_large"},
            lambda: patch.multiple(
                settings,
                handle_request=Mock(return_value={"state": "absent"}),
                source_ids=Mock(return_value=frozenset()),
            ),
            lambda: patch.multiple(
                settings,
                handle_request=Mock(side_effect=RuntimeError("boom")),
                source_ids=Mock(return_value=frozenset()),
            ),
        ),
        (
            "adm_baselines",
            baselines,
            baselines.BaselinesHandler,
            1024 * 1024,
            {"error": "body_too_large"},
            lambda: patch.object(
                baselines,
                "handle",
                return_value=(200, {"available": False}, {"Cache-Control": "no-store"}),
            ),
            lambda: patch.object(baselines, "handle", side_effect=RuntimeError("boom")),
        ),
    ]


class RestEnvelopeLimitsTests(unittest.TestCase):
    def setUp(self):
        self.specs = _handler_specs()

    def _assert_security_headers(self, response):
        headers = response.get("headers")
        self.assertIsInstance(headers, dict)
        for key, value in EXPECTED_HEADERS.items():
            self.assertEqual(headers.get(key), value)

    def test_envelope_limits_are_configured(self):
        for name, module, _cls, expected_limit, *_rest in self.specs:
            with self.subTest(handler=name):
                self.assertEqual(module.MAX_ENVELOPE_BYTES, expected_limit)

    def test_oversized_str_bytes_and_multibyte_utf8_reject_413_without_json_loads(self):
        for name, module, cls, limit, expected_subset, *_rest in self.specs:
            oversized_str = "a" * (limit + 1)
            oversized_bytes = b"b" * (limit + 1)
            # Each 2-byte UTF-8 char stays below len() limit in codepoints but
            # exceeds MAX_ENVELOPE_BYTES once encoded to UTF-8.
            multibyte_chars = (limit // 2) + 1
            oversized_utf8 = "\u00e9" * multibyte_chars
            self.assertLessEqual(len(oversized_utf8), limit)
            self.assertGreater(len(oversized_utf8.encode("utf-8")), limit)

            cases = (
                ("str", oversized_str),
                ("bytes", oversized_bytes),
                ("multibyte_utf8", oversized_utf8),
            )
            for label, raw in cases:
                with (
                    self.subTest(handler=name, kind=label),
                    patch.object(
                        module.json,
                        "loads",
                        side_effect=AssertionError("json.loads must not be called"),
                    ),
                ):
                    response = cls("cmd", "arg").handle(raw)
                    self.assertEqual(response["status"], 413)
                    self._assert_security_headers(response)
                    for key, value in expected_subset.items():
                        self.assertEqual(response["payload"].get(key), value)

    def test_non_string_and_invalid_utf8_envelopes_return_400_without_json_loads(self):
        for name, module, cls, *_rest in self.specs:
            for label, bad_input in (
                ("none", None),
                ("int", 42),
                ("dict", {}),
                ("lone_surrogate", "\ud800"),
                ("invalid_utf8_bytes", b"\xff\xfe"),
            ):
                with (
                    self.subTest(handler=name, kind=label),
                    patch.object(
                        module.json,
                        "loads",
                        side_effect=AssertionError("json.loads must not be called"),
                    ),
                ):
                    response = cls("cmd", "arg").handle(bad_input)
                    self.assertEqual(response["status"], 400)
                    self._assert_security_headers(response)

    def test_deeply_nested_json_returns_400_without_leaking_trace(self):
        depth = sys.getrecursionlimit() + 500
        deep_json = "[" * depth + "]" * depth
        for name, _module, cls, limit, *_rest in self.specs:
            self.assertLess(len(deep_json.encode("utf-8")), limit)
            with self.subTest(handler=name):
                response = cls("cmd", "arg").handle(deep_json)
                self.assertEqual(response["status"], 400)
                self._assert_security_headers(response)
                serialized = json.dumps(response)
                self.assertNotIn("Traceback", serialized)
                self.assertNotIn("RecursionError", serialized)
                self.assertNotIn("File ", serialized)

    def test_non_object_json_envelope_returns_400_with_headers(self):
        for name, _module, cls, *_rest in self.specs:
            for body in ("[]", "null", "123", '"text"'):
                with self.subTest(handler=name, body=body):
                    response = cls("cmd", "arg").handle(body)
                    self.assertEqual(response["status"], 400)
                    self._assert_security_headers(response)

    def test_normal_and_fallback_503_responses_include_security_headers(self):
        valid_envelope = json.dumps(
            {
                "method": "GET",
                "session": {"authtoken": "synthetic-token"},
            }
        )
        for name, _module, cls, _limit, _subset, ok_patch, fail_patch in self.specs:
            with self.subTest(handler=name, path="normal_str"), ok_patch():
                response = cls("cmd", "arg").handle(valid_envelope)
                self.assertEqual(response["status"], 200)
                self._assert_security_headers(response)
            with self.subTest(handler=name, path="normal_bytes"), ok_patch():
                response = cls("cmd", "arg").handle(valid_envelope.encode("utf-8"))
                self.assertEqual(response["status"], 200)
                self._assert_security_headers(response)
            with self.subTest(handler=name, path="fallback_503"), fail_patch():
                response = cls("cmd", "arg").handle(valid_envelope)
                self.assertEqual(response["status"], 503)
                self._assert_security_headers(response)
                self.assertNotIn("boom", json.dumps(response))

    def test_utf8_bom_bytes_accepted_and_invalid_utf8_rejected_without_json_loads(self):
        valid_envelope = json.dumps(
            {
                "method": "GET",
                "session": {"authtoken": "synthetic-token"},
            }
        )
        bom_envelope = b"\xef\xbb\xbf" + valid_envelope.encode("utf-8")
        for name, module, cls, _limit, _subset, ok_patch, _fail_patch in self.specs:
            with self.subTest(handler=name, kind="utf8_bom_bytes"), ok_patch():
                response = cls("cmd", "arg").handle(bom_envelope)
                self.assertEqual(response["status"], 200)
                self._assert_security_headers(response)
            with (
                self.subTest(handler=name, kind="invalid_utf8_bytes"),
                patch.object(
                    module.json,
                    "loads",
                    side_effect=AssertionError("json.loads must not be called"),
                ),
            ):
                response = cls("cmd", "arg").handle(b"\xff\xfe")
                self.assertEqual(response["status"], 400)
                self._assert_security_headers(response)

    def test_baselines_preserves_custom_headers_and_fills_defaults(self):
        baselines = load_handler("adm_baselines.py", "envlim_baselines_headers")
        valid_envelope = json.dumps(
            {
                "method": "GET",
                "session": {"authtoken": "synthetic-token"},
            }
        )
        with patch.object(
            baselines,
            "handle",
            return_value=(
                200,
                {"ok": True},
                {
                    "cache-control": "public",
                    "X-Content-Type-Options": "unsafe",
                    "X-Custom-Header": "preserved",
                },
            ),
        ):
            response = baselines.BaselinesHandler("cmd", "arg").handle(valid_envelope)
        self.assertEqual(response["status"], 200)
        self._assert_security_headers(response)
        self.assertNotIn("cache-control", response["headers"])
        self.assertEqual(response["headers"]["X-Custom-Header"], "preserved")


if __name__ == "__main__":
    unittest.main()
