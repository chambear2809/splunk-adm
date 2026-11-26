"""Operator log: sanitized outcome lines, path safety, rotation and isolation."""

import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from tempfile import TemporaryDirectory
import time
import types
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
APP_BIN = ROOT / "splunk_app/splunk_adm/bin"
sys.path.insert(0, str(APP_BIN))
import adm_log_lib  # noqa: E402

TOKEN = "SessionCanary7f3c9d2e1b0a4c6d8e5f"
USER = "alice.canary"
PAYLOAD = "PayloadCanary-4111111111111111"
CANARIES = (TOKEN, USER, PAYLOAD, "Authorization", "Splunk ")
LINE = re.compile(
    r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z level=[A-Z]+ event=adm_request"
    r"( [a-z_]+=[A-Za-z0-9_.:-]+)+"
)


def canary_request(method="POST"):
    return {
        "method": method,
        "rest_path": f"/adm/collaboration/{PAYLOAD}",
        "query": [["q", PAYLOAD]],
        "session": {"authtoken": TOKEN, "user": USER},
        "headers": [
            ["Authorization", f"Splunk {TOKEN}"],
            ["X-Request-Id", TOKEN],
            ["Cookie", f"splunkd_8000={TOKEN}"],
        ],
        "payload": json.dumps({"secret": PAYLOAD, "owner": USER}),
    }


def canary_error():
    return RuntimeError(f"failed for {USER} with {TOKEN}: {PAYLOAD}")


class LogHome:
    """A canonical SPLUNK_HOME with var/log/splunk and a fresh helper state."""

    def __enter__(self):
        self._temp = TemporaryDirectory()
        self.home = Path(self._temp.name).resolve()
        self.directory = self.home / "var/log/splunk"
        self.directory.mkdir(parents=True)
        self.path = self.directory / adm_log_lib.LOG_NAME
        self._env = patch.dict(os.environ, {"SPLUNK_HOME": str(self.home)})
        self._env.start()
        adm_log_lib._reset_for_tests()
        return self

    def __exit__(self, *exc):
        adm_log_lib._reset_for_tests()
        self._env.stop()
        self._temp.cleanup()

    def text(self):
        adm_log_lib._reset_for_tests()
        return self.path.read_text(encoding="utf-8") if self.path.exists() else ""


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


class HelperTests(unittest.TestCase):
    def test_line_format_and_fields(self):
        with LogHome() as home:
            request = {
                "method": "GET",
                "headers": [["X-Request-Id", "0F8FAD5B-D9CB-469F-A165-70867728950E"]],
            }
            adm_log_lib.log_response(
                "adm_collaboration",
                {"status": 503, "payload": {"code": "unavailable", "error": "x y"}},
                started=time.monotonic(),
                request=request,
                error=KeyError("k"),
            )
            text = home.text()
        self.assertRegex(text.strip(), LINE)
        for field in (
            "level=ERROR",
            "outcome=failed",
            "handler=adm_collaboration",
            "method=GET",
            "status=503",
            "code=unavailable",
            "error_class=KeyError",
            "correlation_id=0f8fad5bd9cb469fa16570867728950e",
            "duration_ms=",
        ):
            self.assertIn(field, text)

    def test_messages_and_unsafe_values_are_never_written(self):
        with LogHome() as home:
            for payload in (
                {"code": f"{TOKEN} {PAYLOAD}", "error": f"for {USER}"},
                {"error": f"Bad value {PAYLOAD}"},
                {"code": "x" * 200},
                {"code": "bad\nlevel=INFO event=forged"},
            ):
                adm_log_lib.log_response(
                    "adm_baselines\nforged",
                    {"status": 400, "payload": payload},
                    started=time.monotonic(),
                    request=canary_request("PO ST"),
                    error=canary_error(),
                )
            text = home.text()
        for canary in CANARIES:
            self.assertNotIn(canary, text)
        self.assertNotIn("forged", text)
        lines = text.splitlines()
        self.assertEqual(len(lines), 4)
        for line in lines:
            self.assertRegex(line, LINE)
            self.assertIn("code=unspecified", line)
            self.assertIn("handler=unknown", line)
            self.assertNotIn("method=", line)

    def test_client_correlation_id_must_be_a_uuid(self):
        self.assertEqual(
            adm_log_lib.correlation_id(
                {
                    "headers": {
                        "X-Correlation-ID": "0f8fad5b-d9cb-469f-a165-70867728950e"
                    }
                }
            ),
            "0f8fad5bd9cb469fa16570867728950e",
        )
        for value in (TOKEN, "a" * 32 + "\n", "../../etc"):
            generated = adm_log_lib.correlation_id(
                {"headers": [["X-Request-Id", value]]}
            )
            self.assertRegex(generated, r"^[0-9a-f]{32}$")
            self.assertNotEqual(generated, value)
        self.assertNotEqual(adm_log_lib.correlation_id(), adm_log_lib.correlation_id())

    def test_default_level_records_only_refusals_and_failures_lazily(self):
        with LogHome() as home:
            adm_log_lib.log_outcome(
                "adm_recovery", started=time.monotonic(), status=200
            )
            self.assertFalse(home.path.exists())
            adm_log_lib.log_outcome(
                "adm_recovery", started=time.monotonic(), status=403
            )
            adm_log_lib.log_outcome(
                "adm_recovery", started=time.monotonic(), status=503
            )
            text = home.text()
        self.assertNotIn("outcome=ok", text)
        self.assertIn("level=INFO event=adm_request outcome=refused", text)
        self.assertIn("level=ERROR event=adm_request outcome=failed", text)

    def test_configured_levels(self):
        expectations = {
            "DEBUG": {"ok", "refused", "failed"},
            "info": {"refused", "failed"},
            "WARNING": {"failed"},
            "ERROR": {"failed"},
            "OFF": set(),
            "verbose": {"refused", "failed"},
        }
        for level, outcomes in expectations.items():
            with (
                self.subTest(level=level),
                LogHome() as home,
                TemporaryDirectory() as app,
            ):
                (Path(app) / "default").mkdir()
                (Path(app) / "default/adm_logging.conf").write_text(
                    "[logging]\nlevel = INFO\n"
                )
                (Path(app) / "local").mkdir()
                (Path(app) / "local/adm_logging.conf").write_text(
                    f"[logging]\nlevel = {level}\n"
                )
                with patch.object(adm_log_lib, "APP_ROOT", Path(app)):
                    adm_log_lib._reset_for_tests()
                    for status in (200, 404, 500):
                        adm_log_lib.log_outcome(
                            "adm_recovery", started=time.monotonic(), status=status
                        )
                text = home.text()
                written = set(re.findall(r"outcome=([a-z]+)", text))
                self.assertEqual(written, outcomes)

    def test_shipped_default_level_is_info(self):
        adm_log_lib._reset_for_tests()
        self.assertEqual(adm_log_lib._threshold(), adm_log_lib.LEVELS["INFO"])

    def test_alert_action_outcomes_use_exit_codes(self):
        with LogHome() as home:
            adm_log_lib.log_outcome(
                "adm_recovery",
                started=time.monotonic(),
                outcome="refused",
                code="recovery_disabled",
                exit_code=1,
            )
            adm_log_lib.log_outcome(
                "adm_recovery", started=time.monotonic(), code="uncertain", exit_code=1
            )
            text = home.text()
        self.assertIn("outcome=refused handler=adm_recovery exit_code=1", text)
        self.assertIn("outcome=failed handler=adm_recovery exit_code=1", text)
        self.assertNotIn("status=", text)


class PathSafetyTests(unittest.TestCase):
    def test_requires_canonical_absolute_home_and_log_directory(self):
        with TemporaryDirectory() as temp:
            base = Path(temp).resolve()
            real = base / "real"
            (real / "var/log/splunk").mkdir(parents=True)
            (base / "link").symlink_to(real, target_is_directory=True)
            elsewhere = base / "elsewhere"
            elsewhere.mkdir()
            linked_logs = base / "linked_logs"
            (linked_logs / "var/log").mkdir(parents=True)
            (linked_logs / "var/log/splunk").symlink_to(elsewhere)
            (base / "missing/var/log").mkdir(parents=True)
            (base / "file/var/log").mkdir(parents=True)
            (base / "file/var/log/splunk").write_text("")
            cases = {
                "": None,
                "relative/splunk": None,
                str(base / "link"): None,
                str(real / ".." / "real"): None,
                str(linked_logs): None,
                str(base / "missing"): None,
                str(base / "file"): None,
                str(real): real / "var/log/splunk/splunk_adm.log",
            }
            for home, expected in cases.items():
                with (
                    self.subTest(home=home),
                    patch.dict(os.environ, {"SPLUNK_HOME": home}),
                ):
                    self.assertEqual(adm_log_lib.log_path(), expected)

    def test_unset_home_disables_logging_without_error(self):
        with patch.dict(os.environ, {}, clear=True):
            adm_log_lib._reset_for_tests()
            adm_log_lib.log_outcome(
                "adm_recovery", started=time.monotonic(), status=503
            )
            self.assertIsNone(adm_log_lib._logger)
        adm_log_lib._reset_for_tests()

    def test_never_writes_through_a_symlinked_or_hardlinked_log_file(self):
        with LogHome() as home, TemporaryDirectory() as other:
            target = Path(other) / "target"
            target.write_text("original\n")
            home.path.symlink_to(target)
            adm_log_lib.log_outcome(
                "adm_recovery", started=time.monotonic(), status=503
            )
            adm_log_lib._reset_for_tests()
            self.assertEqual(target.read_text(), "original\n")
            home.path.unlink()
            os.link(target, home.path)
            adm_log_lib.log_outcome(
                "adm_recovery", started=time.monotonic(), status=503
            )
            adm_log_lib._reset_for_tests()
            self.assertEqual(target.read_text(), "original\n")

    def test_new_log_file_is_private(self):
        with LogHome() as home:
            adm_log_lib.log_outcome(
                "adm_recovery", started=time.monotonic(), status=503
            )
            adm_log_lib._reset_for_tests()
            self.assertEqual(home.path.stat().st_mode & 0o777, 0o600)


class RotationTests(unittest.TestCase):
    def _sizes(self, directory):
        return {
            path.name: path.stat().st_size
            for path in directory.iterdir()
            if path.name.startswith(adm_log_lib.LOG_NAME)
        }

    def test_rotation_bounds_file_size_and_backup_count(self):
        with LogHome() as home, patch.object(adm_log_lib, "MAX_BYTES", 2048):
            for _ in range(400):
                adm_log_lib.log_outcome(
                    "adm_collaboration", started=time.monotonic(), status=503
                )
            adm_log_lib._reset_for_tests()
            sizes = self._sizes(home.directory)
        self.assertEqual(
            set(sizes),
            {"splunk_adm.log"} | {f"splunk_adm.log.{index}" for index in range(1, 4)},
        )
        self.assertTrue(all(0 < size <= 2048 for size in sizes.values()), sizes)

    def test_rotation_bounds_hold_across_independent_writers(self):
        with LogHome() as home:
            writers = [
                adm_log_lib._SafeRotatingHandler(
                    str(home.path), maxBytes=1024, backupCount=2, delay=True
                )
                for _ in range(2)
            ]
            formatter = adm_log_lib._UtcFormatter("%(asctime)s %(message)s")
            try:
                for index in range(300):
                    writer = writers[index % 2]
                    writer.setFormatter(formatter)
                    record = adm_log_lib.logging.LogRecord(
                        "t",
                        40,
                        __file__,
                        1,
                        "event=adm_request x=" + "y" * 40,
                        None,
                        None,
                    )
                    writer.handle(record)
            finally:
                for writer in writers:
                    writer.close()
            sizes = self._sizes(home.directory)
        self.assertLessEqual(len(sizes), 3)
        self.assertTrue(all(size <= 1024 for size in sizes.values()), sizes)


class HandlerLoggingTests(unittest.TestCase):
    """Feed canaries through real handler failure paths and inspect the log."""

    def _assert_clean(self, text, handler, status):
        self.assertIn(f"handler={handler}", text)
        self.assertIn(f"status={status}", text)
        for canary in CANARIES:
            self.assertNotIn(canary, text)
        for line in text.splitlines():
            self.assertRegex(line, LINE)

    def _scenarios(self):
        settings = load_handler("adm_settings.py", "oplog_settings")
        baselines = load_handler("adm_baselines.py", "oplog_baselines")
        collaboration = load_handler("adm_collaboration.py", "oplog_collaboration")
        observer = load_handler("adm_observer_mapping.py", "oplog_observer")
        cases = load_handler("adm_cases.py", "oplog_cases")
        return [
            (
                "adm_deployment_settings",
                settings.SettingsHandler,
                patch.multiple(
                    settings,
                    handle_request=Mock(side_effect=canary_error()),
                    source_ids=Mock(return_value=frozenset()),
                ),
            ),
            (
                "adm_dependency_monitoring",
                baselines.BaselinesHandler,
                patch.object(baselines, "handle", side_effect=canary_error()),
            ),
            (
                "adm_collaboration",
                collaboration.CollaborationHandler,
                patch.object(
                    collaboration, "handle_request", side_effect=canary_error()
                ),
            ),
            (
                "adm_observer_mapping",
                observer.ObserverMappingHandler,
                patch.object(observer, "handle_request", side_effect=canary_error()),
            ),
            (
                "adm_investigations",
                cases.CasesHandler,
                patch.object(
                    cases,
                    "supervise",
                    return_value=cases.supervise.__globals__["unavailable"](),
                ),
            ),
        ]

    def test_failures_log_handler_status_and_class_but_no_secrets(self):
        for handler, cls, seam in self._scenarios():
            with self.subTest(handler=handler), LogHome() as home, seam:
                response = cls("command", "argument").handle(
                    json.dumps(canary_request())
                )
                self.assertEqual(response["status"], 503)
                text = home.text()
                self._assert_clean(text, handler, 503)
                self.assertIn("outcome=failed", text)
                if handler != "adm_investigations":
                    self.assertIn("error_class=RuntimeError", text)
                    self.assertIn("method=POST", text)

    def test_unauthenticated_refusals_are_logged(self):
        handlers = {
            "adm_deployment_settings": load_handler(
                "adm_settings.py", "oplog_settings_401"
            ).SettingsHandler,
            "adm_collaboration": load_handler(
                "adm_collaboration.py", "oplog_collaboration_401"
            ).CollaborationHandler,
            "adm_observer_mapping": load_handler(
                "adm_observer_mapping.py", "oplog_observer_401"
            ).ObserverMappingHandler,
        }
        request = canary_request()
        request["session"] = {"user": USER}
        for handler, cls in handlers.items():
            with self.subTest(handler=handler), LogHome() as home:
                response = cls("command", "argument").handle(json.dumps(request))
                self.assertEqual(response["status"], 401)
                text = home.text()
                self._assert_clean(text, handler, 401)
                self.assertIn("level=INFO", text)
                self.assertIn("code=forbidden", text)

    def test_unparseable_body_is_logged_without_content(self):
        cls = load_handler(
            "adm_collaboration.py", "oplog_bad_json"
        ).CollaborationHandler
        with LogHome() as home:
            response = cls("c", "a").handle(f'{{"session": "{TOKEN}", {PAYLOAD}')
            self.assertEqual(response["status"], 503)
            text = home.text()
        self._assert_clean(text, "adm_collaboration", 503)
        self.assertIn("error_class=JSONDecodeError", text)

    def test_real_case_supervisor_refusal_is_logged_in_parent(self):
        cases = load_handler("adm_cases.py", "oplog_cases_real")
        with LogHome() as home:
            response = cases.CasesHandler("c", "a").handle(
                json.dumps(canary_request()) + " " * (1024 * 1024)
            )
            self.assertEqual(response["status"], 413)
            text = home.text()
        self._assert_clean(text, "adm_investigations", 413)
        self.assertIn("code=body_too_large", text)

    def test_supervisor_exception_is_logged_and_reraised(self):
        cases = load_handler("adm_cases.py", "oplog_cases_raise")
        with (
            LogHome() as home,
            patch.object(cases, "supervise", side_effect=canary_error()),
        ):
            with self.assertRaises(RuntimeError):
                cases.CasesHandler("c", "a").handle(json.dumps(canary_request()))
            text = home.text()
        self._assert_clean(text, "adm_investigations", 503)
        self.assertIn("error_class=RuntimeError", text)

    def test_logging_failure_does_not_change_any_response(self):
        breakages = (
            patch.object(adm_log_lib, "_threshold", side_effect=RuntimeError("x")),
            patch.object(adm_log_lib, "_get_logger", side_effect=OSError("disk")),
            patch.object(adm_log_lib, "correlation_id", side_effect=MemoryError()),
            patch.object(
                adm_log_lib._SafeRotatingHandler,
                "_open",
                side_effect=PermissionError("denied"),
            ),
        )
        requests = (canary_request(), {**canary_request(), "session": {}})
        for handler, cls, seam in self._scenarios():
            for request in requests:
                with LogHome(), seam:
                    expected = cls("c", "a").handle(json.dumps(request))
                for breakage in breakages:
                    with self.subTest(handler=handler), LogHome(), seam, breakage:
                        actual = cls("c", "a").handle(json.dumps(request))
                        self.assertEqual(actual, expected)

    def test_success_response_is_returned_unchanged(self):
        collaboration = load_handler("adm_collaboration.py", "oplog_success")
        result = {"records": [PAYLOAD]}
        with (
            LogHome() as home,
            patch.object(collaboration, "handle_request", return_value=result),
        ):
            response = collaboration.CollaborationHandler("c", "a").handle(
                json.dumps(canary_request("GET"))
            )
            text = home.text()
        self.assertEqual(
            response,
            {
                "status": 200,
                "payload": result,
                "headers": {"Cache-Control": "no-store"},
            },
        )
        self.assertEqual(text, "")


class RecoveryActionLoggingTests(unittest.TestCase):
    def _run(self, conf, stdin):
        with TemporaryDirectory() as temp:
            base = Path(temp).resolve()
            app = base / "apps/splunk_adm"
            shutil.copytree(
                APP_BIN, app / "bin", ignore=shutil.ignore_patterns("__pycache__")
            )
            (app / "default").mkdir()
            (app / "default/adm_recovery.conf").write_text(conf)
            logs = base / "var/log/splunk"
            logs.mkdir(parents=True)
            completed = subprocess.run(
                [sys.executable, str(app / "bin/adm_recovery.py")],
                input=stdin,
                capture_output=True,
                text=True,
                timeout=60,
                env={"SPLUNK_HOME": str(base), "PATH": os.environ.get("PATH", "")},
                check=False,
            )
            log = logs / "splunk_adm.log"
            text = log.read_text() if log.exists() else ""
        return completed, text

    def test_failure_with_secret_in_payload_and_exception_message(self):
        conf = (ROOT / "splunk_app/splunk_adm/default/adm_recovery.conf").read_text()
        conf = conf.replace("enabled = 0", "enabled = 1").replace(
            "initial_backlog_limit = 4", f"initial_backlog_limit = {PAYLOAD}"
        )
        stdin = json.dumps(
            {"app": "splunk_adm", "session_key": TOKEN, "owner": USER, "result": {}}
        )
        completed, text = self._run(conf, stdin)
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(
            json.loads(completed.stdout),
            {"status": "uncertain", "error_type": "ValueError"},
        )
        self.assertEqual(completed.stderr, "")
        for canary in CANARIES:
            self.assertNotIn(canary, text)
        self.assertRegex(text.strip(), LINE)
        self.assertIn("level=ERROR", text)
        self.assertIn("handler=adm_recovery exit_code=1 code=uncertain", text)
        self.assertIn("error_class=ValueError", text)

    def test_disabled_refusal_is_logged(self):
        conf = (ROOT / "splunk_app/splunk_adm/default/adm_recovery.conf").read_text()
        completed, text = self._run(conf, json.dumps({"session_key": TOKEN}))
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(json.loads(completed.stdout)["status"], "refused")
        self.assertIn("level=INFO", text)
        self.assertIn("outcome=refused handler=adm_recovery", text)
        self.assertIn("code=recovery_disabled", text)
        self.assertNotIn(TOKEN, text)


class DependencyWatchActionTests(unittest.TestCase):
    def invoke(self, home, *, enabled=True, error=None):
        from adm_dependency_watch import main

        host = Mock()
        executor = host.watch_executor.return_value
        executor.execute.return_value = {
            "id": "22222222-2222-2222-2222-222222222222",
            "revision": 3,
            "resultWithheld": True,
        }
        if error is not None:
            executor.execute.side_effect = error
        payload = {
            "app": "splunk_adm",
            "session_key": TOKEN,
            "result": {
                "binding_id": "11111111-1111-1111-1111-111111111111",
                "start": 10,
                "end": 20,
                "request_id": PAYLOAD,
            },
        }
        code = main(
            stdin=io.BytesIO(json.dumps(payload).encode()),
            stdout=io.StringIO(),
            configuration=lambda: {"enabled": enabled},
            host_factory=lambda _token: host,
        )
        return code, home.text()

    def test_outcomes_are_logged_without_secrets(self):
        with LogHome() as home:
            code, text = self.invoke(home, enabled=False)
            self.assertEqual(code, 1)
            self.assertIn("outcome=refused handler=adm_dependency_watch", text)
            self.assertIn("code=disabled", text)
        with LogHome() as home:
            code, text = self.invoke(home, error=canary_error())
            self.assertEqual(code, 1)
            self.assertIn("level=ERROR", text)
            self.assertIn("outcome=failed handler=adm_dependency_watch", text)
            self.assertIn("code=unavailable_or_uncertain", text)
            self.assertIn("error_class=RuntimeError", text)
            for canary in CANARIES:
                self.assertNotIn(canary, text)
            for line in text.splitlines():
                self.assertRegex(line, LINE)

    def test_success_is_debug_only(self):
        with LogHome() as home:
            code, text = self.invoke(home)
            self.assertEqual(code, 0)
            self.assertEqual(text, "")


class PackagingTests(unittest.TestCase):
    def test_props_assign_operator_sourcetype(self):
        import configparser

        props = configparser.RawConfigParser(strict=True)
        props.read(ROOT / "splunk_app/splunk_adm/default/props.conf")
        self.assertEqual(
            props.get("source::...splunk_adm.log*", "sourcetype"), "adm:operator"
        )
        stanza = props["adm:operator"]
        self.assertEqual(stanza["TZ"], "UTC")
        self.assertEqual(stanza["SHOULD_LINEMERGE"], "false")

    def test_spec_documents_every_level(self):
        spec = (ROOT / "splunk_app/splunk_adm/README/adm_logging.conf.spec").read_text()
        for level in adm_log_lib.LEVELS:
            self.assertIn(level, spec)


if __name__ == "__main__":
    unittest.main()
