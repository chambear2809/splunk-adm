"""Unit coverage for the disposable case-request fault payload."""

import importlib.util
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import Mock, patch

HOOK = Path(__file__).parent / "splunk/case_request_fault_hook.py"
spec = importlib.util.spec_from_file_location("case_request_fault_hook_test", HOOK)
hook = importlib.util.module_from_spec(spec)
spec.loader.exec_module(hook)


class CaseRequestFaultHookTests(unittest.TestCase):
    def test_normal_import_never_activates(self):
        with patch.object(hook, "_activate") as activate:
            exec(
                compile(HOOK.read_text(), str(HOOK), "exec"),
                {"__name__": "test_import"},
            )
        activate.assert_not_called()

    def test_activation_requires_exact_worker_path(self):
        with patch.object(hook, "_read_config", return_value=None) as read:
            with patch.object(hook, "sys") as fake_sys:
                fake_sys.argv = [hook.WORKER + ".bak"]
                hook._activate()
                read.assert_not_called()
                fake_sys.argv = [hook.WORKER]
                hook._activate()
                read.assert_called_once_with()

    def test_exact_worker_exits_without_logging_on_invalid_config(self):
        with patch.object(hook, "_read_config", side_effect=hook._InvalidConfig):
            with patch.object(hook, "_patch") as patch_hook:
                with patch.object(hook, "sys") as fake_sys:
                    fake_sys.argv = [hook.WORKER]
                    with patch.object(
                        hook.os, "_exit", side_effect=RuntimeError("exit")
                    ) as exit_process:
                        with self.assertRaisesRegex(RuntimeError, "exit"):
                            hook._activate()
        exit_process.assert_called_once_with(78)
        patch_hook.assert_not_called()

    def test_private_config_accepts_exact_schema_and_rejects_bad_modes(self):
        with tempfile.TemporaryDirectory() as temp:
            old_dir, old_config = hook.CONTROL_DIR, hook.CONFIG
            hook.CONTROL_DIR = Path(temp)
            hook.CONFIG = Path(temp) / "fault.json"
            try:
                import os

                os.chmod(temp, 0o700)
                hook.CONFIG.write_text(
                    '{"mode":"precommit","request_id":"r1","generation":"precommit"}'
                )
                os.chmod(hook.CONFIG, 0o600)
                self.assertEqual(hook._read_config()["request_id"], "r1")
                hook.CONFIG.write_text(
                    '{"mode":"wat","request_id":"r1","generation":"precommit"}'
                )
                os.chmod(hook.CONFIG, 0o600)
                with self.assertRaises(hook._InvalidConfig):
                    hook._read_config()
                hook.CONFIG.write_text(
                    '{"mode":"precommit","request_id":"","generation":"precommit"}'
                )
                os.chmod(hook.CONFIG, 0o600)
                with self.assertRaises(hook._InvalidConfig):
                    hook._read_config()
            finally:
                hook.CONTROL_DIR, hook.CONFIG = old_dir, old_config

    def test_off_does_not_patch_or_import_sdk(self):
        with patch.object(hook, "__import__", create=True) as importer:
            hook._patch({"mode": "off", "generation": "auth", "request_id": None})
        importer.assert_not_called()

    def test_auth_wraps_only_fixed_current_context_path(self):
        original = Mock(return_value="ok")
        rest = type("Rest", (), {"simpleRequest": original})()
        with patch.object(hook, "_stall") as stall:
            hook._patch(
                {"mode": "auth", "generation": "auth", "request_id": None},
                {"rest": rest},
            )
            self.assertEqual(rest.simpleRequest("/services/server/info"), "ok")
            self.assertEqual(
                rest.simpleRequest(
                    "/services/authentication/current-context?output_mode=json"
                ),
                "ok",
            )
        stall.assert_called_once_with("auth")

    def test_config_wraps_only_fixed_persistence_btool_and_preserves_call(self):
        command = [
            "/opt/splunk/bin/splunk",
            "btool",
            "--app=splunk_adm",
            "--user=nobody",
            "adm_investigations",
            "list",
            "persistence",
        ]
        config = {"mode": "config", "generation": "config", "request_id": None}
        with (
            patch.object(hook, "_stall") as stall,
            patch.object(hook.subprocess, "run") as run,
        ):
            hook._patch(config)
            hook.subprocess.run(command, check=False)
            hook.subprocess.run([*command[:-1], "capture_transport"])
        self.assertEqual(stall.call_count, 1)
        self.assertEqual(run.call_count, 2)

    def test_commit_stalls_at_exact_request_and_on_correct_side_of_commit(self):
        with tempfile.TemporaryDirectory() as temp:
            dbpath = Path(temp) / "cases.sqlite"
            db = sqlite3.connect(dbpath)
            db.execute("CREATE TABLE requests (request_id TEXT)")
            db.commit()
            db.execute("INSERT INTO requests VALUES ('match')")
            db.commit()
            old_path = hook.DATABASE
            old_connect = sqlite3.connect
            hook.DATABASE = str(dbpath)
            try:
                for mode in ("precommit", "postcommit"):
                    sqlite3.connect = old_connect
                    events = []
                    instrumented = None
                    with patch.object(
                        hook,
                        "_stall",
                        side_effect=lambda gen: events.append(
                            (gen, instrumented.in_transaction)
                        ),
                    ):
                        hook._patch(
                            {"mode": mode, "generation": mode, "request_id": "match"}
                        )
                        instrumented = sqlite3.connect(str(dbpath))
                        instrumented.execute(
                            "UPDATE requests SET request_id='match' WHERE request_id='match'"
                        )
                        instrumented.commit()
                        instrumented.close()
                    self.assertEqual(events, [(mode, mode == "precommit")])
            finally:
                sqlite3.connect = old_connect
                hook.DATABASE = old_path
                db.close()


if __name__ == "__main__":
    unittest.main()
