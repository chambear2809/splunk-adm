"""Synthetic in-process host wiring only; no installed provider qualification."""

from contextlib import closing
import io
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

sys.path.insert(
    0, str(Path(__file__).resolve().parents[1] / "splunk_app/splunk_adm/bin")
)
from adm_baselines_lib.executor import RunBudget  # noqa: E402
from adm_baselines_lib.splunk_host import HostUnavailable, SplunkHost  # noqa: E402
from adm_dependency_watch import main  # noqa: E402
from tests.test_baseline_executor import Provider  # noqa: E402


class WatchHostIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.db = self.root / "splunk_adm_baselines/baselines.sqlite"
        self.context = {
            "username": "alice",
            "roles": ["admin"],
            "capabilities": ["adm_investigate"],
        }
        self.server = {
            "product_type": "enterprise",
            "version": "10.6.0.5",
            "activeLicenseGroup": "Trial",
        }
        self.provider = Provider()
        self.lock_checks = []

        def verify_unlocked(kind):
            if self.db.exists():
                with closing(
                    sqlite3.connect(self.db, timeout=0.05, isolation_level=None)
                ) as db:
                    db.execute("BEGIN IMMEDIATE")
                    db.rollback()
                self.lock_checks.append(kind)

        def request(path):
            verify_unlocked("request")
            return self.context if path.endswith("current-context") else self.server

        def configuration():
            verify_unlocked("baseline config")
            return {
                "mode": "single_search_head",
                "platform": "enterprise",
                "source_mode": "unavailable",
            }

        def execution_configuration():
            verify_unlocked("execution config")
            return {"enabled": True}

        def topology():
            verify_unlocked("topology")
            return {"disabled": "true"}

        self.host = SplunkHost(
            "synthetic-token",
            request=request,
            database_root=str(self.root),
            topology=topology,
            configuration=configuration,
            source_provider=self.provider,
            clock=lambda: 100,
            execution_configuration=execution_configuration,
        )
        self.executor = self.host.watch_executor()
        self.seed = self.executor.store_factory("alice", self.provider, RunBudget())
        self.baseline = self.seed.create("alice", "create", "baseline", "base")["id"]
        self.seed.set_watch(
            "alice",
            "watch",
            self.baseline,
            1,
            {"id": "w", "threshold": 1, "cooldownSeconds": 0, "expectedWindows": []},
        )
        selection = {
            "service": "s",
            "environment": "e",
            "cluster": "c",
            "namespace": "n",
        }
        binding = self.executor.create_binding(self.baseline, "w", selection)
        self.binding = self.executor.set_enabled(
            binding["id"], binding["revision"], True
        )

    def action(self, request_id="stable"):
        payload = {
            "app": "splunk_adm",
            "session_key": "synthetic-token",
            "result": {
                "binding_id": self.binding["id"],
                "start": 10,
                "end": 20,
                "request_id": request_id,
            },
        }
        output = io.StringIO()
        code = main(
            stdin=io.BytesIO(json.dumps(payload).encode()),
            stdout=output,
            configuration=lambda: {"enabled": True},
            host_factory=lambda _token: self.host,
        )
        return code, json.loads(output.getvalue()), output.getvalue()

    def test_real_host_execution_and_action_retry_use_shared_budget_and_no_writer_io(
        self,
    ):
        self.provider.budgets.clear()
        code, body, raw = self.action()
        self.assertEqual((code, body), (0, {"status": "committed"}))
        self.assertEqual(self.provider.calls, 1)
        self.assertGreater(len(self.provider.budgets), 3)
        self.assertEqual(len({id(budget) for budget in self.provider.budgets}), 1)
        self.assertNotIn("synthetic-token", raw)
        self.assertNotIn("inserted", raw)
        self.provider.budgets.clear()
        self.assertEqual(self.action()[:2], (0, {"status": "committed"}))
        self.assertEqual(self.provider.calls, 1)
        self.assertEqual(len({id(budget) for budget in self.provider.budgets}), 1)
        self.assertGreater(len(self.lock_checks), 0)
        self.assertIn("request", self.lock_checks)
        self.assertIn("execution config", self.lock_checks)
        self.assertIn("baseline config", self.lock_checks)
        self.assertIn("topology", self.lock_checks)
        self.assertEqual(
            len(self.seed.occurrences("alice", self.baseline, "w")["items"]), 1
        )

    def test_admin_nonowner_and_current_role_loss_prevent_execution(self):
        self.context["username"] = "bob"
        self.assertEqual(self.action()[:2], (1, {"status": "unavailable_or_uncertain"}))
        self.assertEqual(self.provider.calls, 0)
        self.context["username"] = "alice"
        self.context["roles"] = ["user"]
        self.assertEqual(self.action()[:2], (1, {"status": "unavailable_or_uncertain"}))
        self.assertEqual(self.provider.calls, 0)

    def test_role_lost_during_capture_stops_evaluation(self):
        original = self.provider.capture

        def revoke(*args, **kwargs):
            result = original(*args, **kwargs)
            self.context["roles"] = ["user"]
            return result

        self.provider.capture = revoke
        self.assertEqual(self.action()[:2], (1, {"status": "unavailable_or_uncertain"}))
        self.assertEqual(self.provider.calls, 1)
        self.context["roles"] = ["admin"]
        self.assertEqual(
            self.seed.occurrences("alice", self.baseline, "w")["items"], []
        )
        self.assertEqual(self.action()[:2], (0, {"status": "committed"}))
        self.assertEqual(self.provider.calls, 1)

    def test_default_source_none_does_not_touch_storage(self):
        with tempfile.TemporaryDirectory() as root:
            host = SplunkHost(
                "synthetic-token",
                database_root=root,
                source_provider=None,
                execution_configuration=lambda: {"enabled": True},
            )
            with self.assertRaises(HostUnavailable):
                host.watch_executor()
            self.assertEqual(list(Path(root).iterdir()), [])

    def test_execution_configuration_uses_fixed_bounded_command(self):
        with (
            mock.patch.dict("os.environ", {"SPLUNK_HOME": "/opt/splunk"}),
            mock.patch(
                "adm_baselines_lib.splunk_host.subprocess.run",
                return_value=SimpleNamespace(stdout=b"[execution]\nenabled=true\n"),
            ) as call,
        ):
            self.assertEqual(SplunkHost._execution_configuration(), {"enabled": True})
            self.assertEqual(
                call.call_args.args[0],
                [
                    "/opt/splunk/bin/splunk",
                    "btool",
                    "--app=splunk_adm",
                    "--user=nobody",
                    "adm_dependency_watch",
                    "list",
                    "execution",
                ],
            )
            self.assertEqual(call.call_args.kwargs["timeout"], 3)
            call.return_value.stdout = b"x" * 16385
            with self.assertRaises(HostUnavailable):
                SplunkHost._execution_configuration()


if __name__ == "__main__":
    unittest.main()
