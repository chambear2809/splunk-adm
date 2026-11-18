from contextlib import closing
import io
import json

from tests.test_baseline_executor import ExecutorTests
from adm_baseline_provision import main
from adm_baselines_lib.store import Conflict


class ProvisionTests(ExecutorTests):
    def test_request_retry_preserves_identity_and_rejects_changed_definition(self):
        first = self.executor.create_binding(
            self.id, "w", self.selection, request_id="key"
        )
        retry = self.executor.create_binding(
            self.id, "w", self.selection, request_id="key"
        )
        self.assertEqual(first, retry)
        changed = dict(self.selection, namespace="other")
        # The synthetic provider accepts the selection; the journal rejects key reuse.
        with self.assertRaises(Conflict):
            self.executor.create_binding(self.id, "w", changed, request_id="key")

    def test_bounded_stdin_and_retry(self):
        class Host:
            def __init__(inner, token):
                if token != "session":
                    raise ValueError()

            def watch_executor(inner):
                return self.executor

        payload = {
            "session_key": "session",
            "baseline_id": self.id,
            "watch_id": "w",
            "selection": self.selection,
            "request_id": "request",
        }

        def call(raw):
            output = io.StringIO()
            code = main(stdin=io.BytesIO(raw), stdout=output, host_factory=Host)
            return code, json.loads(output.getvalue())

        raw = json.dumps(payload).encode()
        code, first = call(raw)
        self.assertEqual(code, 0)
        self.assertFalse(first["enabled"])
        self.assertEqual(call(raw), (code, first))
        self.assertEqual(call(b'{"session_key":"a","session_key":"b"}')[0], 1)
        self.assertEqual(call(b"x" * 65537)[0], 1)

    def test_management_retries_and_inspection(self):
        class Host:
            def __init__(inner, token):
                if token != "session":
                    raise ValueError()

            def watch_executor(inner):
                return self.executor

            def watch_manager(inner):
                return self.executor.stopper

        def invoke(operation, **fields):
            payload = {"session_key": "session", "operation": operation, **fields}
            output = io.StringIO()
            status = main(
                stdin=io.BytesIO(json.dumps(payload).encode()),
                stdout=output,
                host_factory=Host,
            )
            return status, json.loads(output.getvalue())

        status, created = invoke(
            "create",
            baseline_id=self.id,
            watch_id="w",
            selection=self.selection,
            request_id="create",
        )
        self.assertEqual(status, 0)
        ident = created["id"]
        command = {"binding_id": ident, "expected_revision": 1, "request_id": "enable"}
        status, enabled = invoke("enable", **command)
        self.assertEqual(
            (status, enabled["revision"], enabled["enabled"]), (0, 2, True)
        )
        self.assertEqual(invoke("enable", **command), (status, enabled))
        self.assertEqual(invoke("enable", **dict(command, expected_revision=2))[0], 1)
        self.provider.denied = True
        self.assertEqual(invoke("enable", **command)[0], 1)
        disable = {"binding_id": ident, "expected_revision": 2, "request_id": "stop"}
        status, stopped = invoke("disable", **disable)
        self.assertEqual(
            (status, stopped["revision"], stopped["enabled"]), (0, 3, False)
        )
        self.assertEqual(invoke("disable", **disable), (status, stopped))
        status, receipt = invoke("receipt", binding_id=ident, request_id="enable")
        self.assertEqual(
            (
                status,
                receipt["expected_revision"],
                receipt["revision"],
                receipt["enabled"],
            ),
            (0, 1, 2, True),
        )
        self.assertEqual(invoke("find_created", request_id="create")[1]["id"], ident)
        self.assertEqual(
            invoke("receipt", binding_id=ident, request_id="missing")[0], 1
        )
        self.assertEqual(invoke("disable", **dict(disable, expected_revision=3))[0], 1)
        status, current = invoke("inspect", binding_id=ident)
        self.assertEqual(
            (status, current["revision"], current["enabled"]), (0, 3, False)
        )
        self.user = "bob"
        self.assertEqual(invoke("inspect", binding_id=ident)[0], 1)
        self.assertEqual(invoke("receipt", binding_id=ident, request_id="enable")[0], 1)
        self.assertEqual(invoke("find_created", request_id="create")[0], 1)
        self.user = "alice"
        self.admin = False
        self.assertEqual(invoke("inspect", binding_id=ident)[0], 1)

    def test_management_receipt_migrates_v1_and_preserves_run_journal(self):
        import sqlite3
        from adm_baselines_lib.run_store import ExecutionStore
        from adm_baselines_lib.executor import WatchStopper

        binding = self.executor.create_binding(
            self.id, "w", self.selection, request_id="create"
        )
        binding = self.executor.set_enabled(binding["id"], 1, True)
        run = self.journal.begin(
            "alice",
            "run",
            binding["id"],
            {"start": 10, "end": 20},
            "a" * 32,
            expected_binding_revision=2,
        )
        self.journal.release(run["id"], "alice", "a" * 32, run["revision"])
        with closing(sqlite3.connect(self.journal.path)) as db:
            db.execute("DROP TABLE management_receipts")
            db.execute("PRAGMA user_version=1")
            db.commit()
        old = ExecutionStore(
            self.journal.path, clock=lambda: self.now, existing_only=True
        )
        manager = WatchStopper(old, lambda: self.user, lambda _: self.admin)
        first = manager.set_enabled(binding["id"], 2, False, request_id="stop")
        self.assertEqual(
            first, manager.set_enabled(binding["id"], 2, False, request_id="stop")
        )
        with closing(sqlite3.connect(self.journal.path)) as db:
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 2)
            self.assertEqual(
                db.execute("SELECT count(*) FROM management_receipts").fetchone()[0], 1
            )
            self.assertEqual(
                db.execute("SELECT state FROM runs").fetchone()[0], "capture_unknown"
            )

    def test_receipt_capacity_reserves_stops(self):
        import sqlite3
        from adm_baselines_lib.store import QuotaExceeded

        item = self.executor.create_binding(
            self.id, "w", self.selection, request_id="create"
        )
        with closing(sqlite3.connect(self.journal.path)) as db:
            db.executemany(
                "INSERT INTO management_receipts VALUES (?,?,?,?,?,?)",
                [("alice", f"prior-{i}", item["id"], 1, 1, 1) for i in range(896)],
            )
            db.commit()
        with self.assertRaises(QuotaExceeded):
            self.journal.set_enabled(item["id"], 1, True, request_id="enable")
        receipt = self.journal.set_enabled(item["id"], 1, False, request_id="stop")
        self.assertEqual(
            receipt, self.journal.set_enabled(item["id"], 1, False, request_id="stop")
        )

    def test_receipts_reserve_each_legacy_enabled_binding(self):
        import sqlite3
        from adm_baselines_lib.store import QuotaExceeded

        first = self.executor.create_binding(self.id, "w", self.selection)
        second = self.journal.create_binding(dict(first["definition"], watchId="w2"))
        inactive = self.journal.create_binding(dict(first["definition"], watchId="w3"))
        for item in (first, second):
            self.journal.set_enabled(item["id"], 1, True)
        with closing(sqlite3.connect(self.journal.path)) as db:
            db.executemany(
                "INSERT INTO management_receipts VALUES (?,?,?,?,?,?)",
                [("alice", f"prior-{i}", inactive["id"], 1, 0, 1) for i in range(1021)],
            )
            db.commit()

        self.journal.set_enabled(inactive["id"], 1, False, request_id="noop")
        with self.assertRaises(QuotaExceeded):
            self.journal.set_enabled(inactive["id"], 1, False, request_id="extra")
        with self.assertRaises(QuotaExceeded):
            self.journal.set_enabled(inactive["id"], 1, True)
        self.assertFalse(self.journal.binding(inactive["id"])["enabled"])
        for number, item in enumerate((first, second)):
            receipt = self.journal.set_enabled(
                item["id"], 2, False, request_id=f"stop-{number}"
            )
            self.assertEqual(
                receipt,
                self.journal.set_enabled(
                    item["id"], 2, False, request_id=f"stop-{number}"
                ),
            )
        with closing(sqlite3.connect(self.journal.path)) as db:
            self.assertEqual(
                db.execute("SELECT count(*) FROM management_receipts").fetchone()[0],
                1024,
            )

    def test_unkeyed_stop_remains_available_for_overcommitted_old_journal(self):
        import sqlite3
        from adm_baselines_lib.store import QuotaExceeded

        item = self.executor.create_binding(self.id, "w", self.selection)
        self.journal.set_enabled(item["id"], 1, True)
        with closing(sqlite3.connect(self.journal.path)) as db:
            db.executemany(
                "INSERT INTO management_receipts VALUES (?,?,?,?,?,?)",
                [("alice", f"prior-{i}", item["id"], 1, 1, 2) for i in range(1024)],
            )
            db.commit()
        with self.assertRaises(QuotaExceeded):
            self.journal.set_enabled(item["id"], 2, False, request_id="stop")
        self.assertFalse(self.journal.set_enabled(item["id"], 2, False)["enabled"])

    def test_concurrent_exact_management_requests_commit_once(self):
        from concurrent.futures import ThreadPoolExecutor

        item = self.executor.create_binding(
            self.id, "w", self.selection, request_id="create"
        )

        def attempt(_):
            return self.journal.set_enabled(item["id"], 1, True, request_id="enable")

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(attempt, range(2)))
        self.assertEqual(results[0], results[1])
        self.assertEqual(results[0]["revision"], 2)
        self.assertEqual(self.journal.binding(item["id"])["revision"], 2)


from tests.test_dependency_watch_host import WatchHostIntegrationTests  # noqa: E402


class ProvisionHostTests(WatchHostIntegrationTests):
    def test_cli_with_authenticated_host_and_source_unavailable_stop(self):
        def invoke(operation, **fields):
            payload = {
                "session_key": "synthetic-token",
                "operation": operation,
                **fields,
            }
            output = io.StringIO()
            status = main(
                stdin=io.BytesIO(json.dumps(payload).encode()),
                stdout=output,
                host_factory=lambda _: self.host,
            )
            return status, json.loads(output.getvalue())

        status, created = invoke(
            "create",
            baseline_id=self.baseline,
            watch_id="w",
            selection={
                "service": "s",
                "environment": "e",
                "cluster": "c",
                "namespace": "n",
            },
            request_id="new-binding",
        )
        self.assertEqual(status, 0)
        ident = created["id"]
        enable = {"binding_id": ident, "expected_revision": 1, "request_id": "enable"}
        self.assertEqual(invoke("enable", **enable)[0], 0)
        self.host.source_provider = None
        self.assertEqual(invoke("enable", **enable)[0], 1)
        stop = {"binding_id": ident, "expected_revision": 2, "request_id": "stop"}
        self.assertEqual(invoke("disable", **stop)[0], 0)
        self.assertEqual(invoke("disable", **stop)[0], 0)
        self.assertFalse(invoke("inspect", binding_id=ident)[1]["enabled"])
        self.context["roles"] = []
        self.assertEqual(invoke("inspect", binding_id=ident)[0], 1)
