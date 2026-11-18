"""Connection lifecycle regressions for app-owned SQLite stores."""

import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from contextlib import closing
from unittest import mock

sys.path.insert(
    0, str(Path(__file__).resolve().parents[1] / "splunk_app/splunk_adm/bin")
)
import adm_baselines_lib.run_store as run_store_module  # noqa: E402
import adm_baselines_lib.store as baseline_module  # noqa: E402
import adm_cases_lib.store as cases_module  # noqa: E402


class TrackingConnection(sqlite3.Connection):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.was_closed = False

    def close(self):
        self.was_closed = True
        super().close()


class FailingConnection:
    def __init__(self):
        self.was_closed = False

    def execute(self, *_args, **_kwargs):
        raise sqlite3.OperationalError("setup failed")

    def close(self):
        self.was_closed = True


class ForeignKeyFailingJournalConnection(FailingConnection):
    def __init__(self):
        super().__init__()
        self.statements = []
        self.row_factory = None

    def execute(self, statement, *_args, **_kwargs):
        self.statements.append(statement)
        if statement == "PRAGMA journal_mode":
            return self
        if statement == "PRAGMA foreign_keys=ON":
            raise sqlite3.OperationalError("foreign-key setup failed")
        raise AssertionError(f"unexpected SQL during connection setup: {statement}")

    def fetchone(self):
        return ("delete",)


class SQLiteConnectionLifecycleTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)

    def test_store_setup_failure_closes_connection(self):
        cases = [
            (cases_module, cases_module.CaseStore),
            (baseline_module, baseline_module.BaselineStore),
        ]
        journal_path = Path(self.temp.name) / "watch_runs.sqlite"
        journal_path.touch(mode=0o600)
        run_store = object.__new__(run_store_module.ExecutionStore)
        run_store.path = journal_path
        run_store.existing_only = True

        for module, store_or_type in cases:
            label = (
                type(store_or_type).__name__
                if not isinstance(store_or_type, type)
                else store_or_type.__name__
            )
            with self.subTest(store=label):
                connection = FailingConnection()
                store = (
                    object.__new__(store_or_type)
                    if isinstance(store_or_type, type)
                    else store_or_type
                )
                if isinstance(store_or_type, type):
                    store.path = Path(self.temp.name) / (label + ".db")
                with mock.patch.object(
                    module.sqlite3, "connect", return_value=connection
                ):
                    with self.assertRaisesRegex(
                        sqlite3.OperationalError, "setup failed"
                    ):
                        store._connect()
                self.assertTrue(connection.was_closed)

        journal_connection = ForeignKeyFailingJournalConnection()
        with (
            mock.patch.object(
                run_store_module.sqlite3, "connect", return_value=journal_connection
            ),
            mock.patch.object(
                run_store_module.ExecutionStore, "_validate_existing_schema"
            ),
        ):
            with self.assertRaisesRegex(
                sqlite3.OperationalError, "foreign-key setup failed"
            ):
                run_store._connect()
        self.assertEqual(
            journal_connection.statements,
            ["PRAGMA journal_mode", "PRAGMA foreign_keys=ON"],
        )
        self.assertTrue(journal_connection.was_closed)

    def test_case_connections_close_after_success_and_rollback(self):
        path = Path(self.temp.name) / "cases.db"
        store = cases_module.CaseStore(
            path,
            lambda *_: True,
            max_audit_rows=2,
        )
        real_connect = sqlite3.connect
        opened = []

        def tracked_connect(*args, **kwargs):
            kwargs["factory"] = TrackingConnection
            connection = real_connect(*args, **kwargs)
            opened.append(connection)
            return connection

        data = {
            "schema_version": 1,
            "title": "Lifecycle",
            "window": {
                "start": "2026-01-01T00:00:00Z",
                "end": "2026-01-02T00:00:00Z",
            },
        }
        with mock.patch.object(
            cases_module.sqlite3, "connect", side_effect=tracked_connect
        ):
            first = store.create("alice", "request-1", data)
            replay = store.create("alice", "request-1", data)
            self.assertEqual(replay, first)
            with self.assertRaises(cases_module.QuotaExceeded):
                store.create("alice", "request-3", data)

        self.assertTrue(opened)
        self.assertTrue(all(connection.was_closed for connection in opened))
        with closing(real_connect(path)) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM cases").fetchone()[0], 1)
            self.assertEqual(
                db.execute("SELECT COUNT(*) FROM requests").fetchone()[0], 1
            )


if __name__ == "__main__":
    unittest.main()
