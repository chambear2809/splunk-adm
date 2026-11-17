"""Synthetic, quiescent same-build SQLite copy rehearsal; not an operational restore tool."""

import copy
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from contextlib import closing

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(
    0, str(Path(__file__).resolve().parents[1] / "splunk_app/splunk_adm/bin")
)
from test_baselines import capture  # noqa: E402
from adm_baselines_lib.store import (
    BaselineStore,
    Forbidden as BaselineForbidden,
    signature,
)  # noqa: E402
from adm_cases_lib.store import CaseStore, Forbidden as CaseForbidden  # noqa: E402
from adm_cases_lib.job_ledger import Invalid as LedgerInvalid, JobLedger, QuotaExceeded  # noqa: E402

OWNER = "a" * 32
HASH = "c" * 64


def backup(source, target):
    # Fixture writers are quiescent. SQLite backup includes committed journal state.
    fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(fd)
    with (
        closing(sqlite3.connect(source)) as src,
        closing(sqlite3.connect(target)) as dst,
    ):
        src.backup(dst)


def inspect(path):
    with closing(sqlite3.connect(path)) as db:
        integrity = db.execute("PRAGMA integrity_check").fetchall()
        foreign_keys = db.execute("PRAGMA foreign_key_check").fetchall()
        schema = db.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name"
        ).fetchall()
        version = db.execute("PRAGMA user_version").fetchone()[0]
    return integrity, foreign_keys, schema, version


class SQLiteRestoreRehearsal(unittest.TestCase):
    def test_quiescent_copy_preserves_access_and_unresolved_jobs(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            original, restored = root / "original", root / "restored"
            original.mkdir(mode=0o700)
            restored.mkdir(mode=0o700)
            source_allowed = {"alice", "bob"}

            def entitled(*_):
                return True

            def case_source(principal, _kind, _item):
                return principal in source_allowed

            def resolve(_p, ref):
                return {
                    "captured_at": "2026-01-01T03:00:00Z",
                    "data": {"value": ref},
                    "source": {"dataset": ref},
                }

            cases = CaseStore(
                original / "cases.sqlite",
                entitled,
                capture_resolver=resolve,
                source_entitlement=case_source,
            )
            data = {
                "schema_version": 1,
                "title": "Synthetic case",
                "window": {
                    "start": "2026-01-01T00:00:00Z",
                    "end": "2026-01-02T00:00:00Z",
                },
            }
            case_id = cases.create("alice", "create", data)["id"]
            note = cases.append(
                "alice",
                "note",
                case_id,
                1,
                "entry",
                {"type": "note", "text": "original"},
            )["entries"][0]
            revised = {
                "type": "note",
                "text": "revised",
                "supersedes_entry_id": note["id"],
            }
            cases.append("alice", "revise", case_id, 2, "entry", revised)
            captured = cases.append_capture(
                "alice", "capture", case_id, 3, "synthetic-reference"
            )
            cases.attach_capture_reference(
                "alice", "attach", case_id, 4, note["id"], captured["capture_ids"][0]
            )
            cases.share("alice", "share", case_id, 5, "bob", True)
            audit = cases.audit("alice", case_id)

            sources = {"a": capture(), "b": capture(10), "c": capture(20)}
            sources["c"]["dependencies"][0]["blocked"] = True

            def base_source(p, _ref, _capture):
                return p in source_allowed

            def validator(_p, ref):
                return copy.deepcopy(sources[ref])

            baselines = BaselineStore(
                original / "baselines.sqlite",
                entitled,
                validator,
                source_entitlement=base_source,
                clock=lambda: 32,
            )
            base_id = baselines.create(
                "alice", "base-create", "Synthetic baseline", "a"
            )["id"]
            baselines.version("alice", "version", base_id, 1, "b")
            baselines.set_watch(
                "alice",
                "watch",
                base_id,
                2,
                {
                    "id": "w",
                    "threshold": 1,
                    "cooldownSeconds": 5,
                    "expectedWindows": [],
                },
            )
            sig = signature(capture()["dependencies"][0])
            baselines.append_occurrence("alice", "occ", base_id, 3, "w", sig, "c")
            self.assertFalse(
                baselines.append_occurrence(
                    "alice", "duplicate", base_id, 4, "w", sig, "c"
                )["inserted"]
            )
            baselines.share("alice", "base-share", base_id, 4, "bob", True)

            jobs = JobLedger(original / "capture_jobs.sqlite", clock=lambda: 100)
            ids = ["adm-capture-" + f"{i:032x}" for i in range(3)]
            for ident in ids:
                jobs.reserve("alice", ident, HASH, 1, 301, OWNER, transport_hash=HASH)
            jobs.transition(
                "alice", ids[0], OWNER, "creation_unknown", expected_revision=1
            )
            jobs.bind_created(
                "alice", ids[1], OWNER, "1700000000.1", expected_revision=1
            )
            jobs.transition(
                "alice", ids[1], OWNER, "cleanup_unknown", expected_revision=2
            )
            outstanding = jobs.outstanding("alice")

            for name in ("cases.sqlite", "baselines.sqlite", "capture_jobs.sqlite"):
                backup(original / name, restored / name)
                before, after = inspect(original / name), inspect(restored / name)
                self.assertEqual(before, after)
                self.assertEqual(after[:2], ([("ok",)], []))
                self.assertEqual((restored / name).stat().st_mode & 0o777, 0o600)
                with self.assertRaises(FileExistsError):
                    backup(original / name, restored / name)

            cases = CaseStore(
                restored / "cases.sqlite",
                entitled,
                capture_resolver=resolve,
                source_entitlement=case_source,
            )
            baselines = BaselineStore(
                restored / "baselines.sqlite",
                entitled,
                validator,
                source_entitlement=base_source,
                clock=lambda: 32,
            )
            jobs = JobLedger(restored / "capture_jobs.sqlite", clock=lambda: 100000)
            self.assertEqual(jobs.outstanding("alice"), outstanding)
            self.assertIsNone(outstanding[0]["server_sid"])
            self.assertEqual(outstanding[1]["server_sid"], "1700000000.1")
            with self.assertRaises(QuotaExceeded):
                jobs.reserve(
                    "bob",
                    "adm-capture-" + "f" * 32,
                    HASH,
                    1,
                    301,
                    OWNER,
                    transport_hash=HASH,
                )
            self.assertEqual(cases.audit("alice", case_id), audit)
            self.assertEqual(len(cases.get("bob", case_id)["captures"]), 1)
            self.assertEqual(len(cases.get("bob", case_id)["attachments"]), 1)
            self.assertEqual(
                len(baselines.get("bob", base_id, 1)["capture"]["dependencies"]), 1
            )
            with self.assertRaises(CaseForbidden):
                cases.get("outsider", case_id)
            with self.assertRaises(BaselineForbidden):
                baselines.get("outsider", base_id)
            self.assertEqual(len(baselines.list_versions("alice", base_id)["items"]), 2)
            self.assertEqual(
                len(baselines.occurrences("alice", base_id, "w")["items"]), 1
            )
            self.assertEqual(
                baselines.evaluate("alice", base_id, "w", sig, 33)["count"], 1
            )
            self.assertTrue(
                baselines.append_occurrence(
                    "alice", "duplicate", base_id, 4, "w", sig, "c"
                )["resultWithheld"]
            )
            self.assertFalse(
                baselines.append_occurrence(
                    "alice", "duplicate-after", base_id, 5, "w", sig, "c"
                )["inserted"]
            )
            source_allowed.clear()
            for document in (
                cases.get("bob", case_id),
                cases.export("alice", case_id),
                cases.append_capture(
                    "alice", "capture", case_id, 3, "synthetic-reference"
                ),
            ):
                self.assertEqual(document["captures"], [])
                self.assertEqual(document["redactions"]["captures"], 1)
                self.assertTrue(document["entries"])
            self.assertEqual(cases.get("bob", case_id)["attachments"], [])
            self.assertEqual(cases.get("bob", case_id)["redactions"]["attachments"], 1)
            with self.assertRaises(BaselineForbidden):
                baselines.export("bob", base_id)
            with self.assertRaises(BaselineForbidden):
                baselines.get("alice", base_id)

    def test_legacy_ledger_migration_only_changes_copy(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "source").mkdir(mode=0o700)
            (root / "target").mkdir(mode=0o700)
            source = root / "source/capture_jobs.sqlite"
            target = root / "target/capture_jobs.sqlite"
            fd = os.open(source, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
            intent = "adm-capture-" + "0" * 32
            with sqlite3.connect(source) as db:
                db.execute(
                    "CREATE TABLE jobs (seq INTEGER PRIMARY KEY AUTOINCREMENT, sid TEXT NOT NULL UNIQUE, principal TEXT NOT NULL, query_hash TEXT NOT NULL, window_start INTEGER NOT NULL, window_end INTEGER NOT NULL, state TEXT NOT NULL, revision INTEGER NOT NULL, lease_owner TEXT, lease_until REAL, terminal_seq INTEGER, transport_hash TEXT)"
                )
                db.execute(
                    "CREATE TABLE ledger_meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL)"
                )
                db.execute("INSERT INTO ledger_meta VALUES ('terminal_seq',0)")
                db.execute(
                    "INSERT INTO jobs(sid,principal,query_hash,window_start,window_end,state,revision,lease_owner,lease_until,transport_hash) VALUES (?,?,?,?,?,'created',1,?,?,?)",
                    (intent, "alice", HASH, 1, 2, OWNER, 135, HASH),
                )
                db.execute("PRAGMA user_version=2")
            backup(source, target)
            migrated = JobLedger(target, clock=lambda: 100)
            item = migrated.outstanding("alice")[0]
            self.assertEqual(item["state"], "creation_unknown")
            self.assertIsNone(item["server_sid"])
            self.assertEqual(item["transport_hash"], HASH)
            self.assertEqual(inspect(source)[3], 2)
            self.assertEqual(inspect(target)[3], 3)

    def test_future_ledger_schema_fails_closed_on_copy(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "source").mkdir(mode=0o700)
            (root / "target").mkdir(mode=0o700)
            source, target = (
                root / "source/capture_jobs.sqlite",
                root / "target/capture_jobs.sqlite",
            )
            JobLedger(source)
            backup(source, target)
            with sqlite3.connect(target) as db:
                db.execute("PRAGMA user_version=999")
            with self.assertRaises(LedgerInvalid):
                JobLedger(target)
            self.assertEqual(inspect(source)[3], 3)
            self.assertEqual(inspect(target)[3], 999)


if __name__ == "__main__":
    unittest.main()
