import concurrent.futures
import os
import sqlite3
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(
    0, str(Path(__file__).resolve().parents[1] / "splunk_app/splunk_adm/bin")
)
from adm_cases_lib.job_ledger import (
    Conflict,
    Invalid,
    JobLedger,
    NotFound,
    QuotaExceeded,
)  # noqa: E402

OWNER = "a" * 32
OTHER_OWNER = "b" * 32
HASH = "c" * 64


def sid(number):
    return "adm-capture-" + f"{number:032x}"


def server_sid(number):
    return f"{1700000000 + number}.1"


class JobLedgerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "capture_jobs.sqlite"
        self.now = 100.0
        self.store = JobLedger(self.path, clock=lambda: self.now)

    def reserve(self, number=0, principal="alice", owner=OWNER):
        return self.store.reserve(
            principal, sid(number), HASH, 1, 301, owner, transport_hash=HASH
        )

    def test_persistence_reopen_isolation_and_optimistic_leases(self):
        record = self.reserve()
        self.assertEqual(record["state"], "creating")
        self.assertEqual(record["revision"], 1)
        self.assertEqual(record["transport_hash"], HASH)
        reopened = JobLedger(self.path, clock=lambda: self.now)
        self.assertEqual(reopened.outstanding("alice"), [record])
        self.assertEqual(reopened.outstanding("bob"), [])
        with self.assertRaises(NotFound):
            reopened.claim("bob", sid(0), OTHER_OWNER, expected_revision=1)
        with self.assertRaises(NotFound):
            reopened.transition("bob", sid(0), OWNER, "created", expected_revision=1)
        with self.assertRaises(Conflict):
            reopened.claim("alice", sid(0), OTHER_OWNER, expected_revision=1)
        with self.assertRaises(Conflict):
            reopened.transition(
                "alice", sid(0), OTHER_OWNER, "created", expected_revision=1
            )
        self.now = 135
        claimed = reopened.claim("alice", sid(0), OTHER_OWNER, expected_revision=1)
        self.assertEqual(claimed["revision"], 2)
        with self.assertRaises(Conflict):
            reopened.transition("alice", sid(0), OWNER, "created", expected_revision=1)
        created = reopened.bind_created(
            "alice", sid(0), OTHER_OWNER, server_sid(0), expected_revision=2
        )
        self.assertEqual(created["state"], "created")
        self.assertEqual(created["server_sid"], server_sid(0))
        self.assertEqual(created["lease_owner"], OTHER_OWNER)

    def test_principals_preserve_unicode_domain_and_spacing(self):
        principal = " DOMAIN\\Zoë 東京 "
        record = self.reserve(principal=principal)
        self.assertEqual(record["principal"], principal)
        self.assertEqual(self.store.outstanding(principal)[0]["principal"], principal)
        for different in (principal.strip(), principal.lower(), " DOMAIN\\Zoe 東京 "):
            self.assertEqual(self.store.outstanding(different), [])
            with self.assertRaises(NotFound):
                self.store.claim(different, sid(0), OTHER_OWNER, expected_revision=1)
        for invalid in ("", "   ", "alice\n", "a\x00b", "a\ud800b", "a" * 257):
            with self.subTest(principal_type="invalid"), self.assertRaises(Invalid):
                self.store.outstanding(invalid)

    def test_busy_database_fails_fast_without_mutating_budget(self):
        blocker = sqlite3.connect(self.path, timeout=0, isolation_level=None)
        try:
            blocker.execute("BEGIN IMMEDIATE")
            started = time.monotonic()
            with self.assertRaises(sqlite3.OperationalError):
                self.reserve()
            self.assertLess(time.monotonic() - started, 1.0)
        finally:
            blocker.rollback()
            blocker.close()
        self.assertEqual(self.store.outstanding("alice"), [])
        self.assertEqual(self.reserve()["revision"], 1)

    def test_clock_rollback_does_not_erase_or_release_unknown(self):
        item = self.reserve()
        self.store.transition(
            "alice", item["sid"], OWNER, "creation_unknown", expected_revision=1
        )
        self.now = 1
        self.assertEqual(
            self.store.outstanding("alice")[0]["state"], "creation_unknown"
        )
        self.reserve(1, "bob")
        self.reserve(2, "charlie")
        with self.assertRaises(QuotaExceeded):
            self.reserve(3, "dana")

    def test_transport_hash_required_and_strict(self):
        with self.assertRaises(TypeError):
            self.store.reserve("alice", sid(0), HASH, 1, 2, OWNER)
        for invalid in (None, "", "g" * 64, "A" * 64, "a" * 63):
            with self.subTest(), self.assertRaises(Invalid):
                self.store.reserve(
                    "alice", sid(0), HASH, 1, 2, OWNER, transport_hash=invalid
                )
        self.assertEqual(self.store.outstanding("alice"), [])
        saved = self.reserve()
        self.assertEqual(
            JobLedger(self.path, clock=lambda: self.now).outstanding("alice")[0][
                "transport_hash"
            ],
            saved["transport_hash"],
        )

    def test_v1_migration_preserves_unknown_unbound_and_budget(self):
        old_dir = Path(self.tmp.name) / "legacy"
        old_dir.mkdir(mode=0o700)
        old_path = old_dir / "capture_jobs.sqlite"
        fd = os.open(old_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        with sqlite3.connect(old_path) as db:
            db.execute(
                "CREATE TABLE jobs (seq INTEGER PRIMARY KEY AUTOINCREMENT, sid TEXT NOT NULL UNIQUE, principal TEXT NOT NULL, query_hash TEXT NOT NULL, window_start INTEGER NOT NULL, window_end INTEGER NOT NULL, state TEXT NOT NULL, revision INTEGER NOT NULL, lease_owner TEXT, lease_until REAL, terminal_seq INTEGER)"
            )
            db.execute(
                "CREATE TABLE ledger_meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL)"
            )
            db.execute("INSERT INTO ledger_meta VALUES ('terminal_seq',0)")
            db.execute(
                "INSERT INTO jobs(sid,principal,query_hash,window_start,window_end,state,revision) VALUES (?,?,?,?,?,'creation_unknown',1)",
                (sid(99), "alice", HASH, 1, 2),
            )
            db.execute("PRAGMA user_version=1")
        migrated = JobLedger(old_path, clock=lambda: self.now)
        legacy = migrated.outstanding("alice")[0]
        self.assertIsNone(legacy["transport_hash"])
        self.assertEqual(legacy["state"], "creation_unknown")
        self.assertIsNone(legacy["server_sid"])
        claimed = migrated.claim("alice", sid(99), OWNER, expected_revision=2)
        self.assertIsNone(claimed["transport_hash"])
        for state in ("created", "collision"):
            with self.assertRaises(Conflict):
                migrated.transition("alice", sid(99), OWNER, state, expected_revision=3)
        migrated.reserve("bob", sid(100), HASH, 1, 2, OWNER, transport_hash=HASH)
        migrated.reserve("carol", sid(101), HASH, 1, 2, OWNER, transport_hash=HASH)
        self.now += 100000
        with self.assertRaises(QuotaExceeded):
            migrated.reserve("dana", sid(102), HASH, 1, 2, OWNER, transport_hash=HASH)
        self.assertIsNone(migrated.outstanding("alice")[0]["transport_hash"])
        with sqlite3.connect(old_path) as db:
            self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0], 3)

    def test_v2_created_job_migrates_to_unknown_without_inferred_server_id(self):
        old_dir = Path(self.tmp.name) / "legacy-v2"
        old_dir.mkdir(mode=0o700)
        old_path = old_dir / "capture_jobs.sqlite"
        fd = os.open(old_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        legacy_sid = "adm-sid-" + f"{99:032x}"
        with sqlite3.connect(old_path) as db:
            db.execute(
                "CREATE TABLE jobs (seq INTEGER PRIMARY KEY AUTOINCREMENT, sid TEXT NOT NULL UNIQUE, principal TEXT NOT NULL, query_hash TEXT NOT NULL, window_start INTEGER NOT NULL, window_end INTEGER NOT NULL, state TEXT NOT NULL, revision INTEGER NOT NULL, lease_owner TEXT, lease_until REAL, terminal_seq INTEGER, transport_hash TEXT)"
            )
            db.execute(
                "CREATE TABLE ledger_meta (key TEXT PRIMARY KEY, value INTEGER NOT NULL)"
            )
            db.execute("INSERT INTO ledger_meta VALUES ('terminal_seq',0)")
            db.execute(
                "INSERT INTO jobs(sid,principal,query_hash,window_start,window_end,state,revision,lease_owner,lease_until,transport_hash) VALUES (?,?,?,?,?,'created',1,?,?,?)",
                (legacy_sid, "alice", HASH, 1, 2, OWNER, 135, HASH),
            )
            db.execute("PRAGMA user_version=2")
        migrated = JobLedger(old_path, clock=lambda: self.now)
        legacy = migrated.outstanding("alice")[0]
        self.assertEqual(legacy["state"], "creation_unknown")
        self.assertEqual(legacy["revision"], 2)
        self.assertEqual(legacy["transport_hash"], HASH)
        self.assertIsNone(legacy["server_sid"])
        self.assertIsNone(legacy["lease_owner"])
        claimed = migrated.claim("alice", legacy_sid, OWNER, expected_revision=2)
        with self.assertRaises(Conflict):
            migrated.transition(
                "alice",
                legacy_sid,
                OWNER,
                "created",
                expected_revision=claimed["revision"],
            )
        with self.assertRaises(Conflict):
            migrated.bind_created(
                "alice",
                legacy_sid,
                OWNER,
                server_sid(99),
                expected_revision=claimed["revision"],
            )

    def test_server_id_binding_is_authorized_immutable_and_unique(self):
        item = self.reserve()
        self.assertIsNone(item["server_sid"])
        for invalid in ("", "x/other", "x y", "x\n", "x" * 256):
            with self.subTest(), self.assertRaises(Invalid):
                self.store.bind_created(
                    "alice", item["sid"], OWNER, invalid, expected_revision=1
                )
        with self.assertRaises(NotFound):
            self.store.bind_created(
                "bob", item["sid"], OWNER, server_sid(0), expected_revision=1
            )
        with self.assertRaises(Conflict):
            self.store.bind_created(
                "alice", item["sid"], OTHER_OWNER, server_sid(0), expected_revision=1
            )
        with self.assertRaises(Conflict):
            self.store.transition(
                "alice", item["sid"], OWNER, "created", expected_revision=1
            )
        bound = self.store.bind_created(
            "alice", item["sid"], OWNER, server_sid(0), expected_revision=1
        )
        self.assertEqual(bound["server_sid"], server_sid(0))
        self.assertEqual(
            (
                bound["query_hash"],
                bound["transport_hash"],
                bound["window_start"],
                bound["window_end"],
            ),
            (HASH, HASH, 1, 301),
        )
        with self.assertRaises(Conflict):
            self.store.bind_created(
                "alice",
                item["sid"],
                OWNER,
                server_sid(1),
                expected_revision=bound["revision"],
            )
        second = self.reserve(1, "bob")
        with self.assertRaises(Conflict):
            self.store.bind_created(
                "bob", second["sid"], OWNER, server_sid(0), expected_revision=1
            )
        self.assertIsNone(self.store.outstanding("bob")[0]["server_sid"])

    def test_unknown_releases_lease_but_never_expires_or_releases_budget(self):
        item = self.reserve()
        unknown = self.store.transition(
            "alice", item["sid"], OWNER, "creation_unknown", expected_revision=1
        )
        self.assertIsNone(unknown["lease_owner"])
        self.now = 100000
        known = self.reserve(1, "bob")
        self.reserve(2, "charlie")
        with self.assertRaises(QuotaExceeded):
            self.reserve(3, "dana")
        self.assertEqual(
            self.store.outstanding("alice")[0]["state"], "creation_unknown"
        )
        claimed = self.store.claim(
            "alice", item["sid"], OTHER_OWNER, expected_revision=2
        )
        with self.assertRaises(Conflict):
            self.store.bind_created(
                "alice",
                item["sid"],
                OTHER_OWNER,
                server_sid(0),
                expected_revision=claimed["revision"],
            )
        with self.assertRaises(Conflict):
            self.store.transition(
                "alice",
                item["sid"],
                OTHER_OWNER,
                "collision",
                expected_revision=claimed["revision"],
            )
        created = self.store.bind_created(
            "bob", known["sid"], OWNER, server_sid(1), expected_revision=1
        )
        unknown_delete = self.store.transition(
            "bob",
            known["sid"],
            OWNER,
            "cleanup_unknown",
            expected_revision=created["revision"],
        )
        self.assertIsNone(unknown_delete["lease_owner"])
        self.now += 1_000_000
        with self.assertRaises(QuotaExceeded):
            self.reserve(4, "dana")
        reclaimed = self.store.claim(
            "bob", known["sid"], OWNER, expected_revision=unknown_delete["revision"]
        )
        deleted = self.store.transition(
            "bob",
            known["sid"],
            OWNER,
            "deleted",
            expected_revision=reclaimed["revision"],
        )
        self.assertEqual(deleted["state"], "deleted")
        self.assertEqual(self.store.outstanding("bob"), [])
        self.assertEqual(
            self.store.outstanding("alice")[0]["state"], "creation_unknown"
        )
        self.reserve(5, "dana")

    def test_concurrent_reserves_respect_global_budget(self):
        def apply(i):
            try:
                return self.reserve(i, "user" + str(i))
            except QuotaExceeded:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            values = list(pool.map(apply, range(8)))
        self.assertEqual(sum(value is not None for value in values), 3)
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM jobs").fetchone()[0], 3)

    def test_concurrent_reconciliation_has_one_lease_owner(self):
        self.reserve()
        self.now = 136

        def claim(owner):
            try:
                return self.store.claim("alice", sid(0), owner, expected_revision=1)
            except Conflict:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(claim, (OWNER, OTHER_OWNER)))
        self.assertEqual(sum(result is not None for result in results), 1)

    def test_legal_transitions_and_revision_conflicts(self):
        item = self.reserve()
        with self.assertRaises(Conflict):
            self.store.transition(
                "alice", item["sid"], OWNER, "deleted", expected_revision=1
            )
        with self.assertRaises(Invalid):
            self.store.transition("alice", item["sid"], OWNER, [], expected_revision=1)
        with self.assertRaises(Conflict):
            self.store.transition(
                "alice", item["sid"], OWNER, "created", expected_revision=2
            )
        self.now = 136
        with self.assertRaises(Conflict):
            self.store.transition(
                "alice", item["sid"], OWNER, "created", expected_revision=1
            )
        item = self.store.claim("alice", item["sid"], OTHER_OWNER, expected_revision=1)
        created = self.store.bind_created(
            "alice",
            item["sid"],
            OTHER_OWNER,
            server_sid(0),
            expected_revision=item["revision"],
        )
        terminal = self.store.transition(
            "alice",
            item["sid"],
            OTHER_OWNER,
            "deleted",
            expected_revision=created["revision"],
        )
        self.assertEqual(terminal["state"], "deleted")
        with self.assertRaises(Conflict):
            self.store.claim(
                "alice", item["sid"], OWNER, expected_revision=terminal["revision"]
            )
        with self.assertRaises(Conflict):
            self.reserve()

    def test_terminal_history_is_bounded_and_live_records_survive(self):
        self.reserve(1000, "bob")
        for n in range(140):
            item = self.reserve(n)
            created = self.store.bind_created(
                "alice", item["sid"], OWNER, server_sid(n), expected_revision=1
            )
            self.store.transition(
                "alice",
                item["sid"],
                OWNER,
                "deleted",
                expected_revision=created["revision"],
            )
        with sqlite3.connect(self.path) as db:
            rows = db.execute(
                "SELECT state,terminal_seq FROM jobs ORDER BY seq"
            ).fetchall()
        self.assertEqual(len(rows), 129)
        self.assertEqual(sum(state == "creating" for state, _ in rows), 1)
        self.assertEqual(
            [n for state, n in rows if state == "deleted"], list(range(13, 141))
        )
        self.assertEqual(len(self.store.outstanding("bob")), 1)

    def test_validation_and_clock_fail_without_persisting(self):
        for args in (
            ("alice", "not-cryptographic", HASH, 1, 2, OWNER),
            ("alice", sid(0), "not-a-hash", 1, 2, OWNER),
            ("alice", sid(0), HASH, 1, 302, OWNER),
            ("alice", sid(0), HASH, 1, 2, "bad"),
            ("alice", sid(0), HASH, True, 2, OWNER),
            ("alice\nother", sid(0), HASH, 1, 2, OWNER),
        ):
            with self.subTest(), self.assertRaises(Invalid):
                self.store.reserve(*args, transport_hash=HASH)
        for value in (float("nan"), -1, True):
            self.now = value
            with self.subTest(), self.assertRaises(Invalid):
                self.reserve()
        self.assertEqual(self.store.outstanding("alice"), [])

    def test_private_files_symlinks_and_hardlinks_fail_closed(self):
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        self.path.chmod(0o644)
        try:
            with self.assertRaises(Invalid):
                self.store.outstanding("alice")
        finally:
            self.path.chmod(0o600)
        hard = self.path.parent / "hardlink"
        os.link(self.path, hard)
        try:
            with self.assertRaises(Invalid):
                self.store.outstanding("alice")
        finally:
            hard.unlink()
        self.path.parent.chmod(0o755)
        try:
            with self.assertRaises(Invalid):
                self.store.outstanding("alice")
        finally:
            self.path.parent.chmod(0o700)
        self.path.unlink()
        target = self.path.parent / "other"
        target.write_text("unrelated")
        target.chmod(0o600)
        self.path.symlink_to(target)
        with self.assertRaises(Invalid):
            JobLedger(self.path)
        self.assertEqual(target.read_text(), "unrelated")
        with self.assertRaises(Invalid):
            JobLedger("capture_jobs.sqlite")
        with self.assertRaises(Invalid):
            JobLedger(self.path.parent / "cases.sqlite")


if __name__ == "__main__":
    unittest.main()
