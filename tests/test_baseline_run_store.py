import concurrent.futures
from contextlib import closing
import hashlib
import os
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(
    0, str(Path(__file__).resolve().parents[1] / "splunk_app/splunk_adm/bin")
)
from adm_baselines_lib.run_store import ExecutionStore  # noqa: E402
from adm_baselines_lib.store import (
    Conflict,
    Forbidden,
    Invalid,
    NotFound,
    QuotaExceeded,
)  # noqa: E402

DIGEST = "c" * 64
OWNER = "a" * 32
OTHER = "b" * 32
BASELINE = "00000000-0000-4000-8000-000000000001"
DEFINITION = {
    "baselineId": BASELINE,
    "watchId": "w",
    "baselineVersion": 1,
    "principal": "alice",
    "selection": {
        "service": "checkout",
        "environment": "prod",
        "cluster": "c",
        "namespace": "n",
    },
    "providerContractRevision": "v1",
}
WINDOW = {"start": 100, "end": 200}


class ExecutionStoreTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "watch_runs.sqlite"
        self.now = 100.0
        self.store = ExecutionStore(self.path, clock=lambda: self.now)
        self.binding = self.store.create_binding(DEFINITION)

    def enable(self):
        self.binding = self.store.set_enabled(
            self.binding["id"], self.binding["revision"], True
        )

    def begin(self, key="req", window=WINDOW, owner=OWNER):
        return self.store.begin("alice", key, self.binding["id"], window, owner)

    def change(self, run, state, **data):
        return self.store.transition(
            run["id"], "alice", OWNER, run["revision"], state, **data
        )

    def test_binding_validation_disable_and_revision(self):
        self.assertFalse(self.binding["enabled"])
        self.assertEqual(self.binding["revision"], 1)
        with self.assertRaises(Forbidden):
            self.begin()
        self.enable()
        self.assertEqual(self.binding["revision"], 2)
        with self.assertRaises(Conflict):
            self.store.set_enabled(self.binding["id"], 1, False)
        for definition in (
            {**DEFINITION, "extra": 1},
            {**DEFINITION, "selection": {"service": "x"}},
            {**DEFINITION, "baselineVersion": True},
            {**DEFINITION, "principal": "a\n"},
        ):
            with self.subTest(definition=definition), self.assertRaises(Invalid):
                self.store.create_binding(definition)
        run = self.begin()
        self.binding = self.store.set_enabled(self.binding["id"], 2, False)
        with self.assertRaises(Forbidden):
            self.change(
                run,
                "prepared",
                reference="ref",
                baselineRevision=3,
                evaluationKey="e",
                captureDigest=DIGEST,
            )
        self.assertEqual(
            self.store.release(run["id"], "alice", OWNER, 1)["state"], "capture_unknown"
        )

    def test_crash_intent_never_restarts_capture_and_reserves_slot(self):
        self.enable()
        run = self.begin()
        with self.assertRaises(Conflict):
            self.begin(owner=OTHER)
        with self.assertRaises(Conflict):
            self.begin("different")
        with self.assertRaises(Conflict):
            self.begin(window={"start": 100, "end": 201})
        self.now += 61
        recovered = self.begin(owner=OTHER)
        self.assertEqual(recovered["state"], "capture_unknown")
        self.assertIsNone(recovered["reference"])
        self.assertEqual(self.begin(owner=OTHER), recovered)
        self.assertEqual(
            ExecutionStore(self.path, clock=lambda: self.now).begin(
                "alice", "req", self.binding["id"], WINDOW, OTHER
            ),
            recovered,
        )
        with self.assertRaises(Conflict):
            self.change(
                run,
                "prepared",
                reference="ref",
                baselineRevision=3,
                evaluationKey="e",
                captureDigest=DIGEST,
            )

    def test_prepared_recovery_and_commit_receipt(self):
        self.enable()
        run = self.begin()
        run = self.change(
            run,
            "prepared",
            reference="opaque-ref",
            baselineRevision=7,
            evaluationKey="evaluation-1",
            captureDigest=DIGEST,
        )
        run = self.change(run, "evaluation_unknown")
        released = self.store.release(run["id"], "alice", OWNER, run["revision"])
        run = self.begin(owner=OTHER)
        self.assertEqual(run["revision"], released["revision"] + 1)
        self.assertEqual(
            (run["reference"], run["baselineRevision"], run["evaluationKey"]),
            ("opaque-ref", 7, "evaluation-1"),
        )
        receipt = {"id": BASELINE, "revision": 8, "resultWithheld": True}
        with self.assertRaises(Invalid):
            self.store.transition(
                run["id"],
                "alice",
                OTHER,
                run["revision"],
                "committed",
                receipt={**receipt, "inserted": 1},
            )
        committed = self.store.transition(
            run["id"], "alice", OTHER, run["revision"], "committed", receipt=receipt
        )
        self.assertEqual(committed["receipt"], receipt)
        self.assertEqual(self.begin(owner=OWNER), committed)
        self.assertEqual(
            ExecutionStore(self.path).begin(
                "alice", "req", self.binding["id"], WINDOW, OWNER
            ),
            committed,
        )
        with self.assertRaises(Conflict):
            self.store.transition(
                run["id"], "alice", OTHER, run["revision"], "rejected"
            )

    def test_capacity_lease_races_and_principal_isolation(self):
        self.enable()
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:

            def reserve(i):
                try:
                    return self.begin(
                        "r" + str(i), {"start": 1000 + i * 10, "end": 1001 + i * 10}
                    )
                except QuotaExceeded:
                    return None

            rows = list(pool.map(reserve, range(6)))
        rows = [row for row in rows if row]
        self.assertEqual(len(rows), 3)
        with self.assertRaises(Forbidden):
            self.store.begin("bob", "r", self.binding["id"], WINDOW, OWNER)
        with self.assertRaises(NotFound):
            self.store.release(rows[0]["id"], "bob", OWNER, 1)
        self.now = 999999
        with self.assertRaises(QuotaExceeded):
            self.begin("extra")

    def test_retained_run_capacity_is_reserved_before_dispatch(self):
        self.store = ExecutionStore(self.path, clock=lambda: self.now, max_runs=1)
        self.enable()
        run = self.begin()
        self.change(run, "rejected")
        with self.assertRaises(QuotaExceeded):
            self.begin("next", {"start": 200, "end": 250})

    def test_prepared_expiry_and_forward_only_transitions(self):
        self.enable()
        run = self.begin()
        for ref in (None, "x" * 4097, "unsafe\n"):
            with self.subTest(ref=type(ref).__name__), self.assertRaises(Invalid):
                self.change(
                    run,
                    "prepared",
                    reference=ref,
                    baselineRevision=1,
                    evaluationKey="e",
                    captureDigest=DIGEST,
                )
        with self.assertRaises(Conflict):
            self.change(
                run,
                "committed",
                receipt={"id": BASELINE, "revision": 2, "resultWithheld": True},
            )
        run = self.change(
            run,
            "prepared",
            reference="opaque-ref",
            baselineRevision=2,
            evaluationKey="e",
            captureDigest=DIGEST,
        )
        self.now += 61
        resumed = self.begin(owner=OTHER)
        self.assertEqual(resumed["state"], "prepared")
        self.assertEqual(resumed["baselineRevision"], 2)
        self.assertEqual(resumed["captureDigest"], DIGEST)
        with self.assertRaises(Conflict):
            self.change(run, "evaluation_unknown")
        active = self.store.transition(
            run["id"], "alice", OTHER, resumed["revision"], "evaluation_unknown"
        )
        self.binding = self.store.set_enabled(
            self.binding["id"], self.binding["revision"], False
        )
        committed = self.store.transition(
            active["id"],
            "alice",
            OTHER,
            active["revision"],
            "committed",
            receipt={"id": BASELINE, "revision": 3, "resultWithheld": True},
        )
        self.assertEqual(committed["state"], "committed")

    def test_concurrent_same_key_has_one_intent(self):
        self.enable()

        def begin(owner):
            try:
                return self.begin(owner=owner)
            except Conflict:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(begin, (OWNER, OTHER)))
        self.assertEqual(sum(item is not None for item in results), 1)
        with closing(sqlite3.connect(self.path)) as db, db:
            self.assertEqual(db.execute("SELECT count(*) FROM runs").fetchone()[0], 1)

    def test_binding_limit_and_hardlink_rejected(self):
        store = ExecutionStore(self.path, max_bindings=1)
        with self.assertRaises(QuotaExceeded):
            store.create_binding(DEFINITION)
        link = self.path.parent / "hardlink"
        os.link(self.path, link)
        with self.assertRaises(Invalid):
            ExecutionStore(self.path)
        link.unlink()

    def test_binding_revision_fences_begin_and_evaluation_retry(self):
        self.enable()
        binding_revision = self.binding["revision"]
        run = self.store.begin(
            "alice",
            "req",
            self.binding["id"],
            WINDOW,
            OWNER,
            expected_binding_revision=binding_revision,
        )
        run = self.store.transition(
            run["id"],
            "alice",
            OWNER,
            run["revision"],
            "prepared",
            binding_revision=binding_revision,
            reference="ref",
            baselineRevision=3,
            evaluationKey="e",
            captureDigest=DIGEST,
        )
        run = self.store.transition(
            run["id"],
            "alice",
            OWNER,
            run["revision"],
            "evaluation_unknown",
            binding_revision=binding_revision,
        )
        rechecked = self.store.transition(
            run["id"],
            "alice",
            OWNER,
            run["revision"],
            "evaluation_unknown",
            binding_revision=binding_revision,
        )
        self.assertEqual(rechecked["revision"], run["revision"] + 1)
        self.binding = self.store.set_enabled(
            self.binding["id"], binding_revision, False
        )
        self.binding = self.store.set_enabled(
            self.binding["id"], self.binding["revision"], True
        )
        with self.assertRaises(Conflict):
            self.store.transition(
                run["id"],
                "alice",
                OWNER,
                rechecked["revision"],
                "evaluation_unknown",
                binding_revision=binding_revision,
            )
        with self.assertRaises(Conflict):
            self.store.begin(
                "alice",
                "new",
                self.binding["id"],
                {"start": 200, "end": 300},
                OTHER,
                expected_binding_revision=binding_revision,
            )
        self.assertEqual(
            self.store.release(run["id"], "alice", OWNER, rechecked["revision"])[
                "state"
            ],
            "evaluation_unknown",
        )

    def test_sidecars_fail_closed_without_touching_targets(self):
        for suffix in ("-journal", "-wal", "-shm"):
            sidecar = Path(str(self.path) + suffix)
            victim = self.path.parent / "victim"
            victim.write_bytes(b"unchanged")
            victim.chmod(0o600)
            sidecar.symlink_to(victim)
            with (
                self.subTest(suffix=suffix, kind="symlink"),
                self.assertRaises(Invalid),
            ):
                ExecutionStore(self.path)
            self.assertEqual(victim.read_bytes(), b"unchanged")
            sidecar.unlink()
            os.link(victim, sidecar)
            with (
                self.subTest(suffix=suffix, kind="hardlink"),
                self.assertRaises(Invalid),
            ):
                ExecutionStore(self.path)
            sidecar.unlink()
            sidecar.write_bytes(b"evidence")
            sidecar.chmod(0o644)
            with (
                self.subTest(suffix=suffix, kind="permissive"),
                self.assertRaises(Invalid),
            ):
                ExecutionStore(self.path)
            self.assertEqual(sidecar.read_bytes(), b"evidence")
            sidecar.unlink()
            victim.unlink()
        self.assertFalse(
            any(Path(str(self.path) + s).exists() for s in ("-journal", "-wal", "-shm"))
        )

    def test_persistent_wal_mode_rejected(self):
        with closing(sqlite3.connect(self.path)) as db, db:
            self.assertEqual(db.execute("PRAGMA journal_mode=WAL").fetchone()[0], "wal")
        with self.assertRaises(Invalid):
            ExecutionStore(self.path)

    def test_future_schema_does_not_modify_file(self):
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("PRAGMA user_version=999")
        before = hashlib.sha256(self.path.read_bytes()).digest()
        with self.assertRaises(Invalid):
            ExecutionStore(self.path)
        self.assertEqual(hashlib.sha256(self.path.read_bytes()).digest(), before)

    def test_disable_reenable_cannot_adopt_new_binding_revision(self):
        for state in ("prepared", "evaluation_unknown"):
            with self.subTest(state=state):
                binding = self.store.create_binding(DEFINITION)
                binding = self.store.set_enabled(binding["id"], 1, True)
                run = self.store.begin(
                    "alice",
                    "req-" + state,
                    binding["id"],
                    WINDOW,
                    OWNER,
                    expected_binding_revision=binding["revision"],
                )
                self.assertEqual(run["bindingRevision"], binding["revision"])
                run = self.store.transition(
                    run["id"],
                    "alice",
                    OWNER,
                    run["revision"],
                    "prepared",
                    binding_revision=binding["revision"],
                    reference="ref",
                    baselineRevision=2,
                    evaluationKey="e",
                    captureDigest=DIGEST,
                )
                if state == "evaluation_unknown":
                    run = self.store.transition(
                        run["id"],
                        "alice",
                        OWNER,
                        run["revision"],
                        "evaluation_unknown",
                        binding_revision=binding["revision"],
                    )
                binding = self.store.set_enabled(
                    binding["id"], binding["revision"], False
                )
                binding = self.store.set_enabled(
                    binding["id"], binding["revision"], True
                )
                with self.assertRaises(Conflict):
                    self.store.transition(
                        run["id"],
                        "alice",
                        OWNER,
                        run["revision"],
                        "evaluation_unknown",
                        binding_revision=binding["revision"],
                    )
                released = self.store.release(
                    run["id"], "alice", OWNER, run["revision"]
                )
                with self.assertRaises(Conflict):
                    self.store.begin(
                        "alice",
                        "req-" + state,
                        binding["id"],
                        WINDOW,
                        OTHER,
                        expected_binding_revision=binding["revision"],
                    )
                with self.assertRaises(Conflict):
                    self.store.begin(
                        "alice",
                        "fresh-" + state,
                        binding["id"],
                        WINDOW,
                        OTHER,
                        expected_binding_revision=binding["revision"],
                    )
                with closing(sqlite3.connect(self.path)) as db, db:
                    saved = db.execute(
                        "SELECT state,binding_revision FROM runs WHERE id=?",
                        (run["id"],),
                    ).fetchone()
                self.assertEqual(saved, (state, released["bindingRevision"]))

    def test_capture_digest_required_immutable_and_recovered(self):
        self.enable()
        run = self.begin()
        for digest in (None, "A" * 64, "g" * 64, "a" * 63):
            with self.subTest(digest=digest), self.assertRaises(Invalid):
                self.change(
                    run,
                    "prepared",
                    reference="ref",
                    baselineRevision=3,
                    evaluationKey="e",
                    captureDigest=digest,
                )
        with self.assertRaises(Invalid):
            self.change(
                run, "prepared", reference="ref", baselineRevision=3, evaluationKey="e"
            )
        run = self.change(
            run,
            "prepared",
            reference="ref",
            baselineRevision=3,
            evaluationKey="e",
            captureDigest=DIGEST,
        )
        with self.assertRaises(Invalid):
            self.change(run, "evaluation_unknown", captureDigest="a" * 64)
        run = self.change(run, "evaluation_unknown")
        self.store.release(run["id"], "alice", OWNER, run["revision"])
        resumed = self.begin(owner=OTHER)
        self.assertEqual(resumed["captureDigest"], DIGEST)
        committed = self.store.transition(
            run["id"],
            "alice",
            OTHER,
            resumed["revision"],
            "committed",
            receipt={"id": BASELINE, "revision": 4, "resultWithheld": True},
        )
        self.assertEqual(committed["captureDigest"], DIGEST)

    def test_unreleased_schema_without_digest_fails_closed(self):
        other = Path(self.tmp.name) / "old"
        other.mkdir(mode=0o700)
        path = other / "watch_runs.sqlite"
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        with closing(sqlite3.connect(path)) as db, db:
            db.execute("CREATE TABLE runs(id TEXT PRIMARY KEY, state TEXT)")
            db.execute("INSERT INTO runs VALUES ('prior', 'prepared')")
            db.execute("PRAGMA user_version=1")
        before = hashlib.sha256(path.read_bytes()).digest()
        with self.assertRaises(Invalid):
            ExecutionStore(path)
        self.assertEqual(hashlib.sha256(path.read_bytes()).digest(), before)

    def test_existing_only_rejects_missing_empty_and_disappearing_files(self):
        directory = self.path.parent / "missing"
        directory.mkdir(mode=0o700)
        path = directory / "watch_runs.sqlite"
        with self.assertRaises(Invalid):
            ExecutionStore(path, existing_only=True)
        self.assertFalse(path.exists())
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
        before = path.read_bytes()
        with self.assertRaises(Invalid):
            ExecutionStore(path, existing_only=True)
        self.assertEqual(path.read_bytes(), before)
        path.unlink()
        ExecutionStore(path)
        connect = sqlite3.connect

        def gone(*args, **kwargs):
            path.unlink()
            return connect(*args, **kwargs)

        with mock.patch(
            "adm_baselines_lib.run_store.sqlite3.connect", side_effect=gone
        ):
            with self.assertRaises(sqlite3.OperationalError):
                ExecutionStore(path, existing_only=True)
        self.assertFalse(path.exists())

    def test_future_schema_and_unsafe_files_rejected(self):
        with closing(sqlite3.connect(self.path)) as db, db:
            db.execute("PRAGMA user_version=999")
        with self.assertRaises(Invalid):
            ExecutionStore(self.path)
        os.chmod(self.path, 0o644)
        with self.assertRaises(Invalid):
            ExecutionStore(self.path)
        other = Path(self.tmp.name) / "unsafe"
        other.mkdir(mode=0o755)
        with self.assertRaises(Invalid):
            ExecutionStore(other / "watch_runs.sqlite")
        other.chmod(0o700)
        (other / "watch_runs.sqlite").symlink_to(self.path)
        with self.assertRaises(Invalid):
            ExecutionStore(other / "watch_runs.sqlite")


if __name__ == "__main__":
    unittest.main()
