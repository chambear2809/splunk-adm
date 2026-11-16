import copy
import json
import os
import sqlite3
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(
    0, os.path.join(os.path.dirname(__file__), "..", "splunk_app", "splunk_adm", "bin")
)
from adm_baselines_lib.store import (  # noqa: E402
    BaselineStore,
    Conflict,
    Forbidden,
    Invalid,
    QuotaExceeded,
    signature,
)


def capture(start=0):
    return {
        "id": "evidence-" + str(start),
        "coverage": {
            "requested": {"start": start, "end": start + 10},
            "returned": {"start": start, "end": start + 10},
            "authority": "cluster",
            "scope": "prod",
            "sourceRevision": "s1",
            "configRevision": "c1",
            "normalizationRevision": "n1",
            "signatureVersion": 1,
            "permission": "allowed",
            "complete": True,
            "capped": False,
            "progressive": False,
            "sampled": False,
            "stale": False,
            "knowledgeHorizon": start + 12,
            "requiredLatenessSeconds": 2,
        },
        "dependencies": [
            {
                "authority": "cluster",
                "scope": "prod",
                "source": "service-a",
                "destination": "service-b",
                "protocol": "tcp",
                "port": 443,
                "relation": "calls",
                "direction": "out",
                "blocked": False,
            }
        ],
    }


class BaselineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.sources = {"a": capture(), "b": capture(10)}
        self.denied = set()
        self.source_denied = set()
        self.now = 22
        self.store = BaselineStore(
            os.path.join(self.tmp.name, "baselines.db"),
            self.entitled,
            self.source,
            source_entitlement=self.source_entitlement,
            clock=lambda: self.now,
        )

    def tearDown(self):
        self.tmp.cleanup()

    def entitled(self, principal, action, baseline_id):
        return (principal, action, baseline_id) not in self.denied

    def source(self, principal, reference):
        return copy.deepcopy(self.sources[reference])

    def source_entitlement(self, principal, reference, capture):
        return (principal, reference) not in self.source_denied

    def create(self):
        return self.store.create("alice", "create", "Production", "a")

    def test_source_admission_and_compatibility(self):
        for field, value in [
            ("complete", False),
            ("capped", True),
            ("progressive", True),
            ("sampled", True),
            ("stale", True),
            ("permission", "unknown"),
            ("signatureVersion", 2),
            ("knowledgeHorizon", 11),
        ]:
            self.sources["bad"] = capture()
            self.sources["bad"]["coverage"][field] = value
            with self.subTest(field=field), self.assertRaises(Invalid):
                self.store.create("alice", field, "bad", "bad")
        self.sources["bad"] = capture()
        self.sources["bad"]["dependencies"][0]["scope"] = "other"
        with self.assertRaises(Invalid):
            self.store.create("alice", "wrong-scope", "bad", "bad")
        with self.assertRaises(Invalid):
            self.store.create("alice", "untrusted", "bad", {"capture": capture()})
        item = self.create()
        self.sources["b"]["coverage"]["sourceRevision"] = "other"
        with self.assertRaises(Invalid):
            self.store.version("alice", "version-bad", item["id"], 1, "b")
        self.sources["b"] = capture(10)
        self.store.version("alice", "version-good", item["id"], 1, "b")
        self.assertEqual(self.store.get("alice", item["id"], 1)["capture"], capture())

    def test_private_access_revocation_and_entitlement(self):
        item = self.create()
        ident = item["id"]
        with self.assertRaises(Forbidden):
            self.store.get("bob", ident)
        self.assertEqual(self.store.list("bob")["items"], [])
        self.store.share("alice", "share", ident, 1, "bob", True)
        self.assertEqual(self.store.export("bob", ident)["id"], ident)
        self.denied.add(("bob", "export", ident))
        with self.assertRaises(Forbidden):
            self.store.export("bob", ident)
        self.store.share("alice", "revoke", ident, 2, "bob", False)
        with self.assertRaises(Forbidden):
            self.store.get("bob", ident)
        self.denied.add(("alice", "read", ident))
        with self.assertRaises(Forbidden):
            self.store.create("alice", "create", "Production", "a")

    def test_concurrent_retry_and_conflict(self):
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(
                pool.map(
                    lambda _: self.store.create("alice", "create", "Production", "a"),
                    range(4),
                )
            )
        self.assertTrue(all(result == results[0] for result in results))
        ident = results[0]["id"]
        with self.assertRaises(Conflict):
            self.store.create("alice", "create", "Different", "a")

        def change(i):
            try:
                return self.store.version("alice", "v" + str(i), ident, 1, "b")
            except Conflict:
                return None

        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(change, range(2)))
        self.assertEqual(sum(result is not None for result in results), 1)

    def test_watches_dedup_cooldown_expected_and_quota(self):
        self.store.max_occurrences = 1
        ident = self.create()["id"]
        definition = {
            "id": "w",
            "threshold": 1,
            "cooldownSeconds": 5,
            "expectedWindows": [{"start": 20, "end": 30}],
        }
        self.store.set_watch("alice", "watch", ident, 1, definition)
        sig = signature(capture()["dependencies"][0])
        with self.assertRaises(Invalid):
            self.store.append_occurrence("alice", "no-change", ident, 2, "w", sig, "b")
        self.sources["b"]["dependencies"][0]["blocked"] = True
        self.store.append_occurrence("alice", "occ", ident, 2, "w", sig, "b")
        duplicate = self.store.append_occurrence(
            "alice", "occ2", ident, 3, "w", sig, "b"
        )
        self.assertFalse(duplicate["inserted"])
        self.assertEqual(
            self.store.evaluate("alice", ident, "w", sig, 23),
            {"count": 1, "thresholdMet": True, "expected": True, "coolingDown": True},
        )
        self.assertFalse(
            self.store.evaluate("alice", ident, "w", sig, 30)["coolingDown"]
        )
        self.assertEqual(len(self.store.occurrences("alice", ident, "w")["items"]), 1)
        self.assertEqual(
            self.store.list_watches("alice", ident)["items"][0]["baselineVersion"], 1
        )
        self.sources["c"] = capture(20)
        self.sources["c"]["dependencies"][0]["blocked"] = True
        self.now = 32
        with self.assertRaises(QuotaExceeded):
            self.store.append_occurrence("alice", "occ3", ident, 3, "w", sig, "c")

    def test_quotas_and_pagination(self):
        self.store.max_baselines = 1
        self.store.max_versions = 1
        ident = self.create()["id"]
        with self.assertRaises(QuotaExceeded):
            self.store.create("alice", "another", "Other", "a")
        with self.assertRaises(QuotaExceeded):
            self.store.version("alice", "v", ident, 1, "b")
        self.assertEqual(self.store.list("alice", limit=1)["items"][0]["id"], ident)
        self.store.delete("alice", "delete", ident, 1)
        self.assertTrue(self.store.delete("alice", "delete", ident, 1)["deleted"])

    def test_retry_quota_reserves_delete_and_revoke(self):
        self.store.max_requests = 4
        ident = self.create()["id"]
        self.store.share("alice", "grant", ident, 1, "bob", True)
        with self.assertRaises(QuotaExceeded):
            self.store.set_watch(
                "alice",
                "watch",
                ident,
                2,
                {
                    "id": "w",
                    "threshold": 1,
                    "cooldownSeconds": 0,
                    "expectedWindows": [],
                },
            )
        self.store.share("alice", "revoke", ident, 2, "bob", False)
        self.store.delete("alice", "delete", ident, 3)

    def test_current_source_access_on_all_reads_and_retry(self):
        ident = self.create()["id"]
        self.store.set_watch(
            "alice",
            "watch",
            ident,
            1,
            {"id": "w", "threshold": 1, "cooldownSeconds": 0, "expectedWindows": []},
        )
        self.store.share("alice", "share", ident, 2, "bob", True)
        self.source_denied.add(("bob", "a"))
        for read in (
            lambda: self.store.get("bob", ident),
            lambda: self.store.export("bob", ident),
            lambda: self.store.list_versions("bob", ident),
            lambda: self.store.list_watches("bob", ident),
            lambda: self.store.occurrences("bob", ident, "w"),
            lambda: self.store.evaluate("bob", ident, "w", "signature", 1),
        ):
            with self.assertRaises(Forbidden):
                read()
        self.assertEqual(self.store.list("bob")["items"], [])
        self.source_denied.add(("alice", "a"))
        with self.assertRaises(Forbidden):
            self.create()
        self.store.share("alice", "revoke", ident, 3, "bob", False)
        self.assertEqual(
            self.store.share("alice", "revoke", ident, 3, "bob", False)["revision"], 4
        )
        self.store.delete("alice", "delete", ident, 4)

    def test_default_denial_and_deleted_receipt_purge(self):
        path = os.path.join(self.tmp.name, "deny.db")
        deny = BaselineStore(path, self.entitled, self.source)
        with self.assertRaises(Forbidden):
            deny.create("alice", "x", "x", "a")
        self.store.max_requests = 2
        ident = self.create()["id"]
        self.store.delete("alice", "delete", ident, 1)
        with self.assertRaises(QuotaExceeded):
            self.store.create("alice", "new", "new", "a")
        self.assertEqual(self.store.purge_deleted_receipts("alice"), 0)
        with sqlite3.connect(self.store.path) as db:
            db.execute("UPDATE requests SET created_at=1")
        self.assertEqual(self.store.purge_deleted_receipts("alice"), 2)
        self.store.create("alice", "new", "new", "a")
        with sqlite3.connect(self.store.path) as db:
            db.execute("UPDATE requests SET created_at=1")
        self.assertEqual(self.store.purge_deleted_receipts("alice"), 0)

    def test_occurrence_source_revocation(self):
        ident = self.create()["id"]
        self.store.set_watch(
            "alice",
            "watch",
            ident,
            1,
            {"id": "w", "threshold": 1, "cooldownSeconds": 0, "expectedWindows": []},
        )
        self.sources["b"]["dependencies"][0]["blocked"] = True
        sig = signature(self.sources["b"]["dependencies"][0])
        self.store.append_occurrence("alice", "occ", ident, 2, "w", sig, "b")
        self.source_denied.add(("alice", "b"))
        with self.assertRaises(Forbidden):
            self.store.occurrences("alice", ident, "w")
        with self.assertRaises(Forbidden):
            self.store.append_occurrence("alice", "occ", ident, 2, "w", sig, "b")
        self.store.delete("alice", "delete", ident, 3)

    def test_occurrence_uses_trusted_clock_and_preserves_retry(self):
        ident = self.create()["id"]
        definition = {
            "id": "w",
            "threshold": 1,
            "cooldownSeconds": 5,
            "expectedWindows": [],
        }
        self.store.set_watch("alice", "watch", ident, 1, definition)
        self.sources["b"]["dependencies"][0]["blocked"] = True
        sig = signature(self.sources["b"]["dependencies"][0])
        self.now = 21
        with self.assertRaises(Invalid):
            self.store.append_occurrence("alice", "occ", ident, 2, "w", sig, "b")
        self.now = 22
        result = self.store.append_occurrence("alice", "occ", ident, 2, "w", sig, "b")
        self.now = 100
        self.assertEqual(
            self.store.append_occurrence("alice", "occ", ident, 2, "w", sig, "b"),
            result,
        )
        self.assertEqual(
            self.store.occurrences("alice", ident, "w")["items"][0]["observedAt"], 22
        )
        self.assertTrue(
            self.store.evaluate("alice", ident, "w", sig, 23)["coolingDown"]
        )
        self.assertFalse(
            self.store.evaluate("alice", ident, "w", sig, 100)["coolingDown"]
        )

    def test_unicode_signatures_and_surrogates(self):
        fixture = os.path.join(
            os.path.dirname(__file__),
            "..",
            "fixtures",
            "contracts",
            "dependency-signatures.json",
        )
        with open(fixture, encoding="utf-8") as handle:
            vectors = json.load(handle)["vectors"]
        for vector in vectors:
            self.assertEqual(signature(vector["dependency"]), vector["signature"])
        dep = capture()["dependencies"][0]
        dep["source"] = "源😀"
        self.assertIn("源😀", signature(dep))
        dep["source"] = "\ud800"
        with self.assertRaises(Invalid):
            signature(dep)

    def test_evidence_quota_dedup_and_operation_ids(self):
        ident = self.create()["id"]
        watch = {"id": "w", "threshold": 1, "cooldownSeconds": 0, "expectedWindows": []}
        self.store.set_watch("alice", "watch", ident, 1, watch)
        with self.assertRaises(Conflict):
            self.store.version("alice", "watch", ident, 1, "b")
        with self.assertRaises(Invalid):
            self.store.version("alice", "watch", ident, 1, watch)
        self.sources["b"]["dependencies"][0]["blocked"] = True
        sig = signature(self.sources["b"]["dependencies"][0])
        with sqlite3.connect(self.store.path) as db:
            size = db.execute(
                "SELECT SUM(size) FROM evidence WHERE baseline_id=?", (ident,)
            ).fetchone()[0]
        self.store.max_evidence_bytes = size
        with self.assertRaises(QuotaExceeded):
            self.store.append_occurrence("alice", "occ", ident, 2, "w", sig, "b")
        self.store.max_evidence_bytes = 8 * 1024 * 1024
        self.store.append_occurrence("alice", "occ", ident, 2, "w", sig, "b")
        self.store.set_watch("alice", "watch2", ident, 3, {**watch, "id": "w2"})
        self.store.append_occurrence("alice", "occ2", ident, 4, "w2", sig, "b")
        with sqlite3.connect(self.store.path) as db:
            count, total = db.execute(
                "SELECT COUNT(*),SUM(size) FROM evidence WHERE baseline_id=?", (ident,)
            ).fetchone()
            self.assertEqual(count, 2)
            self.assertLessEqual(total, self.store.max_evidence_bytes)
        calls = []
        self.store.source_entitlement = lambda principal, ref, cap: (
            calls.append(ref) or True
        )
        self.store.occurrences("alice", ident, "w2")
        self.assertCountEqual(calls, ["a", "b"])

    def test_inline_evidence_migration(self):
        ident = self.create()["id"]
        with sqlite3.connect(self.store.path) as db:
            reference, evidence = db.execute(
                "SELECT reference,capture FROM evidence WHERE baseline_id=?", (ident,)
            ).fetchone()
            db.execute(
                "UPDATE versions SET reference=?,capture=?,evidence_key=NULL WHERE baseline_id=?",
                (reference, evidence, ident),
            )
            db.execute("DELETE FROM evidence WHERE baseline_id=?", (ident,))
        restored = BaselineStore(
            self.store.path,
            self.entitled,
            self.source,
            source_entitlement=self.source_entitlement,
        )
        self.assertEqual(restored.get("alice", ident)["capture"], capture())


if __name__ == "__main__":
    unittest.main()
