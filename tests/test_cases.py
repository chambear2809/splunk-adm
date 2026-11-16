import concurrent.futures
from contextlib import closing
import json
import os
import sqlite3
import sys
import tempfile
import threading
import unittest

sys.path.insert(
    0, os.path.join(os.path.dirname(__file__), "..", "splunk_app", "splunk_adm", "bin")
)
from adm_cases_lib import (
    CaseStore,
    Conflict,
    Forbidden,
    Invalid,
    NotFound,
    QuotaExceeded,
)


class CasesTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = os.path.join(self.tmp.name, "cases.sqlite")
        self.denied = set()
        self.store = CaseStore(
            self.path, lambda p, action, case: (p, action, case) not in self.denied
        )
        self.input = {
            "schema_version": 1,
            "title": "Investigation",
            "window": {"start": "2026-01-01T00:00:00Z", "end": "2026-01-02T00:00:00Z"},
        }
        self.case = self.store.create("alice", "create-1", self.input)
        self.id = self.case["id"]

    def append(self, request="append-1", revision=1):
        return self.store.append(
            "alice",
            request,
            self.id,
            revision,
            "entry",
            {"type": "note", "text": "Evidence"},
        )

    def test_private_share_revoke_and_current_entitlement(self):
        with self.assertRaises(Forbidden):
            self.store.get("bob", self.id)
        self.assertEqual([], self.store.list_cases("bob")["items"])
        self.store.share("alice", "grant", self.id, 1, "bob", True)
        self.assertEqual(self.id, self.store.export("bob", self.id)["id"])
        self.denied.add(("bob", "export", self.id))
        with self.assertRaises(Forbidden):
            self.store.export("bob", self.id)
        self.store.share("alice", "revoke", self.id, 2, "bob", False)
        with self.assertRaises(Forbidden):
            self.store.get("bob", self.id)
        self.assertEqual([], self.store.list_cases("bob")["items"])

    def test_capture_projection_rechecks_each_historical_response(self):
        denied = set()
        self.store.capture_resolver = lambda principal, ref: {
            "captured_at": "2026-01-01T03:00:00Z",
            "data": {"value": ref},
            "source": {"dataset": ref},
        }
        self.store.source_entitlement = lambda principal, kind, item: (
            (principal, item["source"]["dataset"]) not in denied
        )
        self.store.append_capture("alice", "cap1", self.id, 1, "one")
        self.store.append_capture("alice", "cap2", self.id, 2, "two")
        self.store.share("alice", "grant", self.id, 3, "bob", True)
        denied.update({("bob", "one"), ("alice", "one")})
        for doc in (
            self.store.get("bob", self.id),
            self.store.export("bob", self.id),
        ):
            self.assertEqual([x["data"]["value"] for x in doc["captures"]], ["two"])
            self.assertEqual(doc["redactions"]["captures"], 1)
            self.assertNotIn("source", doc["captures"][0])
        listed = self.store.list_cases("bob")["items"][0]
        self.assertEqual(listed["captures"], [])
        self.assertEqual(listed["redactions"]["captures"], 2)
        # The historical retry snapshot had only the now-revoked first capture.
        historical = self.store.append_capture("alice", "cap1", self.id, 1, "one")
        self.assertEqual(historical["captures"], [])
        self.assertEqual(historical["redactions"]["captures"], 1)
        note = self.store.append(
            "alice",
            "note",
            self.id,
            4,
            "entry",
            {"type": "note", "text": "Still visible"},
        )
        self.assertEqual(note["entries"][0]["text"], "Still visible")
        self.assertEqual(note["redactions"]["captures"], 1)
        self.store.source_entitlement = lambda *args: (_ for _ in ()).throw(
            RuntimeError("secret")
        )
        self.assertEqual(self.store.get("bob", self.id)["redactions"]["captures"], 2)
        self.assertEqual(
            self.store.append(
                "alice",
                "note",
                self.id,
                4,
                "entry",
                {"type": "note", "text": "Still visible"},
            )["redactions"]["captures"],
            2,
        )
        self.assertEqual(
            self.store.share("alice", "grant", self.id, 3, "bob", True)["redactions"][
                "captures"
            ],
            2,
        )
        self.store.capture_resolver = None
        self.assertEqual(
            self.store.append_capture("alice", "cap1", self.id, 1, "one")["redactions"][
                "captures"
            ],
            1,
        )
        self.store.share("alice", "revoke", self.id, 5, "bob", False)
        self.store.delete("alice", "delete", self.id, 6)

    def test_legacy_unbound_evidence_is_redacted(self):
        with closing(sqlite3.connect(self.path)) as db:
            doc = json.loads(
                db.execute(
                    "SELECT document FROM cases WHERE id=?", (self.id,)
                ).fetchone()[0]
            )
            doc["captures"].append({"data": {"secret": "legacy"}})
            doc["attachments"].append({"content": "legacy"})
            db.execute(
                "UPDATE cases SET document=? WHERE id=?", (json.dumps(doc), self.id)
            )
            db.commit()
        self.store.source_entitlement = lambda *args: True
        doc = self.store.get("alice", self.id)
        self.assertEqual(doc["captures"], [])
        self.assertEqual(doc["attachments"], [])
        self.assertEqual(doc["capture_ids"], [])
        self.assertEqual(doc["redactions"], {"captures": 1, "attachments": 1})

    def test_targeted_capture_access_with_bounded_source_budget(self):
        self.store.capture_resolver = lambda principal, ref: {
            "captured_at": "2026-01-01T03:00:00Z",
            "data": {"windows": [ref + "-a", ref + "-b"]},
            "source": {"dataset": ref},
        }
        self.store.source_entitlement = lambda *args: True
        first = self.store.append_capture("alice", "one", self.id, 1, "one")
        first_id = first["capture_ids"][0]
        second = self.store.append_capture("alice", "two", self.id, 2, "two")
        second_id = second["capture_ids"][1]
        self.assertEqual(
            self.store.list_cases("alice")["items"][0]["capture_ids"],
            [first_id, second_id],
        )
        calls = []

        def budget(principal, kind, item):
            calls.append(item["source"]["dataset"])
            return len(calls) * 2 <= 3

        self.store.source_entitlement = budget
        full = self.store.get("alice", self.id)
        self.assertEqual(len(full["captures"]), 1)
        self.assertEqual(full["redactions"]["captures"], 1)
        calls.clear()
        selected = self.store.get("alice", self.id, capture_id=second_id)
        self.assertEqual(calls, ["two"])
        self.assertEqual(selected["captures"][0]["id"], second_id)
        self.assertEqual(selected["redactions"]["captures"], 1)
        calls.clear()
        exported = self.store.export("alice", self.id, capture_id=second_id)
        self.assertEqual(calls, ["two"])
        self.assertEqual(exported["captures"][0]["id"], second_id)
        with self.assertRaises(Invalid):
            self.store.get("alice", self.id, capture_id="bad")
        with self.assertRaises(NotFound):
            self.store.get(
                "alice", self.id, capture_id="00000000-0000-4000-8000-000000000000"
            )
        with self.assertRaises(Forbidden):
            self.store.get("bob", self.id, capture_id="bad")

    def test_capture_quota_and_concurrent_revisions(self):
        self.store.capture_resolver = lambda principal, ref: {
            "captured_at": "2026-01-01T03:00:00Z",
            "data": {"value": ref},
            "source": {"dataset": ref},
        }
        self.store.source_entitlement = lambda *args: True
        self.store.max_case_bytes = 1
        with self.assertRaises(QuotaExceeded):
            self.store.append_capture("alice", "cap", self.id, 1, "one")
        self.assertEqual(self.store.get("alice", self.id)["revision"], 1)
        self.store.max_case_bytes = 1_000_000

        def append(i):
            try:
                return self.store.append_capture(
                    "alice", "capture-" + str(i), self.id, 1, str(i)
                )
            except Conflict:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(append, range(2)))
        self.assertEqual(sum(result is not None for result in results), 1)

    def test_resolver_outside_write_transaction_and_revision_rechecked(self):
        started, release = threading.Event(), threading.Event()

        def resolve(principal, reference):
            # Acquiring this lock proves the resolver does not hold the write lock.
            with closing(sqlite3.connect(self.path, timeout=0.1)) as db:
                db.execute("BEGIN IMMEDIATE")
                db.rollback()
            started.set()
            self.assertTrue(release.wait(5))
            return {
                "captured_at": "2026-01-01T03:00:00Z",
                "data": {},
                "source": {"dataset": "s"},
            }

        self.store.capture_resolver = resolve
        self.store.source_entitlement = lambda *args: True
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(
                self.store.append_capture, "alice", "capture", self.id, 1, "s"
            )
            self.assertTrue(started.wait(5))
            self.append("note", 1)
            release.set()
            with self.assertRaises(Conflict):
                pending.result()
        self.assertEqual(self.store.get("alice", self.id)["captures"], [])

    def test_list_redacts_without_source_checks_and_access_rechecked_after_projection(
        self,
    ):
        self.store.capture_resolver = lambda p, r: {
            "captured_at": "2026-01-01T03:00:00Z",
            "data": {},
            "source": {"dataset": r},
        }

        def authorize(*args):
            with closing(sqlite3.connect(self.path, timeout=0.1)) as db:
                db.execute("BEGIN IMMEDIATE")
                db.rollback()
            return True

        self.store.source_entitlement = authorize
        self.store.append_capture("alice", "cap", self.id, 1, "s")
        calls = []
        self.store.source_entitlement = lambda *args: calls.append(args) or True
        listed = self.store.list_cases("alice")["items"][0]
        self.assertEqual(listed["redactions"]["captures"], 1)
        self.assertEqual(calls, [])

        def revoke_during_check(*args):
            self.denied.add(("alice", "read", self.id))
            return True

        self.store.source_entitlement = revoke_during_check
        with self.assertRaises(Forbidden):
            self.store.get("alice", self.id)

    def test_retry_and_conflicting_request(self):
        first = self.append()
        self.assertEqual(first, self.append())
        with self.assertRaises(Conflict):
            self.store.append(
                "alice",
                "append-1",
                self.id,
                1,
                "entry",
                {"type": "note", "text": "Different"},
            )
        self.denied.add(("alice", "read", self.id))
        with self.assertRaises(Forbidden):
            self.append()

    def test_concurrent_edits_use_one_revision(self):
        def run(n):
            try:
                return self.append("request-" + str(n))
            except Conflict:
                return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(run, range(2)))
        self.assertEqual(1, sum(result is not None for result in results))
        self.assertEqual(1, len(self.store.get("alice", self.id)["entries"]))

    def test_capture_attachment_export_and_delete_retry(self):
        capture = {
            "captured_at": "2026-01-01T03:00:00Z",
            "data": {"count": 3},
            "source": {"dataset": "trusted"},
        }
        self.store.capture_resolver = lambda principal, reference: capture
        self.store.source_entitlement = lambda principal, kind, item: True
        doc = self.store.append_capture(
            "alice", "capture", self.id, 1, "ref", "Snapshot"
        )
        capture["data"]["count"] = 9
        self.assertEqual(3, doc["captures"][0]["data"]["count"])
        with self.assertRaises(Forbidden):
            self.store.append(
                "alice", "attach", self.id, 2, "attachment", {"content": "sample"}
            )
        self.assertEqual(
            3, self.store.export("alice", self.id)["captures"][0]["data"]["count"]
        )
        actions = [
            item["action"] for item in self.store.audit("alice", self.id)["items"]
        ]
        self.assertIn("export", actions)
        receipt = self.store.delete("alice", "delete", self.id, 2)
        self.assertEqual(receipt, self.store.delete("alice", "delete", self.id, 2))
        with self.assertRaises(NotFound):
            self.store.get("alice", self.id)
        with closing(sqlite3.connect(self.path)) as db:
            self.assertTrue(
                all(
                    row[0] == "null"
                    for row in db.execute(
                        "SELECT result FROM requests WHERE action != 'delete'"
                    )
                )
            )
        with self.assertRaises(NotFound):
            self.store.create("alice", "create-1", self.input)

    def test_metadata_limits_are_transactional_and_preserve_deletion(self):
        store = CaseStore(
            os.path.join(self.tmp.name, "bounded.sqlite"),
            lambda *_: True,
            max_request_rows=4,
            max_request_bytes=4096,
            max_audit_rows=4,
            max_acl_members=2,
        )
        case = store.create("alice", "c", self.input)
        case_id = case["id"]
        store.share("alice", "share", case_id, 1, "bob", True)
        with self.assertRaises(QuotaExceeded):
            store.share("alice", "share2", case_id, 2, "carol", True)
        with self.assertRaises(QuotaExceeded):
            store.append(
                "alice",
                "full",
                case_id,
                2,
                "entry",
                {"type": "note", "text": "must roll back"},
            )
        self.assertEqual(2, store.get("alice", case_id)["revision"])
        self.assertEqual([], store.get("alice", case_id)["entries"])
        # Both the audit and request limits have a reserved slot for deletion.
        receipt = store.delete("alice", "delete", case_id, 2)
        self.assertEqual(receipt, store.delete("alice", "delete", case_id, 2))

    def test_revoke_remains_available_when_metadata_is_full(self):
        store = CaseStore(
            os.path.join(self.tmp.name, "revoke.sqlite"),
            lambda *_: True,
            max_request_rows=4,
            max_audit_rows=4,
            max_request_bytes=4096,
        )
        case_id = store.create("alice", "c", self.input)["id"]
        store.share("alice", "grant", case_id, 1, "bob", True)
        self.assertEqual(case_id, store.get("bob", case_id)["id"])
        with self.assertRaises(QuotaExceeded):
            store.export("alice", case_id)
        with self.assertRaises(QuotaExceeded):
            store.append(
                "alice", "edit", case_id, 2, "entry", {"type": "note", "text": "x"}
            )
        receipt = store.share("alice", "revoke", case_id, 2, "bob", False)
        self.assertEqual(
            receipt, store.share("alice", "revoke", case_id, 2, "bob", False)
        )
        with self.assertRaises(Forbidden):
            store.get("bob", case_id)
        with self.assertRaises(Invalid):
            store.share("alice", "repeat", case_id, 3, "bob", False)

    def test_export_quota_and_list_rechecks_read(self):
        store = CaseStore(
            os.path.join(self.tmp.name, "audit.sqlite"),
            lambda p, a, c: (p, a, c) not in self.denied,
            max_audit_rows=3,
        )
        case = store.create("alice", "c", self.input)
        case_id = case["id"]
        store.export("alice", case_id)
        with self.assertRaises(QuotaExceeded):
            store.export("alice", case_id)
        self.denied.add(("alice", "read", case_id))
        self.assertEqual([], store.list_cases("alice")["items"])
        store.delete("alice", "delete", case_id, 1)

    def test_retry_byte_limit_rolls_back(self):
        store = CaseStore(
            os.path.join(self.tmp.name, "bytes.sqlite"),
            lambda *_: True,
            max_request_bytes=1600,
        )
        case = store.create("alice", "c", self.input)
        with self.assertRaises(QuotaExceeded):
            store.append(
                "alice",
                "big",
                case["id"],
                1,
                "entry",
                {"type": "note", "text": "x" * 1000},
            )
        self.assertEqual(1, store.get("alice", case["id"])["revision"])
        store.delete("alice", "delete", case["id"], 1)

    def test_schema_quota_pagination_and_retention(self):
        bad = dict(self.input, extra=True)
        with self.assertRaises(Invalid):
            self.store.create("alice", "bad", bad)
        with self.assertRaises(Invalid):
            self.store.create(
                "alice",
                "bad",
                dict(self.input, window={"start": "2026-01-01", "end": "2026-01-02"}),
            )
        with self.assertRaises(Forbidden):
            self.store.append(
                "alice",
                "bad",
                self.id,
                1,
                "capture",
                {
                    "label": "x",
                    "captured_at": "2026-01-01T00:00:00Z",
                    "data": {"x": (1, 2)},
                },
            )
        other = self.store.create("alice", "create-2", self.input)
        page = self.store.list_cases("alice", limit=1)
        self.assertIsNotNone(page["next"])
        self.assertNotEqual(
            page["items"][0]["id"],
            self.store.list_cases("alice", after=page["next"], limit=1)["items"][0][
                "id"
            ],
        )
        with closing(sqlite3.connect(self.path)) as db:
            db.execute(
                "UPDATE cases SET expires_at=? WHERE id=?",
                ("2000-01-01T00:00:00Z", other["id"]),
            )
            db.commit()
        self.assertEqual(1, self.store.purge_expired("alice"))
        with self.assertRaises(NotFound):
            self.store.get("alice", other["id"])
        limited = CaseStore(
            os.path.join(self.tmp.name, "limited.sqlite"), lambda *_: True, max_items=1
        )
        case = limited.create("alice", "c", self.input)
        limited.append(
            "alice", "a", case["id"], 1, "entry", {"type": "question", "text": "Why?"}
        )
        with self.assertRaises(QuotaExceeded):
            limited.append(
                "alice", "b", case["id"], 2, "entry", {"type": "note", "text": "x"}
            )


if __name__ == "__main__":
    unittest.main()
