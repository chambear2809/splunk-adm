import concurrent.futures
from contextlib import closing
import os
import sqlite3
import sys
import tempfile
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
            "label": "Snapshot",
            "captured_at": "2026-01-01T03:00:00Z",
            "data": {"count": 3},
        }
        doc = self.store.append("alice", "capture", self.id, 1, "capture", capture)
        capture["data"]["count"] = 9
        self.assertEqual(3, doc["captures"][0]["data"]["count"])
        self.store.append(
            "alice",
            "attach",
            self.id,
            2,
            "attachment",
            {"label": "log", "media_type": "text/plain", "content": "sample"},
        )
        self.assertEqual(
            "sample", self.store.export("alice", self.id)["attachments"][0]["content"]
        )
        actions = [
            item["action"] for item in self.store.audit("alice", self.id)["items"]
        ]
        self.assertIn("export", actions)
        receipt = self.store.delete("alice", "delete", self.id, 3)
        self.assertEqual(receipt, self.store.delete("alice", "delete", self.id, 3))
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
        with self.assertRaises(Invalid):
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
