import os
import sys
import unittest

sys.path.insert(
    0, os.path.join(os.path.dirname(__file__), "..", "splunk_app", "splunk_adm", "bin")
)
from adm_kv_lib.ledger import (  # noqa: E402
    Conflict,
    Invalid,
    LedgerError,
    RecordLedger,
    Uncertain,
    canonical,
    digest,
    successor_key,
)


class MemoryStore:
    def __init__(self):
        self.rows = []
        self.fail_insert = False

    def scan(self, limit):
        ordered = sorted(self.rows, key=lambda row: row["_key"])
        return ordered[:limit]

    def insert(self, document):
        if self.fail_insert:
            raise RuntimeError("insert lost")
        if any(row["_key"] == document["_key"] for row in self.rows):
            raise RuntimeError("duplicate")
        self.rows.append(dict(document))


class KvLedgerTests(unittest.TestCase):
    def setUp(self):
        self.store = MemoryStore()
        self.ledger = RecordLedger(self.store, kind="views", max_records=8)

    def test_first_write_and_idempotent_retry(self):
        first = self.ledger.write(
            {"name": "Payments Prod Map"},
            expected_revision=None,
            request_id="req-1",
        )
        self.assertEqual(first["state"], "configured")
        retry = self.ledger.write(
            {"name": "Payments Prod Map"},
            expected_revision=None,
            request_id="req-1",
        )
        self.assertEqual(retry["committedRevision"], first["committedRevision"])
        self.assertEqual(len(self.store.rows), 1)

    def test_stale_revision_conflict_preserves_head(self):
        self.ledger.write({"name": "a"}, None, "req-1")
        with self.assertRaises(Conflict):
            self.ledger.write({"name": "b"}, None, "req-2")

    def test_successor_and_duplicate_request_conflict(self):
        first = self.ledger.write({"name": "a"}, None, "req-1")
        second = self.ledger.write({"name": "b"}, first["committedRevision"], "req-2")
        self.assertNotEqual(first["committedRevision"], second["committedRevision"])
        with self.assertRaises(Conflict):
            self.ledger.write({"name": "c"}, first["committedRevision"], "req-2")

    def test_lost_insert_is_uncertain_until_retry_proves_absence(self):
        self.store.fail_insert = True
        with self.assertRaises(Uncertain):
            self.ledger.write({"name": "a"}, None, "req-1")
        self.store.fail_insert = False
        retry = self.ledger.write({"name": "a"}, None, "req-1")
        self.assertEqual(retry["state"], "configured")
        self.assertFalse(retry["superseded"])
        self.assertEqual(len(self.store.rows), 1)

    def test_successor_key_is_stable(self):
        self.assertEqual(
            successor_key("views", "abc"),
            "views_after_" + digest("abc"),
        )
        self.assertEqual(canonical({"b": 1, "a": 2}), '{"a":2,"b":1}')

    def test_invalid_request_rejected(self):
        with self.assertRaises(Invalid):
            self.ledger.write({"name": "a"}, None, "bad id")
        with self.assertRaises(LedgerError):
            self.ledger.write({"name": "a"}, None, "bad id")


if __name__ == "__main__":
    unittest.main()
