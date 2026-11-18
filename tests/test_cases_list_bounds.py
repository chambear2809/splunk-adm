"""Byte and count pagination regressions for CaseStore.list_cases."""

from contextlib import closing
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(
    0, str(Path(__file__).resolve().parents[1] / "splunk_app/splunk_adm/bin")
)
from adm_cases_lib.store import CaseStore, MAX_LIST_PAGE_BYTES  # noqa: E402


class CaseListBoundsTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "cases.sqlite"
        self.denied = set()
        self.store = CaseStore(
            self.path,
            lambda _principal, action, case_id: (
                not (action == "read" and case_id in self.denied)
            ),
            max_case_bytes=2_000_000,
        )

    def seed(self, number, *, text="small", expires="2099-01-01T00:00:00Z"):
        case_id = f"00000000-0000-0000-0000-{number:012d}"
        document = {
            "schema_version": 1,
            "id": case_id,
            "revision": 1,
            "title": "Seeded case",
            "window": {
                "start": "2026-01-01T00:00:00Z",
                "end": "2026-01-02T00:00:00Z",
            },
            "captures": [],
            "entries": [
                {
                    "id": "10000000-0000-0000-0000-000000000001",
                    "type": "note",
                    "text": text,
                }
            ],
            "attachments": [],
        }
        with closing(self.store._connect()) as db, db:
            db.execute(
                "INSERT INTO cases VALUES (?, ?, ?, ?, ?)",
                (case_id, "alice", 1, json.dumps(document), expires),
            )
            db.execute("INSERT INTO acl VALUES (?, ?)", (case_id, "alice"))
        return case_id

    @staticmethod
    def envelope_size(page):
        return len(
            json.dumps(page, ensure_ascii=True, separators=(",", ":")).encode("ascii")
        )

    def test_large_cases_page_by_bytes_without_skips_or_duplicates(self):
        ids = [self.seed(index, text="x" * 800_000) for index in range(1, 4)]
        seen = []
        after = ""
        while True:
            page = self.store.list_cases("alice", after=after)
            seen.extend(item["id"] for item in page["items"])
            self.assertLessEqual(self.envelope_size(page), MAX_LIST_PAGE_BYTES)
            if page["next"] is None:
                break
            self.assertEqual(page["next"], page["items"][-1]["id"])
            after = page["next"]
        self.assertEqual(seen, ids)

    def test_expired_and_acl_denied_rows_do_not_consume_page_or_cursor(self):
        allowed_first = self.seed(1, text="x" * 900_000)
        self.seed(2, text="x" * 900_000, expires="2000-01-01T00:00:00Z")
        denied = self.seed(3, text="x" * 900_000)
        allowed_last = self.seed(4, text="x" * 900_000)
        self.denied.add(denied)

        first = self.store.list_cases("alice")
        self.assertEqual([item["id"] for item in first["items"]], [allowed_first])
        self.assertEqual(first["next"], allowed_first)
        second = self.store.list_cases("alice", after=first["next"])
        self.assertEqual([item["id"] for item in second["items"]], [allowed_last])
        self.assertIsNone(second["next"])

    def test_default_count_limit_and_cursor_semantics_are_unchanged(self):
        ids = [self.seed(index) for index in range(1, 4)]
        first = self.store.list_cases("alice", limit=1)
        self.assertEqual([item["id"] for item in first["items"]], [ids[0]])
        self.assertEqual(first["next"], ids[0])
        second = self.store.list_cases("alice", after=first["next"], limit=1)
        self.assertEqual([item["id"] for item in second["items"]], [ids[1]])
        self.assertEqual(second["next"], ids[1])
        last = self.store.list_cases("alice", after=second["next"], limit=1)
        self.assertEqual([item["id"] for item in last["items"]], [ids[2]])
        self.assertIsNone(last["next"])

    def test_first_custom_oversized_case_remains_listable(self):
        case_id = self.seed(1, text="x" * (MAX_LIST_PAGE_BYTES + 100))
        page = self.store.list_cases("alice")
        self.assertEqual([item["id"] for item in page["items"]], [case_id])
        self.assertIsNone(page["next"])
        self.assertGreater(self.envelope_size(page), MAX_LIST_PAGE_BYTES)


if __name__ == "__main__":
    unittest.main()
