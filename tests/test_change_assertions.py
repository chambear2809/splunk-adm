import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(
    0, os.path.join(os.path.dirname(__file__), "..", "splunk_app", "splunk_adm", "bin")
)
from adm_collaboration_lib import rest as collab_rest  # noqa: E402
from adm_collaboration_lib.assertions import (  # noqa: E402
    MAX_ASSERTIONS,
    assertions_payload,
)
from adm_collaboration_lib.payload import PayloadError, validate  # noqa: E402
from adm_kv_lib.ledger import Forbidden, RecordLedger  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), "..")


def reaches(**overrides):
    row = {
        "id": "a1",
        "name": "Web reaches DB",
        "kind": "reaches",
        "scope": "prod",
        "src": "10.1.1.10",
        "dst": "10.2.2.20",
        "transport": "tcp",
        "port": 5432,
    }
    row.update(overrides)
    return row


class MemoryStore:
    def __init__(self):
        self.rows = []

    def scan(self, limit):
        return sorted(self.rows, key=lambda row: row["_key"])[:limit]

    def insert(self, document):
        if any(row["_key"] == document["_key"] for row in self.rows):
            raise RuntimeError("duplicate")
        self.rows.append(dict(document))

    def delete(self, key):
        self.rows = [row for row in self.rows if row["_key"] != key]


class AssertionPayloadTests(unittest.TestCase):
    def test_accepts_each_kind_and_defaults_owner(self):
        document = assertions_payload(
            {
                "assertions": [
                    reaches(),
                    reaches(
                        id="a2",
                        name="Two paths",
                        kind="redundant",
                        minObservers=2,
                        team="netops",
                    ),
                    {
                        "id": "a3",
                        "name": "No new drops",
                        "kind": "no_new_blocked",
                        "scope": "prod",
                        "src": "2001:db8::1",
                        "dst": "2001:db8::2",
                        "note": "CAB 42",
                    },
                ]
            },
            "alice",
        )
        rows = document["assertions"]
        self.assertEqual([row["owner"] for row in rows], ["alice"] * 3)
        self.assertEqual(rows[1]["minObservers"], 2)
        self.assertNotIn("port", rows[2])
        self.assertEqual(validate("assertions", document, "alice"), document)

    def test_rejects_invalid_rows(self):
        invalid = [
            reaches(kind="absent"),
            reaches(src="10.1.1.010"),
            reaches(src="::ffff:10.1.1.10"),
            reaches(src="2001:DB8::1", dst="2001:db8::2"),
            reaches(dst="10.1.1.10"),
            reaches(scope="unmapped:10.0.0.0/8"),
            reaches(scope=""),
            reaches(transport="icmp"),
            reaches(port=0),
            reaches(port="5432"),
            reaches(port=True),
            reaches(minObservers=2),
            reaches(kind="redundant", minObservers=1),
            reaches(kind="redundant", minObservers=9),
            reaches(kind="no_new_blocked"),
            reaches(note="line\nbreak"),
            reaches(note="x" * 281),
            reaches(extra=1),
            reaches(owner="bad owner"),
            reaches(name="   "),
        ]
        for row in invalid:
            with self.subTest(row=row), self.assertRaises(PayloadError):
                assertions_payload({"assertions": [row]}, "alice")

    def test_document_bounds_and_duplicates(self):
        with self.assertRaises(PayloadError):
            assertions_payload({"assertions": [reaches(), reaches(name="b")]}, "a")
        with self.assertRaises(PayloadError):
            assertions_payload({"assertions": [reaches(), reaches(id="a2")]}, "a")
        with self.assertRaises(PayloadError):
            assertions_payload({"assertions": [], "extra": 1}, "a")
        too_many = [
            reaches(id="a" + str(i), name="n" + str(i))
            for i in range(MAX_ASSERTIONS + 1)
        ]
        with self.assertRaises(PayloadError):
            assertions_payload({"assertions": too_many}, "a")
        long_note = "x" * 280
        heavy = [
            reaches(id="a" + str(i), name="n" + str(i), note=long_note)
            for i in range(MAX_ASSERTIONS)
        ]
        with self.assertRaises(PayloadError):
            assertions_payload({"assertions": heavy}, "a")


class AssertionRestTests(unittest.TestCase):
    def _fake(self, store, granted, collections):
        class FakeStore:
            def __init__(self, token, collection):
                collections.append(collection)

            def allows_write(self, capability):
                return capability in granted

            def scan(self, limit):
                return store.scan(limit)

            def insert(self, document):
                return store.insert(document)

            def delete(self, key):
                return store.delete(key)

        return FakeStore

    def _post(self, body, principal="alice"):
        with patch.object(collab_rest, "principal_of", return_value=principal):
            return collab_rest.handle_request(
                {"method": "POST", "query": [["kind", "assertions"]], "payload": body},
                "token",
            )

    def test_round_trip_uses_dedicated_collection(self):
        store, collections = MemoryStore(), []
        fake = self._fake(store, {"adm_investigate"}, collections)
        with patch.object(collab_rest, "SplunkCollectionStore", fake):
            saved = self._post(
                {
                    "expectedRevision": None,
                    "requestId": "req-1",
                    "payload": {"assertions": [reaches()]},
                }
            )
            self.assertEqual(saved["payload"]["assertions"][0]["owner"], "alice")
            with patch.object(collab_rest, "principal_of", return_value="bob"):
                read = collab_rest.handle_request(
                    {"method": "GET", "query": [["kind", "assertions"]]}, "token"
                )
        self.assertEqual(read["payload"], saved["payload"])
        self.assertEqual(set(collections), {"adm_change_assertions"})

    def test_write_requires_collection_write(self):
        store = MemoryStore()
        fake = self._fake(store, set(), [])
        with (
            patch.object(collab_rest, "SplunkCollectionStore", fake),
            self.assertRaises(Forbidden),
        ):
            self._post(
                {
                    "expectedRevision": None,
                    "requestId": "req-1",
                    "payload": {"assertions": [reaches()]},
                }
            )
        self.assertEqual(store.rows, [])

    def test_cannot_modify_or_delete_another_owners_assertion(self):
        store = MemoryStore()
        bob = reaches(owner="bob")
        head = RecordLedger(store, "assertions").write(
            {"assertions": [bob]}, None, "req-1"
        )["committedRevision"]
        fake = self._fake(store, {"adm_investigate"}, [])
        attempts = [
            [],
            [{**bob, "port": 5433}],
            [reaches(id="a2", name="Mine", owner="bob"), bob],
        ]
        with patch.object(collab_rest, "SplunkCollectionStore", fake):
            for index, rows in enumerate(attempts):
                with self.subTest(rows=rows), self.assertRaises(Forbidden):
                    self._post(
                        {
                            "expectedRevision": head,
                            "requestId": "deny-" + str(index),
                            "payload": {"assertions": rows},
                        }
                    )
            kept = self._post(
                {
                    "expectedRevision": head,
                    "requestId": "req-2",
                    "payload": {
                        "assertions": [bob, reaches(id="a2", name="Alice copy")]
                    },
                }
            )
        self.assertEqual(len(kept["payload"]["assertions"]), 2)

    def test_compaction_requires_administrator(self):
        store = MemoryStore()
        granted = {"adm_investigate"}
        fake = self._fake(store, granted, [])
        with patch.object(collab_rest, "SplunkCollectionStore", fake):
            revision = None
            for index in range(2):
                revision = self._post(
                    {
                        "expectedRevision": revision,
                        "requestId": "req-" + str(index),
                        "payload": {"assertions": [reaches()]},
                    }
                )["committedRevision"]
            compact = {
                "action": "compact",
                "expectedRevision": revision,
                "requestId": "compact-1",
            }
            with self.assertRaises(Forbidden):
                self._post(compact)
            granted.add("admin_all_objects")
            self.assertEqual(self._post(compact)["epoch"], 1)


class AssertionPackagingTests(unittest.TestCase):
    def _read(self, relative):
        with open(os.path.join(ROOT, relative), encoding="utf-8") as handle:
            return handle.read()

    def test_collection_is_admin_written_and_not_replicated(self):
        collections = self._read("splunk_app/splunk_adm/default/collections.conf")
        block = collections.split("[adm_change_assertions]", 1)[1].split("\n[", 1)[0]
        self.assertIn("replicate = false", block)
        self.assertIn("field.payload_json = string", block)
        meta = self._read("splunk_app/splunk_adm/metadata/default.meta")
        self.assertIn(
            "[collections/adm_change_assertions]\n"
            "access = read : [ adm_investigate, adm_viewer, admin, sc_admin ], "
            "write : [ admin, sc_admin ]",
            meta,
        )

    def test_change_request_macro_is_bounded_and_validated(self):
        macros = self._read("splunk_app/splunk_adm/default/macros.conf")
        block = macros.split("[adm_change_request_window(1)]", 1)[1].split("\n[", 1)[0]
        self.assertIn(
            'validation = match(number, "^[A-Za-z]{2,10}[0-9]{1,16}\\z")', block
        )
        self.assertIn('sourcetype="snow:change_request"', block)
        self.assertIn("| head 501", block)
        self.assertIn("records_capped", block)
        for field in (
            "number",
            "sys_id",
            "state",
            "start_date",
            "end_date",
            "work_start",
            "work_end",
            "sys_updated_on",
        ):
            self.assertIn(field, block)


if __name__ == "__main__":
    unittest.main()
