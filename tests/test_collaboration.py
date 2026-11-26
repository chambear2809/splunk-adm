import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(
    0, os.path.join(os.path.dirname(__file__), "..", "splunk_app", "splunk_adm", "bin")
)
from adm_collaboration_lib import rest as collab_rest  # noqa: E402
from adm_collaboration_lib.payload import (  # noqa: E402
    PayloadError,
    ownership_payload,
    validate,
    views_payload,
)
from adm_kv_lib.ledger import Forbidden, Invalid, RecordLedger  # noqa: E402


class MemoryStore:
    def __init__(self, writable=True):
        self.rows = []
        self.writable = writable

    def allows_write(self, capability):
        return self.writable

    def scan(self, limit):
        return sorted(self.rows, key=lambda row: row["_key"])[:limit]

    def insert(self, document):
        if any(row["_key"] == document["_key"] for row in self.rows):
            raise RuntimeError("duplicate")
        self.rows.append(dict(document))


class CollaborationPayloadTests(unittest.TestCase):
    def test_views_accept_shared_only(self):
        payload = views_payload(
            {
                "views": [
                    {
                        "id": "view-1",
                        "name": "Payments Prod",
                        "visibility": "shared",
                        "owner": "alice",
                        "team": "netops",
                        "state": {"mode": "live", "tab": "network"},
                    }
                ]
            },
            "alice",
        )
        self.assertEqual(payload["views"][0]["visibility"], "shared")

    def test_private_views_rejected_from_shared_ledger(self):
        with self.assertRaises(PayloadError):
            views_payload(
                {
                    "views": [
                        {
                            "id": "view-1",
                            "name": "Mine",
                            "visibility": "private",
                            "owner": "alice",
                            "state": {"mode": "live"},
                        }
                    ]
                },
                "alice",
            )

    def test_ownership_is_directory_only(self):
        payload = ownership_payload(
            {
                "records": [
                    {
                        "service": "payments",
                        "environment": "prod",
                        "owner": "alice",
                        "team": "netops",
                        "contact": "pager-payments",
                    }
                ]
            }
        )
        self.assertEqual(payload["records"][0]["service"], "payments")
        with self.assertRaises(PayloadError):
            validate("ownership", {"records": "nope"}, "alice")

    def test_ledger_round_trip(self):
        ledger = RecordLedger(MemoryStore(), "views")
        written = ledger.write({"views": []}, None, "req-1")
        self.assertEqual(written["state"], "configured")
        self.assertEqual(ledger.read()["payload"], {"views": []})

    def test_rest_get_post_and_write_denial(self):
        store = MemoryStore(writable=True)

        class FakeStore:
            def __init__(self, token, collection):
                self.session_key = token
                self.collection = collection

            def allows_write(self, capability):
                return store.allows_write(capability)

            def scan(self, limit):
                return store.scan(limit)

            def insert(self, document):
                return store.insert(document)

        shared = {
            "id": "s1",
            "name": "Shared",
            "visibility": "shared",
            "owner": "alice",
            "state": {"mode": "live"},
        }
        with (
            patch.object(collab_rest, "SplunkCollectionStore", FakeStore),
            patch.object(collab_rest, "principal_of", return_value="alice"),
        ):
            empty = collab_rest.handle_request(
                {"method": "GET", "query": [["kind", "views"]]},
                "token",
            )
            self.assertEqual(empty["state"], "absent")
            saved = collab_rest.handle_request(
                {
                    "method": "POST",
                    "query": [["kind", "views"]],
                    "payload": {
                        "expectedRevision": None,
                        "requestId": "req-1",
                        "payload": {"views": [shared]},
                    },
                },
                "token",
            )
            self.assertEqual(saved["payload"]["views"][0]["name"], "Shared")

            store.writable = False
            with self.assertRaises(Forbidden):
                collab_rest.handle_request(
                    {
                        "method": "POST",
                        "query": [["kind", "views"]],
                        "payload": {
                            "expectedRevision": saved["committedRevision"],
                            "requestId": "req-2",
                            "payload": {"views": [shared]},
                        },
                    },
                    "token",
                )

            store.writable = True
            with self.assertRaises(Invalid):
                collab_rest.handle_request(
                    {
                        "method": "POST",
                        "query": [["kind", "views"]],
                        "payload": "x" * (collab_rest.MAX_BODY_BYTES + 1),
                    },
                    "token",
                )

    def test_rest_compaction_requires_administrator(self):
        store = MemoryStore()
        granted = {"adm_investigate"}
        test = self

        class FakeStore:
            def __init__(self, token, collection):
                self.session_key = token

            def allows_write(self, capability):
                return capability in granted

            def scan(self, limit):
                return store.scan(limit)

            def insert(self, document):
                return store.insert(document)

            def delete(self, key):
                test.assertIn("admin_all_objects", granted)
                store.rows = [row for row in store.rows if row["_key"] != key]

        def post(body):
            return collab_rest.handle_request(
                {"method": "POST", "query": [["kind", "ownership"]], "payload": body},
                "token",
            )

        record = {
            "service": "payments",
            "environment": "prod",
            "owner": "alice",
            "team": "netops",
            "contact": "pager-payments",
        }
        with (
            patch.object(collab_rest, "SplunkCollectionStore", FakeStore),
            patch.object(collab_rest, "principal_of", return_value="alice"),
        ):
            revision = None
            for index in range(3):
                revision = post(
                    {
                        "expectedRevision": revision,
                        "requestId": "req-" + str(index),
                        "payload": {"records": [record]},
                    }
                )["committedRevision"]
            compact = {
                "action": "compact",
                "expectedRevision": revision,
                "requestId": "compact-1",
            }
            with self.assertRaises(Forbidden):
                post(compact)
            with self.assertRaises(Invalid):
                post({**compact, "payload": {"records": []}})
            with self.assertRaises(Invalid):
                post({**compact, "action": "purge"})
            granted.add("admin_all_objects")
            result = post(compact)
            self.assertEqual(result["recordCount"], 2)
            self.assertEqual(result["epoch"], 1)
            self.assertEqual(result["payload"]["records"][0]["owner"], "alice")

    def test_view_ownership_checked_against_superseded_head(self):
        store = MemoryStore()
        ledger = RecordLedger(store, "views")
        bob = {
            "id": "b1",
            "name": "Bob view",
            "visibility": "shared",
            "owner": "bob",
            "state": {"mode": "live"},
        }
        head = ledger.write({"views": [bob]}, None, "req-1")["committedRevision"]

        class FakeStore:
            def __init__(self, token, collection):
                self.session_key = token

            def allows_write(self, capability):
                return True

            def scan(self, limit):
                return store.scan(limit)

            def insert(self, document):
                return store.insert(document)

        with (
            patch.object(collab_rest, "SplunkCollectionStore", FakeStore),
            patch.object(collab_rest, "principal_of", return_value="alice"),
        ):
            with self.assertRaises(Forbidden):
                collab_rest.handle_request(
                    {
                        "method": "POST",
                        "query": [["kind", "views"]],
                        "payload": {
                            "expectedRevision": head,
                            "requestId": "req-2",
                            "payload": {"views": []},
                        },
                    },
                    "token",
                )
        self.assertEqual(len(store.rows), 1)


if __name__ == "__main__":
    unittest.main()
