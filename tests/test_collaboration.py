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
            self.assertIs(empty["writable"], True)
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
            read_only = collab_rest.handle_request(
                {"method": "GET", "query": [["kind", "views"]]},
                "token",
            )
            self.assertIs(read_only["writable"], False)
            self.assertEqual(read_only["payload"]["views"][0]["name"], "Shared")
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

    def test_assertions_kind_writable_flag_and_head_only_store_path(self):
        rows = []
        calls = []
        state = {"writable": True, "admin": False}

        class HeadOnlyStore:
            def __init__(self, token, collection):
                self.session_key = token
                self.collection = collection

            def allows_write(self, capability):
                if capability == "admin_all_objects":
                    return state["admin"]
                return state["writable"]

            def scan(self, limit):
                raise AssertionError("full scan must not be called")

            def scan_metadata(self, limit):
                calls.append(("scan_metadata", limit))
                meta_keys = {
                    "_key",
                    "format",
                    "epoch",
                    "epoch_root",
                    "seal",
                    "kind",
                    "previous_revision",
                    "request_id",
                    "operation_fingerprint",
                    "revision",
                }
                return [
                    {k: v for k, v in r.items() if k in meta_keys}
                    for r in sorted(rows, key=lambda r: r["_key"])[:limit]
                ]

            def get(self, key):
                calls.append(("get", key))
                for r in rows:
                    if r["_key"] == key:
                        return dict(r)
                return None

            def insert(self, document):
                if any(r["_key"] == document["_key"] for r in rows):
                    raise RuntimeError("duplicate")
                rows.append(dict(document))

            def delete_many(self, keys):
                calls.append(("delete_many", list(keys)))
                ks = set(keys)
                rows[:] = [r for r in rows if r["_key"] not in ks]

        assertion = {
            "id": "a1",
            "name": "Payments calls Auth",
            "owner": "alice",
            "kind": "reaches",
            "scope": "fabric-a",
            "src": "10.0.0.1",
            "dst": "10.0.0.2",
            "transport": "tcp",
            "port": 443,
        }
        with (
            patch.object(collab_rest, "SplunkCollectionStore", HeadOnlyStore),
            patch.object(collab_rest, "principal_of", return_value="alice"),
        ):
            written = collab_rest.handle_request(
                {
                    "method": "POST",
                    "query": [["kind", "assertions"]],
                    "payload": {
                        "expectedRevision": None,
                        "requestId": "req-a1",
                        "payload": {"assertions": [assertion]},
                    },
                },
                "token",
            )
            self.assertEqual(written["state"], "configured")
            calls.clear()
            got = collab_rest.handle_request(
                {"method": "GET", "query": [["kind", "assertions"]]}, "token"
            )
            self.assertTrue(got["writable"])
            self.assertEqual(len(got["payload"]["assertions"]), 1)
            self.assertEqual([c[0] for c in calls], ["scan_metadata", "get"])

            state["writable"] = False
            got_ro = collab_rest.handle_request(
                {"method": "GET", "query": [["kind", "assertions"]]}, "token"
            )
            self.assertFalse(got_ro["writable"])

            # Non-admin cannot compact.
            with self.assertRaises(Forbidden):
                collab_rest.handle_request(
                    {
                        "method": "POST",
                        "query": [["kind", "assertions"]],
                        "payload": {
                            "action": "compact",
                            "expectedRevision": written["committedRevision"],
                            "requestId": "req-c1",
                        },
                    },
                    "token",
                )


if __name__ == "__main__":
    unittest.main()
