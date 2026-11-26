import os
import sys
import unittest

sys.path.insert(
    0, os.path.join(os.path.dirname(__file__), "..", "splunk_app", "splunk_adm", "bin")
)
from adm_collaboration_lib.payload import (  # noqa: E402
    PayloadError,
    ownership_payload,
    validate,
    views_payload,
)
from adm_kv_lib.ledger import RecordLedger  # noqa: E402


class MemoryStore:
    def __init__(self):
        self.rows = []

    def scan(self, limit):
        return sorted(self.rows, key=lambda row: row["_key"])[:limit]

    def insert(self, document):
        if any(row["_key"] == document["_key"] for row in self.rows):
            raise RuntimeError("duplicate")
        self.rows.append(dict(document))


class CollaborationPayloadTests(unittest.TestCase):
    def test_views_accept_shared_and_owner_private(self):
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

    def test_private_view_cannot_change_owner(self):
        with self.assertRaises(PayloadError):
            views_payload(
                {
                    "views": [
                        {
                            "id": "view-1",
                            "name": "Mine",
                            "visibility": "private",
                            "owner": "bob",
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


if __name__ == "__main__":
    unittest.main()
