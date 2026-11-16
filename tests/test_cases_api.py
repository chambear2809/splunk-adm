import json
import os
import sys
import tempfile
import unittest

sys.path.insert(
    0, os.path.join(os.path.dirname(__file__), "..", "splunk_app", "splunk_adm", "bin")
)
from adm_cases_lib import CaseStore
from adm_cases_lib.api import CaseAPI


class CaseAPITest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.denied = set()
        self.store = CaseStore(
            os.path.join(self.tmp.name, "cases.sqlite"),
            lambda p, a, c: (p, a, c) not in self.denied,
        )
        self.api = CaseAPI(self.store)
        self.create_data = {
            "schema_version": 1,
            "title": "Case",
            "window": {"start": "2026-01-01T00:00:00Z", "end": "2026-01-02T00:00:00Z"},
        }

    def call(
        self,
        method,
        path,
        data=None,
        *,
        principal="alice",
        key="key",
        query=None,
        headers=None,
    ):
        if data is not None:
            headers = (
                headers
                if headers is not None
                else {"Content-Type": "application/json", "Idempotency-Key": key}
            )
            body = json.dumps(data).encode()
        else:
            body = b""
        status, result, result_headers = self.api.handle(
            method, path, principal=principal, query=query, headers=headers, body=body
        )
        self.assertEqual(result_headers["Cache-Control"], "no-store")
        return status, result

    def create(self, key="create"):
        status, result = self.call("POST", "/cases", self.create_data, key=key)
        self.assertEqual(status, 201)
        return result

    def test_lifecycle_revision_retry_and_access(self):
        case = self.create()
        path = "/cases/" + case["id"]
        self.assertEqual(self.call("GET", path, principal="bob")[0], 403)
        payload = {"expected_revision": 1, "item": {"type": "note", "text": "A note"}}
        first = self.call("POST", path + "/entries", payload, key="append")
        self.assertEqual(first[0], 200)
        self.assertEqual(
            first, self.call("POST", path + "/entries", payload, key="append")
        )
        self.assertEqual(
            self.call("POST", path + "/entries", payload, key="other")[0], 409
        )
        self.assertEqual(
            self.call(
                "POST",
                path + "/share",
                {"expected_revision": 2, "member": "bob", "grant": True},
                key="share",
            )[0],
            200,
        )
        self.assertEqual(self.call("GET", path, principal="bob")[0], 200)
        self.denied.add(("bob", "read", case["id"]))
        self.assertEqual(self.call("GET", path, principal="bob")[0], 403)
        self.assertEqual(self.call("GET", path + "/export")[0], 200)
        status, audit = self.call("GET", path + "/audit", query={"limit": "1"})
        self.assertEqual(status, 200)
        self.assertEqual(len(audit["items"]), 1)
        self.assertIsNotNone(audit["next"])
        self.assertEqual(
            self.call("DELETE", path, {"expected_revision": 3}, key="delete")[0], 200
        )
        self.assertEqual(self.call("GET", path)[0], 404)

    def test_list_pagination_and_query_validation(self):
        self.create("one")
        self.create("two")
        status, page = self.call("GET", "/cases", query={"limit": "1"})
        self.assertEqual(status, 200)
        self.assertEqual(len(page["items"]), 1)
        status, second = self.call(
            "GET", "/cases", query={"limit": "1", "after": page["next"]}
        )
        self.assertEqual(status, 200)
        self.assertNotEqual(page["items"][0]["id"], second["items"][0]["id"])
        for query in (
            {"limit": "0"},
            {"limit": "101"},
            {"limit": ["1", "2"]},
            {"principal": "bob"},
        ):
            self.assertEqual(self.call("GET", "/cases", query=query)[0], 400)

    def test_identity_schema_and_transport_validation(self):
        self.assertEqual(self.call("GET", "/cases", principal=None)[0], 401)
        self.assertEqual(
            self.call("POST", "/cases", {**self.create_data, "principal": "bob"})[0],
            400,
        )
        self.assertEqual(
            self.call(
                "POST",
                "/cases",
                self.create_data,
                headers={"Content-Type": "application/json"},
            )[0],
            400,
        )
        self.assertEqual(
            self.call(
                "POST",
                "/cases",
                self.create_data,
                headers={"Content-Type": "text/plain", "Idempotency-Key": "a"},
            )[0],
            415,
        )
        self.assertEqual(self.call("PUT", "/cases", self.create_data)[0], 405)
        self.assertEqual(self.call("GET", "/cases/not-a-uuid")[0], 404)
        headers = {"Content-Type": "application/json", "Idempotency-Key": "a"}
        for body in (b'{"title":"x","title":"y"}', b'{"x":NaN}', b"\xff"):
            self.assertEqual(
                self.api.handle(
                    "POST", "/cases", principal="alice", headers=headers, body=body
                )[0],
                400,
            )
        self.assertEqual(
            CaseAPI(self.store, max_body_bytes=1).handle(
                "POST", "/cases", principal="alice", headers=headers, body=b"{}"
            )[0],
            413,
        )
        case = self.create()
        path = "/cases/" + case["id"]
        for revision in (None, True, 0, "1"):
            self.assertEqual(
                self.call("DELETE", path, {"expected_revision": revision})[0], 400
            )

    def test_evidence_requires_current_source_validation(self):
        case = self.create()
        path = "/cases/" + case["id"] + "/captures"
        payload = {
            "expected_revision": 1,
            "item": {
                "label": "capture",
                "captured_at": "2026-01-01T00:00:00Z",
                "data": {"source": "s"},
            },
        }
        self.assertEqual(self.call("POST", path, payload, key="capture")[0], 403)
        checks = []
        self.api = CaseAPI(
            self.store, source_validator=lambda *args: checks.append(args) or True
        )
        self.assertEqual(self.call("POST", path, payload, key="capture")[0], 200)
        self.api.source_validator = lambda *args: False
        self.assertEqual(self.call("POST", path, payload, key="capture")[0], 403)
        self.assertEqual(checks[0][:3], ("alice", case["id"], "capture"))
        payload["item"]["data"]["entitlements"] = ["all"]
        self.assertEqual(self.call("POST", path, payload, key="next")[0], 400)
        self.assertEqual(
            self.call(
                "POST",
                path.replace("captures", "attachments"),
                {
                    "expected_revision": 2,
                    "item": {"label": "a", "media_type": "text/plain", "content": "x"},
                },
            )[0],
            403,
        )

    def test_exceptions_do_not_leak(self):
        self.store.entitlement = lambda *args: (_ for _ in ()).throw(
            RuntimeError("secret")
        )
        status, body = self.call("GET", "/cases")
        self.assertEqual((status, body), (403, {"error": "forbidden"}))
        self.api.store = object()
        self.assertEqual(self.call("GET", "/cases"), (500, {"error": "internal_error"}))


if __name__ == "__main__":
    unittest.main()
