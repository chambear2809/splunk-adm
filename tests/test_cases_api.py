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

    def test_saved_comparison_reference_attachment_uses_current_source_access(self):
        case = self.create()
        path = "/cases/" + case["id"]
        self.store.capture_resolver = lambda _p, ref: {
            "captured_at": "2026-01-01T03:00:00Z",
            "data": {"value": ref},
            "source": {"dataset": ref},
        }
        allowed = True
        self.store.source_entitlement = lambda *_: allowed
        _, noted = self.call(
            "POST",
            path + "/entries",
            {"expected_revision": 1, "item": {"type": "question", "text": "Why?"}},
            key="entry",
        )
        _, captured = self.call(
            "POST",
            path + "/captures",
            {"expected_revision": 2, "reference": "one"},
            key="capture",
        )
        payload = {
            "expected_revision": 3,
            "entry_id": noted["entries"][0]["id"],
            "capture_id": captured["capture_ids"][0],
        }
        status, result = self.call(
            "POST", path + "/attachments", payload, key="attachment"
        )
        self.assertEqual(status, 200)
        self.assertEqual(result["attachments"][0]["kind"], "capture_reference")
        allowed = False
        status, redacted = self.call(
            "POST", path + "/attachments", payload, key="attachment"
        )
        self.assertEqual(status, 200)
        self.assertEqual(redacted["attachments"], [])
        self.assertEqual(redacted["redactions"]["attachments"], 1)
        self.assertEqual(
            self.call(
                "POST", path + "/attachments", payload, key="forged", principal="bob"
            )[0],
            403,
        )

    def test_denial_after_commit_does_not_prove_the_write_failed(self):
        case = self.create()
        path = "/cases/" + case["id"]
        # Model loss of read access at the final response authorization boundary.
        # The write itself is permitted, but its resulting document cannot leave.
        self.store.entitlement = lambda _p, action, _c: action != "read"
        payload = {"expected_revision": 1, "item": {"type": "note", "text": "One note"}}
        self.assertEqual(
            self.call("POST", path + "/entries", payload, key="stable")[0], 403
        )
        self.store.entitlement = lambda *_: True
        stored = self.call("GET", path)[1]
        self.assertEqual(stored["revision"], 2)
        self.assertEqual(len(stored["entries"]), 1)
        status, retried = self.call("POST", path + "/entries", payload, key="stable")
        self.assertEqual(status, 200)
        self.assertEqual(retried, stored)

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
        payload = {"expected_revision": 1, "reference": "trusted", "label": "capture"}
        self.assertEqual(self.call("POST", path, payload, key="capture")[0], 422)
        # A legacy boolean API validator cannot authorize any capture.
        self.api = CaseAPI(self.store, source_validator=lambda *args: True)
        self.assertEqual(self.call("POST", path, payload, key="capture")[0], 422)
        self.store.capture_resolver = lambda principal, reference: {
            "captured_at": "2026-01-01T00:00:00Z",
            "data": {"count": 3},
            "source": {"dataset": "trusted"},
        }
        self.store.source_entitlement = lambda principal, kind, item: True
        self.assertEqual(
            self.call(
                "POST", path, {**payload, "item": {"data": {"count": 99}}}, key="bad"
            )[0],
            400,
        )
        result = self.call("POST", path, payload, key="capture")
        self.assertEqual(result[0], 200)
        self.assertEqual(result[1]["captures"][0]["data"]["count"], 3)
        self.store.source_entitlement = lambda *args: False
        retry = self.call("POST", path, payload, key="capture")
        self.assertEqual(retry[0], 200)
        self.assertEqual(retry[1]["captures"], [])
        self.assertEqual(retry[1]["redactions"]["captures"], 1)
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

    def test_capture_selector_and_opaque_ids(self):
        case = self.create()
        path = "/cases/" + case["id"]
        self.store.capture_resolver = lambda p, r: {
            "captured_at": "2026-01-01T00:00:00Z",
            "data": {"name": r},
            "source": {"dataset": r},
        }
        self.store.source_entitlement = lambda *args: True
        first = self.call(
            "POST",
            path + "/captures",
            {"expected_revision": 1, "reference": "one"},
            key="one",
        )[1]
        second = self.call(
            "POST",
            path + "/captures",
            {"expected_revision": 2, "reference": "two"},
            key="two",
        )[1]
        ids = second["capture_ids"]
        self.assertEqual(ids[0], first["capture_ids"][0])
        listed = self.call("GET", "/cases")[1]["items"][0]
        self.assertEqual(listed["capture_ids"], ids)
        self.assertEqual(listed["captures"], [])
        for target in (path, path + "/export"):
            status, result = self.call("GET", target, query={"capture_id": ids[1]})
            self.assertEqual(status, 200)
            self.assertEqual(result["captures"][0]["id"], ids[1])
            self.assertEqual(result["redactions"]["captures"], 1)
        self.assertEqual(self.call("GET", path, query={"capture_id": "bad"})[0], 400)
        self.assertEqual(
            self.call(
                "GET",
                path,
                query={"capture_id": "00000000-0000-4000-8000-000000000000"},
            )[0],
            404,
        )
        self.assertEqual(
            self.call("GET", path, principal="bob", query={"capture_id": "bad"})[0], 403
        )
        self.assertEqual(
            self.call(
                "POST",
                path + "/entries",
                {"expected_revision": 3, "item": {"type": "note", "text": "x"}},
                query={"capture_id": ids[0]},
            )[0],
            400,
        )

    def test_unavailable_source_is_distinct_and_does_not_commit(self):
        case = self.create()
        path = "/cases/" + case["id"]
        capture_path = path + "/captures"
        payload = {"expected_revision": 1, "reference": "trusted"}
        self.store.capture_resolver = lambda *args: (_ for _ in ()).throw(
            RuntimeError("sensitive backend detail")
        )
        self.store.source_entitlement = lambda *args: True
        self.assertEqual(
            self.call("POST", capture_path, payload, key="cap"),
            (422, {"error": "source_unavailable"}),
        )
        self.store.capture_resolver = lambda *args: {
            "captured_at": "2026-01-01T00:00:00Z",
            "data": {},
            "source": {"id": "source"},
        }
        self.store.source_entitlement = lambda *args: False
        self.assertEqual(
            self.call("POST", capture_path, payload, key="cap"),
            (422, {"error": "source_unavailable"}),
        )
        self.assertEqual(self.call("GET", path)[1]["revision"], 1)
        self.assertEqual(
            self.call("POST", capture_path, payload, principal="bob", key="bob")[0], 403
        )
        self.store.source_entitlement = lambda *args: True
        self.assertEqual(self.call("POST", capture_path, payload, key="cap")[0], 200)

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
