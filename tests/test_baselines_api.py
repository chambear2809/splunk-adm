import copy
import json
import os
import sys
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(
    0, os.path.join(os.path.dirname(__file__), "..", "splunk_app", "splunk_adm", "bin")
)
from adm_baselines_lib.api import BaselineAPI  # noqa: E402
from adm_baselines_lib.store import BaselineStore, signature  # noqa: E402

sys.path.insert(0, os.path.dirname(__file__))
from test_baselines import capture  # noqa: E402


class BaselineAPITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.sources = {"a": capture(), "b": capture(10)}
        self.denied = set()
        self.store = BaselineStore(
            os.path.join(self.tmp.name, "api.db"),
            lambda principal, action, ident: (
                (principal, action, ident) not in self.denied
            ),
            lambda principal, ref: copy.deepcopy(self.sources[ref]),
            clock=lambda: 32,
            source_entitlement=lambda principal, ref, evidence: (
                (principal, "source", ref) not in self.denied
            ),
        )
        self.api = BaselineAPI(self.store, max_body_bytes=4096)

    def tearDown(self):
        self.tmp.cleanup()

    def call(
        self, method, path, data=None, *, principal="alice", key="key", query=None
    ):
        headers = {"Content-Type": "application/json", "Idempotency-Key": key}
        body = json.dumps(data).encode() if data is not None else b""
        return self.api.handle(
            method, path, principal=principal, query=query, headers=headers, body=body
        )

    def create(self):
        status, result, _ = self.call(
            "POST", "/baselines", {"name": "Production", "reference": "a"}, key="create"
        )
        self.assertEqual(status, 201)
        return "/baselines/" + result["id"]

    def test_manual_evaluate_endpoint_rejects_injected_findings(self):
        created = self.call(
            "POST", "/baselines", {"name": "x", "reference": "a"}, key="create"
        )
        path = "/baselines/" + created[1]["id"]
        definition = {
            "id": "w",
            "threshold": 1,
            "cooldownSeconds": 10,
            "expectedWindows": [],
        }
        self.call(
            "POST",
            path + "/watches",
            {"expected_revision": 1, "definition": definition},
            key="watch",
        )
        self.sources["b"]["dependencies"][0]["blocked"] = True
        endpoint = path + "/watches/w/evaluate"
        payload = {"expected_revision": 2, "baseline_version": 1, "reference": "b"}
        self.assertEqual(
            self.call("POST", endpoint, {**payload, "findings": []}, key="bad")[0], 400
        )
        result = self.call("POST", endpoint, payload, key="evaluate")
        self.assertEqual(result[0], 200)
        self.assertEqual((result[1]["inserted"], result[1]["surfaced"]), (1, 1))
        self.assertEqual(
            self.call("POST", endpoint, payload, key="evaluate")[1],
            {
                "id": result[1]["id"],
                "revision": result[1]["revision"],
                "resultWithheld": True,
            },
        )

    def test_lifecycle_and_source_access(self):
        path = self.create()
        self.assertEqual(
            self.call("GET", "/baselines")[1]["items"][0]["name"], "Production"
        )
        self.assertEqual(self.call("GET", path)[1]["capture"], capture())
        self.assertEqual(
            self.call(
                "POST",
                path + "/versions",
                {"expected_revision": 1, "reference": "b"},
                key="version",
            )[0],
            200,
        )
        self.assertEqual(
            self.call("GET", path + "/versions", query={"limit": "1"})[1]["next"], 1
        )
        self.assertEqual(
            self.call("GET", path + "/versions/1")[1]["capture"], capture()
        )
        definition = {
            "id": "w",
            "threshold": 1,
            "cooldownSeconds": 5,
            "expectedWindows": [],
        }
        self.assertEqual(
            self.call(
                "POST",
                path + "/watches",
                {"expected_revision": 2, "definition": definition},
                key="watch",
            )[0],
            200,
        )
        self.assertEqual(
            self.call("GET", path + "/watches")[1]["items"][0]["baselineVersion"], 2
        )
        self.sources["c"] = capture(20)
        self.sources["c"]["dependencies"][0]["blocked"] = True
        sig = signature(self.sources["c"]["dependencies"][0])
        data = {
            "expected_revision": 3,
            "signature": sig,
            "reference": "c",
        }
        self.assertEqual(
            self.call("POST", path + "/watches/w/occurrences", data, key="occ")[0], 200
        )
        occurrences = self.call("GET", path + "/watches/w/occurrences")[1]["items"]
        self.assertEqual(len(occurrences), 1)
        self.assertEqual(occurrences[0]["baselineVersion"], 2)
        self.assertEqual(occurrences[0]["changeKinds"], ["newly_blocked"])
        self.assertTrue(
            self.call(
                "GET",
                path + "/watches/w/evaluate",
                query={"signature": sig, "now": "32"},
            )[1]["thresholdMet"]
        )
        self.assertEqual(
            self.call(
                "POST",
                path + "/share",
                {"expected_revision": 4, "member": "bob", "grant": True},
                key="share",
            )[0],
            200,
        )
        self.denied.add(("bob", "source", "c"))
        self.assertEqual(self.call("GET", path + "/export", principal="bob")[0], 200)
        self.assertEqual(
            len(self.call("GET", "/baselines", principal="bob")[1]["items"]), 1
        )
        self.assertEqual(
            self.call(
                "POST",
                path + "/share",
                {"expected_revision": 5, "member": "bob", "grant": False},
                key="revoke",
            )[0],
            200,
        )
        self.assertEqual(
            self.call("DELETE", path, {"expected_revision": 6}, key="delete")[0], 200
        )
        self.assertEqual(self.call("POST", "/baselines/purge", {}, key="purge")[0], 204)

    def test_retries_and_concurrent_revision_conflicts(self):
        with ThreadPoolExecutor(max_workers=4) as pool:
            responses = list(
                pool.map(
                    lambda _: self.call(
                        "POST",
                        "/baselines",
                        {"name": "x", "reference": "a"},
                        key="same",
                    ),
                    range(4),
                )
            )
        self.assertTrue(all(r[0] == 201 and r[1] == responses[0][1] for r in responses))
        path = "/baselines/" + responses[0][1]["id"]
        self.assertEqual(
            self.call(
                "POST",
                "/baselines",
                {"name": "different", "reference": "a"},
                key="same",
            )[0],
            409,
        )

        def update(i):
            return self.call(
                "POST",
                path + "/versions",
                {"expected_revision": 1, "reference": "b"},
                key="v" + str(i),
            )[0]

        with ThreadPoolExecutor(max_workers=2) as pool:
            self.assertCountEqual(list(pool.map(update, range(2))), [200, 409])

    def test_client_cannot_poison_observation_time(self):
        path = self.create()
        definition = {
            "id": "w",
            "threshold": 1,
            "cooldownSeconds": 5,
            "expectedWindows": [],
        }
        self.call(
            "POST",
            path + "/watches",
            {"expected_revision": 1, "definition": definition},
            key="watch",
        )
        self.sources["b"]["dependencies"][0]["blocked"] = True
        sig = signature(self.sources["b"]["dependencies"][0])
        data = {"expected_revision": 2, "signature": sig, "reference": "b"}
        url = path + "/watches/w/occurrences"
        self.assertEqual(
            self.call("POST", url, {**data, "observedAt": 10**15}, key="occ")[0], 400
        )
        self.assertEqual(self.call("POST", url, data, key="occ")[0], 200)
        self.assertEqual(self.call("GET", url)[1]["items"][0]["observedAt"], 32)
        self.assertEqual(
            self.call(
                "GET",
                path + "/watches/w/evaluate",
                query={"signature": sig, "now": "33"},
            )[1]["count"],
            1,
        )

    def test_strict_parser_and_sanitized_errors(self):
        path = self.create()
        h = {"Content-Type": "application/json", "Idempotency-Key": "r"}
        cases = [
            ("POST", "/baselines", b'{"name":"a","name":"b","reference":"a"}', h, 400),
            (
                "POST",
                "/baselines",
                b'{"name":"a","reference":"a","principal":"bob"}',
                h,
                400,
            ),
            (
                "POST",
                "/baselines",
                b'{"name":"a","reference":"a","permission":"allowed"}',
                h,
                400,
            ),
            ("POST", "/baselines", b'{"name":"a","reference":"a","x":NaN}', h, 400),
            ("POST", "/baselines", b"\xff", h, 400),
            ("POST", "/baselines", b" " * 4097, h, 413),
            ("POST", "/baselines", b"{}", {}, 400),
            (
                "POST",
                "/baselines",
                b"{}",
                {"Content-Type": "text/plain", "Idempotency-Key": "x"},
                415,
            ),
            (
                "POST",
                "/baselines",
                b"{}",
                {
                    "Content-Type": "application/json",
                    "content-type": "application/json",
                    "Idempotency-Key": "x",
                },
                400,
            ),
            ("GET", path, b"{}", {}, 400),
            ("PUT", path, b"", {}, 405),
            ("GET", "/baselines/not-uuid", b"", {}, 404),
        ]
        for method, target, body, headers, expected in cases:
            with self.subTest(method=method, target=target, body=body[:30]):
                status, result, response_headers = self.api.handle(
                    method, target, principal="alice", headers=headers, body=body
                )
                self.assertEqual(status, expected)
                self.assertEqual(set(result), {"error"})
                self.assertEqual(response_headers["Cache-Control"], "no-store")
        self.assertEqual(self.call("GET", path, principal=None)[0], 401)
        self.assertEqual(self.call("GET", path, query={"limit": "2"})[0], 400)
        self.assertEqual(
            self.call("GET", path + "/versions", query={"limit": ["2", "3"]})[0], 400
        )
        self.assertEqual(
            self.call(
                "POST",
                path + "/versions",
                {"expected_revision": True, "reference": "b"},
            )[0],
            400,
        )
        self.assertEqual(
            self.call(
                "POST",
                "/baselines",
                {"name": "x", "reference": "unknown"},
                key="unknown",
            )[1],
            {"error": "forbidden"},
        )
        self.denied.add(("alice", "purge", None))
        self.assertEqual(self.call("POST", "/baselines/purge", {}, key="purge")[0], 403)
