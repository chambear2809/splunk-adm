import hashlib
import json
import os
import sys
import unittest

sys.path.insert(
    0, os.path.join(os.path.dirname(__file__), "..", "splunk_app", "splunk_adm", "bin")
)
from unittest.mock import patch

from adm_kv_lib.ledger import Forbidden, Invalid, Unavailable  # noqa: E402
from adm_observer_lib import rest as observer_rest  # noqa: E402
from adm_observer_lib.rest import mapping_key, validate_mapping  # noqa: E402


class ObserverMappingTests(unittest.TestCase):
    def test_stable_key_matches_json_array(self):
        kind, observer = "exporter", "198.51.100.10"
        expected = hashlib.sha256(
            json.dumps([kind, observer], separators=(",", ":")).encode()
        ).hexdigest()
        self.assertEqual(mapping_key(kind, observer), expected)

    def test_normalizes_and_rejects_reserved_scope(self):
        document = validate_mapping(
            {
                "observer_kind": "Exporter",
                "observer": "198.51.100.10",
                "scope": "dc1",
                "cluster": "prod-a",
            }
        )
        self.assertEqual(document["observer_kind"], "exporter")
        self.assertEqual(document["mapping_status"], "mapped")
        self.assertEqual(document["_key"], mapping_key("exporter", "198.51.100.10"))
        with self.assertRaises(Invalid):
            validate_mapping(
                {
                    "observer_kind": "exporter",
                    "observer": "198.51.100.10",
                    "scope": "unmapped:abc",
                }
            )

    def test_realm_must_be_documented_token(self):
        validate_mapping(
            {
                "observer_kind": "o11y_export",
                "observer": "cluster-a",
                "scope": "dc1",
                "realm": "us0",
            }
        )
        with self.assertRaises(Invalid):
            validate_mapping(
                {
                    "observer_kind": "o11y_export",
                    "observer": "cluster-a",
                    "scope": "dc1",
                    "realm": "us-east-1",
                }
            )

    def test_list_fails_closed_when_scan_hits_bound(self):
        class FullStore:
            def __init__(self, token, collection):
                self.session_key = token

            def scan(self, limit):
                return [
                    {
                        "_key": f"{index:04d}",
                        "observer_kind": "cluster",
                        "observer": "x",
                    }
                    for index in range(limit)
                ]

        with patch.object(observer_rest, "SplunkCollectionStore", FullStore):
            with self.assertRaises(Unavailable):
                observer_rest.handle_request({"method": "GET"}, "token")

    def test_post_requires_administrator_write(self):
        class ReadOnlyStore:
            def __init__(self, token, collection):
                self.session_key = token

            def allows_write(self, capability):
                return False

            def insert(self, document):
                raise AssertionError("insert must not run")

        with patch.object(observer_rest, "SplunkCollectionStore", ReadOnlyStore):
            with self.assertRaises(Forbidden):
                observer_rest.handle_request(
                    {
                        "method": "POST",
                        "payload": {
                            "observer_kind": "cluster",
                            "observer": "atlas-k3s",
                            "scope": "dc1",
                        },
                    },
                    "token",
                )

    def test_rejects_bad_origin_urls_and_oversized_body(self):
        for field in (
            "observability_origin",
            "controller_origin",
            "thousandeyes_origin",
        ):
            for bad in (
                "http://example.com",
                "https://",
                "https://user:pw@example.com",
                "https://host:99999",
                "https://host:0",
                "https://host:abc",
                "https://host/api",
                "https://host?x=1",
                "https://host/?x=1",
                "https://host#top",
                "https://host?",
                "https://host#",
                "https://host\r\n",
                " https://host",
                "https://host ",
                "https://host\t",
                "https://host\x7f",
                "https://host name",
                "https://trusted.com\\evil",
                "https://host:",
                "https://[::1]:",
                "https://host:000443",
                "https://host<script>",
                'https://host"quoted"',
                "https://host;foo",
                "https://host\u200b",
                "https://host\x9f",
                "HTTPS://host",
                "https://[bad",
                "https://host]",
                "https://ho[st]",
                "https://host:443",
                "https://host:443/",
                "https://[2001:db8::1]:443",
                "https://Host.Example.com",
                "https://HOST",
                "https://[fe80::1%25eth0]",
                "https://[fe80::1%eth0]",
                "https://[2001:DB8::1]",
                "https://[2001:0db8::1]",
                "https://[0:0:0:0:0:0:0:1]",
                "https://[::ffff:192.0.2.1]",
                "https://[::ffff:192.0.2.1]/",
                "https://[2001:db8::1:1:1:1:1]",
                "https://[2001:0:1:0:0:1::]",
                "https://010.0.0.1",
                "https://0x7f.0.0.1",
                "https://127.1",
                "https://2130706433",
                "https://123",
                "https://foo.123",
                "https://foo.0x",
                "https://foo.0x1",
                "https://999.999.999.999",
                "https://1.2.3.4.5",
                "https://1.2.3.04",
                "https://[127.0.0.1]",
                "https://" + "a" * 250,
            ):
                with self.subTest(field=field, bad=bad), self.assertRaises(Invalid):
                    validate_mapping(
                        {
                            "observer_kind": "cluster",
                            "observer": "atlas-k3s",
                            "scope": "dc1",
                            field: bad,
                        }
                    )
        with self.assertRaises(Invalid):
            observer_rest.handle_request(
                {"method": "POST", "payload": "x" * (observer_rest.MAX_BODY_BYTES + 1)},
                "token",
            )

    def test_accepts_valid_origin_urls(self):
        for field in (
            "observability_origin",
            "controller_origin",
            "thousandeyes_origin",
        ):
            for good in (
                "https://host",
                "https://host/",
                "https://host:8090",
                "https://host:8090/",
                "https://app.us1.signalfx.com",
                "https://198.51.100.10:8443",
                "https://198.51.100.10/",
                "https://[2001:db8::1]:8443",
                "https://[2001:db8::1]/",
                "https://[::1]",
                "https://[::]/",
                "https://[::ffff:c000:201]/",
                "https://[2001:0:1::1:0:0]",
                "https://[2001:db8:0:1:1:1:1:1]",
                "https://[1:0:0:1::1]",
                "https://foo.0x1g",
                "https://foo.123a",
            ):
                with self.subTest(field=field, good=good):
                    document = validate_mapping(
                        {
                            "observer_kind": "cluster",
                            "observer": "atlas-k3s",
                            "scope": "dc1",
                            field: good,
                        }
                    )
                    self.assertEqual(document[field], good)
        for bad_direct in ("", None, 123):
            with self.subTest(bad_direct=bad_direct), self.assertRaises(Invalid):
                observer_rest._https_origin(bad_direct, "controller_origin")

    def test_duplicate_with_changed_optional_field_is_rejected(self):
        doc = validate_mapping(
            {
                "observer_kind": "cluster",
                "observer": "atlas-k3s",
                "scope": "dc1",
                "region": "us-east-1",
            }
        )

        class DuplicateStore:
            def __init__(self, token, collection):
                self.session_key = token

            def allows_write(self, capability):
                return True

            def insert(self, document):
                raise RuntimeError("duplicate")

            def scan(self, limit):
                return [doc]

        with patch.object(observer_rest, "SplunkCollectionStore", DuplicateStore):
            with self.assertRaises(Invalid):
                observer_rest.handle_request(
                    {
                        "method": "POST",
                        "payload": {
                            "observer_kind": "cluster",
                            "observer": "atlas-k3s",
                            "scope": "dc1",
                            "region": "us-west-2",
                        },
                    },
                    "token",
                )

    def test_post_duplicate_uses_point_get_and_get_uses_field_projection(self):
        doc = validate_mapping(
            {
                "observer_kind": "cluster",
                "observer": "atlas-k3s",
                "scope": "dc1",
            }
        )
        calls = []

        class PointStore:
            def __init__(self, token, collection):
                self.session_key = token

            def allows_write(self, capability):
                return True

            def scan(self, limit, *, fields=None):
                calls.append(("scan", limit, fields))
                return [doc]

            def insert(self, document):
                calls.append(("insert", document["_key"]))
                raise RuntimeError("duplicate")

            def get(self, key):
                calls.append(("get", key))
                return dict(doc) if key == doc["_key"] else None

        with patch.object(observer_rest, "SplunkCollectionStore", PointStore):
            listed = observer_rest.handle_request({"method": "GET"}, "token")
            self.assertEqual(listed["recordCount"], 1)
            self.assertEqual(
                calls[0],
                (
                    "scan",
                    observer_rest.MAPPING_LIMIT + 1,
                    "_key,observer_kind,observer,scope,cluster,mapping_status",
                ),
            )
            calls.clear()
            res = observer_rest.handle_request(
                {
                    "method": "POST",
                    "payload": {
                        "observer_kind": "cluster",
                        "observer": "atlas-k3s",
                        "scope": "dc1",
                    },
                },
                "token",
            )
            self.assertTrue(res["idempotent"])
            # Duplicate check must use single-key point get, never a full scan.
            self.assertEqual(calls, [("insert", doc["_key"]), ("get", doc["_key"])])


if __name__ == "__main__":
    unittest.main()
