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
            ):
                with self.assertRaises(Invalid):
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


if __name__ == "__main__":
    unittest.main()
