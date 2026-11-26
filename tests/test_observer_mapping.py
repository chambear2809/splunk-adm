import hashlib
import json
import os
import sys
import unittest

sys.path.insert(
    0, os.path.join(os.path.dirname(__file__), "..", "splunk_app", "splunk_adm", "bin")
)
from adm_kv_lib.ledger import Invalid  # noqa: E402
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


if __name__ == "__main__":
    unittest.main()
