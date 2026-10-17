"""KV Store collection schema regressions, without a Splunk server."""

import configparser
from pathlib import Path
import unittest


APP = Path(__file__).resolve().parents[1] / "splunk_app/splunk_adm"
CATALOG_BOUNDARY = '{"service": 1, "environment": 1, "cluster": 1, "namespace": 1}'


def _collections() -> configparser.RawConfigParser:
    parser = configparser.RawConfigParser()
    parser.read(APP / "default/collections.conf")
    return parser


class CollectionsConfigTest(unittest.TestCase):
    def test_v1_and_v2_catalogs_keep_boundary_acceleration(self):
        collections = _collections()
        for name in ("adm_app_catalog", "adm_app_catalog_v2"):
            with self.subTest(collection=name):
                self.assertEqual(
                    collections[name].get("accelerated_fields.boundary"),
                    CATALOG_BOUNDARY,
                )

    def test_v2_collections_mirror_v1_schema_and_acceleration(self):
        collections = _collections()
        pairs = [
            (name.removesuffix("_v2"), name)
            for name in collections.sections()
            if name.endswith("_v2")
        ]
        self.assertTrue(pairs)
        for v1, v2 in pairs:
            with self.subTest(collection=v2):
                self.assertIn(v1, collections)
                self.assertEqual(dict(collections[v1]), dict(collections[v2]))


if __name__ == "__main__":
    unittest.main()
