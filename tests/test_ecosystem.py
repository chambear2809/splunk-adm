import os
import sys
import unittest

sys.path.insert(
    0, os.path.join(os.path.dirname(__file__), "..", "splunk_app", "splunk_adm", "bin")
)
from adm_ops_lib.ecosystem import producer_for, sourcetype_for  # noqa: E402


class EcosystemCatalogTests(unittest.TestCase):
    def test_catalog_is_existing_producers(self):
        self.assertEqual(sourcetype_for("stream_netflow"), "stream:netflow")
        self.assertEqual(sourcetype_for("f5"), "f5:bigip:syslog")
        self.assertIn("Splunk Add-on", producer_for("haproxy"))
        with self.assertRaises(KeyError):
            sourcetype_for("custom_collector")
