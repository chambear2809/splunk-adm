"""adm_observer_scope field coverage across collection, lookup and migration."""

import configparser
from pathlib import Path
import re
import unittest


APP = Path(__file__).resolve().parents[1] / "splunk_app/splunk_adm"


class ObserverScopeMappingStatusTest(unittest.TestCase):
    def test_collection_fields_are_listed_and_migrated(self):
        collections = configparser.RawConfigParser()
        collections.read(APP / "default/collections.conf")
        fields = {
            key.removeprefix("field.")
            for key in collections["adm_observer_scope"]
            if key.startswith("field.")
        }
        transforms = configparser.RawConfigParser()
        transforms.read(APP / "default/transforms.conf")
        listed = {
            field.strip()
            for field in transforms["adm_observer_scope"]["fields_list"].split(",")
        }
        self.assertLessEqual(fields, listed)

        searches = (APP / "default/savedsearches.conf").read_text()
        stanza = searches.split("[ADM - Migrate observer scope]", 1)[1].split("\n[", 1)[
            0
        ]
        projection = re.search(r"\| fields (_key[^|]*?) \| outputlookup", stanza)
        self.assertIsNotNone(projection)
        projected = set(projection.group(1).split())
        self.assertLessEqual(fields, projected)
        self.assertIn("mapping_status AS adm_existing_status", stanza)
        self.assertIn("mapping_status=adm_existing_status", stanza)


if __name__ == "__main__":
    unittest.main()
