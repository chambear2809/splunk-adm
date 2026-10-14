"""Lab equivalence tests for the grounded ``adm_scope_options`` macro."""

from __future__ import annotations

import os
import json
import sys
import unittest
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
FIELDS = ["environment", "cluster", "namespace", "service", "last_seen", "pods"]


@unittest.skipUnless(
    os.environ.get("ADM_LAB") == "1", "set ADM_LAB=1 with the lab running"
)
class ScopeOptionsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        sys.path.insert(0, str(HERE))
        import lab

        cls.lab = lab
        cls.keys = [f"phase2-scope-{uuid.uuid4().hex}-{i}" for i in range(2)]
        cls.addClassCleanup(cls.cleanup_rows)
        payload = json.dumps(
            [
                {
                    "_key": cls.keys[0],
                    "service": "",
                    "environment": "",
                    "cluster": "",
                    "namespace": "",
                    "pod_uid": "p1",
                    "last_seen": "2000000000",
                },
                {
                    "_key": cls.keys[1],
                    "service": "",
                    "cluster": "",
                    "namespace": "",
                    "pod_uid": "p2",
                    "last_seen": "2000000100",
                },
            ]
        )
        cls.lab.search(
            f"| makeresults format=json data={json.dumps(payload)} | outputlookup append=true key_field=_key adm_service_workload"
        )
        cls.rows = lab.search("| `adm_scope_options`", "0", "now")
        cls.direct = lab.search(
            '| inputlookup adm_service_workload | fillnull value="" environment cluster namespace service '
            "| stats max(last_seen) AS last_seen dc(pod_uid) AS pods by environment cluster namespace service "
            "| fields environment cluster namespace service last_seen pods "
            "| sort 0 environment cluster namespace service",
            "0",
            "now",
        )

    @classmethod
    def cleanup_rows(cls) -> None:
        for key in cls.keys:
            with cls.lab._mgmt(
                "DELETE",
                f"/servicesNS/nobody/splunk_adm/storage/collections/data/adm_service_workload/{key}",
            ) as response:
                response.read()

    @staticmethod
    def normalize(rows: list[dict]) -> list[dict]:
        return [{field: row.get(field) for field in FIELDS} for row in rows]

    def test_macro_matches_grounded_lookup_aggregation(self) -> None:
        self.assertEqual(self.normalize(self.rows), self.normalize(self.direct))
        for row in self.rows:
            self.assertEqual(set(row), set(FIELDS))

    def test_blank_dimensions_are_preserved_when_present(self) -> None:
        blank = next((row for row in self.rows if row.get("service") == ""), None)
        self.assertIsNotNone(blank)
        self.assertEqual(blank["environment"], "")
        self.assertEqual(blank["cluster"], "")
        self.assertEqual(blank["namespace"], "")
        self.assertEqual(str(blank["pods"]), "2")
        self.assertEqual(str(blank["last_seen"]), "2000000100")
