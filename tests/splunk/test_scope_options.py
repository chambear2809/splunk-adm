"""Lab equivalence tests for the grounded ``adm_scope_options`` macro."""

from __future__ import annotations

import os
import json
import base64
import sys
import urllib.parse
import urllib.request
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
        from tools.fault_pipeline import wait_kv_ready

        wait_kv_ready(timeout=180)
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
        self.assertFalse([row for row in self.rows if row.get("warnings")])
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

    def test_scope_options_read_all_rows_beyond_one_page(self) -> None:
        limit_path = "/servicesNS/nobody/splunk_adm/configs/conf-limits/kvstore"
        original = self.lab._json("GET", limit_path)["entry"][0]["content"][
            "max_rows_per_query"
        ]
        self.addCleanup(
            self.lab._json, "POST", limit_path, {"max_rows_per_query": original}
        )
        self.lab._json("POST", limit_path, {"max_rows_per_query": "10000"})
        prefix = "scope-overpage-" + uuid.uuid4().hex + "-"
        namespace = prefix + "namespace"
        self.addCleanup(self._delete_scope_namespace, namespace)
        seeded = [
            {
                "_key": f"{prefix}{index:05d}",
                "service": f"{prefix}{index:05d}",
                "environment": "overpage",
                "cluster": "cluster",
                "namespace": namespace,
                "pod_uid": f"{prefix}{index:05d}",
                "last_seen": 2000000000 + index,
            }
            for index in range(50001)
        ]
        for start in range(0, len(seeded), 1000):
            self._batch_save_scope_rows(seeded[start : start + 1000])
        rows = self.lab.search(
            "| `adm_scope_options` | search service="
            + json.dumps(prefix + "*")
            + " | stats dc(service) AS service_count",
            "0",
            "now",
        )
        self.assertEqual(int(rows[0]["service_count"]), 50001)

    def _scope_rest(self, method: str, path: str, payload: object | None) -> None:
        secrets = self.lab.read_secrets()
        auth = base64.b64encode(f"admin:{secrets['SPLUNK_PASSWORD']}".encode()).decode()
        separator = "&" if "?" in path else "?"
        request = urllib.request.Request(
            self.lab.MGMT + path + separator + "output_mode=json",
            data=None if payload is None else json.dumps(payload).encode(),
            method=method,
            headers={
                "Authorization": f"Basic {auth}",
                **({"Content-Type": "application/json"} if payload is not None else {}),
            },
        )
        with urllib.request.urlopen(
            request, context=self.lab._CTX, timeout=120
        ) as response:
            response.read()

    def _batch_save_scope_rows(self, rows: list[dict]) -> None:
        self._scope_rest(
            "POST",
            "/servicesNS/nobody/splunk_adm/storage/collections/data/"
            "adm_service_workload/batch_save",
            rows,
        )

    def _delete_scope_namespace(self, namespace: str) -> None:
        query = urllib.parse.urlencode({"query": json.dumps({"namespace": namespace})})
        self._scope_rest(
            "DELETE",
            "/servicesNS/nobody/splunk_adm/storage/collections/data/"
            f"adm_service_workload?{query}",
            None,
        )
