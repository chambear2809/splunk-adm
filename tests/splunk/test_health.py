"""Read-only data-pipeline health searches against the local Splunk lab."""

from __future__ import annotations

import os
import json
import unittest


@unittest.skipUnless(
    os.environ.get("ADM_LAB") == "1", "set ADM_LAB=1 with the lab running"
)
class HealthSearchTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from pathlib import Path
        import sys

        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import lab

        cls.lab = lab

    def test_source_health_returns_all_sources_and_explicit_empty_status(self):
        query = self.definition("adm_health_sources")
        import re

        query, replacements = re.subn(
            r"search `adm_index_[a-z0-9]+`[^|]*",
            "| makeresults | where false()",
            query,
        )
        self.assertEqual(replacements, 8)
        rows = self.lab.search(query, "0", "1")
        self.assertEqual({row.get("kind") for row in rows}, {"source"})
        self.assertEqual(
            {row.get("name") for row in rows},
            {
                "NetFlow",
                "DC Networking",
                "FTD",
                "Isovalent",
                "Kubernetes",
                "Traces",
                "Hubble",
                "Summary",
            },
        )
        for row in rows:
            self.assertEqual(row.get("records"), "0")
            self.assertEqual(row.get("status"), "no_visible_records")
            self.assertNotIn("max_ingest_lag", row)

    def test_job_health_exposes_app_jobs_and_no_recent_run(self):
        rows = self.lab.search("| `adm_health_jobs`", "0", "1")
        self.assertTrue(rows)
        self.assertTrue(all(row.get("kind") == "job" for row in rows))
        self.assertTrue(all(row.get("name", "").startswith("ADM - ") for row in rows))
        for row in rows:
            self.assertIn(row.get("status"), {"disabled", "no_recent_run", "unknown"})
            self.assertNotIn("last_success", row)

    @staticmethod
    def definition(name):
        import configparser
        from pathlib import Path

        conf = configparser.RawConfigParser()
        path = (
            Path(__file__).resolve().parents[2]
            / "splunk_app/splunk_adm/default/macros.conf"
        )
        conf.read_string(path.read_text().replace("\\\n", ""))
        return "| " + conf[name]["definition"]

    def test_source_lag_and_latest_times_from_actual_macro(self):
        query = self.definition("adm_health_sources")
        seed = (
            '| makeresults | eval samples=split("100@200;300@320", ";") '
            '| mvexpand samples | eval parts=split(samples, "@") '
            "| eval _time=tonumber(mvindex(parts, 0)), _indextime=tonumber(mvindex(parts, 1)) "
        )
        import re

        query = re.sub(r"search `adm_index_netflow`[^|]*", lambda _: seed, query)
        rows = self.lab.search(query, "0", "1")
        netflow = next(row for row in rows if row["name"] == "NetFlow")
        self.assertEqual(netflow["max_ingest_lag"], "100")
        self.assertEqual(netflow["latest_event"], "300")
        self.assertEqual(netflow["latest_indexed"], "320")
        self.assertEqual(netflow["records"], "2")

    def test_source_window_uses_ingestion_time_for_old_events(self):
        import time
        import uuid

        token = uuid.uuid4().hex
        old_time = int(time.time()) - 3 * 86400
        self.lab._hec_post(
            __import__("json")
            .dumps(
                {
                    "index": "adm_alt_nf",
                    "sourcetype": "stream:netflow",
                    "time": old_time,
                    "event": {"health_token": token},
                }
            )
            .encode()
        )
        self.lab._hec_post(
            json.dumps(
                {
                    "index": "adm_alt_nf",
                    "sourcetype": "unrelated:health:test",
                    "time": old_time,
                    "event": {"health_token": token},
                }
            ).encode()
        )
        query = self.definition("adm_health_sources").replace(
            "`adm_index_netflow`", f'index=adm_alt_nf health_token="{token}"'
        )
        deadline = time.monotonic() + 30
        while True:
            rows = self.lab.search(query, "-24h", "now")
            source = next(row for row in rows if row["name"] == "NetFlow")
            if source.get("records") == "1" or time.monotonic() >= deadline:
                break
            time.sleep(1)
        self.assertEqual(source["records"], "1")
        self.assertEqual(int(source["latest_event"]), old_time)
        self.assertGreaterEqual(float(source["max_ingest_lag"]), 3 * 86400 - 10)

    def test_scheduler_macro_preserves_outcomes_and_unknown_configuration(self):
        query = self.definition("adm_health_jobs")
        seed = (
            "| makeresults | eval samples=split("
            '"ADM - Identity builder@failed@100;ADM - Identity builder@success@300;'
            "ADM - Service binding@skipped@200;ADM - Service binding@success@150;"
            'ADM - Missing config@success@250", ";") '
            '| mvexpand samples | eval parts=split(samples, "@"), savedsearch_name=mvindex(parts, 0), '
            "status=mvindex(parts, 1), _time=tonumber(mvindex(parts, 2)) "
        )
        query = query.replace(
            'search index=_internal source=*scheduler.log* app="splunk_adm" savedsearch_name="ADM -*"',
            seed,
        )
        rows = {row["name"]: row for row in self.lab.search(query, "0", "1")}
        failed = rows["ADM - Identity builder"]
        self.assertEqual(failed["failures"], "1")
        self.assertEqual(failed["last_run"], "300")
        self.assertEqual(failed["last_success"], "300")
        self.assertEqual(failed["last_status"], "success")
        skipped = rows["ADM - Service binding"]
        self.assertEqual(skipped["last_status"], "skipped")
        self.assertEqual(skipped["skips"], "1")
        self.assertEqual(skipped["last_success"], "150")
        missing = rows["ADM - Missing config"]
        self.assertNotIn("disabled", missing)
        self.assertEqual(missing["status"], "unavailable")


if __name__ == "__main__":
    unittest.main()
