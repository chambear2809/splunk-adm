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

    def test_missed_slots_macro_parses_and_is_empty_against_shipped_disabled_jobs(
        self,
    ):
        # The four targets ship disabled=1, so the real REST-backed disabled
        # filter must exclude all of them: no expected slots, hence no rows.
        # Running the unmodified macro against the live lab is itself the
        # syntax check (invalid SPL would fail the search job).
        rows = self.lab.search("| `adm_health_missed_slots`", "0", "1")
        self.assertEqual(rows, [])

    def test_missed_slots_macro_reports_missing_slot_not_satisfied_slot_or_disabled(
        self,
    ):
        import re
        import time

        query = self.definition("adm_health_missed_slots")
        # Pin the lookback/grace tunables to small literal values so the
        # Python-side expected-slot computation below only has to reason
        # about a 30-minute window instead of the shipped 24-hour default.
        query = query.replace("`adm_missed_slot_lookback`", "1800")
        query = query.replace("`adm_missed_slot_grace`", "600")

        now = int(time.time())
        end = now // 60 * 60
        start = end - 1800
        slots = list(range(start, end + 60, 60))
        grace_cutoff = now - 600

        def phase(slot):
            return (slot // 60) % 5

        eligible = {
            p: [s for s in slots if phase(s) == p and s <= grace_cutoff]
            for p in (0, 1, 2, 3)
        }
        # Need at least two eligible identity-builder slots: one left
        # unsatisfied (expected missing) and one marked successful (expected
        # absent from the report).
        self.assertGreaterEqual(len(eligible[1]), 2)
        self.assertTrue(eligible[0])

        identity_missing = eligible[1][1]
        identity_success = [slot for slot in eligible[1] if slot != identity_missing]
        binding_success = eligible[2]

        success_payload = ";".join(
            [f"ADM - Identity builder@{s}" for s in identity_success]
            + [f"ADM - Service binding@{s}" for s in binding_success]
        )
        scheduler_seed = (
            "| makeresults | eval samples=split("
            + json.dumps(success_payload)
            + ', ";") | mvexpand samples | eval parts=split(samples, "@"), '
            'savedsearch_name=mvindex(parts, 0), scheduled_time=tonumber(mvindex(parts, 1)), sid="scheduler__health_fixture" '
        )
        query, n = re.subn(
            r"search index=_internal source=\*scheduler\.log\* "
            r'app="splunk_adm" savedsearch_name="ADM -\*" status=success\s*',
            scheduler_seed + " ",
            query,
        )
        self.assertEqual(n, 1)

        # Identity builder and Conversation rollup are reported enabled;
        # Service binding is enabled too (its slots are all satisfied above);
        # Service backends is reported disabled and has no successes at all,
        # so it must never appear despite having unsatisfied slots.
        config_payload = ";".join(
            [
                "ADM - Identity builder@0",
                "ADM - Service binding@0",
                "ADM - Service backends@1",
                "ADM - Conversation rollup@0",
            ]
        )
        config_seed = (
            "| makeresults | eval samples=split("
            + json.dumps(config_payload)
            + ', ";") | mvexpand samples | eval parts=split(samples, "@"), '
            'name=mvindex(parts, 0), adm_kind="config", adm_disabled=tonumber(mvindex(parts, 1)), adm_is_scheduled=1 '
        )
        query, n = re.subn(
            r"rest /servicesNS/-/splunk_adm/saved/searches splunk_server=local count=0\s*"
            r'\|\s*where match\(title, "\^ADM - "\)\s*'
            r"\|\s*rename title AS name\s*"
            r'\|\s*eval adm_kind="config", adm_disabled=tonumber\(disabled\), adm_is_scheduled=tonumber\(is_scheduled\)\s*'
            r"\|\s*fields adm_kind name adm_disabled adm_is_scheduled",
            config_seed,
            query,
        )
        self.assertEqual(n, 1)

        rows = self.lab.search(query, "0", "1")
        by_name = {}
        for row in rows:
            if row["reason"] == "missed_slot":
                by_name.setdefault(row["name"], set()).add(int(row["scheduled_time"]))

        # The one deliberately-unsatisfied Identity builder slot is reported...
        self.assertIn(identity_missing, by_name.get("ADM - Identity builder", set()))
        # ...and the satisfied ones are not.
        self.assertFalse(
            set(identity_success) & by_name.get("ADM - Identity builder", set())
        )
        # Service binding had every eligible slot satisfied: nothing missing.
        self.assertNotIn("ADM - Service binding", by_name)
        # Service backends is disabled, despite zero successes: nothing missing.
        self.assertNotIn("ADM - Service backends", by_name)
        # No successful checkpoint means one target-level incident, not a
        # fabricated backlog spanning every slot before first operation.
        no_checkpoint = [
            row for row in rows if row["name"] == "ADM - Conversation rollup"
        ]
        self.assertEqual(len(no_checkpoint), 1)
        self.assertEqual(no_checkpoint[0]["reason"], "no_successful_checkpoint")
        self.assertNotIn("scheduled_time", no_checkpoint[0])
        self.assertNotIn("scheduled_time_human", no_checkpoint[0])
        self.assertNotIn("late_seconds", no_checkpoint[0])
        for row in rows:
            if row["reason"] == "missed_slot":
                self.assertGreaterEqual(int(row["late_seconds"]), 595)

    def missed_slots_fixture_query(self, scheduler_search):
        """Replace evidence sources, retaining the detector's filtering SPL."""
        import re

        query = self.definition("adm_health_missed_slots")
        query, count = re.subn(
            r"search index=_internal source=\*scheduler\.log\* "
            r'app="splunk_adm" savedsearch_name="ADM -\*" status=success',
            lambda _: scheduler_search,
            query,
        )
        self.assertEqual(count, 1)
        # No builder schedule is enabled to manufacture expected slots.
        query, count = re.subn(
            r"rest /servicesNS/-/splunk_adm/saved/searches "
            r"splunk_server=local count=0",
            '| makeresults | eval title="ADM - Identity builder", '
            "disabled=0, is_scheduled=1",
            query,
        )
        self.assertEqual(count, 1)
        return query

    def test_missed_slots_manual_success_does_not_hide_scheduled_slot(self):
        import time

        now = int(time.time())
        slot = now - 1200
        slot -= (slot - 60) % 300
        evidence = (
            '| makeresults | eval samples="scheduler__checkpoint@'
            f"{slot - 300};manual_dispatch@"
            f"{slot};scheduler__health_fixture@{slot + 300};"
            f'not_scheduler__fixture@{slot + 600};missing@{slot + 900}" '
            '| makemv delim=";" samples | mvexpand samples '
            '| eval parts=split(samples,"@"), sid=mvindex(parts,0), '
            'sid=if(sid="missing",null(),sid), '
            "scheduled_time=tonumber(mvindex(parts,1)), "
            'savedsearch_name="ADM - Identity builder", status="success"'
        )
        query = self.missed_slots_fixture_query(evidence).replace(
            "`adm_missed_slot_grace`", "0"
        )
        missing = {
            int(row["scheduled_time"])
            for row in self.lab.search(query, "-24h", "now")
            if row["name"] == "ADM - Identity builder"
            and row["reason"] == "missed_slot"
        }
        self.assertIn(slot, missing)
        self.assertNotIn(slot + 300, missing)
        self.assertIn(slot + 600, missing)
        self.assertIn(slot + 900, missing)

    def checkpoint_fixture(self):
        import time

        first = int(time.time()) - 1800
        first -= (first - 60) % 300
        evidence = (
            f'| makeresults | eval scheduled_time=split("{first};{first + 600}",";") '
            "| mvexpand scheduled_time | eval scheduled_time=tonumber(scheduled_time), "
            'savedsearch_name="ADM - Identity builder", sid="scheduler__checkpoint_test"'
        )
        rows = self.lab.search(self.missed_slots_fixture_query(evidence), "-25h", "now")
        return first, [row for row in rows if row["name"] == "ADM - Identity builder"]

    def test_missed_slots_before_first_success_are_not_reported(self):
        first, rows = self.checkpoint_fixture()
        self.assertTrue(rows)
        self.assertTrue(all(row["reason"] == "missed_slot" for row in rows))
        self.assertTrue(all(int(row["scheduled_time"]) > first for row in rows))

    def test_missed_slots_gap_after_first_success_is_reported(self):
        first, rows = self.checkpoint_fixture()
        missing = {int(row["scheduled_time"]) for row in rows}
        self.assertIn(first + 300, missing)
        self.assertNotIn(first, missing)
        self.assertNotIn(first + 600, missing)

    def test_missed_slots_manual_only_success_has_no_checkpoint(self):
        query = self.missed_slots_fixture_query(
            "| makeresults | eval scheduled_time=floor(now()/300)*300-1200+60, "
            'savedsearch_name="ADM - Identity builder", sid="manual_checkpoint"'
        )
        rows = [
            row
            for row in self.lab.search(query, "-25h", "now")
            if row["name"] == "ADM - Identity builder"
        ]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["reason"], "no_successful_checkpoint")
        self.assertNotIn("scheduled_time", rows[0])

    def test_missed_slots_paused_period_after_checkpoint_is_reported(self):
        import time

        before_pause = int(time.time()) - 2400
        before_pause -= (before_pause - 60) % 300
        resumed = before_pause + 900
        evidence = (
            f'| makeresults | eval scheduled_time=split("{before_pause};{resumed}",";") '
            "| mvexpand scheduled_time | eval scheduled_time=tonumber(scheduled_time), "
            'savedsearch_name="ADM - Identity builder", sid="scheduler__maintenance_test"'
        )
        # Preserve both pre-pause and post-resume successes in the history.
        # The first post-resume success must not reset the checkpoint and hide
        # the intervening slots: their closed slices still require replay.
        rows = [
            row
            for row in self.lab.search(
                self.missed_slots_fixture_query(evidence), "-25h", "now"
            )
            if row["name"] == "ADM - Identity builder"
        ]
        self.assertTrue(all(row["reason"] == "missed_slot" for row in rows))
        missing = {int(row["scheduled_time"]) for row in rows}
        self.assertTrue({before_pause + 300, before_pause + 600}.issubset(missing))
        self.assertNotIn(before_pause, missing)
        self.assertNotIn(resumed, missing)

    def change_live_config(self, path, changes):
        original = self.lab._json("GET", path)["entry"][0]["content"]
        restore = {
            key: str(int(original[key]))
            if isinstance(original[key], bool)
            else original[key]
            for key in changes
        }
        # Register first: a POST could take effect even if its response is lost.
        self.addCleanup(self.lab._json, "POST", path, restore)
        self.lab._json("POST", path, changes)

    def test_missed_slots_unscheduled_targets_produce_no_rows(self):
        import urllib.parse

        for target in (
            "ADM - Identity builder",
            "ADM - Service binding",
            "ADM - Service backends",
            "ADM - Conversation rollup",
        ):
            path = "/servicesNS/nobody/splunk_adm/saved/searches/" + urllib.parse.quote(
                target, safe=""
            )
            self.change_live_config(path, {"disabled": "0", "is_scheduled": "0"})
        self.assertEqual(
            self.lab.search("| `adm_health_missed_slots`", "-25h", "now"), []
        )

    def test_missed_slots_saved_alert_uses_full_history_and_checkpoint(self):
        import time
        import urllib.parse
        import uuid
        from datetime import datetime

        now = int(time.time())
        end = now // 60 * 60
        start = end - 86400

        def identity_slot(timestamp):
            return timestamp - (timestamp - 60) % 300

        old_slots = [identity_slot(end - 2 * 3600), identity_slot(start + 600)]
        manual_slot = identity_slot(end - 3 * 3600)
        checkpoint = identity_slot(start - 1)
        token = uuid.uuid4().hex
        events = [
            {
                "index": "adm",
                "sourcetype": "adm:health:scheduler",
                # Scheduler evidence can be logged after its scheduled slot.
                # Keep the checkpoint event just before the lookback boundary
                # so a minute tick during dispatch cannot age out the fixture.
                "time": start - 1 if slot == checkpoint else slot,
                "event": {
                    "health_token": token,
                    "app": "splunk_adm",
                    "savedsearch_name": "ADM - Identity builder",
                    "scheduled_time": slot,
                    "status": "success",
                    "sid": "manual_health_fixture"
                    if slot == manual_slot
                    else f"scheduler__health_{token}_{slot}",
                },
            }
            for slot in [*old_slots, manual_slot, checkpoint]
        ]
        self.lab._hec_post("\n".join(json.dumps(event) for event in events).encode())
        fixture_search = (
            f'index=adm sourcetype="adm:health:scheduler" health_token="{token}"'
        )
        deadline = time.monotonic() + 30
        while True:
            count = self.lab.search(fixture_search + " | stats count", "-26h", "now")
            if count[0]["count"] == str(len(events)):
                break
            self.assertLess(
                time.monotonic(), deadline, "historical fixtures not indexed"
            )
            time.sleep(1)

        query = self.missed_slots_fixture_query(
            "search " + fixture_search + ' app="splunk_adm" '
            'savedsearch_name="ADM -*" status=success'
        ).replace("floor(now()/60)*60", str(end))
        macro_path = (
            "/servicesNS/nobody/splunk_adm/configs/conf-macros/adm_health_missed_slots"
        )
        self.change_live_config(macro_path, {"definition": query.removeprefix("| ")})

        # Control: the former dispatch range loses every successful checkpoint,
        # so it cannot distinguish healthy historical slots from an unseen run.
        short_rows = self.lab.search("| `adm_health_missed_slots`", "-1h", "now")
        short_identity = [
            row for row in short_rows if row["name"] == "ADM - Identity builder"
        ]
        self.assertEqual(len(short_identity), 1)
        self.assertEqual(short_identity[0]["reason"], "no_successful_checkpoint")
        self.assertNotIn("scheduled_time", short_identity[0])

        path = "/servicesNS/nobody/splunk_adm/saved/searches/" + urllib.parse.quote(
            "ADM - Scheduler missed-slot alert", safe=""
        )
        self.change_live_config(path, {"disabled": "0", "is_scheduled": "0"})
        # Dispatch the installed alert itself, without overriding its time range
        # or search. Only its macro's evidence sources were isolated above.
        sid = self.lab._json("POST", path + "/dispatch", {"trigger_actions": "0"})[
            "sid"
        ]
        job = self.lab._wait_job(sid)
        rows = self.lab._results(sid)
        missing = {
            int(row["scheduled_time"])
            for row in rows
            if row["name"] == "ADM - Identity builder"
            and row["reason"] == "missed_slot"
        }
        self.assertFalse(set(old_slots) & missing)
        self.assertIn(manual_slot, missing)
        earliest = datetime.fromisoformat(job["earliestTime"].replace("Z", "+00:00"))
        latest = datetime.fromisoformat(job["latestTime"].replace("Z", "+00:00"))
        expected_start = int(latest.timestamp()) // 60 * 60 - 86400
        self.assertLessEqual(earliest.timestamp(), expected_start - 300)
        # The preceding checkpoint is outside the expected-slot set, but must
        # still be searchable using the alert's actual resolved bounds.
        history = self.lab.search(
            fixture_search + f" scheduled_time={checkpoint} | stats count",
            str(earliest.timestamp()),
            "now",
        )
        self.assertEqual(history[0]["count"], "1")

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
