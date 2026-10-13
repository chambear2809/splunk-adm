"""Evaluate shipped scheduler windows with Splunk's actual relative-time parser."""

import configparser
import os
from pathlib import Path
import unittest

import lab

ROOT = Path(__file__).resolve().parents[2]


@unittest.skipUnless(os.environ.get("ADM_LAB") == "1", "requires disposable Splunk lab")
class SchedulerWindowTest(unittest.TestCase):
    def test_rollup_windows_are_valid_and_adjacent_at_cron_slots(self):
        conf = configparser.RawConfigParser()
        conf.read(ROOT / "splunk_app/splunk_adm/default/savedsearches.conf")
        rollup = conf["ADM - Conversation rollup"]
        earliest, latest = (
            rollup["dispatch.index_earliest"],
            rollup["dispatch.index_latest"],
        )
        rows = lab.search(
            "| makeresults | eval anchor=1791918000, "
            f'first=relative_time(anchor,"{earliest}"), last=relative_time(anchor,"{latest}"), '
            f'next_first=relative_time(anchor+300,"{earliest}") | table first last next_first'
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(float(rows[0].get("first") or 0), 1791917400)
        self.assertEqual(float(rows[0].get("last") or 0), 1791917700)
        self.assertEqual(rows[0].get("next_first"), rows[0].get("last"))
