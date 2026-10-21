"""Unit regressions for the recovery entrypoint's detector-row target selection."""

from __future__ import annotations

import importlib.util
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "splunk_app/splunk_adm/bin"
for path in (BIN, BIN / "lib"):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))

SPEC = importlib.util.spec_from_file_location(
    "adm_recovery_entry", BIN / "adm_recovery.py"
)
entry = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(entry)

V2_ROWS = (
    "ADM - Network client history builder",
    "ADM - Conversation rollup v2",
    "ADM - Traffic observation rollup v2",
    "ADM - Application catalog v2",
)


class FakeRecovery:
    rows: list[dict] = []
    ran: list[str] = []
    queries: list[str] = []

    def __init__(self, api, settings):
        self.settings = settings

    def search(self, query):
        FakeRecovery.queries.append(query)
        return FakeRecovery.rows

    def run(self, name):
        FakeRecovery.ran.append(name)
        return {"status": "noop", "name": name}


class EarliestReplayableTest(unittest.TestCase):
    def test_v2_rows_before_a_v1_gap_do_not_block_recovery(self):
        rows = [{"name": name, "scheduled_time": "100"} for name in V2_ROWS]
        rows.append({"name": "ADM - Service binding", "scheduled_time": "400"})
        rows.append({"name": "ADM - Identity builder", "scheduled_time": "200"})
        self.assertEqual(entry.earliest_replayable(rows), "ADM - Identity builder")

    def test_only_unrecoverable_or_malformed_rows_yield_no_target(self):
        rows = [{"name": name, "scheduled_time": "100"} for name in V2_ROWS]
        rows.append({"name": "ADM - Identity builder", "scheduled_time": "bad"})
        rows.append({"name": "ADM - Identity builder"})
        self.assertIsNone(entry.earliest_replayable(rows))
        self.assertIsNone(entry.earliest_replayable([]))

    def test_detector_query_restricts_to_every_recoverable_target(self):
        for name in entry.TARGET_WINDOWS:
            self.assertIn(json.dumps(name), entry.DETECTOR_QUERY)
        for name in V2_ROWS:
            self.assertNotIn(json.dumps(name), entry.DETECTOR_QUERY)
        self.assertEqual(entry._spl_string('a"b\\c'), '"a\\"b\\\\c"')


class EntrypointTargetTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        app = Path(self.tmp.name)
        (app / "default").mkdir()
        (app / "default/adm_recovery.conf").write_text(
            (BIN.parent / "default/adm_recovery.conf")
            .read_text()
            .replace("enabled = 0", "enabled = 1")
        )
        (app / "bin").mkdir()
        FakeRecovery.rows, FakeRecovery.ran, FakeRecovery.queries = [], [], []
        self.patches = [
            patch.object(entry, "BIN", app / "bin"),
            patch.object(entry, "Recovery", FakeRecovery),
            patch.object(entry, "Rest", lambda *args: object()),
        ]
        for item in self.patches:
            item.start()

    def tearDown(self):
        for item in self.patches:
            item.stop()
        self.tmp.cleanup()

    def invoke(self, name):
        payload = {"app": "splunk_adm", "session_key": "x", "result": {"name": name}}
        out = io.StringIO()
        with patch.object(sys, "stdin", io.StringIO(json.dumps(payload))):
            with redirect_stdout(out):
                code = entry.main()
        return code, json.loads(out.getvalue())

    def test_v2_trigger_falls_back_to_the_earliest_v1_gap(self):
        FakeRecovery.rows = [
            {"name": "ADM - Conversation rollup v2", "scheduled_time": "100"},
            {"name": "ADM - Service backends", "scheduled_time": "300"},
        ]
        code, output = self.invoke("ADM - Conversation rollup v2")
        self.assertEqual((code, output["status"]), (0, "noop"))
        self.assertEqual(FakeRecovery.ran, ["ADM - Service backends"])
        self.assertEqual(FakeRecovery.queries, [entry.DETECTOR_QUERY])

    def test_only_v2_gaps_are_a_noop_without_running(self):
        FakeRecovery.rows = [{"name": name, "scheduled_time": "1"} for name in V2_ROWS]
        code, output = self.invoke("ADM - Application catalog v2")
        self.assertEqual((code, output["status"]), (0, "noop"))
        self.assertEqual(FakeRecovery.ran, [])

    def test_v1_trigger_runs_directly(self):
        code, _ = self.invoke("ADM - Identity builder")
        self.assertEqual(code, 0)
        self.assertEqual(FakeRecovery.ran, ["ADM - Identity builder"])
        self.assertEqual(FakeRecovery.queries, [])


class RecoveryConfSpecTest(unittest.TestCase):
    def test_spec_documents_exactly_the_shipped_and_read_keys(self):
        import configparser
        import re

        from adm_recovery_lib.core import Settings

        shipped = configparser.RawConfigParser()
        shipped.read(BIN.parent / "default/adm_recovery.conf")
        spec = (BIN.parent / "README/adm_recovery.conf.spec").read_text()
        self.assertIn("\n[recovery]\n", spec)
        documented = set(re.findall(r"^([a-z_]+) = ", spec, re.M))
        read = set(vars(Settings())) | {"management_uri", "ca_file"}
        self.assertEqual(documented, set(shipped["recovery"]))
        self.assertEqual(documented, read)


if __name__ == "__main__":
    unittest.main()
