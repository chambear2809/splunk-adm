"""Focused replay-safety checks for the summary-row deduplication macro.

The unit-shaped cases use in-memory rows; the end-to-end cases load real
NetFlow fixtures and invoke the shipped rollup definition without changing
the running app configuration.
"""

from __future__ import annotations

import json
import os
import sys
import time
import unittest
from configparser import RawConfigParser
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
MACROS = ROOT / "splunk_app" / "splunk_adm" / "default" / "macros.conf"


@unittest.skipUnless(
    os.environ.get("ADM_LAB") == "1", "set ADM_LAB=1 with the lab running"
)
class RecoveryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, str(HERE))
        import lab

        cls.lab = lab

    @staticmethod
    def macro_definition(name: str) -> str:
        parser = RawConfigParser()
        parser.read_string(MACROS.read_text(encoding="utf-8").replace("\\\n", " "))
        return parser[name]["definition"]

    @classmethod
    def rollup_search(cls, token: str) -> str:
        flow = cls.macro_definition("adm_flows_netflow").replace(
            "`adm_index_netflow`", f"index=adm_alt_nf recovery_token={token}"
        )
        _, tail = cls.macro_definition("adm_flow_enrich").split("eval adm_kind=", 1)
        all_flows = (
            f"multisearch [search {flow}] [search {flow} | where false()] "
            f"| eval adm_kind={tail}"
        )
        return "| " + cls.macro_definition("adm_conversation_rollup").replace(
            "`adm_flows`", all_flows
        )

    @classmethod
    def dispatch_search(cls, search: str, start: int, end: int) -> list[dict]:
        data = {
            "search": search,
            "exec_mode": "normal",
            "earliest_time": "0",
            "latest_time": "now",
            "index_earliest": str(start),
            "index_latest": str(end),
        }
        with cls.lab._mgmt(
            "POST", "/servicesNS/admin/splunk_adm/search/v2/jobs?output_mode=json", data
        ) as response:
            sid = json.loads(response.read())["sid"]
        cls.lab._wait_job(sid)
        return cls.lab._results(sid)

    @classmethod
    def load_netflow(cls, token: str, duplicate_first: bool = False) -> int:
        source = ROOT / "fixtures" / "raw" / "stream_netflow.ndjson"
        events = []
        lines = source.read_text(encoding="utf-8").splitlines()[:3]
        if duplicate_first:
            lines = [lines[0], lines[0], lines[1]]
        for line in lines:
            envelope = json.loads(line)
            envelope["index"] = "adm_alt_nf"
            envelope["event"]["recovery_token"] = token
            events.append(json.dumps(envelope, separators=(",", ":")).encode())
        cls.lab._hec_post(b"\n".join(events), "?index=adm_alt_nf")
        return len(events)

    @classmethod
    def collect_rows(
        cls, token: str, start: int, end: int, partial: bool
    ) -> list[dict]:
        suffix = " | head 1" if partial else ""
        search = (
            cls.rollup_search(token)
            + suffix
            + f' | eval recovery_token="{token}" | collect index=adm source="adm:recovery:{token}"'
        )
        return cls.dispatch_search(search, start, end)

    @classmethod
    def reduce(cls, rows: list[dict]) -> dict:
        """Apply the production summary dedup macro and sum rollup metrics."""
        data = json.dumps(json.dumps(rows, separators=(",", ":")))
        result = cls.lab.search(
            f"| makeresults format=json data={data} "
            "| `adm_summary_dedup` "
            "| stats count AS rows sum(bytes_c2s) AS bytes sum(records) AS records "
            "sum(acl_permits) AS permits"
        )
        return result[0]

    @staticmethod
    def row(rollup_id: str | None, *, bytes_c2s=10, records=1, permits=0, **extra):
        row = {
            "bytes_c2s": bytes_c2s,
            "records": records,
            "acl_permits": permits,
        }
        if rollup_id is not None:
            row["rollup_id"] = rollup_id
        row.update(extra)
        return row

    def wait_for_token(self, token: str, expected: int = 3) -> None:
        deadline = time.time() + 120
        while time.time() < deadline:
            rows = self.lab.search(
                f'index=adm_alt_nf recovery_token="{token}" | stats count AS n',
                "0",
                "now",
            )
            if rows and int(rows[0]["n"]) == expected:
                return
            time.sleep(2)
        self.fail("recovery events were not indexed")

    def baseline(self, token):
        start = int(time.time()) - 5
        self.load_netflow(token)
        self.wait_for_token(token)
        end = int(time.time()) + 1
        time.sleep(2)
        rows = self.dispatch_search(self.rollup_search(token), start, end)
        self.assertEqual(sum(int(r["records"]) for r in rows), 3, rows)
        self.assertGreater(len(rows), 1, rows)
        for row in rows:
            self.assertRegex(row.get("rollup_id", ""), r"^[0-9a-f]{64}$")
            self.assertEqual(row.get("replay_protected"), "1", row)
        return start, end, rows

    def assert_totals(self, token, baseline):
        got = self.summary(token)
        self.assertEqual(int(got["records"]), 3, got)
        self.assertEqual(
            float(got["bytes"]),
            sum(float(r.get("bytes_c2s", 0)) for r in baseline),
            got,
        )
        self.assertEqual(got["replay_protected"], "1", got)

    def test_actual_rollup_exact_slice_replay_is_idempotent(self):
        token = f"recovery_{int(time.time() * 1000000)}"
        start, end, baseline = self.baseline(token)
        self.collect_rows(token, start, end, partial=False)
        self.wait_for_summary(token, len(baseline))
        self.assert_totals(token, baseline)
        self.collect_rows(token, start, end, partial=False)
        self.wait_for_summary(token, 2 * len(baseline))
        self.assert_totals(token, baseline)

    def test_actual_partial_collect_then_retry_deduplicates_shared_rows(self):
        token = f"recovery_{int(time.time() * 1000000)}"
        start, end, baseline = self.baseline(token)
        self.collect_rows(token, start, end, partial=True)
        self.wait_for_summary(token, 1)
        self.collect_rows(token, start, end, partial=False)
        self.wait_for_summary(token, 1 + len(baseline))
        self.assert_totals(token, baseline)

    def test_actual_identical_payloads_remain_distinct_observations(self):
        token = f"recovery_{int(time.time() * 1000000)}"
        start = int(time.time()) - 5
        self.load_netflow(token, duplicate_first=True)
        self.wait_for_token(token)
        identities = self.lab.search(
            f'index=adm_alt_nf recovery_token="{token}" '
            '| eval event_id=_bkt."|"._cd | stats dc(event_id) AS identities',
            "0",
            "now",
        )
        self.assertEqual(identities[0]["identities"], "3", identities)
        end = int(time.time()) + 1
        time.sleep(2)
        self.collect_rows(token, start, end, partial=False)
        self.wait_for_summary(token, 1)
        summary = self.summary(token)
        self.assertEqual(summary["records"], "3")
        self.assertEqual(summary["replay_protected"], "1")

    def wait_for_summary(self, token: str, expected: int) -> int:
        deadline = time.time() + 120
        while time.time() < deadline:
            rows = self.lab.search(
                f'index=adm source="adm:recovery:{token}" | stats count AS n',
                "0",
                "now",
            )
            if rows and int(rows[0]["n"]) == expected:
                return int(rows[0]["n"])
            time.sleep(2)
        self.fail("rollup summary rows were not collected")

    def summary(self, token: str) -> dict:
        rows = self.lab.search(
            f'index=adm source="adm:recovery:{token}" | `adm_summary_dedup` '
            "| stats sum(records) AS records sum(bytes_c2s) AS bytes "
            "min(replay_protected) AS replay_protected",
            "0",
            "now",
        )
        self.assertEqual(len(rows), 1, rows)
        return rows[0]

    def test_exact_slice_replay_is_idempotent(self):
        row = self.row("slice-a-event-1", bytes_c2s=17)
        got = self.reduce([row, dict(row)])
        self.assertEqual(got["rows"], "1")
        self.assertEqual(got["bytes"], "17")
        self.assertEqual(got["records"], "1")

    def test_partial_collect_then_exact_retry_deduplicates_shared_events(self):
        first = self.row("slice-a-event-1", bytes_c2s=10)
        second = self.row("slice-a-event-2", bytes_c2s=20)
        got = self.reduce([first, second, dict(first), dict(second)])
        self.assertEqual(got["rows"], "2")
        self.assertEqual(got["bytes"], "30")
        self.assertEqual(got["records"], "2")

    def test_adjacent_late_input_remains_additive(self):
        got = self.reduce(
            [
                self.row("slice-a-event-1", bytes_c2s=10),
                self.row("slice-b-event-1", bytes_c2s=20),
            ]
        )
        self.assertEqual(got["rows"], "2")
        self.assertEqual(got["bytes"], "30")
        self.assertEqual(got["records"], "2")

    def test_independently_indexed_byte_identical_events_stay_distinct(self):
        # Distinct physical IDs are intentional: SPL cannot infer upstream
        # identity from identical normalized fields alone.
        a = self.row("physical-a", bytes_c2s=11)
        b = self.row("physical-b", bytes_c2s=11)
        got = self.reduce([a, b])
        self.assertEqual(got["rows"], "2")
        self.assertEqual(got["bytes"], "22")
        self.assertEqual(got["records"], "2")

    def test_distinct_observers_are_not_collapsed(self):
        got = self.reduce(
            [
                self.row("observer-a-event-1", bytes_c2s=7, observer="netflow:leaf-a"),
                self.row("observer-b-event-1", bytes_c2s=9, observer="netflow:leaf-b"),
            ]
        )
        self.assertEqual(got["rows"], "2")
        self.assertEqual(got["bytes"], "16")

    def test_legacy_rows_without_rollup_id_are_retained(self):
        got = self.reduce(
            [
                self.row(None, bytes_c2s=3),
                self.row(None, bytes_c2s=5),
            ]
        )
        self.assertEqual(got["rows"], "2")
        self.assertEqual(got["bytes"], "8")
        self.assertEqual(got["records"], "2")


if __name__ == "__main__":
    unittest.main()
