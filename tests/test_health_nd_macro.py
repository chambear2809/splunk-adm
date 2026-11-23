"""Static contract checks for the Nexus Dashboard health receipt probe."""

from __future__ import annotations

import re
import unittest

from test_path_trace_macros import definition, stanzas


class NexusDashboardHealthMacroTest(unittest.TestCase):
    def setUp(self) -> None:
        self.body = definition(stanzas()["adm_health_source_nd"])

    def test_counts_flows_and_endpoints_separately(self) -> None:
        self.assertIn(
            'count(eval(sourcetype=="cisco:dc:nd:flows")) AS flow_records', self.body
        )
        self.assertIn(
            'count(eval(sourcetype=="cisco:dc:nd:endpoints")) AS endpoint_records',
            self.body,
        )

    def test_warns_when_endpoints_arrive_without_flows(self) -> None:
        self.assertRegex(
            self.body,
            r"warning=if\(endpoint_records>0 AND flow_records==0, \"[^\"]+\", null\(\)\)",
        )

    def test_status_contract_is_unchanged(self) -> None:
        self.assertIn('status=if(records>0,"ok","no_visible_records")', self.body)
        fields = re.search(r"\| fields (.+)$", self.body.strip()).group(1).split()
        for name in (
            "kind",
            "name",
            "records",
            "status",
            "warning",
            "flow_records",
            "endpoint_records",
            "contract_version",
        ):
            self.assertIn(name, fields)


if __name__ == "__main__":
    unittest.main()
