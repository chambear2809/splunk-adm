"""admqualified summary reader: run reconciliation, gap sampling, coverage.

The reader dispatches the summary aggregate beside the manifest read. These
tests simulate summaries being collected between those two reads and check
that no slice is counted twice (from summaries and from its raw read) or
claimed as summarized without contributing.
"""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parents[1] / "splunk_app/splunk_adm/bin"
sys.path.insert(0, str(ROOT))
import admqualified  # noqa: E402
from adm_identity_lib.search import SearchError  # noqa: E402

from splunk_app.splunk_adm.bin.adm_identity_lib.network_graph import (  # noqa: E402
    assemble,
)
from splunk_app.splunk_adm.bin.adm_identity_lib.qualified import (  # noqa: E402
    qualify,
    service_id,
)
from tests.test_qualified_identity import PROFILE  # noqa: E402
from tests.test_qualified_rollup import (  # noqa: E402
    CHECKOUT,
    WINDOWS,
    config,
    edges_by,
    manifests,
    raw_graph,
    scenario,
    summary_docs,
)

ROOT_TOKEN = admqualified.rollup.root_token(service_id(CHECKOUT))


class FakeSearch:
    """Answers manifest and aggregate queries from in-memory summary documents.

    ``manifest_docs`` is what the manifest read sees; ``aggregate_docs(n)``
    what the n-th aggregate read sees (reads race with collection).
    """

    def __init__(self, manifest_docs, aggregate_docs, honor_exclusions=True):
        self.manifest_docs = manifest_docs
        self.aggregate_docs = aggregate_docs
        self.honor_exclusions = honor_exclusions
        self.aggregates = []

    def run(self, query, **_):
        if "AS root" in query:
            return manifests(self.manifest_docs, ROOT_TOKEN)
        assert "q_grp" in query, query
        excluded = set()
        match = re.search(r"NOT q_run IN \(([^)]*)\)", query)
        if match and self.honor_exclusions:
            excluded = set(match.group(1).split(","))
        self.aggregates.append(excluded)
        docs = self.aggregate_docs(len(self.aggregates))
        runs = {d["q_run"] for d in docs} - excluded
        return admqualified.rollup.aggregate(docs, ROOT_TOKEN, runs)


def raw_slice(identity, native):
    def window(profile, config_, selection, start, end):
        result = qualify(identity[start], PROFILE, start, end)
        return assemble(result, native[start], config(), selection)

    return window


def command(fake, identity, native):
    cmd = admqualified.AdmQualified()
    cmd.mode = "graph"
    cmd.tail = None
    cmd._metadata = SimpleNamespace(searchinfo=SimpleNamespace(session_key="k"))
    cmd._settings = lambda _config: {
        "enabled": True,
        "index": "adm_summary_v2",
        "lateness": 0,
    }
    cmd._network_config = lambda _config, _profile: config()
    cmd._native = lambda: fake
    cmd._window = raw_slice(identity, native)
    return cmd


class SummaryReaderRaceTests(unittest.TestCase):
    def setUp(self):
        self.identity, self.native = scenario()
        self.docs = summary_docs(self.identity, self.native, WINDOWS)
        self.first = [d for d in self.docs if d["q_slice"] == 0]
        self.reference = raw_graph(
            self.identity, self.native, CHECKOUT, WINDOWS, 0, 600
        )

    def read(self, fake):
        return command(fake, self.identity, self.native)._summarized(
            PROFILE, None, CHECKOUT, 0, 600
        )

    def assert_reference_totals(self, graph):
        self.assertEqual(graph[-1]["network_records"], 21)
        self.assertEqual(
            graph[-1]["network_records"], self.reference[-1]["network_records"]
        )
        for relationship in ("calls", "traffic_observation"):
            got = edges_by(graph, relationship)
            want = edges_by(self.reference, relationship)
            self.assertEqual(set(got), set(want), relationship)
            for ident, edge in want.items():
                self.assertEqual(
                    got[ident].get("records") or got[ident].get("count"),
                    edge.get("records") or edge.get("count"),
                    ident,
                )

    def test_slice_collected_between_aggregate_and_manifest_is_not_double_counted(
        self,
    ):
        # The aggregate already sees slice 300; the manifest does not, so 300
        # is read raw as the tail and must be excluded from the aggregate.
        fake = FakeSearch(self.first, lambda n: self.docs)
        graph = self.read(fake)
        self.assert_reference_totals(graph)
        self.assertEqual(len(fake.aggregates), 2)
        late_run = {d["q_run"] for d in self.docs if d["q_slice"] == 300}
        self.assertEqual(fake.aggregates[1], late_run)
        self.assertEqual(graph[-1]["summary_slices"], 1)

    def test_concurrent_run_with_another_horizon_is_excluded(self):
        later = summary_docs(self.identity, self.native, WINDOWS[1:], lateness=60)
        fake = FakeSearch(self.docs, lambda n: self.docs + later)
        graph = self.read(fake)
        self.assert_reference_totals(graph)
        self.assertEqual(fake.aggregates[1], {later[0]["q_run"]})

    def test_chosen_run_the_aggregate_missed_is_reread(self):
        fake = FakeSearch(self.docs, lambda n: self.first if n == 1 else self.docs)
        graph = self.read(fake)
        self.assert_reference_totals(graph)
        self.assertEqual(len(fake.aggregates), 2)
        self.assertEqual(graph[-1]["summary_slices"], 2)

    def test_consistent_reads_need_one_aggregate(self):
        fake = FakeSearch(self.docs, lambda n: self.docs)
        self.assert_reference_totals(self.read(fake))
        self.assertEqual(len(fake.aggregates), 1)

    def test_runs_that_keep_changing_fail_instead_of_miscounting(self):
        fake = FakeSearch(self.first, lambda n: self.docs, honor_exclusions=False)
        with self.assertRaisesRegex(SearchError, "changed while"):
            self.read(fake)
        self.assertEqual(len(fake.aggregates), 3)

    def test_unaligned_start_states_the_counted_start(self):
        fake = FakeSearch(self.docs, lambda n: self.docs)
        graph = command(fake, self.identity, self.native)._summarized(
            PROFILE, None, CHECKOUT, 120, 600
        )
        self.assertEqual(graph[-1]["window_start"], 0)
        self.assertIn("Counted from 0", graph[-1]["warnings"][0])
        aligned = command(fake, self.identity, self.native)._summarized(
            PROFILE, None, CHECKOUT, 0, 600
        )
        self.assertNotIn("Counted from", aligned[-1]["warnings"][0])

    def test_aggregate_query_emits_run_rows_and_split_separates_them(self):
        query = admqualified.rollup.aggregate_query(
            "adm_summary_v2", "a" * 24, 0, 600, ROOT_TOKEN
        )
        self.assertIn('"r:".q_run', query)
        self.assertIn("by q_grp", query)
        rows, seen = admqualified.rollup.split_runs(
            admqualified.rollup.aggregate(
                self.docs, ROOT_TOKEN, {d["q_run"] for d in self.docs}
            )
        )
        self.assertEqual(seen, {d["q_run"] for d in self.docs})
        self.assertFalse(any(r["q_kind"] == "r" for r in rows))
        with self.assertRaises(admqualified.rollup.SummaryError):
            admqualified.rollup.split_runs([{"q_kind": "r", "q_key": "x;"}])


class GapSamplingTests(unittest.TestCase):
    def test_gap_reads_never_exceed_the_bound(self):
        limit = admqualified.MAX_GAP_READS
        for count in range(0, 40):
            gaps = list(range(0, 300 * count, 300))
            with self.subTest(count=count):
                read = admqualified.sample_gaps(gaps)
                self.assertEqual(len(read), min(count, limit))
                self.assertTrue(set(read) <= set(gaps))
                if count:
                    self.assertEqual((read[0], read[-1]), (gaps[0], gaps[-1]))

    def test_five_gaps_are_sampled_not_all_read(self):
        gaps = [0, 300, 600, 900, 1200]
        self.assertEqual(len(admqualified.sample_gaps(gaps)), 4)


class SlicedCoverageTests(unittest.TestCase):
    def test_empty_slices_count_as_read(self):
        identity, native = scenario()
        cmd = command(None, identity, native)
        outputs = {0: raw_slice(identity, native)}

        def window(profile, config_, selection, start, end):
            if start == 600:
                raise SearchError("Selected service has no qualified observations.")
            return outputs[0](profile, config_, selection, start, end)

        cmd._window = window
        graph = cmd._sliced(PROFILE, None, CHECKOUT, 0, 900)
        meta = graph[-1]
        self.assertEqual(meta["window_slices_read"], 3)
        self.assertEqual(meta["read_coverage"], 100)
        self.assertFalse(any(w.startswith("Read ") for w in meta["warnings"]))


class SummaryLatenessTests(unittest.TestCase):
    def settings(self, lateness):
        import configparser

        conf = configparser.ConfigParser()
        conf["summary"] = {"enabled": "true", "lateness": str(lateness)}
        return admqualified.AdmQualified()._settings(conf)

    def test_scheduled_lateness_must_fit_the_rollup_offset(self):
        self.assertEqual(self.settings(90)["lateness"], 90)
        self.assertEqual(self.settings(0)["lateness"], 0)
        with self.assertRaisesRegex(SearchError, r"between 0 and 90 seconds"):
            self.settings(91)
        with self.assertRaisesRegex(SearchError, r"adm_qualified_rollup\("):
            self.settings(3600)

    def test_shipped_schedule_matches_the_bound(self):
        conf = (ROOT.parent / "default/savedsearches.conf").read_text()
        stanza = conf.split("[ADM - Qualified graph rollup]", 1)[1].split("\n[", 1)[0]
        latest = re.search(r"dispatch.latest_time = -(\d+)m@m", stanza)
        self.assertIsNotNone(latest)
        self.assertEqual(
            int(latest.group(1)) * 60 - admqualified.VISIBILITY_MARGIN,
            admqualified.MAX_SCHEDULED_LATENESS,
        )
        macros = (ROOT.parent / "default/macros.conf").read_text()
        self.assertIn("[adm_qualified_rollup(1)]", macros)
        self.assertIn("admqualified mode=rollup lateness=$lateness$", macros)


if __name__ == "__main__":
    unittest.main()
