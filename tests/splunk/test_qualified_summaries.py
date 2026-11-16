"""Qualified graph summaries in Splunk: collect round trip, stats read, exact totals.

Ingests one ten-minute qualified scenario (ownership intervals, spans, Hubble
and NetFlow) through HEC, writes summaries with the shipped rollup command and
``collect``, then checks that

* the summary-backed ``admqualified mode=graph`` equals the library's per-slice
  qualified graph over the same raw evidence and horizon,
* summary manifests account for every raw native event (``stats count``),
* a replay is skipped, duplicate collected documents are not double counted,
* a late event is included only by a run with a larger horizon, which supersedes.
"""

import json
import math
import os
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(ROOT))

PROFILE = {
    "enabled": "true",
    "cluster": "cluster-a",
    "environment": "prod",
    "scope": "scope-a",
    "producer_id": "producer-a",
    "interval_source": "atlas:identity:lab",
    "span_source": "http:atlas-lab",
    "interval_index": "k8s",
    "span_index": "otel_traces",
    "interval_sourcetype": "adm:pod_ip_interval:v2",
    "span_sourcetype": "otel:traces",
    "namespaces": "shop",
    "slice_workers": "2",
}
PROFILES = [
    {
        "id": "sensor-a",
        "kind": "hubble",
        "index": "cilium_hubble",
        "source": "/hubble/",
        "sourcetype": "cilium:hubble:flow",
        "scope": "scope-a",
        "owner_scope": "scope-a",
        "cluster": "cluster-a",
        "observers": ["node-a", "node-b"],
    },
    {
        "id": "vds",
        "kind": "netflow",
        "index": "netflow",
        "source": "stream:netflow",
        "sourcetype": "stream:netflow",
        "scope": "fabric",
        "cluster": "cluster-a",
        "exporter_ip": "192.0.2.13",
        "netflow_version": 10,
        "observation_domain_present": True,
        "observation_domain_id": 0,
    },
]
SELECTION = 'service="checkout" environment="prod" cluster="cluster-a" namespace="shop"'


def envelope(row):
    """HEC envelope for one unit-test fixture row (already rebased)."""
    index = {"identity": "k8s", "traces": "otel_traces", "hubble": "cilium_hubble"}
    body = {
        "time": float(row["event_time"]),
        "index": index.get(row["index"], row["index"]),
        "source": {"producer-a": "atlas:identity:lab", "otel-a": "http:atlas-lab"}.get(
            row["source"], row["source"]
        ),
        "sourcetype": row["sourcetype"],
        "event": json.loads(row["_raw"]),
    }
    if row.get("host"):
        body["host"] = row["host"]
        body["fields"] = {"k8s.cluster.name": "cluster-a"}
    return body


@unittest.skipUnless(os.environ.get("ADM_LAB") == "1", "set ADM_LAB=1")
class QualifiedSummaryLabTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import lab

        from tests import test_qualified_rollup as fixture

        cls.lab = lab
        cls.fixture = fixture
        # Rebase the scenario 40 minutes into the past on a slice boundary.
        now = time.time()
        cls.base = int(now - now % 300) - 2400
        cls.start, cls.end = cls.base, cls.base + 600
        identity, native = fixture.scenario(cls.base)
        # The late event is ingested later, after the first rollup.
        first = native[cls.base]
        cls.late = [r for r in first if r["_cd"] == "0:late"]
        native[cls.base] = [r for r in first if r["_cd"] != "0:late"]
        rows = [r for part in (identity, native) for v in part.values() for r in v]
        for name, stanza in (
            ("profile", PROFILE),
            (
                "network",
                {
                    "enabled": "true",
                    "profiles_json": json.dumps(PROFILES),
                    "frontends_json": json.dumps(fixture.frontends(cls.base)),
                },
            ),
            (
                "summary",
                {"enabled": "true", "index": "adm_summary_v2", "lateness": "90"},
            ),
        ):
            path = "/servicesNS/nobody/splunk_adm/configs/conf-adm_identity"
            try:
                lab._json("POST", path, {"name": name, **stanza})
            except lab.LabError:
                lab._json("POST", f"{path}/{name}", stanza)
        body = "\n".join(json.dumps(envelope(r)) for r in rows).encode()
        lab._hec_post(body)
        cls.ingested = time.time()
        cls.hubble_count = sum(1 for r in rows if r["index"] == "hubble")
        cls.wait_for_count(
            len(rows),
            "(index=k8s OR index=otel_traces OR index=cilium_hubble OR index=netflow)",
        )

    @classmethod
    def tearDownClass(cls):
        # Leave the shared lab with the shipped inert identity defaults.
        path = "/servicesNS/nobody/splunk_adm/configs/conf-adm_identity"
        for name in ("profile", "network", "summary"):
            try:
                cls.lab._json("POST", f"{path}/{name}", {"enabled": "false"})
            except cls.lab.LabError:
                pass

    @classmethod
    def wait_for_count(cls, expected, terms):
        deadline = time.time() + 120
        while time.time() < deadline:
            got = cls.lab.search(
                f"search {terms} earliest={cls.start} latest={cls.end} | stats count",
                cls.start,
                cls.end,
            )
            if int(got[0]["count"]) >= expected:
                return
            time.sleep(3)
        raise AssertionError("events were not searchable in time")

    def horizon(self, ingested):
        """One knowledge horizon after ingestion, closed for the rollup."""
        value = math.ceil(ingested) + 5
        wait = value + 31 - time.time()
        if wait > 0:
            time.sleep(wait)
        return value

    def rollup(self, horizon):
        for a in range(self.start, self.end, 300):
            # The documented re-run form: an explicit lateness through
            # adm_qualified_rollup(1), bounds from the search time range.
            self.lab.search(
                f"| `adm_qualified_rollup({horizon - a - 300})` "
                '| collect index=adm_summary_v2 source="adm:qualified"',
                a,
                a + 300,
            )

    def graph(self):
        rows = self.lab.search(
            f"| admqualified mode=graph {SELECTION} start={self.start} as_of={self.end}",
            self.start,
            self.end,
        )
        return rows

    def reference(self, horizon):
        """Library per-slice qualified graph over the indexed raw evidence."""
        from splunk_app.splunk_adm.bin.adm_identity_lib.native_network import (
            normalize_records,
        )
        from splunk_app.splunk_adm.bin.adm_identity_lib.network_graph import (
            assemble,
            configuration,
        )
        from splunk_app.splunk_adm.bin.adm_identity_lib.qualified import qualify
        from splunk_app.splunk_adm.bin.adm_identity_lib.slices import merge

        profile = dict(PROFILE, enabled=True, namespaces=["shop"])
        network = configuration(
            {
                "enabled": True,
                "profiles": PROFILES,
                "frontends": self.fixture.frontends(self.base),
            },
            profile,
        )
        selection = dict(self.fixture.CHECKOUT)
        outputs, windows = [], []
        for a in range(self.start, self.end, 300):
            b = a + 300
            fields = "_raw index source sourcetype event_time receipt_time host k8s.cluster.name _bkt _cd"
            identity = self.lab.search(
                f'search (index=k8s source="atlas:identity:lab") OR (index=otel_traces source="http:atlas-lab") '
                f"earliest={a} latest={b} _index_latest={horizon} "
                f"| eval event_time=_time, receipt_time=_indextime | fields {fields}",
                a,
                b,
            )
            native = self.lab.search(
                f"search (index=cilium_hubble) OR (index=netflow) earliest={a} latest={b} "
                f"_index_latest={horizon} | eval event_time=_time, receipt_time=_indextime "
                f"| fields {fields}",
                a,
                b,
            )
            for row in identity + native:
                for key in list(row):
                    if isinstance(row[key], list) and key != "_raw":
                        row[key] = row[key][0]
            result = qualify(identity, profile, a, b, horizon)
            self.assertTrue(result["complete"], result.get("warnings"))
            decoded = normalize_records(native, PROFILES, a, b, horizon=horizon)
            outputs.append(assemble(result, native, network, selection, decoded))
            windows.append((a, b))
        return merge(outputs, self.start, self.end, len(windows), windows)

    @staticmethod
    def totals(rows):
        edges = {}
        for r in rows:
            if r.get("row_type") == "edge":
                edges[r["id"]] = (
                    r["relationship"],
                    int(float(r.get("records") or r.get("count") or 0)),
                    r.get("raw_bytes") and int(float(r["raw_bytes"])),
                )
        nodes = {r["id"] for r in rows if r.get("row_type") == "node"}
        meta = next(r for r in rows if r.get("row_type") == "meta")
        return nodes, edges, int(float(meta.get("network_records") or 0)), meta

    def test_summary_read_equals_raw_qualification_and_supersedes_late(self):
        horizon = self.horizon(self.ingested)
        self.rollup(horizon)
        manifests = self.manifests(2)
        nodes, edges, records, meta = self.totals(self.graph())
        ref_nodes, ref_edges, ref_records, _ = self.totals(self.reference(horizon))
        self.assertEqual(nodes, ref_nodes)
        self.assertEqual(edges, ref_edges)
        self.assertEqual(records, ref_records)
        self.assertEqual(records, 21)
        self.assertEqual(meta.get("read_coverage"), "100")
        self.assertEqual(meta.get("summary_slices"), "2")

        # Progressive read: one more (unsummarized, empty) slice is deferred,
        # then read raw; summaries alone already carry the exact totals.
        rows = self.lab.search(
            f"| admqualified mode=graph {SELECTION} start={self.start} "
            f"as_of={self.end + 300} tail=deferred",
            self.start,
            self.end + 300,
        )
        deferred = self.totals(rows)
        self.assertEqual(deferred[3].get("raw_pending_seconds"), "300")
        self.assertEqual(deferred[2], 21)
        rows = self.lab.search(
            f"| admqualified mode=graph {SELECTION} start={self.start} as_of={self.end + 300}",
            self.start,
            self.end + 300,
        )
        self.assertEqual(self.totals(rows)[3].get("read_coverage"), "100")

        # Exactness: manifests account for every raw native event.
        from splunk_app.splunk_adm.bin.adm_identity_lib.rollup import unpack

        summarized = sum(
            int(unpack(m["q_meta"])["native_rows"]["native"]) for m in manifests
        )
        raw = self.lab.search(
            f"| tstats count where (index=cilium_hubble OR index=netflow) earliest={self.start} latest={self.end}",
            self.start,
            self.end,
        )
        self.assertEqual(summarized, int(raw[0]["count"]))

        # A replay with the same horizon is skipped (no new documents).
        before = self.count_docs()
        self.rollup(horizon)
        time.sleep(5)
        self.assertEqual(self.count_docs(), before)

        # Re-collected (duplicated) documents do not change totals.
        self.lab.search(
            f'search index=adm_summary_v2 source="adm:qualified" earliest={self.start} latest={self.start + 300} '
            '| collect index=adm_summary_v2 source="adm:qualified"',
            self.start,
            self.end,
        )
        deadline = time.time() + 60
        while self.count_docs() == before and time.time() < deadline:
            time.sleep(2)
        self.assertEqual(self.totals(self.graph())[1], edges)

        # A late event is summarized only by a run with a larger horizon.
        self.lab._hec_post(
            "\n".join(json.dumps(envelope(r)) for r in self.late).encode()
        )
        late_ingested = time.time()
        self.wait_for_count(self.hubble_count + 1, "index=cilium_hubble")
        self.assertEqual(self.totals(self.graph())[2], 21)
        later = self.horizon(late_ingested)
        self.rollup(later)
        self.manifests(4)
        _, late_edges, late_records, _ = self.totals(self.graph())
        self.assertEqual(late_records, 22)
        self.assertEqual(late_edges, self.totals(self.reference(later))[1])

    def test_rollup_lateness_argument_is_validated(self):
        for value in ("abc", "86401", "-5", "1 OR 1"):
            with self.assertRaises(Exception, msg=value):
                self.lab.search(
                    f"| `adm_qualified_rollup({value})`", self.start, self.start + 300
                )

    def manifests(self, expected):
        """Wait until collected summaries are searchable (collect is async)."""
        deadline = time.time() + 120
        while True:
            rows = self.lab.search(
                'search index=adm_summary_v2 source="adm:qualified" '
                f"earliest={self.start} latest={self.end} "
                "| eventstats count AS rows by q_run "
                '| where q_kind="m" AND rows=q_expected '
                "| table q_slice q_run q_expected q_meta q_horizon",
                self.start,
                self.end,
            )
            if len(rows) >= expected or time.time() > deadline:
                return rows
            time.sleep(3)

    def count_docs(self):
        got = self.lab.search(
            f'search index=adm_summary_v2 source="adm:qualified" earliest={self.start} latest={self.end} | stats count',
            self.start,
            self.end,
        )
        return int(got[0]["count"])


if __name__ == "__main__":
    unittest.main()
