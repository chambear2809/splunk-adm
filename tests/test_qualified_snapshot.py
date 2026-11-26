import os
import sys
import unittest

sys.path.insert(
    0, os.path.join(os.path.dirname(__file__), "..", "splunk_app", "splunk_adm", "bin")
)
from adm_baselines_lib.qualified_snapshot import (  # noqa: E402
    QualifiedSnapshotProvider,
    SnapshotUnavailable,
)


class Broker:
    def __init__(self, records):
        self.records = records

    def lookup(self, principal, selection, window):
        return [record["reference"] for record in self.records]

    def read(self, reference):
        for record in self.records:
            if record["reference"] == reference:
                return record
        return None

    def authorize(self, principal, reference, provenance):
        return True


class QualifiedSnapshotTests(unittest.TestCase):
    def test_rejects_unqualified_source(self):
        provider = QualifiedSnapshotProvider(Broker([]))
        with self.assertRaises(SnapshotUnavailable):
            provider.lookup(
                "alice",
                {
                    "service": "payments",
                    "environment": "prod",
                    "cluster": "a",
                    "namespace": "shop",
                },
                {"start": 1, "end": 2},
            )

    def test_accepts_adm_qualified_source_only(self):
        capture = {
            "source": "adm:qualified",
            "complete": True,
            "findings": [{"id": "edge-1", "kind": "new_dependency"}],
        }
        provider = QualifiedSnapshotProvider(
            Broker(
                [
                    {
                        "reference": "ref-1",
                        "capture": capture,
                        "provenance": {"source": "adm:qualified"},
                    }
                ]
            )
        )
        rows = provider.lookup(
            "alice",
            {
                "service": "payments",
                "environment": "prod",
                "cluster": "a",
                "namespace": "shop",
            },
            {"start": 1, "end": 2},
        )
        self.assertEqual(rows[0]["source"], "adm:qualified")


if __name__ == "__main__":
    unittest.main()
