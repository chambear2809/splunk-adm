from __future__ import annotations
import hashlib
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[1]
MACROS = ROOT / "splunk_app/splunk_adm/default/macros.conf"
CATALOG_FIELDS = [
    "_key",
    "service",
    "environment",
    "cluster",
    "namespace",
    "pods",
    "first_seen",
    "last_seen",
    "peers",
    "conversations_1h",
    "blocked_1h",
    "unknown_peers_1h",
    "updated",
    "window_start",
    "window_end",
]

FIND_FIELDS = [
    "_key",
    "service",
    "environment",
    "cluster",
    "namespace",
    "pods",
    "last_seen",
]


def macro_hashes() -> dict[str, str]:
    text = MACROS.read_text()
    bodies: dict[str, str] = {}
    pending = ["adm_catalog_build", "adm_find"]
    while pending:
        name = pending.pop()
        if name in bodies:
            continue
        match = re.search(
            rf"\[{re.escape(name)}(?:\([^]]+\))?\]\n(?P<body>.*?)(?=\n\[|\Z)",
            text,
            re.S,
        )
        if match is None:
            raise AssertionError(f"missing macro {name}")
        bodies[name] = match.group("body").strip()
        pending.extend(re.findall(r"`(adm_[a-z_]+)(?:\(|`)", bodies[name]))
    return {
        name: hashlib.sha256(body.encode()).hexdigest() for name, body in bodies.items()
    }


class DemoCatalogGroundingTest(unittest.TestCase):
    def payload(self, name):
        path = ROOT / "fixtures" / name
        self.assertTrue(path.exists(), f"missing real capture: {path}")
        return json.loads(path.read_text())

    def test_catalog_capture_schema_and_provenance(self):
        p = self.payload("demo-catalog.json")
        self.assertEqual(p["search"], "| `adm_catalog_build`")
        self.assertTrue(p["rows"])
        self.assertEqual(list(p["rows"][0]), CATALOG_FIELDS)
        self.assertEqual(p["provenance"]["schema"], CATALOG_FIELDS)
        self.assertEqual(p["provenance"]["macro_definitions"], macro_hashes())
        self.assertTrue(p["provenance"].get("macro_sha256"))
        self.assertTrue(p["provenance"].get("input_fields"))
        for row in p["rows"]:
            self.assertEqual(
                row["_key"],
                hashlib.sha256(
                    json.dumps(
                        [
                            row["service"],
                            row["environment"],
                            row["cluster"],
                            row["namespace"],
                        ],
                        separators=(",", ":"),
                    ).encode()
                ).hexdigest(),
            )
            self.assertLessEqual(int(p["earliest"]), int(row["window_start"]))
            self.assertLessEqual(int(row["window_start"]), int(row["window_end"]))
            self.assertLessEqual(int(row["window_end"]), int(p["latest"]))
        self.assertEqual(p["earliest"], p["provenance"]["earliest"])

    def test_find_capture_has_positive_grounded_queries(self):
        p = self.payload("demo-find.json")
        self.assertTrue(p["queries"])
        self.assertEqual(p["provenance"]["macro_definitions"], macro_hashes())
        for query in p["queries"]:
            self.assertTrue(query["query"])
            self.assertTrue(query["search"].startswith('| `adm_find("'))
            self.assertTrue(query["rows"])
            self.assertEqual(list(query["rows"][0]), FIND_FIELDS)

    def test_macro_sections_exist(self):
        text = MACROS.read_text()
        for name in ("adm_catalog_build", "adm_find"):
            self.assertRegex(text, rf"\[{name}(?:\([^]]+\))?\]")


if __name__ == "__main__":
    unittest.main()
