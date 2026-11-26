"""Static contract for the ITSI export and CMDB reconciliation macros
(docs/operators/itsi-cmdb.md): inert, unqualified and read-only by default."""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MACROS = ROOT / "splunk_app/splunk_adm/default/macros.conf"
WRITE_COMMANDS = re.compile(
    r"\|\s*(outputlookup|outputcsv|collect|mcollect|sendemail|sendalert|"
    r"itsiimportobjects|delete|tscollect|script|run|rest)\b",
    re.I,
)


def stanzas() -> dict[str, str]:
    text = MACROS.read_text()
    return {
        m.group("name"): m.group("body")
        for m in re.finditer(
            r"^\[(?P<name>[^\]]+)\]\n(?P<body>.*?)(?=^\[|\Z)", text, re.M | re.S
        )
    }


def field(body: str, name: str) -> str:
    m = re.search(rf"^{name} = (.*?)(?=^\w+ = |^#|\Z)", body, re.M | re.S)
    assert m, f"missing {name}"
    return m.group(1).replace("\\\n", "\n").strip()


class ItsiCmdbMacros(unittest.TestCase):
    def setUp(self) -> None:
        self.macros = stanzas()

    def test_external_sources_ship_inert_and_unqualified(self) -> None:
        self.assertEqual(
            field(self.macros["adm_itsi_import_objects"], "definition"),
            "| makeresults | where 1=0",
        )
        self.assertEqual(
            field(self.macros["adm_cmdb_relationship_rows"], "definition"),
            "makeresults | where 1=0",
        )
        qualified = self.macros["adm_cmdb_relationships_schema_qualified"]
        self.assertEqual(field(qualified, "definition"), "0")
        self.assertEqual(field(qualified, "iseval"), "0")
        snow = field(self.macros["adm_index_snow"], "description")
        self.assertIn("snow:incident", snow)
        self.assertNotIn("cmdb", snow.lower())

    def test_observed_relationships_are_read_only_and_scope_validated(self) -> None:
        body = self.macros["adm_cmdb_observed_relationships(1)"]
        self.assertEqual(field(body, "args"), "scope")
        self.assertIn(r'"^[A-Za-z0-9][A-Za-z0-9._:/@-]{0,252}\z"', body)
        definition = field(body, "definition")
        self.assertTrue(definition.startswith("search `adm_index_summary`"))
        self.assertIn('scope="$scope$"', definition)
        self.assertIn("by scope client_ip server_ip server_port transport", definition)
        for name in self.macros:
            if name.startswith("adm_cmdb_") or name == "adm_itsi_import_objects":
                self.assertIsNone(
                    WRITE_COMMANDS.search(field(self.macros[name], "definition")),
                    name,
                )

    def test_observed_relationship_dependencies_exist(self) -> None:
        definition = field(
            self.macros["adm_cmdb_observed_relationships(1)"], "definition"
        )
        for call in re.findall(r"`([^`]+)`", definition):
            m = re.match(r"^(\w+)\((.*)\)$", call, re.S)
            name = f"{m.group(1)}({len(m.group(2).split(','))})" if m else call.strip()
            self.assertIn(name, self.macros, call)

    def test_frontend_only_calls_defined_macros(self) -> None:
        source = (ROOT / "frontend/src/cmdb/reconciliation.ts").read_text()
        names = re.findall(r"\\`(adm_cmdb_\w+)", source)
        self.assertEqual(len(set(names)), 3)
        for name in names:
            self.assertTrue(name in self.macros or f"{name}(1)" in self.macros, name)


if __name__ == "__main__":
    unittest.main()
