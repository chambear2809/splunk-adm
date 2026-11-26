"""Static contract of the scoped endpoint typeahead macro, adm_ip_suggest.

Each KV read must be anchored on the leading key of an adm_ip_identity index
and capped, the output bounded to 20 suggestions, and arguments validated
before substitution. Live wildcard push-down still needs a lab check."""

from __future__ import annotations

import configparser
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MACROS = ROOT / "splunk_app/splunk_adm/default/macros.conf"
COLLECTIONS = ROOT / "splunk_app/splunk_adm/default/collections.conf"
BEGIN = "# ---- BEGIN adm_ip_suggest: scoped endpoint typeahead ----"
END = "# ---- END adm_ip_suggest ----"


def stanzas(text: str) -> dict[str, str]:
    return {
        m.group("name"): m.group("body")
        for m in re.finditer(
            r"^\[(?P<name>[^\]]+)\]\n(?P<body>.*?)(?=^\[|^# ---- |\Z)",
            text,
            re.M | re.S,
        )
    }


def setting(body: str, key: str) -> str:
    m = re.search(rf"^{key} = (.*?)(?=^\w+ = |\Z)", body, re.M | re.S)
    assert m, f"{key} missing"
    return m.group(1).replace("\\\n", "\n").strip()


def splunk_regex(validation: str, arg: str) -> re.Pattern[str]:
    m = re.search(rf'match\({arg}, "(.*?)"\)', validation)
    assert m, arg
    return re.compile(m.group(1).replace("\\z", "\\Z"))


class IpSuggestMacroTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = MACROS.read_text()
        cls.macros = stanzas(cls.text)
        cls.body = cls.macros["adm_ip_suggest(2)"]
        cls.search = setting(cls.body, "definition")
        cls.validation = setting(cls.body, "validation")

    def test_block_is_one_contiguous_section_after_the_identity_resolver(self):
        self.assertEqual(self.text.count(BEGIN), 1)
        self.assertEqual(self.text.count(END), 1)
        start, end = self.text.index(BEGIN), self.text.index(END)
        self.assertLess(start, end)
        block = self.text[start:end]
        self.assertEqual(
            re.findall(r"^\[([^\]]+)\]", block, re.M),
            ["adm_ip_suggest_read_limit", "adm_ip_suggest(2)"],
        )
        outside = self.text[:start] + self.text[end + len(END) :]
        self.assertNotIn("adm_ip_suggest", outside)
        before = re.findall(r"^\[([^\]]+)\]", self.text[:start], re.M)
        self.assertEqual(before[-1], "adm_path_trace_resolve(2)")

    def test_arguments_are_validated_before_substitution(self):
        self.assertEqual(setting(self.body, "args"), "prefix, scope")
        prefix = splunk_regex(self.validation, "prefix")
        scope = splunk_regex(self.validation, "scope")
        for good in ("10.", "10.4.0", "2001:db8", "web-0", "orders.db"):
            self.assertTrue(prefix.match(good), good)
        for bad in (
            "10",
            "-10.4",
            "10.4*",
            '10.4"',
            "10.4 OR",
            "a_b_c",
            "10.4\n",
            "x" * 64,
            "10.4)|delete",
        ):
            self.assertIsNone(prefix.match(bad), bad)
        for good in ("fabric-a", "vrf/blue", "tenant@site", "a:b"):
            self.assertTrue(scope.match(good), good)
        for bad in ("", "fab ric", 'a"b', "a,b", "a\n"):
            self.assertIsNone(scope.match(bad), bad)
        reserved = re.search(r'NOT match\(scope, "(.*?)"\)', self.validation)
        self.assertIsNotNone(reserved)
        reserved_re = re.compile(reserved.group(1))
        for bad in ("unmapped:10.0.0.1", "UNKNOWN", "reserved"):
            self.assertTrue(reserved_re.search(bad), bad)
        self.assertIsNone(reserved_re.search("fabric-a"))

    def test_every_read_is_capped_and_anchored_on_an_index_leading_key(self):
        collections = configparser.RawConfigParser()
        collections.read(COLLECTIONS)
        identity = collections["adm_ip_identity"]
        leading = {
            name.removeprefix("accelerated_fields."): next(iter(json.loads(value)))
            for name, value in identity.items()
            if name.startswith("accelerated_fields.")
        }
        self.assertEqual(leading["ip_scope"], "ip")
        self.assertEqual(leading["name_scope"], "entity_name")
        self.assertEqual(
            list(json.loads(identity["accelerated_fields.name_scope"])),
            ["entity_name", "scope"],
        )
        reads = re.findall(
            r"inputlookup (?:append=true )?max=`adm_ip_suggest_read_limit` "
            r'adm_ip_identity where (\w+)="\$prefix\$\*" AND scope="\$scope\$"',
            self.search,
        )
        self.assertEqual(reads, ["ip", "entity_name"])
        self.assertEqual(len(re.findall(r"\binputlookup\b", self.search)), 2)
        self.assertNotRegex(self.search, r"(?<!input)\blookup\b")
        limit = int(setting(self.macros["adm_ip_suggest_read_limit"], "definition"))
        self.assertTrue(0 < limit <= 1000)

    def test_output_is_bounded_current_scope_verified_and_reports_truncation(self):
        for clause in (
            'scope=="$scope$" AND scope_mapping_verified==1',
            'substr(ip,1,len("$prefix$"))=="$prefix$"',
            'substr(entity_name,1,len("$prefix$"))=="$prefix$"',
            "tonumber(valid_from)<=now()",
            "(isnull(valid_end) OR tonumber(valid_end)>now())",
            "by ip",
            "where adm_rank<=21",
            "adm_total>20",
            "adm_ip_reads>=`adm_ip_suggest_read_limit`",
            "adm_name_reads>=`adm_ip_suggest_read_limit`",
        ):
            self.assertIn(clause, self.search)
        self.assertTrue(
            self.search.rstrip().endswith(
                "| fields row_type ip label entity_kind truncated"
            )
        )


if __name__ == "__main__":
    unittest.main()
