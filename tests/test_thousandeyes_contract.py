"""Static safeguards for optional ThousandEyes and its isolated lab index."""

from __future__ import annotations

import configparser
import json
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]


def macro(name: str) -> str:
    config = configparser.RawConfigParser()
    config.read_string(
        (ROOT / "splunk_app/splunk_adm/default/macros.conf")
        .read_text(encoding="utf-8")
        .replace("\\\n", "\n    ")
    )
    return config.get(name, "definition")


def shell_array(source: str, name: str) -> set[str]:
    match = re.search(rf"(?m)^{re.escape(name)}=\(([^)]*)\)", source)
    if match is None:
        raise AssertionError(f"missing {name} array")
    return {
        quoted or unquoted
        for quoted, unquoted in re.findall(r'"([^"\n]+)"|([^\s()]+)', match.group(1))
        if quoted or unquoted
    }


class ThousandEyesContractTest(unittest.TestCase):
    def test_optional_source_starts_unselected_and_unqualified(self):
        self.assertEqual(macro("adm_index_thousandeyes"), "index=unconfigured_optional")
        self.assertEqual(macro("adm_thousandeyes_schema_qualified"), "0")

        registry = json.loads(
            (ROOT / "config/deployment-health.json").read_text(encoding="utf-8")
        )
        definition = next(
            source for source in registry["sources"] if source["id"] == "thousandeyes"
        )
        self.assertTrue(definition["selectable"])
        self.assertTrue(definition["quiet"])
        self.assertEqual(definition["readinessImpact"], "optional_evidence")

    def test_vendor_ta_is_optional_and_only_search_time_configuration_is_copied(self):
        lab = (ROOT / "tests/splunk/lab.sh").read_text(encoding="utf-8")
        required_tas = shell_array(lab, "TAS")
        optional_tas = shell_array(lab, "OPTIONAL_TAS")
        thousandeyes_ta = "cisco-thousandeyes-app-for-splunk_090/ta_cisco_thousandeyes"
        self.assertNotIn(thousandeyes_ta, required_tas)
        self.assertEqual(optional_tas, {thousandeyes_ta})
        self.assertIn('if [[ -d "$EXTRACTED/$ta" ]]; then', lab)
        self.assertIn('copy_ta "$EXTRACTED/$ta" "$stage/$(basename "$ta")"', lab)

        search_time_confs = shell_array(lab, "SEARCH_TIME_CONFS")
        self.assertTrue(
            {"props", "transforms", "eventtypes", "tags", "fields", "macros"}.issubset(
                search_time_confs
            )
        )
        self.assertFalse(
            {"inputs", "savedsearches", "alert_actions", "restmap"} & search_time_confs
        )
        copy_ta = lab.split("copy_ta() {", 1)[1].split("\n}\n", 1)[0]
        self.assertIn('"$src/default/$conf.conf"', copy_ta)
        self.assertNotIn('"$src/bin"', copy_ta)
        self.assertNotIn('"$src/default/inputs.conf"', copy_ta)
        self.assertNotIn('"$src/default/savedsearches.conf"', copy_ta)

    def test_atlas_te_index_is_dedicated_and_resettable(self):
        config = configparser.RawConfigParser()
        config.read(ROOT / "tests/splunk/lab_app/default/indexes.conf")
        self.assertEqual(
            dict(config.items("atlas_te")),
            {
                "homepath": "$SPLUNK_DB/atlas_te/db",
                "coldpath": "$SPLUNK_DB/atlas_te/colddb",
                "thawedpath": "$SPLUNK_DB/atlas_te/thaweddb",
            },
        )
        lab = (ROOT / "tests/splunk/lab.sh").read_text(encoding="utf-8")
        self.assertIn("atlas_te", shell_array(lab, "LAB_INDEXES"))
        hec = configparser.RawConfigParser()
        hec.read(ROOT / "tests/splunk/lab_app/default/inputs.conf.template")
        allowed = {
            index.strip() for index in hec["http://adm-lab"]["indexes"].split(",")
        }
        self.assertIn("atlas_te", allowed)
        self.assertNotIn("*", allowed)

    def test_atlas_path_rows_use_json_props_without_installing_vendor_writers(self):
        props = configparser.RawConfigParser()
        props.read(ROOT / "splunk_app/splunk_adm/default/props.conf")
        self.assertEqual(
            dict(props.items("atlas:thousandeyes:path")),
            {
                "should_linemerge": "false",
                "kv_mode": "json",
                "truncate": "65536",
            },
        )

        lab = (ROOT / "tests/splunk/lab.sh").read_text(encoding="utf-8")
        search_time_confs = shell_array(lab, "SEARCH_TIME_CONFS")
        self.assertNotIn("inputs", search_time_confs)
        self.assertNotIn("savedsearches", search_time_confs)
        copy_ta = lab.split("copy_ta() {", 1)[1].split("\n}\n", 1)[0]
        self.assertNotIn('"$src/default/inputs.conf"', copy_ta)
        self.assertNotIn('"$src/default/savedsearches.conf"', copy_ta)
        self.assertNotIn('"$src/bin"', copy_ta)


if __name__ == "__main__":
    unittest.main()
