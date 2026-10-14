"""Scope lookup schema and ACL regressions, without a Splunk server."""

import configparser
from pathlib import Path
import re
import unittest


APP = Path(__file__).resolve().parents[1] / "splunk_app/splunk_adm"


class ScopeConfigTest(unittest.TestCase):
    def test_scope_uses_kv_with_existing_field_names(self):
        collections = configparser.RawConfigParser()
        collections.read(APP / "default/collections.conf")
        scope = collections["adm_observer_scope"]
        self.assertEqual(
            {key.removeprefix("field.") for key in scope if key.startswith("field.")},
            {"observer_kind", "observer", "scope", "cluster"},
        )
        self.assertTrue(scope.getboolean("replicate"))
        transforms = configparser.RawConfigParser()
        transforms.read(APP / "default/transforms.conf")
        definition = transforms["adm_observer_scope"]
        self.assertEqual(definition["external_type"], "kvstore")
        self.assertEqual(definition["collection"], "adm_observer_scope")
        self.assertEqual(
            {field.strip() for field in definition["fields_list"].split(",")},
            {"_key", "observer_kind", "observer", "scope", "cluster"},
        )
        self.assertNotIn("filename", definition)
        self.assertNotIn("check_permission", definition)
        for name in ("adm_recovery_state", "adm_recovery_audit"):
            self.assertTrue(transforms[name].getboolean("check_permission"))

    def test_scope_collection_and_lookup_explicitly_restrict_writes(self):
        metadata = (APP / "metadata/default.meta").read_text()
        for name in ("collections/adm_observer_scope", "transforms/adm_observer_scope"):
            match = re.search(
                r"(?m)^\[" + re.escape(name) + r"\]\naccess = ([^\n]+)", metadata
            )
            self.assertIsNotNone(match)
            self.assertEqual(match[1], "read : [ * ], write : [ admin, sc_admin ]")

    def test_migration_is_disabled_unscheduled_and_owner_dispatched(self):
        saved = configparser.RawConfigParser()
        saved.read(APP / "default/savedsearches.conf")
        migration = saved["ADM - Migrate observer scope"]
        self.assertTrue(migration.getboolean("disabled"))
        self.assertFalse(migration.getboolean("enableSched"))
        self.assertEqual(migration["dispatchAs"], "owner")
        self.assertNotIn("cron_schedule", migration)
