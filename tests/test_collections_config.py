"""KV Store collection schema regressions, without a Splunk server."""

import configparser
import json
from pathlib import Path
import unittest

from tools import platform_restore_adapters, rehearse_restore


APP = Path(__file__).resolve().parents[1] / "splunk_app/splunk_adm"
CATALOG_BOUNDARY = '{"service": 1, "environment": 1, "cluster": 1, "namespace": 1}'
VIEWER_ACCESS = "read : [ adm_investigate, adm_viewer, admin, sc_admin ], write : [ admin, sc_admin ]"
ADMIN_ACCESS = "read : [ admin, sc_admin ], write : [ admin, sc_admin ]"
ADMIN_ONLY = {
    "collections/adm_recovery_state",
    "collections/adm_recovery_audit",
    "transforms/adm_recovery_state",
    "transforms/adm_recovery_audit",
    "transforms/adm_ip_identity_all",
}


def _collections() -> configparser.RawConfigParser:
    parser = configparser.RawConfigParser()
    parser.read(APP / "default/collections.conf")
    return parser


def _metadata() -> configparser.RawConfigParser:
    metadata = configparser.RawConfigParser()
    metadata.read_string(
        (APP / "metadata/default.meta").read_text().replace("[]", "[app]", 1)
    )
    return metadata


class CollectionsConfigTest(unittest.TestCase):
    def test_shared_deployment_intent_has_administrator_write_acl(self):
        self.assertIn("adm_deployment_settings", _collections())
        self.assertEqual(
            _metadata()["collections/adm_deployment_settings"]["access"],
            VIEWER_ACCESS,
        )

    def test_app_and_every_derived_lookup_are_readable_only_by_atlas_viewers(self):
        metadata = _metadata()
        self.assertEqual(metadata["app"]["access"], VIEWER_ACCESS)
        transforms = configparser.RawConfigParser()
        transforms.read(APP / "default/transforms.conf")
        stanzas = [f"collections/{name}" for name in _collections().sections()]
        stanzas += [f"transforms/{name}" for name in transforms.sections()]
        for stanza in stanzas:
            with self.subTest(stanza=stanza):
                self.assertEqual(
                    metadata[stanza]["access"],
                    ADMIN_ACCESS if stanza in ADMIN_ONLY else VIEWER_ACCESS,
                )
        for section in metadata.sections():
            with self.subTest(section=section):
                self.assertNotIn("*", metadata[section].get("access", ""))

    def test_viewer_role_grants_no_capability_and_investigator_inherits_it(self):
        authorize = configparser.RawConfigParser()
        authorize.optionxform = str
        authorize.read(APP / "default/authorize.conf")
        viewer = dict(authorize["role_adm_viewer"])
        self.assertTrue(viewer)
        self.assertEqual(set(viewer.values()), {"disabled"})
        self.assertNotIn("importRoles", viewer)
        self.assertEqual(authorize["role_adm_investigate"]["importRoles"], "adm_viewer")

    def test_v1_and_v2_catalogs_keep_boundary_acceleration(self):
        collections = _collections()
        for name in ("adm_app_catalog", "adm_app_catalog_v2"):
            with self.subTest(collection=name):
                self.assertEqual(
                    collections[name].get("accelerated_fields.boundary"),
                    CATALOG_BOUNDARY,
                )

    def test_v2_collections_mirror_v1_schema_and_acceleration(self):
        collections = _collections()
        pairs = [
            (name.removesuffix("_v2"), name)
            for name in collections.sections()
            if name.endswith("_v2")
        ]
        self.assertTrue(pairs)
        for v1, v2 in pairs:
            with self.subTest(collection=v2):
                self.assertIn(v1, collections)
                self.assertEqual(dict(collections[v1]), dict(collections[v2]))

    def test_transforms_and_collections_have_zero_schema_drift(self):
        # Splunk collections.conf field.<name> only allows string, number, bool,
        # and time; JSON array fields are stored untyped in KV Store while still
        # exposed through transforms.conf fields_list.
        untyped_array_fields = {("adm_recovery_audit", "changed_fields")}
        collections = _collections()
        transforms = configparser.RawConfigParser()
        transforms.read(APP / "default/transforms.conf")
        for stanza in transforms.sections():
            definition = transforms[stanza]
            if definition.get("external_type") != "kvstore":
                continue
            col_name = definition["collection"]
            with self.subTest(transform=stanza, collection=col_name):
                self.assertIn(col_name, collections)
                col_fields = {
                    key.removeprefix("field.")
                    for key in collections[col_name]
                    if key.startswith("field.")
                }
                listed_fields = {
                    field.strip()
                    for field in definition["fields_list"].split(",")
                    if field.strip()
                }
                allowed_untyped = {
                    field for col, field in untyped_array_fields if col == col_name
                }
                self.assertIn("_key", listed_fields)
                self.assertEqual(listed_fields - {"_key"} - allowed_untyped, col_fields)

    def test_every_accelerated_field_references_declared_collection_fields(self):
        collections = _collections()
        valid_types = {"string", "number", "bool", "time"}
        for name in collections.sections():
            section = collections[name]
            declared = {}
            for key, value in section.items():
                if key.startswith("field."):
                    self.assertIn(value, valid_types, (name, key, value))
                    declared[key.removeprefix("field.")] = value
            for key, value in section.items():
                if key.startswith("accelerated_fields."):
                    spec = json.loads(value)
                    self.assertIsInstance(spec, dict, (name, key))
                    self.assertTrue(spec, (name, key))
                    for field_name, direction in spec.items():
                        self.assertIn(
                            field_name,
                            declared,
                            f"{name} {key} references undeclared field {field_name}",
                        )
                        self.assertIn(direction, (1, -1), (name, key, field_name))

    def test_backup_restore_tools_cover_every_configured_collection(self):
        configured = set(_collections().sections())
        self.assertGreaterEqual(len(configured), 19)
        self.assertEqual(set(platform_restore_adapters.COLLECTIONS), configured)
        self.assertEqual(set(rehearse_restore.COLLECTIONS), configured)

    def test_saved_searches_have_bounded_windows_priorities_and_ship_disabled(self):
        saved = configparser.RawConfigParser(strict=False)
        saved.read_string(
            (APP / "default/savedsearches.conf").read_text().replace("\\\n", "")
        )
        self.assertGreaterEqual(len(saved.sections()), 20)
        # Only the late-Catalyst history builder genuinely needs event-time earliest=0,
        # and it must remain strictly bounded by dispatch.index_earliest/index_latest.
        indexed_earliest_zero_allowlist = {"ADM - Network client history builder"}
        for name in saved.sections():
            stanza = saved[name]
            with self.subTest(saved_search=name):
                self.assertEqual(stanza.get("disabled"), "1")
                self.assertEqual(stanza.get("dispatchAs"), "owner")
                earliest = stanza.get("dispatch.earliest_time")
                latest = stanza.get("dispatch.latest_time")
                self.assertTrue(earliest, f"{name} missing dispatch.earliest_time")
                self.assertTrue(latest, f"{name} missing dispatch.latest_time")
                if earliest == "0":
                    self.assertIn(name, indexed_earliest_zero_allowlist)
                    self.assertTrue(stanza.get("dispatch.index_earliest"))
                    self.assertTrue(stanza.get("dispatch.index_latest"))
                if stanza.get("cron_schedule"):
                    self.assertIn(
                        stanza.get("schedule_priority"),
                        {"default", "higher", "highest"},
                    )
                if name.endswith(" prune"):
                    self.assertEqual(stanza.get("enableSched"), "0")
                    self.assertEqual(stanza.get("max_concurrent"), "1")
                if "action.webhook" in stanza:
                    self.assertEqual(stanza.get("action.webhook"), "0")
                    self.assertEqual(stanza.get("enableSched"), "0")

    def test_adm_find_macros_use_indexed_bounded_reads_not_full_scans(self):
        macros_text = (APP / "default/macros.conf").read_text()
        macros = configparser.RawConfigParser(strict=False)
        macros.read_string(macros_text.replace("\\\n", ""))
        collections = _collections()

        def leading_keys(col_name: str) -> set[str]:
            return {
                next(iter(json.loads(val)))
                for key, val in collections[col_name].items()
                if key.startswith("accelerated_fields.")
            }

        self.assertTrue(
            {"ip", "epg", "attach_device"} <= leading_keys("adm_ip_identity")
        )
        self.assertIn("pod_uid", leading_keys("adm_service_workload"))
        self.assertTrue(
            {"client_ip", "client_mac", "native_id"}
            <= leading_keys("adm_network_client_history")
        )

        for name in ("adm_find(1)", "adm_find_v2(1)"):
            defn = macros.get(name, "definition")
            with self.subTest(macro=name):
                self.assertNotIn("adm_catalog_append_kv(adm_ip_identity)", defn)
                self.assertNotIn("adm_catalog_append_kv(adm_service_workload)", defn)
                self.assertNotIn("where [|", defn)
                self.assertIn("lookup local=true adm_ip_identity ip AS", defn)
                self.assertIn("lookup local=true adm_ip_identity epg AS", defn)
                self.assertIn(
                    "lookup local=true adm_ip_identity attach_device AS", defn
                )
                self.assertIn("lookup local=true adm_service_workload pod_uid AS", defn)
                self.assertIn(
                    "stats count AS adm_status_rows max(adm_catalog_invalid)", defn
                )
                self.assertIn("mvcount(adm_ip_key)>=`adm_identity_max_matches`", defn)
                self.assertIn("mvcount(adm_sw_key)>=`adm_identity_max_matches`", defn)

        nc_find = macros.get("adm_find_network_client(1)", "definition")
        self.assertIn('`adm_find_network_client_read("$query$")`', nc_find)
        self.assertNotIn("adm_kv_read_all(", nc_find)
        nc_read = macros.get("adm_find_network_client_read(1)", "definition")
        self.assertNotIn("where [|", nc_read)
        self.assertIn(
            "lookup local=true adm_network_client_history client_ip AS", nc_read
        )
        self.assertIn(
            "lookup local=true adm_network_client_history client_mac AS", nc_read
        )
        self.assertIn(
            "lookup local=true adm_network_client_history native_id AS", nc_read
        )
        self.assertIn("mvcount(adm_ip_key)>=`adm_identity_max_matches`", nc_read)


if __name__ == "__main__":
    unittest.main()
