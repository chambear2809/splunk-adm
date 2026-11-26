"""KV Store collection schema regressions, without a Splunk server."""

import configparser
from pathlib import Path
import unittest


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


if __name__ == "__main__":
    unittest.main()
