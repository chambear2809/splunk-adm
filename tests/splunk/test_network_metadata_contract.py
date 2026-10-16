"""Offline contract checks for endpoint network metadata and NetFlow VLANs."""

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
MACROS = (ROOT / "splunk_app/splunk_adm/default/macros.conf").read_text()
TRANSFORMS = (ROOT / "splunk_app/splunk_adm/default/transforms.conf").read_text()
COLLECTIONS = (ROOT / "splunk_app/splunk_adm/default/collections.conf").read_text()
DATA_LAYER = (ROOT / "docs/DATA_LAYER.md").read_text()


class NetworkMetadataContractTest(unittest.TestCase):
    def test_netflow_vlan_contract_is_bounded_and_keeps_original_tuple(self):
        self.assertIn("adm_ingress_vlan", MACROS)
        self.assertIn("adm_egress_vlan", MACROS)
        self.assertIn("vlan_observations_truncated", MACROS)
        self.assertIn("vlan_observations", DATA_LAYER)


    def test_identity_network_metadata_has_apic_relation_and_nd_fallback(self):
        self.assertIn('component=="fvRsBd"', MACROS)
        self.assertIn("adm_aci_epg_dn", MACROS)
        self.assertIn("adm_poll_interval", MACROS)
        self.assertIn('"vlan", attr_vlan', MACROS)
        self.assertIn('"bd", attr_bridge_domain', MACROS)
        self.assertIn("adm_network_history_cap", MACROS)
        self.assertIn("desc.nh", DATA_LAYER)
        for key in ("t", "v", "b", "bd_dn", "bd_tenant", "source"):
            self.assertIn(f"`{key}`", DATA_LAYER)


    def test_lookup_contract_carries_network_fields(self):
        for field in (
            "attr_vlan",
            "attr_bridge_domain",
            "attr_vlan_status",
            "attr_bridge_domain_status",
            "network_history",
        ):
            self.assertIn(field, TRANSFORMS)
            self.assertIn(field, COLLECTIONS)

