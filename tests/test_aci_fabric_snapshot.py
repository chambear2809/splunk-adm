import json
import hashlib
import sys
import unittest
from pathlib import Path
from unittest.mock import ANY, patch

BIN = Path(__file__).parents[1] / "splunk_app" / "splunk_adm" / "bin"
sys.path.insert(0, str(BIN))

from adm_aci_lib import fabric, reader, schema  # noqa: E402
from adm_identity_lib.search import SearchError  # noqa: E402


PROFILE = {
    "authority": "apic.example",
    "fabric": "lab",
    "scope": "cv-lab",
    "apic_host": "10.0.0.1",
    "apic_pin": "a" * 64,
    "index": "cisco_aci",
    "host": "splunk-ta",
    "poll_version": "2",
}


def events(*, links=None, devices=None):
    return (
        [
            {
                "record_type": "manifest",
                "capture_id": "00000000-0000-0000-0000-000000000001",
                "capture_started_at": 100.0,
                "capture_completed_at": 101.0,
                "capture_digest": "d" * 64,
            }
        ]
        + [
            {
                "record_type": "object",
                "class": "topSystem",
                "attributes": {
                    "dn": f"topology/pod-1/node-{node}/sys",
                    "id": node,
                    "name": f"leaf-{node}",
                    "oobMgmtAddr": f"192.0.2.{node}",
                },
            }
            for node in (devices or (101, 102))
        ]
        + [
            {
                "record_type": "object",
                "class": "fabricLink",
                "attributes": {
                    "dn": f"topology/pod-1/lnkcnt-10{index}/lnk-101-1-{index + 1}-to-102-1-2",
                    "n1": 101,
                    "n2": 102,
                    "s1": 1,
                    "s2": 1,
                    "p1": index + 1,
                    "p2": 2,
                },
            }
            for index in range(links or 1)
        ]
    )


REPORT = {"capture_id": "00000000-0000-0000-0000-000000000001"}


def valid_envelope(capture_id, completed, *, routed=False):
    started = completed - 1
    objects = []
    for class_index, class_name in enumerate(schema.CLASSES_V2):
        observation_start = started + class_index * 0.001
        observation_end = observation_start + 0.0005
        entries = []
        if class_name == "topSystem":
            entries = [
                (
                    "topology/pod-1/node-101/sys",
                    {
                        "dn": "topology/pod-1/node-101/sys",
                        "id": 101,
                        "name": "leaf-101",
                        "oobMgmtAddr": "192.0.2.101",
                    },
                ),
                (
                    "topology/pod-1/node-102/sys",
                    {
                        "dn": "topology/pod-1/node-102/sys",
                        "id": 102,
                        "name": "leaf-102",
                        "oobMgmtAddr": "192.0.2.102",
                    },
                ),
            ]
        elif class_name == "fabricLink":
            entries = [
                (
                    "topology/pod-1/lnkcnt-1/lnk-101-1-1-to-102-1-2",
                    {
                        "dn": "topology/pod-1/lnkcnt-1/lnk-101-1-1-to-102-1-2",
                        "n1": 101,
                        "n2": 102,
                        "s1": 1,
                        "s2": 1,
                        "p1": 1,
                        "p2": 2,
                    },
                )
            ]
        elif routed and class_name == "l3EncRtdIf":
            entries = [
                (
                    "topology/pod-1/node-101/sys/ctx-[vxlan-1]/encrtd-[eth1/24.15]",
                    {
                        "dn": "topology/pod-1/node-101/sys/ctx-[vxlan-1]/encrtd-[eth1/24.15]",
                        "id": "eth1/24.15",
                        "encap": "vlan-304",
                        "adminSt": "up",
                        "ifConnDn": "resPolCont/rtdOutCont/rtdOutDef-[uni/tn-lab/out-external]/node-101/stpathatt-[eth1/24]/conndef/conn-[vlan-304]-[198.51.100.6/30]",
                        "rtdOutDefDn": "resPolCont/rtdOutCont/rtdOutDef-[uni/tn-lab/out-external]",
                    },
                )
            ]
        elif routed and class_name == "l1PhysIf":
            entries = [
                (
                    "topology/pod-1/node-101/sys/phys-[eth1/24]",
                    {
                        "dn": "topology/pod-1/node-101/sys/phys-[eth1/24]",
                        "id": "eth1/24",
                        "layer": "Layer3",
                    },
                )
            ]
        elif routed and class_name == "ethpmPhysIf":
            entries = [
                (
                    "topology/pod-1/node-101/sys/phys-[eth1/24]/phys",
                    {
                        "dn": "topology/pod-1/node-101/sys/phys-[eth1/24]/phys",
                        "encap": "3",
                    },
                )
            ]
        else:
            entries = [(f"uni/test/{class_name}", {"dn": f"uni/test/{class_name}"})]
        for dn, attrs in entries:
            canonical = json.dumps(
                {class_name: {"attributes": attrs}},
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
            objects.append(
                {
                    "schema": "application_atlas.aci_poll.v2",
                    "schema_version": 2,
                    "record_type": "object",
                    "class": class_name,
                    "dn": dn,
                    "attributes": attrs,
                    "capture_id": capture_id,
                    "authority": PROFILE["authority"],
                    "fabric": PROFILE["fabric"],
                    "scope": PROFILE["scope"],
                    "capture_started_at": started,
                    "capture_completed_at": completed,
                    "consumer_quarantine": True,
                    "observation_started_at": observation_start,
                    "observation_completed_at": observation_end,
                    "record_fingerprint": hashlib.sha256(canonical).hexdigest(),
                }
            )
    first = {}
    for class_name in schema.CLASSES_V2:
        rows = [
            {class_name: {"attributes": o["attributes"]}}
            for o in objects
            if o["class"] == class_name
        ]
        digest = hashlib.sha256(
            b"\n".join(
                json.dumps(r, sort_keys=True, separators=(",", ":")).encode()
                for r in rows
            )
        ).hexdigest()
        class_index = list(schema.CLASSES_V2).index(class_name)
        window_start = started + class_index * 0.001
        first[class_name] = {
            "expected_total": len(rows),
            "observed_total": len(rows),
            "pages": 1,
            "request_windows": [
                {"started_at": window_start, "completed_at": window_start + 0.0005}
            ],
            "canonical_digest": digest,
            "comparison_digest": digest,
            "comparison_omissions": sorted(
                schema.VOLATILE_ATTRIBUTES.get(class_name, ())
            ),
        }
    second = {
        k: {
            **v,
            "request_windows": [
                {
                    "started_at": v["request_windows"][0]["started_at"] + 0.05,
                    "completed_at": v["request_windows"][0]["completed_at"] + 0.05,
                }
            ],
        }
        for k, v in first.items()
    }
    manifest = {
        "schema": "application_atlas.aci_poll.v2",
        "schema_version": 2,
        "record_type": "manifest",
        "capture_id": capture_id,
        "authority": PROFILE["authority"],
        "fabric": PROFILE["fabric"],
        "scope": PROFILE["scope"],
        "apic_address": PROFILE["apic_host"],
        "apic_certificate_sha256": PROFILE["apic_pin"],
        "capture_started_at": started,
        "capture_completed_at": completed,
        "consumer_quarantine": True,
        "complete": True,
        "page_size": 500,
        "classes": list(schema.CLASSES_V2),
        "record_count": len(objects),
        "passes": [first, second],
        "capture_digest": hashlib.sha256(
            json.dumps(
                {k: v["canonical_digest"] for k, v in first.items()},
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ).hexdigest(),
    }
    return [manifest] + objects


class FabricSnapshotTests(unittest.TestCase):
    def reader_rows(self, envelopes, receipts=None):
        receipts = receipts or {}
        rows = []
        for envelope in envelopes:
            completed = envelope[0]["capture_completed_at"]
            receipt = receipts.get(envelope[0]["capture_id"], completed + 0.5)
            for event in envelope:
                rows.append(
                    {
                        "_raw": json.dumps(event),
                        "index": PROFILE["index"],
                        "host": PROFILE["host"],
                        "source": reader.SOURCE,
                        "sourcetype": "adm:aci_poll:v2",
                        "event_time": completed,
                        "receipt_time": receipt,
                    }
                )
        for row in rows:
            row["_atlas_total"] = len(rows)
        return rows

    def test_reader_validates_full_envelope_and_selects_latest_capture(self):
        old = valid_envelope("00000000-0000-0000-0000-000000000001", 100)
        new = valid_envelope("00000000-0000-0000-0000-000000000002", 101)
        profile = {**PROFILE, "enabled": True}
        rows = self.reader_rows(
            [old, new], {old[0]["capture_id"]: 100.25, new[0]["capture_id"]: 101.25}
        )
        result = reader.read_fabric_snapshot(rows, profile, 0, 102, 102)
        snapshot = json.loads(result[0]["snapshot"])
        self.assertEqual(snapshot["capture_id"], new[0]["capture_id"])
        self.assertEqual(snapshot["receipt_time"], 101.25)

    def test_reader_projects_native_routed_fixture(self):
        envelope = valid_envelope(
            "00000000-0000-0000-0000-000000000009", 101, routed=True
        )
        result = reader.read_fabric_snapshot(
            self.reader_rows([envelope]), {**PROFILE, "enabled": True}, 0, 102, 102
        )
        snapshot = json.loads(result[0]["snapshot"])
        self.assertEqual(snapshot["routed_interface_count"], 1)
        routed = snapshot["routed_interfaces"][0]
        self.assertEqual(routed["interface"], "eth1/24.15")
        self.assertEqual(routed["parent_interface"], "eth1/24")
        self.assertEqual(routed["encap"], "vlan-304")

    def test_reader_rejects_ambiguous_tie_and_newer_invalid_capture(self):
        first = valid_envelope("00000000-0000-0000-0000-000000000001", 101)
        second = valid_envelope("00000000-0000-0000-0000-000000000002", 101)
        with self.assertRaisesRegex(SearchError, "ambiguous_capture_tie"):
            reader.read_fabric_snapshot(
                self.reader_rows([first, second]),
                {**PROFILE, "enabled": True},
                0,
                102,
                102,
            )
        invalid = valid_envelope("00000000-0000-0000-0000-000000000003", 102)
        invalid.pop()
        with self.assertRaisesRegex(SearchError, "newer_capture_invalid"):
            reader.read_fabric_snapshot(
                self.reader_rows([first, invalid]),
                {**PROFILE, "enabled": True},
                0,
                103,
                103,
            )

    def test_reader_rejects_missing_manifest_and_conflicting_capture_clock(self):
        first = valid_envelope("00000000-0000-0000-0000-000000000001", 101)
        missing = valid_envelope("00000000-0000-0000-0000-000000000002", 102)[1:]
        with self.assertRaisesRegex(SearchError, "newer_capture_invalid"):
            reader.read_fabric_snapshot(
                self.reader_rows([first, missing]),
                {**PROFILE, "enabled": True},
                0,
                103,
                103,
            )
        conflicting = valid_envelope("00000000-0000-0000-0000-000000000003", 101)
        conflicting[1]["capture_completed_at"] = 102
        with self.assertRaises(SearchError):
            reader.read_fabric_snapshot(
                self.reader_rows([conflicting]),
                {**PROFILE, "enabled": True},
                0,
                103,
                103,
            )
        equal_invalid = valid_envelope("00000000-0000-0000-0000-000000000004", 101)[1:]
        with self.assertRaisesRegex(SearchError, "newer_capture_invalid"):
            reader.read_fabric_snapshot(
                self.reader_rows([first, equal_invalid]),
                {**PROFILE, "enabled": True},
                0,
                103,
                103,
            )

    def test_reader_does_not_rank_mixed_clock_group_by_old_manifest(self):
        first = valid_envelope("00000000-0000-0000-0000-000000000001", 101)
        mixed = valid_envelope("00000000-0000-0000-0000-000000000005", 100)
        for event in mixed[1:]:
            event["capture_completed_at"] = 102
        mixed_rows = self.reader_rows([mixed])
        for row in mixed_rows[1:]:
            row["event_time"] = 102
            row["receipt_time"] = 102.5
        combined = self.reader_rows([first]) + mixed_rows
        for row in combined:
            row["_atlas_total"] = len(combined)
        with self.assertRaisesRegex(SearchError, "newer_capture_invalid"):
            reader.read_fabric_snapshot(
                combined,
                {**PROFILE, "enabled": True},
                0,
                103,
                103,
            )

    @patch.object(fabric, "validate_events", return_value=REPORT)
    def test_projects_qualified_devices_and_parallel_links(self, _validate):
        result = fabric.project_fabric_snapshot(
            events(links=2), PROFILE, receipts={("x",): 101.5}, as_of=102
        )
        _validate.assert_called_once_with(
            ANY,
            expected_authority="apic.example",
            expected_fabric="lab",
            expected_scope="cv-lab",
            expected_apic_pin="a" * 64,
            expected_apic_host="10.0.0.1",
            now=102,
            expected_version=2,
        )
        self.assertEqual(result["schema"], "application_atlas.aci_fabric_snapshot.v1")
        self.assertEqual(result["classification"], "inventory_snapshot")
        self.assertEqual(result["traversal"], "not_observed")
        self.assertEqual(result["device_count"], 2)
        self.assertEqual(result["link_count"], 2)
        self.assertEqual(
            result["links"][0]["parallel_key"], result["links"][1]["parallel_key"]
        )
        self.assertNotEqual(result["links"][0]["id"], result["links"][1]["id"])
        self.assertEqual(result["links"][0]["a_interface"], "eth1/1")

    @patch.object(fabric, "validate_events", return_value=REPORT)
    def test_missing_endpoint_fails_closed(self, _validate):
        value = events()
        value[-1]["attributes"]["n2"] = "pod-1/node-999"
        with self.assertRaisesRegex(ValueError, "endpoint_missing"):
            fabric.project_fabric_snapshot(value, PROFILE, receipts={}, as_of=102)

    @patch.object(
        fabric, "validate_events", side_effect=ValueError("capture_digest_mismatch")
    )
    def test_capture_failure_is_not_projected(self, _validate):
        with self.assertRaisesRegex(ValueError, "capture_digest_mismatch"):
            fabric.project_fabric_snapshot(events(), PROFILE, receipts={}, as_of=102)

    @patch.object(fabric, "validate_events", return_value=REPORT)
    def test_no_attachment_or_path_promotion(self, _validate):
        result = fabric.project_fabric_snapshot(
            events(), PROFILE, receipts={}, as_of=102
        )
        encoded = json.dumps(result)
        self.assertNotIn("fvCEp", encoded)
        self.assertNotIn("attachment", encoded)
        self.assertNotIn("valid_from", encoded)

    @patch.object(fabric, "validate_events", return_value=REPORT)
    def test_routed_interface_requires_same_node_physical_correlates(self, _validate):
        value = events()
        value.extend(
            [
                {
                    "record_type": "object",
                    "class": "l1PhysIf",
                    "attributes": {"dn": "topology/pod-1/node-101/sys/phys-[eth1/24]"},
                },
                {
                    "record_type": "object",
                    "class": "ethpmPhysIf",
                    "attributes": {
                        "dn": "topology/pod-1/node-101/sys/phys-[eth1/24]/phys"
                    },
                },
                {
                    "record_type": "object",
                    "class": "l3EncRtdIf",
                    "attributes": {
                        "dn": "topology/pod-1/node-101/sys/ctx-[vxlan-1]/encrtd-[eth1/24.15]",
                        "id": "eth1/24.15",
                        "encap": "vlan-304",
                        "adminSt": "up",
                        "ifConnDn": "resPolCont/rtdOutCont/rtdOutDef-[uni/tn-a/out-a]/node-101/stpathatt-[eth1/24]/conndef/conn-[vlan-304]-[198.51.100.6/30]",
                        "rtdOutDefDn": "resPolCont/rtdOutCont/rtdOutDef-[uni/tn-a/out-a]",
                    },
                },
            ]
        )
        result = fabric.project_fabric_snapshot(value, PROFILE, receipts={}, as_of=102)
        self.assertEqual(result["routed_interface_count"], 1)
        self.assertEqual(result["routed_interfaces"][0]["parent_interface"], "eth1/24")
        value[-1]["attributes"]["dn"] = (
            "topology/pod-1/node-999/sys/ctx-[vxlan-1]/encrtd-[eth1/24.15]"
        )
        with self.assertRaisesRegex(ValueError, "node_missing"):
            fabric.project_fabric_snapshot(value, PROFILE, receipts={}, as_of=102)
        value[-1]["attributes"]["dn"] = (
            "topology/pod-1/node-101/sys/ctx-[vxlan-1]/encrtd-[eth1/24.15]"
        )
        value[-1]["attributes"]["ifConnDn"] = (
            "resPolCont/rtdOutCont/rtdOutDef-[uni/tn-a/out-a]/node-102/stpathatt-[eth1/24]/conndef/conn-[vlan-304]-[198.51.100.6/30]"
        )
        with self.assertRaisesRegex(ValueError, "node_mismatch"):
            fabric.project_fabric_snapshot(value, PROFILE, receipts={}, as_of=102)

    @patch.object(fabric, "validate_events", return_value=REPORT)
    def test_malformed_device_dn_fails_closed(self, _validate):
        value = events()
        value[1]["attributes"]["dn"] = "not-a-node"
        with self.assertRaisesRegex(ValueError, "topSystem_dn_invalid"):
            fabric.project_fabric_snapshot(value, PROFILE, receipts={}, as_of=102)


if __name__ == "__main__":
    unittest.main()
