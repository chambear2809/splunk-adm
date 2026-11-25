"""Installed regressions for Device evidence boundaries and authority selection."""

from __future__ import annotations

import copy
import datetime
import json
import os
from pathlib import Path
import tempfile
import time
import unittest

import lab

ROOT = Path(__file__).resolve().parents[2]
NODE = "pod-1/node-101"


def event_line(path: Path, predicate) -> dict:
    for line in path.read_text(encoding="utf-8").splitlines():
        row = json.loads(line)
        if predicate(row):
            return row
    raise AssertionError(f"no fixture row in {path}")


def replace_tab(raw: str, key: str, value: str) -> str:
    import re

    return re.sub(
        rf'(?<=\t){re.escape(key)}=(?:"[^"]*"|[^\t]*)',
        f'{key}="{value}"',
        raw,
    )


def iso_stamp(epoch: int) -> str:
    return datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.000+00:00"
    )


@unittest.skipUnless(os.environ.get("ADM_LAB") == "1", "requires disposable lab")
class DeviceEvidenceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        lab.wait_ready()
        cls.tag = "device-evidence-" + os.urandom(5).hex()
        cls.at = int(time.time()) - 900
        cls.earliest = cls.at - 30
        cls.latest = cls.at + 30
        cls.authority_a = cls.tag + "-a"
        cls.authority_b = cls.tag + "-b"
        cls.exporter = "198.19." + ".".join(map(str, os.urandom(2)))
        cls.counter_exporter = "198.18." + ".".join(map(str, os.urandom(2)))
        cls.firewall = "203.0.113." + str(1 + os.urandom(1)[0] % 254)
        cls.firewall_scope = cls.tag + "-firewall"
        cls.events = []
        acl = event_line(
            ROOT / "fixtures/raw-aci/aci_class.ndjson",
            lambda row: 'component="acllogPermitL3Pkt"' in row["event"],
        )
        for authority, src, dst, poll, stamp, record_id in (
            (
                cls.authority_a,
                "198.18.1.9",
                "198.18.1.19",
                cls.latest - 20,
                cls.latest - 20,
                "a-inside",
            ),
            (
                cls.authority_a,
                "198.18.1.10",
                "198.18.1.20",
                cls.latest + 120,
                cls.latest - 10,
                "a-delayed",
            ),
            (
                cls.authority_a,
                "198.18.1.10",
                "198.18.1.20",
                cls.latest + 200,
                cls.latest - 10,
                "a-delayed",
            ),
            (
                cls.authority_b,
                "198.18.2.10",
                "198.18.2.20",
                cls.latest - 20,
                cls.latest - 20,
                "b-inside",
            ),
            (
                cls.authority_a,
                "198.18.1.11",
                "198.18.1.21",
                cls.latest - 20,
                cls.latest,
                "a-at-end",
            ),
            (
                cls.authority_a,
                "198.18.1.12",
                "198.18.1.22",
                cls.latest - 20,
                cls.earliest - 1,
                "a-before-start",
            ),
        ):
            row = copy.deepcopy(acl)
            row["time"] = poll
            raw = row["event"]
            raw = replace_tab(raw, "apic_host", authority)
            raw = replace_tab(raw, "actual_host", authority)
            raw = replace_tab(raw, "srcIp", src)
            raw = replace_tab(raw, "dstIp", dst)
            raw = replace_tab(
                raw,
                "timeStamp",
                iso_stamp(stamp),
            )
            raw = replace_tab(
                raw,
                "dn",
                f"topology/pod-1/node-101/ndbgs/acllog/tn-test/permitl3pkt-{record_id}",
            )
            row["event"] = raw
            row["source"] = cls.tag
            cls.events.append(row)
        flow = event_line(
            ROOT / "fixtures/raw/stream_netflow.ndjson",
            lambda row: isinstance(row["event"], dict),
        )
        flow = copy.deepcopy(flow)
        flow["time"] = cls.latest - 30
        flow["source"] = cls.tag
        flow["event"].update(
            exporter_ip=cls.exporter,
            src_ip="198.18.8.10",
            dest_ip="198.18.8.20",
            protoid=1,
            bytes=128,
            packets=2,
        )
        flow["event"].pop("src_port", None)
        flow["event"].pop("dest_port", None)
        cls.events.append(flow)
        for offset, byte_count, packets in ((1, 100, 10), (2, -20, 2)):
            counter = copy.deepcopy(flow)
            counter["time"] = cls.at + offset
            counter["event"].update(
                exporter_ip=cls.counter_exporter,
                protoid=6,
                src_port=51001,
                dest_port=443,
                bytes=byte_count,
                packets=packets,
            )
            cls.events.append(counter)
        firewall = event_line(
            ROOT / "fixtures/raw/ftd_estreamer.ndjson",
            lambda row: True,
        )
        event = json.loads(firewall["event"])
        event.update(DeviceIP=cls.firewall, FirstPacketSecond=cls.at)
        firewall.update(time=cls.at, source=cls.tag, event=json.dumps(event))
        cls.events.append(firewall)
        bad_time = event | {
            "FirstPacketSecond": cls.at + 1,
            "LastPacketSecond": "malformed",
        }
        cls.events.append(
            firewall | {"time": cls.at + 1, "event": json.dumps(bad_time)}
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "device-evidence.ndjson"
            path.write_text("\n".join(json.dumps(row) for row in cls.events) + "\n")
            lab.load([path])
        deadline = time.time() + 120
        while time.time() < deadline:
            count = lab.search(
                f'search (index=cisco_dc OR index=netflow OR index=cisco_secure_fw) source="{cls.tag}" | stats count',
                str(cls.earliest - 1),
                str(cls.latest + 300),
            )
            if int(count[0]["count"]) == len(cls.events):
                return
            time.sleep(2)
        raise AssertionError("device evidence fixtures did not become searchable")

    def test_aci_device_query_is_authority_qualified_and_window_bounded(self):
        a = lab.search(
            f"| `adm_device_flows({NODE},{self.authority_a},{self.earliest}.000000,{self.latest}.000000)`",
            str(self.earliest),
            str(self.latest),
        )
        b = lab.search(
            f"| `adm_device_flows({NODE},{self.authority_b},{self.earliest},{self.latest})`",
            str(self.earliest),
            str(self.latest),
        )
        self.assertEqual(
            {r["src"]: r["flows"] for r in a}, {"198.18.1.9": "1", "198.18.1.10": "1"}
        )
        self.assertEqual({r["src"] for r in b}, {"198.18.2.10"})

    def test_icmp_without_ports_is_retained(self):
        rows = lab.search(
            f"| `adm_device_flows({self.exporter})`",
            str(self.earliest),
            str(self.latest),
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["protocol"], "icmp")
        self.assertEqual(rows[0]["flows"], "1")
        self.assertNotIn("dest_port", rows[0])

    def test_device_withholds_mixed_invalid_byte_counters(self):
        (row,) = lab.search(
            f"| `adm_device_flows({self.counter_exporter})`",
            str(self.earliest),
            str(self.latest),
        )
        self.assertEqual(row["flows"], "2", row)
        self.assertEqual(row["packets"], "12", row)
        self.assertEqual(row["invalid_bytes"], "1", row)
        self.assertEqual(row["total_invalid_bytes"], "1", row)
        self.assertFalse(row.get("bytes"), row)
        self.assertFalse(row.get("total_bytes"), row)

    def test_scoped_ftd_keeps_valid_point_observations(self):
        from test_data_layer import DataLayerTest

        DataLayerTest.lab = lab
        DataLayerTest.wait_for_kvstore()
        mapping = {
            "_key": self.firewall_scope,
            "observer_kind": "firewall",
            "observer": self.firewall,
            "scope": self.firewall_scope,
            "mapping_status": "mapped",
            "valid_from": self.earliest - 1,
            "valid_end": self.latest + 1,
        }
        lab.search(
            "| makeresults format=json data="
            + json.dumps(json.dumps([mapping]))
            + " | fields - _time | outputlookup append=true key_field=_key adm_observer_scope"
        )
        try:
            for scope, count in ((self.firewall_scope, 1), (self.tag + "-other", 0)):
                with self.subTest(scope=scope):
                    observations = [
                        row
                        for row in lab.search(
                            f"| `adm_path_trace(198.51.100.8,203.0.113.10,{scope})`",
                            str(self.earliest),
                            str(self.latest),
                        )
                        if row.get("flow_source") == "ftd"
                    ]
                    self.assertEqual(len(observations), count, observations)
                    if observations:
                        (row,) = observations
                        self.assertEqual(row["records"], "1", row)
                        self.assertEqual(row["point_time_records"], "1", row)
                        self.assertEqual(row["first_seen"], str(self.at), row)
                        self.assertEqual(row["last_seen"], str(self.at), row)
        finally:
            path = (
                "/servicesNS/nobody/splunk_adm/storage/collections/data/"
                f"adm_observer_scope/{self.firewall_scope}"
            )
            with lab._mgmt("DELETE", path):
                pass
