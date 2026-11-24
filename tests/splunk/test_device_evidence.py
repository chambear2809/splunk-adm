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
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "device-evidence.ndjson"
            path.write_text("\n".join(json.dumps(row) for row in cls.events) + "\n")
            lab.load([path])
        deadline = time.time() + 120
        while time.time() < deadline:
            count = lab.search(
                f'search (index=cisco_dc OR index=netflow) source="{cls.tag}" | stats count',
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
