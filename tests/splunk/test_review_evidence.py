"""Installed-search regressions for fabric isolation and unscoped ownership.

Mutated records retain the vendor-grounded ACI and Stream fixture shapes.
Only this run's KV keys are removed; indexed fixtures live in the disposable lab.
"""

from __future__ import annotations

import copy
import datetime
import json
import os
from pathlib import Path
import re
import tempfile
import time
import unittest
import uuid

import lab

ROOT = Path(__file__).resolve().parents[2]


def field(raw, key, value):
    return re.sub(
        rf"(?<=\t){re.escape(key)}=(?:\"[^\"]*\"|[^\t]*)",
        lambda _: f'{key}="{value}"',
        raw,
    )


@unittest.skipUnless(os.environ.get("ADM_LAB") == "1", "requires disposable lab")
class ReviewEvidenceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from test_data_layer import DataLayerTest

        DataLayerTest.lab = lab
        DataLayerTest.wait_for_kvstore()
        cls.tag = "review-" + uuid.uuid4().hex[:10]
        cls.at = int(time.time()) - 120
        cls.window = (str(cls.at - 1), str(cls.at + 1))
        cls.authorities = [cls.tag + "-a", cls.tag + "-b"]
        records = [
            json.loads(line)
            for line in (ROOT / "fixtures/raw-aci/aci_class.ndjson")
            .read_text()
            .splitlines()
        ]
        cls.events = []
        for authority, link_kind in zip(
            cls.authorities, ("fabricLink", "lldpAdjEp"), strict=True
        ):
            for node in (101, 201):
                original = next(
                    r
                    for r in records
                    if 'component="topSystem"' in r["event"]
                    and f'dn="topology/pod-1/node-{node}/sys"' in r["event"]
                )
                event = copy.deepcopy(original)
                event["event"] = field(
                    event["event"],
                    "name",
                    cls.tag + ("-leaf" if node == 101 else "-spine"),
                )
                cls.add_event(event, authority)
            original = next(
                r
                for r in records
                if f'component="{link_kind}"' in r["event"]
                and (
                    "n1=101\tn2=201" in r["event"]
                    if link_kind == "fabricLink"
                    else 'dn="topology/pod-1/node-101/sys/lldp/inst/if-[eth1/49]/adj-1"'
                    in r["event"]
                )
            )
            event = copy.deepcopy(original)
            event["event"] = field(event["event"], "sysName", cls.tag + "-spine")
            cls.add_event(event, authority)

        flow = json.loads(
            (ROOT / "fixtures/raw-vmware/vds_ipfix.ndjson").read_text().splitlines()[0]
        )
        cls.exporter = "192.0.2.248"
        cls.destination = "10.254.248.2"
        flow.update(time=cls.at, source=cls.tag)
        stamp = datetime.datetime.fromtimestamp(cls.at, datetime.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S.000000Z"
        )
        flow["event"].update(
            exporter_ip=cls.exporter,
            src_ip="10.254.248.1",
            dest_ip=cls.destination,
            timestamp=stamp,
            endtime=stamp,
        )
        cls.events.append(flow)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.ndjson"
            path.write_text("\n".join(json.dumps(e) for e in cls.events) + "\n")
            lab.load([path])
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            count = lab.search(
                f'search (index=cisco_dc OR index=netflow) source="{cls.tag}" | stats count',
                *cls.window,
            )
            if int(count[0]["count"]) == len(cls.events):
                break
            time.sleep(1)
        else:
            raise AssertionError("review fixtures did not become searchable")

    @classmethod
    def add_event(cls, event, authority):
        event.update(time=cls.at, source=cls.tag)
        for key in ("apic_host", "actual_host"):
            event["event"] = field(event["event"], key, authority)
        cls.events.append(event)

    def test_same_named_fabrics_keep_distinct_devices_and_native_links(self):
        rows = lab.search("`adm_topology`", *self.window)
        devices = {
            r["device_id"]: r
            for r in rows
            if r.get("row_type") == "device" and r.get("name", "").startswith(self.tag)
        }
        self.assertEqual(len(devices), 4)
        self.assertTrue(all(key.startswith("legacy-aci:") for key in devices))
        links = [
            r
            for r in rows
            if r.get("row_type") == "link" and r.get("a_device") in devices
        ]
        self.assertEqual(len(links), 2, links)
        for link in links:
            self.assertIn(link["b_device"], devices)
            self.assertEqual(
                devices[link["a_device"]]["fabric"],
                devices[link["b_device"]]["fabric"],
            )
        inventory = lab.search("| `adm_aci_node_inventory`", *self.window)
        self.assertEqual(
            {
                r["device_id"]
                for r in inventory
                if r.get("name", "").startswith(self.tag)
            },
            set(devices),
        )

    def test_foreign_and_expired_identity_never_label_device_conversations(self):
        key = self.tag + "-identity"
        path = f"/servicesNS/nobody/splunk_adm/storage/collections/data/adm_ip_identity/{key}"
        for kind in ("foreign_scope", "expired"):
            with self.subTest(kind=kind):
                identity = {
                    "_key": key,
                    "ip": self.destination,
                    "scope": self.tag
                    + ("-other" if kind == "foreign_scope" else "-local"),
                    "scope_mapping_verified": 1,
                    "entity_name": "unrelated-endpoint",
                    "service": "unrelated-app",
                    "entity_kind": "pod",
                    "entity_id": key,
                    "valid_from": self.at - 600,
                    "valid_end": self.at + 600
                    if kind == "foreign_scope"
                    else self.at - 100,
                }
                lab.search(
                    "| makeresults format=json data="
                    + json.dumps(json.dumps([identity]))
                    + " | fields - _time | outputlookup append=true key_field=_key adm_ip_identity"
                )
                try:
                    rows = lab.search(
                        f"| `adm_device_flows({self.exporter})`", *self.window
                    )
                    self.assertEqual(len(rows), 1, rows)
                    self.assertEqual(rows[0]["dst"], self.destination)
                    self.assertEqual(rows[0]["flows"], "1")
                    for label in ("src_name", "dst_name", "app"):
                        self.assertFalse(rows[0].get(label), (kind, label, rows[0]))
                finally:
                    with lab._mgmt("DELETE", path):
                        pass
