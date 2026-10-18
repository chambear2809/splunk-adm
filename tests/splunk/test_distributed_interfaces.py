"""Opt-in interface lookup regression on a prepared disposable distributed lab.

The external client module supplies task-owned STATE, Api(role).json(...) and search(...), returning
(rows, job evidence), with credential/TLS handling outside this repository. No
lab is provisioned or reset. The lab must have three members, a remote peer,
empty adm_interfaces, and fixtures/raw-aci NetFlow events already indexed.
"""

import importlib
import os
import time
import unittest
import uuid


ENABLED = os.environ.get("ADM_SHC_QUALIFICATION") == "1"
COLLECTION = "/servicesNS/nobody/splunk_adm/storage/collections/data/adm_interfaces"
QUERY = (
    "search `adm_flows_netflow` "
    '| where adm_exporter="192.0.2.101" AND adm_in_ifindex=436248576 '
    "| `adm_flow_enrich` | stats count values(adm_in_if) AS interfaces"
)


@unittest.skipUnless(ENABLED, "requires a prepared disposable distributed SHC lab")
class DistributedInterfacesTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.client = importlib.import_module(os.environ["ADM_SHC_CLIENT_MODULE"])
        cls.window = (os.environ["ADM_SHC_EARLIEST"], os.environ["ADM_SHC_LATEST"])
        task = cls.client.STATE.get("task", "")
        if not task.startswith("adm-shc-"):
            raise AssertionError(
                "client must identify a task-owned SHC qualification lab"
            )
        for role in ("sh1", "sh2", "sh3"):
            expected = cls.client.STATE["created"][role]["name"]
            server = cls.client.Api(role).json("GET", "/services/server/info")["entry"][
                0
            ]["content"]
            if (
                not expected.startswith(task + "-sh")
                or server.get("serverName") != expected
            ):
                raise AssertionError(
                    "member is not the identified qualification instance"
                )
            peers = cls.client.Api(role).json(
                "GET", "/services/search/distributed/peers?count=0"
            )["entry"]
            if not peers or not all(
                p["content"].get("status") == "Up" and task + "-idx" in p["name"]
                for p in peers
            ):
                raise AssertionError(
                    "qualification requires healthy remote search peers"
                )
        cls.jobs = []

    def check_labels(self, label):
        for role in ("sh1", "sh2", "sh3"):
            with self.subTest(member=role):
                rows, evidence = self.client.Api(role).search(QUERY, *self.window)
                self.jobs.append({"member": role, **evidence})
                self.assertEqual(len(rows), 1)
                self.assertGreater(int(rows[0]["count"]), 0)
                labels = rows[0].get("interfaces", [])
                labels = [labels] if isinstance(labels, str) else labels
                self.assertEqual(labels, [label])

    def test_01_empty_inventory_keeps_ifindex_fallback(self):
        for role in ("sh1", "sh2", "sh3"):
            self.assertEqual(
                self.client.Api(role).json("GET", COLLECTION + "?limit=1"),
                [],
                "empty-inventory case requires an empty disposable inventory",
            )
        self.check_labels("ifIndex 436248576")

    def test_02_populated_inventory_resolves_interface_name(self):
        import json

        key = "adm-shc-interface-" + uuid.uuid4().hex
        label = "qualification-" + key
        self.addCleanup(self.remove_probe, key)
        self.client.Api("sh1").json(
            "POST",
            COLLECTION + "/batch_save",
            raw=json.dumps(
                [
                    {
                        "_key": key,
                        "device_ip": "192.0.2.101",
                        "ifindex": "436248576",
                        "interface": label,
                    }
                ]
            ).encode(),
        )
        deadline = time.monotonic() + 60
        while True:
            try:
                ready = all(
                    self.client.Api(role)
                    .json("GET", COLLECTION + "/" + key)
                    .get("interface")
                    == label
                    for role in ("sh1", "sh2", "sh3")
                )
            except Exception as error:
                if getattr(error, "status", None) != 404:
                    raise
                ready = False
            if ready:
                break
            if time.monotonic() > deadline:
                self.fail("interface probe did not converge")
            time.sleep(1)
        self.check_labels(label)

    def remove_probe(self, key):
        for role in ("sh1", "sh2", "sh3"):
            try:
                self.client.Api(role).json("DELETE", COLLECTION + "/" + key)
            except Exception as error:
                if getattr(error, "status", None) != 404:
                    raise
