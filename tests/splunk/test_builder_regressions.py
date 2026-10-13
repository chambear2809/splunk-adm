"""Builder regressions against the disposable Splunk lab; no fixture reset needed."""

import json
import os
import time
import unittest
import uuid

import lab


@unittest.skipUnless(os.environ.get("ADM_LAB") == "1", "set ADM_LAB=1")
class BuilderRegressions(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.token = uuid.uuid4().hex[:10]
        cls.cluster = "builder-" + cls.token
        cls.start = int(time.time()) - 3600
        cls.source = "builder-regression-" + cls.token
        cls.loaded = 0

    def upload(self, bodies, sourcetype):
        events = [
            {
                "time": self.start + offset,
                "source": self.source,
                "host": "regression-node",
                "index": "k8s" if sourcetype.startswith("kube:") else "cisco_dc",
                "sourcetype": sourcetype,
                "fields": {"k8s.cluster.name": self.cluster},
                "event": body,
            }
            for offset, body in bodies
        ]
        lab._hec_post("\n".join(json.dumps(e) for e in events).encode())
        type(self).loaded += len(events)
        for _ in range(60):
            rows = lab.search(
                f'index=* source="{self.source}" | stats count', "0", "now"
            )
            if int(rows[0]["count"]) == self.loaded:
                return
            time.sleep(1)
        self.fail("regression events were not indexed")

    def build(self, start=0, end=1000):
        return lab.search(
            "`adm_k8s_service_build`", self.start + start, self.start + end
        )

    def backend(self, name, ready):
        return {
            "type": "MODIFIED",
            "object": {
                "metadata": {
                    "uid": self.token + name,
                    "name": name,
                    "namespace": "regression",
                    "labels": {"kubernetes.io/service-name": name},
                },
                "ports": [{"name": "http", "port": 8080, "protocol": "TCP"}],
                "endpoints": [
                    {
                        "addresses": ["10.99.1.2"],
                        "conditions": {"ready": ready},
                        "nodeName": "regression-node",
                        "targetRef": {"kind": "Pod", "uid": name, "name": name},
                    }
                ],
            },
        }

    def intervals(self, name):
        rows = lab.search(
            f'| inputlookup adm_service_backends where cluster="{self.cluster}" '
            f'service="{name}" | sort 0 valid_from | table valid_from valid_to'
        )
        return [
            (
                int(float(r["valid_from"])) - self.start,
                int(float(r["valid_to"])) - self.start if "valid_to" in r else None,
            )
            for r in rows
        ]

    def test_readiness_gap_in_one_batch_and_replay(self):
        self.upload(
            [
                (n, self.backend("batch", ready))
                for n, ready in [(0, True), (60, False), (120, True)]
            ],
            "kube:object:endpointslices",
        )
        self.build()
        self.assertEqual(self.intervals("batch"), [(0, 60), (120, None)])
        self.build()
        self.assertEqual(self.intervals("batch"), [(0, 60), (120, None)])

    def test_stored_interval_closes_before_reappearance_in_one_batch(self):
        self.upload([(200, self.backend("stored", True))], "kube:object:endpointslices")
        self.build(200, 201)
        self.upload(
            [(260, self.backend("stored", False)), (320, self.backend("stored", True))],
            "kube:object:endpointslices",
        )
        self.build(250, 330)
        self.assertEqual(self.intervals("stored"), [(200, 260), (320, None)])
        self.build(200, 330)
        self.assertEqual(self.intervals("stored"), [(200, 260), (320, None)])

    def test_indexed_late_batch_preserves_existing_interval_boundaries(self):
        self.upload(
            [
                (700, self.backend("late", True)),
                (760, self.backend("late", False)),
                (820, self.backend("late", True)),
            ],
            "kube:object:endpointslices",
        )
        self.build(700, 821)
        self.assertEqual(self.intervals("late"), [(700, 760), (820, None)])
        time.sleep(2)
        indexed_after = int(time.time())
        self.upload(
            [
                (730, self.backend("late", True)),
                (790, self.backend("late", False)),
                (850, self.backend("late", True)),
            ],
            "kube:object:endpointslices",
        )
        lab.search(
            f"_index_earliest={indexed_after} `adm_k8s_service_build`",
            self.start + 700,
            self.start + 851,
        )
        self.assertEqual(self.intervals("late"), [(700, 760), (820, None)])

    def test_late_gap_splits_open_history_and_preserves_later_observation(self):
        for name, later_ready in [("late-gap", True), ("late-absence", False)]:
            with self.subTest(name=name):
                self.upload(
                    [
                        (1100, self.backend(name, True)),
                        (1300, self.backend(name, True)),
                    ],
                    "kube:object:endpointslices",
                )
                self.build(1100, 1301)
                time.sleep(2)
                indexed_after = int(time.time())
                events = [(1160, self.backend(name, False))]
                if later_ready:
                    events.append((1220, self.backend(name, True)))
                self.upload(events, "kube:object:endpointslices")
                query = f"_index_earliest={indexed_after} `adm_k8s_service_build`"
                lab.search(query, self.start + 1100, self.start + 1301)
                expected = [(1100, 1160), (1220 if later_ready else 1300, None)]
                self.assertEqual(self.intervals(name), expected)
                lab.search(query, self.start + 1100, self.start + 1301)
                self.assertEqual(self.intervals(name), expected)
                if not later_ready:
                    time.sleep(2)
                    indexed_after = int(time.time())
                    self.upload(
                        [(1220, self.backend(name, True))], "kube:object:endpointslices"
                    )
                    query = f"_index_earliest={indexed_after} `adm_k8s_service_build`"
                    lab.search(query, self.start + 1100, self.start + 1301)
                    self.assertEqual(self.intervals(name), [(1100, 1160), (1220, None)])
                    lab.search(query, self.start + 1100, self.start + 1301)
                    self.assertEqual(self.intervals(name), [(1100, 1160), (1220, None)])
                    time.sleep(2)
                    indexed_after = int(time.time())
                    self.upload(
                        [(1260, self.backend(name, False))],
                        "kube:object:endpointslices",
                    )
                    query = f"_index_earliest={indexed_after} `adm_k8s_service_build`"
                    lab.search(query, self.start + 1100, self.start + 1301)
                    expected = [(1100, 1160), (1220, 1260), (1300, None)]
                    self.assertEqual(self.intervals(name), expected)
                    lab.search(query, self.start + 1100, self.start + 1301)
                    self.assertEqual(self.intervals(name), expected)

    def test_unchanged_snapshots_merge_and_deletion_closes(self):
        deleted = self.backend("deleted", True)
        deleted["type"] = "DELETED"
        self.upload(
            [
                (600, self.backend("deleted", True)),
                (620, self.backend("deleted", True)),
                (650, deleted),
            ],
            "kube:object:endpointslices",
        )
        self.build(600, 651)
        self.assertEqual(self.intervals("deleted"), [(600, 650)])
        self.build(600, 651)
        self.assertEqual(self.intervals("deleted"), [(600, 650)])

    def test_named_ingress_port_is_retained(self):
        events = []
        for name, port in [("named", {"name": "http"}), ("numeric", {"number": 8080})]:
            events.append(
                (
                    400,
                    {
                        "type": "ADDED",
                        "object": {
                            "metadata": {
                                "uid": self.token + name,
                                "name": name,
                                "namespace": "regression",
                            },
                            "spec": {
                                "rules": [
                                    {
                                        "host": "regression.example",
                                        "http": {
                                            "paths": [
                                                {
                                                    "path": "/",
                                                    "pathType": "Prefix",
                                                    "backend": {
                                                        "service": {
                                                            "name": "app",
                                                            "port": port,
                                                        }
                                                    },
                                                }
                                            ]
                                        },
                                    }
                                ]
                            },
                        },
                    },
                )
            )
        self.upload(events, "kube:object:ingresses")
        self.build(400, 401)
        rows = {
            r["route_name"]: r
            for r in lab.search(
                f'| inputlookup adm_service_routes where cluster="{self.cluster}" '
                "| table route_name backend_port backend_port_name"
            )
        }
        self.assertEqual(rows["named"]["backend_port_name"], "http")
        self.assertEqual(rows["numeric"]["backend_port"], "8080")
        self.assertNotIn("backend_port", rows["named"])

    def test_apic_identity_aggregation_keeps_fabrics_separate(self):
        scope_rows = [
            {
                "observer_kind": "apic",
                "observer": "regression-apic-a",
                "scope": "regression-a",
                "cluster": "",
            },
            {
                "observer_kind": "apic",
                "observer": "regression-apic-b",
                "scope": "regression-b",
                "cluster": "",
            },
        ]
        data = json.dumps(json.dumps(scope_rows))
        lab.search(
            f"| inputlookup adm_observer_scope.csv | append [| makeresults format=json data={data}] | dedup observer_kind observer | fields - _time | outputlookup adm_observer_scope.csv"
        )
        dn = f"uni/tn-{self.token}/ap-app/epg-app/cep-AA:BB:CC:DD:EE:FF"
        self.upload(
            [
                (
                    500,
                    f'component="fvCEp" apic_host="regression-apic-a" dn="{dn}" ip="10.99.2.1" mac="AA:BB:CC:DD:EE:FF"',
                ),
                (
                    510,
                    f'component="fvCEp" apic_host="regression-apic-b" dn="{dn}" ip="10.99.3.1" mac="AA:BB:CC:DD:EE:FF"',
                ),
            ],
            "cisco:dc:aci:class",
        )
        rows = lab.search(
            f'`adm_identity_observations` | search entity_id="{dn}" | table ip scope',
            self.start + 500,
            self.start + 511,
        )
        self.assertEqual(
            {(r["ip"], r["scope"]) for r in rows},
            {("10.99.2.1", "regression-a"), ("10.99.3.1", "regression-b")},
        )
