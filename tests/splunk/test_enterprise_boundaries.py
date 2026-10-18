"""Exercise production scope, NodePort and policy macros on an owned lab."""

import json
import os
import unittest
import uuid
from urllib.parse import quote

import lab


def results(rows):
    return "| makeresults format=json data=" + json.dumps(json.dumps(rows))


@unittest.skipUnless(os.environ.get("ADM_LAB") == "1", "set ADM_LAB=1")
class EnterpriseBoundariesTest(unittest.TestCase):
    def setUp(self):
        self.token = "boundary-" + uuid.uuid4().hex
        self.scope = self.token
        self.keys = []
        self.addCleanup(self.cleanup)

    def cleanup(self):
        for collection, key in reversed(self.keys):
            with lab._mgmt(
                "DELETE",
                "/servicesNS/nobody/splunk_adm/storage/collections/data/"
                + collection
                + "/"
                + quote(key, safe=""),
            ) as response:
                response.read()

    def seed(self, collection, rows):
        for index, row in enumerate(rows):
            row.setdefault("_key", self.token + "-" + str(len(self.keys) + index))
        self.keys.extend((collection, row["_key"]) for row in rows)
        lab.search(
            results(rows) + " | outputlookup append=true key_field=_key " + collection,
            "0",
            "now",
        )

    def identity(self, ip, kind, cluster, name, start=900, end=None, port=None):
        desc = {
            "ip": ip,
            "sc": self.scope,
            "vf": start,
            "ve": end,
            "fs": start,
            "ls": start,
            "p": 0 if port else 2,
            "kind": kind,
            "id": name,
            "name": name,
            "cluster": cluster,
            "ns": "boundary",
            "ek": kind + ":" + cluster + "/" + name,
            "source": "k8s_services" if port else "k8s_nodes",
            "port": port,
            "tp": "tcp",
        }
        return {
            "ip": ip,
            "scope": self.scope,
            "entity_kind": kind,
            "cluster": cluster,
            "namespace": "boundary",
            "desc": json.dumps(desc),
        }

    def test_unmapped_observers_cannot_borrow_default_or_other_authority(self):
        isolated = lab.search(
            results([{"kind": "cluster", "observer": self.token}])
            + " | eval scope=`adm_unmapped_scope(kind, observer)` | table scope"
        )[0]["scope"]
        for scope in ("default", isolated):
            rows = [
                self.identity(ip, "pod", self.token, name)
                for ip, name in (("10.253.1.1", "client"), ("10.253.1.2", "server"))
            ]
            for row in rows:
                row["scope"] = scope
            self.seed("adm_ip_identity", rows)
        flow = {
            "adm_source": "netflow",
            "adm_scope_kind": "exporter",
            "adm_scope_observer": "192.0.2.243",
            "adm_observer": "192.0.2.243",
            "adm_src_ip": "10.253.1.1",
            "adm_dest_ip": "10.253.1.2",
            "adm_start": 1000,
            "adm_end": 1010,
            "adm_transport": "tcp",
            "adm_src_port": 50000,
            "adm_dest_port": 443,
        }
        rows = lab.search(
            results([flow])
            + " | `adm_flow_enrich`"
            + " | eval scope=adm_scope, client_ip=adm_src_ip, server_ip=adm_dest_ip,"
            + ' server_port=443, transport="tcp", adm_row="conv",'
            + " adm_bfs=1000, adm_bls=1010, adm_ws=1000, adm_we=1100"
            + f' | `adm_graph_resolve("svc", "prod", "{self.token}", "boundary")`'
            + " | table adm_scope_unmapped adm_scope adm_c_state adm_s_state adm_keep"
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["adm_scope_unmapped"], "1")
        self.assertNotIn(rows[0]["adm_scope"], ("default", isolated))
        self.assertEqual(rows[0]["adm_c_state"], "none")
        self.assertEqual(rows[0]["adm_s_state"], "none")
        self.assertEqual(rows[0]["adm_keep"], "0")

    def test_nodeport_uses_one_temporally_covering_node(self):
        self.seed(
            "adm_ip_identity",
            [
                self.identity(
                    "10.253.2.1", "k8s_node", "old-cluster", "old-node", end=1000
                ),
                self.identity(
                    "10.253.2.1", "k8s_node", "new-cluster", "new-node", start=1000
                ),
                self.identity(
                    "nodeport:old-cluster:30443/tcp",
                    "k8s_service",
                    "old-cluster",
                    "old-service",
                    port=30443,
                ),
                self.identity(
                    "nodeport:new-cluster:30443/tcp",
                    "k8s_service",
                    "new-cluster",
                    "new-service",
                    port=30443,
                ),
            ],
        )
        rows = lab.search(
            results(
                [
                    {
                        "scope": self.scope,
                        "server_ip": "10.253.2.1",
                        "server_port": 30443,
                        "transport": "tcp",
                        "adm_row": "conv",
                        "adm_bfs": 1100,
                        "adm_bls": 1110,
                        "adm_ws": 1100,
                        "adm_we": 1200,
                    }
                ]
            )
            + ' | `adm_graph_resolve("svc", "prod", "new-cluster", "boundary")`'
            + " | table adm_np_cl adm_s_np_node adm_s_name adm_s_kind"
        )
        self.assertEqual(rows[0]["adm_np_cl"], "new-cluster")
        self.assertEqual(rows[0]["adm_s_np_node"], "new-node")
        self.assertEqual(rows[0]["adm_s_name"], "new-service")
        self.assertEqual(rows[0]["adm_s_kind"], "k8s_service")

    def test_legacy_default_summary_requires_mapping_provenance(self):
        rows = lab.search(
            results(
                [
                    {"rollup_id": "old", "scope": "default"},
                    {
                        "rollup_id": "new",
                        "scope": "default",
                        "scope_mapping_verified": 1,
                    },
                    {"rollup_id": "mapped", "scope": self.scope},
                ]
            )
            + " | `adm_summary_dedup` | table rollup_id scope"
        )
        scopes = {row["rollup_id"]: row["scope"] for row in rows}
        self.assertEqual(scopes["old"], "unmapped:legacy-default")
        self.assertEqual(scopes["new"], "default")
        self.assertEqual(scopes["mapped"], self.scope)

    def policy(self, controller, scope, port, last=1500):
        self.seed(
            "adm_observer_scope",
            [
                {
                    "observer_kind": "apic",
                    "observer": controller,
                    "scope": scope,
                }
            ],
        )
        prefix = "uni/tn-" + self.token
        contract, filt = prefix + "/brc-web", prefix + "/flt-web"
        rows = [
            {
                "object_kind": "cons",
                "class_dn": prefix + "/ap-app/epg-client",
                "contract_dn": contract,
            },
            {
                "object_kind": "prov",
                "class_dn": prefix + "/ap-app/epg-server",
                "contract_dn": contract,
            },
            {
                "object_kind": "filtatt",
                "contract_dn": contract,
                "subject": "web",
                "filter_dn": filt,
                "action": "permit",
            },
            {
                "object_kind": "entry",
                "filter_dn": filt,
                "prot": "tcp",
                "d_from": str(port),
                "d_to": str(port),
                "ether_t": "ip",
            },
            {"object_kind": "contract", "dn": contract, "contract_scope": "tenant"},
        ]
        for index, row in enumerate(rows):
            row.update(
                apic_host=controller, first_seen=900, last_seen=last, tenant=self.token
            )
            if row["object_kind"] == "filtatt":
                row["action_verified"] = 1
            row.setdefault("dn", prefix + "/object-" + str(index))
        self.seed("adm_aci_policy", rows)

    def evaluate_policy(self):
        prefix = "uni/tn-" + self.token + "/ap-app/epg-"
        row = {
            "id": self.token,
            "adm_row": "edge",
            "relationship": "communicates_with",
            "transport": "tcp",
            "server_port": 443,
            "adm_c_aciepg": prefix + "client",
            "adm_s_aciepg": prefix + "server",
            "adm_src_node": json.dumps(
                {
                    "kind": "endpoint",
                    "endpoint_kind": "vm",
                    "addr": "10.253.1.1",
                    "attr_scope": self.scope,
                }
            ),
            "adm_dst_node": json.dumps(
                {
                    "kind": "endpoint",
                    "endpoint_kind": "vm",
                    "addr": "10.253.1.2",
                    "attr_scope": self.scope,
                }
            ),
        }
        return lab.search(
            results([row])
            + f' | `adm_graph_contracts("svc", "prod", "{self.token}", "boundary")`'
            + " | table contract_basis contract",
            "1000",
            "2000",
        )[0]

    def test_policy_isolated_between_mapped_controllers(self):
        self.policy(self.token + "-a", self.scope, 80)
        self.policy(self.token + "-b", self.scope + "-other", 443)
        self.assertNotEqual(self.evaluate_policy().get("contract_basis"), "intent")

    def test_multiple_controllers_in_one_scope_refuse_policy_inference(self):
        self.policy(self.token + "-a", self.scope, 80)
        self.policy(self.token + "-b", self.scope, 443)
        self.assertEqual(self.evaluate_policy()["contract_basis"], "not_evaluated")

    def test_future_policy_cannot_change_historical_graph(self):
        self.policy(self.token + "-a", self.scope, 443, last=2500)
        self.assertEqual(self.evaluate_policy()["contract_basis"], "not_evaluated")

    def test_one_mapped_contemporaneous_controller_still_evaluates(self):
        self.policy(self.token + "-a", self.scope, 443)
        self.assertEqual(self.evaluate_policy()["contract_basis"], "intent")
