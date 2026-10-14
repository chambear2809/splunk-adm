"""Exact flow endpoint ownership through real pod observations and KV lookups."""

import copy
import datetime
import json
import os
from pathlib import Path
import time
import unittest
import urllib.parse
import uuid

import lab


@unittest.skipUnless(os.environ.get("ADM_LAB") == "1", "set ADM_LAB=1")
class IdentityOwnershipTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from test_data_layer import DataLayerTest

        DataLayerTest.lab = lab
        DataLayerTest.wait_for_kvstore()
        cls.token = uuid.uuid4().hex[:12]
        cls.cluster = "ownership-" + cls.token
        cls.other_cluster = cls.cluster + "-other"
        cls.scope = "ownership-" + cls.token
        cls.other_scope = cls.scope + "-other"
        cls.source = "ownership-" + cls.token
        cls.start = int(time.time()) - 7200
        cls.loaded = 0
        path = (
            Path(__file__).resolve().parents[2] / "fixtures/raw/kube_object_pods.ndjson"
        )
        cls.template = next(
            e
            for line in path.read_text().splitlines()
            if (e := json.loads(line))["event"]["object"]["status"].get("podIP")
        )
        # Only append this class's isolated scopes; preserve every existing mapping.
        rows = [
            {"observer_kind": "cluster", "observer": cluster, "scope": scope}
            for cluster, scope in [
                (cls.cluster, cls.scope),
                (cls.other_cluster, cls.other_scope),
            ]
        ]
        cls.addClassCleanup(cls.cleanup)
        lab.search(
            f"| makeresults format=json data={json.dumps(json.dumps(rows))} "
            "| eval observer_kind=lower(observer_kind), observer=lower(observer), "
            "_key=sha256(json_array(observer_kind, observer)) "
            "| fields _key observer_kind observer scope cluster "
            "| outputlookup append=true key_field=_key adm_observer_scope"
        )

    @classmethod
    def cleanup(cls):
        # Remove only rows owned by this test run, including after a failed assertion.
        query = urllib.parse.urlencode(
            {"query": json.dumps({"scope": {"$in": [cls.scope, cls.other_scope]}})}
        )
        lab._mgmt(
            "DELETE",
            f"/servicesNS/nobody/{lab.APP}/storage/collections/data/adm_ip_identity?{query}",
        )
        lab._mgmt(
            "DELETE",
            f"/servicesNS/nobody/{lab.APP}/storage/collections/data/adm_observer_scope?{query}",
        ).close()

    def pod(self, uid, ip, at, *, born=None, deleted=False, cluster=None):
        event = copy.deepcopy(self.template)
        event.update(time=self.start + at, source=self.source)
        cluster = cluster or self.cluster
        event["fields"] = {"k8s.cluster.name": cluster}
        event["event"]["type"] = "DELETED" if deleted else "ADDED"
        obj = event["event"]["object"]
        stamp = datetime.datetime.fromtimestamp(
            self.start + (born if born is not None else at), datetime.timezone.utc
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
        obj["metadata"].update(
            uid=self.token + uid,
            name="same-pod-name",
            namespace="ownership",
            creationTimestamp=stamp,
        )
        obj["status"].update(
            phase="Running", podIP=ip, podIPs=[{"ip": ip}], startTime=stamp
        )
        return event

    def upload_and_build(self, events, window=(0, 2000)):
        lab._hec_post("\n".join(json.dumps(e) for e in events).encode())
        type(self).loaded += len(events)
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            count = lab.search(
                f'index=k8s source="{self.source}" | stats count', "0", "now"
            )
            if int(count[0]["count"]) == self.loaded:
                break
            time.sleep(1)
        else:
            self.fail("identity observations did not become searchable")
        self.build(*window)

    def build(self, first=0, last=2000):
        rows = lab.search(
            f'source="{self.source}" `adm_identity_build`',
            self.start + first,
            self.start + last,
        )
        self.assertEqual(len(rows), 1)
        self.assertFalse(rows[0].get("warnings"), rows)

    def identities(self, ip, scope=None):
        rows = lab.search(
            f'| inputlookup adm_ip_identity where ip="{ip}" '
            f'scope="{scope or self.scope}" entity_kind="pod" '
            "| table entity_id valid_from valid_to"
        )
        return {
            r["entity_id"]: (
                int(float(r["valid_from"])) - self.start,
                int(float(r["valid_to"])) - self.start if r.get("valid_to") else None,
            )
            for r in rows
        }

    def resolve(self, client, server, first, last, scope=None):
        row = {
            "adm_row": "conv",
            "client_ip": client,
            "server_ip": server,
            "server_port": 8080,
            "transport": "tcp",
            "scope": scope or self.scope,
            "adm_bfs": self.start + first,
            "adm_bls": self.start + last,
        }
        rows = lab.search(
            f"| makeresults format=json data={json.dumps(json.dumps([row]))} "
            f'| `adm_graph_resolve("frontend","demo","{self.cluster}","ownership")` '
            "| table adm_c_id adm_s_id adm_c_state adm_s_state"
        )
        self.assertEqual(len(rows), 1)
        return rows[0]

    def assert_owners(self, row, client, server, cluster=None):
        cluster = cluster or self.cluster
        self.assertEqual(row["adm_c_state"], "resolved")
        self.assertEqual(row["adm_s_state"], "resolved")
        self.assertEqual(row["adm_c_id"], f"pod:{cluster}/{self.token}{client}")
        self.assertEqual(row["adm_s_id"], f"pod:{cluster}/{self.token}{server}")

    def test_restart_same_name_reused_ips_resolve_both_sides_at_boundary(self):
        c, s = "10.99.71.1", "10.99.71.2"
        self.upload_and_build(
            [
                self.pod("client-old", c, 0),
                self.pod("server-old", s, 0),
                self.pod("client-new", c, 300),
                self.pod("server-new", s, 300),
            ]
        )
        for ip, side in [(c, "client"), (s, "server")]:
            self.assertEqual(
                self.identities(ip),
                {
                    self.token + side + "-old": (0, 300),
                    self.token + side + "-new": (300, None),
                },
            )
        self.assert_owners(self.resolve(c, s, 299, 299), "client-old", "server-old")
        self.assert_owners(self.resolve(c, s, 300, 301), "client-new", "server-new")
        spanning = self.resolve(c, s, 299, 300)
        for side, ip in [("c", c), ("s", s)]:
            self.assertEqual(spanning[f"adm_{side}_state"], "none")
            self.assertEqual(spanning[f"adm_{side}_id"], f"ip:{self.scope}/{ip}")

    def test_deleted_pod_gap_does_not_claim_flows(self):
        c, s = "10.99.72.1", "10.99.72.2"
        self.upload_and_build(
            [
                self.pod("gap-client", c, 0),
                self.pod("gap-old", s, 0),
                self.pod("gap-old", s, 100, born=0, deleted=True),
                self.pod("gap-new", s, 200),
            ]
        )
        self.assertEqual(
            self.identities(s),
            {self.token + "gap-old": (0, 100), self.token + "gap-new": (200, None)},
        )
        self.assert_owners(self.resolve(c, s, 99, 99), "gap-client", "gap-old")
        for at in (100, 150, 199):
            with self.subTest(at=at):
                row = self.resolve(c, s, at, at)
                self.assertEqual(
                    row["adm_c_id"], f"pod:{self.cluster}/{self.token}gap-client"
                )
                self.assertEqual(row["adm_s_state"], "none")
                self.assertEqual(row["adm_s_id"], f"ip:{self.scope}/{s}")
        self.assert_owners(self.resolve(c, s, 200, 201), "gap-client", "gap-new")

    def test_late_older_observation_and_replay_preserve_exact_owners(self):
        c, s = "10.99.73.1", "10.99.73.2"
        self.upload_and_build(
            [self.pod("late-client", c, 0), self.pod("late-new", s, 600)]
        )
        # The earlier owner arrives after the replacement has already been built.
        self.upload_and_build([self.pod("late-old", s, 100)], window=(100, 101))
        expected = {
            self.token + "late-old": (100, 600),
            self.token + "late-new": (600, None),
        }
        for replay in ("initial", "late-only", "full"):
            with self.subTest(replay=replay):
                if replay == "late-only":
                    self.build(100, 101)
                elif replay == "full":
                    self.build()
                self.assertEqual(self.identities(s), expected)
                self.assert_owners(
                    self.resolve(c, s, 599, 599), "late-client", "late-old"
                )
                self.assert_owners(
                    self.resolve(c, s, 600, 601), "late-client", "late-new"
                )

    def test_overlapping_addresses_are_isolated_by_network_scope(self):
        c, s = "10.99.74.1", "10.99.74.2"
        self.upload_and_build(
            [
                self.pod("scope-client", c, 0),
                self.pod("scope-server", s, 0),
                self.pod("other-client", c, 50, cluster=self.other_cluster),
                self.pod("other-server", s, 50, cluster=self.other_cluster),
            ]
        )
        self.assert_owners(self.resolve(c, s, 100, 101), "scope-client", "scope-server")
        self.assert_owners(
            self.resolve(c, s, 100, 101, self.other_scope),
            "other-client",
            "other-server",
            self.other_cluster,
        )
        self.assertEqual(self.identities(s), {self.token + "scope-server": (0, None)})
        self.assertEqual(
            self.identities(s, self.other_scope),
            {self.token + "other-server": (50, None)},
        )
