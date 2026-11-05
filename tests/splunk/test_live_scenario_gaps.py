"""Splunk lab regressions for the 2026-11-04 live scenario gaps (docs/operators/LIVE_SCENARIOS.md).

Skipped unless ADM_LAB=1 with the lab running (`tests/splunk/lab.sh up && install`).
Events are built from the generated raw fixtures (fixtures/raw-aci, fixtures/raw) so
field names and formats stay grounded in the TA and collector definitions:

- ACI ACL log: the DC Networking `cisco:dc:aci:class` acllogDropL3Pkt record shape
  (tab-separated key=value with the record DN embedding its timeStamp). A record stays
  in the leaf buffer and is re-reported by every 5-minute APIC poll.
- Stream NetFlow: `stream:netflow` JSON records, one per direction.
- Hubble: Cilium flow.proto JSON lines (`flow.verdict` DROPPED with `drop_reason` and
  `drop_reason_desc`, `event_type.type` 1 for drop notifications).
- Kubernetes: OTel k8sobjects watch events `{"object": ..., "type": ...}` whose object
  is longer than the automatic JSON extraction limit (limits.conf [kv] maxchars 10240),
  as for the live teastore pods with injected instrumentation, plus Atlas point
  snapshots (adm:k8s_pod_node_snapshot:v1, see tools/qualify_k8s_snapshot.py).

Every address, cluster, scope and source is unique to this run.
"""

from __future__ import annotations

import copy
import datetime
import json
import os
import time
import unittest
import urllib.parse
import uuid
from pathlib import Path

import lab

ROOT = Path(__file__).resolve().parents[2]


def iso(epoch: float, ms: bool = False) -> str:
    d = datetime.datetime.fromtimestamp(epoch, datetime.timezone.utc)
    return (
        d.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "+00:00"
        if ms
        else d.strftime("%Y-%m-%dT%H:%M:%SZ")
    )


def first_line(path: Path, predicate) -> dict:
    return next(
        e for line in path.read_text().splitlines() if predicate(e := json.loads(line))
    )


def multi(value) -> list[str]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


@unittest.skipUnless(os.environ.get("ADM_LAB") == "1", "set ADM_LAB=1")
class LiveScenarioGapsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from test_data_layer import DataLayerTest

        DataLayerTest.lab = lab
        DataLayerTest.wait_for_kvstore()
        cls.token = uuid.uuid4().hex[:10]
        cls.source = "gaps-" + cls.token
        cls.cluster = "gaps-" + cls.token
        cls.scope = "gaps-" + cls.token
        cls.start = int(time.time()) - 5400
        n = int(cls.token[:4], 16) % 200 + 20
        # Distinct per run so earlier runs cannot add records.
        cls.src, cls.dst = f"10.77.{n}.3", f"10.77.{n}.2"
        cls.pod_a, cls.pod_b = f"10.78.{n}.10", f"10.78.{n}.20"
        cls.node_a, cls.node_b = f"gaps-node-a-{cls.token}", f"gaps-node-b-{cls.token}"
        cls.leaf = f"node-{1100 + n}"
        cls.loaded = 0
        cls.addClassCleanup(cls.cleanup)
        rows = [
            {"observer_kind": "cluster", "observer": cls.cluster, "scope": cls.scope}
        ]
        lab.search(
            f"| makeresults format=json data={json.dumps(json.dumps(rows))} "
            "| eval observer_kind=lower(observer_kind), observer=lower(observer), "
            "_key=sha256(json_array(observer_kind, observer)) "
            "| fields _key observer_kind observer scope cluster "
            "| outputlookup append=true key_field=_key adm_observer_scope"
        )
        cls.templates = {
            "netflow": first_line(
                ROOT / "fixtures/raw-aci/stream_netflow.ndjson", lambda e: True
            ),
            "acl": first_line(
                ROOT / "fixtures/raw-aci/aci_class.ndjson",
                lambda e: "acllogDropL3Pkt" in e["event"],
            ),
            "hubble": first_line(
                ROOT / "fixtures/raw-aci/hubble_flows.ndjson",
                lambda e: '"Type":"L3_L4"' in e["event"],
            ),
            "pod": first_line(
                ROOT / "fixtures/raw/kube_object_pods.ndjson",
                lambda e: e["event"]["object"]["status"].get("podIP"),
            ),
        }
        cls.send(cls.flow_events() + cls.k8s_events())
        cls.build(0, 3000)
        cls.send(cls.snapshot_events())
        cls.build(3000, 4000)

    @classmethod
    def cleanup(cls):
        query = urllib.parse.urlencode({"query": json.dumps({"scope": cls.scope})})
        for collection in ("adm_ip_identity", "adm_observer_scope"):
            lab._mgmt(
                "DELETE",
                f"/servicesNS/nobody/{lab.APP}/storage/collections/data/{collection}?{query}",
            ).close()

    @classmethod
    def send(cls, events):
        for e in events:
            e["source"] = cls.source
        lab._hec_post("\n".join(json.dumps(e) for e in events).encode())
        cls.loaded += len(events)
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            got = lab.search(f'index=* source="{cls.source}" | stats count', "0", "now")
            if int(got[0]["count"]) >= cls.loaded:
                return
            time.sleep(1)
        raise AssertionError("events did not become searchable")

    @classmethod
    def build(cls, first, last):
        rows = lab.search("| `adm_identity_build`", cls.start + first, cls.start + last)
        assert len(rows) == 1, rows

    # ---- events -------------------------------------------------------------

    @classmethod
    def netflow(cls, at, src, dst, sport, dport):
        e = copy.deepcopy(cls.templates["netflow"])
        t = cls.start + at
        e["time"] = t
        e["event"].update(
            timestamp=iso(t - 1).replace("Z", ".000000Z"),
            endtime=iso(t).replace("Z", ".000000Z"),
            exporter_ip="192.0.2.199",
            src_ip=src,
            dest_ip=dst,
            src_port=sport,
            dest_port=dport,
            protoid=6,
        )
        return e

    @classmethod
    def acl(cls, record_at, polled_at, sport, dport, seq):
        e = copy.deepcopy(cls.templates["acl"])
        rec, poll = cls.start + record_at, cls.start + polled_at
        stamp = iso(rec, ms=True)
        fields = dict(
            part.split("=", 1) for part in e["event"].split("\t")[1:] if "=" in part
        )
        fields.update(
            dn=f'"topology/pod-1/{cls.leaf}/ndbgs/acllog/tn-shop/ctx-prod/dropl3pkt-{seq}-smac-00:50:56:AA:40:25-dmac-00:22:BD:F8:19:FF-time-{stamp}"',
            srcIp=cls.src,
            dstIp=cls.dst,
            srcPort=str(sport),
            dstPort=str(dport),
            timeStamp=f'"{stamp}"',
            modTs=f'"{stamp}"',
            recordId=str(seq),
        )
        head = datetime.datetime.fromtimestamp(poll, datetime.timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        e["time"] = poll
        e["event"] = "\t".join([head] + [f"{k}={v}" for k, v in fields.items()])
        return e

    @classmethod
    def hubble(cls, at, verdict, node, sport, dport, reply=False):
        e = copy.deepcopy(cls.templates["hubble"])
        flow = json.loads(e["event"])
        t = cls.start + at
        f = flow["flow"]
        f.update(
            time=iso(t).replace("Z", ".000Z"),
            verdict=verdict,
            IP={"source": cls.pod_a, "destination": cls.pod_b, "ipVersion": "IPv4"},
            l4={"TCP": {"source_port": sport, "destination_port": dport}},
            node_name=f"{cls.cluster}/{node}",
            is_reply=reply,
            source={"namespace": "shop", "pod_name": "web-1"},
            destination={"namespace": "shop", "pod_name": "api-1"},
        )
        if verdict == "DROPPED":
            f.update(
                drop_reason=133,
                drop_reason_desc="POLICY_DENIED",
                event_type={"type": 1, "sub_type": 133},
            )
            f.pop("trace_observation_point", None)
        flow["node_name"] = f"{cls.cluster}/{node}"
        flow["time"] = f["time"]
        e["time"] = t
        e["host"] = node
        e["event"] = json.dumps(flow)
        e["fields"] = {"k8s.node.name": node, "k8s.cluster.name": cls.cluster}
        return e

    @classmethod
    def flow_events(cls):
        s, d = cls.src, cls.dst
        out = []
        # Service ports 47001/47003; client ports above and below them.
        for i, (sport, dport) in enumerate(
            [(47110, 47001), (47111, 47003), (41682, 47003)]
        ):
            out.append(cls.netflow(1000 + i, s, d, sport, dport))
            out.append(cls.netflow(1000 + i, d, s, dport, sport))
        # One drop record re-reported by three polls; one buffered month-old record.
        out += [cls.acl(1200, 1200 + p, 47111, 47003, 7) for p in (40, 340, 640)]
        out.append(cls.acl(1200 - 30 * 86400, 1240, 47112, 47003, 3))
        out += [
            cls.hubble(1300, "DROPPED", cls.node_b, 41000, 8080),
            cls.hubble(1301, "DROPPED", cls.node_b, 41002, 8080),
            cls.hubble(1302, "FORWARDED", cls.node_b, 41004, 9090),
        ]
        return out

    @classmethod
    def pod(cls, at, uid, name, ip, kind, node, large=False):
        e = copy.deepcopy(cls.templates["pod"])
        t = cls.start + at
        obj = e["event"]["object"]
        obj["metadata"].update(
            uid=f"{cls.token}-{uid}",
            name=f"{name}-{cls.token}",
            namespace="gaps",
            creationTimestamp=iso(cls.start + 100),
        )
        obj["metadata"].pop("ownerReferences", None)
        obj["spec"]["nodeName"] = node
        obj["status"].update(phase="Running", startTime=iso(cls.start + 100))
        # No hostIP: the builder would otherwise add node identities for it.
        for k in ("hostIP", "hostIPs"):
            obj["status"].pop(k, None)
        if ip:
            obj["status"].update(podIP=ip, podIPs=[{"ip": ip}])
        else:
            for k in ("podIP", "podIPs"):
                obj["status"].pop(k, None)
        if large:
            # Injected init containers push status and type past 10240 characters.
            obj["spec"]["initContainers"] = [
                {
                    "name": f"opentelemetry-auto-instrumentation-{i}",
                    "image": "ghcr.io/open-telemetry/autoinstrumentation-java:2.10.0",
                    "env": [
                        {"name": f"OTEL_VAR_{i}_{j}", "value": "x" * 40}
                        for j in range(40)
                    ],
                }
                for i in range(4)
            ]
        e["time"] = t
        e["fields"] = {"k8s.cluster.name": cls.cluster}
        e["event"] = {"object": obj, "type": kind}
        return e

    @classmethod
    def k8s_events(cls):
        ip = lambda last: cls.pod_a.rsplit(".", 1)[0] + f".{last}"  # noqa: E731
        cls.web_ip, cls.auth_ip, cls.gone_ip = ip(159), ip(190), ip(77)
        events = [
            # Running pod first seen in watch events; its IP arrives in a large MODIFIED.
            cls.pod(200, "web", "teastore-webui", None, "ADDED", cls.node_a),
            cls.pod(
                260, "web", "teastore-webui", cls.web_ip, "MODIFIED", cls.node_a, True
            ),
            # Deleted pod: large ADDED and large DELETED.
            cls.pod(
                200, "auth", "teastore-auth", cls.auth_ip, "ADDED", cls.node_a, True
            ),
            cls.pod(
                900, "auth", "teastore-auth", cls.auth_ip, "DELETED", cls.node_a, True
            ),
            # Pod later absent from a complete snapshot.
            cls.pod(200, "gone", "gone", cls.gone_ip, "ADDED", cls.node_b),
            # Pair pods for the trace.
            cls.pod(200, "pa", "web-1", cls.pod_a, "ADDED", cls.node_a),
            cls.pod(200, "pb", "api-1", cls.pod_b, "ADDED", cls.node_b),
        ]
        cls.large = len(json.dumps(events[1]["event"]))
        return events

    @classmethod
    def snapshot(cls, at, present, expected):
        gen = str(uuid.uuid4())
        t = cls.start + at
        common = {
            "cluster": cls.cluster,
            "generation_id": gen,
            "namespace_scope": "all",
            "observation_started_at": t,
            "observation_completed_at": t + 0.05,
            "producer_id": "gaps-" + cls.token,
            "schema": "application_atlas.k8s_pod_node_snapshot.v1",
            "schema_version": 1,
            "scope": cls.scope,
            "validity_basis": "point_snapshot",
        }
        objects = [
            {
                **common,
                "kind": "object",
                "uid": f"{cls.token}-{uid}",
                "name": f"{uid}-{cls.token}",
                "namespace": "gaps",
                "node_name": cls.node_a,
                "host_network": False,
                "phase": "Running",
                "pod_ips": [ip],
                "record_fingerprint": uuid.uuid4().hex * 2,
            }
            for uid, ip in present
        ]
        manifest = {
            **common,
            "kind": "manifest",
            "complete": True,
            "expected_count": expected,
            "records_sha256": uuid.uuid4().hex * 2,
            "resource_version": "1",
        }
        return [
            {
                "time": t,
                "host": "atlas-producer",
                "sourcetype": "adm:k8s_pod_node_snapshot:v1",
                "index": "k8s",
                "event": item,
            }
            for item in [manifest, *objects]
        ]

    @classmethod
    def snapshot_events(cls):
        present = [("web", cls.web_ip), ("pa", cls.pod_a), ("pb", cls.pod_b)]
        return [
            # Complete: lists every pod except "gone".
            *cls.snapshot(3100, present, 3),
            # Incomplete (one record missing): its absences mean nothing.
            *cls.snapshot(3200, present[1:], 3),
        ]

    # ---- helpers ------------------------------------------------------------

    def search(self, spl, first=0, last=5400):
        return lab.search(spl, self.start + first, self.start + last)

    def trace(self, src, dst, first=900, last=5400):
        return self.search(f"| `adm_path_trace({src},{dst})`", first, last)

    def identity(self, ip):
        rows = lab.search(
            f'| inputlookup adm_ip_identity where ip="{ip}" scope="{self.scope}" '
            'entity_kind="pod" | table entity_name node valid_from valid_to'
        )
        return [
            (
                r["entity_name"],
                r.get("node"),
                int(float(r["valid_to"])) - self.start if r.get("valid_to") else None,
            )
            for r in rows
        ]

    # ---- gap 1 --------------------------------------------------------------

    def test_gap1_acl_drop_counted_once_by_record_time(self):
        rows = [
            r
            for r in self.trace(self.src, self.dst)
            if r.get("row_type") == "observation"
            and r.get("flow_source") == "aci_acllog"
        ]
        self.assertEqual(len(rows), 1, rows)
        r = rows[0]
        self.assertEqual(r["observer_device"], f"pod-1/{self.leaf}")
        self.assertEqual((r["records"], r["drops"]), ("1", "1"))
        self.assertEqual(int(float(r["first_seen"])), self.start + 1200)
        self.assertEqual(int(float(r["last_seen"])), self.start + 1200)
        self.assertEqual(multi(r["drop_services"]), ["tcp/47003"])

    def test_gap1_acl_record_windowed_by_its_own_time(self):
        # Polls at +1240.. fall in this window; the record (+1200) does not.
        rows = self.trace(self.src, self.dst, 1220, 5400)
        self.assertFalse(
            [r for r in rows if r.get("flow_source") == "aci_acllog"], rows
        )

    def test_gap1_device_flows_count_each_record_once(self):
        rows = self.search(f"| `adm_device_flows(pod-1/{self.leaf})`", 900, 5400)
        self.assertEqual(
            [
                (r["src"], r["dst"], r["dest_port"], r["drops"], r["blocked"])
                for r in rows
            ],
            [(self.src, self.dst, "47003", "1", "1")],
        )

    # ---- gap 6 --------------------------------------------------------------

    def test_gap6_hubble_drops_in_pair_trace(self):
        rows = self.trace(self.pod_a, self.pod_b)
        obs = [r for r in rows if r.get("flow_source") == "hubble"]
        self.assertEqual(len(obs), 1, obs)
        r = obs[0]
        self.assertEqual(r["observer"], f"hubble:{self.node_b}")
        self.assertEqual((r["records"], r["drops"]), ("3", "2"))
        self.assertEqual(multi(r["drop_reasons"]), ["POLICY_DENIED"])
        self.assertEqual(multi(r["drop_services"]), ["tcp/8080"])
        self.assertEqual(sorted(multi(r["services"])), ["tcp/8080", "tcp/9090"])
        self.assertEqual(multi(r["dst_pods"]), ["shop/api-1"])

    def test_gap6_pod_nodes_attach_pods_to_their_nodes(self):
        lab.search(
            "| makeresults count=2 | streamstats count AS n "
            f'| eval ip=if(n==1, "192.0.2.61", "192.0.2.62"), entity_name=if(n==1, "{self.node_a}", "{self.node_b}"), '
            f'node=entity_name, entity_kind="k8s_node", entity_id="{self.cluster}/".entity_name, cluster="{self.cluster}", '
            f'scope="{self.scope}", source="k8s_nodes", valid_from={self.start}, priority=2, '
            "_key=sha256(entity_id) | fields - n _time "
            "| outputlookup append=true key_field=_key adm_ip_identity"
        )
        rows = self.trace(self.pod_a, self.pod_b)
        nodes = sorted(
            (r["entity_name"], r["ip"])
            for r in rows
            if r.get("trace_role") == "pod_node"
        )
        self.assertEqual(
            nodes, [(self.node_a, "192.0.2.61"), (self.node_b, "192.0.2.62")]
        )
        pods = {
            r["ip"]: r.get("node")
            for r in rows
            if r.get("row_type") == "endpoint" and r.get("entity_kind") == "pod"
        }
        self.assertEqual(pods, {self.pod_a: self.node_a, self.pod_b: self.node_b})

    def test_gap6_device_flows_for_a_kubernetes_node(self):
        rows = self.search(f"| `adm_device_flows({self.node_b})`", 900, 5400)
        blocked = {
            (r["dest_port"], r["blocked"], tuple(multi(r.get("drop_reasons"))))
            for r in rows
        }
        self.assertEqual(
            blocked, {("8080", "1", ("POLICY_DENIED",)), ("9090", "0", ())}
        )

    # ---- gap 7 --------------------------------------------------------------

    def test_gap7_large_watch_events_keep_ip_and_delete(self):
        self.assertGreater(self.large, 10240)
        self.assertEqual(
            self.identity(self.web_ip),
            [(f"teastore-webui-{self.token}", self.node_a, None)],
        )
        self.assertEqual(
            self.identity(self.auth_ip),
            [(f"teastore-auth-{self.token}", self.node_a, 900)],
        )

    def test_gap7_complete_snapshot_closes_absent_pods_only(self):
        self.assertEqual(
            self.identity(self.gone_ip), [(f"gone-{self.token}", self.node_b, 3100)]
        )
        # Present in the complete snapshot, absent only from the incomplete one.
        self.assertEqual(self.identity(self.web_ip)[0][2], None)
        self.assertEqual(self.identity(self.pod_a)[0][2], None)

    # ---- gap 8 --------------------------------------------------------------

    def test_gap8_services_are_listener_ports(self):
        rows = [
            r
            for r in self.trace(self.src, self.dst)
            if r.get("row_type") == "observation" and r.get("flow_source") == "netflow"
        ]
        self.assertEqual({r["direction"] for r in rows}, {"forward", "reverse"})
        for r in rows:
            self.assertEqual(sorted(multi(r["services"])), ["tcp/47001", "tcp/47003"])
            self.assertEqual(
                sorted(multi(r["client_ports"])), ["41682", "47110", "47111"]
            )


if __name__ == "__main__":
    unittest.main()
