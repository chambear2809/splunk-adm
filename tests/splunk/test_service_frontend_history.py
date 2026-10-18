"""Live regression for Service frontend membership reconciliation."""

import base64
import hashlib
import json
import os
import time
import unittest
import uuid
import urllib.error
import urllib.request
from urllib.parse import urlencode

import lab


@unittest.skipUnless(os.environ.get("ADM_LAB") == "1", "set ADM_LAB=1")
class ServiceFrontendHistory(unittest.TestCase):
    def setUp(self):
        self.token = uuid.uuid4().hex[:10]
        self.cluster = "service-history-" + self.token
        self.uid = "svc-" + self.token
        self.start = int(time.time()) - 900
        self.source = "service-history-" + self.token
        self.loaded = 0
        self.addCleanup(self.cleanup)

    def cleanup(self):
        query = urlencode({"query": json.dumps({"cluster": self.cluster})})
        with lab._mgmt(
            "DELETE",
            "/servicesNS/nobody/splunk_adm/storage/collections/data/adm_ip_identity?"
            + query,
        ) as response:
            response.read()

    def service(
        self,
        offset,
        ips,
        event_type="MODIFIED",
        uid=None,
        node_port=None,
        port_name="http",
        target_port=None,
        lb_mode=None,
    ):
        port = {
            "name": port_name,
            "port": 8080,
            "protocol": "TCP",
        }
        if node_port:
            port["nodePort"] = node_port
        if target_port is not None:
            port["targetPort"] = target_port
        metadata = {
            "uid": uid or self.uid,
            "name": "frontend",
            "namespace": "history",
        }
        if lb_mode is not None:
            metadata["annotations"] = {"service.cilium.io/forwarding-mode": lb_mode}
        return {
            "type": event_type,
            "object": {
                "metadata": metadata,
                "spec": {
                    "type": "LoadBalancer",
                    "ports": [port],
                    "externalIPs": ips,
                },
            },
        }, offset

    def upload(self, events):
        payload = [
            {
                "time": self.start + offset,
                "source": self.source,
                "host": "service-history-node",
                "index": "k8s",
                "sourcetype": "kube:object:services",
                "fields": {"k8s.cluster.name": self.cluster},
                "event": body,
            }
            for body, offset in events
        ]
        lab._hec_post("\n".join(json.dumps(row) for row in payload).encode())
        self.loaded += len(payload)
        for _ in range(30):
            rows = lab.search(
                f'index=k8s source="{self.source}" | stats count', "0", "now"
            )
            if int(rows[0]["count"]) == self.loaded:
                return
            time.sleep(1)
        self.fail("Service history events were not indexed")

    def build(self, indexed_after=None, window=(0, 301)):
        data = {
            "search": "| `adm_identity_build`",
            "exec_mode": "blocking",
            "earliest_time": str(self.start + window[0]),
            "latest_time": str(self.start + window[1]),
        }
        if indexed_after:
            data["index_earliest"] = str(indexed_after)
        sid = lab._json("POST", "/servicesNS/admin/splunk_adm/search/v2/jobs", data)[
            "sid"
        ]
        lab._wait_job(sid)
        return lab._results(sid)

    def rest_batch_save(self, collection, rows):
        """Save bounded JSON batches without exposing credentials in output."""
        secrets = lab.read_secrets()
        auth = base64.b64encode(f"admin:{secrets['SPLUNK_PASSWORD']}".encode()).decode()
        path = (
            "/servicesNS/nobody/splunk_adm/storage/collections/data/"
            + collection
            + "/batch_save?output_mode=json"
        )
        for start in range(0, len(rows), 1000):
            chunk = rows[start : start + 1000]
            request = urllib.request.Request(
                lab.MGMT + path,
                data=json.dumps(chunk).encode(),
                method="POST",
                headers={
                    "Authorization": f"Basic {auth}",
                    "Content-Type": "application/json",
                },
            )
            try:
                with urllib.request.urlopen(
                    request, context=lab._CTX, timeout=120
                ) as response:
                    response.read()
            except urllib.error.HTTPError as error:
                with error:
                    self.fail(
                        f"batch_save failed: HTTP {error.code}: {error.read(2000)!r}"
                    )

    def rows(self):
        return lab.search(
            f'| inputlookup adm_ip_identity where cluster="{self.cluster}" '
            'entity_kind="k8s_service" '
            "| sort 0 ip valid_from | table _key entity_id ip valid_from valid_to "
            "lb_mode target_port port_name"
        )

    def parent_rows(self, uid):
        return lab.search(
            f'| inputlookup adm_ip_identity where cluster="{self.cluster}" '
            f'entity_kind="k8s_service_parent" entity_id="{uid}" '
            "| table _key entity_id valid_to valid_end desc"
        )

    def merge_incomplete_uid(self, uid):
        """Run the merge with a selected UID marked as incomplete evidence."""
        search = (
            f'| `adm_identity_observations` | search entity_id="{uid}" '
            "| eval adm_network_complete=0 | `adm_identity_merge` "
            "| stats sum(adm_write) AS rows_written sum(adm_close) AS rows_closed "
            "min(adm_network_complete) AS network_complete"
        )
        data = {
            "search": search,
            "exec_mode": "blocking",
            "earliest_time": str(self.start),
            "latest_time": str(self.start + 301),
        }
        sid = lab._json("POST", "/servicesNS/admin/splunk_adm/search/v2/jobs", data)[
            "sid"
        ]
        lab._wait_job(sid)
        return lab._results(sid)

    def test_removed_frontends_close_and_reappearance_starts_interval(self):
        self.upload(
            [
                (self.service(0, ["10.77.0.1", "10.77.0.2"])),
                (self.service(60, ["10.77.0.1"])),
                (self.service(120, [])),
                (self.service(180, ["10.77.0.1"])),
            ]
        )
        self.build()
        rows = self.rows()
        by_ip = {}
        for row in rows:
            by_ip.setdefault(row["ip"], []).append(row)
        self.assertEqual(len(by_ip["10.77.0.2"]), 1)
        self.assertEqual(int(float(by_ip["10.77.0.2"][0]["valid_to"])) - self.start, 60)
        self.assertEqual(
            [int(float(row["valid_from"])) - self.start for row in by_ip["10.77.0.1"]],
            [0, 180],
        )
        self.assertEqual(
            int(float(by_ip["10.77.0.1"][0]["valid_to"])) - self.start, 120
        )
        self.build()
        self.assertEqual(self.rows(), rows)

    def test_day_of_unchanged_snapshots_builds_and_replays_without_expansion_cap(self):
        offsets = range(-86100, 1, 300)
        self.upload([self.service(offset, ["10.77.0.16"]) for offset in offsets])
        summary = self.build(window=(-86400, 301))
        self.assertEqual(summary[0]["network_lookup_complete"], "1")
        rows = self.rows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(float(rows[0]["valid_from"]) - self.start, -86100)
        self.assertNotIn("valid_to", rows[0])
        summary = self.build(window=(-86400, 301))
        self.assertEqual(summary[0]["network_lookup_complete"], "1")
        self.assertEqual(self.rows(), rows)

    def test_retained_thousand_snapshot_history_reconstructs_twenty_frontends(self):
        ips = [f"10.77.10.{index}" for index in range(1, 21)]
        self.upload([self.service(-6000, ips)])
        summary = self.build(window=(-6005, -5995))
        self.assertEqual(summary[0]["network_lookup_complete"], "1")

        parent_rows = lab.search(
            f'| inputlookup adm_ip_identity_all where cluster="{self.cluster}" '
            f'entity_kind="k8s_service_parent" entity_id="{self.uid}"'
        )
        self.assertEqual(len(parent_rows), 1)
        parent = parent_rows[0]
        children = lab.search(
            f'| inputlookup adm_ip_identity_all where cluster="{self.cluster}" '
            f'entity_kind="k8s_service" entity_id="{self.uid}" '
            "| table ip desc"
        )
        self.assertEqual({row["ip"] for row in children}, set(ips))
        child_keys = {json.loads(row["desc"])["sck"] for row in children}
        self.assertEqual(len(child_keys), 20)

        historical_members = "|".join(
            sorted(hashlib.sha256(key.encode()).hexdigest() for key in child_keys)
        )
        history = [
            {"t": self.start - 5000 + index * 5, "p": historical_members}
            for index in range(1000)
        ]
        anchor_desc = json.loads(parent["desc"])
        anchor_desc["sh"] = history
        anchor_desc["ls"] = self.start - 5
        parent["desc"] = json.dumps(anchor_desc, separators=(",", ":"))
        parent["last_seen"] = self.start - 5
        self.rest_batch_save("adm_ip_identity", [parent])

        self.upload([self.service(0, ips), self.service(60, ips)])
        summary = self.build()
        self.assertEqual(summary[0]["network_lookup_complete"], "1")
        rows = self.rows()
        self.assertEqual(len(rows), 20)
        self.assertEqual({row["ip"] for row in rows}, set(ips))
        for row in rows:
            self.assertEqual(float(row["valid_from"]) - self.start, -6000)
            self.assertNotIn("valid_to", row)

        # The retained parent history is the source of truth for reconstructing
        # membership.  Verify that the 1,000 seeded states and both new polls
        # survive the merge, and that every state still names all 20 children.
        anchor = self.parent_rows(self.uid)
        self.assertEqual(len(anchor), 1)
        history_after = json.loads(anchor[0]["desc"])["sh"]
        self.assertEqual(len(history_after), 1002)
        expected_members = set(historical_members.split("|"))
        self.assertTrue(
            all(
                set(state["p"].split("|")) == expected_members
                for state in history_after
            )
        )

        replay = self.build()
        self.assertEqual(replay[0]["network_lookup_complete"], "1")
        self.assertEqual(self.rows(), rows)
        replay_anchor = self.parent_rows(self.uid)
        self.assertEqual(len(replay_anchor), 1)
        self.assertEqual(json.loads(replay_anchor[0]["desc"])["sh"], history_after)

    def test_empty_snapshot_survives_before_indexed_late_presence(self):
        for event_type in ("MODIFIED", "DELETED"):
            with self.subTest(event_type=event_type):
                uid = self.uid + event_type
                ip = "10.77.0.3" if event_type == "MODIFIED" else "10.77.0.13"
                self.upload([self.service(120, [], event_type, uid=uid)])
                self.build()
                anchors = self.parent_rows(uid)
                self.assertEqual(len(anchors), 1)
                self.assertEqual(
                    float(anchors[0]["valid_to"]) - self.start,
                    120,
                )
                self.assertEqual(
                    float(anchors[0]["valid_end"]),
                    float(anchors[0]["valid_to"]),
                )
                time.sleep(1.1)
                boundary = int(time.time())
                self.upload([self.service(0, [ip], uid=uid)])
                self.build(indexed_after=boundary)
                rows = [r for r in self.rows() if r["entity_id"] == uid]
                self.assertEqual(len(rows), 1)
                self.assertEqual(float(rows[0]["valid_to"]) - self.start, 120)
                self.build(indexed_after=boundary)
                self.assertEqual(
                    [r for r in self.rows() if r["entity_id"] == uid], rows
                )

    def test_subsecond_frontend_reopening_preserves_both_intervals(self):
        self.upload(
            [
                self.service(0.1, ["10.77.0.4"]),
                self.service(0.2, []),
                self.service(0.3, ["10.77.0.4"]),
            ]
        )
        self.build()
        rows = self.rows()
        self.assertEqual(len(rows), 2)
        self.assertAlmostEqual(float(rows[0]["valid_to"]) - self.start, 0.2, places=5)
        self.assertAlmostEqual(float(rows[1]["valid_from"]) - self.start, 0.3, places=5)
        self.assertNotEqual(rows[0]["_key"], rows[1]["_key"])

    def test_indexed_late_presence_does_not_close_retained_presence(self):
        self.upload([self.service(0, ["10.77.0.8"]), self.service(120, ["10.77.0.8"])])
        self.build()
        time.sleep(1.1)
        boundary = int(time.time())
        self.upload([self.service(60, ["10.77.0.8"])])
        self.build(indexed_after=boundary)
        rows = self.rows()
        self.assertEqual(len(rows), 1)
        self.assertNotIn("valid_to", rows[0])
        self.assertEqual(float(rows[0]["valid_from"]) - self.start, 0)

    def test_indexed_late_absence_splits_stored_presence(self):
        self.upload([self.service(0, ["10.77.0.9"]), self.service(120, ["10.77.0.9"])])
        self.build()
        time.sleep(1.1)
        boundary = int(time.time())
        self.upload([self.service(60, [])])
        self.build(indexed_after=boundary)
        rows = self.rows()
        self.assertEqual(len(rows), 2)
        self.assertEqual(float(rows[0]["valid_to"]) - self.start, 60)
        self.assertEqual(float(rows[1]["valid_from"]) - self.start, 120)
        self.build(indexed_after=boundary)
        self.assertEqual(self.rows(), rows)

    def test_late_presence_extends_reopened_interval_after_prior_gap(self):
        self.upload(
            [
                self.service(0, ["10.77.0.15"]),
                self.service(60, []),
                self.service(180, ["10.77.0.15"]),
            ]
        )
        self.build()
        time.sleep(1.1)
        boundary = int(time.time())
        self.upload([self.service(120, ["10.77.0.15"])])
        self.build(indexed_after=boundary)
        rows = self.rows()
        self.assertEqual(len(rows), 2)
        self.assertEqual(float(rows[0]["valid_to"]) - self.start, 60)
        self.assertEqual(float(rows[1]["valid_from"]) - self.start, 120)
        self.build(indexed_after=boundary)
        self.assertEqual(self.rows(), rows)

    def test_multiple_indexed_late_absences_split_all_retained_presence(self):
        self.upload(
            [
                self.service(0, ["10.77.0.10"]),
                self.service(120, ["10.77.0.10"]),
                self.service(240, ["10.77.0.10"]),
            ]
        )
        self.build()
        time.sleep(1.1)
        boundary = int(time.time())
        self.upload([self.service(60, []), self.service(180, [])])
        self.build(indexed_after=boundary)
        rows = self.rows()
        self.assertEqual(len(rows), 3)
        self.assertEqual(
            [round(float(row["valid_from"]) - self.start) for row in rows],
            [0, 120, 240],
        )
        self.assertEqual(
            [round(float(row["valid_to"]) - self.start) for row in rows[:2]],
            [60, 180],
        )
        self.assertNotIn("valid_to", rows[2])
        self.build(indexed_after=boundary)
        self.assertEqual(self.rows(), rows)

    def test_reopened_frontend_preserves_changed_service_attributes(self):
        self.upload(
            [
                self.service(
                    0,
                    ["10.77.0.11"],
                    port_name="web",
                    target_port="http",
                    lb_mode="snat",
                ),
                self.service(
                    60,
                    [],
                    port_name="web",
                    target_port="http",
                    lb_mode="snat",
                ),
                self.service(
                    120,
                    ["10.77.0.11"],
                    port_name="metrics",
                    target_port=9090,
                    lb_mode="dsr",
                ),
            ]
        )
        self.build()
        time.sleep(1.1)
        boundary = int(time.time())
        self.upload(
            [
                self.service(
                    180,
                    [],
                    port_name="metrics",
                    target_port=9090,
                    lb_mode="dsr",
                )
            ]
        )
        self.build(indexed_after=boundary)
        rows = self.rows()
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["lb_mode"], "snat")
        self.assertEqual(rows[0]["target_port"], "http")
        self.assertEqual(rows[0]["port_name"], "web")
        self.assertEqual(rows[1]["lb_mode"], "dsr")
        self.assertEqual(str(rows[1]["target_port"]), "9090")
        self.assertEqual(rows[1]["port_name"], "metrics")
        self.assertEqual(float(rows[0]["valid_to"]) - self.start, 60)
        self.assertEqual(float(rows[1]["valid_to"]) - self.start, 180)

    def test_incomplete_new_uid_does_not_close_existing_frontend(self):
        old_uid = self.uid + "-old"
        new_uid = self.uid + "-new"
        self.upload([self.service(0, ["10.77.0.12"], uid=old_uid)])
        self.build()
        before = self.rows()
        self.upload([self.service(60, ["10.77.0.12"], uid=new_uid)])
        summary = self.merge_incomplete_uid(new_uid)
        self.assertEqual(int(summary[0].get("rows_closed", 0)), 0)
        self.assertEqual(int(summary[0].get("rows_written", 0)), 0)
        self.assertEqual(self.rows(), before)

    def test_third_uid_closes_both_simultaneous_previous_owners(self):
        first_uid = self.uid + "-a"
        second_uid = self.uid + "-b"
        third_uid = self.uid + "-c"
        self.upload(
            [
                self.service(0, ["10.77.0.14"], uid=first_uid),
                self.service(0, ["10.77.0.14"], uid=second_uid),
                self.service(60, ["10.77.0.14"], uid=third_uid),
            ]
        )
        self.build()
        rows = self.rows()
        self.assertEqual(len(rows), 3)
        by_uid = {row["entity_id"]: row for row in rows}
        self.assertEqual(
            float(by_uid[first_uid]["valid_to"]) - self.start,
            60,
        )
        self.assertEqual(
            float(by_uid[second_uid]["valid_to"]) - self.start,
            60,
        )
        self.assertNotIn("valid_to", by_uid[third_uid])
        for row in rows:
            if "valid_to" in row:
                self.assertGreater(float(row["valid_to"]), float(row["valid_from"]))

    def test_replacement_uid_closes_previous_frontend_owner(self):
        self.upload(
            [
                self.service(0, ["10.77.0.5"]),
                self.service(60, ["10.77.0.5"], uid=self.uid + "new"),
            ]
        )
        self.build()
        rows = self.rows()
        self.assertEqual(len(rows), 2)
        old = next(r for r in rows if r["entity_id"] == self.uid)
        self.assertEqual(float(old["valid_to"]) - self.start, 60)

    def test_nodeport_removal_and_service_deletion_close_children(self):
        self.upload(
            [
                self.service(0, ["10.77.0.6"], node_port=30080),
                self.service(60, ["10.77.0.7"]),
                self.service(120, ["10.77.0.7"], "DELETED"),
            ]
        )
        self.build()
        rows = self.rows()
        ends = {r["ip"]: float(r["valid_to"]) - self.start for r in rows}
        self.assertEqual(ends["10.77.0.6"], 60)
        self.assertEqual(ends[f"nodeport:{self.cluster}:30080/tcp"], 60)
        self.assertEqual(ends["10.77.0.7"], 120)
