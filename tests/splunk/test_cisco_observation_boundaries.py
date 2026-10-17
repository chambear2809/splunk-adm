"""TA-shaped Stream v2 isolation and non-authoritative counter boundaries."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import sys
import time
import unittest
import urllib.parse
import uuid

import lab

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from capture_networking_fixtures import search  # noqa: E402
from lab_lock import LabLock  # noqa: E402
from load_networking_lab import dispatch  # noqa: E402


@unittest.skipUnless(os.environ.get("ADM_LAB") == "1", "requires disposable Splunk lab")
class CiscoObservationBoundariesTest(unittest.TestCase):
    """Exercise explicit exporter-domain profiles and raw-only Stream evidence."""

    @classmethod
    def setUpClass(cls):
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            try:
                status = lab._json("GET", "/services/kvstore/status")["entry"][0][
                    "content"
                ]
                if status.get("current", {}).get("status") == "ready":
                    return
            except (lab.LabError, OSError, KeyError, IndexError):
                pass
            time.sleep(3)
        raise AssertionError(
            "KV store did not become ready for observation-boundary tests"
        )

    def setUp(self):
        self.token = "cisco-observation-" + uuid.uuid4().hex[:12]
        self.scope = self.token
        self.cluster = "observation-" + uuid.uuid4().hex[:10]
        self.now = int(time.time()) - 15
        self.raw_event_count = 0
        self.profile_keys: list[str] = []
        # Register cleanup before profile seeding so failures remain isolated.
        self.addCleanup(self._cleanup_profiles)

    @staticmethod
    def _exporter(seed: str) -> str:
        value = int(seed[:8], 16)
        return f"198.18.{value % 254 + 1}.{value // 254 % 254 + 1}"

    def _profile(self, exporter: str, domain: int, scope: str, cluster: str) -> dict:
        return {
            "source": "stream_ipfix",
            "source_authority": exporter,
            "domain_kind": "exporter",
            "observation_domain_present": "1",
            "observation_domain_id": str(domain),
            "vpn_id": "",
            "routing_domain": "",
            "scope": scope,
            "cluster": cluster,
            "mapping_status": "mapped",
            "profile": "catalyst_campus_fnf",
            "duplicate_count": 1,
        }

    def _seed_profiles(self, profiles: list[dict]) -> None:
        payload = json.dumps(json.dumps(profiles, separators=(",", ":")))
        result = lab.search(
            f"| makeresults format=json data={payload} "
            '| eval mapping_key=sha256(json_array(tostring(coalesce(source,"")), '
            'tostring(coalesce(source_authority,"")), tostring(coalesce(domain_kind,"")), '
            'tostring(coalesce(observation_domain_present,"")), '
            'tostring(coalesce(observation_domain_id,"")), tostring(coalesce(vpn_id,"")), '
            'tostring(coalesce(routing_domain,"")))), '
            "_key=sha256(json_array(mapping_key,scope,cluster,profile,mapping_status)) "
            "| fields _key mapping_key source source_authority domain_kind "
            "observation_domain_present observation_domain_id vpn_id routing_domain "
            "scope cluster mapping_status profile duplicate_count "
            "| outputlookup append=true key_field=_key adm_network_source_scope "
            "| table _key",
            "0",
            "+10y",
        )
        if len(result) != len(profiles):
            raise AssertionError("did not seed every source-scope profile")
        self.profile_keys = [str(row.get("_key", "")) for row in result]
        if any(not key for key in self.profile_keys) or len(
            set(self.profile_keys)
        ) != len(profiles):
            raise AssertionError("source-scope seeding did not return owned keys")
        keys = ",".join(json.dumps(key) for key in self.profile_keys)
        visible = lab.search(
            f"| inputlookup strict=true adm_network_source_scope "
            f"| where _key IN ({keys}) | table _key mapping_key scope cluster profile",
            "0",
            "+10y",
        )
        if {str(row.get("_key")) for row in visible} != set(self.profile_keys):
            raise AssertionError("source-scope profile readback was incomplete")

    def _cleanup_profiles(self) -> None:
        if not self.profile_keys:
            return
        query = urllib.parse.urlencode(
            {"query": json.dumps({"_key": {"$in": self.profile_keys}})}
        )
        response = lab._mgmt(
            "DELETE",
            f"/servicesNS/nobody/{lab.APP}/storage/collections/data/"
            f"adm_network_source_scope?{query}",
        )
        response.close()

    def _event(
        self,
        *,
        exporter: str,
        domain: int,
        source_port: int,
        sequence: int,
        at: int,
        raw_bytes: int,
        raw_packets: int,
        sampling_interval: int,
        input_ifindex: int,
        output_ifindex: int,
        reverse: bool = False,
    ) -> dict:
        stamp = (
            datetime.fromtimestamp(at, timezone.utc)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z")
        )
        end_stamp = (
            datetime.fromtimestamp(at + 1, timezone.utc)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z")
        )
        src_ip, dest_ip = ("10.71.0.20", "10.71.0.80")
        src_port, dest_port = source_port, 443
        if reverse:
            src_ip, dest_ip = dest_ip, src_ip
            src_port, dest_port = dest_port, source_port
        return {
            "time": at + 1,
            "host": "cisco-observation-test",
            "source": self.token,
            "sourcetype": "stream:netflow",
            "index": "netflow",
            "event": {
                "timestamp": stamp,
                "endtime": end_stamp,
                "netflow_version": 9,
                "seqnumber": sequence,
                "exporter_ip": exporter,
                "observation_domain_id": domain,
                "exporter_sampling_interval": sampling_interval,
                "src_ip": src_ip,
                "dest_ip": dest_ip,
                "src_port": src_port,
                "dest_port": dest_port,
                "protoid": 6,
                "bytes": raw_bytes,
                "packets": raw_packets,
                "input_snmpidx": input_ifindex,
                "output_snmpidx": output_ifindex,
            },
        }

    def _load_and_wait(self, events: list[dict]) -> None:
        lab._hec_post(("\n".join(json.dumps(row) for row in events) + "\n").encode())
        self.raw_event_count += len(events)
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            rows = lab.search(
                f'index=netflow source="{self.token}" | stats count', "0", "+10y"
            )
            if rows and int(rows[0].get("count", 0)) == self.raw_event_count:
                return
            time.sleep(1)
        self.fail("raw Stream observations did not all become searchable")

    def test_one_exporter_maps_distinct_nonzero_domains_to_separate_scopes(self):
        exporter = self._exporter(uuid.uuid4().hex)
        scopes = [self.token + "-domain-a", self.token + "-domain-b"]
        clusters = [self.cluster + "-a", self.cluster + "-b"]
        domains = [53, 91]
        self._seed_profiles(
            [
                self._profile(exporter, domain, scope, cluster)
                for domain, scope, cluster in zip(domains, scopes, clusters)
            ]
        )
        port = 41000 + int(uuid.uuid4().hex[:4], 16) % 20000
        events = [
            self._event(
                exporter=exporter,
                domain=domain,
                source_port=port,
                sequence=7000 + i,
                at=self.now + i,
                raw_bytes=100,
                raw_packets=2,
                sampling_interval=1,
                input_ifindex=17,
                output_ifindex=18,
            )
            for i, domain in enumerate(domains)
        ]
        self._load_and_wait(events)
        rows = lab.search(
            f'| `adm_flows_v2` | where adm_scope_authority="{exporter}" '
            f"AND adm_src_port={port} "
            "| table adm_scope_authority adm_scope_observation_domain_id adm_scope "
            "adm_cluster adm_profile_status adm_registered_duplicate_counts",
            "0",
            "+10y",
        )
        self.assertEqual(len(rows), 2, rows)
        by_domain = {
            str(row.get("adm_scope_observation_domain_id")): row for row in rows
        }
        self.assertEqual(set(by_domain), {str(value) for value in domains})
        for domain, scope, cluster in zip(domains, scopes, clusters):
            with self.subTest(domain=domain):
                row = by_domain[str(domain)]
                self.assertEqual(row.get("adm_scope_authority"), exporter)
                self.assertEqual(row.get("adm_scope"), scope)
                self.assertEqual(row.get("adm_cluster"), cluster)
                self.assertEqual(row.get("adm_profile_status"), "mapped")
                self.assertEqual(str(row.get("adm_registered_duplicate_counts")), "1")

        observations = lab.search(
            f'`adm_traffic_observations_v2` | search adm_scope_authority="{exporter}" '
            f"AND source_port={port} | table rollup_id scope cluster "
            "adm_scope_observation_domain_id source_ip destination_ip records "
            "counter_semantics metrics_authoritative adm_profile_status",
            "0",
            "+10y",
        )
        self.assertEqual(len(observations), 2, observations)
        self.assertEqual({row.get("scope") for row in observations}, set(scopes))
        self.assertEqual({row.get("cluster") for row in observations}, set(clusters))
        self.assertEqual(len({row.get("rollup_id") for row in observations}), 2)
        self.assertEqual(
            {(row.get("source_ip"), row.get("destination_ip")) for row in observations},
            {("10.71.0.20", "10.71.0.80")},
        )
        for row in observations:
            self.assertEqual(int(row.get("records", 0)), 1)
            self.assertEqual(row.get("counter_semantics"), "unknown")
            self.assertEqual(str(row.get("metrics_authoritative")), "0")
            self.assertEqual(row.get("adm_profile_status"), "mapped")

    def test_repeated_sampled_updates_and_paired_interfaces_stay_raw_only(self):
        exporter_ingress = self._exporter(uuid.uuid4().hex)
        exporter_egress = self._exporter(uuid.uuid4().hex)
        while exporter_egress == exporter_ingress:
            exporter_egress = self._exporter(uuid.uuid4().hex)
        domain = 73
        self._seed_profiles(
            [
                self._profile(exporter, domain, self.scope, self.cluster)
                for exporter in (exporter_ingress, exporter_egress)
            ]
        )
        source_port = 43000 + int(uuid.uuid4().hex[:4], 16) % 20000
        events = [
            self._event(
                exporter=exporter_ingress,
                domain=domain,
                source_port=source_port,
                sequence=8100 + i,
                at=self.now + i,
                raw_bytes=counter,
                raw_packets=i + 1,
                sampling_interval=10,
                input_ifindex=17,
                output_ifindex=18,
            )
            for i, counter in enumerate((100, 200, 300))
        ]
        events.append(
            self._event(
                exporter=exporter_egress,
                domain=domain,
                source_port=source_port,
                sequence=9100,
                at=self.now + 4,
                raw_bytes=400,
                raw_packets=4,
                sampling_interval=10,
                input_ifindex=18,
                output_ifindex=17,
                reverse=True,
            )
        )
        self._load_and_wait(events)

        rows = lab.search(
            f'`adm_traffic_observations_v2` | search scope="{self.scope}" '
            f"AND (source_port={source_port} OR destination_port={source_port}) "
            "| table rollup_id scope cluster adm_scope_authority "
            "adm_scope_observation_domain_id raw_bytes raw_packets raw_sampling "
            "source_port destination_port counter_semantics metrics_authoritative "
            "records direction "
            "adm_profile_status adm_quality_status "
            "adm_traffic_observation",
            "0",
            "+10y",
        )
        self.assertEqual(len(rows), len(events), rows)
        self.assertEqual(len({row.get("rollup_id") for row in rows}), len(events))
        self.assertEqual(sum(int(row.get("records", 0)) for row in rows), len(events))
        self.assertEqual({int(row["raw_bytes"]) for row in rows}, {100, 200, 300, 400})
        self.assertEqual({int(row["raw_packets"]) for row in rows}, {1, 2, 3, 4})
        self.assertEqual({int(row["raw_sampling"]) for row in rows}, {10})
        self.assertEqual(
            {(int(row["source_port"]), int(row["destination_port"])) for row in rows},
            {(source_port, 443), (443, source_port)},
        )
        self.assertEqual(
            {row.get("adm_scope_authority") for row in rows},
            {exporter_ingress, exporter_egress},
        )
        self.assertEqual(
            {str(row.get("adm_scope_observation_domain_id")) for row in rows},
            {str(domain)},
        )
        self.assertTrue(all(row.get("scope") == self.scope for row in rows))
        self.assertTrue(all(row.get("cluster") == self.cluster for row in rows))
        self.assertTrue(all(row.get("adm_profile_status") == "mapped" for row in rows))
        self.assertTrue(
            all(row.get("adm_quality_status") == "accepted" for row in rows)
        )
        self.assertTrue(all(row.get("counter_semantics") == "unknown" for row in rows))
        self.assertTrue(
            all(str(row.get("metrics_authoritative")) == "0" for row in rows)
        )
        self.assertTrue(
            all(
                not {"bytes_c2s", "bytes_s2c", "packets", "conns"}.intersection(row)
                for row in rows
            )
        )
        for row in rows:
            evidence = json.loads(row["adm_traffic_observation"])
            self.assertEqual(evidence["records"], 1)
            self.assertEqual(evidence["counter_semantics"], "unknown")
            self.assertEqual(str(evidence["metrics_authoritative"]), "0")
            # JSON extraction preserves the IPFIX observation-domain schema
            # as a number even though the normalized top-level field is text.
            self.assertEqual(evidence["observation_domain_id"], domain)
            self.assertIn(
                evidence["source_authority"], {exporter_ingress, exporter_egress}
            )
            self.assertIn(
                evidence["interface_in"], {"17", "18", "ifIndex 17", "ifIndex 18"}
            )
            self.assertIn(
                evidence["interface_out"],
                {"17", "18", "ifIndex 17", "ifIndex 18"},
            )
            self.assertNotEqual(evidence["interface_in"], evidence["interface_out"])
            self.assertEqual(evidence["direction"], "unknown")
        by_exporter = {
            evidence["source_authority"]: evidence
            for evidence in (json.loads(row["adm_traffic_observation"]) for row in rows)
        }
        ingress = by_exporter[exporter_ingress]
        egress = by_exporter[exporter_egress]
        self.assertEqual(ingress["interface_in"].replace("ifIndex ", ""), "17")
        self.assertEqual(ingress["interface_out"].replace("ifIndex ", ""), "18")
        self.assertEqual(egress["interface_in"].replace("ifIndex ", ""), "18")
        self.assertEqual(egress["interface_out"].replace("ifIndex ", ""), "17")

        # Stream observations are intentionally excluded from conversation
        # totals and connection inference until a profile proves counter
        # semantics; raw counter-shaped values above remain evidence only.
        conversations = lab.search(
            f'| `adm_conversation_rollup_v2` | search scope="{self.scope}"',
            "0",
            "+10y",
        )
        self.assertEqual(conversations, [])


@unittest.skipUnless(os.environ.get("ADM_LAB") == "1", "requires disposable Splunk lab")
class CiscoTrafficContextOwnershipBoundariesTest(unittest.TestCase):
    """Prove partial IP/client ownership cannot create traffic context edges.

    The test consumes the root-prepared combined synthetic scenario. It never
    resets the lab; temporary identity/history rows use unique keys and only
    those keys are removed.
    """

    client_mac = "02:71:00:00:00:20"
    client_ip = "10.71.0.20"
    cluster = "cilium-nxos-west"
    namespace = "shop"
    service = "checkout"

    @classmethod
    def setUpClass(cls):
        if not LabLock(ROOT).check_owned():
            raise RuntimeError("run this suite under tools/lab_lock.py")
        cls.lab = lab

    def setUp(self):
        self.token = "cisco-context-owner-" + uuid.uuid4().hex[:12]
        self.scope = "meraki-nxos"
        self.other_scope = self.scope + "-other"
        self.identity_keys: list[str] = []
        self.history_keys: list[str] = []
        self.addCleanup(self._cleanup_owned_rows)

    def _context(self, observation_id: str) -> list[dict]:
        rows, _ = search(
            self.lab,
            '`adm_graph_traffic_context_v2("checkout","demo","cilium-nxos-west","shop")` '
            f'| search traffic_observation_id="{observation_id}"',
            "0",
            "+10y",
        )
        return [row for row in rows if row.get("row_type") == "edge"]

    def _seed_pod_identity(
        self,
        ip: str,
        *,
        scope: str,
        valid_from: float,
        valid_to: float,
        name: str,
    ) -> str:
        entity_id = self.token + "-" + name
        row = {
            "ip": ip,
            "scope": scope,
            "entity_id": entity_id,
            "entity_name": name,
            "cluster": self.cluster,
            "namespace": self.namespace,
            "node": "worker-boundary-test",
            "valid_from": valid_from,
            "valid_to": valid_to,
            "first_seen": valid_from,
            "last_seen": valid_to,
        }
        data = json.dumps(json.dumps([row], separators=(",", ":")))
        rows = self.lab.search(
            f"| makeresults format=json data={data} "
            '| eval source="k8s_pods", entity_kind="pod", priority=1, '
            'ek="pod:".cluster."/".entity_id, updated=now(), '
            '_key=sha256(source."|".entity_kind."|".entity_id."|".ip."|".scope) '
            "| `adm_identity_desc` "
            "| fields _key ip scope entity_kind entity_id entity_name cluster "
            "namespace node valid_from valid_to valid_end first_seen last_seen "
            "priority source ek updated desc "
            "| outputlookup append=true key_field=_key override_if_empty=false adm_ip_identity "
            "| table _key",
            "0",
            "+10y",
        )
        if len(rows) != 1 or not rows[0].get("_key"):
            raise AssertionError("temporary identity row was not written with a key")
        key = str(rows[0]["_key"])
        self.identity_keys.append(key)
        return key

    def _delete_identity_keys(self, keys: list[str]) -> None:
        if not keys:
            return
        query = urllib.parse.urlencode({"query": json.dumps({"_key": {"$in": keys}})})
        response = self.lab._mgmt(
            "DELETE",
            f"/servicesNS/nobody/{self.lab.APP}/storage/collections/data/adm_ip_identity?{query}",
        )
        response.close()
        self.identity_keys = [key for key in self.identity_keys if key not in keys]

    def _cleanup_owned_rows(self) -> None:
        self._delete_identity_keys(self.identity_keys.copy())
        if self.history_keys:
            query = urllib.parse.urlencode(
                {"query": json.dumps({"_key": {"$in": self.history_keys}})}
            )
            response = self.lab._mgmt(
                "DELETE",
                f"/servicesNS/nobody/{self.lab.APP}/storage/collections/data/adm_network_client_history?{query}",
            )
            response.close()

    def _positive_context_fixture(self) -> dict:
        rows, _ = search(
            self.lab,
            '`adm_graph_traffic_context_v2("checkout","demo","cilium-nxos-west","shop")` '
            f'| search scope="{self.scope}" source_mac="{self.client_mac}"',
            "0",
            "+10y",
        )
        candidates = [
            row
            for row in rows
            if row.get("row_type") == "edge"
            and row.get("relationship") == "traffic_observation"
            and row.get("source_ip") == self.client_ip
        ]
        if not candidates:
            raise AssertionError(
                "root-prepared fixture has no positive traffic-context control"
            )
        return candidates[0]

    def _flow_template(self, context: dict) -> dict:
        rows, _ = search(
            self.lab,
            'index=netflow sourcetype="stream:netflow" '
            "| spath input=_raw path=src_mac output=src_mac "
            "| spath input=_raw path=src_ip output=src_ip "
            "| spath input=_raw path=dest_ip output=dest_ip "
            "| spath input=_raw path=src_port output=src_port "
            f'| where src_mac="{context["source_mac"]}" AND src_ip="{context["source_ip"]}" '
            f'AND dest_ip="{context["destination_ip"]}" AND src_port={context["source_port"]} '
            "| table _raw",
            "0",
            "+10y",
        )
        target = float(context["first_seen"])
        for row in rows:
            raw = json.loads(row["_raw"])
            event = raw.get("event", raw)
            stamp = datetime.fromisoformat(
                event["timestamp"].replace("Z", "+00:00")
            ).timestamp()
            if abs(stamp - target) <= 1:
                return event
        raise AssertionError("positive context row had no matching raw Stream event")

    def _load_long_flow_and_build(
        self, context: dict, *, include_source_mac: bool = True
    ) -> tuple[str, float, float]:
        event = self._flow_template(context)
        first = float(context["first_seen"])
        last = first + 10
        start_stamp = datetime.fromtimestamp(first, timezone.utc)
        end_stamp = start_stamp + timedelta(seconds=10)
        payload = json.loads(json.dumps(event))
        payload["timestamp"] = start_stamp.isoformat(timespec="milliseconds").replace(
            "+00:00", "Z"
        )
        payload["endtime"] = end_stamp.isoformat(timespec="milliseconds").replace(
            "+00:00", "Z"
        )
        port = 40000 + int(uuid.uuid4().hex[:4], 16) % 20000
        payload["src_port"] = port
        payload["seqnumber"] = int(uuid.uuid4().hex[:8], 16)
        if not include_source_mac:
            payload.pop("src_mac", None)
        flow_source = self.token + "-flow-" + uuid.uuid4().hex[:8]
        raw = {
            "time": last,
            "host": "cisco-context-boundary-test",
            "source": flow_source,
            "sourcetype": "stream:netflow",
            "index": "netflow",
            "event": payload,
        }
        self.lab._hec_post((json.dumps(raw) + "\n").encode())

        deadline = time.monotonic() + 90
        while True:
            visible, _ = search(
                self.lab,
                f'index=netflow source="{flow_source}" | stats count',
                "0",
                "+10y",
            )
            if visible and int(visible[0].get("count", 0)) == 1:
                break
            if time.monotonic() >= deadline:
                self.fail("cloned long-duration Stream input did not become searchable")
            time.sleep(1)

        index_bounds = (int(time.time()) - 120, int(time.time()) + 2)
        dispatch(
            self.lab,
            "ADM - Traffic observation rollup v2",
            index_bounds,
            ("0", "+10y"),
        )
        summaries, _ = search(
            self.lab,
            f'index=adm_summary_v2 source="adm:traffic_observation" '
            f'scope="{self.scope}" source_ip="{payload["src_ip"]}" '
            f"source_port={port} | table rollup_id first_seen last_seen destination_ip",
            "0",
            "+10y",
        )
        self.assertEqual(len(summaries), 1, summaries)
        return str(summaries[0]["rollup_id"]), first, last

    def _assert_context_count(self, observation_id: str, expected: int) -> None:
        rows = self._context(observation_id)
        self.assertEqual(len(rows), expected, rows)
        if expected:
            self.assertTrue(rows[0].get("source", "").startswith("network_client:"))
            self.assertTrue(
                rows[0].get("target", "").startswith(("k8s_service:", "pod:")),
                "positive control did not preserve the known destination identity",
            )

    def _check_identity_interval_cases(
        self,
        observation_id: str,
        ip: str,
        first: float,
        last: float,
        *,
        side: str,
    ) -> None:
        cases = (
            ("partial_from_start", first - 5, first + 1, self.scope, 0),
            ("partial_until_end", last - 1, last + 5, self.scope, 0),
            ("exclusive_end_at_start", first - 5, first, self.scope, 1),
            ("starts_after_end", last + 1, last + 5, self.scope, 1),
            ("other_scope_overlap", first - 5, last + 5, self.other_scope, 1),
        )
        for name, start, end, scope, expected in cases:
            with self.subTest(side=side, case=name):
                seeded: list[str] = []
                seeded.append(
                    self._seed_pod_identity(
                        ip,
                        scope=scope,
                        valid_from=start,
                        valid_to=end,
                        name=f"{side}-rival-{name}",
                    )
                )
                try:
                    self._assert_context_count(observation_id, expected)
                finally:
                    self._delete_identity_keys(seeded)

    def _load_midflow_competing_client(
        self, first: float, *, competitor_mac: str | None = None
    ) -> str:
        rows, _ = search(
            self.lab,
            'index=cisco_meraki sourcetype="meraki:accesspoints" '
            "| spath input=_raw path=type output=event_type "
            "| spath input=_raw path=clientMac output=client_mac "
            '| where lower(event_type)=="association" AND client_mac=="02:71:00:00:00:21" '
            "| table _raw",
            "0",
            "+10y",
        )
        self.assertTrue(rows, "positive fixture lacks a supported Meraki association")
        if competitor_mac is None:
            competitor_mac = "02:" + ":".join(
                uuid.uuid4().hex[i : i + 2] for i in range(0, 10, 2)
            )
        indexed_raw = json.loads(rows[0]["_raw"])
        event = json.loads(json.dumps(indexed_raw.get("event", indexed_raw)))
        event["clientId"] = self.token + "-competing-client-id"
        event["clientDescription"] = "Synthetic competing client identity"
        event["clientMac"] = competitor_mac
        event["eventData"]["client_mac"] = competitor_mac
        event["eventData"]["client_ip"] = self.client_ip
        # Start the builder window at a fresh index-time second. This keeps an
        # earlier temporary association out of the next isolated comparison.
        index_start = int(time.time()) + 1
        while time.time() < index_start:
            time.sleep(0.1)
        event_time = datetime.fromtimestamp(first + 5, timezone.utc)
        event["occurredAt"] = event_time.isoformat(timespec="milliseconds").replace(
            "+00:00", "Z"
        )
        association_source = self.token + "-association-" + uuid.uuid4().hex[:8]
        hec_event = {
            "time": first + 5,
            "host": "cisco-context-boundary-test",
            "source": association_source,
            "sourcetype": "meraki:accesspoints",
            "index": "cisco_meraki",
            "event": event,
        }
        self.lab._hec_post((json.dumps(hec_event) + "\n").encode())

        deadline = time.monotonic() + 90
        while True:
            visible, _ = search(
                self.lab,
                f'index=cisco_meraki source="{association_source}" | stats count',
                "0",
                "+10y",
            )
            if visible and int(visible[0].get("count", 0)) == 1:
                break
            if time.monotonic() >= deadline:
                self.fail("mid-flow client association did not become searchable")
            time.sleep(1)

        received, _ = search(
            self.lab,
            f'index=cisco_meraki source="{association_source}" | stats max(_indextime) AS latest',
            "0",
            "+10y",
        )
        self.assertTrue(received and received[0].get("latest"))
        index_bounds = (index_start, int(float(received[0]["latest"])) + 1)
        dispatch(
            self.lab,
            "ADM - Network client history builder",
            index_bounds,
            ("0", "+10y"),
        )
        history, _ = search(
            self.lab,
            "| inputlookup strict=true adm_network_client_history "
            f'| search native_id="{competitor_mac.lower()}" client_ip="{self.client_ip}" '
            f"| table _key source_time native_id scope cluster mapping_status",
            "0",
            "+10y",
        )
        self.assertEqual(len(history), 1, history)
        self.assertEqual(history[0].get("scope"), self.scope)
        self.assertEqual(history[0].get("cluster"), self.cluster)
        self.assertEqual(history[0].get("mapping_status"), "mapped")
        originals, _ = search(
            self.lab,
            "| inputlookup strict=true adm_network_client_history "
            '| search source="meraki_association" client_mac="02:71:00:00:00:21" '
            f'AND scope="{self.scope}" AND cluster="{self.cluster}" '
            "| stats values(native_id) AS native_ids",
            "0",
            "+10y",
        )
        original_ids = originals[0].get("native_ids", []) if originals else []
        if isinstance(original_ids, str):
            original_ids = [original_ids]
        self.assertTrue(original_ids, "fixture lacks the original client identity")
        self.assertNotIn(history[0].get("native_id"), original_ids)
        self.history_keys.append(str(history[0]["_key"]))
        return str(history[0]["_key"])

    def _delete_history_keys(self, keys: list[str]) -> None:
        if not keys:
            return
        query = urllib.parse.urlencode({"query": json.dumps({"_key": {"$in": keys}})})
        response = self.lab._mgmt(
            "DELETE",
            f"/servicesNS/nobody/{self.lab.APP}/storage/collections/data/adm_network_client_history?{query}",
        )
        response.close()
        self.history_keys = [key for key in self.history_keys if key not in keys]

    def _assert_context_client_mac(self, observation_id: str, mac: str) -> None:
        rows, _ = search(
            self.lab,
            '`adm_graph_traffic_context_v2("checkout","demo","cilium-nxos-west","shop")` '
            f'| search traffic_observation_id="{observation_id}"',
            "0",
            "+10y",
        )
        edges = [row for row in rows if row.get("row_type") == "edge"]
        self.assertEqual(len(edges), 1, edges)
        clients = [
            row
            for row in rows
            if row.get("row_type") == "node"
            and row.get("id") == edges[0].get("source")
            and row.get("endpoint_kind") == "network_client"
        ]
        self.assertEqual(len(clients), 1, clients)
        self.assertEqual(clients[0].get("attr_client_mac"), mac)

    def test_partial_source_destination_and_client_ownership_fail_closed(self):
        positive = self._positive_context_fixture()
        observation_id, first, last = self._load_long_flow_and_build(positive)
        self._assert_context_count(observation_id, 1)

        # Any same-scope source identity claim overlapping only the leading or
        # trailing portion must invalidate the previously positive correlation.
        self._check_identity_interval_cases(
            observation_id, positive["source_ip"], first, last, side="source"
        )
        # The normal fixture supplies a full destination service owner; partial
        # pod ownership conflicts must be rejected against that owner.
        self._check_identity_interval_cases(
            observation_id, positive["destination_ip"], first, last, side="destination"
        )

        # A second supported Meraki identity begins halfway through this
        # ten-second flow. A different valid MAC can be excluded by the actual
        # flow MAC, while an IP-only flow remains unresolved.
        valid_competitor_key = self._load_midflow_competing_client(first)
        self._assert_context_count(observation_id, 1)
        self._assert_context_client_mac(observation_id, self.client_mac)
        ip_only_id, _, _ = self._load_long_flow_and_build(
            positive, include_source_mac=False
        )
        self._assert_context_count(ip_only_id, 0)

        # A malformed candidate MAC cannot be used to disambiguate a valid
        # flow MAC. Remove the valid competitor history row and build only the
        # newly indexed malformed association in the next interval.
        self._delete_history_keys([valid_competitor_key])
        malformed_key = self._load_midflow_competing_client(
            first, competitor_mac="not-a-mac"
        )
        malformed_rows, _ = search(
            self.lab,
            "| inputlookup strict=true adm_network_client_history "
            f'| search _key="{malformed_key}" | table client_mac client_ip mapping_status',
            "0",
            "+10y",
        )
        self.assertEqual(len(malformed_rows), 1, malformed_rows)
        self.assertFalse(malformed_rows[0].get("client_mac"))
        malformed_candidate_id, _, _ = self._load_long_flow_and_build(positive)
        self._assert_context_count(malformed_candidate_id, 0)

    def test_traffic_evidence_drilldown_returns_stored_scope_columns(self):
        positive = self._positive_context_fixture()
        observation_id, _, _ = self._load_long_flow_and_build(positive)
        stored, _ = search(
            self.lab,
            'index=adm_summary_v2 source="adm:traffic_observation" '
            f'rollup_id="{observation_id}" | table source_ip destination_ip '
            "server_port transport traffic_observations adm_scope_source "
            "adm_scope_authority adm_scope_observation_domain_present "
            "adm_scope_observation_domain_id adm_scope_vpn_id adm_profile_status",
            "0",
            "+10y",
        )
        self.assertEqual(len(stored), 1, stored)
        summary = stored[0]
        blob = json.loads(summary["traffic_observations"])[0]
        self.assertTrue(summary["adm_scope_authority"])
        self.assertEqual(summary["adm_scope_authority"], blob["source_authority"])
        self.assertEqual(summary["adm_profile_status"], blob["mapping_status"])

        rows, _ = search(
            self.lab,
            f'`adm_traffic_evidence_v2("{summary["source_ip"]}",'
            f'"{summary["destination_ip"]}",{summary["server_port"]},'
            f'"{summary["transport"]}","{observation_id}")`',
            "0",
            "+10y",
        )
        self.assertEqual(len(rows), 1, rows)
        row = rows[0]
        self.assertEqual(row["source"], summary["adm_scope_source"])
        self.assertNotEqual(row["source"], "adm:traffic_observation")
        self.assertEqual(row["source_authority"], summary["adm_scope_authority"])
        self.assertEqual(
            row["observation_domain_present"],
            summary["adm_scope_observation_domain_present"],
        )
        self.assertEqual(
            row["observation_domain_id"], summary["adm_scope_observation_domain_id"]
        )
        self.assertEqual(row.get("vpn_id", ""), summary.get("adm_scope_vpn_id", ""))
        self.assertTrue(row["profile"])
        self.assertEqual(row["profile"], blob["profile"])
        self.assertEqual(row["mapping_status"], summary["adm_profile_status"])
        self.assertEqual(row["mapping_status"], "mapped")


if __name__ == "__main__":
    unittest.main()
