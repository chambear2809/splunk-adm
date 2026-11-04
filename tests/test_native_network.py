import json
import unittest

from splunk_app.splunk_adm.bin.adm_identity_lib.native_network import (
    NativeEvidenceError,
    normalize_records,
    validate_profiles,
)


HUBBLE = {
    "id": "cilium-lab",
    "kind": "hubble",
    "index": "k8s",
    "source": "/var/run/cilium/hubble/",
    "sourcetype": "cilium:hubble:flow",
    "scope": "k8-fabrix-ai-pod-network",
    "cluster": "K8-Fabrix-AI",
    "owner_scope": "k8-fabrix-ai-pod-network",
    "observers": ["appd-k8-5"],
}
NETFLOW = {
    "id": "vds-13",
    "kind": "netflow",
    "index": "netflow",
    "source": "stream:netflow",
    "sourcetype": "stream:netflow",
    "scope": "CV",
    "cluster": "K8-Fabrix-AI",
    "exporter_ip": "10.110.253.13",
    "netflow_version": 10,
    "observation_domain_present": True,
    "observation_domain_id": 0,
}
IDENTITY = {"cluster": "K8-Fabrix-AI", "owner_scope": "k8-fabrix-ai-pod-network"}


def row(profile, raw, **extra):
    return {
        "index": profile["index"],
        "source": profile["source"],
        "sourcetype": profile["sourcetype"],
        "event_time": 10.0,
        "receipt_time": 10.5,
        "_bkt": "b",
        "_cd": "c",
        "host": "appd-k8-5",
        "k8s.cluster.name": "K8-Fabrix-AI",
        "_raw": json.dumps(raw),
        **extra,
    }


class NativeNetworkTests(unittest.TestCase):
    def test_profile_guards_and_present_zero_domain(self):
        self.assertEqual(validate_profiles([HUBBLE], IDENTITY)[0]["id"], "cilium-lab")
        with self.assertRaises(NativeEvidenceError):
            validate_profiles([HUBBLE, {**HUBBLE, "id": "other"}], IDENTITY)
        with self.assertRaises(NativeEvidenceError):
            validate_profiles([{**HUBBLE, "source": "stream:* | search"}], IDENTITY)

    def test_hubble_scalar_parsing_to_stack_and_no_nat(self):
        raw = {
            "time": "2026-11-03T12:00:10.000Z",
            "node_name": "appd-k8-5",
            "flow": {
                "Type": "L3_L4",
                "time": "2026-11-03T12:00:10.000Z",
                "node_name": "appd-k8-5",
                "IP": {
                    "source": "10.0.0.1",
                    "destination": "10.0.0.2",
                    "source_xlated": "192.0.2.1",
                },
                "l4": {"TCP": {"source_port": 1234, "destination_port": 443}},
                "source": {"namespace": "a", "pod_name": "p"},
                "destination": {"namespace": "b", "pod_name": "q"},
                "trace_observation_point": "TO_STACK",
                "traffic_direction": "INGRESS",
                "verdict": "FORWARDED",
            },
        }
        item = row(HUBBLE, raw, event_time=1793707210.0, receipt_time=1793707210.5)
        result = normalize_records([item], [HUBBLE], 1793707209, 1793707211)
        self.assertEqual(result["records"][0]["observation_point"], "TO_STACK")
        self.assertIsNone(result["records"][0]["raw_bytes"])

    def test_netflow_raw_clocks_protocol_and_replay(self):
        raw = {
            "timestamp": "2026-11-03T12:00:09Z",
            "endtime": "2026-11-03T12:00:10Z",
            "exporter_ip": "10.110.253.13",
            "netflow_version": 10,
            "observation_domain_id": 0,
            "src_ip": "10.0.0.1",
            "dest_ip": "10.0.0.2",
            "src_port": 1,
            "dest_port": 2,
            "protoid": 6,
            "bytes_in": 2,
            "packets_in": 1,
        }
        item = row(
            NETFLOW,
            raw,
            event_time=1793707210.0,
            receipt_time=1793707210.5,
            host=None,
            **{"k8s.cluster.name": None},
        )
        result = normalize_records(
            [item, dict(item)], [NETFLOW], 1793707209, 1793707211
        )
        self.assertEqual(len(result["records"]), 1)
        self.assertEqual(result["records"][0]["observation_domain_id"], 0)

    def test_same_provenance_selects_exact_netflow_authority_and_numeric_metadata(self):
        alt = {**NETFLOW, "id": "vds-14", "exporter_ip": "10.110.253.14"}
        raw = {
            "timestamp": "2026-11-03T12:00:09Z",
            "endtime": "2026-11-03T12:00:10Z",
            "exporter_ip": "10.110.253.14",
            "netflow_version": 10,
            "observation_domain_id": 0,
            "src_ip": "10.0.0.1",
            "dest_ip": "10.0.0.2",
            "src_port": 0,
            "dest_port": 2,
            "protoid": 17,
        }
        item = row(
            NETFLOW,
            raw,
            event_time="1793707210.0",
            receipt_time="1793707210.5",
            host=None,
            **{"k8s.cluster.name": None},
        )
        result = normalize_records([item], [NETFLOW, alt], 1793707209, 1793707211)
        self.assertEqual(result["records"][0]["profile_id"], "vds-14")

    def test_malformed_json_duplicate_keys_and_missing_provenance_excluded(self):
        bad = row(HUBBLE, {})
        bad["_raw"] = '{"flow":1,"flow":2}'
        missing = dict(bad)
        missing.pop("_bkt")
        result = normalize_records([bad, missing], [HUBBLE], 0, 20)
        self.assertEqual(len(result["records"]), 0)
        self.assertGreaterEqual(sum(result["excluded"].values()), 2)

    def test_raw_budget_and_deep_json_fail_closed(self):
        huge = row(HUBBLE, {})
        huge["_raw"] = "{" + '"x":{' * 2000 + "null" + "}" * 2000
        deep = row(HUBBLE, {}, _cd="deep")
        deep["_raw"] = "{" + '"x":{' * 20000 + "null" + "}" * 20000
        result = normalize_records([huge, deep], [HUBBLE], 0, 20)
        self.assertEqual(result["records"], [])

    def test_non_object_raw_and_invalid_conflicting_replay_raise(self):
        array_row = row(NETFLOW, [])
        self.assertEqual(
            normalize_records([array_row], [NETFLOW], 0, 20)["records"], []
        )
        first = row(NETFLOW, {"bad": 1})
        second = dict(first)
        second["_raw"] = json.dumps({"bad": 2})
        with self.assertRaises(NativeEvidenceError):
            normalize_records([first, second], [NETFLOW], 0, 20)

    def test_conflicting_replay_precedes_all_exclusion_paths_in_both_orders(self):
        raw = {
            "timestamp": "1970-01-01T00:00:09Z",
            "endtime": "1970-01-01T00:00:10Z",
            "exporter_ip": "10.110.253.13",
            "netflow_version": 10,
            "observation_domain_id": 0,
            "src_ip": "10.0.0.1",
            "dest_ip": "10.0.0.2",
            "src_port": 1234,
            "dest_port": 443,
            "protoid": 6,
        }
        valid = row(NETFLOW, raw)
        self.assertEqual(
            len(normalize_records([valid], [NETFLOW], 0, 20)["records"]), 1
        )
        variants = [{"_raw": body} for body in ["[]", "null", "{bad json", "{}"]]
        variants += [{"receipt_time": 21}, {"source": "unknown"}, {"host": "other"}]
        conflicts = [dict(valid, **variant) for variant in variants]
        for field in ["event_time", "receipt_time", "source"]:
            variant = dict(valid)
            del variant[field]
            conflicts.append(variant)
        for conflict in conflicts:
            for pair in [[valid, conflict], [conflict, valid]]:
                with (
                    self.subTest(conflict=conflict, first_valid=pair[0] is valid),
                    self.assertRaisesRegex(
                        NativeEvidenceError, "conflicting replay evidence"
                    ),
                ):
                    normalize_records(pair, [NETFLOW], 0, 20)

    def test_netflow_icmpv6_ports_and_malformed_annotations(self):
        raw = {
            "timestamp": "1970-01-01T00:00:09Z",
            "endtime": "1970-01-01T00:00:10Z",
            "exporter_ip": "10.110.253.13",
            "netflow_version": 10,
            "observation_domain_id": 0,
            "src_ip": "2001:db8::1",
            "dest_ip": "2001:db8::2",
            "src_port": 0,
            "dest_port": 0,
            "protoid": 58,
        }
        valid = row(NETFLOW, raw)
        record = normalize_records([valid], [NETFLOW], 0, 20)["records"][0]
        self.assertIsNone(record["source_port"])
        self.assertIsNone(record["destination_port"])
        for invalid in [[], {}, True, "x" * 256]:
            result = normalize_records(
                [row(NETFLOW, dict(raw, flow_dir=invalid))], [NETFLOW], 0, 20
            )
            self.assertEqual(result["records"], [])

    def test_conflicting_multivalue_metadata_and_bool_domain_rejected(self):
        raw = {
            "timestamp": "2026-11-03T12:00:09Z",
            "endtime": "2026-11-03T12:00:10Z",
            "exporter_ip": "10.110.253.13",
            "netflow_version": 10,
            "observation_domain_id": True,
            "src_ip": "10.0.0.1",
            "dest_ip": "10.0.0.2",
            "src_port": 1,
            "dest_port": 2,
            "protoid": 6,
        }
        item = row(
            NETFLOW,
            raw,
            event_time=1793707210.0,
            receipt_time=1793707210.5,
            host=["h1", "h2"],
            **{"k8s.cluster.name": None},
        )
        result = normalize_records([item], [NETFLOW], 1793707209, 1793707211)
        self.assertEqual(result["records"], [])

    def test_icmp_has_no_ports_and_malformed_l4_is_excluded(self):
        raw = {
            "time": "2026-11-03T12:00:10Z",
            "node_name": "appd-k8-5",
            "flow": {
                "Type": "L3_L4",
                "time": "2026-11-03T12:00:10Z",
                "node_name": "appd-k8-5",
                "IP": {"source": "2001:db8::1", "destination": "2001:db8::2"},
                "l4": {"ICMPv6": {}},
                "source": {},
                "destination": {},
                "verdict": "DROPPED",
            },
        }
        item = row(HUBBLE, raw, event_time=1793707210.0, receipt_time=1793707210.5)
        result = normalize_records([item], [HUBBLE], 1793707209, 1793707211)
        self.assertEqual(result["records"][0]["transport"], "IPv6-ICMP")
        raw["flow"]["l4"] = {"TCP": None}
        self.assertEqual(
            normalize_records(
                [row(HUBBLE, raw, event_time=1793707210.0, receipt_time=1793707210.5)],
                [HUBBLE],
                1793707209,
                1793707211,
            )["records"],
            [],
        )


if __name__ == "__main__":
    unittest.main()
