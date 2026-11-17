"""Synthetic-only tests of offline replay sanitization; no Cloud or private inputs."""

import copy
import json
import unittest
from unittest import mock

from tools import sanitize_feature_replay as sanitizer
from splunk_app.splunk_adm.bin.adm_identity_lib.native_network import validate_profiles
from splunk_app.splunk_adm.bin.adm_identity_lib.qualified import profile_config
from tests.test_qualified_identity import PROFILE
from tests.test_qualified_rollup import NETWORK

KEY = b"test-key-material-is-at-least-32-bytes"
WINDOW = {"start": 100, "end": 120}
REPLAY = {"start": 10, "end": 30}


def source():
    flow = {
        "node_name": "cluster-a/node-a",
        "time": "1970-01-01T00:01:50.123456789Z",
        "flow_start_time_milli": 110123,
        "flow_end_time_milli": 111123,
        "secret": "sensitive outer",
        "flow": {
            "time": "1970-01-01T00:01:51.123456789Z",
            "node_name": "cluster-a/node-b",
            "Type": "L3_L4",
            "event_type": {"type": 4, "sub_type": 2, "secret": "event-secret"},
            "trace_observation_point": "TO_STACK",
            "traffic_direction": "INGRESS",
            "is_reply": False,
            "verdict": "DROPPED",
            "IP": {
                "source": "10.0.0.1",
                "destination": "2001:db8:ffff::2",
                "source_xlated": "private",
            },
            "l4": {
                "TCP": {
                    "source_port": 0,
                    "destination_port": 443,
                    "flags": {"SYN": True},
                    "other": "password",
                }
            },
            "source": {
                "namespace": "shop",
                "pod_name": "pod-a",
                "workloads": [
                    {"name": "checkout", "kind": "Deployment"},
                    {"name": "checkout", "kind": "Deployment"},
                ],
            },
            "destination": {"namespace": "shop", "pod_name": "pod-b"},
            "http": {"url": "https://secret"},
        },
    }
    pod = {
        "type": "ADDED",
        "resourceVersion": "99",
        "metadata": {"namespace": "shop", "name": "outer", "uid": "outer-uid"},
        "object": {
            "metadata": {
                "namespace": "shop",
                "name": "pod-a",
                "uid": "uid-a",
                "resourceVersion": "100",
                "creationTimestamp": "1970-01-01T00:01:50.123456789Z",
                "deletionTimestamp": None,
                "labels": {"secret": "leak"},
                "ownerReferences": [
                    {
                        "name": "checkout",
                        "kind": "Deployment",
                        "uid": "uid-owner",
                        "controller": True,
                    }
                ],
            },
            "spec": {
                "nodeName": "node-a",
                "hostNetwork": False,
                "containers": [{"image": "SECRET"}],
            },
            "status": {
                "phase": "Running",
                "podIPs": [{"ip": "10.0.0.1"}, {"ip": "10.0.0.1"}],
                "conditions": [
                    {
                        "type": "Ready",
                        "status": "False",
                        "lastTransitionTime": "1970-01-01T00:01:51.123456789Z",
                        "message": "TOKEN",
                    }
                ],
            },
        },
    }

    def row(raw, sourcetype, index, host):
        return {
            "_raw": json.dumps(raw),
            "_time": 110,
            "_indextime": 112,
            "index": index,
            "source": "hubble-path" if sourcetype.startswith("cilium") else "pod-path",
            "sourcetype": sourcetype,
            "host": host,
            "k8s.cluster.name": "cluster-a",
            "_bkt": "bucket",
            "_cd": "offset",
            "secret": "row-secret",
        }

    return {
        "hubble": [row(flow, "cilium:hubble:flow", "hubble", "node-a")],
        "pods": [row(pod, "kube:object:pods", "k8s", "node-a")],
    }


class SanitizerTests(unittest.TestCase):
    def sanitize(self, families=None, **kwargs):
        return sanitizer.sanitize(
            source() if families is None else families,
            key=KEY,
            original_window=WINDOW,
            replay_window=REPLAY,
            **kwargs,
        )

    def test_projects_safe_fields_preserves_relationships_and_contradictions(self):
        identity = copy.deepcopy(PROFILE)
        network = copy.deepcopy(NETWORK["profiles"][0])
        network["source"] = "hubble-path"
        output = self.sanitize(identity_profile=identity, network_profiles=[network])
        hub = output["families"]["hubble"][0]
        pod = output["families"]["pods"][0]
        flow, event = json.loads(hub["_raw"]), json.loads(pod["_raw"])
        identity_out, profile = (
            output["identity_profile"],
            output["network_profiles"][0],
        )
        profile_config(identity_out)
        validate_profiles([profile], identity_out)
        self.assertEqual(hub["index"], profile["index"])
        self.assertEqual(hub["source"], profile["source"])
        self.assertEqual(hub["host"], profile["observers"][0])
        self.assertEqual(flow["node_name"].split("/")[1], hub["host"])
        self.assertNotEqual(flow["node_name"], flow["flow"]["node_name"])
        self.assertEqual(
            flow["flow"]["source"]["pod_name"], event["object"]["metadata"]["name"]
        )
        self.assertEqual(
            flow["flow"]["source"]["namespace"],
            event["object"]["metadata"]["namespace"],
        )
        self.assertEqual(
            flow["flow"]["IP"]["source"], event["object"]["status"]["podIPs"][0]["ip"]
        )
        self.assertEqual(
            event["object"]["status"]["podIPs"][0],
            event["object"]["status"]["podIPs"][1],
        )
        self.assertEqual(
            flow["flow"]["source"]["workloads"][0],
            flow["flow"]["source"]["workloads"][1],
        )
        self.assertNotEqual(
            event["metadata"]["name"], event["object"]["metadata"]["name"]
        )
        self.assertIsNone(event["object"]["metadata"]["deletionTimestamp"])
        self.assertNotIn("hostNetwork", event["status"] if "status" in event else {})
        encoded = json.dumps(output)
        for secret in (
            "sensitive outer",
            "password",
            "https://secret",
            "TOKEN",
            "row-secret",
            "10.0.0.1",
            "uid-a",
            "hubble-path",
        ):
            self.assertNotIn(secret, encoded)
        self.assertEqual(flow["flow"]["event_type"], {"type": 4, "sub_type": 2})
        self.assertIn("flow.event_type.type", output["report"]["approved_paths"])
        self.assertEqual(output["report"]["sample_counts"], {"hubble": 1, "pods": 1})
        self.assertNotIn("event-secret", encoded)
        self.assertFalse(output["report"]["complete"])
        self.assertIn("routing", output["report"]["address_class_note"])

    def test_time_shift_preserves_nanoseconds_clock_conflicts_and_order(self):
        output = self.sanitize()
        hub, pod = output["families"]["hubble"][0], output["families"]["pods"][0]
        flow, event = json.loads(hub["_raw"]), json.loads(pod["_raw"])
        self.assertEqual((hub["_time"], hub["_indextime"]), (20, 22))
        self.assertEqual(flow["time"], "1970-01-01T00:00:20.123456789Z")
        self.assertEqual(flow["flow"]["time"], "1970-01-01T00:00:21.123456789Z")
        self.assertEqual(
            (flow["flow_start_time_milli"], flow["flow_end_time_milli"]), (20123, 21123)
        )
        self.assertEqual(
            event["object"]["status"]["conditions"][0]["lastTransitionTime"],
            "1970-01-01T00:00:21.123456789Z",
        )
        self.assertEqual(type(hub["_time"]), int)
        self.assertLess(
            int(event["resourceVersion"]),
            int(event["object"]["metadata"]["resourceVersion"]),
        )

    def test_nulls_unsupported_types_and_duplicate_json_keys(self):
        data = source()
        flow = json.loads(data["hubble"][0]["_raw"])
        flow["flow"]["source"]["pod_name"] = None
        flow["flow"]["destination"].pop("pod_name")
        data["hubble"][0]["_raw"] = json.dumps(flow)
        out = json.loads(self.sanitize(data)["families"]["hubble"][0]["_raw"])["flow"]
        self.assertIsNone(out["source"]["pod_name"])
        self.assertNotIn("pod_name", out["destination"])
        flow["flow"]["is_reply"] = "PRIVATE TOKEN"
        data["hubble"][0]["_raw"] = json.dumps(flow)
        with self.assertRaises(sanitizer.SanitizationError):
            self.sanitize(data)
        data["hubble"][0]["_raw"] = '{"flow":{},"flow":{}}'
        with self.assertRaises(sanitizer.SanitizationError):
            self.sanitize(data)

    def test_invalid_pod_tokens_are_not_repaired_into_valid_identity(self):
        from splunk_app.splunk_adm.bin.adm_identity_lib.protocol import (
            _pod,
            ProtocolError,
        )

        for field in ("name", "namespace", "uid"):
            data = source()
            raw = json.loads(data["pods"][0]["_raw"])
            raw["object"]["metadata"][field] = "invalid token with spaces"
            with self.assertRaises(ProtocolError):
                _pod(raw["object"])
            data["pods"][0]["_raw"] = json.dumps(raw)
            with self.assertRaises(sanitizer.SanitizationError):
                self.sanitize(data)

    def test_noncanonical_ip_never_becomes_accepted_by_sanitization(self):
        from splunk_app.splunk_adm.bin.adm_identity_lib.native_network import (
            _ip,
            NativeEvidenceError,
        )

        for address in ("2001:0db8:0000:0000:0000:0000:0000:0001", "2001:DB8::1"):
            with self.subTest(address=address):
                with self.assertRaises(NativeEvidenceError):
                    _ip(address)
                data = source()
                raw = json.loads(data["hubble"][0]["_raw"])
                raw["flow"]["IP"]["source"] = address
                data["hubble"][0]["_raw"] = json.dumps(raw)
                with self.assertRaises(sanitizer.SanitizationError):
                    self.sanitize(data)

    def test_documented_observation_enum_is_preserved_without_free_text(self):
        for point in (
            "TO_OVERLAY",
            "FROM_OVERLAY",
            "TO_HOST",
            "FROM_HOST",
            "TO_CRYPTO",
            "FROM_CRYPTO",
            "UNKNOWN_POINT",
        ):
            data = source()
            raw = json.loads(data["hubble"][0]["_raw"])
            raw["flow"]["trace_observation_point"] = point
            data["hubble"][0]["_raw"] = json.dumps(raw)
            self.assertEqual(
                json.loads(self.sanitize(data)["families"]["hubble"][0]["_raw"])[
                    "flow"
                ]["trace_observation_point"],
                point,
            )

    def test_domains_ip_collision_and_namespace_context(self):
        aliases = sanitizer.Aliases(KEY)
        self.assertNotEqual(
            aliases.text("pod", "ns-a\0one"), aliases.text("pod", "ns-b\0one")
        )
        self.assertEqual(
            aliases.node("cluster-a/node-a").split("/")[1], aliases.node("node-a")
        )
        self.assertTrue(
            aliases.ip("10.0.0.1").startswith(("192.0.2.", "198.51.100.", "203.0.113."))
        )
        self.assertTrue(aliases.ip("2001:db8:ffff::2").startswith("2001:db8:"))
        with mock.patch.object(aliases, "_digest", return_value=b"x" * 32):
            aliases.text("test", "a")
            with self.assertRaises(sanitizer.SanitizationError):
                aliases.text("test", "b")

    def test_rejects_unvalidated_profiles_keys_windows_and_numeric_loss(self):
        for bad in (b"", b"short"):
            with self.assertRaises(sanitizer.SanitizationError):
                sanitizer.sanitize(
                    {}, key=bad, original_window=WINDOW, replay_window=REPLAY
                )
        with self.assertRaises(sanitizer.SanitizationError):
            self.sanitize(network_profiles=[NETWORK["profiles"][0]])
        with self.assertRaises(sanitizer.SanitizationError):
            self.sanitize(
                identity_profile=PROFILE, network_profiles=[NETWORK["profiles"][1]]
            )
        with self.assertRaises(sanitizer.SanitizationError):
            sanitizer.sanitize(
                {},
                key=KEY,
                original_window=WINDOW,
                replay_window={"start": 10, "end": 31},
            )
        self.assertEqual(
            sanitizer._clock("1970-01-01T01:01:50.123456789+01:00", -90),
            "1970-01-01T01:00:20.123456789+01:00",
        )
        with self.assertRaises(sanitizer.SanitizationError):
            sanitizer._clock(0.1, 100)
        with self.assertRaises(sanitizer.SanitizationError):
            self.sanitize({"hubble": source()["hubble"] * 5})


if __name__ == "__main__":
    unittest.main()


class SyntheticNormalizationTest(unittest.TestCase):
    def test_attested_hubble_profile_survives_consistent_pseudonyms(self):
        from splunk_app.splunk_adm.bin.adm_identity_lib.native_network import (
            normalize_records,
        )

        families = source()
        row = families["hubble"][0]
        raw = json.loads(row["_raw"])
        raw["flow"]["node_name"] = raw["node_name"]
        raw["flow"]["time"] = raw["time"]
        raw["flow_end_time_milli"] = raw["flow_start_time_milli"]
        row["_time"] = "110.123456789"
        row["_raw"] = json.dumps(raw)
        profile = copy.deepcopy(NETWORK["profiles"][0])
        profile["source"] = "hubble-path"
        output = sanitizer.sanitize(
            families,
            key=KEY,
            original_window=WINDOW,
            replay_window=REPLAY,
            identity_profile=PROFILE,
            network_profiles=[profile],
        )
        sanitized = output["families"]["hubble"][0]
        normalized_row = {
            **sanitized,
            "event_time": sanitized["_time"],
            "receipt_time": sanitized["_indextime"],
        }
        normalized = normalize_records(
            [normalized_row], output["network_profiles"], 10, 30
        )
        self.assertEqual(len(normalized["records"]), 1)
        self.assertEqual(normalized["records"][0]["observation_point"], "TO_STACK")


class MinimalIdentityTest(unittest.TestCase):
    def test_actual_minimal_identity_is_not_expanded_or_marked_complete(self):
        profile = copy.deepcopy(NETWORK["profiles"][0])
        profile["source"] = "hubble-path"
        identity = {"enabled": "1", "cluster": "cluster-a", "scope": "scope-a"}
        output = sanitizer.sanitize(
            source(),
            key=KEY,
            original_window=WINDOW,
            replay_window=REPLAY,
            identity_profile=identity,
            network_profiles=[profile],
        )
        self.assertEqual(
            set(output["identity_profile"]), {"enabled", "cluster", "scope"}
        )
        self.assertEqual(output["identity_profile"]["enabled"], "1")
        self.assertEqual(output["report"]["identity_scope"], "limited_native_profile")
        validate_profiles(output["network_profiles"], output["identity_profile"])
        for bad in (
            {**identity, "enabled": False},
            {**identity, "enabled": 1},
            {**identity, "scope": " "},
            {**identity, "owner_scope": None},
        ):
            with self.subTest(bad=bad), self.assertRaises(sanitizer.SanitizationError):
                sanitizer.sanitize(
                    {},
                    key=KEY,
                    original_window=WINDOW,
                    replay_window=REPLAY,
                    identity_profile=bad,
                )
