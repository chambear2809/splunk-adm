"""Checks for local Cisco scenario loading; no Splunk service is contacted."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from tools.load_networking_lab import (
    COLLECTIONS,
    PROFILE_KEY,
    _lookup,
    dispatch,
    raw_window,
    seed_profiles,
    wait_summary_readback,
)


class NetworkingLabLoaderTest(unittest.TestCase):
    def test_disposable_reset_clears_both_catalog_generations(self):
        self.assertIn("adm_app_catalog", COLLECTIONS)
        self.assertIn("adm_app_catalog_v2", COLLECTIONS)
        self.assertEqual(len(COLLECTIONS), len(set(COLLECTIONS)))

    def test_summary_waits_for_exact_searchable_records(self):
        row = {
            "rollup_id": "a" * 64,
            "contract_version": "2",
            "adm_record": "conversation",
            "records": "1",
        }
        with (
            patch(
                "tools.load_networking_lab.search", side_effect=[([], {}), ([row], {})]
            ) as query,
            patch("tools.load_networking_lab.time.sleep"),
        ):
            wait_summary_readback(None, "ADM - Conversation rollup v2", [row])
            self.assertEqual(query.call_count, 2)
        with patch(
            "tools.load_networking_lab.search",
            return_value=([{**row, "records": ["1", "2"]}], {}),
        ):
            with self.assertRaises(RuntimeError):
                wait_summary_readback(None, "ADM - Conversation rollup v2", [row])
        with self.assertRaises(RuntimeError):
            wait_summary_readback(
                None, "ADM - Conversation rollup v2", [{**row, "rollup_id": ""}]
            )

    def test_profile_hash_casts_each_dimension_inside_json_array(self):
        row = dict.fromkeys(PROFILE_KEY, "")
        row.update(source="stream_ipfix", observation_domain_present="0")
        with patch(
            "tools.load_networking_lab.search", return_value=([row], {})
        ) as query:
            _lookup(None, "adm_network_source_scope", [row], PROFILE_KEY)
        expression = ",".join(
            f'tostring(coalesce({field}, ""))' for field in PROFILE_KEY
        )
        self.assertIn(
            f"mapping_key=sha256(json_array({expression}))", query.call_args.args[1]
        )

    def test_dispatch_refuses_active_schedule_and_keeps_unknown_job_stopped(self):
        lab = Mock()
        lab._json.return_value = {
            "entry": [{"content": {"disabled": False, "is_scheduled": True}}]
        }
        with self.assertRaises(RuntimeError):
            dispatch(lab, "builder", (100, 200), ("0", "300"))
        self.assertEqual(lab._json.call_count, 1)
        lab.reset_mock()

        def request(method, path, data=None):
            if method == "GET":
                return {
                    "entry": [{"content": {"disabled": True, "is_scheduled": True}}]
                }
            if path.endswith("/dispatch"):
                self.assertEqual(data["trigger_actions"], "0")
                return {"sid": "known-test-sid"}
            return {}

        lab._json.side_effect = request
        lab._wait_job.side_effect = TimeoutError("unknown outcome")
        with (
            tempfile.TemporaryDirectory() as directory,
            patch("tools.load_networking_lab.ROOT", Path(directory)),
        ):
            with self.assertRaises(TimeoutError):
                dispatch(lab, "builder", (100, 200), ("0", "300"))
            state = json.loads(
                (Path(directory) / "dist/cisco-lab-dispatch.json").read_text()
            )
        self.assertEqual(state["state"], "unresolved")
        self.assertEqual(state["sid"], "known-test-sid")
        self.assertEqual(
            lab._json.call_args.args[2], {"disabled": "1", "is_scheduled": "0"}
        )

    def test_raw_window_includes_baseline_inventory_and_exclusive_latest(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.ndjson"
            path.write_text("\n".join(json.dumps({"time": n}) for n in (10.5, 8, 20)))
            self.assertEqual(raw_window([path]), ("8", "21"))
            for value in (True, -1, "20", None, float("nan")):
                path.write_text(json.dumps({"time": value}))
                with self.subTest(value=value), self.assertRaises(ValueError):
                    raw_window([path])

    def test_duplicate_profile_configuration_is_refused_before_write(self):
        with patch("tools.load_networking_lab.search") as search:
            with self.assertRaises(ValueError):
                _lookup(None, "adm_observer_scope", [{"a": "x"}, {"a": "x"}], ("a",))
            search.assert_not_called()

    def test_duplicate_native_serial_scope_is_case_normalized_before_write(self):
        rows = [
            {"observer_kind": kind, "observer": observer, "scope": scope}
            for kind, observer, scope in (
                ("NXOS_SERIAL", '["collector","ABC123"]', "east"),
                ("nxos_serial", '["collector","abc123"]', "west"),
            )
        ]
        with patch("tools.load_networking_lab.search") as search:
            with self.assertRaises(ValueError):
                _lookup(None, "adm_observer_scope", rows, ("observer_kind", "observer"))
            search.assert_not_called()

    def test_cluster_settings_are_explicit_without_global_inheritance(self):
        profiles = {
            "network_source_scope": [{"source": "test"}],
            "legacy_observer_scope": [{"observer": "test"}],
            "clusters": [
                {
                    "name": "east",
                    "cilium": {
                        "loadBalancerMode": "snat",
                        "ingressMode": "dedicated",
                        "l2announcementsEnabled": False,
                    },
                }
            ],
        }
        with patch("tools.load_networking_lab._lookup") as lookup:
            seed_profiles(None, profiles)
            self.assertEqual(
                lookup.call_args.args[1:],
                (
                    "adm_cilium_cluster_settings",
                    [
                        {
                            "cluster": "east",
                            "lb_mode": "snat",
                            "ingress_mode": "dedicated",
                            "l2announcements_enabled": 0,
                            "mapping_status": "mapped",
                        }
                    ],
                    ("cluster",),
                ),
            )
        del profiles["clusters"][0]["cilium"]["loadBalancerMode"]
        with patch("tools.load_networking_lab._lookup"), self.assertRaises(KeyError):
            seed_profiles(None, profiles)
