"""Live history-boundary checks over the combined TA-shaped Cisco scenario.

The extra records are clones of generated Meraki association and Stream IPFIX
events. Only timestamps and existing tuple values are changed to exercise the
history boundaries; no new vendor fields or collector behavior are modeled.
The caller owns the disposable Splunk lab lifecycle and lock.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tools"))
from capture_networking_fixtures import search  # noqa: E402
from lab_lock import LabLock  # noqa: E402
from load_networking_lab import dispatch, initialize  # noqa: E402


PRIMARY_MAC = "02:71:00:00:00:20"
REUSED_MAC = "02:71:00:00:00:21"
CONFLICT_MAC = "02:71:00:00:00:22"
STALE_MAC = "02:71:00:00:00:88"
PRIMARY_IP = "10.71.0.20"
CONFLICT_IP = "10.71.0.22"
STALE_IP = "10.71.0.88"


def _parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    return (
        value.astimezone(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z")
    )


def _epoch(value: datetime) -> float:
    return value.timestamp()


def _clone_flow(
    template: dict,
    anchor: datetime,
    start_offset: float,
    end_offset: float,
    *,
    source_ip: str | None = None,
    source_mac: str | None = None,
) -> dict:
    """Clone a generated Stream event, changing only existing tuple/time fields."""
    clone = json.loads(json.dumps(template))
    event = clone["event"]
    start = anchor + timedelta(seconds=start_offset)
    end = anchor + timedelta(seconds=end_offset)
    event["timestamp"] = _iso(start)
    event["endtime"] = _iso(end)
    if source_ip is not None:
        event["src_ip"] = source_ip
    if source_mac is not None:
        event["src_mac"] = source_mac
    clone["time"] = _epoch(end)
    return clone


def _clone_association_without_ip(template: dict, anchor: datetime) -> dict:
    """Clone an observed association while omitting its documented optional IP."""
    clone = json.loads(json.dumps(template))
    when = anchor + timedelta(seconds=330)
    clone["event"]["occurredAt"] = _iso(when)
    clone["event"]["eventData"].pop("client_ip", None)
    clone["time"] = _epoch(when)
    return clone


@unittest.skipUnless(os.environ.get("ADM_LAB") == "1", "requires disposable Splunk lab")
class CiscoHistoryEdgesLabTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not LabLock(ROOT).check_owned():
            raise RuntimeError("run this suite under tools/lab_lock.py")
        sys.path.insert(0, str(ROOT / "tests/splunk"))
        import lab

        cls.lab = lab
        cls.raw_dir = ROOT / "dist/cisco-history-edge-tests"
        cls.initialized = initialize(
            cls.raw_dir,
            cls.raw_dir / "initialization.json",
            regenerate=True,
        )
        cls.window = tuple(
            cls.initialized["window"][name] for name in ("earliest", "latest")
        )
        cls.build_window = tuple(
            cls.initialized["build_window"][name] for name in ("earliest", "latest")
        )
        cls.anchor = _parse_time(
            json.loads((cls.raw_dir / "capture-manifest.json").read_text())[
                "window_start"
            ]
        )
        cls._load_boundary_clones()

    @classmethod
    def _load_boundary_clones(cls):
        associations = [
            json.loads(line)
            for line in (cls.raw_dir / "meraki_associations.ndjson")
            .read_text()
            .splitlines()
            if line
        ]
        roam = next(
            row
            for row in associations
            if row["event"].get("clientMac") == PRIMARY_MAC
            and row["event"].get("deviceName") == "MR-NXOS-02"
        )
        flows = [
            json.loads(line)
            for line in (cls.raw_dir / "meraki_ms390_ipfix.ndjson")
            .read_text()
            .splitlines()
            if line
        ]
        flow_template = next(
            row
            for row in flows
            if row["event"].get("src_mac") == PRIMARY_MAC
            and row["event"].get("src_ip") == PRIMARY_IP
        )

        # Before and after the +150s roam, plus intervals that must not resolve:
        # one straddles the roam, one follows an association missing client_ip,
        # one is outside stale evidence, and one has simultaneous conflicting claims.
        cloned = [
            _clone_flow(flow_template, cls.anchor, 120, 120.18),
            _clone_flow(flow_template, cls.anchor, 149.9, 150.1),
            _clone_flow(flow_template, cls.anchor, 360, 360.18),
            _clone_flow(
                flow_template,
                cls.anchor,
                500,
                500.18,
                source_ip=STALE_IP,
                source_mac=STALE_MAC,
            ),
            _clone_flow(
                flow_template,
                cls.anchor,
                100,
                100.18,
                source_ip=CONFLICT_IP,
                source_mac=CONFLICT_MAC,
            ),
            _clone_association_without_ip(roam, cls.anchor),
        ]
        clone_path = cls.raw_dir / "history-boundary-clones.ndjson"
        clone_path.write_text(
            "".join(json.dumps(row, separators=(",", ":")) + "\n" for row in cloned)
        )
        if cls.lab.load([clone_path]) != len(cloned):
            raise RuntimeError("did not load every cloned history-boundary event")

        # HEC acknowledges receipt before Splunk has indexed every event. The
        # history builder's index-time bounds must include the last clone, so
        # wait for each intended source path before choosing the upper bound.
        expected_flow_times = {
            str(row["event"]["timestamp"])
            for row in cloned
            if row["sourcetype"] == "stream:netflow"
        }
        expected_history_time = next(
            str(row["event"]["occurredAt"])
            for row in cloned
            if row["sourcetype"] == "meraki:accesspoints"
        )
        deadline = time.monotonic() + 90
        while True:
            flow_rows, _ = search(
                cls.lab,
                'index=netflow sourcetype="stream:netflow" '
                "| spath input=_raw path=timestamp output=timestamp "
                "| spath input=_raw path=src_mac output=src_mac "
                "| where timestamp IN ("
                + ",".join(json.dumps(value) for value in sorted(expected_flow_times))
                + ") AND src_mac IN ("
                + ",".join(
                    json.dumps(value)
                    for value in (PRIMARY_MAC, STALE_MAC, CONFLICT_MAC, REUSED_MAC)
                )
                + ") | stats dc(timestamp) AS visible",
                *cls.window,
            )
            history_rows, _ = search(
                cls.lab,
                'index=cisco_meraki sourcetype="meraki:accesspoints" '
                "| spath input=_raw path=occurredAt output=occurredAt "
                "| spath input=_raw path=clientMac output=clientMac "
                f"| where occurredAt=={json.dumps(expected_history_time)} "
                f"AND clientMac=={json.dumps(PRIMARY_MAC)} | stats count AS visible",
                *cls.window,
            )
            flow_visible = int(flow_rows[0].get("visible", 0) or 0) if flow_rows else 0
            history_visible = (
                int(history_rows[0].get("visible", 0) or 0) if history_rows else 0
            )
            if flow_visible == len(expected_flow_times) and history_visible >= 1:
                break
            if time.monotonic() >= deadline:
                raise RuntimeError(
                    "Splunk did not index every raw history-boundary clone before dispatch"
                )
            time.sleep(1)

        bounds = (
            int(cls.initialized["index_window"][0]),
            int(time.time()) + 1,
        )
        for name in (
            "ADM - Network client history builder",
            "ADM - Traffic observation rollup v2",
        ):
            dispatch(cls.lab, name, bounds, cls.build_window)

    @classmethod
    def _graph(cls):
        rows, _ = search(
            cls.lab,
            '| search `adm_graph_v2("checkout","demo","cilium-nxos-west","shop")`',
            *cls.window,
        )
        return rows

    @staticmethod
    def _observation_payload(edge: dict) -> list[dict]:
        value = edge.get("traffic_observations")
        if isinstance(value, str):
            value = json.loads(value)
        if isinstance(value, dict):
            value = [value]
        return value if isinstance(value, list) else []

    @staticmethod
    def _attachment_name(edge: dict) -> str | None:
        value = edge.get("attachment_evidence")
        if isinstance(value, str):
            value = json.loads(value)
        if isinstance(value, list) and value:
            return value[0].get("device_name")
        return None

    def _raw_flow_timestamps(self, source_mac: str, source_ip: str) -> set[str]:
        rows, _ = search(
            self.lab,
            'index=netflow sourcetype="stream:netflow" '
            "| spath input=_raw path=src_mac output=src_mac "
            "| spath input=_raw path=src_ip output=src_ip "
            "| spath input=_raw path=timestamp output=timestamp "
            f'| where src_mac=="{source_mac}" AND src_ip=="{source_ip}" '
            "| table timestamp",
            *self.build_window,
        )
        return {str(row.get("timestamp")) for row in rows}

    def test_roam_keeps_each_valid_flow_attachment_and_marks_client_node_varied(self):
        raw_timestamps = self._raw_flow_timestamps(PRIMARY_MAC, PRIMARY_IP)
        self.assertIn(_iso(self.anchor + timedelta(seconds=120)), raw_timestamps)
        self.assertIn(_iso(self.anchor + timedelta(seconds=180)), raw_timestamps)
        self.assertIn(_iso(self.anchor + timedelta(seconds=149.9)), raw_timestamps)
        rows = self._graph()
        clients = {
            row.get("attr_client_mac"): row
            for row in rows
            if row.get("row_type") == "node"
            and row.get("endpoint_kind") == "network_client"
        }
        client = clients[PRIMARY_MAC]
        self.assertEqual(client.get("attr_attachment_status"), "varied")
        self.assertEqual(client.get("attr_attachment_device_name"), "varied")

        edges = [
            row
            for row in rows
            if row.get("row_type") == "edge"
            and row.get("relationship") == "traffic_observation"
            and row.get("source") == client.get("id")
        ]
        seen: dict[int, str | None] = {}
        anchor_epoch = _epoch(self.anchor)
        for edge in edges:
            for observation in self._observation_payload(edge):
                start = float(observation.get("first_seen", 0)) - anchor_epoch
                if abs(start - 120) < 1:
                    seen[120] = self._attachment_name(edge)
                elif abs(start - 180) < 1:
                    seen[180] = self._attachment_name(edge)
                self.assertFalse(149.8 <= start <= 150.2, "roam-crossing flow resolved")
                self.assertFalse(
                    359 <= start <= 361, "flow after missing-IP association resolved"
                )

        self.assertEqual(seen.get(120), "MR-NXOS-01")
        self.assertEqual(seen.get(180), "MR-NXOS-02")

    def test_address_reuse_uses_the_second_client_and_its_own_attachment(self):
        rows = self._graph()
        clients = {
            row.get("attr_client_mac"): row
            for row in rows
            if row.get("row_type") == "node"
            and row.get("endpoint_kind") == "network_client"
        }
        first = clients[PRIMARY_MAC]
        second = clients[REUSED_MAC]
        self.assertNotEqual(first.get("id"), second.get("id"))
        self.assertEqual(first.get("addresses"), second.get("addresses"))
        reuse_edges = [
            row
            for row in rows
            if row.get("row_type") == "edge"
            and row.get("relationship") == "traffic_observation"
            and row.get("source") == second.get("id")
        ]
        reuse_observations = [
            observation
            for edge in reuse_edges
            for observation in self._observation_payload(edge)
            if abs(float(observation.get("first_seen", 0)) - _epoch(self.anchor) - 270)
            < 1
        ]
        self.assertTrue(reuse_observations, "generated later IP-reuse flow was absent")
        self.assertTrue(
            any(self._attachment_name(edge) == "MR-NXOS-01" for edge in reuse_edges)
        )

    def test_stale_and_conflicting_claims_remain_unresolved_with_raw_inputs_present(
        self,
    ):
        history, _ = search(
            self.lab,
            '| inputlookup strict=true adm_network_client_history | where source=="meraki_association" AND client_mac IN ("02:71:00:00:00:88","02:71:00:00:00:22") | table client_mac client_ip source_time attachment_device_name',
            *self.build_window,
        )
        stale = [row for row in history if row.get("client_mac") == STALE_MAC]
        conflicting = [row for row in history if row.get("client_mac") == CONFLICT_MAC]
        self.assertEqual(len(stale), 1)
        self.assertEqual(len(conflicting), 2)
        self.assertEqual(
            {row.get("client_ip") for row in conflicting},
            {"10.71.0.22", "10.71.0.23"},
        )
        self.assertEqual(
            {row.get("attachment_device_name") for row in conflicting},
            {"MR-NXOS-01", "MR-NXOS-02"},
        )
        conflict_times = {float(row["source_time"]) for row in conflicting}
        self.assertEqual(len(conflict_times), 1)

        raw, _ = search(
            self.lab,
            'index=netflow sourcetype="stream:netflow" | spath input=_raw path=src_mac output=src_mac | spath input=_raw path=src_ip output=src_ip | stats count by src_mac src_ip',
            *self.build_window,
        )
        self.assertTrue(
            any(
                row.get("src_mac") == STALE_MAC and row.get("src_ip") == STALE_IP
                for row in raw
            )
        )
        self.assertTrue(
            any(
                row.get("src_mac") == CONFLICT_MAC and row.get("src_ip") == CONFLICT_IP
                for row in raw
            )
        )

        rows = self._graph()
        context_sources = {
            row.get("source")
            for row in rows
            if row.get("row_type") == "edge"
            and row.get("relationship") == "traffic_observation"
        }
        context_nodes = {
            row.get("id"): row.get("attr_client_mac")
            for row in rows
            if row.get("row_type") == "node"
            and row.get("endpoint_kind") == "network_client"
        }
        self.assertNotIn(
            STALE_MAC, [context_nodes.get(source) for source in context_sources]
        )
        self.assertNotIn(
            CONFLICT_MAC, [context_nodes.get(source) for source in context_sources]
        )

    def test_missing_optional_association_ip_is_retained_but_does_not_attach_flow(self):
        missing, _ = search(
            self.lab,
            '| inputlookup strict=true adm_network_client_history | where source=="meraki_association" AND client_mac=="02:71:00:00:00:20" AND source_time>0 | table client_mac client_ip source_time attachment_device_name',
            *self.build_window,
        )
        anchor_epoch = _epoch(self.anchor)
        row = next(
            item
            for item in missing
            if abs(float(item["source_time"]) - anchor_epoch - 330) < 1
        )
        self.assertFalse(row.get("client_ip"))
        self.assertEqual(row.get("attachment_device_name"), "MR-NXOS-02")

        self.assertIn(
            _iso(self.anchor + timedelta(seconds=360)),
            self._raw_flow_timestamps(PRIMARY_MAC, PRIMARY_IP),
        )

        rows = self._graph()
        primary = next(
            row
            for row in rows
            if row.get("row_type") == "node"
            and row.get("endpoint_kind") == "network_client"
            and row.get("attr_client_mac") == PRIMARY_MAC
        )
        anchor_epoch = _epoch(self.anchor)
        self.assertFalse(
            any(
                abs(float(observation.get("first_seen", 0)) - anchor_epoch - 360) < 1
                for edge in rows
                if edge.get("row_type") == "edge"
                and edge.get("relationship") == "traffic_observation"
                and edge.get("source") == primary.get("id")
                for observation in self._observation_payload(edge)
            ),
            "flow after the missing-IP event fell back to an older association",
        )
