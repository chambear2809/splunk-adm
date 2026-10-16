"""Regression checks for ACI relation lookback outside an identity index slice.

The tests are live-lab checks only.  They do not start, reset, or purge the
lab; each case uses a unique endpoint address and EPG so retained KV rows do
not affect another run.
"""

from __future__ import annotations

import json
import os
import time
import unittest
import urllib.parse
import uuid
from pathlib import Path


HERE = Path(__file__).resolve().parent


@unittest.skipUnless(
    os.environ.get("ADM_LAB") == "1", "set ADM_LAB=1 with the lab running"
)
class NetworkIndexWindowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import sys

        sys.path.insert(0, str(HERE))
        import lab

        cls.lab = lab

    @staticmethod
    def _event(
        event: str, *, timestamp: float, marker: str, sourcetype: str = "cisco:dc:aci:class"
    ) -> dict:
        return {
            "time": timestamp,
            "host": marker,
            "source": "cisco_nexus_aci://class",
            "sourcetype": sourcetype,
            "index": "cisco_dc",
            "event": event,
        }

    @classmethod
    def _load(cls, events: list[dict]) -> None:
        path = Path("/tmp/adm-index-window-%s.ndjson" % uuid.uuid4().hex)
        path.write_text("\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8")
        try:
            cls.lab.load([path])
        finally:
            path.unlink(missing_ok=True)

    @classmethod
    def _indexed_time(cls, marker: str) -> int:
        rows = cls.lab.search(
            '| search index=cisco_dc host="%s" | stats max(_indextime) AS indexed' % marker,
            0,
            "now",
        )
        return int(float(rows[0]["indexed"]))

    @classmethod
    def _dispatch_identity(cls, index_window: tuple[int, int]) -> list[dict]:
        data = {
            "trigger_actions": "0",
            "dispatch.earliest_time": "-24h",
            "dispatch.latest_time": "+15m",
            "dispatch.index_earliest": str(index_window[0]),
            "dispatch.index_latest": str(index_window[1]),
        }
        path = (
            "/servicesNS/nobody/splunk_adm/saved/searches/"
            + urllib.parse.quote("ADM - Identity builder", safe="")
            + "/dispatch?output_mode=json"
        )
        with cls.lab._mgmt("POST", path, data) as response:
            sid = json.loads(response.read())["sid"]
        cls.lab._wait_job(sid)
        return cls.lab._results(sid)

    def _wait_indexed(self, marker: str) -> int:
        deadline = time.time() + 120
        while time.time() < deadline:
            rows = self.lab.search(
                '| search index=cisco_dc host="%s" | stats max(_indextime) AS indexed'
                % marker,
                0,
                "now",
            )
            if rows and rows[0].get("indexed"):
                return int(float(rows[0]["indexed"]))
            time.sleep(2)
        self.fail("timed out waiting for %s to index" % marker)

    def _assert_identity(
        self, ip: str, *, expect_bd: str | None, present: bool = True
    ) -> None:
        rows = self.lab.search(
            '| inputlookup adm_ip_identity where ip="%s" | table ip scope attr_bridge_domain attr_vlan'
            % ip,
            0,
            "now",
        )
        if not present:
            self.assertEqual(rows, [], rows)
            return
        self.assertEqual(len(rows), 1, rows)
        if expect_bd is None:
            self.assertIsNone(rows[0].get("attr_bridge_domain"))
        else:
            self.assertEqual(rows[0].get("attr_bridge_domain"), expect_bd)

    def test_prior_relation_is_visible_to_narrow_current_builder_slice(self):
        suffix = uuid.uuid4().hex[:8]
        marker = "index-window-" + suffix
        old_ip = "198.18.250.10"
        fresh_ip = "198.18.250.11"
        epg = "epg-late-" + suffix
        old_dn = "uni/tn-test/ap-app/epg-old-%s/cep-00:00:00:00:00:10" % suffix
        fresh_dn = "uni/tn-test/ap-app/%s/cep-00:00:00:00:00:11" % epg
        relation_dn = "uni/tn-test/ap-app/%s/rsbd" % epg
        now = time.time()
        old_events = [
            self._event(
                'dn="%s" encap="vlan-3990" ip=%s mac="00:00:00:00:00:10" '
                'addr=%s component="fvCEp" apic_host="192.0.2.250" state="formed"'
                % (old_dn, old_ip, old_ip),
                timestamp=now,
                marker=marker,
            ),
            self._event(
                'dn="%s" tDn="uni/tn-test/BD-bd-late" tnFvBDName="bd-late" '
                'state="formed" component="fvRsBd" apic_host="192.0.2.250"'
                % relation_dn,
                timestamp=now,
                marker=marker,
            ),
        ]
        self._load(old_events)
        old_index = self._wait_indexed(marker)
        while int(time.time()) <= old_index:
            time.sleep(1)
        fresh_event = self._event(
            'dn="%s" encap="vlan-3991" ip=%s mac="00:00:00:00:00:11" '
            'addr=%s component="fvCEp" apic_host="192.0.2.250" state="formed"'
            % (fresh_dn, fresh_ip, fresh_ip),
            timestamp=time.time(),
            marker=marker,
        )
        self._load([fresh_event])
        fresh_index = self._wait_indexed(marker)
        self.assertGreater(fresh_index, old_index)
        self._dispatch_identity((old_index + 1, fresh_index + 1))

        self._assert_identity(fresh_ip, expect_bd="bd-late")
        self._assert_identity(old_ip, expect_bd=None, present=False)

    def test_old_relation_event_time_is_not_used_after_freshness_window(self):
        suffix = uuid.uuid4().hex[:8]
        marker = "index-window-stale-" + suffix
        ip = "198.18.250.12"
        epg = "epg-stale-" + suffix
        relation_dn = "uni/tn-test/ap-app/%s/rsbd" % epg
        endpoint_dn = "uni/tn-test/ap-app/%s/cep-00:00:00:00:00:12" % epg
        now = time.time()
        self._load(
            [
                self._event(
                    'dn="%s" tDn="uni/tn-test/BD-bd-stale" tnFvBDName="bd-stale" '
                    'state="formed" component="fvRsBd" apic_host="192.0.2.251"'
                    % relation_dn,
                    timestamp=now - 2 * 300 - 30,
                    marker=marker,
                )
            ]
        )
        old_index = self._wait_indexed(marker)
        while int(time.time()) <= old_index:
            time.sleep(1)
        self._load(
            [
                self._event(
                    'dn="%s" encap="vlan-3992" ip=%s mac="00:00:00:00:00:12" '
                    'addr=%s component="fvCEp" apic_host="192.0.2.251" state="formed"'
                    % (endpoint_dn, ip, ip),
                    timestamp=time.time(),
                    marker=marker,
                )
            ]
        )
        fresh_index = self._wait_indexed(marker)
        self.assertGreater(fresh_index, old_index)
        self._dispatch_identity((old_index + 1, fresh_index + 1))
        self._assert_identity(ip, expect_bd=None)

