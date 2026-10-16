"""Regression checks for ACI relation lookback outside an identity index slice.

The tests are live-lab checks only.  They do not start, reset, or purge the
lab; each case uses a unique endpoint address and EPG so retained KV rows do
not affect another run.
"""

from __future__ import annotations

from datetime import datetime, timezone
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

    def _install_scope(self, observer: str, scope: str) -> None:
        self.scope = scope
        row = json.dumps(
            [
                {
                    "observer_kind": "apic",
                    "observer": observer,
                    "scope": scope,
                    "cluster": "",
                }
            ]
        )
        self.lab.search(
            "| inputlookup adm_observer_scope | append [| makeresults format=json data=%s] "
            "| eval observer_kind=lower(observer_kind), observer=lower(observer), "
            "_key=sha256(json_array(observer_kind, observer)) | dedup observer_kind observer "
            "| fields _key observer_kind observer scope cluster | outputlookup adm_observer_scope"
            % json.dumps(row)
        )

    def _cleanup_scope(self, scope: str) -> None:
        query = urllib.parse.urlencode({"query": json.dumps({"scope": scope})})
        for collection in ("adm_ip_identity", "adm_observer_scope"):
            with self.lab._mgmt(
                "DELETE",
                "/servicesNS/nobody/splunk_adm/storage/collections/data/%s?%s"
                % (collection, query),
            ) as response:
                response.read()

    @staticmethod
    def _event(
        event: str,
        *,
        timestamp: float,
        marker: str,
        sourcetype: str = "cisco:dc:aci:class",
    ) -> dict:
        return {
            "time": timestamp,
            "host": marker,
            "source": "cisco_nexus_aci://class",
            "sourcetype": sourcetype,
            "index": "cisco_dc",
            "event": datetime.fromtimestamp(timestamp, timezone.utc).strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            + "\t"
            + event,
        }

    @classmethod
    def _load(cls, events: list[dict]) -> None:
        path = Path("/tmp/adm-index-window-%s.ndjson" % uuid.uuid4().hex)
        path.write_text(
            "\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8"
        )
        try:
            cls.lab.load([path])
        finally:
            path.unlink(missing_ok=True)

    @classmethod
    def _dispatch_identity(
        cls, index_window: tuple[int, int], event_window: tuple[int, int]
    ) -> list[dict]:
        data = {
            "trigger_actions": "0",
            "dispatch.earliest_time": str(event_window[0]),
            "dispatch.latest_time": str(event_window[1]),
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

    def _wait_indexed(self, marker: str, expected: int = 1) -> int:
        deadline = time.time() + 120
        while time.time() < deadline:
            rows = self.lab.search(
                '| search index=cisco_dc host="%s" | stats count AS found max(_indextime) AS indexed'
                % marker,
                0,
                "now",
            )
            if (
                rows
                and int(rows[0].get("found", 0)) >= expected
                and rows[0].get("indexed")
            ):
                return int(float(rows[0]["indexed"]))
            time.sleep(2)
        self.fail("timed out waiting for %s to index" % marker)

    def _assert_identity(
        self, ip: str, *, expect_bd: str | None, present: bool = True
    ) -> None:
        rows = self.lab.search(
            '| inputlookup adm_ip_identity where ip="%s" scope="%s" | table ip scope attr_bridge_domain attr_vlan'
            % (ip, self.scope),
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
        old_marker = marker + "-old"
        fresh_marker = marker + "-fresh"
        octet = int(suffix[:2], 16) % 200 + 1
        old_ip = "198.18.%d.10" % octet
        fresh_ip = "198.18.%d.11" % octet
        apic = "apic-index-window-" + suffix
        scope = "scope-index-window-" + suffix
        self._install_scope(apic, scope)
        self.addCleanup(self._cleanup_scope, scope)
        epg = "epg-late-" + suffix
        old_dn = "uni/tn-test/ap-app/epg-old-%s/cep-00:00:00:00:00:10" % suffix
        fresh_dn = "uni/tn-test/ap-app/%s/cep-00:00:00:00:00:11" % epg
        relation_dn = "uni/tn-test/ap-app/%s/rsbd" % epg
        now = int(time.time()) - 1200
        old_events = [
            self._event(
                'dn="%s"\tencap="vlan-3990"\tip=%s\tmac="00:00:00:00:00:10"\t'
                'addr=%s\tcomponent="fvCEp"\tapic_host=%s\tstate="formed"'
                % (old_dn, old_ip, old_ip, apic),
                timestamp=now,
                marker=old_marker,
            ),
            self._event(
                'dn="%s"\ttDn="uni/tn-test/BD-bd-late"\ttnFvBDName="bd-late"\t'
                'state="formed"\tcomponent="fvRsBd"\tapic_host=%s'
                % (relation_dn, apic),
                timestamp=now - 300,
                marker=old_marker,
            ),
        ]
        self._load(old_events)
        old_index = self._wait_indexed(old_marker, expected=2)
        while int(time.time()) <= old_index:
            time.sleep(1)
        fresh_event = self._event(
            'dn="%s"\tencap="vlan-3991"\tip=%s\tmac="00:00:00:00:00:11"\t'
            'addr=%s\tcomponent="fvCEp"\tapic_host=%s\tstate="formed"'
            % (fresh_dn, fresh_ip, fresh_ip, apic),
            timestamp=now + 1,
            marker=fresh_marker,
        )
        self._load([fresh_event])
        fresh_index = self._wait_indexed(fresh_marker)
        self.assertGreater(fresh_index, old_index)
        self._dispatch_identity((old_index + 1, fresh_index + 1), (now - 1, now + 60))

        self._assert_identity(fresh_ip, expect_bd="bd-late")
        self._assert_identity(old_ip, expect_bd=None, present=False)

    def test_old_relation_event_time_is_not_used_after_freshness_window(self):
        suffix = uuid.uuid4().hex[:8]
        marker = "index-window-stale-" + suffix
        octet = int(suffix[:2], 16) % 200 + 1
        ip = "198.18.%d.12" % octet
        old_marker = marker + "-old"
        fresh_marker = marker + "-fresh"
        apic = "apic-index-window-stale-" + suffix
        scope = "scope-index-window-stale-" + suffix
        self._install_scope(apic, scope)
        self.addCleanup(self._cleanup_scope, scope)
        epg = "epg-stale-" + suffix
        relation_dn = "uni/tn-test/ap-app/%s/rsbd" % epg
        endpoint_dn = "uni/tn-test/ap-app/%s/cep-00:00:00:00:00:12" % epg
        now = int(time.time()) - 1200
        self._load(
            [
                self._event(
                    'dn="%s"\ttDn="uni/tn-test/BD-bd-stale"\ttnFvBDName="bd-stale"\t'
                    'state="formed"\tcomponent="fvRsBd"\tapic_host=%s'
                    % (relation_dn, apic),
                    timestamp=now - 2 * 300 - 30,
                    marker=old_marker,
                )
            ]
        )
        old_index = self._wait_indexed(old_marker)
        while int(time.time()) <= old_index:
            time.sleep(1)
        self._load(
            [
                self._event(
                    'dn="%s"\tencap="vlan-3992"\tip=%s\tmac="00:00:00:00:00:12"\t'
                    'addr=%s\tcomponent="fvCEp"\tapic_host=%s\tstate="formed"'
                    % (endpoint_dn, ip, ip, apic),
                    timestamp=now + 1,
                    marker=fresh_marker,
                )
            ]
        )
        fresh_index = self._wait_indexed(fresh_marker)
        self.assertGreater(fresh_index, old_index)
        self._dispatch_identity((old_index + 1, fresh_index + 1), (now - 1, now + 60))
        self._assert_identity(ip, expect_bd=None)
