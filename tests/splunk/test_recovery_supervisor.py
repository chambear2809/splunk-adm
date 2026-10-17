"""Live, read-only abandoned-lease detection and tracked-alert checks."""

from __future__ import annotations

import json
import os
import time
import unittest
import uuid
from urllib.parse import quote

from tests.splunk import test_recovery_action as support

ALERT = "ADM - Recovery abandoned-lease alert"
APP = "/servicesNS/nobody/splunk_adm"
STATE = APP + "/storage/collections/data/adm_recovery_state"


@unittest.skipUnless(os.environ.get("ADM_LAB") == "1", "requires disposable Splunk lab")
class RecoverySupervisorLiveTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        support.RecoveryActionLiveTest.setUpClass()
        cls.lab = support.RecoveryActionLiveTest.lab

    def setUp(self):
        self.path = APP + "/saved/searches/" + quote(ALERT, safe="")
        # Enable only manual dispatch while exercising the shipped alert, then
        # restore the captured state (registered first: the POST may apply even
        # if its response is lost).
        original = self.lab._json("GET", self.path)["entry"][0]["content"]
        self.addCleanup(
            self.lab._json,
            "POST",
            self.path,
            {
                "disabled": str(int(original["disabled"] in (True, 1, "1"))),
                "is_scheduled": str(int(original["is_scheduled"] in (True, 1, "1"))),
            },
        )
        self.lab._json("POST", self.path, {"disabled": "0", "is_scheduled": "0"})

    def test_abandoned_target_after_50000_recovered_slots_is_visible(self):
        api = support.RecoveryActionLiveTest.rest()
        owner = "supervisor_bulk_" + uuid.uuid4().hex
        # Cleanup by this test's owner only; every batch is registered before
        # writing so even partial batch failures are removed.
        from urllib.parse import urlencode

        self.addCleanup(
            api.request,
            "DELETE",
            STATE + "?" + urlencode({"query": json.dumps({"owner": owner})}),
        )
        for start in range(0, 50001, 1000):
            records = [
                {
                    "_key": f"{owner}_{i:06d}",
                    "owner": owner,
                    "record_type": "slot",
                    "state": "recovered",
                    "expires_at": 1,
                }
                for i in range(start, min(start + 1000, 50001))
            ]
            api.request("POST", STATE + "/batch_save", records, json_body=True)
        key = owner + "_target"
        api.request(
            "POST",
            STATE,
            {
                "_key": key,
                "owner": owner,
                "record_type": "target",
                "state": "restored",
                "expires_at": 1,
            },
            json_body=True,
        )
        rows = self.lab.run_saved_search(ALERT)
        self.assertEqual({r["_key"] for r in rows if r.get("owner") == owner}, {key})
        self.assertFalse(
            any(r.get("incident") == "incomplete_recovery_state_read" for r in rows)
        )

    def test_incomplete_read_raises_incident_even_with_only_terminal_rows(self):
        api = support.RecoveryActionLiveTest.rest()
        key = "supervisor_incomplete_" + uuid.uuid4().hex
        api.request(
            "POST",
            STATE,
            {"_key": key, "record_type": "slot", "state": "recovered", "expires_at": 1},
            json_body=True,
        )
        self.addCleanup(api.request, "DELETE", STATE + "/" + key)
        path = APP + "/configs/conf-macros/adm_kv_complete"
        original = self.lab._json("GET", path)["entry"][0]["content"]["definition"]
        self.addCleanup(self.lab._json, "POST", path, {"definition": original})
        # Controlled completeness fault, while retaining actual live KV reads.
        self.lab._json("POST", path, {"definition": "eval adm_complete=0"})
        rows = self.lab.run_saved_search(ALERT)
        self.assertTrue(
            any(r.get("incident") == "incomplete_recovery_state_read" for r in rows)
        )

    def test_expired_claim_matrix_is_read_only_and_tracks_alert(self):
        api = support.RecoveryActionLiveTest.rest()
        owner = "supervisor_" + uuid.uuid4().hex
        now = time.time()
        expected = set()
        records = []
        # Target/restored and even target/recovered still block Recovery.run().
        for kind, states in (
            (
                "target",
                [
                    "pause_pending",
                    "paused",
                    "restore_pending",
                    "restored",
                    "uncertain",
                    "recovered",
                    "unexpected",
                ],
            ),
            (
                "slot",
                [
                    "claimed",
                    "slice_checked",
                    "dispatch_pending",
                    "running",
                    "verified",
                    "uncertain",
                    "recovered",
                    "unexpected",
                ],
            ),
            ("unknown", ["recovered"]),
        ):
            for state in states:
                for expired in (False, True):
                    key = f"{owner}_{kind}_{state}_{expired}"
                    record = {
                        "_key": key,
                        "owner": owner,
                        "name": "supervisor fixture",
                        "record_type": kind,
                        "state": state,
                        "expires_at": now - 60 if expired else now + 3600,
                    }
                    api.request("POST", STATE, record, json_body=True)
                    self.addCleanup(api.request, "DELETE", STATE + "/" + key)
                    records.append(api.request("GET", STATE + "/" + key))
                    if expired and not (kind == "slot" and state == "recovered"):
                        expected.add(key)
        before = self.lab._json("GET", APP + "/saved/searches?count=0")
        sid = self.lab._json("POST", self.path + "/dispatch", {"trigger_actions": "1"})[
            "sid"
        ]
        self.lab._wait_job(sid)
        rows = self.lab._results(sid)
        self.assertEqual({r["_key"] for r in rows if r.get("owner") == owner}, expected)
        for record in records:
            self.assertEqual(api.request("GET", STATE + "/" + record["_key"]), record)
        after = self.lab._json("GET", APP + "/saved/searches?count=0")

        def schedules(response):
            return {
                e["name"]: {
                    k: e["content"].get(k)
                    for k in ("disabled", "is_scheduled", "cron_schedule")
                }
                for e in response["entry"]
            }

        self.assertEqual(schedules(before), schedules(after))
        # The actual saved search executes alert tracking, rather than merely
        # checking a matching SPL result and assuming an incident was recorded.
        deadline = time.monotonic() + 30
        while True:
            fired = self.lab._json(
                "GET",
                APP + "/alerts/fired_alerts/" + quote(ALERT, safe="") + "?count=0",
            )
            if any(
                e.get("content", {}).get("sid") == sid for e in fired.get("entry", [])
            ):
                break
            self.assertLess(time.monotonic(), deadline, "no tracked supervisor alert")
            time.sleep(0.5)
