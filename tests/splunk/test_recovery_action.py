"""Milestone-one live checks for the automated assisted recovery core."""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import ssl
import sys
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request


@unittest.skipUnless(os.environ.get("ADM_LAB") == "1", "requires disposable Splunk lab")
class RecoveryActionLiveTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        here = Path(__file__).resolve().parent
        root = here.parents[1]
        sys.path.insert(0, str(here))
        sys.path.insert(0, str(root))
        sys.path.insert(0, str(root / "splunk_app/splunk_adm/bin/lib"))
        sys.path.insert(0, str(root / "splunk_app/splunk_adm/bin"))
        import lab
        from tools.fault_pipeline import wait_kv_ready
        from adm_recovery_lib.core import Recovery, Settings
        from adm_recovery_lib.rest import ApiError

        cls.lab, cls.Recovery, cls.Settings, cls.ApiError = (
            lab,
            Recovery,
            Settings,
            ApiError,
        )
        wait_kv_ready(timeout=180)
        cls.ctx = ssl.create_default_context()
        cls.ctx.check_hostname = False
        cls.ctx.verify_mode = ssl.CERT_NONE

    @classmethod
    def rest(cls):
        password = cls.lab.read_secrets()["SPLUNK_PASSWORD"]

        class LabRest:
            def request(self, method, path, data=None, json_body=False, timeout=30):
                sep = "&" if "?" in path else "?"
                headers = {
                    "Authorization": "Basic "
                    + base64.b64encode(f"admin:{password}".encode()).decode()
                }
                if json_body:
                    body, headers["Content-Type"] = (
                        json.dumps(data).encode(),
                        "application/json",
                    )
                else:
                    body = (
                        urllib.parse.urlencode(data, doseq=True).encode()
                        if data
                        else None
                    )
                try:
                    request = urllib.request.Request(
                        cls.lab.MGMT + path + sep + "output_mode=json",
                        data=body,
                        method=method,
                        headers=headers,
                    )
                    with urllib.request.urlopen(
                        request, context=cls.ctx, timeout=timeout
                    ) as response:
                        raw = response.read()
                except urllib.error.HTTPError as exc:
                    exc.close()
                    raise cls.ApiError(exc.code) from None
                return json.loads(raw) if raw else {}

        return LabRest()

    @staticmethod
    def slot(offset, age=600):
        now = int(time.time()) - age
        return now - ((now - offset) % 300)

    def recovery(self, rows, wall, api=None):
        parent = self

        class FixtureRecovery(parent.Recovery):
            def history(self, target):
                return [row for row in rows if row.get("savedsearch_name") == target]

        return FixtureRecovery(
            api or self.rest(),
            settings=self.Settings(enabled=True),
            wall=wall,
            monotonic=time.monotonic,
            sleep=time.sleep,
        )

    def enable_target(self, target):
        path = "/servicesNS/nobody/splunk_adm/saved/searches/" + urllib.parse.quote(
            target, safe=""
        )
        original = self.lab._json("GET", path)["entry"][0]["content"]
        self.lab._json("POST", path, {"disabled": "0", "is_scheduled": "1"})

        def restore():
            self.lab._json(
                "POST",
                path,
                {
                    "disabled": str(int(original.get("disabled") in (1, "1", True))),
                    "is_scheduled": str(
                        int(original.get("is_scheduled") in (1, "1", True))
                    ),
                },
            )

        self.addCleanup(restore)

    def cleanup_owner(self, recovery):
        path = (
            "/servicesNS/nobody/splunk_adm/storage/collections/data/adm_recovery_state"
        )
        query = urllib.parse.urlencode(
            {"query": json.dumps({"owner": recovery.owner}), "limit": 1000}
        )
        rows = self.lab._json("GET", path + "?" + query)
        if isinstance(rows, dict):
            rows = rows.get("entry", [])
        for row in rows:
            key = row.get("_key") or row.get("content", {}).get("_key")
            if key:
                self.rest().request(
                    "DELETE", path + "/" + urllib.parse.quote(key, safe="")
                )

    def state_rows(self, target):
        path = (
            "/servicesNS/nobody/splunk_adm/storage/collections/data/adm_recovery_state"
        )
        query = urllib.parse.urlencode(
            {"query": json.dumps({"name": target}), "limit": 1000}
        )
        return self.lab._json("GET", path + "?" + query)

    def audit_rows(self, target):
        return self.lab.search(
            f'| inputlookup adm_recovery_audit | search name="{target}"', "0", "now"
        )

    def isolated_netflow(self):
        """Index a current-time fixture and point only this test's macro at it."""
        source = (
            Path(__file__).resolve().parents[1]
            / "../fixtures/raw/stream_netflow.ndjson"
        )
        token = "recovery_action_" + str(time.time_ns())
        now = time.time()
        events = []
        for line in source.read_text(encoding="utf-8").splitlines()[:3]:
            envelope = json.loads(line)
            envelope["index"] = "adm_alt_nf"
            envelope["time"] = now
            envelope["event"]["recovery_token"] = token
            stamp = time.strftime("%Y-%m-%dT%H:%M:%S.000000Z", time.gmtime(now))
            envelope["event"]["timestamp"] = stamp
            envelope["event"]["endtime"] = stamp
            events.append(json.dumps(envelope, separators=(",", ":")).encode())
        self.lab._hec_post(b"\n".join(events), "?index=adm_alt_nf")
        deadline = time.time() + 120
        while time.time() < deadline:
            rows = self.lab.search(
                f'index=adm_alt_nf recovery_token="{token}" | stats count AS n max(_indextime) AS indexed',
                "0",
                "now",
            )
            if rows and int(rows[0].get("n", 0)) == len(events):
                indexed = int(float(rows[0]["indexed"]))
                break
            time.sleep(1)
        else:
            self.fail("isolated NetFlow fixture was not indexed")
        path = "/servicesNS/nobody/splunk_adm/configs/conf-macros/adm_index_netflow"
        original = self.lab._json("GET", path)["entry"][0]["content"]["definition"]
        self.lab._json(
            "POST", path, {"definition": f'index=adm_alt_nf recovery_token="{token}"'}
        )
        self.lab._json("GET", "/servicesNS/nobody/splunk_adm/admin/macros/_reload")

        def restore():
            self.lab._json("POST", path, {"definition": original})
            self.lab._json("GET", "/servicesNS/nobody/splunk_adm/admin/macros/_reload")

        self.addCleanup(restore)
        return token, indexed

    def test_single_builder_slot_replays_and_records_audit(self):
        for target, offset in (
            ("ADM - Identity builder", 60),
            ("ADM - Service binding", 120),
            ("ADM - Service backends", 180),
        ):
            with self.subTest(target=target):
                self.assert_single_builder_slot(target, offset)

    def assert_single_builder_slot(self, target, offset):
        slot = self.slot(offset)
        self.enable_target(target)
        recovery = self.recovery(
            [
                {
                    "savedsearch_name": target,
                    "status": "success",
                    "scheduled_time": slot - 300,
                    "sid": "scheduler__fixture_checkpoint",
                },
                {
                    "savedsearch_name": target,
                    "status": "success",
                    "scheduled_time": slot + 300,
                    "sid": "scheduler__fixture_after",
                },
            ],
            lambda: slot + 301,
        )
        self.addCleanup(self.cleanup_owner, recovery)
        result = recovery.run(target)
        self.assertEqual(result.get("status"), "recovered", result)
        self.assertTrue(
            any(row.get("event") == "recovered" for row in self.audit_rows(target))
        )
        audit = self.rest().request(
            "GET",
            "/servicesNS/nobody/splunk_adm/storage/collections/data/adm_recovery_audit?"
            + urllib.parse.urlencode({"query": json.dumps({"owner": recovery.owner})}),
        )
        running = [row for row in audit if row.get("event") == "running"]
        self.assertEqual(len(running), 1, audit)
        self.assertEqual(int(running[0]["index_earliest"]), slot - 600)
        self.assertEqual(int(running[0]["index_latest"]), slot)
        self.assertTrue(running[0]["sid"])
        restored = [row for row in audit if row.get("event") == "restored"]
        self.assertEqual(len(restored), 1, audit)
        self.assertIs(restored[0]["local_override_retained"], True)
        self.assertEqual(restored[0]["before"]["is_scheduled"], "1")

    def test_two_builder_slots_are_chronological_and_overlap_is_allowed(self):
        target, first = "ADM - Identity builder", self.slot(60)
        second = first + 300
        self.enable_target(target)
        parent = self
        rows = [
            {
                "savedsearch_name": target,
                "status": "success",
                "scheduled_time": first - 300,
                "sid": "scheduler__fixture_checkpoint",
            },
            {
                "savedsearch_name": target,
                "status": "success",
                "scheduled_time": second + 300,
                "sid": "scheduler__fixture_after",
            },
        ]

        class OrderedRecovery(parent.Recovery):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.replay_order = []

            def history(self, name):
                return rows

            def replay(self, slot, before):
                self.replay_order.append(slot["scheduled_time"])
                return super().replay(slot, before)

        class ObservingRest:
            def __init__(self):
                self.inner = parent.rest()
                self.dispatch_sids = []
                self.preconditions = []

            def request(self, method, path, data=None, json_body=False, timeout=30):
                if path.endswith("/dispatch") and self.dispatch_sids:
                    config = self.inner.request(
                        "GET",
                        "/servicesNS/nobody/splunk_adm/saved/searches/"
                        + urllib.parse.quote(target, safe=""),
                    )
                    jobs = self.inner.request("GET", "/services/search/v2/jobs?count=0")
                    previous = next(
                        (
                            entry
                            for entry in jobs.get("entry", [])
                            if entry.get("name") == self.dispatch_sids[-1]
                            or entry.get("content", {}).get("sid")
                            == self.dispatch_sids[-1]
                        ),
                        None,
                    )
                    self.preconditions.append(
                        bool(
                            config["entry"][0]["content"].get("is_scheduled")
                            in (0, "0", False)
                        )
                        and previous is not None
                        and bool(
                            previous.get("content", {}).get("isDone") in (1, "1", True)
                        )
                    )
                result = self.inner.request(method, path, data, json_body, timeout)
                if path.endswith("/dispatch"):
                    self.dispatch_sids.append(result["sid"])
                return result

        adapter = ObservingRest()
        recovery = OrderedRecovery(
            adapter,
            settings=self.Settings(enabled=True),
            wall=lambda: second + 301,
            monotonic=time.monotonic,
            sleep=time.sleep,
        )
        self.addCleanup(self.cleanup_owner, recovery)
        result = recovery.run(target)
        self.assertEqual(result.get("status"), "recovered", result)
        self.assertEqual(recovery.replay_order, [first, second])
        self.assertEqual(len(adapter.dispatch_sids), 2)
        self.assertEqual(adapter.preconditions, [True])
        rows = self.state_rows(target)
        replay = sorted(
            (
                int(row["scheduled_time"]),
                int(row["index_earliest"]),
                int(row["index_latest"]),
            )
            for row in rows
            if row.get("record_type") == "slot"
        )
        self.assertEqual([row[0] for row in replay], [first, second], replay)
        self.assertLess(replay[1][1], replay[0][2], replay)

    def test_empty_rollup_is_a_verified_noop(self):
        target, checkpoint = "ADM - Conversation rollup", self.slot(0) + 3600
        self.enable_target(target)
        recovery = self.recovery(
            [
                {
                    "savedsearch_name": target,
                    "status": "success",
                    "scheduled_time": checkpoint - 300,
                    "sid": "scheduler__fixture_checkpoint",
                },
                {
                    "savedsearch_name": target,
                    "status": "success",
                    "scheduled_time": checkpoint + 300,
                    "sid": "scheduler__fixture_after",
                },
            ],
            lambda: checkpoint + 1,
        )
        self.addCleanup(self.cleanup_owner, recovery)
        result = recovery.run(target)
        self.assertEqual(result.get("status"), "recovered", result)
        state = self.state_rows(target)
        slots = [row for row in state if row.get("record_type") == "slot"]
        self.assertEqual(len(slots), 1, state)
        self.assertEqual(int(slots[0]["manifest"]["accepted_records"]), 0, state)

    def test_nonempty_rollup_reconciles_real_summary_rows(self):
        _token, indexed = self.isolated_netflow()
        target = "ADM - Conversation rollup"
        # For a rollup slot s, the closed index slice is [s-600,s-300].
        # Select the next aligned slot that contains the fixture's real
        # _indextime, then inject the wall clock just after that slot.
        checkpoint = indexed - (indexed % 300) + 600
        self.enable_target(target)
        recovery = self.recovery(
            [
                {
                    "savedsearch_name": target,
                    "status": "success",
                    "scheduled_time": checkpoint - 300,
                    "sid": "scheduler__fixture_checkpoint",
                },
                {
                    "savedsearch_name": target,
                    "status": "success",
                    "scheduled_time": checkpoint + 300,
                    "sid": "scheduler__fixture_after",
                },
            ],
            lambda: checkpoint + 301,
        )
        self.addCleanup(self.cleanup_owner, recovery)
        result = recovery.run(target)
        self.assertEqual(result.get("status"), "recovered", result)
        state = self.state_rows(target)
        slots = [row for row in state if row.get("record_type") == "slot"]
        self.assertEqual(len(slots), 1, state)
        manifest = slots[0].get("manifest", {})
        self.assertGreater(int(manifest.get("accepted_records", 0)), 0, state)
        self.assertTrue(manifest.get("rows"), state)

    def test_dispatch_failure_is_uncertain_and_never_retried(self):
        target, slot = "ADM - Identity builder", self.slot(60)
        self.enable_target(target)
        parent = self

        class FailingRest:
            def __init__(self):
                self.inner, self.dispatch_attempts = parent.rest(), 0

            def request(self, method, path, data=None, json_body=False, timeout=30):
                if path.endswith("/dispatch"):
                    self.dispatch_attempts += 1
                    raise parent.ApiError(500)
                return self.inner.request(method, path, data, json_body, timeout)

        recovery = self.recovery(
            [
                {
                    "savedsearch_name": target,
                    "status": "success",
                    "scheduled_time": slot - 300,
                    "sid": "scheduler__fixture_checkpoint",
                },
                {
                    "savedsearch_name": target,
                    "status": "success",
                    "scheduled_time": slot + 300,
                    "sid": "scheduler__fixture_after",
                },
            ],
            lambda: slot + 301,
            FailingRest(),
        )
        self.addCleanup(self.cleanup_owner, recovery)
        result = recovery.run(target)
        self.assertEqual(result.get("status"), "uncertain", result)
        self.assertEqual(recovery.api.dispatch_attempts, 1)
        state = self.state_rows(target)
        self.assertTrue(any(row.get("state") == "uncertain" for row in state), state)
        self.assertTrue(
            any(row.get("event") == "uncertain" for row in self.audit_rows(target)),
            self.audit_rows(target),
        )
        detector = self.lab.search("| `adm_health_missed_slots`", "-1445m@m", "now")
        self.assertTrue(
            any(
                row.get("name") == target
                and row.get("reason") == "uncertain"
                and int(float(row.get("scheduled_time", -1))) == slot
                for row in detector
            ),
            detector,
        )
        second = self.recovery([], lambda: slot + 301, recovery.api)
        self.assertEqual(second.run(target).get("status"), "refused")
        self.assertEqual(recovery.api.dispatch_attempts, 1)

    def test_second_invocation_does_not_replay_recovered_slot(self):
        target, slot = "ADM - Identity builder", self.slot(60)
        self.enable_target(target)
        rows = [
            {
                "savedsearch_name": target,
                "status": "success",
                "scheduled_time": slot - 300,
                "sid": "scheduler__fixture_checkpoint",
            },
            {
                "savedsearch_name": target,
                "status": "success",
                "scheduled_time": slot + 300,
                "sid": "scheduler__fixture_after",
            },
        ]
        first_api = self.rest()
        dispatch_count = {"n": 0}
        original_request = first_api.request

        def counted_request(method, path, data=None, json_body=False, timeout=30):
            if path.endswith("/dispatch"):
                dispatch_count["n"] += 1
            return original_request(method, path, data, json_body, timeout)

        first_api.request = counted_request
        first = self.recovery(rows, lambda: slot + 301, first_api)
        self.addCleanup(self.cleanup_owner, first)
        self.assertEqual(first.run(target).get("status"), "recovered")
        second = self.recovery(rows, lambda: slot + 301, first_api)
        self.addCleanup(self.cleanup_owner, second)
        self.assertEqual(second.run(target).get("status"), "noop")
        self.assertEqual(dispatch_count["n"], 1)

    def test_recovered_slot_is_removed_from_live_missed_slot_detector(self):
        """The durable recovered state suppresses only that exact slot."""
        target, slot = "ADM - Identity builder", self.slot(60)
        self.enable_target(target)
        rows = [
            {
                "savedsearch_name": target,
                "status": "success",
                "scheduled_time": slot - 300,
                "sid": "scheduler__fixture_checkpoint",
            },
            {
                "savedsearch_name": target,
                "status": "success",
                "scheduled_time": slot + 300,
                "sid": "scheduler__fixture_after",
            },
        ]
        recovery = self.recovery(rows, lambda: slot + 301)
        self.addCleanup(self.cleanup_owner, recovery)
        self.assertEqual(recovery.run(target).get("status"), "recovered")

        from test_health import HealthSearchTest

        health = HealthSearchTest("run")
        health.lab = self.lab
        scheduler = (
            '| makeresults | eval samples="'
            f"ADM - Identity builder@{slot - 300};ADM - Identity builder@{slot + 300}"
            '" | makemv delim=";" samples | mvexpand samples | eval parts=split(samples,"@"), '
            "savedsearch_name=mvindex(parts,0), scheduled_time=tonumber(mvindex(parts,1)), "
            'sid="scheduler__detector_fixture", status="success"'
        )
        query = health.missed_slots_fixture_query(scheduler)
        detected = self.lab.search(query, "0", "1")
        self.assertFalse(
            any(
                row.get("name") == target and int(row.get("scheduled_time", -1)) == slot
                for row in detected
            ),
            detected,
        )

    def test_slot_created_while_paused_is_recovered_before_restore(self):
        target, first = "ADM - Identity builder", self.slot(60)
        second = first + 300
        self.enable_target(target)
        clock = [first + 301]
        initial = [
            {
                "savedsearch_name": target,
                "status": "success",
                "scheduled_time": first - 300,
                "sid": "scheduler__fixture_checkpoint",
            },
            {
                "savedsearch_name": target,
                "status": "success",
                "scheduled_time": second,
                "sid": "scheduler__fixture_after",
            },
        ]
        parent = self

        class AdvancingRecovery(parent.Recovery):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.advanced = False

            def history(self, name):
                if self.advanced:
                    return [initial[0]]
                return list(initial)

            def replay(self, slot, before):
                super().replay(slot, before)
                self.advanced = True
                # Advance past the newly closed second slot, but before the
                # following cron boundary, so exactly one slot is added.
                clock[0] = second + 1

        recovery = AdvancingRecovery(
            self.rest(),
            settings=self.Settings(enabled=True),
            wall=lambda: clock[0],
            monotonic=time.monotonic,
            sleep=time.sleep,
        )
        self.addCleanup(self.cleanup_owner, recovery)
        result = recovery.run(target)
        self.assertEqual(result.get("status"), "recovered", result)
        self.assertEqual(sorted(result.get("slots", [])), [first, second], result)

    def test_empty_backlog_returns_noop(self):
        target, checkpoint = "ADM - Identity builder", self.slot(60)
        self.enable_target(target)
        recovery = self.recovery(
            [
                {
                    "savedsearch_name": target,
                    "status": "success",
                    "scheduled_time": checkpoint,
                    "sid": "scheduler__fixture_checkpoint",
                },
                {
                    "savedsearch_name": target,
                    "status": "success",
                    "scheduled_time": checkpoint + 300,
                    "sid": "scheduler__fixture_after",
                },
            ],
            lambda: checkpoint + 301,
        )
        self.addCleanup(self.cleanup_owner, recovery)
        self.assertEqual(recovery.run(target).get("status"), "noop")

    def test_rollup_bad_plan_is_refused_before_pause(self):
        """Malformed rollup plans must fail admission before schedule mutation."""
        target, slot = "ADM - Conversation rollup", self.slot(0)
        self.enable_target(target)
        path = "/servicesNS/nobody/splunk_adm/saved/searches/" + urllib.parse.quote(
            target, safe=""
        )
        parent = self

        def item(start, end=None):
            end = start + 300 if end is None else end
            return {
                "name": target,
                "scheduled_time": start,
                "earliest": start - 86400,
                "latest": start + 900,
                "index_earliest": start - 600,
                "index_latest": end,
            }

        class InvalidPlanRecovery(parent.Recovery):
            def __init__(self, *args, invalid, **kwargs):
                super().__init__(*args, **kwargs)
                self.invalid = invalid

            def history(self, name):
                return [
                    {
                        "savedsearch_name": name,
                        "status": "success",
                        "scheduled_time": slot - 300,
                        "sid": "scheduler__fixture_checkpoint",
                    }
                ]

            def plan(self, name, history):
                return self.invalid

        cases = {
            "overlap": [item(slot), item(slot + 300, slot + 599)],
            "altered": [dict(item(slot), index_earliest=slot - 599)],
            "unclosed": [item(slot)],
        }
        for label, invalid in cases.items():
            with self.subTest(label=label):
                recovery = InvalidPlanRecovery(
                    self.rest(),
                    settings=self.Settings(enabled=True),
                    wall=lambda: slot + 1,
                    monotonic=time.monotonic,
                    sleep=time.sleep,
                    invalid=invalid,
                )
                result = recovery.run(target)
                self.addCleanup(self.cleanup_owner, recovery)
                self.assertIn(result.get("status"), {"refused", "uncertain"}, result)
                current = self.lab._json("GET", path)["entry"][0]["content"]
                self.assertIn(current.get("is_scheduled"), (1, "1", True), result)

    def test_prior_native_failure_refuses_candidate_before_pause_or_dispatch(self):
        """A failed native run cannot be safely replaced by replay."""
        target, slot = "ADM - Conversation rollup", self.slot(0)
        self.enable_target(target)
        parent = self

        class GuardedRest:
            def __init__(self):
                self.inner = parent.rest()
                self.pause_posts = 0
                self.dispatch_posts = 0

            def request(self, method, path, data=None, json_body=False, timeout=30):
                if method == "POST" and "/saved/searches/" in path:
                    if path.endswith("/dispatch"):
                        self.dispatch_posts += 1
                    else:
                        self.pause_posts += 1
                return self.inner.request(method, path, data, json_body, timeout)

        class NativeFailureRecovery(parent.Recovery):
            def history(self, name):
                return [
                    {
                        "savedsearch_name": name,
                        "status": "success",
                        "scheduled_time": slot - 300,
                        "sid": "scheduler__checkpoint",
                    },
                    {
                        "savedsearch_name": name,
                        "status": "failed",
                        "scheduled_time": slot,
                        "sid": "scheduler__native_failed",
                        "dispatchState": "FAILED",
                    },
                ]

        api = GuardedRest()
        recovery = NativeFailureRecovery(
            api,
            settings=self.Settings(enabled=True),
            wall=lambda: slot + 301,
            monotonic=time.monotonic,
            sleep=time.sleep,
        )
        self.addCleanup(self.cleanup_owner, recovery)
        result = recovery.run(target)
        self.assertEqual(result.get("status"), "refused", result)
        self.assertIn("prior", result.get("reason", "").lower(), result)
        self.assertEqual(api.pause_posts, 0)
        self.assertEqual(api.dispatch_posts, 0)
        current = self.lab._json(
            "GET",
            "/servicesNS/nobody/splunk_adm/saved/searches/"
            + urllib.parse.quote(target, safe=""),
        )["entry"][0]["content"]
        self.assertIn(current.get("disabled"), (0, "0", False))
        self.assertIn(current.get("is_scheduled"), (1, "1", True))


if __name__ == "__main__":
    unittest.main()
