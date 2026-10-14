"""Real SIGKILL, stalled replay and administrator-conflict lab checks.

Only history/wall-clock fixtures and synchronization points are injected.
Planning, dispatch, job polling, KV writes and restoration use production code.
"""

from __future__ import annotations

import json
import os
import selectors
import signal
import subprocess
import sys
import time
import unittest
import uuid
from pathlib import Path
from urllib.parse import quote, urlencode

from tests.splunk import test_recovery_action as support

ROOT = Path(__file__).resolve().parents[2]
APP = "/servicesNS/nobody/splunk_adm"
STATE = APP + "/storage/collections/data/adm_recovery_state"
TARGET = "ADM - Identity builder"
TARGET_PATH = APP + "/saved/searches/" + quote(TARGET, safe="")
ALERT = "ADM - Recovery abandoned-lease alert"


def fixture(api, slot, settings=None, after_save=None):
    base = support.RecoveryActionLiveTest

    class Fixture(base.Recovery):
        def history(self, name):
            return [
                {
                    "savedsearch_name": name,
                    "status": "success",
                    "scheduled_time": stamp,
                    "sid": "scheduler__fixture",
                }
                for stamp in (slot - 300, slot + 300)
            ]

        def save(self, record, **changes):
            super().save(record, **changes)
            if after_save:
                after_save(self, record)

    return Fixture(
        api,
        settings=settings or base.Settings(enabled=True),
        wall=lambda: slot + 301,
        monotonic=time.monotonic,
        sleep=time.sleep,
    )


class ObservedApi:
    def __init__(self):
        self.inner = support.RecoveryActionLiveTest.rest()
        self.calls = []

    def request(self, method, path, data=None, json_body=False, timeout=30):
        self.calls.append((method, path, data))
        return self.inner.request(method, path, data, json_body, timeout)


@unittest.skipUnless(os.environ.get("ADM_LAB") == "1", "requires disposable Splunk lab")
class RecoveryFailureLiveTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        support.RecoveryActionLiveTest.setUpClass()
        cls.lab = support.RecoveryActionLiveTest.lab

    def setUp(self):
        self.api = ObservedApi()
        self.original = self.api.request("GET", TARGET_PATH)["entry"][0]["content"]
        self.slot = support.RecoveryActionLiveTest.slot(60)
        self.addCleanup(self.restore_target)
        self.api.request("POST", TARGET_PATH, {"disabled": "0", "is_scheduled": "1"})

    def restore_target(self):
        self.api.request(
            "POST",
            TARGET_PATH,
            {
                "disabled": str(int(self.original["disabled"] in (1, "1", True))),
                "is_scheduled": str(
                    int(self.original["is_scheduled"] in (1, "1", True))
                ),
                "cron_schedule": self.original["cron_schedule"],
            },
        )

    def rows(self, owner):
        return self.api.request(
            "GET",
            STATE
            + "?"
            + urlencode({"query": json.dumps({"owner": owner}), "limit": 1000}),
        )

    def cleanup_owner(self, owner):
        for row in self.rows(owner):
            if row.get("sid"):
                path = "/services/search/v2/jobs/" + quote(row["sid"], safe="")
                try:
                    self.api.request("POST", path + "/control", {"action": "cancel"})
                except support.RecoveryActionLiveTest.ApiError as exc:
                    if exc.status != 404:
                        raise
            self.api.request("DELETE", STATE + "/" + row["_key"])

    def scheduled(self):
        value = self.api.request("GET", TARGET_PATH)["entry"][0]["content"][
            "is_scheduled"
        ]
        return value in (1, "1", True)

    def supervise_expired(self, owner):
        rows = self.rows(owner)
        for row in rows:
            self.api.request(
                "POST",
                STATE + "/" + row["_key"],
                {**row, "expires_at": time.time() - 1},
                json_body=True,
            )
        path = APP + "/saved/searches/" + quote(ALERT, safe="")
        search = self.api.request("GET", path)["entry"][0]["content"]["search"]
        # Executes the installed supervisor SPL; the separate supervisor suite
        # verifies actual saved-search dispatch and tracked alert creation.
        observed = self.lab.search(search)
        expected = {
            r["_key"]
            for r in rows
            if r["record_type"] == "target" or r["state"] != "recovered"
        }
        self.assertEqual(
            {r["_key"] for r in observed if r.get("owner") == owner}, expected
        )

    def assert_refuses_existing_claim(self, owner):
        base = support.RecoveryActionLiveTest
        rows_before = self.rows(owner)
        target = next(r for r in rows_before if r["record_type"] == "target")
        scheduled_before = self.scheduled()
        # Ordinary invocation refuses paused preflight or the existing target.
        probe_api = ObservedApi()
        result = fixture(probe_api, self.slot).run(TARGET)
        self.assertEqual(result["status"], "refused", result)
        expected_reason = (
            "target claim already exists; no takeover"
            if scheduled_before
            else "target must be enabled and scheduled"
        )
        self.assertEqual(result["reason"], expected_reason)
        if not scheduled_before:
            # Reach the existence guard specifically without re-enabling the
            # schedule. Only preflight is substituted with persisted evidence.
            class CapturedPreflight(base.Recovery):
                def preflight(self, name):
                    return target["before"], target["configuration"]

            result = CapturedPreflight(
                probe_api, settings=base.Settings(enabled=True)
            ).run(TARGET)
            self.assertEqual(
                result["reason"], "target claim already exists; no takeover"
            )
            self.assertEqual(result["status"], "refused")
        mutations = [
            (method, path)
            for method, path, _ in probe_api.calls
            if method != "GET" and not path.endswith("/adm_recovery_audit")
        ]
        self.assertEqual(mutations, [])
        self.assertEqual(self.rows(owner), rows_before)
        self.assertEqual(self.scheduled(), scheduled_before)

    def crash_at(self, stage):
        owner = uuid.uuid4().hex
        self.addCleanup(self.cleanup_owner, owner)
        child = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "tests.splunk.test_recovery_failures",
                "--worker",
                stage,
                str(self.slot),
                owner,
            ],
            cwd=ROOT,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(child.stdout, selectors.EVENT_READ)
                self.assertTrue(
                    selector.select(timeout=90), "worker never reached durable stage"
                )
            marker = json.loads(child.stdout.readline())
            self.assertEqual(marker["stage"], stage, marker)
            self.assertEqual(marker["owner"], owner)
            child.kill()
            self.assertEqual(child.wait(timeout=10), -signal.SIGKILL)
            rows = self.rows(owner)
            target = next(r for r in rows if r["record_type"] == "target")
            slots = [r for r in rows if r["record_type"] == "slot"]
            self.assertEqual(target["state"], "paused" if stage == "running" else stage)
            self.assertEqual(self.scheduled(), stage == "restored")
            if stage == "paused":
                self.assertEqual(slots, [])
                self.assertEqual(marker["dispatches"], 0)
            else:
                self.assertEqual(len(slots), 1)
                self.assertTrue(slots[0]["sid"])
                self.assertEqual(
                    slots[0]["state"], "running" if stage == "running" else "verified"
                )
                self.assertEqual(marker["dispatches"], 1)
            self.supervise_expired(owner)
            self.assert_refuses_existing_claim(owner)
            self.assertEqual(self.scheduled(), stage == "restored")
        finally:
            if child.poll() is None:
                child.kill()
                child.wait(timeout=10)
            child.stdin.close()
            child.stdout.close()

    def test_sigkill_after_paused_before_dispatch(self):
        self.crash_at("paused")

    def test_sigkill_after_running_before_verified(self):
        self.crash_at("running")

    def test_sigkill_after_restored_before_delete(self):
        self.crash_at("restored")

    def conflict(self, changes):
        def edit(recovery, record):
            if record["record_type"] == "target" and record["state"] == "paused":
                # Separate administrator REST client, outside recovery's adapter.
                self.lab._json("POST", TARGET_PATH, changes)

        recovery = fixture(self.api, self.slot, after_save=edit)
        self.addCleanup(self.cleanup_owner, recovery.owner)
        result = recovery.run(TARGET)
        self.assertEqual(result["status"], "uncertain", result)
        self.assertEqual(result["reason"], "conflicting administrator changes")
        current = self.api.request("GET", TARGET_PATH)["entry"][0]["content"]
        for key, value in changes.items():
            self.assertEqual(
                str(int(current[key]))
                if isinstance(current[key], bool)
                else str(current[key]),
                value,
            )
        self.assertFalse(
            any(path.endswith("/dispatch") for _, path, _ in self.api.calls)
        )
        schedule_writes = [
            data
            for method, path, data in self.api.calls
            if method == "POST" and path == TARGET_PATH
        ]
        self.assertEqual(
            schedule_writes,
            [{"disabled": "0", "is_scheduled": "1"}, {"is_scheduled": "0"}],
        )
        self.assertEqual(
            next(r for r in self.rows(recovery.owner) if r["record_type"] == "target")[
                "state"
            ],
            "uncertain" if changes.get("is_scheduled") == "1" else "paused",
        )

    def test_conflicting_admin_cron_is_preserved(self):
        self.conflict({"cron_schedule": "7-57/5 * * * *"})
        self.assertFalse(self.scheduled())

    def test_conflicting_admin_reenable_is_preserved(self):
        self.conflict({"is_scheduled": "1"})
        self.assertTrue(self.scheduled())

    def test_real_replay_exceeds_default_slot_deadline(self):
        self.stalled_replay(
            support.RecoveryActionLiveTest.Settings(enabled=True), 120, {"uncertain"}
        )

    def test_real_replay_reaches_reduced_pause_cap(self):
        self.stalled_replay(
            support.RecoveryActionLiveTest.Settings(enabled=True, pause_cap_seconds=5),
            5,
            {"uncertain"},
        )

    def test_real_replay_reaches_reduced_action_deadline(self):
        # Overall deadline also bounds cleanup: durable running/paused claims
        # must remain supervised even if there is no time to save uncertain.
        self.stalled_replay(
            support.RecoveryActionLiveTest.Settings(
                enabled=True, action_deadline_seconds=5
            ),
            5,
            {"paused", "running"},
        )

    def stalled_replay(self, settings, minimum_seconds, expected_states):
        macro = APP + "/configs/conf-macros/adm_identity_build"
        original = self.api.request("GET", macro)["entry"][0]["content"]["definition"]
        self.addCleanup(self.api.request, "POST", macro, {"definition": original})
        # Capture this fixture in preflight's macro digest. The saved search
        # text remains the shipped definition. No output collection is written.
        self.api.request(
            "POST",
            macro,
            {
                "definition": "index=adm | append [| makeresults count=50000] | eval n=mvrange(0,20) | mvexpand n | eval x=sha512(sha512(tostring(n))) | stats count"
            },
        )
        outer = self

        class StalledApi(ObservedApi):
            def request(self, method, path, data=None, json_body=False, timeout=30):
                result = super().request(method, path, data, json_body, timeout)
                if method == "POST" and path.endswith("/dispatch"):
                    job = "/services/search/v2/jobs/" + quote(result["sid"], safe="")
                    outer.addCleanup(
                        self.inner.request,
                        "POST",
                        job + "/control",
                        {"action": "cancel"},
                    )
                    until = time.monotonic() + 10
                    while True:
                        content = self.inner.request("GET", job)["entry"][0]["content"]
                        self.fixture_job = {
                            key: content.get(key)
                            for key in (
                                "dispatchState",
                                "messages",
                                "isFailed",
                                "isDone",
                                "search",
                            )
                        }
                        if content.get("dispatchState") == "RUNNING":
                            break
                        outer.assertLess(
                            time.monotonic(), until, content.get("messages")
                        )
                        time.sleep(0.05)
                    self.inner.request("POST", job + "/control", {"action": "pause"})
                    content = self.inner.request("GET", job)["entry"][0]["content"]
                    outer.assertFalse(content.get("isDone") in (1, "1", True))
                    outer.assertTrue(content.get("isPaused") in (1, "1", True))
                return result

        api = StalledApi()
        recovery = fixture(api, self.slot, settings=settings)
        self.addCleanup(self.cleanup_owner, recovery.owner)
        started = time.monotonic()
        result = recovery.run(TARGET)
        elapsed = time.monotonic() - started
        diagnostics = dict(result)
        diagnostics["fixture_job"] = getattr(api, "fixture_job", None)
        if recovery.active_sid:
            content = api.inner.request(
                "GET", "/services/search/v2/jobs/" + quote(recovery.active_sid, safe="")
            )["entry"][0]["content"]
            diagnostics["job_messages"] = content.get("messages")
        self.assertGreaterEqual(elapsed, minimum_seconds, diagnostics)
        self.assertLess(elapsed, minimum_seconds + 60)
        self.assertEqual(result["status"], "uncertain", result)
        self.assertEqual(result["reason"], "invocation deadline reached")
        self.assertFalse(self.scheduled())
        rows = self.rows(recovery.owner)
        self.assertEqual({r["state"] for r in rows}, expected_states)
        slot = next(r for r in rows if r["record_type"] == "slot")
        self.assertTrue(slot["sid"])
        self.assertEqual(
            len(
                [
                    1
                    for method, path, _ in api.calls
                    if method == "POST" and path.endswith("/dispatch")
                ]
            ),
            1,
        )
        self.assertGreater(
            len(
                [
                    1
                    for method, path, _ in api.calls
                    if method == "GET" and path.endswith(slot["sid"])
                ]
            ),
            10,
        )
        self.supervise_expired(recovery.owner)
        self.assert_refuses_existing_claim(recovery.owner)


def worker(stage, slot, owner):
    support.RecoveryActionLiveTest.setUpClass()
    api = ObservedApi()

    def gate(recovery, record):
        if record["state"] == stage:
            print(
                json.dumps(
                    {
                        "stage": stage,
                        "owner": recovery.owner,
                        "dispatches": sum(
                            method == "POST" and path.endswith("/dispatch")
                            for method, path, _ in api.calls
                        ),
                    }
                ),
                flush=True,
            )
            sys.stdin.readline()  # Parent kills the process; no exception cleanup.

    recovery = fixture(api, slot, after_save=gate)
    recovery.owner = owner
    result = recovery.run(TARGET)
    print(json.dumps({"stage": "unexpected_exit", "result": result}), flush=True)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--worker":
        worker(sys.argv[2], int(sys.argv[3]), sys.argv[4])
    else:
        unittest.main()
