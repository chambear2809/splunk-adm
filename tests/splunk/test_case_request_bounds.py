"""Installed notes supervision, with explicit disposable platform fault injection."""

import base64
import http.client
import json
import os
from pathlib import Path
import socket
import sys
import threading
import time
import unittest
import urllib.error
import urllib.request

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import case_request_lab as owned  # noqa: E402
import lab  # noqa: E402
import test_cases_endpoint as notes  # noqa: E402
from web_session import CASES, RequestJournal, WebResponse, WebSession  # noqa: E402

PHASE = None


def admin_status(path):
    secret = lab.read_secrets()["SPLUNK_PASSWORD"]
    authorization = base64.b64encode(("admin:" + secret).encode()).decode()
    request = urllib.request.Request(
        lab.MGMT + path + "?output_mode=json",
        headers={"Authorization": "Basic " + authorization},
    )
    try:
        response = lab.urlopen(request, timeout=30)
    except urllib.error.HTTPError as response:
        with response:
            return response.code
    with response:
        return response.status


@unittest.skipUnless(
    os.environ.get("ADM_LAB_REQUEST_BOUNDS") == "1", "exact installed request lab only"
)
class InstalledRequestBounds(notes.InstalledCasesTest):
    def setUp(self):
        owned.guard()
        self.journal = RequestJournal(os.environ["ADM_LAB_WEB_RECEIPT"])
        self._cleaned = False
        super().setUp()
        self.journal.fixture = {
            "phase": PHASE,
            "role": self.role,
            "users": [u for u, _ in self.users],
            "checks": [],
        }
        self.journal._persist()
        self.web = [WebSession(journal=self.journal), WebSession(journal=self.journal)]
        for session, (username, password) in zip(self.web, self.users):
            self.addCleanup(session.close)
            notes.assert_exact_context(
                self, session.login(username, password), username, self.role
            )

    def checked(self, label, details=True):
        self.journal.fixture["checks"].append({"check": label, "details": details})
        self.journal._persist()

    def api(self, user, method, path, body=None, key=None, csrf=True):
        response = self.web[user].request(
            method, CASES + path + "?output_mode=json", data=body, key=key, csrf=csrf
        )
        return response.status, response.json()

    def enable(self):
        status, capabilities = self.api(0, "GET", "/capabilities")
        self.assertEqual(status, 200)
        self.assertFalse(capabilities["available"])
        lab._json(
            "POST",
            notes.CONFIG,
            {
                "mode": "single_search_head",
                "platform": "enterprise",
                "capture_mode": "disabled",
            },
        )
        status, capabilities = 503, {}
        for attempt in range(2):
            status, capabilities = self.api(0, "GET", "/capabilities")
            if status == 200 and capabilities.get("available") is True:
                break
            if attempt == 0:
                time.sleep(0.5)
        failed = status != 200 or capabilities.get("available") is not True
        diagnostic = self.diagnose_capability_failure() if failed else {}
        if failed:
            server_info = self.web[0].request(
                "GET", "/en-US/splunkd/__raw/services/server/info?output_mode=json"
            )
            diagnostic["server_info_http_status"] = server_info.status
        self.assertEqual(
            status,
            200,
            f"capabilities response: {capabilities!r}; host diagnostics: {diagnostic!r}",
        )
        self.assertTrue(capabilities["available"])
        self.assertFalse(capabilities["evidenceWrites"])

    def diagnose_capability_failure(self):
        diagnostic = {}
        try:
            owned.native("hook_install")
            owned.native(
                "set_fault",
                {
                    "mode": "diagnostic",
                    "request_id": "",
                    "generation": "diagnostic",
                },
            )
            try:
                status, payload = self.api(0, "GET", "/capabilities")
                diagnostic["diagnostic_response"] = {
                    "status": status,
                    "available": payload.get("available") is True,
                }
            finally:
                owned.native(
                    "set_fault",
                    {
                        "mode": "off",
                        "request_id": "",
                        "generation": "diagnostic",
                    },
                )
            diagnostic["qualification"] = owned.native("request_diagnostics")
        except Exception as exc:  # noqa: BLE001
            diagnostic["diagnostic_error_type"] = type(exc).__name__
            diagnostic["diagnostic_error"] = str(exc)[:500]
        finally:
            try:
                removed = owned.native("hook_remove")
                diagnostic["hook_restored"] = removed.get("hook_restored") is True
                diagnostic["fixture_hook_active"] = owned.native("probe").get(
                    "fixture_hook_active"
                )
            except Exception as exc:  # noqa: BLE001
                diagnostic["hook_restore_error_type"] = type(exc).__name__
                diagnostic["hook_restore_error"] = str(exc)[:500]
        diagnostic["host"] = owned.native("host_diagnostics")
        return diagnostic

    @staticmethod
    def body(title):
        return {
            "schema_version": 1,
            "title": title,
            "window": {"start": "2026-01-01T00:00:00Z", "end": "2026-01-01T01:00:00Z"},
        }

    def positive(self):
        self.assertFalse(owned.native("probe")["fixture_hook_active"])
        self.enable()
        body = self.body("Supervised notes " + PHASE)
        status, _ = self.api(
            0, "POST", "/cases", body, "csrf-rejected-" + PHASE, csrf=False
        )
        self.assertIn(status, (401, 403))
        self.assertTrue(self.journal.records[-1].get("csrf_error_mentioned"))
        self.assertEqual(self.api(0, "GET", "/cases")[1]["items"], [])
        key = "positive-create-" + PHASE
        status, case = self.api(0, "POST", "/cases", body, key)
        self.assertEqual(status, 201)
        self.assertEqual(self.api(0, "POST", "/cases", body, key), (201, case))
        path = "/cases/" + case["id"]
        for suffix in ("", "/export"):
            self.assertEqual(self.api(1, "GET", path + suffix)[0], 403)
        note = {
            "expected_revision": case["revision"],
            "item": {"type": "note", "text": "Immutable original"},
        }
        status, case = self.api(
            0, "POST", path + "/entries", note, "positive-note-" + PHASE
        )
        self.assertEqual(status, 200)
        edit = {
            "expected_revision": case["revision"],
            "item": {
                "type": "note",
                "text": "Supervised revision",
                "supersedes_entry_id": case["entries"][0]["id"],
            },
        }
        status, case = self.api(
            0, "POST", path + "/entries", edit, "positive-edit-" + PHASE
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            [e["text"] for e in case["entries"]],
            ["Immutable original", "Supervised revision"],
        )
        self.assertEqual(
            self.api(0, "POST", path + "/entries", edit, "positive-stale-" + PHASE)[0],
            409,
        )
        share = {
            "expected_revision": case["revision"],
            "member": self.users[1][0],
            "grant": True,
        }
        status, case = self.api(
            0, "POST", path + "/share", share, "positive-share-" + PHASE
        )
        self.assertEqual(status, 200)
        self.assertEqual(self.api(1, "GET", path)[1], case)
        self.assertEqual(self.api(1, "GET", path + "/export")[1], case)
        question = {
            "expected_revision": case["revision"],
            "item": {"type": "question", "text": "Shared member question"},
        }
        status, case = self.api(
            1, "POST", path + "/entries", question, "positive-question-" + PHASE
        )
        self.assertEqual(status, 200)
        revoke = {
            "expected_revision": case["revision"],
            "member": self.users[1][0],
            "grant": False,
        }
        self.assertEqual(
            self.api(0, "POST", path + "/share", revoke, "positive-revoke-" + PHASE)[0],
            200,
        )
        for suffix in ("", "/export"):
            self.assertEqual(self.api(1, "GET", path + suffix)[0], 403)
        self.assertEqual(self.api(1, "GET", path + "/audit")[0], 403)
        self.assertEqual(
            self.api(
                1, "POST", path + "/entries", question, "positive-question-" + PHASE
            )[0],
            403,
        )
        self.assertEqual(self.api(0, "GET", path + "/audit")[0], 200)
        current = self.api(0, "GET", path)[1]
        self.assertEqual(
            self.api(
                0,
                "DELETE",
                path,
                {"expected_revision": current["revision"]},
                "positive-delete-" + PHASE,
            )[0],
            200,
        )
        self.checked(
            "uninjected login, CSRF, capabilities, create/read/retry/revisions/stale rejection/share/revoke/revoked retry/export/audit/delete"
        )
        if PHASE == "before":
            seeded = owned.native("seed_large", {"principal": self.users[0][0]})
            expected = set(seeded["case_ids"])
            found = []
            cursor = None
            pages = []
            for _ in range(8):
                # api adds output_mode itself, so use explicit URL for cursor pages.
                response = self.web[0].request(
                    "GET",
                    CASES
                    + "/cases?output_mode=json"
                    + ("&after=" + cursor if cursor else ""),
                )
                self.assertEqual(response.status, 200)
                page = response.json()
                pages.append(len(response.body))
                found.extend(c["id"] for c in page["items"])
                cursor = page["next"]
                if cursor is None:
                    break
            self.assertIsNone(cursor)
            self.assertEqual(len(found), len(set(found)))
            self.assertEqual(set(found), expected)
            self.assertGreaterEqual(len(pages), 3)
            self.assertTrue(all(n <= 1_500_000 for n in pages))
            self.checked(
                "installed byte pagination preserves all large cases",
                {"pages": len(pages), "page_bytes": pages, "seed": seeded},
            )

    def connection(self, body, key):
        path = CASES + "/cases?output_mode=json"
        request = urllib.request.Request(self.web[0].origin + path)
        self.web[0].cookies.add_cookie_header(request)
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Requested-With": "XMLHttpRequest",
            "X-Splunk-Form-Key": self.web[0].csrf_token(),
            "Idempotency-Key": key,
            "Cookie": request.get_header("Cookie", ""),
        }
        connection = http.client.HTTPSConnection(
            "127.0.0.1", self.web[0].port, context=lab._context(), timeout=55
        )
        return connection, path, headers, json.dumps(body).encode()

    def wait_retired(self, generation, started):
        deadline = started + 49
        last = None
        while time.monotonic() < deadline:
            last = owned.native("observe", {"generation": generation})
            if time.monotonic() > deadline:
                self.fail("retirement observation exceeded operational test allowance")
            if (
                not last["worker_pids"]
                and not last.get("group_alive", False)
                and not last.get("child_exists", False)
            ):
                return last
            time.sleep(0.2)
        self.fail("request group was not retired within operational test allowance")

    def fault(self, mode, generation):
        key = "bounded-" + generation
        body = self.body("Interrupted " + generation)
        before = owned.native(
            "case_state", {"principal": self.users[0][0], "request_id": key}
        )
        self.assertEqual(before["request_count"], 0)
        owned.native(
            "set_fault", {"mode": mode, "request_id": key, "generation": generation}
        )
        connection, path, headers, raw = self.connection(body, key)
        index = self.journal.begin("POST", path, key, raw)
        started = time.monotonic()
        response = None
        try:
            connection.request("POST", path, body=raw, headers=headers)
            response = connection.getresponse()
            result = WebResponse(
                response.status, response.read(2 * 1024 * 1024 + 1), response.headers
            )
            self.assertLessEqual(len(result.body), 2 * 1024 * 1024)
            self.journal.response(index, result)
            self.assertIn(result.status, (500, 502, 503, 504))
        except (OSError, http.client.HTTPException):
            self.journal.unknown(index)
        finally:
            connection.close()
        response_elapsed = time.monotonic() - started
        retired = self.wait_retired(generation, started)
        retirement_elapsed = time.monotonic() - started
        self.assertEqual(retired["marker"]["phase"], generation)
        state = owned.native(
            "case_state", {"principal": self.users[0][0], "request_id": key}
        )
        self.assertEqual(state["request_count"], 1 if mode == "postcommit" else 0)
        self.assertEqual(
            state["owner_case_count"],
            before["owner_case_count"] + (1 if mode == "postcommit" else 0),
        )
        owned.native(
            "set_fault", {"mode": "off", "request_id": "", "generation": generation}
        )
        status, case = self.api(0, "POST", "/cases", body, key)
        self.assertEqual(status, 201)
        self.assertEqual(self.api(0, "POST", "/cases", body, key), (201, case))
        after = owned.native(
            "case_state", {"principal": self.users[0][0], "request_id": key}
        )
        self.assertEqual(after["request_count"], 1)
        self.assertEqual(after["owner_case_count"], before["owner_case_count"] + 1)
        self.assertEqual(after["result"]["case_id"], case["id"])
        if mode == "postcommit":
            self.assertEqual(state["result"]["case_id"], case["id"])
        self.journal.records[index]["reconciled_by_exact_retry"] = True
        self.journal._persist()
        self.checked(
            "injected " + generation,
            {
                "response_elapsed_seconds": round(response_elapsed, 2),
                "retirement_observed_seconds": round(retirement_elapsed, 2),
                "reconciled_elapsed_seconds": round(time.monotonic() - started, 2),
                "observed": retired,
                "committed_before_retry": bool(state["request_count"]),
                "exact_retry_case_id": case["id"],
            },
        )

    def disconnect(self):
        generation = "disconnect"
        key = "bounded-disconnect"
        body = self.body("Disconnected committed write")
        before = owned.native(
            "case_state", {"principal": self.users[0][0], "request_id": key}
        )
        self.assertEqual(before["request_count"], 0)
        owned.native(
            "set_fault",
            {"mode": "postcommit", "request_id": key, "generation": generation},
        )
        connection, path, headers, raw = self.connection(body, key)
        index = self.journal.begin("POST", path, key, raw)
        result = []

        def request():
            try:
                connection.request("POST", path, body=raw, headers=headers)
                response = connection.getresponse()
                with response:
                    response.read(2 * 1024 * 1024 + 1)
                result.append("unexpected_response")
            except (OSError, http.client.HTTPException):
                result.append("disconnected")

        started = time.monotonic()
        thread = threading.Thread(target=request)
        thread.start()
        try:
            deadline = started + 15
            while time.monotonic() < deadline:
                observed = owned.native("observe", {"generation": generation})
                if observed.get("marker"):
                    break
                time.sleep(0.1)
            else:
                self.fail("post-commit disconnect marker missing")
            committed = owned.native(
                "case_state", {"principal": self.users[0][0], "request_id": key}
            )
            self.assertEqual(committed["request_count"], 1)
            self.assertEqual(
                committed["owner_case_count"], before["owner_case_count"] + 1
            )
            if connection.sock is not None:
                connection.sock.shutdown(socket.SHUT_RDWR)
            connection.close()
            thread.join(timeout=3)
            self.assertFalse(thread.is_alive())
            self.assertEqual(result, ["disconnected"])
            self.journal.unknown(index)
            retired = self.wait_retired(generation, started)
            retirement_elapsed = time.monotonic() - started
        finally:
            connection.close()
            thread.join(timeout=3)
        owned.native(
            "set_fault", {"mode": "off", "request_id": "", "generation": generation}
        )
        status, case = self.api(0, "POST", "/cases", body, key)
        self.assertEqual(status, 201)
        self.assertEqual(self.api(0, "POST", "/cases", body, key), (201, case))
        after = owned.native(
            "case_state", {"principal": self.users[0][0], "request_id": key}
        )
        self.assertEqual(after["request_count"], 1)
        self.assertEqual(after["owner_case_count"], before["owner_case_count"] + 1)
        self.assertEqual(committed["result"]["case_id"], case["id"])
        self.assertEqual(after["result"]["case_id"], case["id"])
        self.journal.records[index]["reconciled_by_exact_retry"] = True
        self.journal._persist()
        self.checked(
            "client disconnect after durable commit",
            {
                "observed": retired,
                "retirement_observed_seconds": round(retirement_elapsed, 2),
                "reconciled_elapsed_seconds": round(time.monotonic() - started, 2),
                "exact_retry_case_id": case["id"],
            },
        )

    def faults(self):
        self.enable()
        self.journal.fixture["hook_state"] = "install_intent"
        self.journal._persist()
        installed = owned.native("hook_install")
        self.journal.fixture["hook_installed"] = installed
        self.journal._persist()
        self.addCleanup(self.remove_hook)
        for mode in ("auth", "config", "precommit", "postcommit"):
            self.fault(mode, mode)
        self.disconnect()
        self.remove_hook()
        self.assertFalse(owned.native("probe")["fixture_hook_active"])
        self.checked("original platform startup hook and cache restored exactly")

    def remove_hook(self):
        if self.journal.fixture.get("hook_removed"):
            return
        owned.native(
            "set_fault", {"mode": "off", "request_id": "", "generation": "auth"}
        )
        removed = owned.native("hook_remove")
        self.assertTrue(removed["hook_restored"])
        self.assertTrue(removed["cache_restored"])
        self.journal.fixture["hook_removed"] = removed
        self.journal._persist()

    def test_installed_notes_request_bounds(self):
        primary = None
        try:
            if PHASE == "faults":
                self.faults()
            else:
                self.positive()
            self.journal.fixture["checks_passed"] = True
            self.journal._persist()
        except BaseException as exc:
            primary = exc
            raise
        finally:
            outcome = self._outcome.result
            before = len(outcome.errors) + len(outcome.failures)
            self.doCleanups()
            self._cleaned = True
            if primary is None:
                self.assertEqual(len(outcome.errors) + len(outcome.failures), before)
                for username, _ in self.users:
                    self.assertEqual(
                        admin_status("/services/authentication/users/" + username), 404
                    )
                self.assertEqual(
                    admin_status("/services/authorization/roles/" + self.role), 404
                )
                config = self._config_content(
                    notes.CONFIG, ("mode", "platform", "capture_mode")
                )
                self.assertEqual(
                    {k: config[k] for k in ("mode", "platform", "capture_mode")},
                    {
                        k: self._config_snapshot[k]
                        for k in ("mode", "platform", "capture_mode")
                    },
                )
                self.journal.fixture["cleanup_verified"] = True
                self.journal._persist()


if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ("before", "faults", "after"):
        raise SystemExit("explicit before/faults/after required")
    PHASE = sys.argv.pop()
    suite = unittest.TestSuite(
        [InstalledRequestBounds("test_installed_notes_request_bounds")]
    )
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(
        0
        if result.wasSuccessful() and result.testsRun == 1 and not result.skipped
        else 1
    )
