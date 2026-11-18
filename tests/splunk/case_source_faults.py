"""Installed synthetic interrupted capture and exact-retry scenario."""

import base64
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path[:0] = [str(HERE), str(ROOT / "tools")]
import lab  # noqa: E402
import case_request_lab as owned  # noqa: E402
import case_source_capture as fixture  # noqa: E402
from lab_lock import LabLock  # noqa: E402


def guard():
    if (
        os.environ.get("ADM_LAB_SOURCE_CAPTURE") != "1"
        or lab.task_identity() != (fixture.TASK, fixture.NAME)
        or not LabLock(ROOT).check_owned()
    ):
        raise RuntimeError("exact source task and live lab lock required")
    lab.verify_target()
    ident = lab.lab_tls.read_container(lab.SECRETS, (fixture.TASK, fixture.NAME))
    info = json.loads(
        subprocess.check_output(["docker", "inspect", ident], timeout=30)
    )[0]
    if not info["State"]["Running"] or sorted(
        (m["Type"], m.get("Name"), m["Destination"]) for m in info["Mounts"]
    ) != sorted(
        ("volume", fixture.NAME + "-" + x, "/opt/splunk/" + x) for x in ("etc", "var")
    ):
        raise RuntimeError("unexpected source container")
    return ident


# Keep the reviewed native helper and hook byte-for-byte, including their fixed
# isolated in-container paths. Only the outer authorization guard is replaced.
owned.guard = guard


@contextmanager
def preserved_hook(native, journal):
    """Attempt restoration independently, including after an unknown install."""
    primary = None
    try:
        native("hook_install")
        yield
    except BaseException as exc:
        primary = exc
        raise
    finally:
        outcomes = {}
        failures = []
        for action, payload in (
            (
                "set_fault",
                {"mode": "off", "request_id": "", "generation": "precommit"},
            ),
            ("hook_remove", None),
        ):
            try:
                result = (
                    native(action, payload) if payload is not None else native(action)
                )
                if action == "hook_remove" and (
                    not isinstance(result, dict)
                    or any(
                        result.get(key) is not True
                        for key in ("hook_removed", "hook_restored", "cache_restored")
                    )
                    or result.get("fixture_hook_active") is not False
                ):
                    raise RuntimeError("original hook restoration unproven")
                outcomes[action] = {"state": "acknowledged"}
            except BaseException as exc:
                failures.append(action)
                outcomes[action] = {
                    "state": "failed_or_uncertain",
                    "error_type": type(exc).__name__,
                }
        try:
            journal({"state": "hook_cleanup", "outcomes": outcomes})
        except BaseException:
            failures.append("cleanup_journal")
        if failures:
            message = "hook cleanup failed or uncertain: " + ", ".join(failures)
            if primary is not None:
                primary.add_note(message)
            else:
                raise RuntimeError(message)


def source_native(principal, key):
    ident = guard()
    result = subprocess.run(
        [
            "docker",
            "exec",
            "--user",
            "splunk",
            "-i",
            "--env",
            "ADM_CASE_SOURCE_NATIVE_TASK=" + fixture.TASK,
            ident,
            "/opt/splunk/bin/splunk",
            "cmd",
            "python3.13",
            owned.DIRECTORY + "/case_source_native.py",
        ],
        input=json.dumps({"principal": principal, "request_id": key}).encode(),
        capture_output=True,
        timeout=30,
    )
    guard()
    if result.returncode:
        raise RuntimeError("source native observation failed")
    return json.loads(result.stdout)


@unittest.skipUnless(os.environ.get("ADM_LAB") == "1", "requires task-owned lab")
class SourceFaults(fixture.InstalledInvestigationEvidenceTest):
    def test_caller_scope_revocation_and_changed_evidence(self):
        owned.stage()
        ident = guard()
        source = HERE / "case_source_native.py"
        target = owned.DIRECTORY + "/case_source_native.py"
        subprocess.run(
            ["docker", "cp", str(source), ident + ":" + target],
            check=True,
            timeout=30,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        for command in (["chown", "splunk:splunk", target], ["chmod", "600", target]):
            subprocess.run(
                ["docker", "exec", "--user", "root", ident, *command],
                check=True,
                timeout=30,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        actual = subprocess.check_output(
            ["docker", "exec", "--user", "splunk", ident, "sha256sum", target],
            timeout=30,
            text=True,
        ).split()[0]
        self.assertEqual(actual, hashlib.sha256(source.read_bytes()).hexdigest())
        self.assertFalse(owned.native("probe")["fixture_hook_active"])
        with preserved_hook(owned.native, self._journal):
            for mode in ("precommit", "postcommit"):
                path, capture_id = self.capture_fault(mode)
        self.assertFalse(owned.native("probe")["fixture_hook_active"])
        status, after = self.request("GET", path + "?capture_id=" + capture_id)
        self.assertEqual(status, 200)
        self.assertEqual(len(after["captures"]), 1)
        self.assertEqual(after["captures"][0]["id"], capture_id)
        self._journal({"state": "uninjected_selected_capture_verified"})

    def capture_fault(self, mode):
        case_body = {
            "schema_version": 1,
            "title": "Synthetic capture " + mode,
            "window": {
                "start": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.base)),
                "end": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.end)),
            },
        }
        status, case = self.request("POST", "/cases", case_body, "create-" + mode)
        self.assertEqual(status, 201)
        path = "/cases/" + case["id"]
        note = {"expected_revision": 1, "item": {"type": "note", "text": "retained"}}
        self.assertEqual(
            self.request("POST", path + "/entries", note, "note-" + mode)[0], 200
        )
        body = {
            "expected_revision": 2,
            "reference": self.reference,
            "label": "Synthetic interrupted capture",
        }
        key = "source-" + mode
        before = source_native(self.users[0][0], key)
        self.assertEqual(before["requests"], [])
        owned.native("set_fault", {"mode": mode, "request_id": key, "generation": mode})
        started = time.monotonic()
        try:
            status, _ = self.request("POST", path + "/captures", body, key)
            self.assertIn(status, (500, 502, 503, 504))
        except (OSError, TimeoutError):
            self._journal({"state": "transport_unknown", "key": key})
        deadline = started + 55
        while time.monotonic() < deadline:
            observed = owned.native("observe", {"generation": mode})
            if (
                observed["marker_present"]
                and not observed["worker_pids"]
                and not observed["group_alive"]
                and not observed["child_exists"]
            ):
                break
            time.sleep(0.2)
        else:
            self.fail("fault worker or descendant retirement unproven")
        state = source_native(self.users[0][0], key)
        self.assertEqual(len(state["requests"]), 1 if mode == "postcommit" else 0)
        jobs = state["jobs"][len(before["jobs"]) :]
        self.assertGreaterEqual(len(jobs), 2)
        self.assertTrue(all(j["state"] == "deleted" and j["server_sid"] for j in jobs))
        self.check_jobs_absent(jobs)
        self._journal(
            {
                "state": "fault_observed",
                "key": key,
                "process": observed,
                "request_count": len(state["requests"]),
                "jobs": jobs,
            }
        )
        owned.native("set_fault", {"mode": "off", "request_id": "", "generation": mode})
        status, saved = self.request("POST", path + "/captures", body, key)
        self.assertEqual(status, 200)
        self.assertEqual(len(saved["capture_ids"]), 1)
        capture_id = saved["capture_ids"][0]
        after = source_native(self.users[0][0], key)
        self.assertTrue(
            all(j["state"] == "deleted" and j["server_sid"] for j in after["jobs"])
        )
        self.check_jobs_absent(after["jobs"])
        self.assertEqual(len(after["requests"]), 1)
        self.assertEqual(after["requests"][0]["case_id"], case["id"])
        if state["requests"]:
            self.assertEqual(
                state["requests"][0]["digest"], after["requests"][0]["digest"]
            )
        self._journal(
            {
                "state": "reconciled_by_exact_retry",
                "key": key,
                "case_id": case["id"],
                "capture_id": capture_id,
            }
        )
        lab._json(
            "POST",
            "/services/authorization/roles/" + self.roles[0],
            {"srchFilter": fixture.RESTRICTED_FILTER},
        )
        self.assert_role_filter(0, fixture.RESTRICTED_FILTER)
        for target in (path, path + "/export"):
            status, denied = self.request("GET", target + "?capture_id=" + capture_id)
            self.assertEqual(status, 200)
            self.assertEqual(denied["captures"], [])
            self.assertEqual(denied["entries"][0]["text"], "retained")
        status, denied_retry = self.request("POST", path + "/captures", body, key)
        self.assertEqual(status, 200)
        self.assertEqual(denied_retry["captures"], [])
        lab._json(
            "POST",
            "/services/authorization/roles/" + self.roles[0],
            {"srchFilter": fixture.FULL_FILTER},
        )
        self.assert_role_filter(0, fixture.FULL_FILTER)
        return path, capture_id

    def check_jobs_absent(self, jobs):
        name, password = self.users[0]
        authorization = base64.b64encode((name + ":" + password).encode()).decode()
        for job in jobs:
            url = (
                lab.MGMT
                + "/services/search/jobs/"
                + urllib.parse.quote(job["server_sid"], safe="")
                + "?output_mode=json"
            )
            request = urllib.request.Request(
                url, headers={"Authorization": "Basic " + authorization}
            )
            try:
                with lab.urlopen(request, timeout=10):
                    self.fail("deleted source job still visible")
            except urllib.error.HTTPError as exc:
                self.assertEqual(exc.code, 404)


if __name__ == "__main__":
    unittest.main()
