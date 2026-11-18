"""Installed caller-specific capture proof in one strictly task-owned lab.

Run only after reviewing the lab plan and installing the approved package. The
scenario is synthetic and the only diagnostic output is native result field names.
"""

import base64
import json
import os
import re
import secrets
import stat
import sys
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT))
import lab  # noqa: E402
from test_qualified_summaries import PROFILE, PROFILES, SELECTION, envelope  # noqa: E402
from tests import test_qualified_rollup as fixture  # noqa: E402
from tools.lab_lock import LabLock  # noqa: E402

TASK = "cases-source-20261118"
NAME = "adm-cases-source-20261118"
ENDPOINT = "/servicesNS/nobody/splunk_adm/adm/investigations"
CASES_CONFIG = (
    "/servicesNS/nobody/splunk_adm/configs/conf-adm_investigations/persistence"
)
IDENTITY_CONFIG = "/servicesNS/nobody/splunk_adm/configs/conf-adm_identity"
INDEXES = ["k8s", "otel_traces", "cilium_hubble", "netflow"]
FULL_FILTER = "source=*"
RESTRICTED_FILTER = 'NOT source="http:atlas-lab"'


@unittest.skipUnless(os.environ.get("ADM_LAB") == "1", "requires task-owned lab")
class InstalledInvestigationEvidenceTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.environ.get("ADM_LAB_SOURCE_CAPTURE") != "1":
            raise RuntimeError("Explicit source capture opt-in required")
        if lab.task_identity() != (TASK, NAME) or not LabLock(ROOT).check_owned():
            raise RuntimeError("Exact task and inherited live lab lock required")
        lab.verify_target()
        journal = Path(os.environ["ADM_LAB_SOURCE_JOURNAL"])
        if not journal.is_absolute() or journal.exists():
            raise RuntimeError("New absolute private journal required")
        parent = journal.parent.resolve()
        if (
            ROOT == parent
            or ROOT in parent.parents
            or parent.stat().st_uid != os.getuid()
            or parent.stat().st_mode & 0o077
        ):
            raise RuntimeError(
                "Journal must be in a private directory outside checkout"
            )
        cls.journal = journal
        # Observations must precede receipt, and receipt must precede as-of.
        cls.base = int(time.time()) + 10
        cls.end = cls.base + 60
        batches = []
        for offset, snapshot, trace, client, server in (
            (0, "s0", "a", "1", "2"),
            (30, "s1", "b", "3", "4"),
        ):
            start = cls.base + offset
            rows = []
            rows.extend(
                fixture.interval(
                    start + 16,
                    start + 15,
                    start + 1,
                    start + 14,
                    snapshot,
                    [("uid-a", "10.0.0.1"), ("uid-b", "10.0.0.2")],
                )
            )
            rows.extend(
                [
                    fixture.span(
                        "checkout",
                        client,
                        "uid-a",
                        start + 3,
                        start + 9,
                        trace=trace,
                        kind="CLIENT",
                    ),
                    fixture.span(
                        "payments",
                        server,
                        "uid-b",
                        start + 4,
                        start + 8,
                        trace=trace,
                        parent=client,
                    ),
                    fixture.hubble(start + 5, "0:40", "10.0.0.1", "10.0.0.2"),
                ]
            )
            batches.append((start, rows))
        for name, values in (
            ("profile", PROFILE),
            (
                "network",
                {
                    "enabled": "true",
                    "profiles_json": json.dumps(PROFILES),
                    "frontends_json": json.dumps(fixture.frontends(cls.base)),
                },
            ),
            ("summary", {"enabled": "false"}),
        ):
            try:
                lab._json("POST", IDENTITY_CONFIG, {"name": name, **values})
            except lab.LabError:
                lab._json("POST", f"{IDENTITY_CONFIG}/{name}", values)
        lab._json(
            "POST",
            "/servicesNS/nobody/splunk_adm/configs/conf-adm_investigations/capture_transport",
            {
                "management_uri": "https://127.0.0.1:8089",
                "ca_file": "/opt/splunk/etc/auth/adm_lab_tls/ca.pem",
            },
        )
        lab._json(
            "POST",
            CASES_CONFIG,
            {
                "mode": "single_search_head",
                "platform": "enterprise",
                "capture_mode": "reproducible_qualified_v1",
            },
        )
        for start, rows in batches:
            wait = start + 16 - time.time()
            if wait > 0:
                time.sleep(wait)
            lab._hec_post("\n".join(json.dumps(envelope(row)) for row in rows).encode())
            deadline = start + 29
            while time.time() < deadline:
                count = lab.search(
                    "search (index=k8s OR index=otel_traces OR index=cilium_hubble OR index=netflow) | stats count",
                    start,
                    start + 30,
                )
                if int(count[0]["count"]) >= len(rows):
                    break
                time.sleep(1)
            else:
                raise AssertionError("Synthetic evidence missed its indexing horizon")
        wait = cls.end + 2 - time.time()
        if wait > 0:
            time.sleep(wait)
        # Output only native field names, never events or rows.
        native_rows = lab.search(
            f"| admqualified mode=graph {SELECTION} start={cls.base} as_of={cls.base + 30}",
            cls.base,
            cls.base + 30,
        )
        print(
            "Native graph result field names: "
            + ", ".join(sorted({key for row in native_rows for key in row}))
        )
        suffix = secrets.token_hex(5)
        cls.roles = ["atlas_ev_" + suffix + suffix2 for suffix2 in ("a", "b")]
        cls.users = [
            ("atlas_ev_" + suffix + suffix2, secrets.token_urlsafe(24))
            for suffix2 in ("a", "b")
        ]
        for role, source_filter in zip(cls.roles, (FULL_FILTER, RESTRICTED_FILTER)):
            lab._json(
                "POST",
                "/services/authorization/roles",
                {
                    "name": role,
                    "capabilities": ["search", "adm_investigate"],
                    "imported_roles": "",
                    "srchIndexesAllowed": INDEXES,
                    "srchIndexesDefault": INDEXES,
                    "srchFilter": source_filter,
                },
            )
            # Explicit capabilities avoid inherited defaults.
            lab._json(
                "POST",
                "/services/authorization/roles/" + role,
                {
                    "capabilities": ["search", "adm_investigate"],
                    "imported_roles": "",
                    "srchIndexesAllowed": INDEXES,
                    "srchIndexesDefault": INDEXES,
                    "srchFilter": source_filter,
                },
            )
        for (user, password), role in zip(cls.users, cls.roles):
            lab._json(
                "POST",
                "/services/authentication/users",
                {"name": user, "password": password, "roles": role},
            )
            authorization = base64.b64encode((user + ":" + password).encode()).decode()
            request = urllib.request.Request(
                lab.MGMT + "/services/authentication/current-context?output_mode=json",
                headers={"Authorization": "Basic " + authorization},
            )
            with lab.urlopen(request, timeout=30) as response:
                context = json.loads(response.read())["entry"][0]["content"]
            if set(context.get("roles", [])) != {role} or set(
                context.get("capabilities", [])
            ) != {"search", "adm_investigate"}:
                raise AssertionError(
                    "Lab user does not have the intended non-admin context"
                )
        for role, expected in zip(cls.roles, (FULL_FILTER, RESTRICTED_FILTER)):
            content = lab._json("GET", "/services/authorization/roles/" + role)[
                "entry"
            ][0]["content"]
            if (
                set(content.get("srchIndexesAllowed", [])) != set(INDEXES)
                or content.get("srchFilter") != expected
                or set(content.get("srchIndexesDefault", [])) != set(INDEXES)
                or content.get("imported_roles") not in ("", [])
                or set(content.get("capabilities", [])) != {"search", "adm_investigate"}
            ):
                raise AssertionError("Role index or search filter did not apply")
        reference = {
            "schema": 1,
            "scope": {
                "service": "checkout",
                "environment": "prod",
                "cluster": "cluster-a",
                "namespace": "shop",
            },
            "windows": [
                {"start": cls.base, "end": cls.base + 30},
                {"start": cls.base + 30, "end": cls.end},
            ],
        }
        cls.reference = json.dumps(
            reference, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )
        reference["scope"]["service"] = "payments"
        cls.second_reference = json.dumps(
            reference, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )

    def request(self, method, path, data=None, key=None, user=0):
        name, password = self.users[user]
        headers = {
            "Authorization": "Basic "
            + base64.b64encode((name + ":" + password).encode()).decode()
        }
        if key:
            headers["Idempotency-Key"] = key
        body = None if data is None else json.dumps(data).encode()
        if body is not None:
            headers["Content-Type"] = "application/json"
        separator = "&" if "?" in path else "?"
        request = urllib.request.Request(
            lab.MGMT + ENDPOINT + path + separator + "output_mode=json",
            method=method,
            headers=headers,
            data=body,
        )
        # Record exact synthetic request identity before dispatch. Authentication
        # headers are deliberately excluded. An interrupted request stays unknown.
        record = {
            "method": method,
            "path": path,
            "body": data,
            "key": key,
            "user": name,
            "state": "dispatching",
        }
        self._journal(record)
        try:
            response = lab.urlopen(request, timeout=120)
        except urllib.error.HTTPError as response:
            with response:
                status, result = response.code, json.loads(response.read())
        else:
            with response:
                status, result = response.status, json.loads(response.read())
        self._journal({"state": "response", "status": status, "result": result})
        return status, result

    def _journal(self, record):
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(self.journal, flags, 0o600)
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_mode & 0o077
                or info.st_nlink != 1
            ):
                raise RuntimeError("Unsafe journal")
            with os.fdopen(fd, "a") as stream:
                fd = None
                stream.write(json.dumps(record, sort_keys=True) + "\n")
                stream.flush()
                os.fsync(stream.fileno())
        finally:
            if fd is not None:
                os.close(fd)
        directory = os.open(
            self.journal.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        )
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def assert_role_filter(self, user, expected):
        content = lab._json("GET", "/services/authorization/roles/" + self.roles[user])[
            "entry"
        ][0]["content"]
        self.assertEqual(content.get("srchFilter"), expected)
        self.assertEqual(set(content.get("srchIndexesAllowed", [])), set(INDEXES))
        self.assertEqual(set(content.get("srchIndexesDefault", [])), set(INDEXES))
        self.assertIn(content.get("imported_roles"), ("", []))
        self.assertEqual(
            set(content.get("capabilities", [])), {"search", "adm_investigate"}
        )
        name, password = self.users[user]
        authorization = base64.b64encode((name + ":" + password).encode()).decode()
        request = urllib.request.Request(
            lab.MGMT + "/services/authentication/current-context?output_mode=json",
            headers={"Authorization": "Basic " + authorization},
        )
        with lab.urlopen(request, timeout=30) as response:
            context = json.loads(response.read())["entry"][0]["content"]
        self.assertEqual(set(context.get("roles", [])), {self.roles[user]})
        self.assertEqual(
            set(context.get("capabilities", [])), {"search", "adm_investigate"}
        )

    def test_caller_scope_revocation_and_changed_evidence(self):
        self.assertTrue(self.request("GET", "/capabilities")[1]["evidenceWrites"])
        case_body = {
            "schema_version": 1,
            "title": "Synthetic evidence",
            "window": {
                "start": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.base)),
                "end": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.end)),
            },
        }
        status, case = self.request("POST", "/cases", case_body, "create")
        self.assertEqual(status, 201)
        path = "/cases/" + case["id"]
        note = {
            "expected_revision": 1,
            "item": {"type": "note", "text": "Keep this note"},
        }
        self.assertEqual(self.request("POST", path + "/entries", note, "note")[0], 200)
        capture = {
            "expected_revision": 2,
            "reference": self.reference,
            "label": "Synthetic comparison",
        }
        status, saved = self.request("POST", path + "/captures", capture, "capture")
        self.assertEqual(status, 200, "Capture did not succeed")
        self.assertEqual(len(saved["captures"]), 1)
        first_id = saved["capture_ids"][0]
        first_capture = saved["captures"][0]
        self.assertNotIn("source", first_capture)
        for key in ("configuration_fingerprint", "evidence_digest"):
            self.assertTrue(
                bool(re.fullmatch(r"[0-9a-f]{64}", first_capture["data"][key]))
            )
        second_capture_request = {
            "expected_revision": 3,
            "reference": self.second_reference,
            "label": "Second synthetic comparison",
        }
        status, second_saved = self.request(
            "POST", path + "/captures", second_capture_request, "capture2"
        )
        self.assertEqual(status, 200, "Second capture did not succeed")
        self.assertEqual(len(second_saved["capture_ids"]), 2)
        second_id = second_saved["capture_ids"][1]
        self.assertTrue(first_id != second_id)
        status, listed = self.request("GET", "/cases")
        self.assertEqual(status, 200)
        listed_case = next(item for item in listed["items"] if item["id"] == case["id"])
        self.assertEqual(len(listed_case["capture_ids"]), 2)
        self.assertTrue(
            all(
                re.fullmatch(
                    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}",
                    value,
                )
                for value in listed_case["capture_ids"]
            )
        )
        self.assertEqual(listed_case["captures"], [])
        self.assertEqual(listed_case["redactions"]["captures"], 2)
        self.assertEqual(
            self.request(
                "POST",
                path + "/share",
                {"expected_revision": 4, "member": self.users[1][0], "grant": True},
                "share",
            )[0],
            200,
        )
        status, restricted = self.request("GET", path, user=1)
        self.assertEqual(status, 200)
        self.assertEqual(restricted["redactions"]["captures"], 2)
        self.assertEqual(len(restricted["captures"]), 0)
        self.assertEqual(restricted["entries"][0]["text"], "Keep this note")
        lab._json(
            "POST",
            "/services/authorization/roles/" + self.roles[1],
            {"srchFilter": FULL_FILTER},
        )
        self.assert_role_filter(1, FULL_FILTER)
        for target in (path, path + "/export"):
            status, allowed = self.request(
                "GET", target + "?capture_id=" + second_id, user=1
            )
            self.assertEqual(status, 200)
            self.assertEqual(len(allowed["captures"]), 1)
            self.assertTrue(allowed["captures"][0]["id"] == second_id)
            self.assertEqual(allowed["redactions"]["captures"], 1)
            self.assertNotIn("source", allowed["captures"][0])
            for key in ("configuration_fingerprint", "evidence_digest"):
                self.assertTrue(
                    bool(
                        re.fullmatch(
                            r"[0-9a-f]{64}", allowed["captures"][0]["data"][key]
                        )
                    )
                )
        lab._json(
            "POST",
            "/services/authorization/roles/" + self.roles[0],
            {"srchFilter": RESTRICTED_FILTER},
        )
        self.assert_role_filter(0, RESTRICTED_FILTER)
        status, revoked = self.request("GET", path)
        self.assertEqual(status, 200)
        self.assertEqual(len(revoked["captures"]), 0)
        self.assertEqual(revoked["redactions"]["captures"], 2)
        self.assertEqual(revoked["entries"][0]["text"], "Keep this note")
        status, revoked_export = self.request(
            "GET", path + "/export?capture_id=" + first_id
        )
        self.assertEqual(status, 200)
        self.assertEqual(revoked_export["captures"], [])
        self.assertEqual(revoked_export["redactions"]["captures"], 2)
        self.assertEqual(revoked_export["entries"][0]["text"], "Keep this note")
        status, retry = self.request("POST", path + "/captures", capture, "capture")
        self.assertEqual(status, 200)
        self.assertEqual(retry["redactions"]["captures"], 1)
        self.assertEqual(len(retry["captures"]), 0)
        # Simulate loss of reproducibility through a changed qualified-source configuration.
        lab._json(
            "POST",
            "/services/authorization/roles/" + self.roles[0],
            {"srchFilter": FULL_FILTER},
        )
        self.assert_role_filter(0, FULL_FILTER)
        lab._json("POST", IDENTITY_CONFIG + "/profile", {"enabled": "false"})
        status, changed = self.request("GET", path)
        self.assertEqual(status, 200)
        self.assertEqual(changed["redactions"]["captures"], 2)
        self.assertEqual(changed["entries"][0]["text"], "Keep this note")
        status, retry = self.request("POST", path + "/captures", capture, "capture")
        self.assertEqual(status, 200)
        self.assertEqual(len(retry["captures"]), 0)


if __name__ == "__main__":
    unittest.main()
