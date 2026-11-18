"""Installed cookie/session, Web proxy, CSRF and case ACL qualification.

Exact owned lab only. Source capture remains disabled. This is a native Web HTTP
session test, not a rendered-browser or protected-source qualification.
"""

import os
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import lab  # noqa: E402
import test_cases_endpoint as notes_fixture  # noqa: E402
from web_session import CASES, CONTEXT, RequestJournal, WebSession, WebSessionError  # noqa: E402

TASK = "cases-web-20261117"
NAME = "adm-cases-web-20261117"


@unittest.skipUnless(
    os.environ.get("ADM_LAB_WEB_TLS") == "1", "explicit HTTPS Web qualification only"
)
class InstalledWebCasesTest(notes_fixture.InstalledCasesTest):
    def setUp(self):
        if lab.task_identity() != (TASK, NAME):
            raise RuntimeError("requires its exact task-owned Web lab")
        if os.environ.get("ADM_LAB_WEB_TLS") != "1":
            raise RuntimeError("requires verified Web HTTPS")
        self.journal = RequestJournal(os.environ["ADM_LAB_WEB_RECEIPT"])
        super().setUp()
        self.journal.fixture = {
            "role": self.role,
            "users": [name for name, _password in self.users],
            "initial_persistence": {
                key: self._config_snapshot[key]
                for key in ("mode", "platform", "capture_mode")
            },
        }
        self.journal._persist()
        self.web = [WebSession(journal=self.journal), WebSession(journal=self.journal)]
        for session in self.web:
            self.addCleanup(session.close)

    def api(self, user, method, path, data=None, *, key=None, csrf=True):
        response = self.web[user].request(
            method, CASES + path + "?output_mode=json", data=data, key=key, csrf=csrf
        )
        return response.status, response.json()

    def test_web_login_csrf_private_sharing_revocation_export_and_logout(self):
        anonymous = WebSession()
        self.addCleanup(anonymous.close)
        response = anonymous.request(
            "GET", CASES + "/cases?output_mode=json", csrf=False
        )
        self.assertIn(response.status, (302, 303, 401, 403))
        # One failed login only; do not trip the platform lockout threshold.
        rejected = WebSession()
        self.addCleanup(rejected.close)
        with self.assertRaises(WebSessionError):
            rejected.login(self.users[1][0], "incorrect-synthetic-password")
        for (username, password), session in zip(self.users, self.web):
            context = session.login(username, password)
            notes_fixture.assert_exact_context(self, context, username, self.role)
        self.assertTrue(self.web[0].csrf_token() != self.web[1].csrf_token())
        status, capabilities = self.api(0, "GET", "/capabilities")
        self.assertEqual(status, 200)
        self.assertFalse(capabilities["available"])
        lab._json(
            "POST",
            notes_fixture.CONFIG,
            {
                "mode": "single_search_head",
                "platform": "enterprise",
                "capture_mode": "disabled",
            },
        )
        status, capabilities = self.api(0, "GET", "/capabilities")
        self.assertEqual(status, 200)
        self.assertTrue(capabilities["available"])
        self.assertFalse(capabilities["evidenceWrites"])
        create = {
            "schema_version": 1,
            "title": "Synthetic Web case",
            "window": {"start": "2026-01-01T00:00:00Z", "end": "2026-01-01T01:00:00Z"},
        }
        for label, token in (
            ("missing", False),
            ("wrong", "invalid-test-token"),
            ("other-session", self.web[1].csrf_token()),
        ):
            response = self.web[0].request(
                "POST",
                CASES + "/cases?output_mode=json",
                data=create,
                key="web-create-csrf-" + label,
                csrf=token,
            )
            self.assertIn(response.status, (401, 403))
            self.assertTrue(
                b"csrf" in response.body.lower(), "Web rejection must identify CSRF"
            )
            status, listing = self.api(0, "GET", "/cases")
            self.assertEqual(status, 200)
            self.assertEqual(listing["items"], [])
        status, case = self.api(0, "POST", "/cases", create, key="web-create")
        self.assertEqual(status, 201)
        path = "/cases/" + case["id"]
        self.assertEqual(
            self.api(0, "POST", "/cases", create, key="web-create"), (201, case)
        )
        for target in (path, path + "/export"):
            self.assertEqual(self.api(1, "GET", target)[0], 403)
        status, listing = self.api(1, "GET", "/cases")
        self.assertEqual(status, 200)
        self.assertNotIn(case["id"], [item["id"] for item in listing["items"]])
        revision = case["revision"]
        share = {
            "expected_revision": revision,
            "member": self.users[1][0],
            "grant": True,
        }
        for label, token in (
            ("missing", False),
            ("wrong", "invalid-test-token"),
            ("other-session", self.web[1].csrf_token()),
        ):
            response = self.web[0].request(
                "POST",
                CASES + path + "/share?output_mode=json",
                data=share,
                key="web-bad-csrf-" + label,
                csrf=token,
            )
            self.assertIn(response.status, (401, 403))
            self.assertTrue(
                b"csrf" in response.body.lower(), "Web rejection must identify CSRF"
            )
            # A native CSRF denial must not be mistaken for a denied-after-commit
            # application response: prove the case and membership did not change.
            status, current = self.api(0, "GET", path)
            self.assertEqual(status, 200)
            self.assertEqual(current["revision"], revision)
            self.assertEqual(self.api(1, "GET", path)[0], 403)
        for label, token in (
            ("missing", False),
            ("wrong", "invalid-test-token"),
            ("other-session", self.web[1].csrf_token()),
        ):
            response = self.web[0].request(
                "POST",
                CASES + path + "/entries?output_mode=json",
                data={
                    "expected_revision": revision,
                    "item": {"type": "note", "text": "Rejected CSRF note"},
                },
                key="web-entries-csrf-" + label,
                csrf=token,
            )
            self.assertIn(response.status, (401, 403))
            self.assertTrue(
                b"csrf" in response.body.lower(), "Web rejection must identify CSRF"
            )
            status, current = self.api(0, "GET", path)
            self.assertEqual(status, 200)
            self.assertEqual(current["revision"], revision)
            self.assertEqual(current["entries"], [])
        status, case = self.api(
            0,
            "POST",
            path + "/entries",
            {
                "expected_revision": revision,
                "item": {"type": "note", "text": "Owner note through Web"},
            },
            key="web-owner-note",
        )
        self.assertEqual(status, 200)
        original = case["entries"][0]
        status, case = self.api(
            0,
            "POST",
            path + "/entries",
            {
                "expected_revision": case["revision"],
                "item": {
                    "type": "note",
                    "text": "Revised Web note",
                    "supersedes_entry_id": original["id"],
                },
            },
            key="web-revise",
        )
        self.assertEqual(status, 200)
        self.assertEqual(case["entries"][0], original)
        self.assertEqual(case["entries"][1]["supersedes_entry_id"], original["id"])
        status, case = self.api(
            0,
            "POST",
            path + "/share",
            {
                **share,
                "expected_revision": case["revision"],
            },
            key="web-share",
        )
        self.assertEqual(status, 200)
        for target in (path, path + "/export"):
            status, shared = self.api(1, "GET", target)
            self.assertEqual(status, 200)
            self.assertEqual(shared["id"], case["id"])
            self.assertEqual(len(shared["entries"]), 2)
        append = {
            "expected_revision": case["revision"],
            "item": {"type": "question", "text": "Shared Web question"},
        }
        status, case = self.api(
            1, "POST", path + "/entries", append, key="web-member-note"
        )
        self.assertEqual(status, 200)
        status, case = self.api(
            0,
            "POST",
            path + "/share",
            {
                "expected_revision": case["revision"],
                "member": self.users[1][0],
                "grant": False,
            },
            key="web-revoke",
        )
        self.assertEqual(status, 200)
        revoked_context = self.web[1].request("GET", CONTEXT)
        self.assertEqual(revoked_context.status, 200)
        notes_fixture.assert_exact_context(
            self,
            revoked_context.json()["entry"][0]["content"],
            self.users[1][0],
            self.role,
        )
        for target in (path, path + "/export"):
            denied_status, denied_body = self.api(1, "GET", target)
            self.assertEqual(denied_status, 403)
            self.assertEqual(denied_body.get("error"), "forbidden")
        self.assertEqual(
            self.api(1, "POST", path + "/entries", append, key="web-member-note")[0],
            403,
        )
        self.assertEqual(
            self.api(
                1,
                "POST",
                path + "/entries",
                {
                    **append,
                    "expected_revision": case["revision"],
                },
                key="web-revoked-write",
            )[0],
            403,
        )
        status, exported = self.api(0, "GET", path + "/export")
        self.assertEqual(status, 200)
        self.assertEqual(len(exported["entries"]), 3)
        self.assertEqual(exported["captures"], [])
        for label, token in (
            ("missing", False),
            ("wrong", "invalid-test-token"),
            ("other-session", self.web[1].csrf_token()),
        ):
            response = self.web[0].request(
                "DELETE",
                CASES + path + "?output_mode=json",
                data={"expected_revision": case["revision"]},
                key="web-delete-csrf-" + label,
                csrf=token,
            )
            self.assertIn(response.status, (401, 403))
            self.assertTrue(
                b"csrf" in response.body.lower(), "Web rejection must identify CSRF"
            )
            status, current = self.api(0, "GET", path)
            self.assertEqual(status, 200)
            self.assertEqual(current["revision"], case["revision"])
        self.assertEqual(
            self.api(
                0,
                "DELETE",
                path,
                {
                    "expected_revision": case["revision"],
                },
                key="web-delete",
            )[0],
            200,
        )
        # Retain old cookies only in memory to prove server-side logout invalidation.
        stale = self.web[0].clone()
        self.addCleanup(stale.close)
        before_logout = stale.request("GET", CONTEXT)
        self.assertEqual(before_logout.status, 200)
        self.assertEqual(
            before_logout.json()["entry"][0]["content"]["username"], self.users[0][0]
        )
        response = self.web[0].request("GET", "/en-US/account/logout")
        self.assertIn(response.status, (200, 302, 303))
        self.assertIn(stale.request("GET", CONTEXT).status, (302, 303, 401, 403))


def load_tests(_loader, _tests, _pattern):
    # Reuse provisioning/cleanup, not the inherited management-REST scenarios.
    return unittest.TestSuite(
        [
            InstalledWebCasesTest(
                "test_web_login_csrf_private_sharing_revocation_export_and_logout"
            )
        ]
    )
