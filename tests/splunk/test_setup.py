"""Least-privilege checks for the live Setup write endpoints."""

from __future__ import annotations

import os
import secrets
from types import SimpleNamespace
import urllib.parse
import unittest


@unittest.skipUnless(
    os.environ.get("ADM_LAB") == "1", "set ADM_LAB=1 with the lab running"
)
class SetupViewerWriteTest(unittest.TestCase):
    """A restricted viewer cannot mutate the Setup allowlist."""

    @classmethod
    def setUpClass(cls) -> None:
        import sys

        sys.path.insert(0, str(__file__).rsplit("/", 1)[0])
        import lab
        from test_permissions import _response, ALLOWED_INDEXES

        admin_password = lab.read_secrets()["SPLUNK_PASSWORD"]
        role = "adm_setup_role_" + secrets.token_hex(8)
        user = "adm_setup_viewer_" + secrets.token_hex(8)
        password = secrets.token_urlsafe(24)

        def remove(path):
            status, _ = _response("DELETE", path, "admin", admin_password)
            if status not in (200, 204):
                raise AssertionError(
                    f"Temporary Setup principal cleanup failed (HTTP {status})"
                )

        status, _ = _response(
            "POST",
            "/services/authorization/roles",
            "admin",
            admin_password,
            urllib.parse.urlencode(
                {
                    "name": role,
                    "capabilities": "search",
                    "srchIndexesAllowed": ALLOWED_INDEXES,
                },
                doseq=True,
            ).encode(),
        )
        if status not in (200, 201):
            raise AssertionError(
                f"Temporary Setup role creation failed (HTTP {status})"
            )
        cls.addClassCleanup(remove, "/services/authorization/roles/" + role)
        # Remove capabilities inherited from the role defaults.
        lab._json(
            "POST", "/services/authorization/roles/" + role, {"capabilities": "search"}
        )
        status, _ = _response(
            "POST",
            "/services/authentication/users",
            "admin",
            admin_password,
            urllib.parse.urlencode(
                {"name": user, "password": password, "roles": role}
            ).encode(),
        )
        if status not in (200, 201):
            raise AssertionError(
                f"Temporary Setup viewer creation failed (HTTP {status})"
            )
        cls.addClassCleanup(remove, "/services/authentication/users/" + user)
        cls.restricted = SimpleNamespace(lab=lab, username=user, password=password)
        path = (
            "/servicesNS/nobody/splunk_adm/saved/searches/ADM%20-%20Identity%20builder"
        )
        original = lab._json("GET", path)["entry"][0]["content"]
        cls.addClassCleanup(
            lab._json,
            "POST",
            path,
            {
                "disabled": str(int(original["disabled"] in (True, 1, "1"))),
                "is_scheduled": str(int(original["is_scheduled"] in (True, 1, "1"))),
            },
        )
        # Keep the target unscheduled while checking hidden-resource denial.
        lab._json("POST", path, {"disabled": "1", "is_scheduled": "0"})

    def test_viewer_macro_write_is_rejected_and_definition_is_unchanged(self) -> None:
        before = self.restricted.lab._json(
            "GET",
            "/servicesNS/nobody/splunk_adm/configs/conf-macros/adm_index_summary",
        )
        from test_permissions import _response

        path = "/servicesNS/nobody/splunk_adm/configs/conf-macros/adm_index_summary"
        self.addCleanup(
            self.restricted.lab._json,
            "POST",
            path,
            {"definition": before["entry"][0]["content"]["definition"]},
        )
        rejected, _ = _response(
            "POST",
            path,
            self.restricted.username,
            self.restricted.password,
            b"definition=index=adm_summary",
        )
        self.assertEqual(rejected, 403)
        after = self.restricted.lab._json("GET", path)
        before_body = before
        after_body = after
        self.assertEqual(
            before_body["entry"][0]["content"].get("definition"),
            after_body["entry"][0]["content"].get("definition"),
        )

    def test_viewer_builder_enable_is_rejected_and_state_is_unchanged(self) -> None:
        before = self.restricted.lab._json(
            "GET",
            "/servicesNS/nobody/splunk_adm/saved/searches/ADM%20-%20Identity%20builder",
        )
        from test_permissions import _response

        path = (
            "/servicesNS/nobody/splunk_adm/saved/searches/ADM%20-%20Identity%20builder"
        )
        rejected, _ = _response(
            "POST",
            path,
            self.restricted.username,
            self.restricted.password,
            b"disabled=0",
        )
        self.assertEqual(rejected, 404)
        # Splunk hides administrator-only saved searches with 404. A combined
        # payload reaches a restricted handler that rejects is_scheduled (400).
        # The native administrator browser test proves the same payload is valid.
        scheduled, _ = _response(
            "POST",
            path,
            self.restricted.username,
            self.restricted.password,
            b"disabled=0&is_scheduled=1",
        )
        self.assertEqual(scheduled, 400)
        after = self.restricted.lab._json("GET", path)
        before_body = before
        after_body = after
        before_content = before_body["entry"][0]["content"]
        after_content = after_body["entry"][0]["content"]
        self.assertEqual(before_content.get("disabled"), after_content.get("disabled"))
        self.assertEqual(
            before_content.get("is_scheduled"), after_content.get("is_scheduled")
        )


if __name__ == "__main__":
    unittest.main()
