"""Live administrator ACL and restricted-writer checks for recovery objects.

The test is lab-gated and creates ephemeral credentials.  It never prints or
stores the generated password outside the running test process.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import ssl
import unittest
import urllib.error
import urllib.parse
import urllib.request


APP = "splunk_adm"
MGMT = f"https://127.0.0.1:{int(os.environ.get('ADM_LAB_MGMT_PORT', '8089'))}"
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


def _request(method, path, username, password, data=None, content_type=None):
    headers = {
        "Authorization": "Basic "
        + base64.b64encode(f"{username}:{password}".encode()).decode()
    }
    if data is not None:
        headers["Content-Type"] = content_type or "application/x-www-form-urlencoded"
    request = urllib.request.Request(
        MGMT + path, data=data, method=method, headers=headers
    )
    try:
        with urllib.request.urlopen(request, context=CTX, timeout=120) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        with error:
            return error.code, error.read(2000)


@unittest.skipUnless(os.environ.get("ADM_LAB") == "1", "requires disposable Splunk lab")
class RecoveryPermissionsTest(unittest.TestCase):
    """Recovery configuration and state are administrator-only objects."""

    @classmethod
    def setUpClass(cls):
        import sys

        sys.path.insert(0, str(__file__).rsplit("/", 1)[0])
        import lab

        cls.lab = lab
        cls.admin_password = lab.read_secrets()["SPLUNK_PASSWORD"]
        cls.username = "adm_recovery_viewer_" + secrets.token_hex(8)
        cls.password = secrets.token_urlsafe(24)
        cls.role = "adm_recovery_viewer_role_" + secrets.token_hex(8)
        role_data = urllib.parse.urlencode(
            {"name": cls.role, "capabilities": "search"}
        ).encode()
        status, body = _request(
            "POST",
            "/services/authorization/roles",
            "admin",
            cls.admin_password,
            role_data,
        )
        if status not in (200, 201):
            raise AssertionError(f"could not create test role (HTTP {status})")
        cls.addClassCleanup(
            _request,
            "DELETE",
            "/services/authorization/roles/" + urllib.parse.quote(cls.role, safe=""),
            "admin",
            cls.admin_password,
        )
        cls.lab._json(
            "POST",
            "/services/authorization/roles/" + urllib.parse.quote(cls.role, safe=""),
            {"capabilities": "search"},
        )
        user_data = urllib.parse.urlencode(
            {"name": cls.username, "password": cls.password, "roles": cls.role}
        ).encode()
        status, body = _request(
            "POST",
            "/services/authentication/users",
            "admin",
            cls.admin_password,
            user_data,
        )
        if status not in (200, 201):
            raise AssertionError(f"could not create test user (HTTP {status})")
        cls.addClassCleanup(
            _request,
            "DELETE",
            "/services/authentication/users/"
            + urllib.parse.quote(cls.username, safe=""),
            "admin",
            cls.admin_password,
        )

    @staticmethod
    def _paths():
        return {
            "action": "configs/conf-alert_actions/adm_recovery",
            "supervisor": "saved/searches/"
            + urllib.parse.quote("ADM - Recovery abandoned-lease alert", safe=""),
            "recovery": "configs/conf-adm_recovery/recovery",
            "state": "configs/conf-collections/adm_recovery_state",
            "audit": "configs/conf-collections/adm_recovery_audit",
            "state_lookup": "configs/conf-transforms/adm_recovery_state",
            "audit_lookup": "configs/conf-transforms/adm_recovery_audit",
        }

    def test_admin_can_read_recovery_acls(self):
        for name, relative in self._paths().items():
            with self.subTest(name=name):
                status, body = _request(
                    "GET",
                    f"/servicesNS/nobody/{APP}/{relative}?output_mode=json",
                    "admin",
                    self.admin_password,
                )
                self.assertEqual(status, 200, body[:500])
                entry = json.loads(body)["entry"][0]
                perms = entry["acl"]["perms"]
                read = set(perms.get("read", []))
                write = set(perms.get("write", []))
                self.assertTrue(read, f"{name} has no explicit read grant")
                self.assertTrue(write, f"{name} has no explicit write grant")
                self.assertTrue(read <= {"admin", "sc_admin"})
                self.assertTrue(write <= {"admin", "sc_admin"})

    def test_restricted_user_cannot_write_or_dispatch_recovery_objects(self):
        payload = json.dumps({"_key": "permission-probe"}).encode()
        for name, relative in self._paths().items():
            with self.subTest(name=name):
                status, body = _request(
                    "POST",
                    f"/servicesNS/nobody/{APP}/{relative}",
                    self.username,
                    self.password,
                    urllib.parse.urlencode({"description": "permission-probe"}).encode()
                    if name == "supervisor"
                    else payload,
                    "application/x-www-form-urlencoded"
                    if name == "supervisor"
                    else "application/json",
                )
                self.assertIn(status, (403, 404), body[:500])

        for collection in ("adm_recovery_state", "adm_recovery_audit"):
            with self.subTest(collection=collection):
                status, body = _request(
                    "POST",
                    f"/servicesNS/nobody/{APP}/storage/collections/data/{collection}",
                    self.username,
                    self.password,
                    payload,
                    "application/json",
                )
                self.assertIn(status, (403, 404), body[:500])

        # Saved-search dispatch is the action execution boundary.  Use a
        # shipped owner-dispatched search and do not require recovery opt-in.
        for target_name in (
            "ADM - Identity builder",
            "ADM - Recovery abandoned-lease alert",
        ):
            self.assert_dispatch_denied(target_name)

    def assert_dispatch_denied(self, name):
        target = urllib.parse.quote(name, safe="")
        status, body = _request(
            "POST",
            f"/servicesNS/nobody/{APP}/saved/searches/{target}/dispatch?output_mode=json",
            self.username,
            self.password,
            urllib.parse.urlencode({"trigger_actions": "0"}).encode(),
        )
        self.assertIn(status, (403, 404), body[:500])


if __name__ == "__main__":
    unittest.main()
