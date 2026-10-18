"""Installed endpoint arbitration. Parent owns the exclusive lab lifecycle."""

import os
import secrets
import sys
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from settings_fixture import CONFIG, ENDPOINT, SettingsFixture  # noqa: E402


def operation(namespace, expected=None, request_id=None, state="active"):
    return {
        "namespace": namespace,
        "requestId": request_id or secrets.token_hex(16),
        "expectedRevision": expected,
        "settings": {
            "schemaVersion": 1,
            "revision": "draft",
            "sources": {
                "netflow": {
                    "state": state,
                    "cadenceSeconds": 60,
                    "staleAfterSeconds": 600,
                }
            },
        },
    }


@unittest.skipUnless(
    os.environ.get("ADM_LAB") == "1", "requires the parent-owned disposable lab"
)
class InstalledAtomicSettingsTest(unittest.TestCase):
    def setUp(self):
        self.fixture = SettingsFixture(self)
        self.fixture.clear()
        status, snapshot = self.fixture.request("GET")
        self.assertEqual(status, 200)
        self.assertTrue(snapshot["canWrite"], snapshot.get("writeUnavailableReason"))
        self.namespace = snapshot["namespace"]

    def compete(self, expected):
        barrier = threading.Barrier(2)

        def save(_):
            payload = operation(self.namespace, expected)
            barrier.wait(timeout=5)
            return self.fixture.request("POST", payload=payload)

        with ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(save, range(2)))
        self.assertEqual(sorted(status for status, _ in outcomes), [200, 409])
        winner = next(value for status, value in outcomes if status == 200)
        loser = next(value for status, value in outcomes if status == 409)
        self.assertEqual(loser["code"], "conflict")
        self.assertEqual(
            self.fixture.request("GET")[1]["settings"]["revision"],
            winner["committedRevision"],
        )
        return winner

    def test_concurrent_initial_creation_and_same_revision(self):
        first = self.compete(None)
        self.compete(first["committedRevision"])
        self.assertEqual(len(self.fixture.rows()), 2)

    def test_stale_and_lost_response_retry_after_successor(self):
        first_request = operation(self.namespace)
        status, first = self.fixture.request("POST", payload=first_request)
        self.assertEqual(status, 200)
        next_request = operation(
            self.namespace, first["committedRevision"], state="staged"
        )
        self.assertEqual(self.fixture.request("POST", payload=next_request)[0], 200)
        # Deliberately discard the original result and recover its operation.
        status, retry = self.fixture.request("POST", payload=first_request)
        self.assertEqual(status, 200)
        self.assertTrue(retry["superseded"])
        self.assertEqual(retry["committedRevision"], first["committedRevision"])
        self.assertEqual(
            self.fixture.request("POST", payload=operation(self.namespace))[0], 409
        )
        self.assertEqual(len(self.fixture.rows()), 2)

    def test_disabled_mode_preserves_existing_reads(self):
        self.assertEqual(
            self.fixture.request("POST", payload=operation(self.namespace))[0], 200
        )
        self.fixture.lab._json("POST", CONFIG, {"write_mode": "disabled"})
        status, snapshot = self.fixture.request("GET")
        self.assertEqual(status, 200)
        self.assertEqual(snapshot["state"], "configured")
        self.assertFalse(snapshot["canWrite"])
        self.assertIn("disabled", snapshot["writeUnavailableReason"])
        self.assertEqual(
            self.fixture.request("POST", payload=operation(self.namespace))[0], 503
        )

    def test_viewer_reads_but_server_rejects_write(self):
        user = "adm_atomic_" + secrets.token_hex(8)
        password = secrets.token_urlsafe(24)
        self.fixture.lab._json(
            "POST",
            "/services/authentication/users",
            {"name": user, "password": password, "roles": "user"},
        )
        self.addCleanup(
            lambda: self.fixture.lab._mgmt(
                "DELETE", "/services/authentication/users/" + user
            ).close()
        )
        self.assertEqual(
            self.fixture.request("GET", username=user, password=password)[0], 200
        )
        self.assertEqual(
            self.fixture.request(
                "POST", ENDPOINT, operation(self.namespace), user, password
            )[0],
            403,
        )
        self.assertFalse(self.fixture.rows())
