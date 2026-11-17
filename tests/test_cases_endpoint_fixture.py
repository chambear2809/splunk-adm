"""Synthetic checks for the disposable installed endpoint fixture contract."""

import sys
import unittest
import json
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent / "splunk"))
import test_cases_endpoint as installed_fixture  # noqa: E402
from test_cases_endpoint import (  # noqa: E402
    assert_exact_context,
    role_authority_payload,
)


class EndpointFixtureTests(unittest.TestCase):
    def test_role_payload_explicitly_carries_no_inherited_search_authority(self):
        payload = role_authority_payload()
        self.assertEqual(payload["imported_roles"], "")
        self.assertEqual(payload["srchIndexesAllowed"], "")
        self.assertEqual(payload["srchIndexesDefault"], "")
        self.assertEqual(payload["capabilities"], ["adm_investigate"])
        self.assertEqual(payload["srchFilter"], "")

    def test_context_refuses_admin_or_index_grants_before_accounts_are_used(self):
        class Probe(unittest.TestCase):
            pass

        valid = {
            "username": "alice",
            "roles": ["fixture"],
            "capabilities": ["adm_investigate"],
            "srchIndexesAllowed": [],
            "srchIndexesDefault": [],
        }
        assert_exact_context(Probe(), valid, "alice", "fixture")
        for key, value in (
            ("username", "bob"),
            ("roles", ["fixture", "admin"]),
            ("capabilities", ["adm_investigate", "search"]),
            ("capabilities", []),
            ("srchIndexesAllowed", ["main"]),
            ("srchIndexesDefault", ["main"]),
        ):
            with (
                self.subTest(field=key, value=value),
                self.assertRaises(AssertionError),
            ):
                assert_exact_context(Probe(), {**valid, key: value}, "alice", "fixture")
        # These fields are absent from standard current-context responses;
        # the role endpoint separately proves both empty index grants.
        assert_exact_context(
            Probe(),
            {key: valid[key] for key in ("username", "roles", "capabilities")},
            "alice",
            "fixture",
        )

    def test_actual_setup_cleanup_excludes_uncertain_user_creation(self):
        calls = []
        snapshots = {
            "mode": "disabled",
            "platform": "unqualified",
            "capture_mode": "disabled",
        }
        role_content = {
            **role_authority_payload(),
            "name": "unused",
            "srchIndexesAllowed": [],
            "srchIndexesDefault": [],
        }

        def api(method, path, data=None):
            calls.append((method, path, data))
            if method == "GET" and path.endswith("persistence"):
                return {"entry": [{"content": snapshots}]}
            if method == "GET" and path.endswith("capture_transport"):
                return {
                    "entry": [
                        {
                            "content": {
                                "management_uri": "unconfigured",
                                "ca_file": "unconfigured",
                            }
                        }
                    ]
                }
            if method == "GET" and path.startswith("/services/authorization/roles/"):
                return {"entry": [{"content": role_content}]}
            if method == "POST" and path.startswith("/services/authentication/users"):
                if data["name"].endswith("b"):
                    raise RuntimeError("unknown user creation result")
            return {}

        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self):
                return json.dumps(
                    {
                        "entry": [
                            {
                                "content": {
                                    "username": self.user,
                                    "roles": [self.role],
                                    "capabilities": ["adm_investigate"],
                                    "srchIndexesAllowed": [],
                                    "srchIndexesDefault": [],
                                }
                            }
                        ]
                    }
                ).encode()

        with (
            mock.patch(
                "test_cases_endpoint.lab.task_identity",
                return_value=("task", "adm-task"),
            ),
            mock.patch("test_cases_endpoint.lab.verify_target"),
            mock.patch("test_cases_endpoint.lab._json", side_effect=api),
            mock.patch("test_cases_endpoint.urllib.request.Request"),
            mock.patch("test_cases_endpoint.lab.urlopen") as open_url,
        ):

            def open_context(_request, timeout=30):
                response = Response()
                response.user, response.role = fixture.users[0][0], fixture.role
                return response

            open_url.side_effect = open_context
            fixture = installed_fixture.InstalledCasesTest(
                "test_private_notes_retry_sharing_revocation_and_disabled_default"
            )
            with self.assertRaises(RuntimeError):
                fixture.setUp()
            fixture.doCleanups()

        deleted = [path for method, path, _data in calls if method == "DELETE"]
        self.assertTrue(
            any(path.endswith("users/" + fixture.users[0][0]) for path in deleted)
        )
        self.assertFalse(
            any(path.endswith("users/" + fixture.users[1][0]) for path in deleted)
        )
        self.assertTrue(any(path.endswith("roles/" + fixture.role) for path in deleted))
        self.assertIn(("POST", installed_fixture.CONFIG, snapshots), calls)
        self.assertIn(
            (
                "POST",
                installed_fixture.TRANSPORT_CONFIG,
                {"management_uri": "unconfigured", "ca_file": "unconfigured"},
            ),
            calls,
        )
