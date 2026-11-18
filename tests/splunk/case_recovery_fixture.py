"""Installed, task-owned case notes recovery fixture (source or target phase)."""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys
import unittest
import urllib.error
import urllib.parse
import urllib.request

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "tools"))

import case_recovery_lab as recovery  # noqa: E402
import lab  # noqa: E402
import test_cases_endpoint as notes_fixture  # noqa: E402
from web_session import CASES, RequestJournal, WebSession  # noqa: E402

MODE = None
CONFIG = notes_fixture.CONFIG
METADATA_LIMIT = 2 * 1024 * 1024


def _no_passwords(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if "password" in str(key).lower() or "token" in str(key).lower():
                raise ValueError("recovery metadata must not contain credentials")
            _no_passwords(child)
    elif isinstance(value, list):
        for child in value:
            _no_passwords(child)


def _metadata_path():
    value = os.environ.get("ADM_RECOVERY_METADATA", "")
    path = Path(value)
    if not path.is_absolute() or not value:
        raise RuntimeError("ADM_RECOVERY_METADATA must be an absolute path")
    parent = path.parent
    info = parent.lstat()
    if (
        parent.is_symlink()
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o700
        or any((part / ".git").exists() for part in (parent, *parent.parents))
        or path.exists()
        or path.is_symlink()
    ):
        raise RuntimeError("recovery metadata path must be new in a private directory")
    return path


def _load_metadata():
    path = _metadata_path_for_read()
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
            or info.st_size > METADATA_LIMIT
        ):
            raise RuntimeError("unsafe recovery metadata")
        data = os.read(fd, METADATA_LIMIT + 1)
        if len(data) != info.st_size or os.read(fd, 1):
            raise RuntimeError("recovery metadata changed while reading")
    finally:
        os.close(fd)
    metadata = json.loads(data)
    _no_passwords(metadata)
    if metadata.get("format") != 1:
        raise RuntimeError("unsupported recovery metadata")
    return metadata


def _metadata_path_for_read():
    value = os.environ.get("ADM_RECOVERY_METADATA", "")
    path = Path(value)
    if not path.is_absolute() or not value or path.parent.is_symlink():
        raise RuntimeError("ADM_RECOVERY_METADATA must be an absolute private file")
    parent = path.parent.lstat()
    if (
        not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != os.getuid()
        or stat.S_IMODE(parent.st_mode) != 0o700
        or any((part / ".git").exists() for part in (path.parent, *path.parents))
    ):
        raise RuntimeError("recovery metadata directory is unsafe")
    return path


def _write_metadata(metadata):
    path = _metadata_path()
    _no_passwords(metadata)
    data = json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode()
    if len(data) > METADATA_LIMIT:
        raise RuntimeError("recovery metadata exceeds bound")
    fd = os.open(
        path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600
    )
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    parent_fd = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)


def _admin_status(method, path, body=None):
    secrets_value = lab.read_secrets()
    auth = base64.b64encode(
        f"admin:{secrets_value['SPLUNK_PASSWORD']}".encode()
    ).decode()
    data = None if body is None else urllib.parse.urlencode(body, doseq=True).encode()
    request = urllib.request.Request(
        lab.MGMT + path + "?output_mode=json",
        method=method,
        data=data,
        headers={"Authorization": "Basic " + auth},
    )
    try:
        response = lab.urlopen(request, timeout=30)
    except urllib.error.HTTPError as error:
        with error:
            return error.code
    with response:
        response.read(1024 * 1024)
        return response.status


class InstalledCaseRecoveryFixture(notes_fixture.InstalledCasesTest):
    def doCleanups(self):
        result = getattr(getattr(self, "_outcome", None), "result", None)
        errors_before = len(result.errors) if result is not None else 0
        failures_before = len(result.failures) if result is not None else 0
        inherited_result = super().doCleanups()
        errors_after = len(result.errors) if result is not None else errors_before
        failures_after = len(result.failures) if result is not None else failures_before
        return (
            inherited_result is not False
            and errors_after == errors_before
            and failures_after == failures_before
        )

    def setUp(self):
        if MODE not in ("source", "target"):
            raise RuntimeError("run this fixture with source or target")
        if os.environ.get("ADM_LAB") != "1" or os.environ.get("ADM_LAB_WEB_TLS") != "1":
            self.skipTest("requires the exact task-owned verified HTTPS lab")
        identity = lab.task_identity()
        if identity != recovery.TASKS[MODE]:
            raise RuntimeError("wrong case-recovery task identity")
        if not os.environ.get("ADM_LAB_WEB_RECEIPT"):
            raise RuntimeError("ADM_LAB_WEB_RECEIPT is required")
        recovery.target(stopped=False)
        self.journal = RequestJournal(os.environ["ADM_LAB_WEB_RECEIPT"])
        self.web = []
        self._cleaned = False
        if MODE == "source":
            super().setUp()
        else:
            self._setup_target_principals()
        self.journal.fixture = {
            "mode": MODE,
            "role": self.role,
            "users": [name for name, _ in self.users],
        }
        self.journal._persist()
        self._login_all()
        if MODE == "target":
            self._assert_native_flags_disabled()

    def _register_config_restore(self, config_snapshot):
        self._config_snapshot = config_snapshot
        self.addCleanup(
            lab._json,
            "POST",
            CONFIG,
            {key: config_snapshot[key] for key in ("mode", "platform", "capture_mode")},
        )

    def _setup_target_principals(self):
        self.metadata = _load_metadata()
        self.assertEqual(self.metadata.get("source_task"), recovery.TASKS["source"][0])
        self.role = self.metadata["role"]
        suffix = re.fullmatch(r"atlas_cases_([0-9a-f]{10})", self.role)
        if not suffix or self.metadata["users"] != [
            "atlas_case_" + suffix[1] + "a",
            "atlas_case_" + suffix[1] + "b",
        ]:
            raise RuntimeError("metadata has unexpected source principals")
        self.users = [
            (name, secrets.token_urlsafe(32)) for name in self.metadata["users"]
        ]
        config = notes_fixture.InstalledCasesTest._config_content(
            CONFIG, ("mode", "platform", "capture_mode")
        )
        transport = notes_fixture.InstalledCasesTest._config_content(
            notes_fixture.TRANSPORT_CONFIG, ("management_uri", "ca_file")
        )
        self._register_config_restore(config)
        self.addCleanup(
            lab._json,
            "POST",
            notes_fixture.TRANSPORT_CONFIG,
            {key: transport[key] for key in ("management_uri", "ca_file")},
        )
        for name in [self.role, *(user for user, _ in self.users)]:
            path = (
                "/services/authorization/roles/"
                if name == self.role
                else "/services/authentication/users/"
            ) + urllib.parse.quote(name, safe="")
            self.assertEqual(
                _admin_status("GET", path), 404, "target identity already exists"
            )
        self._create_role_and_users()

    def _create_role_and_users(self):
        lab._json(
            "POST",
            "/services/authorization/roles",
            {"name": self.role, **notes_fixture.role_authority_payload()},
        )
        self.addCleanup(
            lab._json,
            "DELETE",
            "/services/authorization/roles/" + urllib.parse.quote(self.role, safe=""),
        )
        lab._json(
            "POST",
            "/services/authorization/roles/" + urllib.parse.quote(self.role, safe=""),
            notes_fixture.role_authority_payload(),
        )
        role = lab._json(
            "GET",
            "/services/authorization/roles/" + urllib.parse.quote(self.role, safe=""),
        )["entry"][0]["content"]
        for key in (
            "imported_roles",
            "srchIndexesAllowed",
            "srchIndexesDefault",
            "srchFilter",
        ):
            self.assertIn(key, role)
        self.assertIn(role["imported_roles"], ("", []))
        self.assertIn(role["srchIndexesAllowed"], ("", []))
        self.assertIn(role["srchIndexesDefault"], ("", []))
        self.assertEqual(role["srchFilter"], "")
        self.assertEqual(set(role.get("capabilities", [])), {"adm_investigate"})
        for user, password in self.users:
            lab._json(
                "POST",
                "/services/authentication/users",
                {"name": user, "password": password, "roles": self.role},
            )
            self.addCleanup(
                lab._json,
                "DELETE",
                "/services/authentication/users/" + urllib.parse.quote(user, safe=""),
            )

    def _login_all(self):
        self.web = [WebSession(journal=self.journal) for _ in self.users]
        for (username, password), session in zip(self.users, self.web):
            context = session.login(username, password)
            notes_fixture.assert_exact_context(self, context, username, self.role)
            self.addCleanup(session.close)

    def _assert_native_flags_disabled(self):
        config = notes_fixture.InstalledCasesTest._config_content(
            CONFIG, ("mode", "platform", "capture_mode")
        )
        self.assertEqual(config["mode"], "disabled")
        self.assertEqual(config["capture_mode"], "disabled")

    def _set_notes_enabled(self):
        self._assert_native_flags_disabled()
        lab._json(
            "POST",
            CONFIG,
            {
                "mode": "single_search_head",
                "platform": "enterprise",
                "capture_mode": "disabled",
            },
        )

    def api(self, user, method, path, data=None, key=None):
        response = self.web[user].request(
            method,
            CASES + path + "?output_mode=json",
            data=data,
            key=key,
        )
        return response.status, response.json()

    def _new_case(self, title, key):
        body = {
            "schema_version": 1,
            "title": title,
            "window": {"start": "2026-01-01T00:00:00Z", "end": "2026-01-01T01:00:00Z"},
        }
        status, payload = self.api(0, "POST", "/cases", body, key)
        self.assertEqual(status, 201)
        return body, payload

    def _path(self, projection):
        return "/cases/" + projection["id"]

    def _get_projection(self, user, projection, suffix=""):
        status, result = self.api(user, "GET", self._path(projection) + suffix)
        self.assertEqual(status, 200)
        return result

    def _source_workload(self):
        self._set_notes_enabled()
        retries = {}
        projections = {}

        create_body, private = self._new_case(
            "Recovery private", "recovery-create-private"
        )
        retries["create_private"] = {
            "key": "recovery-create-private",
            "path": "/cases",
            "body": create_body,
            "status": 201,
            "response": private,
        }
        first_note = {
            "expected_revision": 1,
            "item": {"type": "note", "text": "Recovery immutable original"},
        }
        status, private = self.api(
            0,
            "POST",
            self._path(private) + "/entries",
            first_note,
            "recovery-private-note-v1",
        )
        self.assertEqual(status, 200)
        retries["private_note_v1"] = {
            "key": "recovery-private-note-v1",
            "path": self._path(private) + "/entries",
            "body": first_note,
            "status": 200,
            "response": private,
        }
        revision = {
            "expected_revision": 2,
            "item": {
                "type": "note",
                "text": "Recovery revised note",
                "supersedes_entry_id": private["entries"][0]["id"],
            },
        }
        status, private = self.api(
            0,
            "POST",
            self._path(private) + "/entries",
            revision,
            "recovery-private-note-v2",
        )
        self.assertEqual(status, 200)
        self.assertEqual(private["entries"][0]["text"], "Recovery immutable original")
        self.assertEqual(
            private["entries"][1]["supersedes_entry_id"], private["entries"][0]["id"]
        )
        retries["private_note_v2"] = {
            "key": "recovery-private-note-v2",
            "path": self._path(private) + "/entries",
            "body": revision,
            "status": 200,
            "response": private,
        }

        shared_body, shared = self._new_case(
            "Recovery shared", "recovery-create-shared"
        )
        retries["create_shared"] = {
            "key": "recovery-create-shared",
            "path": "/cases",
            "body": shared_body,
            "status": 201,
            "response": shared,
        }
        grant = {"expected_revision": 1, "member": self.users[1][0], "grant": True}
        status, shared = self.api(
            0, "POST", self._path(shared) + "/share", grant, "recovery-share"
        )
        self.assertEqual(status, 200)
        question = {
            "expected_revision": 2,
            "item": {"type": "question", "text": "Recovery member question"},
        }
        status, shared = self.api(
            1,
            "POST",
            self._path(shared) + "/entries",
            question,
            "recovery-member-question",
        )
        self.assertEqual(status, 200)
        retries["member_question"] = {
            "key": "recovery-member-question",
            "path": self._path(shared) + "/entries",
            "body": question,
            "status": 200,
            "response": shared,
            "user": 1,
        }

        revoked_body, revoked = self._new_case(
            "Recovery revoked", "recovery-create-revoked"
        )
        retries["create_revoked"] = {
            "key": "recovery-create-revoked",
            "path": "/cases",
            "body": revoked_body,
            "status": 201,
            "response": revoked,
        }
        status, revoked = self.api(
            0,
            "POST",
            self._path(revoked) + "/share",
            {"expected_revision": 1, "member": self.users[1][0], "grant": True},
            "recovery-revoked-grant",
        )
        self.assertEqual(status, 200)
        status, revoked = self.api(
            0,
            "POST",
            self._path(revoked) + "/share",
            {"expected_revision": 2, "member": self.users[1][0], "grant": False},
            "recovery-revoked-remove",
        )
        self.assertEqual(status, 200)

        for name, case in (
            ("private", private),
            ("shared", shared),
            ("revoked", revoked),
        ):
            owner_case = self._get_projection(0, case)
            owner_export = self._get_projection(0, case, "/export")
            projections[name] = {"owner_case": owner_case, "owner_export": owner_export}
        self.assertEqual(len(projections["private"]["owner_case"]["entries"]), 2)
        self.assertEqual(len(projections["shared"]["owner_case"]["entries"]), 1)
        for name in ("private", "revoked"):
            for suffix in ("", "/export"):
                self.assertEqual(
                    self.api(
                        1, "GET", self._path(projections[name]["owner_case"]) + suffix
                    )[0],
                    403,
                )
        for suffix in ("", "/export"):
            status, member_projection = self.api(
                1, "GET", self._path(projections["shared"]["owner_case"]) + suffix
            )
            self.assertEqual(status, 200)
            projections["shared"]["member" + ("_export" if suffix else "_case")] = (
                member_projection
            )
        return projections, retries

    def _verify_projections(self, projections):
        for name in ("private", "shared", "revoked"):
            case = projections[name]["owner_case"]
            self.assertEqual(
                self._get_projection(0, case), projections[name]["owner_case"]
            )
            self.assertEqual(
                self._get_projection(0, case, "/export"),
                projections[name]["owner_export"],
            )
        for key in ("member_case", "member_export"):
            expected = projections["shared"][key]
            actual = self._get_projection(
                1,
                projections["shared"]["owner_case"],
                "/export" if key.endswith("export") else "",
            )
            self.assertEqual(actual, expected)
        for name in ("private", "revoked"):
            case = projections[name]["owner_case"]
            self.assertEqual(self.api(1, "GET", self._path(case))[0], 403)
            self.assertEqual(self.api(1, "GET", self._path(case) + "/export")[0], 403)

    def _retry_old_requests(self, retries):
        for record in (
            retries["create_private"],
            retries["create_shared"],
            retries["create_revoked"],
            retries["private_note_v1"],
            retries["private_note_v2"],
            retries["member_question"],
        ):
            status, response = self.api(
                record.get("user", 0),
                "POST",
                record["path"],
                record["body"],
                record["key"],
            )
            self.assertEqual(status, record["status"])
            self.assertEqual(response, record["response"])
        private = retries["private_note_v1"]["response"]
        current = self._get_projection(0, private)
        self.assertEqual(len(current["entries"]), 2)
        self.assertEqual(current["entries"][0]["text"], "Recovery immutable original")
        shared = retries["member_question"]["response"]
        self.assertEqual(len(self._get_projection(1, shared)["entries"]), 1)

    def _source(self):
        projections, retries = self._source_workload()
        owner = self.users[0][0]
        member = self.users[1][0]
        self.assertTrue(self.web)
        before = recovery.target(stopped=False)[0]
        self.assertEqual(recovery.restart()["id"], before)
        for session in self.web:
            session.close()
        self.web = []
        self._login_all()
        self._verify_projections(projections)
        self._retry_old_requests(retries)

        fixture = {
            "format": 1,
            "source_task": recovery.TASKS["source"][0],
            "role": self.role,
            "users": [owner, member],
            "projections": projections,
            "retries": retries,
        }
        self.journal.fixture = fixture
        self.journal._persist()
        cleanup_ok = self._cleanup_now()
        if not cleanup_ok:
            self.journal.fixture = {**fixture, "cleanup_failed": True}
            self.journal._persist()
        self.assertTrue(cleanup_ok, "source users, role, or saved flags failed cleanup")
        for user in (owner, member):
            self.assertEqual(
                _admin_status(
                    "GET",
                    "/services/authentication/users/"
                    + urllib.parse.quote(user, safe=""),
                ),
                404,
            )
        self.assertEqual(
            _admin_status(
                "GET",
                "/services/authorization/roles/"
                + urllib.parse.quote(self.role, safe=""),
            ),
            404,
        )
        restored_config = notes_fixture.InstalledCasesTest._config_content(
            CONFIG, ("mode", "platform", "capture_mode")
        )
        for key in ("mode", "platform", "capture_mode"):
            self.assertEqual(restored_config[key], self._config_snapshot[key])
        native = recovery.native("prepare", {"principal": owner})
        self.assertTrue(native["persistence_and_capture_disabled"])
        self.assertFalse(native["native_jobs_dispatched"])
        fixture["native"] = native
        _write_metadata(fixture)

    def _target(self):
        metadata = self.metadata
        self.role = metadata["role"]
        owner = metadata["users"][0]
        self._assert_native_flags_disabled()
        actual = recovery.native(
            "inspect",
            {
                "schemas": metadata["native"]["schemas"],
                "principal": owner,
            },
        )
        self.assertEqual(actual["schemas"], metadata["native"]["schemas"])
        self.assertEqual(actual["databases"], metadata["native"]["databases"])
        self.assertEqual(actual["ledger"], metadata["native"]["ledger"])
        self.assertTrue(actual["quota_still_charged"])
        self.assertFalse(actual["native_jobs_dispatched"])
        self.assertTrue(actual["persistence_and_capture_disabled"])
        _no_passwords(actual)
        self.journal.fixture = {
            **(self.journal.fixture or {}),
            "target_restored_native": actual,
        }
        self.journal._persist()

        self._set_notes_enabled()
        self._verify_projections(metadata["projections"])
        self._retry_old_requests(metadata["retries"])

        shared = metadata["projections"]["shared"]["owner_case"]
        current_member = self._get_projection(1, shared)
        addition = {
            "expected_revision": current_member["revision"],
            "item": {"type": "question", "text": "Post-restore member question"},
        }
        status, updated = self.api(
            1,
            "POST",
            self._path(shared) + "/entries",
            addition,
            "recovery-post-restore-question",
        )
        self.assertEqual(status, 200)
        original = metadata["projections"]["shared"]["member_case"]["entries"]
        self.assertEqual(updated["entries"][: len(original)], original)
        self.assertEqual(updated["entries"][-1]["text"], "Post-restore member question")
        owner_updated = self._get_projection(0, shared)
        self.assertEqual(owner_updated["entries"], updated["entries"])
        self.journal.fixture = {
            **(self.journal.fixture or {}),
            "target_checks_passed": True,
        }
        self.journal._persist()

    def _cleanup_now(self):
        if self._cleaned:
            return True
        result = getattr(getattr(self, "_outcome", None), "result", None)
        errors_before = len(result.errors) if result is not None else 0
        failures_before = len(result.failures) if result is not None else 0
        cleanup_result = self.doCleanups()
        self._cleaned = True
        errors_after = len(result.errors) if result is not None else errors_before
        failures_after = len(result.failures) if result is not None else failures_before
        return (
            bool(cleanup_result)
            and errors_after == errors_before
            and failures_after == failures_before
        )

    def test_installed_case_recovery(self):
        primary_error = None
        try:
            if MODE == "source":
                self._source()
            else:
                self._target()
        except BaseException as exc:
            primary_error = exc
            raise
        finally:
            try:
                cleanup_ok = self._cleanup_now()
                if not cleanup_ok and primary_error is None:
                    raise AssertionError("fixture cleanup failed")
                if not cleanup_ok and primary_error is not None:
                    self.journal.fixture = {
                        **(self.journal.fixture or {}),
                        "cleanup_failed": True,
                    }
                    self.journal._persist()
                if primary_error is None:
                    self._assert_cleaned()
                    self.journal.fixture = {
                        **(self.journal.fixture or {}),
                        "cleanup_verified": True,
                    }
                    self.journal._persist()
            except Exception as cleanup_error:
                # A failed cleanup must not hide the original qualification failure.
                if primary_error is None:
                    raise
                self.journal.fixture = {
                    **(self.journal.fixture or {}),
                    "cleanup_error": type(cleanup_error).__name__,
                }
                self.journal._persist()

    def _assert_cleaned(self):
        for user, _password in self.users:
            self.assertEqual(
                _admin_status(
                    "GET",
                    "/services/authentication/users/"
                    + urllib.parse.quote(user, safe=""),
                ),
                404,
            )
        self.assertEqual(
            _admin_status(
                "GET",
                "/services/authorization/roles/"
                + urllib.parse.quote(self.role, safe=""),
            ),
            404,
        )
        content = notes_fixture.InstalledCasesTest._config_content(
            CONFIG, ("mode", "platform", "capture_mode")
        )
        for key in ("mode", "platform", "capture_mode"):
            self.assertEqual(content[key], self._config_snapshot[key])


def main():
    global MODE
    if len(sys.argv) != 2 or sys.argv[1] not in ("source", "target"):
        raise SystemExit("usage: case_recovery_fixture.py source|target")
    MODE = sys.argv.pop()
    suite = unittest.TestSuite(
        [InstalledCaseRecoveryFixture("test_installed_case_recovery")]
    )
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    success = result.wasSuccessful()
    if os.environ.get("ADM_LAB_CASE_RECOVERY") == "1":
        success = success and result.testsRun == 1 and not result.skipped
    raise SystemExit(0 if success else 1)


if __name__ == "__main__":
    main()
