"""Opt-in pruning qualification on the exclusively owned disposable lab.

Schedules are paused and every app writer drained before a complete bounded
backup is made. Failure keeps the backup and leaves schedules paused unless
state restoration can be verified. No production retention default is changed.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import sys
import time
import types
import unittest
import urllib.parse
import urllib.request
import uuid

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "tools"))
import lab  # noqa: E402
from lab_lock import LabLock  # noqa: E402

APP = "/servicesNS/nobody/splunk_adm"
COLLECTION = "adm_network_client_history"
PAGE_SIZE = 500
MAX_BACKUP_ROWS = 100000
MAX_BACKUP_BYTES = 16 * 1024 * 1024


def _truth(value):
    return str(value).lower() in {"1", "true"}


def _schedule_state(content):
    values = [
        content[field] for field in ("is_scheduled", "enableSched") if field in content
    ]
    if not values or any(
        str(value).lower() not in {"0", "1", "true", "false"} for value in values
    ):
        raise AssertionError("saved-search scheduling state is missing or ambiguous")
    if len({_truth(value) for value in values}) != 1:
        raise AssertionError("saved-search scheduling aliases conflict")
    return _truth(values[0])


def _active_app_job(job):
    content = job.get("content") or {}
    label = content.get("savedsearch_name") or content.get("label") or ""
    if job.get("acl", {}).get("app") != "splunk_adm" and not label.startswith("ADM - "):
        return False
    # FINALIZING can still be flushing writes, even with inconsistent isDone.
    return content.get("dispatchState") == "FINALIZING" or (
        not _truth(content.get("isDone"))
        and content.get("dispatchState") not in {"DONE", "FAILED"}
    )


def _collection_read(get):
    rows = []
    while True:
        page = get(
            APP + f"/storage/collections/data/{COLLECTION}"
            f"?limit={PAGE_SIZE}&skip={len(rows)}&sort=_key:1"
        )
        if not isinstance(page, list) or len(page) > PAGE_SIZE:
            raise AssertionError("history backup page is malformed")
        rows.extend(page)
        if len(rows) > MAX_BACKUP_ROWS:
            raise AssertionError("history backup exceeds qualified row bound")
        if any(not isinstance(row, dict) or not row.get("_key") for row in page):
            raise AssertionError("history backup contains malformed keys")
        if len({row["_key"] for row in rows}) != len(rows):
            raise AssertionError("history backup contains repeated keys")
        if len(json.dumps(rows, sort_keys=True).encode()) > MAX_BACKUP_BYTES:
            raise AssertionError("history backup exceeds qualified byte bound")
        if len(page) < PAGE_SIZE:
            offset = len(rows) - len(page)
            probe = get(
                APP
                + f"/storage/collections/data/{COLLECTION}?limit={PAGE_SIZE}&skip={offset + 1}&sort=_key:1"
            )
            if probe != page[1:]:
                raise AssertionError(
                    "history backup short page failed overlap completion proof"
                )
            return sorted(rows, key=lambda row: row["_key"])


@unittest.skipUnless(
    os.environ.get("ADM_LAB") == "1" and os.environ.get("ADM_CISCO_PRUNE_RUN") == "1",
    "requires ADM_LAB=1 and explicit ADM_CISCO_PRUNE_RUN=1 disposable-data opt-in",
)
class CiscoPruningTest(unittest.TestCase):
    def setUp(self):
        if not LabLock(ROOT).check_owned():
            raise RuntimeError("run under the exclusive tools/lab_lock.py owner")
        self.original = None
        self.backup_verified = False
        self.collection_mutated = False
        self.macros = {}
        self.schedules = {}
        self.prefix = "prune-qualified-" + uuid.uuid4().hex
        self.evidence = ROOT / "dist/final-qualification/pruning" / self.prefix
        self.evidence.mkdir(parents=True, mode=0o700)
        gate = APP + "/configs/conf-macros/adm_prune_maintenance"
        original_gate = lab._json("GET", gate)["entry"][0]["content"]["definition"]
        if str(original_gate).strip() != "0":
            self.fail(
                "prune qualification requires the original maintenance gate closed"
            )
        self.macros[gate] = original_gate
        self.addCleanup(self.restore)
        searches = self._entries(APP + "/saved/searches?count=0")
        for search in searches:
            name, content = search["name"], search["content"]
            if name.startswith("ADM - "):
                value = _schedule_state(content)
                path = APP + "/saved/searches/" + urllib.parse.quote(name, safe="")
                self.schedules[path] = value
                lab._json("POST", path, {"is_scheduled": "0"})
                current = lab._json("GET", path)["entry"][0]["content"]
                if _schedule_state(current):
                    self.fail("saved search did not pause before backup")
        self._drain()
        # Back up only after all writers have stopped, and reject a changing read.
        original = _collection_read(lambda path: lab._json("GET", path))
        if original != _collection_read(lambda path: lab._json("GET", path)):
            self.fail(
                "history changed while writers were paused; no fixture was written"
            )
        self._record("backup", original)
        self.original = original
        self.backup_verified = True
        self.cutoff = 1700000000
        # Fixture-only scalar freezes the actual production prune expression's
        # boundary, without changing its algorithm or production defaults.
        self.override("adm_identity_retention", f"(now()-{self.cutoff})")
        self.override("adm_prune_maintenance", "0")

    def _entries(self, path):
        response = lab._json("GET", path)
        entries = response.get("entry")
        if not isinstance(entries, list) or int(
            (response.get("paging") or {}).get("total", -1)
        ) != len(entries):
            self.fail("REST listing is incomplete; maintenance cannot proceed")
        return entries

    def _drain(self):
        deadline = time.monotonic() + 120
        while any(
            _active_app_job(job)
            for job in self._entries("/services/search/v2/jobs?count=0")
        ):
            if time.monotonic() >= deadline:
                self.fail(
                    "app jobs did not drain; keep schedules paused and gate closed"
                )
            time.sleep(1)

    def _record(self, label, rows):
        payload = json.dumps(rows, sort_keys=True, indent=2).encode()
        if len(payload) > MAX_BACKUP_BYTES:
            self.fail("backup artifact exceeds the qualified byte bound")
        path = self.evidence / f"{label}.json"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
        metadata = dict(rows=len(rows), sha256=hashlib.sha256(payload).hexdigest())
        (self.evidence / f"{label}.sha256.json").write_text(
            json.dumps(metadata, indent=2)
        )
        return metadata

    def override(self, name, definition):
        path = APP + "/configs/conf-macros/" + urllib.parse.quote(name, safe="")
        if path not in self.macros:
            self.macros[path] = lab._json("GET", path)["entry"][0]["content"][
                "definition"
            ]
        lab._json("POST", path, {"definition": definition})
        if lab._json("GET", path)["entry"][0]["content"]["definition"] != definition:
            self.fail("temporary macro override readback differed")

    def write(self, rows):
        if not self.backup_verified or self.original is None:
            self.fail("collection replacement requires a verified complete backup")
        if not LabLock(ROOT).check_owned():
            self.fail("exclusive lab ownership was lost")
        self.collection_mutated = True
        lab._mgmt("DELETE", APP + "/storage/collections/data/" + COLLECTION).close()
        # Restore raw KV documents in bounded batches, preserving keys and types.
        auth = base64.b64encode(
            f"admin:{lab.read_secrets()['SPLUNK_PASSWORD']}".encode()
        ).decode()
        for offset in range(0, len(rows), PAGE_SIZE):
            request = urllib.request.Request(
                lab.MGMT
                + APP
                + "/storage/collections/data/"
                + COLLECTION
                + "/batch_save",
                data=json.dumps(rows[offset : offset + PAGE_SIZE]).encode(),
                method="POST",
                headers={
                    "Authorization": "Basic " + auth,
                    "Content-Type": "application/json",
                },
            )
            with lab._open(request) as response:
                response.read()

    def read(self):
        return {
            row["_key"]: row
            for row in _collection_read(lambda path: lab._json("GET", path))
        }

    def restore(self):
        # On any failure, stop here with schedules paused unless exact state
        # restoration succeeds. A failed setup before backup never rewrites KV.
        gate = APP + "/configs/conf-macros/adm_prune_maintenance"
        lab._json("POST", gate, {"definition": "0"})
        if lab._json("GET", gate)["entry"][0]["content"]["definition"] != "0":
            self.fail("maintenance gate closure is unverified; schedules remain paused")
        self._drain()
        if self.collection_mutated:
            self.write(self.original)
            if self.read() != {row["_key"]: row for row in self.original}:
                self.fail(
                    f"history restore differed; schedules remain paused; backup: {self.evidence}"
                )
            self._record("restored", list(self.read().values()))
        for path, value in self.macros.items():
            lab._json("POST", path, {"definition": value})
            if lab._json("GET", path)["entry"][0]["content"]["definition"] != value:
                self.fail("macro restoration differed; schedules remain paused")
        try:
            for path, value in self.schedules.items():
                desired = "1" if _truth(value) else "0"
                lab._json("POST", path, {"is_scheduled": desired})
                content = lab._json("GET", path)["entry"][0]["content"]
                if _schedule_state(content) != _truth(value):
                    self.fail("saved-search scheduling restoration differed")
        except BaseException:
            pause_errors = []
            for path in self.schedules:
                try:
                    lab._json("POST", path, {"is_scheduled": "0"})
                    if _schedule_state(lab._json("GET", path)["entry"][0]["content"]):
                        pause_errors.append(path)
                except Exception:
                    pause_errors.append(path)
            if pause_errors:
                raise AssertionError(
                    "schedule restore and re-pause are unconfirmed; inspect retained evidence and schedules before further lab work"
                ) from None
            raise

    def fixture(self):
        def row(label, first, last):
            return {
                "_key": self.prefix + "-" + label,
                "received_time": first,
                "latest_received_time": last,
            }

        rows = [
            row("expired", self.cutoff - 2, self.cutoff - 1),
            row("boundary", self.cutoff, self.cutoff),
            row("current", self.cutoff + 1, self.cutoff + 1),
            row("replayed", self.cutoff - 864000, self.cutoff + 1),
        ]
        # Omit unknown typed number fields: storing a string in the number-typed
        # KV column can be rejected before the prune is exercised.
        rows.append(
            {"_key": self.prefix + "-missing", "latest_received_time": self.cutoff - 1}
        )
        rows.append(row("malformed", -1, self.cutoff - 1))
        return rows

    def test_disabled_enabled_boundary_current_replay_and_idempotence(self):
        self.write(self.fixture())
        before = self.read()
        self._record("before", list(before.values()))
        disabled = lab.search("| `adm_network_client_history_prune`", "0", "+10y")[0]
        self.assertEqual(disabled["rows_pruned"], "0", disabled)
        self.assertEqual(before, self.read())
        self.override("adm_prune_maintenance", "1")
        result = lab.search("| `adm_network_client_history_prune`", "0", "+10y")[0]
        self.assertEqual(result["complete"], "1", result)
        self.assertEqual(result["rows_pruned"], "1", result)
        after = self.read()
        self._record("after", list(after.values()))
        self.assertEqual(set(after), set(before) - {self.prefix + "-expired"})
        for key in after:
            self.assertEqual(after[key], before[key])
        repeated = lab.search("| `adm_network_client_history_prune`", "0", "+10y")[0]
        self.assertEqual(repeated["rows_pruned"], "0", repeated)
        self.assertEqual(after, self.read())

    def test_incomplete_read_and_all_expired_safeguards_preserve_rows(self):
        self.write(self.fixture())
        self.override("adm_prune_maintenance", "1")
        before = self.read()
        self.override("adm_kv_complete", "eval adm_complete=0")
        result = lab.search("| `adm_network_client_history_prune`", "0", "+10y")[0]
        self.assertEqual(result["complete"], "0", result)
        self.assertEqual(result["rows_pruned"], "0", result)
        self.assertEqual(before, self.read())
        self.override(
            "adm_kv_complete", self.macros[APP + "/configs/conf-macros/adm_kv_complete"]
        )
        self.write(self.fixture()[:1])
        before = self.read()
        result = lab.search("| `adm_network_client_history_prune`", "0", "+10y")[0]
        self.assertEqual(result["rows_pruned"], "0", result)
        self.assertIn("empty-write safeguard", str(result.get("warnings")))
        self.assertEqual(before, self.read())

    def test_search_only_viewer_cannot_dispatch_prune_or_delete_history(self):
        import test_permissions as permissions

        self.write(self.fixture())
        before = self.read()
        admin_password = lab.read_secrets()["SPLUNK_PASSWORD"]
        role = "adm_prune_viewer_" + secrets.token_hex(8)
        self.username = role
        self.password = secrets.token_urlsafe(24)
        for kind, data in (
            (
                "roles",
                {
                    "name": role,
                    "capabilities": "search",
                    "srchIndexesAllowed": "adm_summary_v2",
                },
            ),
            ("users", {"name": role, "password": self.password, "roles": role}),
        ):
            path = (
                "/services/authorization/roles"
                if kind == "roles"
                else "/services/authentication/users"
            )
            status, _ = permissions._response(
                "POST",
                path,
                "admin",
                admin_password,
                urllib.parse.urlencode(data).encode(),
            )
            self.assertIn(status, (200, 201))
            cleaner = (
                permissions.RestrictedViewerTest._delete_role
                if kind == "roles"
                else permissions.RestrictedViewerTest._delete_user
            )
            self.addCleanup(cleaner, role, admin_password)
        self.override("adm_prune_maintenance", "1")
        for method, path in (
            ("DELETE", APP + "/storage/collections/data/" + COLLECTION),
            (
                "POST",
                APP
                + "/saved/searches/"
                + urllib.parse.quote("ADM - Network client history prune", safe="")
                + "/dispatch",
            ),
            ("POST", APP + "/configs/conf-macros/adm_prune_maintenance"),
        ):
            status, _ = permissions._response(
                method,
                path,
                self.username,
                self.password,
                b"definition=1"
                if "conf-macros" in path
                else b"trigger_actions=0"
                if method == "POST"
                else None,
            )
            self.assertIn(status, (401, 403, 404), path)
        self.lab = lab
        self._viewer_json = types.MethodType(
            permissions.RestrictedViewerTest._viewer_json, self
        )
        self._delete_job = types.MethodType(
            permissions.RestrictedViewerTest._delete_job, self
        )
        with self.assertRaises(permissions.SearchRejected):
            permissions.RestrictedViewerTest._viewer_search(
                self, "| `adm_network_client_history_prune`", 0, "+10y"
            )
        self.assertEqual(before, self.read())
