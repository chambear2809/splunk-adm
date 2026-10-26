"""Owned standalone qualification of the recovery/settings/retention changes.

The parent supplies a private test CA and owns setup, package binding and cleanup.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from urllib.parse import quote, urlencode
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [
    str(ROOT),
    str(ROOT / "tests/splunk"),
    str(ROOT / "splunk_app/splunk_adm/bin"),
    str(ROOT / "splunk_app/splunk_adm/bin/lib"),
]


@unittest.skipUnless(
    os.environ.get("ADM_LAB") == "1" and os.environ.get("ADM_IMPROVEMENT_CA"),
    "requires owned lab and private verified CA",
)
class ImprovementBatchQualification(unittest.TestCase):
    def setUp(self):
        import lab
        from adm_recovery_lib.rest import Rest

        self.lab = lab
        self.assertTrue(
            lab.task_identity(), "qualification must not adopt the default lab"
        )
        lab.verify_target()
        self.ca = os.environ["ADM_IMPROVEMENT_CA"]
        session = lab._json(
            "POST",
            "/services/auth/login",
            {"username": "admin", "password": lab.read_secrets()["SPLUNK_PASSWORD"]},
        )
        self.token = session.get("sessionKey")
        self.assertTrue(isinstance(self.token, str) and self.token)
        self.api = Rest(
            self.token,
            uri="https://localhost:" + os.environ["ADM_LAB_MGMT_PORT"],
            ca_file=self.ca,
        )

    def test_native_completion_metadata_and_readonly_job_cleanup(self):
        from adm_recovery_lib.core import Recovery

        recovery = Recovery(self.api)
        rows = recovery.search('| makeresults | eval checked="native" | table checked')
        self.assertEqual(rows, [{"checked": "native"}])
        self.assertEqual(recovery.readonly_sids, set())

    def test_native_claim_commit_with_lost_response_remains_uncertain(self):
        from adm_recovery_lib.core import Recovery, Uncertain, STATE
        from adm_recovery_lib.rest import TransportTimeout

        api = self.api
        key = "qualification_" + uuid.uuid4().hex

        class LostResponse:
            lost = False

            def request(self, method, path, **kwargs):
                result = api.request(method, path, **kwargs)
                if method == "POST" and path == STATE and not self.lost:
                    self.lost = True
                    raise TransportTimeout()
                return result

        recovery = Recovery(LostResponse())
        record = {
            "_key": key,
            "owner": recovery.owner,
            "name": "qualification",
            "expires_at": time.time() + 120,
            "state": "pause_pending",
            "record_type": "target",
        }
        try:
            with self.assertRaises(Uncertain) as error:
                recovery.insert(record)
            self.assertEqual(error.exception.claim_key, key)
            persisted = api.request("GET", STATE + "/" + key)
            self.assertEqual(persisted["owner"], recovery.owner)
            self.assertEqual(persisted["state"], "pause_pending")
        finally:
            if recovery.state(key) is not None:
                api.request("DELETE", STATE + "/" + key)

    def test_native_full_settings_history_is_readable_and_exactly_retryable(self):
        from settings_fixture import SettingsFixture, COLLECTION
        from adm_settings_lib import (
            MAX_RECORDS,
            ROOT_KEY,
            SettingsService,
            canonical,
            digest,
            successor_key,
        )

        fixture = SettingsFixture(self)
        fixture.clear()
        status, snapshot = fixture.request("GET")
        self.assertEqual(status, 200)
        self.assertTrue(snapshot["canWrite"])
        sources = {
            "netflow": {
                "state": "active",
                "cadenceSeconds": 60,
                "staleAfterSeconds": 600,
            }
        }
        documents, previous = [], None
        last_payload = None
        for index in range(MAX_RECORDS):
            request_id = f"native_capacity_{index}"
            settings = {"schemaVersion": 1, "revision": "draft", "sources": sources}
            fingerprint = SettingsService.fingerprint(settings, previous, request_id)
            revision = digest(["revision", fingerprint])
            document = {
                "_key": ROOT_KEY if previous is None else successor_key(previous),
                "format": 2,
                "previous_revision": previous,
                "request_id": request_id,
                "operation_fingerprint": fingerprint,
                "revision": revision,
                "settings_json": canonical({**settings, "revision": revision}),
            }
            if previous is None:
                document["legacy_fingerprint"] = digest(None)
            documents.append(document)
            last_payload = {
                "namespace": snapshot["namespace"],
                "requestId": request_id,
                "expectedRevision": previous,
                "settings": settings,
            }
            previous = revision
        # The native default admits at most 1,000 documents per batch save.
        for offset in range(0, len(documents), 1000):
            status, _ = fixture.request(
                "POST",
                path=COLLECTION + "/batch_save",
                payload=documents[offset : offset + 1000],
            )
            self.assertIn(status, (200, 201))
        status, full = fixture.request("GET")
        self.assertEqual(status, 200)
        self.assertEqual(
            (full["recordCount"], full["maxRecords"], full["remainingRecords"]),
            (MAX_RECORDS, MAX_RECORDS, 0),
        )
        self.assertFalse(full["canWrite"])
        self.assertTrue(full["canRetry"])
        self.assertEqual(full["settings"]["revision"], previous)
        status, retried = fixture.request("POST", payload=last_payload)
        self.assertEqual(status, 200)
        self.assertEqual(retried["committedRevision"], previous)
        last_payload = {
            **last_payload,
            "requestId": "new_operation",
            "expectedRevision": previous,
        }
        self.assertEqual(fixture.request("POST", payload=last_payload)[0], 503)

    def pause_schedules(self):
        from tools.retention_maintenance import RetentionMaintenance, APP

        helper = RetentionMaintenance(self.api)
        saved = []

        def restore():
            for path, content in reversed(saved):
                self.api.request("POST", path, data=content)

        self.addCleanup(restore)
        for entry in helper.listing(APP + "/saved/searches"):
            if not entry["name"].startswith("ADM - "):
                continue
            content = entry["content"]
            path = APP + "/saved/searches/" + quote(entry["name"], safe="")
            saved.append(
                (
                    path,
                    {
                        "disabled": str(int(content["disabled"] in (True, 1, "1"))),
                        "is_scheduled": str(
                            int(content["is_scheduled"] in (True, 1, "1"))
                        ),
                    },
                )
            )
            self.api.request("POST", path, data={"disabled": "1", "is_scheduled": "0"})
        macro = APP + "/configs/conf-macros/adm_prune_maintenance"
        original = self.api.request("GET", macro)["entry"][0]["content"]["definition"]
        self.addCleanup(
            lambda: self.api.request("POST", macro, data={"definition": original})
        )
        self.api.request("POST", macro, data={"definition": "1"})
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            jobs = helper.listing("/services/search/v2/jobs")
            if all(
                job.get("content", {}).get("isDone") in (True, 1, "1")
                and job["content"].get("dispatchState") in ("DONE", "FAILED")
                for job in jobs
            ):
                return
            time.sleep(1)
        self.fail("owned lab did not reach quiescence")

    def test_native_cursor_retention_cli_backups_and_six_expiry_rules(self):
        from tools.retention_maintenance import COLLECTIONS, RetentionMaintenance

        self.pause_schedules()
        for collection, fields in COLLECTIONS.items():
            with self.subTest(collection=collection):
                path = RetentionMaintenance.path(collection)
                params = urlencode({"limit": 10001, "sort": "_key:1"})
                original = self.api.request("GET", path + "?" + params)
                self.assertLess(
                    len(original),
                    10000,
                    "fixture refuses a potentially incomplete backup",
                )
                shifted = self.api.request(
                    "GET",
                    path
                    + "?"
                    + urlencode({"limit": 10001, "skip": 1, "sort": "_key:1"}),
                )
                self.assertEqual(shifted, original[1:])
                try:
                    self.api.request("DELETE", path)
                    now = time.time()
                    records = [
                        {
                            "_key": "qualification-a-expired",
                            **{field: 1 for field in fields},
                        },
                        {
                            "_key": "qualification-b-current",
                            **{field: now for field in fields},
                        },
                        {"_key": "qualification-c-missing"},
                    ]
                    for record in records:
                        self.api.request("POST", path, data=record, json_body=True)
                    tool = RetentionMaintenance(self.api, page_size=1)
                    observed = tool.status(collection)
                    self.assertTrue(observed["complete"])
                    self.assertEqual(observed["rows_read"], 3)
                    self.assertEqual(observed["rows_expired"], 1)
                    with tempfile.TemporaryDirectory(
                        prefix="adm-native-retention-", dir="/private/tmp"
                    ) as directory:
                        destination = Path(directory) / "backup"
                        result = RetentionMaintenance(self.api, page_size=1).prune(
                            collection, backup_dir=destination, confirm=True
                        )
                        self.assertEqual(result["status"], "complete", result)
                        self.assertEqual(result["rows_deleted"], 1)
                        report = json.loads((destination / "manifest.json").read_text())
                        backup = destination / report["backup"]
                        self.assertEqual(
                            report["backup_sha256"],
                            hashlib.sha256(backup.read_bytes()).hexdigest(),
                        )
                        self.assertEqual(len(backup.read_text().splitlines()), 3)
                        self.assertIsNone(report["pending_key"])
                        self.assertEqual(report["status"], "complete")
                    command = [
                        sys.executable,
                        str(ROOT / "tools/retention_maintenance.py"),
                        "--ca-file",
                        self.ca,
                        "--management-uri",
                        "https://localhost:" + os.environ["ADM_LAB_MGMT_PORT"],
                        "--session-key-stdin",
                        "status",
                        collection,
                    ]
                    cli = subprocess.run(
                        command,
                        input=self.token + "\n",
                        text=True,
                        capture_output=True,
                        timeout=60,
                    )
                    self.assertTrue(
                        self.token not in cli.stdout + cli.stderr,
                        "retention CLI disclosed a credential; raw output withheld",
                    )
                    self.assertEqual(
                        cli.returncode,
                        0,
                        "retention CLI returned nonzero; raw output withheld",
                    )
                    report = json.loads(cli.stdout)
                    self.assertEqual(report["rows_read"], 2)
                    self.assertEqual(report["rows_expired"], 0)
                finally:
                    self.api.request("DELETE", path)
                    for row in original:
                        self.api.request(
                            "POST",
                            path,
                            data={
                                key: value
                                for key, value in row.items()
                                if key != "_user"
                            },
                            json_body=True,
                        )


if __name__ == "__main__":
    unittest.main()
