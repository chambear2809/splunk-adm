"""Native Setup browser writes under the parent-owned local lab lifecycle."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import uuid
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


@unittest.skipUnless(os.environ.get("ADM_LAB") == "1", "requires the owned local lab")
class SetupBrowserTest(unittest.TestCase):
    def test_admin_can_save_macro_and_enable_schedule(self) -> None:
        sys.path.insert(0, str(HERE))
        import lab
        from test_permissions import _response

        deadline = time.monotonic() + 180
        while (
            lab._json("GET", "/services/kvstore/status")["entry"][0]["content"]
            .get("current", {})
            .get("status")
            != "ready"
        ):
            if time.monotonic() > deadline:
                self.fail("KV store did not become ready for Setup qualification")
            time.sleep(2)
        password = lab.read_secrets()["SPLUNK_PASSWORD"]
        settings_collection = "/servicesNS/nobody/splunk_adm/storage/collections/data/adm_deployment_settings"
        settings_path = settings_collection + "/deployment"
        settings_status, settings_body = _response(
            "GET", settings_path, "admin", password
        )
        self.assertIn(settings_status, (200, 404))
        original_settings = (
            json.loads(settings_body) if settings_status == 200 else None
        )
        if original_settings is not None:
            self.assertIsInstance(original_settings, dict)
            self.assertEqual(original_settings.get("_key"), "deployment")
            # _user is KV Store response metadata, not an application setting.
            original_settings = {
                name: value
                for name, value in original_settings.items()
                if name != "_user"
            }

        def restore_settings() -> None:
            if original_settings is None:
                status, _ = _response("DELETE", settings_path, "admin", password)
                self.assertIn(status, (200, 404))
                status, _ = _response("GET", settings_path, "admin", password)
                self.assertEqual(status, 404)
                return
            body = json.dumps(original_settings).encode()
            status, _ = _response(
                "POST", settings_path, "admin", password, body, "application/json"
            )
            if status == 404:
                status, _ = _response(
                    "POST",
                    settings_collection,
                    "admin",
                    password,
                    body,
                    "application/json",
                )
            self.assertIn(status, (200, 201))
            status, restored_body = _response("GET", settings_path, "admin", password)
            self.assertEqual(status, 200)
            restored = {
                name: value
                for name, value in json.loads(restored_body).items()
                if name != "_user"
            }
            self.assertEqual(restored, original_settings)

        self.addCleanup(restore_settings)
        collection = (
            "/servicesNS/nobody/splunk_adm/storage/collections/data/adm_observer_scope"
        )
        key = "atlas_setup_test_" + uuid.uuid4().hex
        status, _ = _response(
            "POST",
            collection,
            "admin",
            password,
            json.dumps(
                {
                    "_key": key,
                    "observer_kind": "exporter",
                    "observer": "192.0.2.11",
                    "scope": "prod",
                    "cluster": "",
                }
            ).encode(),
            "application/json",
        )
        self.assertIn(status, (200, 201))
        self.addCleanup(lambda: lab._mgmt("DELETE", collection + "/" + key).close())
        macro_path = (
            "/servicesNS/nobody/splunk_adm/configs/conf-macros/adm_index_hubble"
        )
        search_path = "/servicesNS/nobody/splunk_adm/saved/searches/ADM%20-%20Application%20catalog"
        definition = lab._json("GET", macro_path)["entry"][0]["content"]["definition"]
        self.addCleanup(lab._json, "POST", macro_path, {"definition": definition})
        original = lab._json("GET", search_path)["entry"][0]["content"]
        restore = {
            "disabled": str(int(original["disabled"] in (True, 1, "1"))),
            "is_scheduled": str(int(original["is_scheduled"] in (True, 1, "1"))),
            "cron_schedule": original["cron_schedule"],
        }
        self.addCleanup(lab._json, "POST", search_path, restore)
        # Keep the enabled schedule away from the test window; the UI must preserve it.
        cadence = "0 0 1 1 *"
        lab._json(
            "POST",
            search_path,
            {"disabled": "1", "is_scheduled": "0", "cron_schedule": cadence},
        )
        result = subprocess.run(
            ["node", str(HERE / "setup-browser.mjs")],
            cwd=ROOT,
            env=dict(
                os.environ,
                ADM_SETUP_PASS=lab.read_secrets()["SPLUNK_PASSWORD"],
                ADM_SETUP_ORIGINAL_INDEX=definition.removeprefix("index="),
            ),
            capture_output=True,
            text=True,
            timeout=360,
        )
        # Only the browser's deliberately sanitized evidence is reported.
        evidence = (
            json.loads(result.stdout.strip().splitlines()[-1])
            if result.stdout.strip()
            else {"ok": False, "stage": "no browser evidence"}
        )
        self.assertEqual(result.returncode, 0, evidence)
        self.assertTrue(evidence["ok"], evidence)
        self.assertEqual(evidence["verifiedWrites"], 3, evidence)
        self.assertEqual(evidence["verifiedDeploymentWrites"], 1, evidence)
        self.assertTrue(evidence["deploymentReadback"], evidence)
        settings_status, settings_body = _response(
            "GET", settings_path, "admin", password
        )
        self.assertEqual(settings_status, 200)
        saved_document = json.loads(settings_body)
        saved_settings = json.loads(saved_document["settings_json"])
        self.assertEqual(saved_document["_key"], "deployment")
        self.assertEqual(saved_settings["schemaVersion"], 1)
        self.assertRegex(
            saved_settings["revision"],
            r"^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$",
        )
        self.assertEqual(saved_document["revision"], saved_settings["revision"])
        if original_settings is not None:
            self.assertNotEqual(
                saved_document["revision"], original_settings["revision"]
            )
        self.assertEqual(saved_settings["sources"]["traces"]["state"], "active")
        self.assertTrue(
            all(
                source["state"] == "not_selected"
                for name, source in saved_settings["sources"].items()
                if name != "traces"
            )
        )
        self.assertEqual(
            lab._json("GET", macro_path)["entry"][0]["content"]["definition"],
            definition,
        )
        changed = lab._json("GET", search_path)["entry"][0]["content"]
        self.assertIn(changed["disabled"], (False, 0, "0"))
        self.assertIn(changed["is_scheduled"], (True, 1, "1"))
        self.assertEqual(changed["cron_schedule"], cadence)
