"""Live browser qualification for a restricted Application Atlas viewer."""

from __future__ import annotations

import json
import os
import selectors
import subprocess
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


@unittest.skipUnless(
    os.environ.get("ADM_LAB") == "1", "set ADM_LAB=1 with the lab running"
)
class ViewerBrowserTest(unittest.TestCase):
    """Run the browser against the parent-owned lab and clean up the viewer."""

    @classmethod
    def setUpClass(cls) -> None:
        sys.path.insert(0, str(HERE))
        import lab
        from test_data_layer import WINDOW
        from test_permissions import RestrictedViewerTest

        cls.window = WINDOW
        cls.catalog_window = (int(WINDOW[1]) - 3600, int(WINDOW[1]))
        cls.restricted = RestrictedViewerTest
        # RestrictedViewerTest owns the ephemeral user, role, and saved-search
        # cleanup. The lab lifecycle itself is deliberately outside this test.
        try:
            RestrictedViewerTest.setUpClass()
        except Exception:
            RestrictedViewerTest.doClassCleanups()
            raise
        cls.addClassCleanup(RestrictedViewerTest.doClassCleanups)
        # Seed only the rows captured by the fixture-backed catalog builder.
        # The browser then exercises the real viewer lookup and Find searches.
        cls.catalog_rows = lab.search("| `adm_catalog_build`", *cls.catalog_window)
        cls.catalog_keys = [row["_key"] for row in cls.catalog_rows]
        lab.search(
            "| `adm_catalog_build` | outputlookup append=true key_field=_key adm_app_catalog",
            *cls.catalog_window,
        )
        cls.addClassCleanup(cls._cleanup_catalog)

    @classmethod
    def _cleanup_catalog(cls) -> None:
        import urllib.parse

        for key in cls.catalog_keys:
            with cls.restricted.lab._mgmt(
                "DELETE",
                "/servicesNS/nobody/splunk_adm/storage/collections/data/"
                f"adm_app_catalog/{urllib.parse.quote(key, safe='')}",
            ) as response:
                response.read()

    def _readline(self, process: subprocess.Popen[str], timeout: float = 1200) -> dict:
        ready = selectors.DefaultSelector()
        try:
            ready.register(process.stdout, selectors.EVENT_READ)
            if not ready.select(timeout):
                self.fail("viewer browser produced no evidence before timeout")
            line = process.stdout.readline()
        finally:
            ready.close()
        self.assertTrue(line, "viewer browser exited without evidence")
        try:
            return json.loads(line)
        except json.JSONDecodeError as error:
            self.fail(f"viewer browser returned non-JSON evidence: {error}")

    def _pin_absent_deployment_settings(self) -> None:
        from settings_fixture import SettingsFixture

        # The parent owns this disposable namespace. Preserve all immutable
        # slots as well as the legacy anchor, and restore the complete snapshot.
        fixture = SettingsFixture(self, enable_writes=False)
        fixture.clear()
        status, snapshot = fixture.request("GET")
        self.assertEqual(status, 200)
        self.assertEqual(snapshot["state"], "absent")

    def test_restricted_viewer_can_use_live_views(self) -> None:
        import lab

        self._pin_absent_deployment_settings()
        viewer = self.restricted.username
        timezone = "Pacific/Honolulu"
        prefs = f"/servicesNS/{viewer}/user-prefs/data/user-prefs/general"
        lab._json("POST", f"/services/authentication/users/{viewer}", {"tz": timezone})
        browser_env = dict(
            os.environ,
            ADM_VIEWER_USER=viewer,
            ADM_VIEWER_PASS=self.restricted.password,
        )
        command = [
            "node",
            str(HERE / "viewer-browser.mjs"),
            self.window[0],
            self.window[1],
            str(
                sum(row.get("row_type") == "node" for row in self.restricted.admin_rows)
            ),
            timezone,
        ]
        process = subprocess.Popen(
            command,
            cwd=ROOT,
            env=browser_env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            login = self._readline(process, timeout=60)
            self.assertEqual(login.get("login"), "ok", login)
            for theme in ("dark", "light"):
                lab._json("POST", prefs, {"theme": theme})
                process.stdin.write(f"theme {theme}\n")
                process.stdin.flush()
                evidence = self._readline(process)
                self.assertNotIn("error", evidence, evidence)
                self.assertTrue(
                    evidence.get("mapRoute", {}).get("status", 0) < 400, evidence
                )
                self.assertEqual(evidence.get("mounted"), "true", evidence)
                self.assertTrue(evidence.get("themeOk"), evidence)
                self.assertTrue(evidence.get("timezoneOk"), evidence)
                field_style = evidence.get("scopeFieldStyle", {})
                self.assertEqual(
                    field_style.get("background"), "rgba(0, 0, 0, 0)", evidence
                )
                self.assertEqual(field_style.get("border"), "0px", evidence)
                self.assertEqual(field_style.get("shadow"), "none", evidence)
                timezone_picker = evidence.get("timezonePicker", {})
                self.assertEqual(
                    timezone_picker.get("name"), "Pacific/Honolulu", evidence
                )
                self.assertEqual(timezone_picker.get("offset"), 600, evidence)
                self.assertEqual(evidence.get("scopeService"), "frontend", evidence)
                self.assertIn("demo", evidence.get("scopeDims", ""), evidence)
                self.assertFalse(evidence.get("notLoaded"), evidence)
                self.assertFalse(evidence.get("incompleteWindow"), evidence)
                self.assertTrue(evidence.get("nodesOk"), evidence)
                self.assertTrue(evidence.get("cardsPresent"), evidence)
                self.assertTrue(evidence.get("serviceHealthEntry"), evidence)
                self.assertEqual(evidence.get("demoRequests"), 0, evidence)
                self.assertIn(
                    evidence.get("scopeControls", {}).get("buildEarliest"),
                    {"-1h", "-60m@m"},
                    evidence,
                )
                self.assertEqual(
                    evidence.get("scopeControls", {}).get("buildLatest"),
                    "now",
                    evidence,
                )
                self.assertTrue(
                    evidence.get("scopeControls", {}).get("incompleteWindow"),
                    evidence,
                )
                self.assertTrue(
                    evidence.get("scopeControls", {}).get("optionSearch"), evidence
                )
                self.assertEqual(
                    evidence.get("reload", {}).get("scopeService"), "frontend", evidence
                )
                self.assertEqual(
                    evidence.get("reload", {}).get("nodeCount"),
                    evidence.get("expectedNodes"),
                    evidence,
                )
                self.assertGreater(
                    evidence.get("reload", {}).get("cards", 0), 0, evidence
                )
                self.assertTrue(evidence.get("legacyRedirectOk"), evidence)
                self.assertTrue(
                    evidence.get("liveEvidence", {}).get("selected"), evidence
                )
                self.assertEqual(
                    evidence.get("liveEvidence", {}).get("target"), "_blank", evidence
                )
                self.assertIn(
                    "noopener",
                    evidence.get("liveEvidence", {}).get("rel", ""),
                    evidence,
                )
                self.assertTrue(
                    evidence.get("liveEvidence", {}).get("safeHref"), evidence
                )
                popup = evidence.get("liveEvidence", {}).get("searchPopup", {})
                self.assertTrue(popup.get("opened"), evidence)
                self.assertTrue(popup.get("dispatched"), evidence)
                self.assertTrue(popup.get("macroRequest"), evidence)
                self.assertTrue(popup.get("completed"), evidence)
                self.assertTrue(popup.get("nonEmpty"), evidence)
                catalog = evidence.get("catalog", {})
                self.assertTrue(catalog.get("loaded"), evidence)
                self.assertEqual(
                    catalog.get("mapPath"), "/en-US/app/splunk_adm/map", evidence
                )
                self.assertEqual(catalog.get("service"), "frontend", evidence)
                self.assertEqual(
                    catalog.get("earliest"), str(int(self.window[1]) - 3600), evidence
                )
                self.assertEqual(catalog.get("latest"), self.window[1], evidence)
                found = evidence.get("find", {})
                self.assertTrue(found.get("loaded"), evidence)
                self.assertEqual(
                    found.get("mapPath"), "/en-US/app/splunk_adm/map", evidence
                )
                self.assertEqual(found.get("service"), "checkout", evidence)
                self.assertEqual(
                    found.get("earliest"), str(int(self.window[1]) - 3600), evidence
                )
                self.assertEqual(found.get("latest"), self.window[1], evidence)
                self.assertTrue(evidence.get("demo", {}).get("synthetic"), evidence)
                self.assertGreater(
                    evidence.get("demo", {}).get("cards", 0), 0, evidence
                )
                self.assertTrue(
                    evidence.get("demoFindings", {}).get("copied"), evidence
                )
                self.assertTrue(evidence.get("demoFindings", {}).get("csv"), evidence)
                self.assertTrue(
                    evidence.get("demoFindings", {}).get("openDisabled"), evidence
                )
                for route in evidence.get("routes", {}).values():
                    self.assertFalse(route["loginRedirect"], route)
                    self.assertTrue(
                        route["status"] is not None and route["status"] < 400, route
                    )
                    self.assertFalse(route["notFound"], route)
                    self.assertTrue(route["headingPresent"], route)
                health_tables = evidence.get("healthTables", {})
                self.assertGreater(health_tables.get("sources", 0), 0, evidence)
                self.assertGreater(health_tables.get("scheduled", 0), 0, evidence)
                for setup in evidence.get("setup", {}).values():
                    self.assertTrue(
                        setup.get("loginRedirect")
                        or setup.get("notFound")
                        or setup.get("status") in (403, 404),
                        evidence,
                    )
                self.assertIn(
                    evidence.get("setupRestStatus"), (401, 403, 404), evidence
                )
                self.assertTrue(evidence.get("searchRequests"), evidence)
                self.assertGreater(evidence.get("graphRequests", 0), 0, evidence)
                unknown_health = evidence.get("healthUnknown", {})
                self.assertTrue(unknown_health.get("visible"), evidence)
                self.assertTrue(unknown_health.get("metadataHeadersObserved"), evidence)
                self.assertTrue(unknown_health.get("healthCompleted"), evidence)
                self.assertEqual(unknown_health.get("settingsStatus"), 200, evidence)
                self.assertEqual(
                    unknown_health.get("settingsState"), "absent", evidence
                )
                expected_selectors = {
                    selector["name"]
                    for selector in json.loads(
                        (ROOT / "research/cisco-pipeline-interface.json").read_text()
                    )["activation"]["cutover_selectors"]
                }
                metadata = unknown_health.get("contractMetadata", [])
                self.assertEqual(
                    {row.get("name") for row in metadata}, expected_selectors, evidence
                )
                self.assertEqual(len(metadata), len(expected_selectors), evidence)
                self.assertTrue(
                    all(row.get("status") == 403 for row in metadata), evidence
                )
                self.assertEqual(
                    unknown_health.get("probeCounter"), "request", evidence
                )
                self.assertEqual(unknown_health.get("probeRequests"), 0, evidence)
                self.assertEqual(evidence.get("healthRequests"), 0, evidence)
                self.assertFalse(evidence.get("requireMismatch"), evidence)
            process.stdin.write("quit\n")
            process.stdin.flush()
            process.wait(timeout=60)
            self.assertEqual(
                process.returncode,
                0,
                "Viewer browser exited unsuccessfully; stderr omitted to protect credentials.",
            )
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)
            for pipe in (process.stdin, process.stdout, process.stderr):
                if pipe is not None:
                    pipe.close()


if __name__ == "__main__":
    unittest.main()
