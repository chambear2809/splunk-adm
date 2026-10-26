from pathlib import Path
import re
import unittest


CI = Path(__file__).parents[1] / ".github/workflows/ci.yml"


class CIChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = CI.read_text(encoding="utf-8")
        cls.lab = cls.text.split("  splunk-lab:", 1)[1]

    def test_lab_uses_the_offline_qualified_archive_before_lifecycle(self):
        for marker in (
            "node-version: 22.13.0",
            "npm ci --registry=https://registry.npmjs.org --ignore-scripts",
            "npx playwright install --with-deps chromium",
            "python3 tools/check_release.py --dist dist",
            "needs: frontend",
            "actions/download-artifact@",
            "--parent-packet dist/qualification/offline",
        ):
            self.assertIn(marker, self.lab)
        self.assertNotIn("npm run package", self.lab)
        self.assertLess(
            self.lab.index("--stage offline"),
            self.lab.index('export ADM_UPGRADE_PACKAGE="$PWD/dist/splunk_adm-'),
        )
        self.assertIn('export ADM_UPGRADE_PACKAGE="$PWD/dist/splunk_adm-', self.lab)
        self.assertIn('test -f "$ADM_UPGRADE_PACKAGE"', self.lab)

    def test_lab_refuses_existing_container_before_purge_trap(self):
        refusal = self.lab.index("docker inspect adm-splunk-lab")
        trap = self.lab.index('trap "tests/splunk/lab.sh purge" EXIT')
        self.assertLess(refusal, trap)
        self.assertIn("Refusing to adopt an existing adm-splunk-lab", self.lab)

    def test_cloud_gate_remains_single_archive_and_report_driven(self):
        self.assertIn('test "${#archives[@]}" -eq 1', self.text)
        self.assertIn('python3 tools/check_appinspect.py "$report"', self.text)

    def test_appinspect_version_is_pinned(self):
        self.assertRegex(self.text, r"'splunk-appinspect==\d+\.\d+\.\d+'")

    def test_third_party_actions_are_pinned_to_commits(self):
        uses = re.findall(r"uses:\s*(\S+)", self.text)
        self.assertTrue(uses)
        for action in uses:
            self.assertRegex(action, r"^[\w.-]+/[\w.-]+@[0-9a-f]{40}$")

    def test_only_pull_requests_cancel_in_progress_runs(self):
        self.assertIn("${{ github.event_name }}", self.text.split("concurrency:")[1])
        self.assertIn(
            "cancel-in-progress: ${{ github.event_name == 'pull_request' }}", self.text
        )

    def test_python_checks_use_the_shipped_handler_interpreter(self):
        python = self.text.split("  python:", 1)[1].split("  splunk-lab:", 1)[0]
        self.assertIn('python-version: "3.13"', python)

    def test_lab_suite_installs_the_verified_archive(self):
        export = self.lab.index('export ADM_LAB_PACKAGE="$ADM_UPGRADE_PACKAGE"')
        self.assertLess(self.lab.index('test -f "$ADM_UPGRADE_PACKAGE"'), export)
        self.assertLess(export, self.lab.index("tests/splunk/lab.sh install"))

    def test_qualification_packets_are_retained_after_failure_without_raw_reports(self):
        for stage in ("offline", "installed"):
            self.assertIn(f"dist/qualification/{stage}/", self.text)
            self.assertIn(
                f"always() && steps.{stage}_evidence.outcome == 'success'", self.text
            )
        self.assertIn("retention-days: 90", self.text)
        self.assertNotIn("path: dist/\n", self.text)
        self.assertNotIn("path: dist/appinspect-cloud.json", self.text)

    def test_lab_records_native_runtime_and_suite_inside_owned_lifecycle(self):
        trap = self.lab.index('trap "tests/splunk/lab.sh purge" EXIT')
        runtime = self.lab.index("qualification_evidence.py lab-runtime")
        suite = self.lab.index("--check splunk_integration")
        self.assertLess(trap, runtime)
        self.assertLess(runtime, suite)


if __name__ == "__main__":
    unittest.main()
