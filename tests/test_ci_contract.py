from pathlib import Path
import re
import unittest


CI = Path(__file__).parents[1] / ".github/workflows/ci.yml"


class CIChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = CI.read_text(encoding="utf-8")
        cls.lab = cls.text.split("  splunk-lab:", 1)[1]

    def test_lab_builds_verified_single_archive_before_lifecycle(self):
        for marker in (
            "node-version: 22.13.0",
            "npm ci --registry=https://registry.npmjs.org --ignore-scripts",
            "npx playwright install --with-deps chromium",
            "npm run package",
            "python3 tools/check_release.py --dist dist",
        ):
            self.assertIn(marker, self.lab)
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


if __name__ == "__main__":
    unittest.main()
