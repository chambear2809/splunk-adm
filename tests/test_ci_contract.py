from pathlib import Path
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


if __name__ == "__main__":
    unittest.main()
