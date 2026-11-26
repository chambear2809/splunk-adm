from pathlib import Path
import re
import unittest


CI = Path(__file__).parents[1] / ".github/workflows/ci.yml"
WORKFLOWS = sorted(CI.parent.glob("*.yml"))


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

    def test_appinspect_gate_covers_every_cloud_experience_tag(self):
        gate = self.text.split("- name: AppInspect Cloud precert gate", 1)[1]
        gate = gate.split("- name:", 1)[0]
        self.assertIn("for tag in cloud private_victoria private_classic; do", gate)
        self.assertIn("splunk-appinspect list tags", gate)
        self.assertIn('--mode precert "${tag_args[@]}"', gate)
        self.assertNotIn("--excluded-tags", gate)

    def test_go_receiver_is_vetted_and_tested(self):
        go = self.text.split("\n  go:\n", 1)[1].split("\n  dependency-audit:", 1)[0]
        self.assertIn("working-directory: integrations/otel_atlas_receiver", go)
        self.assertIn("go-version-file: integrations/otel_atlas_receiver/go.mod", go)
        for command in ("go mod verify", "go vet ./...", "go test ./..."):
            self.assertIn(f"- run: {command}", go)

    def test_dependency_audits_fail_on_shipped_vulnerabilities(self):
        audit = self.text.split("  dependency-audit:", 1)[1].split("\n  secret-scan:")[
            0
        ]
        self.assertIn("npm audit --omit=dev --audit-level=high", audit)
        self.assertRegex(audit, r"'pip-audit==\d+\.\d+\.\d+'")
        self.assertIn("requirements=(tools/requirements*.txt)", audit)
        self.assertIn("pip_audit --strict", audit)

    def test_secret_scan_uses_checksum_verified_gitleaks_over_full_history(self):
        scan = self.text.split("  secret-scan:", 1)[1].split("\n  splunk-lab:", 1)[0]
        self.assertRegex(scan, r"GITLEAKS_SHA256: [0-9a-f]{64}\n")
        self.assertIn("sha256sum --check --strict", scan)
        self.assertIn("fetch-depth: 0", scan)
        self.assertIn('gitleaks" git --redact', scan)
        ignore = (CI.parents[2] / ".gitleaksignore").read_text(encoding="utf-8")
        for line in ignore.splitlines():
            if line and not line.startswith("#"):
                self.assertRegex(line, r"^[0-9a-f]{40}:[^:]+:[\w-]+:\d+$")

    def test_third_party_actions_are_pinned_to_commits(self):
        for workflow in WORKFLOWS:
            with self.subTest(workflow=workflow.name):
                uses = re.findall(r"uses:\s*(\S+)", workflow.read_text("utf-8"))
                self.assertTrue(uses)
                for action in uses:
                    self.assertRegex(action, r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")

    def test_workflows_default_to_read_only_contents(self):
        for workflow in WORKFLOWS:
            with self.subTest(workflow=workflow.name):
                text = workflow.read_text("utf-8")
                self.assertIn("\npermissions:\n  contents: read\n", text)
                self.assertNotRegex(text, r":\s*write-all|contents:\s*write")
                self.assertNotIn("pull_request_target", text)

    def test_codeql_scans_first_party_typescript_and_python(self):
        codeql = (CI.parent / "codeql.yml").read_text(encoding="utf-8")
        self.assertIn("language: [javascript-typescript, python]", codeql)
        self.assertIn("security-events: write", codeql)
        self.assertEqual(codeql.count("security-events: write"), 1)

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
