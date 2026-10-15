import json
import tempfile
import unittest
from pathlib import Path

from tools.check_appinspect import check_report


class AppInspectReportTests(unittest.TestCase):
    def write_report(self, value):
        handle = tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False)
        self.addCleanup(lambda: Path(handle.name).unlink(missing_ok=True))
        json.dump(value, handle)
        handle.close()
        return Path(handle.name)

    def test_accepts_success_warning_and_not_applicable_results(self):
        path = self.write_report(
            {
                "reports": [
                    {
                        "groups": [
                            {
                                "checks": [
                                    {"result": "success"},
                                    {"result": "warning"},
                                    {"result": "not_applicable"},
                                ]
                            }
                        ]
                    }
                ]
            }
        )
        self.assertEqual(check_report(path), [])

    def test_finds_nested_failure_and_error_results(self):
        path = self.write_report(
            {
                "reports": [
                    {
                        "groups": [
                            {
                                "checks": [
                                    {
                                        "name": "bad",
                                        "result": "failure",
                                        "messages": [{"result": "error"}],
                                    }
                                ]
                            }
                        ]
                    }
                ]
            }
        )
        failures = check_report(path)
        self.assertEqual(len(failures), 2)
        self.assertTrue(any("failure" in item for item in failures))
        self.assertTrue(any("error" in item for item in failures))

    def test_rejects_empty_report(self):
        path = self.write_report({})
        with self.assertRaisesRegex(ValueError, "no reports"):
            check_report(path)

    def test_rejects_report_without_checks(self):
        path = self.write_report({"reports": [{"groups": []}]})
        with self.assertRaisesRegex(ValueError, "no checks"):
            check_report(path)

    def test_rejects_unknown_check_result(self):
        path = self.write_report(
            {"reports": [{"groups": [{"checks": [{"result": "mystery"}]}]}]}
        )
        with self.assertRaisesRegex(ValueError, "unknown result"):
            check_report(path)

    def test_rejects_nonzero_summary_even_when_checks_pass(self):
        report = {
            "summary": {"error": 1},
            "reports": [{"groups": [{"checks": [{"result": "success"}]}]}],
        }
        failures = check_report(self.write_report(report))
        self.assertTrue(any("error" in item for item in failures))


if __name__ == "__main__":
    unittest.main()
