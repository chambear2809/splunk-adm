import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from qualify_native_recovery import run_rehearsal  # noqa: E402


class IsolatedRecoveryTests(unittest.TestCase):
    def test_complete_synthetic_exercise_and_negative_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "attempt"
            result = run_rehearsal(
                root, ROOT / "splunk_app/splunk_adm/bin", runtime_label="local-test"
            )
            self.assertEqual(result["status"], "passed")
            receipt = json.loads((root / "receipt.json").read_text())
            self.assertTrue(all(receipt["checks"].values()))
            self.assertEqual((root / "occupied/sentinel").read_bytes(), b"preserve")
            self.assertFalse((root / "partial-target").exists())
            self.assertFalse((root / "corrupt-target").exists())
            self.assertGreater(receipt["source_search_calls"], 0)
            self.assertTrue((root / "restored/cases.sqlite").exists())
            with self.assertRaises(FileExistsError):
                run_rehearsal(
                    root, ROOT / "splunk_app/splunk_adm/bin", runtime_label="local-test"
                )


if __name__ == "__main__":
    unittest.main()
