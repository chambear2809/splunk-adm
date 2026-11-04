"""Smoke-test optional command registration in a fresh, inert lab install."""

import os
from pathlib import Path
import sys
import unittest


@unittest.skipUnless(os.environ.get("ADM_LAB") == "1", "set ADM_LAB=1")
class QualifiedCommandInstallTests(unittest.TestCase):
    def test_shipped_commands_load_and_reject_disabled_profiles(self):
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import lab

        for search, message in (
            ("| admqualified mode=catalog", "Qualified identity is disabled"),
            ("| admacipoll mode=fabric", "ACI poll reader is disabled"),
        ):
            with self.subTest(search=search):
                with self.assertRaises(lab.LabError) as error:
                    lab.search(search, "-1m", "now")
                self.assertIn(message, str(error.exception))


if __name__ == "__main__":
    unittest.main()
