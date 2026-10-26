from pathlib import Path
import re
import unittest

LAB = Path(__file__).resolve().parent / "splunk/lab.sh"


class LabScriptPortabilityTest(unittest.TestCase):
    def test_possibly_empty_arrays_are_guarded_for_bash_3_under_nounset(self):
        text = LAB.read_text()
        self.assertIn("set -euo pipefail", text)
        # macOS /bin/bash 3.2 treats "${empty[@]}" as unbound under set -u.
        for name in re.findall(r"^\s*local (\w+)=\(\)", text, re.MULTILINE):
            self.assertNotIn(
                '"${%s[@]}"' % name,
                text.replace('${%s[@]+"${%s[@]}"}' % (name, name), ""),
            )


if __name__ == "__main__":
    unittest.main()
