from pathlib import Path
import re
import unittest

LAB = Path(__file__).resolve().parent / "splunk/lab.sh"


class LabScriptPortabilityTest(unittest.TestCase):
    def test_task_create_has_fixed_resource_caps_and_log_rotation(self):
        text = LAB.read_text()
        for fragment in (
            "--cpus 4",
            "--memory 8g",
            "--memory-swap 8g",
            "--pids-limit 1024",
            "--log-driver json-file",
            "--log-opt max-size=10m",
            "--log-opt max-file=2",
        ):
            self.assertIn(fragment, text)

    def test_possibly_empty_arrays_are_guarded_for_bash_3_under_nounset(self):
        text = LAB.read_text()
        self.assertIn("set -euo pipefail", text)
        # macOS /bin/bash 3.2 treats "${empty[@]}" as unbound under set -u.
        for name in re.findall(r"^\s*local (\w+)=\(\)", text, re.MULTILINE):
            self.assertNotIn(
                '"${%s[@]}"' % name,
                text.replace('${%s[@]+"${%s[@]}"}' % (name, name), ""),
            )

    def test_lab_script_verifies_active_resource_lease_when_opt_in_env_set(self):
        text = LAB.read_text()
        self.assertIn("SPLUNK_ADM_RESOURCE_LEASE_ID", text)
        self.assertIn("tools/lab_resources.py", text)
        self.assertIn("verify-active", text)


if __name__ == "__main__":
    unittest.main()
