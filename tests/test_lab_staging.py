"""Exercise install staging with fake tools; never contact Docker or Splunk."""

from __future__ import annotations

import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
TOKEN = "synthetic-hec/with&literal-$characters"
PASSWORD = "synthetic-password-unused-by-install"


class LabStagingTest(unittest.TestCase):
    def fixture(self, directory, *, archive=False, secret_mode=0o600, duplicate=False):
        root = Path(directory)
        here = root / "tests/splunk"
        here.mkdir(parents=True)
        shutil.copy2(ROOT / "tests/splunk/lab.sh", here / "lab.sh")
        shutil.copytree(ROOT / "tests/splunk/lab_app", here / "lab_app")
        tools = root / "tools"
        tools.mkdir()
        shutil.copy2(
            ROOT / "tools/stage_lab_package.py", tools / "stage_lab_package.py"
        )
        # The shell guard and restart are intercepted by fake python3 below.
        (tools / "lab_lock.py").write_text("# fake tool path\n")
        (here / "lab.py").write_text("# fake tool path\n")
        extracted = root / "research/extracted"
        for package, app in (
            ("splunk-add-on-for-stream-wire-data_816", "Splunk_TA_stream_wire_data"),
            ("cisco-security-cloud_372", "CiscoSecurityCloud"),
            ("cisco-dc-networking_122", "cisco_dc_networking_app_for_splunk"),
            ("cisco-enterprise-networking-add-on-for-splunk_4050", "TA_cisco_catalyst"),
            (
                "cisco-enterprise-networking-netflow-add-on-for-splunk_400",
                "splunk_app_stream_ipfix_cisco_hsl",
            ),
            ("cisco-meraki-add-on-for-splunk_350", "Splunk_TA_cisco_meraki"),
            ("cisco-enterprise-networking-app-for-splunk_4020", "cisco-catalyst-app"),
        ):
            default = extracted / package / app / "default"
            default.mkdir(parents=True)
            (default / "app.conf").write_text("[launcher]\nversion=synthetic\n")
            (default / "props.conf").write_text("[synthetic]\n")
            (default / "savedsearches.conf").write_text(
                "[Synthetic vendor writer]\nsearch=| makeresults\n"
            )
        source = root / "splunk_app/splunk_adm"
        (source / "default").mkdir(parents=True)
        (source / "bin").mkdir()
        (source / "appserver/static").mkdir(parents=True)
        (source / "default/app.conf").write_text("[id]\nname=source-only\n")
        (source / "appserver/static/example.js").write_text("// static fixture\n")
        (root / "config").mkdir()
        (root / "config/deployment-health.json").write_text("{}\n")
        secrets = root / "protected-secrets"
        secrets.write_text(
            f"SPLUNK_PASSWORD={PASSWORD}\nHEC_TOKEN={TOKEN}\n"
            + (f"HEC_TOKEN={TOKEN}\n" if duplicate else "")
        )
        secrets.chmod(secret_mode)
        fake = root / "fake-bin"
        fake.mkdir()
        python = fake / "python3"
        python.write_text(
            f"#!{sys.executable}\n"
            "import json, os, sys\n"
            "from pathlib import Path\n"
            "with Path(os.environ['TEST_ARGV']).open('a') as out:\n"
            "    out.write(json.dumps(['python3', *sys.argv[1:]])+'\\n')\n"
            "if sys.argv[1].endswith('/tools/lab_lock.py'):\n"
            "    assert '--check-owned' in sys.argv\n"
            "    raise SystemExit(0)\n"
            "if sys.argv[1].endswith('/tests/splunk/lab.py'):\n"
            "    assert sys.argv[2:] == ['restart']\n"
            "    raise SystemExit(0)\n"
            "os.execv(os.environ['REAL_PYTHON'], [os.environ['REAL_PYTHON'], *sys.argv[1:]])\n"
        )
        docker = fake / "docker"
        docker.write_text(
            f"#!{sys.executable}\n"
            "import json, os, shutil, stat, sys\n"
            "from pathlib import Path\n"
            "with Path(os.environ['TEST_ARGV']).open('a') as out:\n"
            "    out.write(json.dumps(['docker', *sys.argv[1:]])+'\\n')\n"
            "if sys.argv[1] == 'cp':\n"
            "    source=Path(sys.argv[2]); stage=source.parent\n"
            "    assert stat.S_IMODE(stage.stat().st_mode)==0o700\n"
            "    target=Path(os.environ['TEST_INSTALLED'])/source.name\n"
            "    shutil.copytree(source,target,copy_function=shutil.copy2)\n"
            "    if source.name == 'adm_lab':\n"
            "        credential=target/'default/inputs.conf'\n"
            "        assert stat.S_IMODE(credential.stat().st_mode)==0o600\n"
            "        assert not (target/'default/inputs.conf.template').exists()\n"
            "    with Path(os.environ['TEST_MODES']).open('a') as out:\n"
            "        out.write(json.dumps({'app':source.name,'stage_mode':stat.S_IMODE(stage.stat().st_mode)})+'\\n')\n"
            "elif sys.argv[1:4] != ['exec','-u','root']:\n"
            "    raise AssertionError('unexpected fake Docker operation')\n"
        )
        sed = fake / "sed"
        sed.write_text(
            f"#!{sys.executable}\n"
            "import json, os, sys\n"
            "from pathlib import Path\n"
            "with Path(os.environ['TEST_ARGV']).open('a') as out:\n"
            "    out.write(json.dumps(['sed', *sys.argv[1:]])+'\\n')\n"
            f"os.execv({shutil.which('sed')!r}, ['sed', *sys.argv[1:]])\n"
        )
        sed.chmod(0o755)
        python.chmod(0o755)
        docker.chmod(0o755)
        environment = dict(
            os.environ,
            PATH=str(fake) + os.pathsep + os.environ["PATH"],
            ADM_LAB_SECRETS=str(secrets),
            REAL_PYTHON=sys.executable,
            TEST_ARGV=str(root / "argv.jsonl"),
            TEST_MODES=str(root / "modes.jsonl"),
            TEST_INSTALLED=str(root / "installed"),
        )
        environment.pop("ADM_LAB_PACKAGE", None)
        if archive:
            path = root / "exact-candidate.tar.gz"
            with tarfile.open(path, "w:gz") as package:
                for name, content in {
                    "default/app.conf": b"[install]\nbuild=1792340274\n[id]\nname=exact-candidate\n",
                    "appserver/static/example.js": b"// exact candidate static\n",
                }.items():
                    entry = tarfile.TarInfo("splunk_adm/" + name)
                    entry.size = len(content)
                    entry.mode = 0o644
                    package.addfile(entry, io.BytesIO(content))
            environment["ADM_LAB_PACKAGE"] = str(path)
        return here, environment

    def test_private_literal_rendering_and_install_modes_for_source_and_exact_archive(
        self,
    ):
        for archive in (False, True):
            with (
                self.subTest(archive=archive),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                here, environment = self.fixture(directory, archive=archive)
                result = subprocess.run(
                    ["bash", str(here / "lab.sh"), "install"],
                    env=environment,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                arguments = (root / "argv.jsonl").read_text()
                for value in (TOKEN, PASSWORD):
                    self.assertNotIn(value, arguments)
                    self.assertNotIn(value, result.stdout + result.stderr)
                self.assertNotIn('"sed"', arguments)
                credentials = root / "installed/adm_lab/default/inputs.conf"
                self.assertIn("token = " + TOKEN + "\n", credentials.read_text())
                self.assertNotIn("@HEC_TOKEN@", credentials.read_text())
                self.assertEqual(stat.S_IMODE(credentials.stat().st_mode), 0o600)
                self.assertEqual(
                    stat.S_IMODE(
                        (root / "installed/adm_lab/default/indexes.conf").stat().st_mode
                    ),
                    0o644,
                )
                static = root / "installed/splunk_adm/appserver/static/example.js"
                self.assertEqual(stat.S_IMODE(static.stat().st_mode), 0o644)
                self.assertEqual(
                    static.read_bytes(),
                    b"// exact candidate static\n"
                    if archive
                    else b"// static fixture\n",
                )
                modes = [
                    json.loads(line)
                    for line in (root / "modes.jsonl").read_text().splitlines()
                ]
                self.assertTrue(modes)
                self.assertTrue(all(row["stage_mode"] == 0o700 for row in modes))
                installed = root / "installed/splunk_adm/default/app.conf"
                self.assertIn(
                    "name=exact-candidate" if archive else "name=source-only",
                    installed.read_text(),
                )

    def test_unprotected_or_ambiguous_secrets_fail_before_install_without_values(self):
        for secret_mode, duplicate in ((0o644, False), (0o600, True)):
            with (
                self.subTest(mode=secret_mode, duplicate=duplicate),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                here, environment = self.fixture(
                    directory, secret_mode=secret_mode, duplicate=duplicate
                )
                result = subprocess.run(
                    ["bash", str(here / "lab.sh"), "install"],
                    env=environment,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(
                    "Unable to render private lab HEC configuration", result.stderr
                )
                self.assertFalse((root / "installed").exists())
                arguments = (root / "argv.jsonl").read_text()
                for value in (TOKEN, PASSWORD):
                    self.assertNotIn(value, arguments + result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
