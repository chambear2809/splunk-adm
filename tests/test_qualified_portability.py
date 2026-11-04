"""Verify the optional readers use only their relocated application runtime."""

from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


APP = Path(__file__).resolve().parents[1] / "splunk_app" / "splunk_adm"


class QualifiedRuntimePortabilityTests(unittest.TestCase):
    def test_relocated_readers_load_without_site_packages_and_stay_disabled(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            relocated = root / "application with spaces"
            for name in ("bin", "default"):
                shutil.copytree(
                    APP / name,
                    relocated / name,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
                )
            # -I excludes the checkout, PYTHONPATH and user site packages; -S
            # also excludes system site packages. Only the app's bundled SDK
            # and sibling libraries are available to these entry points.
            script = r"""
import importlib.util
from pathlib import Path
import sys

root = Path(sys.argv[1]).resolve()
for name, command, options in (
    ("admqualified", "AdmQualified", {"mode": "catalog"}),
    ("admacipoll", "AdmAciPoll", {"mode": "fabric"}),
):
    spec = importlib.util.spec_from_file_location(name, root / "bin" / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    reader = getattr(module, command)()
    for key, value in options.items():
        setattr(reader, key, value)
    try:
        list(reader.generate())
    except module.SearchError as error:
        assert "disabled" in str(error).lower(), str(error)
    else:
        raise AssertionError("shipped reader unexpectedly enabled")
for name, module in sys.modules.items():
    if name.startswith(("adm_identity_lib", "adm_aci_lib", "splunklib")):
        assert Path(module.__file__).resolve().is_relative_to(root), name
"""
            result = subprocess.run(
                [sys.executable, "-I", "-S", "-c", script, str(relocated)],
                cwd=root,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
