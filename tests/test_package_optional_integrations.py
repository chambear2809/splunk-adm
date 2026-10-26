"""Verify optional tools are separately distributed without linked/local content."""

import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
from tempfile import TemporaryDirectory
import unittest

from tools.package_optional_integrations import render_archive, selected_files


class OptionalIntegrationPackageTests(unittest.TestCase):
    def test_unpacked_toolkit_runs_without_the_repository(self):
        root = Path(__file__).resolve().parents[1]
        with TemporaryDirectory(prefix="atlas-toolkit-smoke-") as directory:
            with tarfile.open(
                fileobj=io.BytesIO(render_archive(selected_files(root))), mode="r:gz"
            ) as archive:
                archive.extractall(directory, filter="data")
            unpacked = Path(directory) / "application-atlas-integrations"
            for module in (
                "export_o11y_health",
                "capture_o11y_health",
                "export_o11y_detector_events",
                "hec_delivery",
                "export_thousandeyes_paths",
                "export_appdynamics",
                "import_appdynamics",
            ):
                with self.subTest(module=module):
                    result = subprocess.run(
                        [sys.executable, "-m", f"tools.{module}", "--help"],
                        cwd=unpacked,
                        text=True,
                        capture_output=True,
                        timeout=15,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn("usage:", result.stdout)
            result = subprocess.run(
                [sys.executable, "-m", "tools.validate_processor_contract"],
                cwd=unpacked,
                text=True,
                capture_output=True,
                timeout=15,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(json.loads(result.stdout)["processors_executed"])

    def test_archive_is_reproducible_and_preserves_artifact_bytes(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "tools").mkdir()
            (root / "tools/collector.py").write_bytes(b"print('example')\n")
            files = selected_files(root, ("tools",))
            first = render_archive(files)
            self.assertEqual(first, render_archive(files))
            with tarfile.open(fileobj=io.BytesIO(first), mode="r:gz") as archive:
                self.assertEqual(
                    archive.getnames(),
                    ["application-atlas-integrations/tools/collector.py"],
                )
                member = archive.getmembers()[0]
                self.assertEqual(member.mode, 0o644)
                self.assertEqual(
                    archive.extractfile(member).read(), b"print('example')\n"
                )

    def test_missing_artifact_and_traversal_fail_closed(self):
        with TemporaryDirectory() as directory:
            for paths in (("missing.py",), ("../outside",), ("/absolute",)):
                with self.subTest(paths=paths), self.assertRaises(ValueError):
                    selected_files(Path(directory), paths)

    def test_linked_or_local_artifacts_are_rejected(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "selected").mkdir()
            outside = root / "private.txt"
            outside.write_text("private test material")
            linked = root / "selected/linked.py"
            linked.symlink_to(outside)
            with self.assertRaisesRegex(ValueError, "Linked"):
                selected_files(root, ("selected",))
            linked.unlink()
            for name in (".env", "client.key", "secret.pem"):
                path = root / "selected" / name
                path.write_text("private test material")
                with (
                    self.subTest(name=name),
                    self.assertRaisesRegex(ValueError, "Unsafe"),
                ):
                    selected_files(root, ("selected",))
                path.unlink()


if __name__ == "__main__":
    unittest.main()
