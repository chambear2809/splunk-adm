"""Regression tests for package source-tree safety preflight."""

from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).parents[1]
MODULE = ROOT / "tools/package-tree-safety.mjs"


class PackageTreeSafetyTest(unittest.TestCase):
    def invoke(self, operation, *paths):
        script = """
const tools = await import(process.argv[1]);
await tools[process.argv[2]](...process.argv.slice(3));
"""
        return subprocess.run(
            [
                "node",
                "--input-type=module",
                "-e",
                script,
                MODULE.as_uri(),
                operation,
                *map(str, paths),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )

    def run_check(self, root):
        return self.invoke("assertPackableTree", root)

    def test_regular_fixture_is_accepted_and_link_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "regular.txt").write_text("safe\n", encoding="utf-8")
            accepted = self.run_check(root)
            self.assertEqual(accepted.returncode, 0, accepted.stderr)

            (root / "outside.txt").write_text(
                "must not be followed\n", encoding="utf-8"
            )
            (root / "linked.txt").symlink_to(root / "outside.txt")
            rejected = self.run_check(root)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("Refusing linked or non-regular", rejected.stderr)

    def test_root_link_is_rejected_without_following_target(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "target"
            target.mkdir()
            (target / "regular.txt").write_text("safe\n", encoding="utf-8")
            linked_root = root / "linked-root"
            linked_root.symlink_to(target, target_is_directory=True)
            rejected = self.run_check(linked_root)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("Refusing linked or non-regular", rejected.stderr)

    def test_package_preflight_precedes_source_access_and_mutation(self):
        source = (ROOT / "tools/package-app.mjs").read_text(encoding="utf-8")
        self.assertLess(
            source.index("await assertPackableTree(app"), source.index("await access(")
        )
        self.assertNotIn("rm(`${app}/appserver/static/demo`", source)
        self.assertIn("Refusing linked or non-regular staged input", source)

    def test_separately_copied_input_must_be_regular(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            source = root / "document.md"
            source.write_text("test documentation\n", encoding="utf-8")
            output = root / "chosen.md"
            accepted = self.invoke("copyPackableFile", source, output)
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            self.assertEqual(output.read_text(), source.read_text())

            linked = root / "linked.md"
            linked.symlink_to(source)
            skipped = root / "skipped.md"
            rejected = self.invoke("copyPackableFile", linked, skipped)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("Refusing linked or non-regular", rejected.stderr)
            self.assertFalse(skipped.exists())


if __name__ == "__main__":
    unittest.main()
