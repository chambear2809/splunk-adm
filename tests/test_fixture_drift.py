"""Checked-in raw fixtures must equal the generator's current output."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "fixtures"
INPUTS = {"scenario.json", "edge-cases.json", "FIELDS.md"}


def files(directory: Path) -> dict[str, bytes]:
    return {
        path.relative_to(directory).as_posix(): path.read_bytes()
        for path in sorted(directory.rglob("*"))
        if path.is_file()
    }


class FixtureDriftTests(unittest.TestCase):
    def regenerate(self, scenario: str, *extra: str) -> dict[str, bytes]:
        with tempfile.TemporaryDirectory(prefix=f"adm-drift-{scenario}-") as tmp:
            subprocess.run(
                [
                    sys.executable,
                    "tools/gen_raw_fixtures.py",
                    "--scenario",
                    scenario,
                    "--output-dir",
                    tmp,
                    *extra,
                ],
                cwd=ROOT,
                check=True,
                capture_output=True,
                text=True,
            )
            return files(Path(tmp))

    def assert_matches(self, directory: str, generated: dict[str, bytes]) -> None:
        checked_in = {
            name: data
            for name, data in files(FIXTURES / directory).items()
            if name not in INPUTS
        }
        generated = {
            name: data for name, data in generated.items() if name not in INPUTS
        }
        self.assertEqual(sorted(checked_in), sorted(generated), directory)
        for name, data in generated.items():
            self.assertEqual(
                checked_in[name],
                data,
                f"fixtures/{directory}/{name} is stale; regenerate it with "
                "tools/gen_raw_fixtures.py",
            )

    def test_nxos_fixtures_match_generator(self) -> None:
        self.assert_matches("raw", self.regenerate("nxos"))

    def test_aci_fixtures_match_generator(self) -> None:
        self.assert_matches("raw-aci", self.regenerate("aci"))

    def test_networking_fixtures_match_generator_at_manifest_base_time(self) -> None:
        manifest = json.loads(
            (FIXTURES / "raw-networking" / "capture-manifest.json").read_text()
        )
        generated = self.regenerate("networking", "--base-time", manifest["base_time"])
        self.assert_matches("raw-networking", generated)


if __name__ == "__main__":
    unittest.main()
