import hashlib
import json
import unittest

from tests import test_release as base
from tools.check_release import (
    INCIDENT_BUNDLE_PATH,
    INCIDENT_CSS_PATH,
    INCIDENT_MANIFEST_PATH,
    MAX_INCIDENT_CSS_BYTES,
    MAX_INCIDENT_GZIP_BYTES,
    STATIC_ALLOWLIST,
    check_release,
)

ATLAS = "splunk_adm/appserver/static/pages/atlas.js"


class IncidentReleaseTests(unittest.TestCase):
    setUp = base.ReleaseArchiveTests.setUp
    tearDown = base.ReleaseArchiveTests.tearDown
    _write_archive = base.ReleaseArchiveTests._write_archive
    _files = base.ReleaseArchiveTests._files
    _write_pair = base.ReleaseArchiveTests._write_pair

    def _check(self):
        check_release(self.root / "dist", self.root / "package.json")

    def _incident_files(self):
        files = self._files()
        version = "7" * 24
        files[ATLAS] += b" __AtlasIncidentHost pages/incident.js " + version.encode()
        files[INCIDENT_BUNDLE_PATH] = b"incident bundle " + version.encode()
        files[INCIDENT_CSS_PATH] = b"incident styles"
        files[INCIDENT_MANIFEST_PATH] = json.dumps(
            {
                "schemaVersion": 1,
                "assetVersion": version,
                "javascriptSha256": hashlib.sha256(
                    files[INCIDENT_BUNDLE_PATH]
                ).hexdigest(),
                "cssSha256": hashlib.sha256(files[INCIDENT_CSS_PATH]).hexdigest(),
            }
        ).encode()
        return files

    def test_assets_are_allowlisted(self):
        for path in (
            INCIDENT_BUNDLE_PATH,
            INCIDENT_MANIFEST_PATH,
            INCIDENT_CSS_PATH,
        ):
            self.assertIn(path, STATIC_ALLOWLIST)

    def test_accepts_complete_incident_bundle(self):
        self._write_pair(self._incident_files())
        self._check()

    def test_archive_without_incident_is_unaffected(self):
        self._write_pair(self._files())
        self._check()

    def test_registration_and_partial_assets_require_complete_set(self):
        for missing in (
            INCIDENT_BUNDLE_PATH,
            INCIDENT_MANIFEST_PATH,
            INCIDENT_CSS_PATH,
        ):
            with self.subTest(missing=missing):
                files = self._incident_files()
                del files[missing]
                self._write_pair(files)
                with self.assertRaisesRegex(
                    ValueError, "missing required Incident files"
                ):
                    self._check()
        files = self._files()
        files[INCIDENT_CSS_PATH] = b"orphan"
        self._write_pair(files)
        with self.assertRaisesRegex(ValueError, "missing required Incident files"):
            self._check()

    def test_main_bundle_registration_alone_requires_assets(self):
        files = self._files()
        files[ATLAS] += b" __AtlasIncidentHost"
        self._write_pair(files)
        with self.assertRaisesRegex(ValueError, "missing required Incident files"):
            self._check()

    def test_rejects_tampering_and_mixed_versions(self):
        for path in (
            INCIDENT_BUNDLE_PATH,
            INCIDENT_CSS_PATH,
            INCIDENT_MANIFEST_PATH,
            ATLAS,
        ):
            with self.subTest(path=path):
                files = self._incident_files()
                if path == INCIDENT_MANIFEST_PATH:
                    files[path] = b"{}"
                elif path == ATLAS:
                    files[path] = files[path].replace(b"7" * 24, b"8" * 24)
                else:
                    files[path] += b"tampered"
                self._write_pair(files)
                with self.assertRaisesRegex(ValueError, "Incident asset version/hash"):
                    self._check()

    def test_bundle_has_independent_gzip_budget(self):
        files = self._incident_files()
        files[INCIDENT_BUNDLE_PATH] = base._incompressible(MAX_INCIDENT_GZIP_BYTES + 1)
        self._write_pair(files)
        with self.assertRaisesRegex(ValueError, "Incident optional bundle exceeds"):
            self._check()

    def test_css_has_budget(self):
        files = self._incident_files()
        files[INCIDENT_CSS_PATH] = b"x" * (MAX_INCIDENT_CSS_BYTES + 1)
        self._write_pair(files)
        with self.assertRaisesRegex(ValueError, "Incident optional CSS exceeds"):
            self._check()


if __name__ == "__main__":
    unittest.main()
