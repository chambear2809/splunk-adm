import hashlib
import json
import unittest

from tests import test_release as base
from tools.check_release import (
    MAX_SEGMENTATION_CSS_BYTES,
    MAX_SEGMENTATION_GZIP_BYTES,
    SEGMENTATION_BUNDLE_PATH,
    SEGMENTATION_CSS_PATH,
    SEGMENTATION_MANIFEST_PATH,
    STATIC_ALLOWLIST,
    check_release,
)

ATLAS = "splunk_adm/appserver/static/pages/atlas.js"


class SegmentationReleaseTests(unittest.TestCase):
    setUp = base.ReleaseArchiveTests.setUp
    tearDown = base.ReleaseArchiveTests.tearDown
    _write_archive = base.ReleaseArchiveTests._write_archive
    _files = base.ReleaseArchiveTests._files
    _write_pair = base.ReleaseArchiveTests._write_pair

    def _check(self):
        check_release(self.root / "dist", self.root / "package.json")

    def _segmentation_files(self):
        files = self._files()
        version = "5" * 24
        files[ATLAS] += (
            b" __AtlasSegmentationHost pages/segmentation.js " + version.encode()
        )
        files[SEGMENTATION_BUNDLE_PATH] = b"segmentation bundle " + version.encode()
        files[SEGMENTATION_CSS_PATH] = b"segmentation styles"
        files[SEGMENTATION_MANIFEST_PATH] = json.dumps(
            {
                "schemaVersion": 1,
                "assetVersion": version,
                "javascriptSha256": hashlib.sha256(
                    files[SEGMENTATION_BUNDLE_PATH]
                ).hexdigest(),
                "cssSha256": hashlib.sha256(files[SEGMENTATION_CSS_PATH]).hexdigest(),
            }
        ).encode()
        return files

    def test_assets_are_allowlisted(self):
        for path in (
            SEGMENTATION_BUNDLE_PATH,
            SEGMENTATION_MANIFEST_PATH,
            SEGMENTATION_CSS_PATH,
        ):
            self.assertIn(path, STATIC_ALLOWLIST)

    def test_accepts_complete_segmentation_bundle(self):
        self._write_pair(self._segmentation_files())
        self._check()

    def test_archive_without_segmentation_is_unaffected(self):
        self._write_pair(self._files())
        self._check()

    def test_registration_and_partial_assets_require_complete_set(self):
        for missing in (
            SEGMENTATION_BUNDLE_PATH,
            SEGMENTATION_MANIFEST_PATH,
            SEGMENTATION_CSS_PATH,
        ):
            with self.subTest(missing=missing):
                files = self._segmentation_files()
                del files[missing]
                self._write_pair(files)
                with self.assertRaisesRegex(
                    ValueError, "missing required Segmentation files"
                ):
                    self._check()
        files = self._files()
        files[SEGMENTATION_CSS_PATH] = b"orphan"
        self._write_pair(files)
        with self.assertRaisesRegex(ValueError, "missing required Segmentation files"):
            self._check()

    def test_rejects_tampering_and_mixed_versions(self):
        for path in (
            SEGMENTATION_BUNDLE_PATH,
            SEGMENTATION_CSS_PATH,
            SEGMENTATION_MANIFEST_PATH,
            ATLAS,
        ):
            with self.subTest(path=path):
                files = self._segmentation_files()
                if path == SEGMENTATION_MANIFEST_PATH:
                    files[path] = b"{}"
                elif path == ATLAS:
                    files[path] = files[path].replace(b"5" * 24, b"6" * 24)
                else:
                    files[path] += b"tampered"
                self._write_pair(files)
                with self.assertRaisesRegex(
                    ValueError, "Segmentation asset version/hash"
                ):
                    self._check()

    def test_bundle_has_independent_gzip_budget(self):
        files = self._segmentation_files()
        files[SEGMENTATION_BUNDLE_PATH] = base._incompressible(
            MAX_SEGMENTATION_GZIP_BYTES + 1
        )
        self._write_pair(files)
        with self.assertRaisesRegex(ValueError, "Segmentation optional bundle exceeds"):
            self._check()

    def test_css_has_budget(self):
        files = self._segmentation_files()
        files[SEGMENTATION_CSS_PATH] = b"x" * (MAX_SEGMENTATION_CSS_BYTES + 1)
        self._write_pair(files)
        with self.assertRaisesRegex(ValueError, "Segmentation optional CSS exceeds"):
            self._check()


if __name__ == "__main__":
    unittest.main()
