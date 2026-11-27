import hashlib
import json
import unittest

from tests import test_release as base
from tools.check_release import (
    ADMIN_BUNDLE_PATH,
    ADMIN_CSS_PATH,
    ADMIN_MANIFEST_PATH,
    ENDPOINTS_BUNDLE_PATH,
    ENDPOINTS_CSS_PATH,
    ENDPOINTS_MANIFEST_PATH,
    MAX_ADMIN_CSS_BYTES,
    MAX_ADMIN_GZIP_BYTES,
    MAX_ENDPOINTS_CSS_BYTES,
    MAX_ENDPOINTS_GZIP_BYTES,
    MAX_O11Y_CSS_BYTES,
    MAX_O11Y_GZIP_BYTES,
    O11Y_BUNDLE_PATH,
    O11Y_CSS_PATH,
    O11Y_MANIFEST_PATH,
    STATIC_ALLOWLIST,
    check_release,
)

ATLAS = "splunk_adm/appserver/static/pages/atlas.js"

OPTIONAL_SPECS = (
    (
        "Admin",
        b"__AtlasAdminHost",
        b"pages/admin.js",
        ADMIN_BUNDLE_PATH,
        ADMIN_MANIFEST_PATH,
        ADMIN_CSS_PATH,
        MAX_ADMIN_GZIP_BYTES,
        MAX_ADMIN_CSS_BYTES,
        "2" * 24,
        "3" * 24,
    ),
    (
        "O11y",
        b"__AtlasO11yHost",
        b"pages/o11y.js",
        O11Y_BUNDLE_PATH,
        O11Y_MANIFEST_PATH,
        O11Y_CSS_PATH,
        MAX_O11Y_GZIP_BYTES,
        MAX_O11Y_CSS_BYTES,
        "4" * 24,
        "5" * 24,
    ),
    (
        "Endpoints",
        b"__AtlasEndpointsHost",
        b"pages/endpoints.js",
        ENDPOINTS_BUNDLE_PATH,
        ENDPOINTS_MANIFEST_PATH,
        ENDPOINTS_CSS_PATH,
        MAX_ENDPOINTS_GZIP_BYTES,
        MAX_ENDPOINTS_CSS_BYTES,
        "6" * 24,
        "7" * 24,
    ),
)


class OptionalPagesReleaseTests(unittest.TestCase):
    setUp = base.ReleaseArchiveTests.setUp
    tearDown = base.ReleaseArchiveTests.tearDown
    _write_archive = base.ReleaseArchiveTests._write_archive
    _files = base.ReleaseArchiveTests._files
    _write_pair = base.ReleaseArchiveTests._write_pair

    def _check(self):
        check_release(self.root / "dist", self.root / "package.json")

    def _asset_files(self, spec):
        (
            label,
            host_marker,
            js_marker,
            bundle_path,
            manifest_path,
            css_path,
            _max_gz,
            _max_css,
            version,
            _other_version,
        ) = spec
        files = self._files()
        files[ATLAS] += b" " + host_marker + b" " + js_marker + b" " + version.encode()
        files[bundle_path] = label.lower().encode() + b" bundle " + version.encode()
        files[css_path] = label.lower().encode() + b" styles"
        files[manifest_path] = json.dumps(
            {
                "schemaVersion": 1,
                "assetVersion": version,
                "javascriptSha256": hashlib.sha256(files[bundle_path]).hexdigest(),
                "cssSha256": hashlib.sha256(files[css_path]).hexdigest(),
            }
        ).encode()
        return files

    def test_assets_are_allowlisted(self):
        for spec in OPTIONAL_SPECS:
            for path in (spec[3], spec[4], spec[5]):
                self.assertIn(path, STATIC_ALLOWLIST)

    def test_accepts_complete_bundles(self):
        for spec in OPTIONAL_SPECS:
            with self.subTest(asset=spec[0]):
                self._write_pair(self._asset_files(spec))
                self._check()

    def test_archive_without_optional_pages_is_unaffected(self):
        self._write_pair(self._files())
        self._check()

    def test_registration_and_partial_assets_require_complete_set(self):
        for spec in OPTIONAL_SPECS:
            label, host_marker, _js, bundle, manifest, css = spec[:6]
            for missing in (bundle, manifest, css):
                with self.subTest(asset=label, missing=missing):
                    files = self._asset_files(spec)
                    del files[missing]
                    self._write_pair(files)
                    with self.assertRaisesRegex(
                        ValueError, f"missing required {label} files"
                    ):
                        self._check()
            with self.subTest(asset=label, case="orphan_css"):
                files = self._files()
                files[css] = b"orphan"
                self._write_pair(files)
                with self.assertRaisesRegex(
                    ValueError, f"missing required {label} files"
                ):
                    self._check()
            with self.subTest(asset=label, case="host_marker_only"):
                files = self._files()
                files[ATLAS] += b" " + host_marker
                self._write_pair(files)
                with self.assertRaisesRegex(
                    ValueError, f"missing required {label} files"
                ):
                    self._check()

    def test_rejects_tampering_and_mixed_versions(self):
        for spec in OPTIONAL_SPECS:
            label = spec[0]
            bundle, manifest, css = spec[3], spec[4], spec[5]
            version, other_version = spec[8], spec[9]
            for path in (bundle, css, manifest, ATLAS):
                with self.subTest(asset=label, path=path):
                    files = self._asset_files(spec)
                    if path == manifest:
                        files[path] = b"{}"
                    elif path == ATLAS:
                        files[path] = files[path].replace(
                            version.encode(), other_version.encode()
                        )
                    else:
                        files[path] += b"tampered"
                    self._write_pair(files)
                    with self.assertRaisesRegex(
                        ValueError, f"{label} asset version/hash"
                    ):
                        self._check()

    def test_bundles_have_independent_gzip_and_css_budgets(self):
        for spec in OPTIONAL_SPECS:
            label = spec[0]
            bundle, _manifest, css = spec[3], spec[4], spec[5]
            max_gz, max_css = spec[6], spec[7]
            with self.subTest(asset=label, budget="gzip"):
                files = self._asset_files(spec)
                files[bundle] = base._incompressible(max_gz + 1)
                self._write_pair(files)
                with self.assertRaisesRegex(
                    ValueError, f"{label} optional bundle exceeds"
                ):
                    self._check()
            with self.subTest(asset=label, budget="css"):
                files = self._asset_files(spec)
                files[css] = b"x" * (max_css + 1)
                self._write_pair(files)
                with self.assertRaisesRegex(
                    ValueError, f"{label} optional CSS exceeds"
                ):
                    self._check()


if __name__ == "__main__":
    unittest.main()
