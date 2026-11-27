import hashlib
import gzip
import io
import json
import tarfile
import unittest
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from tools.check_release import (
    BUNDLED_RUNTIME_FILES,
    BASELINE_RUNTIME_FILES,
    BASELINE_CONFIG_FILES,
    CASE_CONFIG_FILES,
    CASE_RUNTIME_FILES,
    QUALIFIED_CONFIG_FILES,
    QUALIFIED_RUNTIME_FILES,
    MAX_ATLAS_GZIP_BYTES,
    MAX_JOURNEYS_GZIP_BYTES,
    JOURNEYS_BUNDLE_PATH,
    JOURNEYS_MANIFEST_PATH,
    JOURNEYS_CSS_PATH,
    JOURNEYS_DOC_PATH,
    MAX_THOUSANDEYES_GZIP_BYTES,
    THOUSANDEYES_BUNDLE_PATH,
    THOUSANDEYES_MANIFEST_PATH,
    THOUSANDEYES_CSS_PATH,
    IMPACT_BUNDLE_PATH,
    IMPACT_MANIFEST_PATH,
    IMPACT_CSS_PATH,
    MAX_IMPACT_GZIP_BYTES,
    MULTICAST_BUNDLE_PATH,
    MULTICAST_MANIFEST_PATH,
    MULTICAST_CSS_PATH,
    MAX_MULTICAST_GZIP_BYTES,
    HISTORY_BUNDLE_PATH,
    HISTORY_MANIFEST_PATH,
    HISTORY_CSS_PATH,
    MAX_HISTORY_GZIP_BYTES,
    MIGRATION_BUNDLE_PATH,
    MIGRATION_MANIFEST_PATH,
    MIGRATION_CSS_PATH,
    MAX_MIGRATION_GZIP_BYTES,
    ECOSYSTEM_BUNDLE_PATH,
    ECOSYSTEM_MANIFEST_PATH,
    ECOSYSTEM_CSS_PATH,
    MAX_ECOSYSTEM_GZIP_BYTES,
    SETTINGS_CONFIG_FILES,
    SETTINGS_REGISTRY_PATH,
    SETTINGS_RUNTIME_FILES,
    COLLABORATION_RUNTIME_FILES,
    LOGGING_CONFIG_FILES,
    check_release,
)

VIEWER_ACCESS = b"read : [ adm_investigate, adm_viewer, admin, sc_admin ]"


def _incompressible(size: int) -> bytes:
    """Deterministic bytes that do not let gzip hide bundle size."""
    chunks: list[bytes] = []
    counter = 0
    while counter * 32 < size:
        chunks.append(sha256(f"atlas-{counter}".encode()).digest())
        counter += 1
    return b"".join(chunks)[:size]


class ReleaseArchiveTests(unittest.TestCase):
    def _history_files(self):
        files = self._files()
        version = "e" * 24
        files["splunk_adm/appserver/static/pages/atlas.js"] += (
            b" __AtlasHistoryHost pages/history.js " + version.encode()
        )
        files[HISTORY_BUNDLE_PATH] = b"history bundle " + version.encode()
        files[HISTORY_CSS_PATH] = b"history styles"
        files[HISTORY_MANIFEST_PATH] = json.dumps(
            {
                "schemaVersion": 1,
                "assetVersion": version,
                "javascriptSha256": hashlib.sha256(
                    files[HISTORY_BUNDLE_PATH]
                ).hexdigest(),
            }
        ).encode()
        return files

    def test_accepts_complete_history_bundle(self):
        self._write_pair(self._history_files())
        check_release(self.root / "dist", self.root / "package.json")

    def test_history_registration_and_partial_assets_require_complete_set(self):
        for missing in (HISTORY_BUNDLE_PATH, HISTORY_MANIFEST_PATH, HISTORY_CSS_PATH):
            with self.subTest(missing=missing):
                files = self._history_files()
                del files[missing]
                self._write_pair(files)
                with self.assertRaisesRegex(
                    ValueError, "missing required History files"
                ):
                    check_release(self.root / "dist", self.root / "package.json")
        files = self._files()
        files[HISTORY_CSS_PATH] = b"orphan"
        self._write_pair(files)
        with self.assertRaisesRegex(ValueError, "missing required History files"):
            check_release(self.root / "dist", self.root / "package.json")

    def test_rejects_history_tampering_and_mixed_versions(self):
        for path in (
            HISTORY_BUNDLE_PATH,
            HISTORY_MANIFEST_PATH,
            "splunk_adm/appserver/static/pages/atlas.js",
        ):
            with self.subTest(path=path):
                files = self._history_files()
                if path == HISTORY_MANIFEST_PATH:
                    files[path] = b"{}"
                elif path.endswith("atlas.js"):
                    files[path] = files[path].replace(b"e" * 24, b"f" * 24)
                else:
                    files[path] += b"tampered"
                self._write_pair(files)
                with self.assertRaisesRegex(ValueError, "History asset version/hash"):
                    check_release(self.root / "dist", self.root / "package.json")

    def test_history_bundle_has_independent_48k_gzip_budget(self):
        files = self._history_files()
        files[HISTORY_BUNDLE_PATH] = _incompressible(MAX_HISTORY_GZIP_BYTES + 1)
        self._write_pair(files)
        with self.assertRaisesRegex(ValueError, "History optional bundle exceeds"):
            check_release(self.root / "dist", self.root / "package.json")

    def _journey_files(self):
        files = self._files()
        version = "b" * 24
        files["splunk_adm/appserver/static/pages/atlas.js"] += (
            b" ApplicationAtlasJourneys " + version.encode()
        )
        files[JOURNEYS_BUNDLE_PATH] = b"journey bundle " + version.encode()
        files[JOURNEYS_CSS_PATH] = b"journey styles"
        files[JOURNEYS_DOC_PATH] = b"journey guide"
        files[JOURNEYS_MANIFEST_PATH] = json.dumps(
            {
                "schemaVersion": 1,
                "assetVersion": version,
                "javascriptSha256": hashlib.sha256(
                    files[JOURNEYS_BUNDLE_PATH]
                ).hexdigest(),
                "cssSha256": hashlib.sha256(files[JOURNEYS_CSS_PATH]).hexdigest(),
            }
        ).encode()
        return files

    def _impact_files(self):
        files = self._files()
        version = "c" * 24
        files["splunk_adm/appserver/static/pages/atlas.js"] += (
            b" __AtlasImpactHost pages/impact.js " + version.encode()
        )
        files[IMPACT_BUNDLE_PATH] = b"impact bundle " + version.encode()
        files[IMPACT_CSS_PATH] = b"impact styles"
        files[IMPACT_MANIFEST_PATH] = json.dumps(
            {
                "schemaVersion": 1,
                "assetVersion": version,
                "javascriptSha256": hashlib.sha256(
                    files[IMPACT_BUNDLE_PATH]
                ).hexdigest(),
                "cssSha256": hashlib.sha256(files[IMPACT_CSS_PATH]).hexdigest(),
            }
        ).encode()
        return files

    def _multicast_files(self):
        files = self._files()
        version = "d" * 24
        files["splunk_adm/appserver/static/pages/atlas.js"] += (
            b" __AtlasMulticastHost pages/multicast.js " + version.encode()
        )
        files[MULTICAST_BUNDLE_PATH] = b"multicast bundle " + version.encode()
        files[MULTICAST_CSS_PATH] = b"multicast styles"
        files[MULTICAST_MANIFEST_PATH] = json.dumps(
            {
                "schemaVersion": 1,
                "assetVersion": version,
                "javascriptSha256": hashlib.sha256(
                    files[MULTICAST_BUNDLE_PATH]
                ).hexdigest(),
                "cssSha256": hashlib.sha256(files[MULTICAST_CSS_PATH]).hexdigest(),
            }
        ).encode()
        return files

    def test_accepts_complete_journey_bundle(self):
        self._write_pair(self._journey_files())
        check_release(self.root / "dist", self.root / "package.json")

    def test_accepts_complete_impact_bundle(self):
        self._write_pair(self._impact_files())
        check_release(self.root / "dist", self.root / "package.json")

    def test_impact_registration_and_partial_assets_require_complete_set(self):
        for missing in (IMPACT_BUNDLE_PATH, IMPACT_MANIFEST_PATH, IMPACT_CSS_PATH):
            with self.subTest(missing=missing):
                files = self._impact_files()
                del files[missing]
                self._write_pair(files)
                with self.assertRaisesRegex(
                    ValueError, "missing required Impact files"
                ):
                    check_release(self.root / "dist", self.root / "package.json")
        files = self._files()
        files[IMPACT_CSS_PATH] = b"orphan"
        self._write_pair(files)
        with self.assertRaisesRegex(ValueError, "missing required Impact files"):
            check_release(self.root / "dist", self.root / "package.json")

    def test_rejects_impact_tampering_and_mixed_versions(self):
        for path in (
            IMPACT_BUNDLE_PATH,
            IMPACT_CSS_PATH,
            IMPACT_MANIFEST_PATH,
            "splunk_adm/appserver/static/pages/atlas.js",
        ):
            with self.subTest(path=path):
                files = self._impact_files()
                if path == IMPACT_MANIFEST_PATH:
                    files[path] = b"{}"
                elif path.endswith("atlas.js"):
                    files[path] = files[path].replace(b"c" * 24, b"d" * 24)
                else:
                    files[path] += b"tampered"
                self._write_pair(files)
                with self.assertRaisesRegex(ValueError, "Impact asset version/hash"):
                    check_release(self.root / "dist", self.root / "package.json")

    def test_impact_bundle_has_independent_64k_gzip_budget(self):
        files = self._impact_files()
        files[IMPACT_BUNDLE_PATH] = _incompressible(MAX_IMPACT_GZIP_BYTES + 1)
        self._write_pair(files)
        with self.assertRaisesRegex(ValueError, "Impact optional bundle exceeds"):
            check_release(self.root / "dist", self.root / "package.json")

    def test_accepts_complete_multicast_bundle(self):
        self._write_pair(self._multicast_files())
        check_release(self.root / "dist", self.root / "package.json")

    def test_multicast_registration_and_partial_assets_require_complete_set(self):
        for missing in (
            MULTICAST_BUNDLE_PATH,
            MULTICAST_MANIFEST_PATH,
            MULTICAST_CSS_PATH,
        ):
            with self.subTest(missing=missing):
                files = self._multicast_files()
                del files[missing]
                self._write_pair(files)
                with self.assertRaisesRegex(
                    ValueError, "missing required Multicast files"
                ):
                    check_release(self.root / "dist", self.root / "package.json")
        files = self._files()
        files[MULTICAST_CSS_PATH] = b"orphan"
        self._write_pair(files)
        with self.assertRaisesRegex(ValueError, "missing required Multicast files"):
            check_release(self.root / "dist", self.root / "package.json")

    def test_rejects_multicast_tampering_and_mixed_versions(self):
        for path in (
            MULTICAST_BUNDLE_PATH,
            MULTICAST_CSS_PATH,
            MULTICAST_MANIFEST_PATH,
            "splunk_adm/appserver/static/pages/atlas.js",
        ):
            with self.subTest(path=path):
                files = self._multicast_files()
                if path == MULTICAST_MANIFEST_PATH:
                    files[path] = b"{}"
                elif path.endswith("atlas.js"):
                    files[path] = files[path].replace(b"d" * 24, b"e" * 24)
                else:
                    files[path] += b"tampered"
                self._write_pair(files)
                with self.assertRaisesRegex(ValueError, "Multicast asset version/hash"):
                    check_release(self.root / "dist", self.root / "package.json")

    def test_multicast_bundle_has_independent_64k_gzip_budget(self):
        files = self._multicast_files()
        files[MULTICAST_BUNDLE_PATH] = _incompressible(MAX_MULTICAST_GZIP_BYTES + 1)
        self._write_pair(files)
        with self.assertRaisesRegex(ValueError, "Multicast optional bundle exceeds"):
            check_release(self.root / "dist", self.root / "package.json")

    def _migration_files(self):
        files = self._files()
        version = "1" * 24
        files["splunk_adm/appserver/static/pages/atlas.js"] += (
            b" __AtlasMigrationHost pages/migration.js " + version.encode()
        )
        files[MIGRATION_BUNDLE_PATH] = b"migration bundle " + version.encode()
        files[MIGRATION_CSS_PATH] = b"migration styles"
        files[MIGRATION_MANIFEST_PATH] = json.dumps(
            {
                "schemaVersion": 1,
                "assetVersion": version,
                "javascriptSha256": hashlib.sha256(
                    files[MIGRATION_BUNDLE_PATH]
                ).hexdigest(),
                "cssSha256": hashlib.sha256(files[MIGRATION_CSS_PATH]).hexdigest(),
            }
        ).encode()
        return files

    def _ecosystem_files(self):
        files = self._files()
        version = "9" * 24
        files["splunk_adm/appserver/static/pages/atlas.js"] += (
            b" __AtlasEcosystemHost pages/ecosystem.js " + version.encode()
        )
        files[ECOSYSTEM_BUNDLE_PATH] = b"ecosystem bundle " + version.encode()
        files[ECOSYSTEM_CSS_PATH] = b"ecosystem styles"
        files[ECOSYSTEM_MANIFEST_PATH] = json.dumps(
            {
                "schemaVersion": 1,
                "assetVersion": version,
                "javascriptSha256": hashlib.sha256(
                    files[ECOSYSTEM_BUNDLE_PATH]
                ).hexdigest(),
                "cssSha256": hashlib.sha256(files[ECOSYSTEM_CSS_PATH]).hexdigest(),
            }
        ).encode()
        return files

    def test_accepts_complete_migration_bundle(self):
        self._write_pair(self._migration_files())
        check_release(self.root / "dist", self.root / "package.json")

    def test_migration_registration_and_partial_assets_require_complete_set(self):
        for missing in (
            MIGRATION_BUNDLE_PATH,
            MIGRATION_MANIFEST_PATH,
            MIGRATION_CSS_PATH,
        ):
            with self.subTest(missing=missing):
                files = self._migration_files()
                del files[missing]
                self._write_pair(files)
                with self.assertRaisesRegex(
                    ValueError, "missing required Migration files"
                ):
                    check_release(self.root / "dist", self.root / "package.json")
        files = self._files()
        files[MIGRATION_CSS_PATH] = b"orphan"
        self._write_pair(files)
        with self.assertRaisesRegex(ValueError, "missing required Migration files"):
            check_release(self.root / "dist", self.root / "package.json")

    def test_rejects_migration_tampering_and_mixed_versions(self):
        for path in (
            MIGRATION_BUNDLE_PATH,
            MIGRATION_CSS_PATH,
            MIGRATION_MANIFEST_PATH,
            "splunk_adm/appserver/static/pages/atlas.js",
        ):
            with self.subTest(path=path):
                files = self._migration_files()
                if path == MIGRATION_MANIFEST_PATH:
                    files[path] = b"{}"
                elif path.endswith("atlas.js"):
                    files[path] = files[path].replace(b"1" * 24, b"2" * 24)
                else:
                    files[path] += b"tampered"
                self._write_pair(files)
                with self.assertRaisesRegex(ValueError, "Migration asset version/hash"):
                    check_release(self.root / "dist", self.root / "package.json")

    def test_migration_bundle_has_independent_48k_gzip_budget(self):
        files = self._migration_files()
        files[MIGRATION_BUNDLE_PATH] = _incompressible(MAX_MIGRATION_GZIP_BYTES + 1)
        self._write_pair(files)
        with self.assertRaisesRegex(ValueError, "Migration optional bundle exceeds"):
            check_release(self.root / "dist", self.root / "package.json")

    def test_accepts_complete_ecosystem_bundle(self):
        self._write_pair(self._ecosystem_files())
        check_release(self.root / "dist", self.root / "package.json")

    def test_ecosystem_registration_and_partial_assets_require_complete_set(self):
        for missing in (
            ECOSYSTEM_BUNDLE_PATH,
            ECOSYSTEM_MANIFEST_PATH,
            ECOSYSTEM_CSS_PATH,
        ):
            with self.subTest(missing=missing):
                files = self._ecosystem_files()
                del files[missing]
                self._write_pair(files)
                with self.assertRaisesRegex(
                    ValueError, "missing required Ecosystem files"
                ):
                    check_release(self.root / "dist", self.root / "package.json")
        files = self._files()
        files[ECOSYSTEM_CSS_PATH] = b"orphan"
        self._write_pair(files)
        with self.assertRaisesRegex(ValueError, "missing required Ecosystem files"):
            check_release(self.root / "dist", self.root / "package.json")

    def test_rejects_ecosystem_tampering_and_mixed_versions(self):
        for path in (
            ECOSYSTEM_BUNDLE_PATH,
            ECOSYSTEM_CSS_PATH,
            ECOSYSTEM_MANIFEST_PATH,
            "splunk_adm/appserver/static/pages/atlas.js",
        ):
            with self.subTest(path=path):
                files = self._ecosystem_files()
                if path == ECOSYSTEM_MANIFEST_PATH:
                    files[path] = b"{}"
                elif path.endswith("atlas.js"):
                    files[path] = files[path].replace(b"9" * 24, b"8" * 24)
                else:
                    files[path] += b"tampered"
                self._write_pair(files)
                with self.assertRaisesRegex(ValueError, "Ecosystem asset version/hash"):
                    check_release(self.root / "dist", self.root / "package.json")

    def test_ecosystem_bundle_has_independent_48k_gzip_budget(self):
        files = self._ecosystem_files()
        files[ECOSYSTEM_BUNDLE_PATH] = _incompressible(MAX_ECOSYSTEM_GZIP_BYTES + 1)
        self._write_pair(files)
        with self.assertRaisesRegex(ValueError, "Ecosystem optional bundle exceeds"):
            check_release(self.root / "dist", self.root / "package.json")

    def test_journey_registration_and_partial_assets_require_complete_set(self):
        for missing in (
            JOURNEYS_BUNDLE_PATH,
            JOURNEYS_MANIFEST_PATH,
            JOURNEYS_CSS_PATH,
            JOURNEYS_DOC_PATH,
        ):
            with self.subTest(missing=missing):
                files = self._journey_files()
                del files[missing]
                self._write_pair(files)
                with self.assertRaisesRegex(
                    ValueError, "missing required Journey files"
                ):
                    check_release(self.root / "dist", self.root / "package.json")
        files = self._files()
        files[JOURNEYS_CSS_PATH] = b"orphan"
        self._write_pair(files)
        with self.assertRaisesRegex(ValueError, "missing required Journey files"):
            check_release(self.root / "dist", self.root / "package.json")

    def test_rejects_journey_tampering_and_mixed_versions(self):
        for path in (
            JOURNEYS_BUNDLE_PATH,
            JOURNEYS_CSS_PATH,
            JOURNEYS_MANIFEST_PATH,
            "splunk_adm/appserver/static/pages/atlas.js",
        ):
            with self.subTest(path=path):
                files = self._journey_files()
                if path == JOURNEYS_MANIFEST_PATH:
                    files[path] = b"{}"
                elif path.endswith("atlas.js"):
                    files[path] = files[path].replace(b"b" * 24, b"c" * 24)
                else:
                    files[path] += b"tampered"
                self._write_pair(files)
                with self.assertRaisesRegex(ValueError, "Journey asset version/hash"):
                    check_release(self.root / "dist", self.root / "package.json")

    def test_journey_bundle_has_independent_budget(self):
        files = self._journey_files()
        files[JOURNEYS_BUNDLE_PATH] = _incompressible(MAX_JOURNEYS_GZIP_BYTES + 1)
        self._write_pair(files)
        with self.assertRaisesRegex(ValueError, "Journey optional bundle exceeds"):
            check_release(self.root / "dist", self.root / "package.json")

    def test_thousandeyes_optional_asset_has_an_independent_enforced_budget(self):
        files = self._files()
        files[THOUSANDEYES_BUNDLE_PATH] = _incompressible(
            MAX_THOUSANDEYES_GZIP_BYTES + 1
        )
        self._write_pair(files)
        with self.assertRaisesRegex(ValueError, "optional bundle exceeds"):
            check_release(self.root / "dist", self.root / "package.json")

    def test_mixed_thousandeyes_asset_versions_are_rejected(self):
        files = self._files()
        files[THOUSANDEYES_BUNDLE_PATH] += b"different candidate"
        self._write_pair(files)
        with self.assertRaisesRegex(ValueError, "version/hash"):
            check_release(self.root / "dist", self.root / "package.json")

    def test_missing_thousandeyes_stylesheet_is_rejected(self):
        files = self._files()
        del files[THOUSANDEYES_CSS_PATH]
        self._write_pair(files)
        with self.assertRaisesRegex(ValueError, "missing required files"):
            check_release(self.root / "dist", self.root / "package.json")

    def test_bundle_budget_is_independent_of_host_default_gzip_level(self):
        self._write_pair(self._files())
        compress = gzip.compress

        def changed_host_default(data, compresslevel=6, *, mtime=0):
            # Model a host with a different default without altering the cap.
            if compresslevel != 9:
                return b"x" * (MAX_ATLAS_GZIP_BYTES + 1)
            return compress(data, compresslevel=compresslevel, mtime=mtime)

        with patch(
            "tools.check_release.gzip.compress", side_effect=changed_host_default
        ):
            check_release(self.root / "dist", self.root / "package.json")

    def test_retention_tool_is_documented_as_repository_only(self):
        repo = Path(__file__).resolve().parents[1]
        doc = (repo / "docs/RETENTION_MAINTENANCE.md").read_text(encoding="utf-8")
        packager = (repo / "tools/package-app.mjs").read_text(encoding="utf-8")
        self.assertIn("not shipped in the\nSplunk app package", doc)
        self.assertNotIn("retention_maintenance", packager)
        self.assertNotIn(
            "tools/retention_maintenance.py", "".join(BUNDLED_RUNTIME_FILES)
        )

    def setUp(self):
        self.temp = TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "config").mkdir()
        (self.root / "config/deployment-health.json").write_bytes(
            b'{"schemaVersion":1,"sources":[{"id":"netflow","selectable":true}]}\n'
        )
        (self.root / "package.json").write_text(
            '{"version": "1.2.3"}\n', encoding="utf-8"
        )

    def tearDown(self):
        self.temp.cleanup()

    def _write_archive(self, name, files, extra_members=()):
        archive = self.root / "dist" / name
        archive.parent.mkdir(exist_ok=True)
        with tarfile.open(archive, "w:gz") as output:
            for path, data in files.items():
                info = tarfile.TarInfo(path)
                info.size = len(data)
                output.addfile(info, io.BytesIO(data))
            for info in extra_members:
                output.addfile(info)
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        archive.with_name(archive.name + ".sha256").write_text(
            f"{digest}  {archive.name}\n", encoding="utf-8"
        )

    def _files(self):
        config = (
            b"[install]\nbuild = 123\n[id]\nversion = 1.2.3\n"
            b"[launcher]\nversion = 1.2.3\n[package]\nid = splunk_adm\n"
            b"[triggers]\nreload.adm_recovery = simple\nreload.adm_settings = simple\n"
            b"reload.adm_dependency_watch = simple\n"
            b"reload.adm_investigations = simple\nreload.adm_baselines = simple\n"
            b"reload.adm_identity = simple\nreload.adm_aci_poll = simple\nreload.adm_aci_bindings = simple\n"
            b"reload.adm_logging = simple\n"
        )
        return {
            **{
                name: (
                    (Path(__file__).parents[1] / "splunk_app" / name).read_bytes()
                    if name
                    in QUALIFIED_RUNTIME_FILES
                    | CASE_RUNTIME_FILES
                    | BASELINE_RUNTIME_FILES
                    | COLLABORATION_RUNTIME_FILES
                    else b"#!/usr/bin/env python3\n"
                    if name.endswith("adm_recovery.py")
                    else b"runtime\n"
                )
                for name in BUNDLED_RUNTIME_FILES
            },
            **{
                name: (Path(__file__).parents[1] / "splunk_app" / name).read_bytes()
                for name in SETTINGS_RUNTIME_FILES
                | SETTINGS_CONFIG_FILES
                | CASE_CONFIG_FILES
                | BASELINE_CONFIG_FILES
                | LOGGING_CONFIG_FILES
            },
            SETTINGS_REGISTRY_PATH: (
                self.root / "config/deployment-health.json"
            ).read_bytes(),
            "splunk_adm/appserver/static/pages/atlas.js": b"toolkit bundle aaaaaaaaaaaaaaaaaaaaaaaa",
            THOUSANDEYES_BUNDLE_PATH: b"optional bundle aaaaaaaaaaaaaaaaaaaaaaaa",
            THOUSANDEYES_CSS_PATH: b"optional styles",
            THOUSANDEYES_MANIFEST_PATH: json.dumps(
                {
                    "schemaVersion": 1,
                    "assetVersion": "a" * 24,
                    "javascriptSha256": hashlib.sha256(
                        b"optional bundle aaaaaaaaaaaaaaaaaaaaaaaa"
                    ).hexdigest(),
                }
            ).encode(),
            **{
                f"splunk_adm/default/data/ui/views/{page}.xml": b"view"
                for page in (
                    "applications",
                    "map",
                    "endpoints",
                    "multicast",
                    "protocols",
                    "data_health",
                    "setup",
                    "help",
                    "device",
                    "impact",
                    "cases",
                    "migration",
                )
            },
            "splunk_adm/appserver/static/adm.css": b"css",
            "splunk_adm/default/app.conf": config,
            "splunk_adm/default/alert_actions.conf": (
                Path(__file__).parents[1]
                / "splunk_app/splunk_adm/default/alert_actions.conf"
            ).read_bytes(),
            "splunk_adm/LICENSE": b"license",
            "splunk_adm/NOTICE": b"notice",
            "splunk_adm/THIRD_PARTY_NOTICES.txt": b"third party",
            "splunk_adm/docs/DATA_LAYER.md": b"docs",
            "splunk_adm/docs/DEPENDENCY_BASELINES.md": b"baseline operator docs",
            "splunk_adm/docs/DEPENDENCY_WATCH_EXECUTION.md": b"disabled execution contract",
            "splunk_adm/docs/BASELINE_SOURCE_PROVIDER.md": b"unqualified provider and operator contract",
            "splunk_adm/docs/CASE_REQUEST_SUPERVISION.md": b"request supervision contract",
            "splunk_adm/docs/CASE_SOURCE_QUALIFICATION.md": b"installed source qualification scope",
            "splunk_adm/docs/INCIDENT_SOURCE_ASSOCIATIONS.md": b"historical audit association contract",
            "splunk_adm/docs/INVESTIGATION_RECORDS.md": b"case source authorization docs",
            "splunk_adm/docs/FEATURE_SOURCE_OBSERVATIONS.md": b"source observations",
            "splunk_adm/docs/FEATURE_FOUNDATIONS.md": b"evidence contracts",
            "splunk_adm/docs/DEPLOYMENT_HEALTH.md": b"settings operator docs",
            "splunk_adm/docs/LATE_CATALYST_RECEIPTS.md": b"late receipt operator docs",
            "splunk_adm/docs/RECOVERY.md": b"# Recovery and replay\n",
            "splunk_adm/docs/RETENTION_MAINTENANCE.md": b"# Retention\n",
            "splunk_adm/docs/UPGRADES.md": b"migration docs",
            "splunk_adm/docs/CISCO_CONTRACT_MIGRATION.md": b"contract migration docs",
            "splunk_adm/docs/CISCO_NETWORKING_QUALIFICATION.md": b"qualification docs",
            "splunk_adm/docs/operators/cisco-enterprise-networking.md": b"operator docs",
            "splunk_adm/docs/operators/qualified-native-network.md": b"operator docs",
            "splunk_adm/docs/DNS_EVIDENCE_QUALIFICATION.md": b"dns qualification docs",
            "splunk_adm/docs/DNS_EVIDENCE_SCENARIOS.md": b"dns scenario docs",
            "splunk_adm/docs/DNS_EVIDENCE_DESIGN.md": b"dns design docs",
            "splunk_adm/docs/VSPHERE_SWITCH_DESIGN.md": b"vsphere design docs",
            "splunk_adm/docs/DNS_INGESTION_RESEARCH.md": b"dns research docs",
            "splunk_adm/docs/operators/dns-evidence.md": b"dns operator docs",
            "splunk_adm/docs/operators/multicast.md": b"multicast operator docs",
            "splunk_adm/docs/multicast-source-qualification.md": b"multicast source findings",
            "splunk_adm/default/collections.conf": (
                Path(__file__).parents[1]
                / "splunk_app/splunk_adm/default/collections.conf"
            ).read_bytes(),
            "splunk_adm/default/adm_recovery.conf": (
                Path(__file__).parents[1]
                / "splunk_app/splunk_adm/default/adm_recovery.conf"
            ).read_bytes(),
            "splunk_adm/default/macros.conf": (
                Path(__file__).parents[1] / "splunk_app/splunk_adm/default/macros.conf"
            ).read_bytes(),
            **{
                name: (Path(__file__).parents[1] / "splunk_app" / name).read_bytes()
                for name in QUALIFIED_CONFIG_FILES
            },
            "splunk_adm/default/savedsearches.conf": (
                Path(__file__).parents[1]
                / "splunk_app/splunk_adm/default/savedsearches.conf"
            ).read_bytes(),
            "splunk_adm/default/transforms.conf": (
                b"[adm_observer_scope]\nexternal_type = kvstore\ncollection = adm_observer_scope\n"
            ),
            "splunk_adm/default/data/ui/nav/default.xml": b"<nav />\n",
            "splunk_adm/default/data/ui/views/dependency_map.xml": b"<view />\n",
            "splunk_adm/metadata/default.meta": (
                Path(__file__).parents[1]
                / "splunk_app/splunk_adm/metadata/default.meta"
            ).read_bytes(),
        }

    def _write_pair(self, install=None, upgrade=None):
        install = install or self._files()
        self._write_archive("splunk_adm-1.2.3.tar.gz", install)

    def test_accepts_valid_pair(self):
        self._write_pair()
        check_release(self.root / "dist", self.root / "package.json")

    def test_baseline_host_requires_case_runtime(self):
        install = self._files()
        for name in CASE_RUNTIME_FILES | CASE_CONFIG_FILES:
            del install[name]
        for name, marker in (
            ("splunk_adm/default/restmap.conf", b"\n[script:adm_investigations]"),
            ("splunk_adm/default/web.conf", b"\n[expose:adm_case_capabilities]"),
        ):
            install[name] = install[name].split(marker)[0] + b"\n"
        self._write_pair(install)
        with self.assertRaises(ValueError):
            check_release(self.root / "dist", self.root / "package.json")

    def test_investigate_capability_requires_admin_role_grants(self):
        grant_error = (
            "adm_investigate only to admin, sc_admin, and the adm_investigate role"
        )
        install = self._files()
        install["splunk_adm/default/authorize.conf"] = (
            b"[capability::adm_investigate]\n"
        )
        self._write_pair(install)
        with self.assertRaisesRegex(ValueError, grant_error):
            check_release(self.root / "dist", self.root / "package.json")
        install = self._files()
        install["splunk_adm/default/authorize.conf"] += (
            b"\n[role_user]\nadm_investigate = enabled\n"
        )
        self._write_pair(install)
        with self.assertRaisesRegex(ValueError, grant_error):
            check_release(self.root / "dist", self.root / "package.json")

    def test_viewer_role_grants_nothing_and_investigator_inherits_it(self):
        for old, new in (
            (
                b"[role_adm_viewer]\n",
                b"[role_adm_viewer]\nimportRoles = user\n",
            ),
            (
                b"[role_adm_viewer]\n",
                b"[role_adm_viewer]\nsrchIndexesAllowed = *\n",
            ),
            (b"importRoles = adm_viewer\n", b""),
            (b"importRoles = adm_viewer\n", b"importRoles = adm_viewer;power\n"),
        ):
            with self.subTest(change=new):
                install = self._files()
                name = "splunk_adm/default/authorize.conf"
                self.assertIn(old, install[name])
                install[name] = install[name].replace(old, new, 1)
                self._write_pair(install)
                with self.assertRaisesRegex(ValueError, "adm_viewer|adm_investigate"):
                    check_release(self.root / "dist", self.root / "package.json")

    def test_rejects_everyone_readable_or_exported_metadata(self):
        name = "splunk_adm/metadata/default.meta"
        for old, new in (
            (
                b"[]\naccess = " + VIEWER_ACCESS,
                b"[]\naccess = read : [ * ]",
            ),
            (
                b"[collections/adm_network_client_history]\naccess = " + VIEWER_ACCESS,
                b"[collections/adm_network_client_history]\naccess = read : [ * ]",
            ),
            (
                b"[transforms/adm_interfaces]\naccess = " + VIEWER_ACCESS,
                b"[transforms/adm_interfaces]\naccess = read : [ adm_viewer, user ]",
            ),
            (b"export = none", b"export = system"),
        ):
            with self.subTest(change=new):
                install = self._files()
                self.assertIn(old, install[name])
                install[name] = install[name].replace(old, new, 1)
                self._write_pair(install)
                with self.assertRaises(ValueError):
                    check_release(self.root / "dist", self.root / "package.json")

    def test_derived_lookups_require_explicit_metadata_acl(self):
        install = self._files()
        install["splunk_adm/default/transforms.conf"] += (
            b"\n[adm_unlisted]\nexternal_type = kvstore\ncollection = adm_unlisted\n"
        )
        self._write_pair(install)
        with self.assertRaisesRegex(ValueError, "transforms/adm_unlisted"):
            check_release(self.root / "dist", self.root / "package.json")

    def test_rejects_unsafe_case_release_contract(self):
        variants = (
            (
                "splunk_adm/default/adm_investigations.conf",
                b"mode = disabled",
                b"mode = single_search_head",
            ),
            (
                "splunk_adm/default/adm_investigations.conf",
                b"platform = unqualified",
                b"platform = enterprise",
            ),
            (
                "splunk_adm/default/adm_investigations.conf",
                b"capture_mode = disabled",
                b"capture_mode = reproducible_qualified_v1",
            ),
            (
                "splunk_adm/default/adm_investigations.conf",
                b"management_uri = unconfigured",
                b"management_uri = http://localhost:8089",
            ),
            (
                "splunk_adm/default/adm_investigations.conf",
                b"management_uri = unconfigured",
                b"management_uri = https://remote.example:8089",
            ),
            (
                "splunk_adm/default/adm_investigations.conf",
                b"management_uri = unconfigured",
                b"management_uri = https://localhost:8089",
            ),
            (
                "splunk_adm/default/adm_investigations.conf",
                b"ca_file = unconfigured",
                b"ca_file = /opt/splunk/etc/auth/cacert.pem",
            ),
            (
                "splunk_adm/default/adm_investigations.conf",
                b"ca_file = unconfigured",
                b"ca_file = unconfigured\nenabled = true",
            ),
            (
                "splunk_adm/default/adm_investigations.conf",
                b"[capture_transport]",
                b"[unexpected_transport]",
            ),
            (
                "splunk_adm/default/restmap.conf",
                b"capability = adm_investigate",
                b"capability = search",
            ),
            (
                "splunk_adm/default/restmap.conf",
                b"passHttpHeaders = true",
                b"passHttpHeaders = false",
            ),
            (
                "splunk_adm/default/restmap.conf",
                b"handler = adm_cases.CasesHandler",
                b"handler = other.Handler",
            ),
            (
                "splunk_adm/default/web.conf",
                b"adm/investigations/cases/*/entries",
                b"adm/investigations/**",
            ),
            (
                "splunk_adm/default/web.conf",
                b"pattern = adm/investigations/cases/*/share",
                b"skipCSRFProtection = true\npattern = adm/investigations/cases/*/share",
            ),
        )
        for name, before, after in variants:
            with self.subTest(name=name, after=after):
                install = self._files()
                self.assertIn(before, install[name])
                install[name] = install[name].replace(before, after)
                self._write_pair(install)
                with self.assertRaises(ValueError):
                    check_release(self.root / "dist", self.root / "package.json")
        for name, extra in (
            (
                "splunk_adm/default/web.conf",
                b"\n[expose:extra]\npattern = adm/**\nmethods = GET\n",
            ),
            (
                "splunk_adm/default/restmap.conf",
                b"\n[script:extra]\nmatch = /adm/investigations/*\n",
            ),
            (
                "splunk_adm/default/authorize.conf",
                b"\n[role_user]\nadm_investigate = enabled\n",
            ),
        ):
            with self.subTest(name=name):
                install = self._files()
                install[name] += extra
                self._write_pair(install)
                with self.assertRaises(ValueError):
                    check_release(self.root / "dist", self.root / "package.json")
        for name in CASE_RUNTIME_FILES | CASE_CONFIG_FILES:
            with self.subTest(missing=name):
                install = self._files()
                del install[name]
                self._write_pair(install)
                with self.assertRaisesRegex(
                    ValueError, "case registration missing required files"
                ):
                    check_release(self.root / "dist", self.root / "package.json")

    def test_dependency_watch_defaults_acl_session_and_schedule_guards(self):
        changes = (
            (
                "splunk_adm/default/adm_dependency_watch.conf",
                b"enabled = false",
                b"enabled = true",
                "must ship disabled",
            ),
            (
                "splunk_adm/default/alert_actions.conf",
                b"[adm_dependency_watch]\n",
                b"[adm_dependency_watch]\npassSystemAuth = true\n",
                "alert_actions.conf",
            ),
            (
                "splunk_adm/metadata/default.meta",
                b"[alert_actions/adm_dependency_watch]\naccess = read : [ admin, sc_admin ]",
                b"[alert_actions/adm_dependency_watch]\naccess = read : [ * ]",
                "administrator-only",
            ),
            (
                "splunk_adm/metadata/default.meta",
                b"[savedsearches]\naccess = read : [ admin, sc_admin ]",
                b"[savedsearches]\naccess = read : [ * ]",
                "administrator-only",
            ),
            (
                "splunk_adm/default/savedsearches.conf",
                b"[ADM - Telemetry blindness]\n",
                b"[ADM - Telemetry blindness]\nactions = email, adm_dependency_watch \n",
                "schedules must not ship",
            ),
            (
                "splunk_adm/default/savedsearches.conf",
                b"[ADM - Telemetry blindness]\n",
                b"[ADM - Telemetry blindness]\naction.adm_dependency_watch = 1\n",
                "schedules must not ship",
            ),
        )
        for name, old, new, message in changes:
            with self.subTest(path=name, change=new):
                files = self._files()
                self.assertIn(old, files[name])
                files[name] = files[name].replace(old, new)
                self._write_pair(files)
                with self.assertRaisesRegex(ValueError, message):
                    check_release(self.root / "dist", self.root / "package.json")

    def test_rejects_unsafe_baseline_release_contract(self):
        variants = (
            (
                "splunk_adm/default/adm_baselines.conf",
                b"mode = disabled",
                b"mode = single_search_head",
            ),
            (
                "splunk_adm/default/adm_baselines.conf",
                b"platform = unqualified",
                b"platform = enterprise",
            ),
            (
                "splunk_adm/default/adm_baselines.conf",
                b"source_mode = unavailable",
                b"source_mode = qualified",
            ),
            (
                "splunk_adm/default/restmap.conf",
                b"handler = adm_baselines.BaselinesHandler",
                b"handler = other.Handler",
            ),
            (
                "splunk_adm/default/restmap.conf",
                b"match = /adm/dependency-monitoring",
                b"match = /adm/elsewhere",
            ),
            (
                "splunk_adm/default/web.conf",
                b"pattern = adm/dependency-monitoring/baselines/*/watches/*/evaluate",
                b"pattern = adm/dependency-monitoring/**",
            ),
            (
                "splunk_adm/default/web.conf",
                b"pattern = adm/dependency-monitoring/capture",
                b"skipCSRFProtection = true\npattern = adm/dependency-monitoring/capture",
            ),
        )
        for name, before, after in variants:
            with self.subTest(name=name, after=after):
                files = self._files()
                self.assertIn(before, files[name])
                files[name] = files[name].replace(before, after)
                self._write_pair(files)
                with self.assertRaises(ValueError):
                    check_release(self.root / "dist", self.root / "package.json")
        for before, after in (
            (b"capability = adm_investigate", b"capability = search"),
            (b"requireAuthentication = true", b"requireAuthentication = false"),
            (b"passSession = true", b"passSession = false"),
            (b"passSystemAuth = false", b"passSystemAuth = true"),
            (b"passHttpHeaders = true", b"passHttpHeaders = false"),
        ):
            with self.subTest(registration=before):
                files = self._files()
                path = "splunk_adm/default/restmap.conf"
                prefix, stanza = files[path].split(
                    b"[script:adm_dependency_monitoring]", 1
                )
                self.assertIn(before, stanza)
                files[path] = (
                    prefix
                    + b"[script:adm_dependency_monitoring]"
                    + stanza.replace(before, after)
                )
                self._write_pair(files)
                with self.assertRaises(ValueError):
                    check_release(self.root / "dist", self.root / "package.json")
        for name in BASELINE_RUNTIME_FILES | BASELINE_CONFIG_FILES:
            with self.subTest(missing=name):
                files = self._files()
                del files[name]
                self._write_pair(files)
                with self.assertRaises(ValueError):
                    check_release(self.root / "dist", self.root / "package.json")
        files = self._files()
        files["splunk_adm/default/web.conf"] += (
            b"\n[expose:purge]\npattern = adm/dependency-monitoring/baselines/purge\nmethods = POST\n"
        )
        self._write_pair(files)
        with self.assertRaises(ValueError):
            check_release(self.root / "dist", self.root / "package.json")

    def test_runtime_inventory_matches_source_files(self):
        source_root = Path(__file__).parents[1] / "splunk_app/splunk_adm/bin"
        source_files = {
            "splunk_adm/" + path.relative_to(source_root.parent).as_posix()
            for path in source_root.rglob("*")
            if path.is_file()
            and "__pycache__" not in path.parts
            and path.suffix not in {".pyc", ".pyo"}
        }
        self.assertEqual(BUNDLED_RUNTIME_FILES, source_files)

    def test_rejects_atlas_bundle_over_gzip_limit(self):
        install = self._files()
        install["splunk_adm/appserver/static/pages/atlas.js"] = _incompressible(
            MAX_ATLAS_GZIP_BYTES + 4096
        )
        self._write_pair(install)
        with self.assertRaisesRegex(ValueError, r"atlas\.js gzip bundle.*maximum"):
            check_release(self.root / "dist", self.root / "package.json")

    def test_accepts_atlas_bundle_just_under_gzip_limit(self):
        install = self._files()
        install["splunk_adm/appserver/static/pages/atlas.js"] = (
            _incompressible(MAX_ATLAS_GZIP_BYTES - 4096) + b"aaaaaaaaaaaaaaaaaaaaaaaa"
        )
        self._write_pair(install)
        check_release(self.root / "dist", self.root / "package.json")

    def test_rejects_demo_fixtures_in_archive(self):
        for path in (
            "splunk_adm/appserver/static/demo/demo-rows-aci.json",
            "splunk_adm/appserver/static/demo/README.txt",
            "splunk_adm/appserver/static/fixtures/demo-find.json",
        ):
            with self.subTest(path=path):
                install = self._files()
                install[path] = b"{}"
                self._write_pair(install)
                with self.assertRaisesRegex(ValueError, "demo fixture"):
                    check_release(self.root / "dist", self.root / "package.json")

    def test_rejects_fixture_shaped_files_anywhere(self):
        for path in (
            "splunk_adm/appserver/static/path-trace-aci.json",
            "splunk_adm/appserver/static/raw-aci/scenario.json",
            "splunk_adm/docs/fixtures/demo-rows.json",
            "splunk_adm/bin/raw-aci/events.ndjson",
            "splunk_adm/lookups/scenario.json",
            "splunk_adm/default/data/events.ndjson",
            "splunk_adm/docs/path-trace-live.json",
        ):
            with self.subTest(path=path):
                install = self._files()
                install[path] = b"{}"
                self._write_pair(install)
                with self.assertRaisesRegex(ValueError, "demo fixture"):
                    check_release(self.root / "dist", self.root / "package.json")

    def test_static_files_are_allowlisted(self):
        for path in (
            "splunk_adm/appserver/static/captured.json",
            "splunk_adm/appserver/static/pages/atlas.js.map",
            "splunk_adm/appserver/static/data/rows.csv",
        ):
            with self.subTest(path=path):
                install = self._files()
                install[path] = b"{}"
                self._write_pair(install)
                with self.assertRaisesRegex(ValueError, "unlisted static file"):
                    check_release(self.root / "dist", self.root / "package.json")

    def test_rejects_demo_code_in_bundles(self):
        for path in (
            "splunk_adm/appserver/static/pages/atlas.js",
            "splunk_adm/appserver/static/pages/extra.js",
        ):
            for marker in (
                b"app/splunk_adm/demo/",
                b"Demo data is not prepared",
                b"ACI pilot fabric",
            ):
                with self.subTest(path=path, marker=marker):
                    install = self._files()
                    install[path] = (
                        install.get(path, b"bundle aaaaaaaaaaaaaaaaaaaaaaaa")
                        + b"label:`"
                        + marker
                        + b"`"
                    )
                    self._write_pair(install)
                    with self.assertRaisesRegex(ValueError, "demo code"):
                        check_release(self.root / "dist", self.root / "package.json")

    def test_rejects_development_records_in_archive(self):
        for name in (
            "research/cisco-pipeline-interface.json",
            "research/package-manifest.json",
            "docs/benchmarks/cisco-networking-local-load.json",
        ):
            with self.subTest(name=name):
                install = self._files()
                install[f"splunk_adm/{name}"] = b"{}"
                self._write_pair(install)
                with self.assertRaisesRegex(ValueError, "development record"):
                    check_release(self.root / "dist", self.root / "package.json")

    def test_rejects_missing_critical_config(self):
        install = self._files()
        del install["splunk_adm/default/macros.conf"]
        self._write_pair(install)
        with self.assertRaisesRegex(ValueError, "missing required files"):
            check_release(self.root / "dist", self.root / "package.json")

    def test_rejects_missing_optional_evidence_views_or_docs(self):
        for name in (
            "splunk_adm/default/data/ui/views/endpoints.xml",
            "splunk_adm/default/data/ui/views/multicast.xml",
            "splunk_adm/docs/operators/multicast.md",
            "splunk_adm/docs/multicast-source-qualification.md",
            "splunk_adm/docs/DNS_EVIDENCE_QUALIFICATION.md",
            "splunk_adm/docs/DNS_EVIDENCE_SCENARIOS.md",
            "splunk_adm/docs/DNS_EVIDENCE_DESIGN.md",
            "splunk_adm/docs/DNS_INGESTION_RESEARCH.md",
            "splunk_adm/docs/operators/dns-evidence.md",
        ):
            with self.subTest(name=name):
                install = self._files()
                del install[name]
                self._write_pair(install)
                with self.assertRaisesRegex(
                    ValueError, f"missing required files.*{Path(name).name}"
                ):
                    check_release(self.root / "dist", self.root / "package.json")

    def test_rejects_missing_recovery_runtime_dependency(self):
        install = self._files()
        del install["splunk_adm/bin/adm_recovery_lib/core.py"]
        self._write_pair(install)
        with self.assertRaisesRegex(ValueError, "missing required files.*core.py"):
            check_release(self.root / "dist", self.root / "package.json")

    def test_rejects_missing_qualified_runtime_configuration_or_spec(self):
        for name in QUALIFIED_RUNTIME_FILES | QUALIFIED_CONFIG_FILES:
            with self.subTest(name=name):
                install = self._files()
                del install[name]
                self._write_pair(install)
                with self.assertRaisesRegex(ValueError, "missing required files"):
                    check_release(self.root / "dist", self.root / "package.json")

    def test_rejects_enabled_or_nonportable_qualified_defaults(self):
        for name, before, after in (
            (
                "splunk_adm/default/adm_identity.conf",
                b"enabled = false",
                b"enabled = true",
            ),
            (
                "splunk_adm/default/adm_identity.conf",
                b"cluster = placeholder",
                b"cluster = lab",
            ),
            (
                "splunk_adm/default/adm_identity.conf",
                b"[network]\nenabled = false",
                b"[network]\nenabled = true",
            ),
            (
                "splunk_adm/default/adm_aci_poll.conf",
                b"enabled = false",
                b"enabled = true",
            ),
            (
                "splunk_adm/default/adm_aci_bindings.conf",
                b"enabled = false",
                b"enabled = true",
            ),
        ):
            with self.subTest(name=name, after=after):
                install = self._files()
                self.assertIn(before, install[name])
                install[name] = install[name].replace(before, after, 1)
                self._write_pair(install)
                with self.assertRaises(ValueError):
                    check_release(self.root / "dist", self.root / "package.json")

    def test_rejects_unreviewed_qualified_command_registration(self):
        name = "splunk_adm/default/commands.conf"
        for before, after in (
            (b"filename = admqualified.py", b"filename = missing.py"),
            (b"python.version = python3", b"python.version = python2"),
            (b"python.required = 3.13", b"python.required = 3.12"),
            (b"local = true", b"local = false"),
        ):
            with self.subTest(after=after):
                install = self._files()
                self.assertIn(before, install[name])
                install[name] = install[name].replace(before, after, 1)
                self._write_pair(install)
                with self.assertRaisesRegex(
                    ValueError, "qualified command registration"
                ):
                    check_release(self.root / "dist", self.root / "package.json")

    def test_rejects_qualified_config_acl_mutation(self):
        install = self._files()
        name = "splunk_adm/metadata/default.meta"
        install[name] = install[name].replace(
            b"write : [ admin, sc_admin ]", b"write : [ * ]", 1
        )
        self._write_pair(install)
        with self.assertRaisesRegex(ValueError, "ACL"):
            check_release(self.root / "dist", self.root / "package.json")

    def test_rejects_noninert_aci_profile_keys_independently(self):
        for name, suffix in (
            ("splunk_adm/default/adm_aci_poll.conf", b"\napic_host = lab\n"),
            ("splunk_adm/default/adm_aci_bindings.conf", b"\njson = []\n"),
        ):
            with self.subTest(name=name):
                install = self._files()
                install[name] += suffix
                self._write_pair(install)
                with self.assertRaises(ValueError):
                    check_release(self.root / "dist", self.root / "package.json")

    def test_rejects_missing_or_repointed_qualified_macro_wrapper(self):
        for before, after in (
            (
                b"definition = inputlookup adm_app_catalog",
                b"definition = admqualified mode=catalog",
            ),
            (
                b'definition = search `adm_graph("$service$", "$environment$", "$cluster$", "$namespace$")`',
                b"definition = search other",
            ),
        ):
            with self.subTest(after=after):
                install = self._files()
                self.assertIn(before, install["splunk_adm/default/macros.conf"])
                install["splunk_adm/default/macros.conf"] = install[
                    "splunk_adm/default/macros.conf"
                ].replace(before, after, 1)
                self._write_pair(install)
                with self.assertRaisesRegex(ValueError, "wrapper"):
                    check_release(self.root / "dist", self.root / "package.json")

    def test_rejects_recovery_registration_to_unshipped_entrypoint(self):
        install = self._files()
        install["splunk_adm/default/alert_actions.conf"] = (
            b"[adm_recovery]\nalert.execute.cmd = missing_recovery.py\n"
        )
        self._write_pair(install)
        with self.assertRaisesRegex(
            ValueError, "registration.*shipped adm_recovery.py"
        ):
            check_release(self.root / "dist", self.root / "package.json")

    def test_rejects_recovery_action_without_exact_python_313_settings(self):
        name = "splunk_adm/default/alert_actions.conf"
        recovery = b"alert.execute.cmd = adm_recovery.py"
        for before, after in (
            (b"python.required = 3.13\n", b"python.required = 3.9,3.13\n"),
            (b"python.required = 3.13\n", b"python.required = 3.9\n"),
            (b"python.required = 3.13\n", b""),
            (b"python.version = python3\n", b""),
        ):
            with self.subTest(after=after):
                install = self._files()
                head, tail = install[name].split(recovery, 1)
                self.assertIn(before, head.split(b"[adm_recovery]", 1)[1])
                install[name] = head.replace(before, after, 1) + recovery + tail
                self._write_pair(install)
                with self.assertRaisesRegex(ValueError, "adm_recovery.*Python 3.13"):
                    check_release(self.root / "dist", self.root / "package.json")

    def test_rejects_missing_settings_runtime_configuration_or_operator_docs(self):
        for name in (
            SETTINGS_RUNTIME_FILES
            | SETTINGS_CONFIG_FILES
            | {
                SETTINGS_REGISTRY_PATH,
                "splunk_adm/docs/DEPLOYMENT_HEALTH.md",
                "splunk_adm/docs/LATE_CATALYST_RECEIPTS.md",
                "splunk_adm/docs/RETENTION_MAINTENANCE.md",
            }
        ):
            with self.subTest(name=name):
                install = self._files()
                del install[name]
                self._write_pair(install)
                with self.assertRaisesRegex(ValueError, "missing required files"):
                    check_release(self.root / "dist", self.root / "package.json")

    def test_rejects_unsafe_settings_authentication_or_system_elevation(self):
        name = "splunk_adm/default/restmap.conf"
        for before, after in (
            (b"requireAuthentication = true", b"requireAuthentication = false"),
            (b"capability.post = admin_all_objects", b"capability.post = search"),
            (b"passSession = true", b"passSession = false"),
            (b"passSystemAuth = false", b"passSystemAuth = true"),
            (
                b"handler = adm_settings.SettingsHandler",
                b"handler = unshipped.UnsafeHandler",
            ),
            (b"script = adm_settings.py", b"script = other.py"),
            (b"python.required = 3.13", b"python.required = 3.9"),
        ):
            with self.subTest(after=after):
                install = self._files()
                self.assertIn(before, install[name])
                install[name] = install[name].replace(before, after)
                self._write_pair(install)
                with self.assertRaisesRegex(ValueError, "settings registration"):
                    check_release(self.root / "dist", self.root / "package.json")

    def test_requires_explicit_current_and_legacy_compatible_python_selectors(self):
        for before, after in (
            (b"python.required = 3.13\n", b""),
            (b"python.version = python3\n", b""),
            (b"python.version = python3\n", b"python.version = python2\n"),
            (b"python.required = 3.13\n", b"python.required = 3.9\n"),
        ):
            with self.subTest(before=before, after=after):
                install = self._files()
                name = "splunk_adm/default/restmap.conf"
                install[name] = install[name].replace(before, after)
                self._write_pair(install)
                with self.assertRaisesRegex(ValueError, "settings registration"):
                    check_release(self.root / "dist", self.root / "package.json")

    def test_rejects_settings_csrf_bypass_or_unsupported_browser_methods(self):
        name = "splunk_adm/default/web.conf"
        for before, after in (
            (None, b"skipCSRFProtection = 1\n"),
            (None, b"skipCSRFProtection = 0\n"),
            (b"methods = GET,POST", b"methods = GET,POST,DELETE"),
            (b"pattern = adm/deployment-settings", b"pattern = adm/**"),
        ):
            with self.subTest(after=after):
                install = self._files()
                install[name] = (
                    install[name].replace(before, after, 1)
                    if before
                    else install[name].replace(
                        b"methods = GET,POST", b"methods = GET,POST\n" + after, 1
                    )
                )
                self._write_pair(install)
                with self.assertRaisesRegex(ValueError, "settings browser exposure"):
                    check_release(self.root / "dist", self.root / "package.json")

    def test_rejects_broadened_or_csrf_bypassed_metadata_browser_exposure(self):
        name = "splunk_adm/default/web.conf"
        for before, after in (
            (b"macros/stanzas:get", b"macros/**"),
            (b"methods = POST\n", b"methods = GET,POST,DELETE\n"),
            (b"methods = POST\n", b"methods = POST\nskipCSRFProtection = 1\n"),
            (b"methods = POST\n", b"methods = POST\nallowRemoteProxy = true\n"),
        ):
            with self.subTest(after=after):
                install = self._files()
                install[name] = install[name].replace(before, after, 1)
                self._write_pair(install)
                with self.assertRaisesRegex(ValueError, "metadata browser exposure"):
                    check_release(self.root / "dist", self.root / "package.json")

    def test_rejects_settings_enabled_or_qualified_installation_defaults(self):
        name = "splunk_adm/default/adm_settings.conf"
        for before, after in (
            (b"write_mode = disabled", b"write_mode = single_namespace"),
            (b"platform = unqualified", b"platform = enterprise"),
        ):
            with self.subTest(after=after):
                install = self._files()
                install[name] = install[name].replace(before, after)
                self._write_pair(install)
                with self.assertRaisesRegex(
                    ValueError, "settings defaults.*disabled and unqualified"
                ):
                    check_release(self.root / "dist", self.root / "package.json")

    def test_rejects_settings_reader_restriction_and_widened_writer_acl(self):
        for name, suffix in (
            (
                "splunk_adm/default/restmap.conf",
                b"capability.get = admin_all_objects\n",
            ),
            ("splunk_adm/metadata/default.meta", b""),
        ):
            with self.subTest(name=name):
                install = self._files()
                if suffix:
                    install[name] = install[name].replace(
                        b"\n[script:adm_investigations]",
                        b"\n" + suffix + b"\n[script:adm_investigations]",
                        1,
                    )
                if not suffix:
                    install[name] = install[name].replace(
                        b"[collections/adm_deployment_settings]\naccess = "
                        + VIEWER_ACCESS
                        + b", write : [ admin, sc_admin ]",
                        b"[collections/adm_deployment_settings]\naccess = "
                        + VIEWER_ACCESS
                        + b", write : [ * ]",
                        1,
                    )
                self._write_pair(install)
                with self.assertRaisesRegex(ValueError, "reader access|settings ACL"):
                    check_release(self.root / "dist", self.root / "package.json")

    def test_rejects_settings_registry_drift_and_invalid_runtime(self):
        for name, value, error in (
            (
                SETTINGS_REGISTRY_PATH,
                b'{"schemaVersion":1,"sources":[{"id":"other","selectable":true}]}',
                "registry.*match",
            ),
            (SETTINGS_REGISTRY_PATH, b"invalid json", "invalid.*registry"),
            (
                "splunk_adm/bin/adm_settings.py",
                b"class WrongHandler: pass\n",
                "entrypoint.*SettingsHandler",
            ),
            (
                "splunk_adm/bin/adm_settings_lib/rest.py",
                b"def invalid(:\n",
                "invalid.*Python runtime",
            ),
        ):
            with self.subTest(name=name, value=value):
                install = self._files()
                install[name] = value
                self._write_pair(install)
                with self.assertRaisesRegex(ValueError, error):
                    check_release(self.root / "dist", self.root / "package.json")

    def test_rejects_ambiguous_settings_endpoint_or_default_inheritance(self):
        name = "splunk_adm/default/restmap.conf"
        for suffix, error in (
            (
                b"\n[script:duplicate]\nmatch = /adm/deployment-settings\n",
                "unambiguous registration",
            ),
            (b"\n[DEFAULT]\npassSystemAuth = false\n", "DEFAULT"),
            (b"\nrestReplay = true\n", "REST replay"),
        ):
            with self.subTest(suffix=suffix):
                install = self._files()
                if suffix == b"\nrestReplay = true\n":
                    install[name] = install[name].replace(
                        b"\n[script:adm_investigations]",
                        suffix + b"\n[script:adm_investigations]",
                        1,
                    )
                else:
                    install[name] += suffix
                self._write_pair(install)
                with self.assertRaisesRegex(ValueError, error):
                    check_release(self.root / "dist", self.root / "package.json")

    def test_rejects_packaged_limits_conf(self):
        install = self._files()
        install["splunk_adm/default/limits.conf"] = (
            b"[outputlookup]\noutputlookup_check_permission = true\n"
        )
        self._write_pair(install)
        with self.assertRaisesRegex(ValueError, "limits.conf.*Cloud"):
            check_release(self.root / "dist", self.root / "package.json")

    def test_rejects_missing_recovery_reload_trigger(self):
        install = self._files()
        install["splunk_adm/default/app.conf"] = install[
            "splunk_adm/default/app.conf"
        ].replace(b"reload.adm_recovery = simple\n", b"")
        self._write_pair(install)
        with self.assertRaisesRegex(ValueError, "reload.adm_recovery must be simple"):
            check_release(self.root / "dist", self.root / "package.json")

    def test_operator_log_must_ship_info_level_and_simple_reload(self):
        name = "splunk_adm/default/adm_logging.conf"
        for content in (
            b"[logging]\nlevel = DEBUG\n",
            b"[logging]\nlevel = INFO\npath = /tmp/x.log\n",
            b"[other]\nlevel = INFO\n",
        ):
            with self.subTest(content=content):
                install = self._files()
                install[name] = content
                self._write_pair(install)
                with self.assertRaisesRegex(ValueError, "level = INFO"):
                    check_release(self.root / "dist", self.root / "package.json")
        install = self._files()
        del install[name]
        self._write_pair(install)
        with self.assertRaisesRegex(ValueError, "missing required files"):
            check_release(self.root / "dist", self.root / "package.json")
        install = self._files()
        app = "splunk_adm/default/app.conf"
        install[app] = install[app].replace(b"reload.adm_logging = simple\n", b"")
        self._write_pair(install)
        with self.assertRaisesRegex(ValueError, "reload.adm_logging must be simple"):
            check_release(self.root / "dist", self.root / "package.json")

    def test_rejects_missing_or_restart_settings_reload_trigger(self):
        for replacement in (b"", b"reload.adm_settings = never\n"):
            with self.subTest(replacement=replacement):
                install = self._files()
                name = "splunk_adm/default/app.conf"
                install[name] = install[name].replace(
                    b"reload.adm_settings = simple\n", replacement
                )
                self._write_pair(install)
                with self.assertRaisesRegex(
                    ValueError, "reload.adm_settings must be simple"
                ):
                    check_release(self.root / "dist", self.root / "package.json")

    def test_qualified_configuration_reload_does_not_require_restart(self):
        for config in (
            "adm_identity",
            "adm_aci_poll",
            "adm_aci_bindings",
            "adm_investigations",
            "adm_baselines",
            "adm_dependency_watch",
        ):
            for replacement in (b"", f"reload.{config} = never\n".encode()):
                with self.subTest(config=config, replacement=replacement):
                    install = self._files()
                    path = "splunk_adm/default/app.conf"
                    install[path] = install[path].replace(
                        f"reload.{config} = simple\n".encode(), replacement
                    )
                    self._write_pair(install)
                    with self.assertRaisesRegex(
                        ValueError, rf"reload\.{config} must be simple"
                    ):
                        check_release(self.root / "dist", self.root / "package.json")

    def test_new_custom_configuration_requires_reload(self):
        for path in (
            "splunk_adm/default/adm_future.conf",
            "splunk_adm/README/future.conf.spec",
        ):
            with self.subTest(path=path):
                install = self._files()
                install[path] = b"[example]\nenabled = false\n"
                self._write_pair(install)
                name = "adm_future" if "/default/" in path else "future"
                with self.assertRaisesRegex(
                    ValueError, rf"reload\.{name} must be declared"
                ):
                    check_release(self.root / "dist", self.root / "package.json")
                install["splunk_adm/default/app.conf"] += (
                    f"reload.{name} = never\n".encode()
                )
                self._write_pair(install)
                check_release(self.root / "dist", self.root / "package.json")

    def test_rejects_installed_local_csv_scope_override(self):
        self._write_pair()
        installed = self.root / "installed"
        (installed / "local").mkdir(parents=True)
        (installed / "local/transforms.conf").write_text(
            "[adm_observer_scope]\nfilename = adm_observer_scope.csv\n"
        )
        with self.assertRaisesRegex(ValueError, "legacy CSV scope lookup"):
            check_release(
                self.root / "dist", self.root / "package.json", installed_app=installed
            )

    def test_accepts_unrelated_installed_local_transform(self):
        self._write_pair()
        installed = self.root / "installed"
        (installed / "local").mkdir(parents=True)
        (installed / "local/transforms.conf").write_text(
            "[unrelated]\nfilename = unrelated.csv\n"
        )
        check_release(
            self.root / "dist", self.root / "package.json", installed_app=installed
        )

    def test_rejects_packaged_local_csv_scope_override(self):
        install = self._files()
        install["splunk_adm/local/transforms.conf"] = (
            b"[adm_observer_scope]\nfilename = adm_observer_scope.csv\n"
        )
        self._write_pair(install)
        with self.assertRaisesRegex(ValueError, "legacy CSV scope lookup"):
            check_release(self.root / "dist", self.root / "package.json")

    def test_rejects_deployment_owned_source_mapping_csv(self):
        for name in ("adm_observer_scope.csv", "adm_network_source_scope.csv"):
            with self.subTest(name=name):
                install = self._files()
                install[f"splunk_adm/lookups/{name}"] = b"source,scope\n"
                self._write_pair(install)
                with self.assertRaisesRegex(ValueError, "deployment-owned scope CSV"):
                    check_release(self.root / "dist", self.root / "package.json")

    def test_rejects_wrong_id_version_even_with_correct_launcher(self):
        install = self._files()
        install["splunk_adm/default/app.conf"] = (
            b"[install]\nbuild = 123\n[id]\nversion = 0.0.0\n"
            b"[launcher]\nversion = 1.2.3\n[package]\nid = splunk_adm\n"
        )
        self._write_pair(install)
        with self.assertRaisesRegex(ValueError, r"app.conf \[id\]"):
            check_release(self.root / "dist", self.root / "package.json")

    def test_rejects_default_version_inheritance(self):
        install = self._files()
        install["splunk_adm/default/app.conf"] = (
            b"[DEFAULT]\nversion = 1.2.3\n[install]\nbuild = 123\n"
            b"[id]\n[launcher]\n[package]\nid = splunk_adm\n"
        )
        self._write_pair(install)
        with self.assertRaisesRegex(ValueError, "DEFAULT"):
            check_release(self.root / "dist", self.root / "package.json")

    def test_rejects_nested_case_insensitive_env_file(self):
        install = self._files()
        install["splunk_adm/appserver/.ENV.production"] = b"secret"
        self._write_pair(install)
        with self.assertRaisesRegex(ValueError, "secret-like path"):
            check_release(self.root / "dist", self.root / "package.json")

    def test_rejects_deployment_local_metadata(self):
        for path in (
            "splunk_adm/metadata/local.meta",
            "splunk_adm/metadata/LOCAL.META",
            "splunk_adm/local/app.conf",
        ):
            with self.subTest(path=path):
                install = self._files()
                install[path] = b"[]\naccess = read : [ * ]\n"
                self._write_pair(install)
                with self.assertRaisesRegex(ValueError, "deployment-local path"):
                    check_release(self.root / "dist", self.root / "package.json")

    def test_rejects_development_artifacts(self):
        for path in (
            "splunk_adm/bin/__pycache__/adm_settings.cpython-313.pyc",
            "splunk_adm/bin/adm_settings.pyc",
            "splunk_adm/bin/adm_settings.pyo",
            "splunk_adm/default/._app.conf",
            "splunk_adm/appserver/.DS_Store",
            "splunk_adm/.git/config",
            "splunk_adm/appserver/static/node_modules/react/index.js",
        ):
            with self.subTest(path=path):
                install = self._files()
                install[path] = b"x"
                self._write_pair(install)
                with self.assertRaisesRegex(ValueError, "development artifact"):
                    check_release(self.root / "dist", self.root / "package.json")

    def test_rejects_empty_local_or_development_directories(self):
        for path, message in (
            ("splunk_adm/local", "deployment-local path"),
            ("splunk_adm/bin/__pycache__", "development artifact"),
        ):
            with self.subTest(path=path):
                directory = tarfile.TarInfo(path)
                directory.type = tarfile.DIRTYPE
                self._write_archive(
                    "splunk_adm-1.2.3.tar.gz", self._files(), [directory]
                )
                with self.assertRaisesRegex(ValueError, message):
                    check_release(self.root / "dist", self.root / "package.json")

    def test_rejects_custom_mako_template(self):
        for path in (
            "splunk_adm/appserver/templates/atlas.html",
            "splunk_adm/appserver/Modules/legacy/legacy.html",
        ):
            with self.subTest(path=path):
                install = self._files()
                install[path] = b"<%! import os %>"
                self._write_pair(install)
                with self.assertRaisesRegex(ValueError, "custom Mako template"):
                    check_release(self.root / "dist", self.root / "package.json")

    def test_rejects_path_traversal(self):
        install = self._files()
        install["splunk_adm/../local/password"] = b"secret"
        self._write_pair(install)
        with self.assertRaisesRegex(ValueError, "archive member path"):
            check_release(self.root / "dist", self.root / "package.json")

    def test_rejects_symlink(self):
        install = self._files()
        link = tarfile.TarInfo("splunk_adm/default/link")
        link.type = tarfile.SYMTYPE
        link.linkname = "app.conf"
        self._write_archive("splunk_adm-1.2.3.tar.gz", install, [link])
        with self.assertRaisesRegex(ValueError, "links or special files"):
            check_release(self.root / "dist", self.root / "package.json")

    def test_rejects_duplicate_member(self):
        install = self._files()
        duplicate = tarfile.TarInfo("splunk_adm/LICENSE")
        duplicate.size = 0
        self._write_archive("splunk_adm-1.2.3.tar.gz", install, [duplicate])
        with self.assertRaisesRegex(ValueError, "duplicate archive member"):
            check_release(self.root / "dist", self.root / "package.json")

    def test_rejects_enabled_webhook_or_savedsearch(self):
        install = self._files()
        install["splunk_adm/default/savedsearches.conf"] = install[
            "splunk_adm/default/savedsearches.conf"
        ].replace(b"action.webhook = 0", b"action.webhook = 1", 1)
        self._write_pair(install)
        with self.assertRaisesRegex(ValueError, "webhook action must ship disabled"):
            check_release(self.root / "dist", self.root / "package.json")

        install = self._files()
        install["splunk_adm/default/savedsearches.conf"] = install[
            "splunk_adm/default/savedsearches.conf"
        ].replace(b"disabled = 1", b"disabled = 0", 1)
        self._write_pair(install)
        with self.assertRaisesRegex(ValueError, "saved search must ship disabled"):
            check_release(self.root / "dist", self.root / "package.json")

    def test_rejects_replicated_or_world_writable_collaboration_collection(self):
        install = self._files()
        install["splunk_adm/default/collections.conf"] = install[
            "splunk_adm/default/collections.conf"
        ].replace(
            b"[adm_saved_views]\n",
            b"[adm_saved_views]\nreplicate = true\n",
            1,
        )
        # Drop the duplicate replicate = false line that follows in the stanza
        raw = install["splunk_adm/default/collections.conf"].decode("utf-8")
        head, tail = raw.split("[adm_saved_views]\n", 1)
        tail = tail.replace("replicate = false\n", "", 1)
        install["splunk_adm/default/collections.conf"] = (
            head + "[adm_saved_views]\n" + tail
        ).encode("utf-8")
        self._write_pair(install)
        with self.assertRaisesRegex(
            ValueError, "packaged collaboration collection adm_saved_views"
        ):
            check_release(self.root / "dist", self.root / "package.json")

        install = self._files()
        install["splunk_adm/metadata/default.meta"] = install[
            "splunk_adm/metadata/default.meta"
        ].replace(
            b"[collections/adm_saved_views]\naccess = "
            + VIEWER_ACCESS
            + b", write : [ admin, sc_admin ]",
            b"[collections/adm_saved_views]\naccess = "
            + VIEWER_ACCESS
            + b", write : [ * ]",
            1,
        )
        self._write_pair(install)
        with self.assertRaisesRegex(
            ValueError, "packaged collections/adm_saved_views ACL"
        ):
            check_release(self.root / "dist", self.root / "package.json")

    def test_rejects_enabled_recovery_conf(self):
        install = self._files()
        install["splunk_adm/default/adm_recovery.conf"] = b"[recovery]\nenabled = 1\n"
        self._write_pair(install)
        with self.assertRaisesRegex(ValueError, "adm_recovery.conf must ship"):
            check_release(self.root / "dist", self.root / "package.json")

    def test_rejects_internal_evidence_docs(self):
        for doc in (
            "splunk_adm/docs/FEATURE_DELIVERY.md",
            "splunk_adm/docs/FEATURE_QUALIFICATION.json",
        ):
            install = self._files()
            install[doc] = b"internal lab record"
            self._write_pair(install)
            with self.assertRaisesRegex(ValueError, "internal evidence doc"):
                check_release(self.root / "dist", self.root / "package.json")


if __name__ == "__main__":
    unittest.main()
