import hashlib
import gzip
import io
import tarfile
import unittest
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from tools.check_release import (
    BUNDLED_RUNTIME_FILES,
    MAX_ATLAS_GZIP_BYTES,
    SETTINGS_CONFIG_FILES,
    SETTINGS_REGISTRY_PATH,
    SETTINGS_RUNTIME_FILES,
    check_release,
)


def _incompressible(size: int) -> bytes:
    """Deterministic bytes that do not let gzip hide bundle size."""
    chunks: list[bytes] = []
    counter = 0
    while counter * 32 < size:
        chunks.append(sha256(f"atlas-{counter}".encode()).digest())
        counter += 1
    return b"".join(chunks)[:size]


class ReleaseArchiveTests(unittest.TestCase):
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
        )
        return {
            **{
                name: b"#!/usr/bin/env python3\n"
                if name.endswith("adm_recovery.py")
                else b"runtime\n"
                for name in BUNDLED_RUNTIME_FILES
            },
            **{
                name: (Path(__file__).parents[1] / "splunk_app" / name).read_bytes()
                for name in SETTINGS_RUNTIME_FILES | SETTINGS_CONFIG_FILES
            },
            SETTINGS_REGISTRY_PATH: (
                self.root / "config/deployment-health.json"
            ).read_bytes(),
            "splunk_adm/appserver/static/pages/atlas.js": b"toolkit bundle",
            **{
                f"splunk_adm/appserver/static/demo/{name}.json": b"{}"
                for name in (
                    "demo-scopes",
                    "demo-catalog",
                    "demo-find",
                    "demo-rows",
                    "demo-rows-aci",
                    "demo-rows-aci-prev",
                    "demo-topology",
                    "demo-topology-aci",
                    "demo-networking-aci",
                    "demo-networking-nxos",
                    "demo-networking-topology",
                    "demo-networking-scopes",
                    "demo-networking-catalog",
                    "demo-networking-find",
                )
            },
            **{
                f"splunk_adm/default/data/ui/views/{page}.xml": b"view"
                for page in (
                    "applications",
                    "map",
                    "endpoints",
                    "data_health",
                    "setup",
                    "help",
                )
            },
            "splunk_adm/appserver/static/adm.css": b"css",
            "splunk_adm/default/app.conf": config,
            "splunk_adm/default/alert_actions.conf": b"[adm_recovery]\nalert.execute.cmd = adm_recovery.py\n",
            "splunk_adm/LICENSE": b"license",
            "splunk_adm/NOTICE": b"notice",
            "splunk_adm/THIRD_PARTY_NOTICES.txt": b"third party",
            "splunk_adm/docs/DATA_LAYER.md": b"docs",
            "splunk_adm/docs/DEPLOYMENT_HEALTH.md": b"settings operator docs",
            "splunk_adm/docs/LATE_CATALYST_RECEIPTS.md": b"late receipt operator docs",
            "splunk_adm/docs/RECOVERY.md": b"# Recovery and replay\n",
            "splunk_adm/docs/RETENTION_MAINTENANCE.md": b"# Retention\n",
            "splunk_adm/docs/UPGRADES.md": b"migration docs",
            "splunk_adm/docs/CISCO_CONTRACT_MIGRATION.md": b"contract migration docs",
            "splunk_adm/docs/CISCO_NETWORKING_QUALIFICATION.md": b"qualification docs",
            "splunk_adm/docs/operators/cisco-enterprise-networking.md": b"operator docs",
            "splunk_adm/docs/DNS_EVIDENCE_QUALIFICATION.md": b"dns qualification docs",
            "splunk_adm/docs/DNS_EVIDENCE_SCENARIOS.md": b"dns scenario docs",
            "splunk_adm/docs/DNS_EVIDENCE_DESIGN.md": b"dns design docs",
            "splunk_adm/docs/DNS_INGESTION_RESEARCH.md": b"dns research docs",
            "splunk_adm/docs/operators/dns-evidence.md": b"dns operator docs",
            "splunk_adm/default/collections.conf": b"[adm_deployment_settings]\nfield.revision = string\nfield.settings_json = string\n",
            "splunk_adm/default/adm_recovery.conf": b"[recovery]\nenabled = 0\n",
            "splunk_adm/default/macros.conf": b"[x]\n",
            "splunk_adm/default/savedsearches.conf": b"[x]\n",
            "splunk_adm/default/transforms.conf": (
                b"[adm_observer_scope]\nexternal_type = kvstore\ncollection = adm_observer_scope\n"
            ),
            "splunk_adm/default/data/ui/nav/default.xml": b"<nav />\n",
            "splunk_adm/default/data/ui/views/dependency_map.xml": b"<view />\n",
            "splunk_adm/metadata/default.meta": b"[]\naccess = read : [ * ], write : [ admin, sc_admin ]\n[collections/adm_deployment_settings]\naccess = read : [ * ], write : [ admin, sc_admin ]\n",
        }

    def _write_pair(self, install=None, upgrade=None):
        install = install or self._files()
        self._write_archive("splunk_adm-1.2.3.tar.gz", install)

    def test_accepts_valid_pair(self):
        self._write_pair()
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
        install["splunk_adm/appserver/static/pages/atlas.js"] = _incompressible(
            MAX_ATLAS_GZIP_BYTES - 4096
        )
        self._write_pair(install)
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

    def test_rejects_missing_endpoints_view_or_dns_docs(self):
        for name in (
            "splunk_adm/default/data/ui/views/endpoints.xml",
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
                    install[name].replace(before, after)
                    if before
                    else install[name] + after
                )
                self._write_pair(install)
                with self.assertRaisesRegex(ValueError, "settings browser exposure"):
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
                install[name] += suffix
                if not suffix:
                    install[name] = install[name].replace(
                        b"write : [ admin, sc_admin ]", b"write : [ * ]"
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
        ].replace(b"[triggers]\nreload.adm_recovery = simple\n", b"")
        self._write_pair(install)
        with self.assertRaisesRegex(ValueError, "reload.adm_recovery must be simple"):
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


if __name__ == "__main__":
    unittest.main()
