import hashlib
import io
import tarfile
import unittest
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory

from tools.check_release import (
    BUNDLED_RUNTIME_FILES,
    MAX_ATLAS_GZIP_BYTES,
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
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.root = Path(self.temp.name)
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
            b"[triggers]\nreload.adm_recovery = simple\n"
        )
        return {
            **{
                name: b"#!/usr/bin/env python3\n"
                if name.endswith("adm_recovery.py")
                else b"runtime\n"
                for name in BUNDLED_RUNTIME_FILES
            },
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
                for page in ("applications", "map", "data_health", "setup", "help")
            },
            "splunk_adm/appserver/static/adm.css": b"css",
            "splunk_adm/default/app.conf": config,
            "splunk_adm/default/alert_actions.conf": b"[adm_recovery]\nalert.execute.cmd = adm_recovery.py\n",
            "splunk_adm/LICENSE": b"license",
            "splunk_adm/NOTICE": b"notice",
            "splunk_adm/THIRD_PARTY_NOTICES.txt": b"third party",
            "splunk_adm/docs/DATA_LAYER.md": b"docs",
            "splunk_adm/docs/RECOVERY.md": b"# Recovery and replay\n",
            "splunk_adm/docs/UPGRADES.md": b"migration docs",
            "splunk_adm/docs/CISCO_CONTRACT_MIGRATION.md": b"contract migration docs",
            "splunk_adm/docs/CISCO_NETWORKING_QUALIFICATION.md": b"qualification docs",
            "splunk_adm/docs/operators/cisco-enterprise-networking.md": b"operator docs",
            "splunk_adm/default/collections.conf": b"[x]\n",
            "splunk_adm/default/adm_recovery.conf": b"[recovery]\nenabled = 0\n",
            "splunk_adm/default/macros.conf": b"[x]\n",
            "splunk_adm/default/savedsearches.conf": b"[x]\n",
            "splunk_adm/default/transforms.conf": (
                b"[adm_observer_scope]\nexternal_type = kvstore\ncollection = adm_observer_scope\n"
            ),
            "splunk_adm/default/data/ui/nav/default.xml": b"<nav />\n",
            "splunk_adm/default/data/ui/views/dependency_map.xml": b"<view />\n",
            "splunk_adm/metadata/default.meta": b"[x]\n",
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
