"""Opt-in upgrade-state checks for the packaged app."""

from __future__ import annotations

from collections.abc import Callable
import base64
import configparser
import csv
import hashlib
import io
import json
import os
import re
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
APP = "splunk_adm"
CONTAINER = "adm-splunk-lab"
MGMT = "https://127.0.0.1:8089"
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


def metadata_risk(text: str) -> list[str]:
    """Flag explicit grants that broaden write or owner-dispatch access."""
    risks = []
    stanza = None
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            stanza = line[1:-1]
        elif stanza is not None and line.lower().startswith("access"):
            for action, roles in re.findall(r"(read|write)\s*:\s*\[([^]]*)\]", line):
                granted = {role.strip() for role in roles.split(",") if role.strip()}
                protected = (
                    action == "write"
                    or stanza == ""
                    or stanza.startswith("savedsearches")
                )
                if (
                    protected
                    and granted - {"admin", "sc_admin"}
                    and stanza not in risks
                ):
                    risks.append(stanza)
    return risks


def operator_metadata(text: str) -> str:
    # Splunk adds this bookkeeping stanza when installing a local archive.
    return re.sub(
        r"(?ms)^\[app/install/install_source_checksum\]\n.*?(?=^\[|\Z)", "", text
    ).rstrip()


def state_fingerprint(
    macros: dict, scopes: list[dict], identities: list[dict], metadata: str
) -> str:
    value = {
        "macros": macros,
        "scopes": scopes,
        "identities": identities,
        "metadata": metadata,
    }
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def archive_version(path: Path) -> str:
    """Read the packaged app version without extracting or executing it."""
    with tarfile.open(path, "r:gz") as archive:
        matches = [
            member
            for member in archive.getmembers()
            if member.name.removeprefix("./") == f"{APP}/default/app.conf"
        ]
        if len(matches) != 1 or not matches[0].isfile():
            raise ValueError("package must contain exactly one regular app.conf")
        if matches[0].size > 1024 * 1024:
            raise ValueError("packaged app.conf exceeds the inspection limit")
        source = archive.extractfile(matches[0])
        if source is None:
            raise ValueError("packaged app.conf cannot be read")
        config = configparser.RawConfigParser()
        config.read_string(source.read().decode("utf-8"))
        value = config.get("launcher", "version", fallback="")
        if not re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?", value):
            raise ValueError("packaged app version is missing or invalid")
        return value


def archive_savedsearches(path: Path) -> tuple[bytes, set[str]]:
    """Inspect the installed release's shipped search inventory."""
    with tarfile.open(path, "r:gz") as archive:
        matches = [
            member
            for member in archive.getmembers()
            if member.name.removeprefix("./") == f"{APP}/default/savedsearches.conf"
        ]
        if (
            len(matches) != 1
            or not matches[0].isfile()
            or matches[0].size > 2 * 1024 * 1024
        ):
            raise ValueError("package requires one bounded regular savedsearches.conf")
        source = archive.extractfile(matches[0])
        if source is None:
            raise ValueError("packaged savedsearches.conf cannot be read")
        payload = source.read()
    config = configparser.RawConfigParser()
    config.read_string(payload.decode("utf-8").replace("\\\n", ""))
    return payload, set(config.sections())


def local_savedsearch_names(payload: bytes) -> set[str]:
    """Return local stanzas that define executable saved searches."""
    config = configparser.RawConfigParser()
    config.read_string(payload.decode("utf-8").replace("\\\n", ""))
    return {
        name
        for name in config.sections()
        if config.get(name, "search", fallback="").strip()
    }


class UpgradeUnitTest(unittest.TestCase):
    def _exercise_upload(self, package, request, subprocess_run, wait_ready):
        integration = UpgradeIntegrationTest
        saved = {
            name: getattr(integration, name, mock.sentinel.missing)
            for name in (
                "package",
                "password",
                "lab",
                "active_archive",
                "upgrade_restore_needed",
            )
        }
        integration.package = Path("/tmp/candidate.tar.gz")
        integration.password = "test-password"
        integration.lab = mock.Mock()
        integration.lab.wait_ready.side_effect = wait_ready
        integration.active_archive = integration.package
        integration.upgrade_restore_needed = False
        observed = None
        try:
            with (
                mock.patch.object(
                    sys.modules[__name__], "_request", side_effect=request
                ),
                mock.patch.object(subprocess, "run", side_effect=subprocess_run),
            ):
                integration._upload_update(package)
                observed = (
                    integration.active_archive,
                    integration.upgrade_restore_needed,
                )
        finally:
            self._last_upload_state = (
                integration.active_archive,
                integration.upgrade_restore_needed,
            )
            for name, value in saved.items():
                if value is mock.sentinel.missing:
                    delattr(integration, name)
                else:
                    setattr(integration, name, value)
        return observed

    def test_upload_marks_accepted_baseline_before_temp_cleanup_failure(self):
        baseline = Path("/tmp/baseline.tar.gz")

        def run(*args, **kwargs):
            if "rm" in args[0]:
                raise subprocess.CalledProcessError(1, args[0])
            return mock.Mock()

        with self.assertRaises(subprocess.CalledProcessError):
            self._exercise_upload(baseline, lambda *args: (200, b""), run, None)
        self.assertEqual(self._last_upload_state[0], baseline)
        self.assertTrue(self._last_upload_state[1])

    def test_upload_retains_restore_flag_when_readiness_fails(self):
        baseline = Path("/tmp/baseline.tar.gz")
        with self.assertRaises(RuntimeError):
            self._exercise_upload(
                baseline,
                lambda *args: (200, b""),
                lambda *args, **kwargs: mock.Mock(),
                RuntimeError("readiness failed"),
            )
        self.assertEqual(self._last_upload_state[0], baseline)
        self.assertTrue(self._last_upload_state[1])

    def test_upload_request_exception_marks_restore_needed(self):
        candidate = Path("/tmp/candidate.tar.gz")
        with self.assertRaises(RuntimeError):
            self._exercise_upload(
                candidate,
                lambda *args: (_ for _ in ()).throw(RuntimeError("unknown outcome")),
                lambda *args, **kwargs: mock.Mock(),
                None,
            )
        self.assertTrue(self._last_upload_state[1])

    def test_successful_candidate_upload_clears_restore_flag(self):
        candidate = Path("/tmp/candidate.tar.gz")
        observed = self._exercise_upload(
            candidate,
            lambda *args: (200, b""),
            lambda *args, **kwargs: mock.Mock(),
            None,
        )
        self.assertEqual(observed[0], Path("/tmp/candidate.tar.gz"))
        self.assertFalse(observed[1])

    def test_local_savedsearch_inventory_ignores_override_only_stanzas(self):
        payload = (
            b"[vendor-only override]\n"
            b"disabled = 1\n"
            b"\n"
            b"[local search]\n"
            b"search = | makeresults\n"
        )
        self.assertEqual(local_savedsearch_names(payload), {"local search"})

    def test_savedsearch_inventory_comes_from_each_release_archive(self):
        with tempfile.TemporaryDirectory() as directory:
            for name, searches in (
                ("old", ["Old writer"]),
                ("new", ["Old writer", "New writer"]),
            ):
                path = Path(directory) / (name + ".tar.gz")
                content = "".join(
                    f"[{search}]\nsearch = | makeresults\n" for search in searches
                ).encode()
                with tarfile.open(path, "w:gz") as archive:
                    member = tarfile.TarInfo(f"{APP}/default/savedsearches.conf")
                    member.size = len(content)
                    archive.addfile(member, io.BytesIO(content))
                self.assertEqual(archive_savedsearches(path), (content, set(searches)))

    def test_archive_version_requires_one_regular_app_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "app.tar.gz"
            for contents, expected in (
                ([b"[launcher]\nversion = 0.2.0\n"], "0.2.0"),
                ([b"[launcher]\nversion = unknown\n"], None),
                ([b"[launcher]\nversion = 0.2.0\n"] * 2, None),
            ):
                with tarfile.open(path, "w:gz") as archive:
                    for content in contents:
                        member = tarfile.TarInfo(f"{APP}/default/app.conf")
                        member.size = len(content)
                        archive.addfile(member, io.BytesIO(content))
                if expected is None:
                    with self.assertRaises(ValueError):
                        archive_version(path)
                else:
                    self.assertEqual(archive_version(path), expected)

    def test_permissive_local_metadata_is_reported_unsafe(self):
        self.assertEqual(
            metadata_risk("[savedsearches]\naccess = read : [ * ], write : [ * ]\n"),
            ["savedsearches"],
        )

    def test_root_and_custom_role_dispatch_grants_are_unsafe(self):
        self.assertEqual(
            metadata_risk("[]\naccess = read : [ * ], write : [ admin ]\n"), [""]
        )
        self.assertEqual(
            metadata_risk(
                "[savedsearches/example]\naccess = read : [ custom_role ], write : [ admin ]\n"
            ),
            ["savedsearches/example"],
        )

    def test_installer_bookkeeping_does_not_hide_operator_metadata(self):
        original = "[savedsearches]\naccess = read : [ admin ], write : [ admin ]\n"
        updated = (
            original + "\n[app/install/install_source_checksum]\nversion = 10.6.0\n"
        )
        self.assertEqual(operator_metadata(original), operator_metadata(updated))
        changed = updated.replace("read : [ admin ]", "read : [ * ]")
        self.assertNotEqual(operator_metadata(original), operator_metadata(changed))

    def test_restrictive_local_metadata_has_no_risk(self):
        self.assertEqual(
            metadata_risk(
                "[savedsearches]\naccess = read : [ admin ], write : [ admin, sc_admin ]\n"
            ),
            [],
        )

    def test_state_fingerprint_is_stable(self):
        a = state_fingerprint(
            {"x": "1"}, [{"scope": "prod", "observer": "a"}], [{"_key": "one"}], ""
        )
        b = state_fingerprint(
            {"x": "1"}, [{"observer": "a", "scope": "prod"}], [{"_key": "one"}], ""
        )
        self.assertEqual(a, b)

    def test_effective_savedsearch_acl_requires_admin_only_read_and_write(self):
        self.assertEqual(
            UpgradeIntegrationTest._safe_acl(
                {"perms": {"read": ["admin"], "write": ["sc_admin"]}}
            ),
            {"read": ("admin",), "write": ("sc_admin",)},
        )
        with self.assertRaises(AssertionError):
            UpgradeIntegrationTest._safe_acl(
                {"perms": {"read": ["*"], "write": ["admin"]}}
            )

    def test_supervisor_is_disabled_admin_only_and_cannot_trigger_recovery(self):
        root = HERE.parents[1] / "splunk_app" / APP
        searches = configparser.RawConfigParser()
        searches.read(root / "default/savedsearches.conf")
        supervisor = searches["ADM - Recovery abandoned-lease alert"]
        self.assertEqual(supervisor["disabled"], "1")
        self.assertEqual(supervisor["action.adm_recovery"], "0")
        self.assertEqual(supervisor["alert.track"], "1")
        metadata = configparser.RawConfigParser()
        metadata.read_string(
            (root / "metadata/default.meta").read_text().replace("[]", "[root]", 1)
        )
        self.assertEqual(
            metadata["savedsearches"]["access"],
            "read : [ admin, sc_admin ], write : [ admin, sc_admin ]",
        )
        # A specific stanza must not accidentally broaden the inherited grant.
        self.assertFalse(
            metadata.has_section("savedsearches/ADM - Recovery abandoned-lease alert")
        )

    def test_recovery_metadata_protects_action_config_collections_and_lookup(self):
        path = HERE.parents[1] / "splunk_app" / APP / "metadata" / "default.meta"
        text = path.read_text(encoding="utf-8")
        for stanza in (
            "alert_actions/adm_recovery",
            "adm_recovery",
            "collections/adm_recovery_state",
            "collections/adm_recovery_audit",
            "transforms/adm_recovery_state",
            "transforms/adm_recovery_audit",
        ):
            self.assertRegex(text, rf"(?ms)^\[{re.escape(stanza)}\]$")
        protected = re.findall(
            r"(?ms)^\[(?:alert_actions/adm_recovery|adm_recovery|collections/adm_recovery_state|collections/adm_recovery_audit|transforms/adm_recovery_state|transforms/adm_recovery_audit)\]\naccess\s*=\s*([^\n]+)",
            text,
        )
        self.assertEqual(len(protected), 6)
        self.assertTrue(
            all("admin" in value and "sc_admin" in value for value in protected)
        )


def retry_kv_initialization(
    operation: Callable[[], tuple[int, bytes]], timeout: float = 180
) -> tuple[int, bytes]:
    """Retry only a rejected operation while the local KV store initializes."""
    deadline = time.monotonic() + timeout
    while True:
        status, body = operation()
        if (
            status != 503
            or b"kv store is initializing" not in body.lower()
            or time.monotonic() >= deadline
        ):
            return status, body
        time.sleep(2)


def _request(
    method: str,
    path: str,
    password: str,
    data: bytes | None = None,
    content_type: str = "application/x-www-form-urlencoded",
) -> tuple[int, bytes]:
    auth = base64.b64encode(f"admin:{password}".encode()).decode()
    request = urllib.request.Request(
        MGMT + path,
        data=data,
        method=method,
        headers={"Authorization": f"Basic {auth}", "Content-Type": content_type},
    )

    def once() -> tuple[int, bytes]:
        try:
            with urllib.request.urlopen(request, context=CTX, timeout=300) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as error:
            with error:
                return error.code, error.read(4000)

    if "/storage/collections/data/" in path:
        return retry_kv_initialization(once)
    return once()


@unittest.skipUnless(
    os.environ.get("ADM_LAB") == "1" and os.environ.get("ADM_UPGRADE_PACKAGE"),
    "set ADM_LAB=1 and ADM_UPGRADE_PACKAGE to run live",
)
class UpgradeIntegrationTest(unittest.TestCase):
    """Preserve deployment-local state across a real Splunk app update."""

    @classmethod
    def setUpClass(cls):
        import sys

        sys.path.insert(0, str(HERE))
        import lab

        cls.lab = lab
        cls.password = lab.read_secrets()["SPLUNK_PASSWORD"]
        cls.package = Path(os.environ["ADM_UPGRADE_PACKAGE"]).resolve()
        if not cls.package.is_file():
            raise unittest.SkipTest(f"package does not exist: {cls.package}")
        with tarfile.open(cls.package, "r:gz") as package:
            names = {name.removeprefix("./") for name in package.getnames()}
        if f"{APP}/lookups/adm_observer_scope.csv" in names:
            raise AssertionError(
                "Release archives must not ship the legacy scope CSV; use the validated single install/update archive"
            )
        cls.token = uuid.uuid4().hex[:12]
        cls.scope = "upgrade-" + cls.token
        # Keep a populated CSV-era migration source alongside the independent
        # KV-to-KV fixture. Mixed-case match keys and outputs must survive bytes
        # for bytes until an administrator explicitly runs the shipped migration.
        cls.legacy_scope_rows = [
            {
                "observer_kind": "ClUsTeR",
                "observer": "CSV-Upgrade-" + cls.token,
                "scope": cls.scope + "-CSV-A",
                "cluster": "LegacyCluster-A",
            },
            {
                "observer_kind": "HeC_SoUrCe",
                "observer": "HTTP:Upgrade-" + cls.token,
                "scope": cls.scope + "-CSV-B",
                "cluster": "LegacyCluster-B",
            },
        ]
        cls.legacy_scope_keys = [
            hashlib.sha256(
                json.dumps(
                    [row["observer_kind"].lower(), row["observer"].lower()],
                    separators=(",", ":"),
                ).encode()
            ).hexdigest()
            for row in cls.legacy_scope_rows
        ]
        legacy_csv = io.StringIO()
        writer = csv.DictWriter(legacy_csv, fieldnames=list(cls.legacy_scope_rows[0]))
        writer.writeheader()
        writer.writerows(cls.legacy_scope_rows)
        cls.legacy_scope_csv = legacy_csv.getvalue().encode()
        cls.identity_keys = [f"upgrade-{cls.token}-old", f"upgrade-{cls.token}-new"]
        cls.original_macro = cls.lab._json(
            "GET", f"/servicesNS/nobody/{APP}/configs/conf-macros/adm_index_netflow"
        )["entry"][0]["content"].get("definition", "")
        cls.original_scope = cls.lab.search("| inputlookup adm_observer_scope")
        cls._docker_preflight()
        cls.original_metadata = cls._local_metadata()
        cls.original_macro_file = cls._docker_file(
            "/opt/splunk/etc/apps/splunk_adm/local/macros.conf"
        )
        cls.original_metadata_file = cls._docker_file(
            "/opt/splunk/etc/apps/splunk_adm/metadata/local.meta"
        )
        cls.original_scope_file = cls._docker_file(
            "/opt/splunk/etc/apps/splunk_adm/lookups/adm_observer_scope.csv"
        )
        cls.original_savedsearch_file = cls._docker_file(
            "/opt/splunk/etc/apps/splunk_adm/local/savedsearches.conf"
        )
        cls.preserved_local_search_names = (
            local_savedsearch_names(cls.original_savedsearch_file[1])
            if cls.original_savedsearch_file[0]
            else set()
        )
        cls.active_archive = cls.package
        cls.addClassCleanup(cls._cleanup)
        cls._seed_state()
        cls.seeded = cls._snapshot()
        real_baseline = os.environ.get("ADM_UPGRADE_BASELINE_PACKAGE")
        cls.baseline = (
            Path(real_baseline).resolve() if real_baseline else cls._make_baseline()
        )
        cls.real_baseline = bool(real_baseline)
        cls.candidate_version = archive_version(cls.package)
        cls.baseline_version = archive_version(cls.baseline)
        if cls.real_baseline and cls.baseline_version == cls.candidate_version:
            raise AssertionError("real baseline must have a distinct release version")
        cls._upload_update(cls.baseline)
        baseline_app = cls.lab._json("GET", f"/services/apps/local/{APP}")
        baseline_text = json.dumps(baseline_app)
        if cls.real_baseline:
            cls._assert_installed_version(cls.baseline_version)
        elif "Synthetic-old-baseline" not in baseline_text:
            raise AssertionError("synthetic baseline marker was not installed")
        # The comparison begins with the actual installed baseline. Local
        # disabled lab overrides are separately identified and preserved.
        cls.before = cls._snapshot()
        cls._upload_update(cls.package)
        cls._assert_installed_version(cls.candidate_version)
        current_app = cls.lab._json("GET", f"/services/apps/local/{APP}")
        if "Synthetic-old-baseline" in json.dumps(current_app):
            raise AssertionError("current package did not replace synthetic baseline")
        cls.after = cls._snapshot()
        # Exercise a real release rollback, then restore the candidate for the
        # remaining integration checks. The migration test independently covers
        # public selector/writer rollback and retained versioned summary data.
        cls.rolled_back = None
        if cls.real_baseline:
            try:
                cls._upload_update(cls.baseline)
                cls._assert_installed_version(cls.baseline_version)
                cls.rolled_back = cls._snapshot()
            finally:
                cls._upload_update(cls.package)
                cls._assert_installed_version(cls.candidate_version)

    @classmethod
    def _assert_installed_version(cls, expected):
        response = cls.lab._json("GET", f"/services/apps/local/{APP}")
        entries = response.get("entry", [])
        if (
            len(entries) != 1
            or entries[0].get("content", {}).get("version") != expected
        ):
            raise AssertionError("installed app version does not match package")

    @classmethod
    def _cleanup(cls):
        if not hasattr(cls, "lab"):
            return
        for key in getattr(cls, "identity_keys", []):
            _request(
                "DELETE",
                f"/servicesNS/nobody/{APP}/storage/collections/data/adm_ip_identity/{urllib.parse.quote(key, safe='')}",
                cls.password,
            )
        for key in [f"upgrade-scope-{cls.token}", *cls.legacy_scope_keys]:
            _request(
                "DELETE",
                f"/servicesNS/nobody/{APP}/storage/collections/data/adm_observer_scope/{key}",
                cls.password,
            )
        cls._restore_docker_file(
            "/opt/splunk/etc/apps/splunk_adm/local/macros.conf",
            *cls.original_macro_file,
        )
        cls._restore_docker_file(
            "/opt/splunk/etc/apps/splunk_adm/metadata/local.meta",
            *cls.original_metadata_file,
        )
        cls._restore_docker_file(
            "/opt/splunk/etc/apps/splunk_adm/lookups/adm_observer_scope.csv",
            *cls.original_scope_file,
        )
        cls._restore_docker_file(
            "/opt/splunk/etc/apps/splunk_adm/local/savedsearches.conf",
            *cls.original_savedsearch_file,
        )
        if getattr(cls, "package", None) is not None and (
            getattr(cls, "active_archive", None) != cls.package
            or getattr(cls, "upgrade_restore_needed", False)
        ):
            cls._upload_update(cls.package)
            cls._assert_installed_version(cls.candidate_version)
        cls.lab._mgmt("GET", f"/servicesNS/nobody/{APP}/admin/macros/_reload").close()

    @classmethod
    def _docker_preflight(cls):
        import sys

        sys.path.insert(0, str(HERE.parents[1] / "tools"))
        from benchmark_pipeline import local_docker_endpoint, validate_ports

        local_docker_endpoint()
        ports = subprocess.run(
            ["docker", "inspect", "-f", "{{json .NetworkSettings.Ports}}", CONTAINER],
            capture_output=True,
            text=True,
            check=True,
        )
        validate_ports(json.loads(ports.stdout))
        result = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", CONTAINER],
            capture_output=True,
            text=True,
            check=True,
        )
        if result.stdout.strip() != "true":
            raise unittest.SkipTest(f"{CONTAINER} is not running")

    @classmethod
    def _docker_file(cls, path):
        result = subprocess.run(
            [
                "docker",
                "exec",
                "-u",
                "root",
                CONTAINER,
                "sh",
                "-c",
                f"if test -f {path}; then cat {path}; else exit 44; fi",
            ],
            capture_output=True,
        )
        if result.returncode == 44:
            return False, b""
        if result.returncode:
            raise AssertionError(result.stderr.decode(errors="replace"))
        return True, result.stdout

    @classmethod
    def _restore_docker_file(cls, path, existed, content):
        if existed:
            parent = path.rsplit("/", 1)[0]
            subprocess.run(
                [
                    "docker",
                    "exec",
                    "-u",
                    "root",
                    "-i",
                    CONTAINER,
                    "sh",
                    "-c",
                    f"mkdir -p {parent} && cat > {path} && chown splunk:splunk {path}",
                ],
                input=content,
                check=True,
            )
        else:
            subprocess.run(
                ["docker", "exec", "-u", "root", CONTAINER, "rm", "-f", path],
                check=True,
                capture_output=True,
            )

    @classmethod
    def _seed_state(cls):
        if not cls.original_metadata_file[0]:
            cls._restore_docker_file(
                "/opt/splunk/etc/apps/splunk_adm/metadata/local.meta",
                True,
                b"[savedsearches]\naccess = read : [ admin, sc_admin ], write : [ admin, sc_admin ]\n",
            )
        cls._restore_docker_file(
            "/opt/splunk/etc/apps/splunk_adm/lookups/adm_observer_scope.csv",
            True,
            cls.legacy_scope_csv,
        )
        cls.lab._json(
            "POST",
            f"/servicesNS/nobody/{APP}/configs/conf-macros/adm_index_netflow",
            {"definition": "index=adm_alt_nf"},
        )
        scope_data = json.dumps(
            json.dumps(
                [
                    {
                        "observer_kind": "cluster",
                        "observer": "upgrade-" + cls.token,
                        "scope": cls.scope,
                        "cluster": "",
                    }
                ]
            )
        )
        cls.lab.search(
            f"| makeresults format=json data={scope_data} "
            "| eval observer_kind=lower(observer_kind), observer=lower(observer), "
            f'_key="upgrade-scope-{cls.token}" '
            "| fields _key observer_kind observer scope cluster "
            "| outputlookup append=true key_field=_key adm_observer_scope"
        )
        for key, valid_from, valid_to in zip(cls.identity_keys, (100, 200), (200, "")):
            payload = {
                "_key": key,
                "ip": "198.51.100.7",
                "scope": cls.scope,
                "entity_kind": "pod",
                "entity_id": key,
                "valid_from": valid_from,
                "valid_to": valid_to,
                "source": "upgrade-test",
            }
            status, body = _request(
                "POST",
                f"/servicesNS/nobody/{APP}/storage/collections/data/adm_ip_identity",
                cls.password,
                json.dumps(payload).encode(),
                "application/json",
            )
            if status not in (200, 201):
                raise AssertionError(f"KV seed failed HTTP {status}: {body[:500]!r}")

    @classmethod
    def _local_metadata(cls) -> str:
        result = subprocess.run(
            [
                "docker",
                "exec",
                "-u",
                "root",
                CONTAINER,
                "sh",
                "-c",
                f"cat /opt/splunk/etc/apps/{APP}/metadata/local.meta 2>/dev/null || true",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout

    @classmethod
    def _snapshot(cls) -> dict:
        macro = cls.lab._json(
            "GET", f"/servicesNS/nobody/{APP}/configs/conf-macros/adm_index_netflow"
        )
        scope_rows = cls.lab.search(
            f'| inputlookup adm_observer_scope | search scope="{cls.scope}"'
        )
        query = urllib.parse.urlencode(
            {"query": json.dumps({"_key": {"$in": cls.identity_keys}})}
        )
        status, body = _request(
            "GET",
            f"/servicesNS/nobody/{APP}/storage/collections/data/adm_ip_identity?{query}",
            cls.password,
        )
        if status != 200:
            raise AssertionError(f"KV snapshot failed HTTP {status}: {body[:500]!r}")
        metadata = cls._local_metadata()
        risks = metadata_risk(metadata)
        acl = cls._savedsearch_acl()
        protected_acl = cls._protected_config_acl()
        macro_file = cls._docker_file(
            "/opt/splunk/etc/apps/splunk_adm/local/macros.conf"
        )
        scope_file = cls._docker_file(
            "/opt/splunk/etc/apps/splunk_adm/lookups/adm_observer_scope.csv"
        )
        identities = json.loads(body.decode())
        if isinstance(identities, dict):
            identities = identities.get("entry", [])
        if len(scope_rows) != 1 or len(identities) != 2:
            raise AssertionError(
                f"synthetic state incomplete: scope={scope_rows!r} identities={identities!r}"
            )
        identities.sort(key=lambda row: row.get("_key", row.get("name", "")))
        scope_rows.sort(key=lambda row: json.dumps(row, sort_keys=True))
        return {
            "macro": macro["entry"][0]["content"].get("definition"),
            "scope": scope_rows,
            "identities": identities,
            "metadata": metadata,
            "metadata_risk": risks,
            "acl": acl,
            "shipped_search_inventory": sorted(
                archive_savedsearches(cls.active_archive)[1]
            ),
            "protected_acl": protected_acl,
            "scope_acl": cls._scope_acl(),
            "macro_file": macro_file,
            "scope_file": scope_file,
            "savedsearch_file": cls._docker_file(
                "/opt/splunk/etc/apps/splunk_adm/local/savedsearches.conf"
            ),
        }

    @classmethod
    def _safe_acl(cls, acl) -> dict:
        perms = acl.get("perms", {})
        read = perms.get("read", [])
        write = perms.get("write", [])
        if isinstance(read, str):
            read = [read]
        if isinstance(write, str):
            write = [write]
        if set(read) - {"admin", "sc_admin"} or set(write) - {"admin", "sc_admin"}:
            raise AssertionError(f"unsafe saved-search ACL: read={read}, write={write}")
        return {"read": tuple(sorted(read)), "write": tuple(sorted(write))}

    @classmethod
    def _savedsearch_acl(cls) -> dict:
        result = cls.lab._json(
            "GET", f"/servicesNS/nobody/{APP}/saved/searches?count=0"
        )
        entries = result.get("entry", [])
        shipped, expected = archive_savedsearches(cls.active_archive)
        installed = cls._docker_file(
            "/opt/splunk/etc/apps/splunk_adm/default/savedsearches.conf"
        )
        if installed != (True, shipped):
            raise AssertionError(
                "installed saved-search defaults differ from the release archive"
            )
        actual = {entry.get("name", "") for entry in entries}
        expected_names = expected | cls.preserved_local_search_names
        if actual != expected_names:
            raise AssertionError(
                "saved-search inventory mismatch: "
                f"expected={sorted(expected_names)!r}, actual={sorted(actual)!r}, "
                f"local_extras={sorted(cls.preserved_local_search_names - expected)!r}"
            )
        out = {}
        for entry in entries:
            name = entry.get("name", "")
            if name not in expected:
                content = entry.get("content", {})
                if content.get("disabled") is not True:
                    raise AssertionError(
                        "retained local search is not disabled after rollback"
                    )
                continue
            acl = entry.get("acl", {})
            out[entry.get("name", "")] = {
                "permissions": cls._safe_acl(acl),
                "owner": acl.get("owner"),
                "sharing": acl.get("sharing"),
            }
        return out

    @classmethod
    def _scope_acl(cls) -> dict:
        out = {}
        for kind in ("collections", "transforms"):
            result = cls.lab._json(
                "GET",
                f"/servicesNS/nobody/{APP}/configs/conf-{kind}/adm_observer_scope",
            )["entry"][0]
            if kind == "transforms":
                content = result["content"]
                if (
                    content.get("external_type") != "kvstore"
                    or content.get("collection") != "adm_observer_scope"
                ):
                    raise AssertionError(
                        "effective scope lookup is not the protected KV collection"
                    )
            perms = result["acl"]["perms"]
            read, write = set(perms["read"]), set(perms["write"])
            if read != {"*"} or write != {"admin", "sc_admin"}:
                raise AssertionError(f"unsafe scope ACL: read={read}, write={write}")
            out[kind] = {"read": sorted(read), "write": sorted(write)}
        return out

    @classmethod
    def _protected_config_acl(cls) -> dict:
        """Capture ACLs for recovery configuration and KV collections."""
        endpoints = {
            "alert_actions/adm_recovery": "configs/conf-alert_actions/adm_recovery",
            "adm_recovery/recovery": "configs/conf-adm_recovery/recovery",
            "collections/adm_recovery_state": "configs/conf-collections/adm_recovery_state",
            "collections/adm_recovery_audit": "configs/conf-collections/adm_recovery_audit",
            "transforms/adm_recovery_state": "configs/conf-transforms/adm_recovery_state",
            "transforms/adm_recovery_audit": "configs/conf-transforms/adm_recovery_audit",
        }
        out = {}
        for name, path in endpoints.items():
            result = cls.lab._json("GET", f"/servicesNS/nobody/{APP}/{path}")
            entries = result.get("entry", [])
            if len(entries) != 1:
                raise AssertionError(
                    f"expected one ACL entry for {name}, got {entries!r}"
                )
            acl = entries[0].get("acl", {})
            out[name] = cls._safe_acl(acl)
        return out

    @classmethod
    def _make_baseline(cls):
        descriptor, filename = tempfile.mkstemp(suffix=".tar.gz")
        os.close(descriptor)
        target = Path(filename)
        with (
            tarfile.open(cls.package, "r:gz") as source,
            tarfile.open(target, "w:gz") as output,
        ):
            for member in source.getmembers():
                data = source.extractfile(member).read() if member.isfile() else None
                if member.name.endswith("/default/app.conf") and data is not None:
                    data = data.replace(
                        b"description = Network-perspective",
                        b"description = Synthetic-old-baseline Network-perspective",
                    )
                    member.size = len(data)
                output.addfile(
                    member, None if data is None else __import__("io").BytesIO(data)
                )
        cls.addClassCleanup(target.unlink, missing_ok=True)
        return target

    @classmethod
    def _upload_update(cls, package):
        # A request can succeed while cleanup of the upload or readiness polling
        # fails. Mark the state before dispatch so class cleanup still retries
        # the candidate package after an ambiguous outcome.
        cls.upgrade_restore_needed = True
        remote = f"/tmp/adm-upgrade-{uuid.uuid4().hex}.tar.gz"
        subprocess.run(
            ["docker", "cp", str(package), f"{CONTAINER}:{remote}"],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            [
                "docker",
                "exec",
                "-u",
                "root",
                CONTAINER,
                "chown",
                "splunk:splunk",
                remote,
            ],
            check=True,
            capture_output=True,
        )
        data = urllib.parse.urlencode(
            {"name": remote, "filename": "true", "update": "1"}
        ).encode()
        status, response = _request("POST", "/services/apps/local", cls.password, data)
        if status in (200, 201, 202):
            # Record the accepted archive before any fallible cleanup/readiness
            # work, so setup failure cannot leave the baseline installed.
            cls.active_archive = package
        subprocess.run(
            ["docker", "exec", "-u", "root", CONTAINER, "rm", "-f", remote],
            check=True,
            capture_output=True,
        )
        if status not in (200, 201, 202):
            raise AssertionError(
                f"Splunk package update failed HTTP {status}: {response[:1000]!r}"
            )
        cls.lab.wait_ready(300)
        cls.upgrade_restore_needed = package != cls.package

    def test_local_state_survives_update(self):
        for key in (
            "macro",
            "scope",
            "identities",
            "macro_file",
            "scope_file",
            "savedsearch_file",
        ):
            self.assertEqual(self.seeded[key], self.before[key], key)
        self.assertEqual(self.before["macro"], self.after["macro"])
        self.assertEqual(self.before["scope"], self.after["scope"])
        self.assertEqual(self.before["identities"], self.after["identities"])
        self.assertEqual(
            operator_metadata(self.before["metadata"]),
            operator_metadata(self.after["metadata"]),
        )
        self.assertEqual(self.before["metadata_risk"], [])
        self.assertEqual(self.after["metadata_risk"], [])
        self.assertTrue(set(self.before["acl"]) <= set(self.after["acl"]))
        for name, acl in self.before["acl"].items():
            self.assertEqual(acl, self.after["acl"][name], name)
        self.assertEqual(self.before["protected_acl"], self.after["protected_acl"])
        self.assertEqual(self.before["scope_acl"], self.after["scope_acl"])
        self.assertEqual(self.before["macro_file"], self.after["macro_file"])
        self.assertEqual(self.before["scope_file"], self.after["scope_file"])
        self.assertEqual(
            self.before["savedsearch_file"], self.after["savedsearch_file"]
        )

    def test_real_release_rollback_preserves_local_state(self):
        if not self.real_baseline:
            self.skipTest(
                "set ADM_UPGRADE_BASELINE_PACKAGE for a real release rollback"
            )
        self.assertIsNotNone(self.rolled_back)
        for key in (
            "macro",
            "scope",
            "identities",
            "metadata_risk",
            "acl",
            "protected_acl",
            "scope_acl",
            "macro_file",
            "scope_file",
            "savedsearch_file",
            "shipped_search_inventory",
        ):
            self.assertEqual(self.before[key], self.rolled_back[key], key)
        self.assertEqual(
            operator_metadata(self.before["metadata"]),
            operator_metadata(self.rolled_back["metadata"]),
        )

    def test_populated_csv_survives_update_and_migrates_to_kv(self):
        self.assertEqual(self.before["scope_file"], (True, self.legacy_scope_csv))
        self.assertEqual(self.after["scope_file"], (True, self.legacy_scope_csv))
        # Prove the retained CSV is readable by filename after the named lookup
        # switches to KV, including its original match-key and output casing.
        self.assertCountEqual(
            self.lab.search(
                "| inputlookup adm_observer_scope.csv "
                "| table observer_kind observer scope cluster"
            ),
            self.legacy_scope_rows,
        )
        kv_query = (
            "| inputlookup adm_observer_scope | search "
            + " OR ".join(f'_key="{key}"' for key in self.legacy_scope_keys)
            + " | table _key observer_kind observer scope cluster"
        )
        self.assertEqual(self.lab.search(kv_query), [], "no unattended CSV import")

        # Execute the installed saved search's SPL as admin, keeping the shipped
        # disabled/unscheduled search disabled rather than creating local overrides.
        name = urllib.parse.quote("ADM - Migrate observer scope", safe="")
        migration = self.lab._json(
            "GET", f"/servicesNS/nobody/{APP}/saved/searches/{name}"
        )["entry"][0]["content"]["search"]
        result = self.lab.search(migration)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["blocked"], "0")
        self.assertEqual(result[0]["source_rows"], str(len(self.legacy_scope_rows)))
        self.assertEqual(result[0]["rows_written"], str(len(self.legacy_scope_rows)))
        self.assertCountEqual(
            self.lab.search(kv_query),
            [
                {
                    **row,
                    "_key": key,
                    "observer_kind": row["observer_kind"].lower(),
                    "observer": row["observer"].lower(),
                }
                for row, key in zip(self.legacy_scope_rows, self.legacy_scope_keys)
            ],
        )
        self.assertEqual(
            self._docker_file(
                "/opt/splunk/etc/apps/splunk_adm/lookups/adm_observer_scope.csv"
            ),
            (True, self.legacy_scope_csv),
        )
        self.assertEqual(
            self.lab.search(
                f'| inputlookup adm_observer_scope | search scope="{self.scope}"'
            ),
            self.after["scope"],
            "migration must preserve the existing KV-to-KV mapping",
        )


if __name__ == "__main__":
    unittest.main()
