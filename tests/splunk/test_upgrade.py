"""Opt-in upgrade-state checks for the packaged app."""

from __future__ import annotations

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
import tarfile
import tempfile
import unittest
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

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


class UpgradeUnitTest(unittest.TestCase):
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
    try:
        with urllib.request.urlopen(request, context=CTX, timeout=300) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as error:
        with error:
            return error.code, error.read(4000)


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
                "Use the -upgrade archive: full-install packages overwrite the deployment scope CSV"
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
        cls.addClassCleanup(cls._cleanup)
        cls._seed_state()
        cls.before = cls._snapshot()
        cls.baseline = cls._make_baseline()
        cls._upload_update(cls.baseline)
        baseline_app = cls.lab._json("GET", f"/services/apps/local/{APP}")
        baseline_text = json.dumps(baseline_app)
        if "Synthetic-old-baseline" not in baseline_text:
            raise AssertionError("synthetic baseline marker was not installed")
        cls._upload_update(cls.package)
        current_app = cls.lab._json("GET", f"/services/apps/local/{APP}")
        if "Synthetic-old-baseline" in json.dumps(current_app):
            raise AssertionError("current package did not replace synthetic baseline")
        cls.after = cls._snapshot()

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
            "protected_acl": protected_acl,
            "scope_acl": cls._scope_acl(),
            "macro_file": macro_file,
            "scope_file": scope_file,
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
        expected = cls._packaged_savedsearch_names()
        actual = {entry.get("name", "") for entry in entries}
        if actual != expected:
            raise AssertionError(
                f"expected shipped saved-search ACLs {sorted(expected)!r}, got {sorted(actual)!r}"
            )
        out = {}
        for entry in entries:
            acl = entry.get("acl", {})
            out[entry.get("name", "")] = {
                "permissions": cls._safe_acl(acl),
                "owner": acl.get("owner"),
                "sharing": acl.get("sharing"),
            }
        return out

    @classmethod
    def _packaged_savedsearch_names(cls) -> set[str]:
        """Read the manifest from the checked-in package, not a count literal."""
        path = HERE.parents[1] / "splunk_app" / APP / "default" / "savedsearches.conf"
        names = set()
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line.startswith("[") and line.endswith("]"):
                names.add(line[1:-1])
        return names

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

    def test_local_state_survives_update(self):
        self.assertEqual(self.before["macro"], self.after["macro"])
        self.assertEqual(self.before["scope"], self.after["scope"])
        self.assertEqual(self.before["identities"], self.after["identities"])
        self.assertEqual(
            operator_metadata(self.before["metadata"]),
            operator_metadata(self.after["metadata"]),
        )
        self.assertEqual(self.before["metadata_risk"], [])
        self.assertEqual(self.after["metadata_risk"], [])
        self.assertEqual(self.before["acl"], self.after["acl"])
        self.assertEqual(self.before["protected_acl"], self.after["protected_acl"])
        self.assertEqual(self.before["scope_acl"], self.after["scope_acl"])
        self.assertEqual(self.before["macro_file"], self.after["macro_file"])
        self.assertEqual(self.before["scope_file"], self.after["scope_file"])

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
