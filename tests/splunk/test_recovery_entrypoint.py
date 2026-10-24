"""Live checks for the packaged recovery alert-action entrypoint."""

from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import unittest
import xml.etree.ElementTree as ET


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CONTAINER = os.environ.get("ADM_LAB_NAME", "adm-splunk-lab")
# The recovery action executes inside the container, where Splunk always
# listens on 8089. ADM_LAB_MGMT_PORT remaps only the host-facing port.
MGMT = "https://localhost:8089"
APP_DIR = "/opt/splunk/etc/apps/splunk_adm"
STATE_PATH = "/servicesNS/nobody/splunk_adm/storage/collections/data/adm_recovery_state"
AUDIT_PATH = "/servicesNS/nobody/splunk_adm/storage/collections/data/adm_recovery_audit"
SERVER_CONF = "/opt/splunk/etc/system/local/server.conf"
SERVER_CERT = "/opt/splunk/etc/auth/adm_recovery_test_server.pem"
SERVER_CA = "/opt/splunk/etc/auth/adm_recovery_test_ca.pem"
LOCAL_FILES = (
    f"{APP_DIR}/local/adm_recovery.conf",
    f"{APP_DIR}/local/savedsearches.conf",
    f"{APP_DIR}/local/macros.conf",
)


@unittest.skipUnless(
    os.environ.get("ADM_LAB") == "1", "set ADM_LAB=1 with the lab running"
)
class RecoveryEntrypointIntegrationTest(unittest.TestCase):
    """Run the actual script with a localhost-verified owner session."""

    @classmethod
    def setUpClass(cls):
        import sys

        sys.path.insert(0, str(HERE))
        sys.path.insert(0, str(ROOT / "tools"))
        import lab
        from fault_pipeline import wait_kv_ready

        cls.lab = lab
        cls.wait_kv_ready = wait_kv_ready
        cls.password = lab.read_secrets()["SPLUNK_PASSWORD"]
        cls.original_server = cls._docker_read(SERVER_CONF)
        cls.original_cert = cls._docker_read(SERVER_CERT)
        cls.original_ca = cls._docker_read(SERVER_CA)
        cls.original_local = {path: cls._docker_read(path) for path in LOCAL_FILES}
        cls.tempdir = tempfile.TemporaryDirectory(prefix="adm-recovery-tls-")
        cls.addClassCleanup(cls._cleanup)
        cls.cert = Path(cls.tempdir.name) / "localhost.crt"
        cls.key = Path(cls.tempdir.name) / "localhost.key"
        cls.ca = Path(cls.tempdir.name) / "localhost-ca.crt"
        cls._make_certificate(cls.cert, cls.key, cls.ca)
        cls._install_tls()
        cls._install_local_overrides()
        cls.configured_saved = cls._docker_read(LOCAL_FILES[1])
        cls._restart()

    @classmethod
    def _docker_read(cls, path: str) -> bytes | None:
        result = subprocess.run(
            [
                "docker",
                "exec",
                "-u",
                "root",
                CONTAINER,
                "sh",
                "-c",
                f"test -f {path}",
            ],
            capture_output=True,
        )
        if result.returncode:
            return None
        return subprocess.check_output(
            ["docker", "exec", "-u", "root", CONTAINER, "cat", path]
        )

    @classmethod
    def _docker_write(cls, path: str, content: bytes | None):
        if content is None:
            subprocess.run(
                ["docker", "exec", "-u", "root", CONTAINER, "rm", "-f", path],
                check=True,
                capture_output=True,
            )
            return
        parent = path.rsplit("/", 1)[0]
        mode = "600" if path in (SERVER_CERT, SERVER_CONF) else "644"
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
                f"mkdir -p {parent} && cat > {path} && chmod {mode} {path} && chown splunk:splunk {path}",
            ],
            input=content,
            check=True,
            capture_output=True,
        )

    @staticmethod
    def _make_certificate(cert: Path, key: Path, ca: Path):
        subprocess.run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=localhost",
                "-addext",
                "subjectAltName=DNS:localhost",
                "-keyout",
                str(key),
                "-out",
                str(cert),
            ],
            check=True,
            capture_output=True,
        )
        ca.write_bytes(cert.read_bytes())

    @classmethod
    def _install_tls(cls):
        cls._docker_write(SERVER_CERT, cls.key.read_bytes() + cls.cert.read_bytes())
        cls._docker_write(SERVER_CA, cls.ca.read_bytes())
        original = (cls.original_server or b"").decode("utf-8", "replace")
        section = re.search(r"(?ms)^\[sslConfig\]\n.*?(?=^\[|\Z)", original)
        values = (
            "serverCert = "
            + SERVER_CERT
            + "\nsslPassword = \nsslRootCAPath = "
            + SERVER_CA
            + "\n"
        )
        if section:
            body = section.group(0)
            body = re.sub(r"(?m)^serverCert\s*=.*\n", "", body)
            body = re.sub(r"(?m)^sslPassword\s*=.*\n", "", body)
            body = re.sub(r"(?m)^sslRootCAPath\s*=.*\n", "", body)
            replacement = body.rstrip("\n") + "\n" + values
            updated = (
                original[: section.start()] + replacement + original[section.end() :]
            )
        else:
            updated = original.rstrip("\n") + "\n\n[sslConfig]\n" + values
        cls._docker_write(SERVER_CONF, updated.encode())

    @staticmethod
    def _set_stanza(text: str, name: str, values: dict[str, str]) -> str:
        stanza = (
            "["
            + name
            + "]\n"
            + "".join(f"{key} = {value}\n" for key, value in values.items())
        )
        pattern = re.compile(rf"(?ms)^\[{re.escape(name)}\]\n.*?(?=^\[|\Z)")
        if pattern.search(text):
            return pattern.sub(stanza, text, count=1)
        return text.rstrip("\n") + "\n\n" + stanza

    @classmethod
    def _install_local_overrides(cls):
        recovery = cls._set_stanza(
            "",
            "recovery",
            {
                "enabled": "1",
                "management_uri": MGMT,
                "ca_file": SERVER_CA,
            },
        )
        saved = cls._set_stanza(
            (cls.original_local[LOCAL_FILES[1]] or b"").decode("utf-8", "replace"),
            "ADM - Identity builder",
            {"disabled": "0", "is_scheduled": "1"},
        )
        synthetic = cls.synthetic_definition = (
            'makeresults | eval savedsearch_name="ADM - Identity builder", '
            'status="success", sid="scheduler__synthetic", '
            "scheduled_time=floor((now()-60)/300)*300+60 | fields "
            "savedsearch_name scheduled_time status sid"
        )
        macros = cls._set_stanza(
            (cls.original_local[LOCAL_FILES[2]] or b"").decode("utf-8", "replace"),
            "adm_recovery_scheduler_history",
            {"definition": synthetic},
        )
        cls._docker_write(LOCAL_FILES[0], recovery.encode())
        cls._docker_write(LOCAL_FILES[1], saved.encode())
        cls._docker_write(LOCAL_FILES[2], macros.encode())

    @classmethod
    def _rewrite_history_macro(cls, definition: str):
        current = (cls._docker_read(LOCAL_FILES[2]) or b"").decode("utf-8", "replace")
        updated = cls._set_stanza(
            current, "adm_recovery_scheduler_history", {"definition": definition}
        )
        cls._docker_write(LOCAL_FILES[2], updated.encode())

    @classmethod
    def _saved_target(cls, name: str, scheduled: bool):
        current = (cls._docker_read(LOCAL_FILES[1]) or b"").decode("utf-8", "replace")
        updated = cls._set_stanza(
            current,
            name,
            {"disabled": "0", "is_scheduled": "1" if scheduled else "0"},
        )
        cls._docker_write(LOCAL_FILES[1], updated.encode())

    def _collection_records(self, path: str) -> list[dict]:
        result = self.lab._json("GET", path + "?limit=0")
        return result if isinstance(result, list) else result.get("results", [])

    def _delete_record(self, path: str, key: str):
        with self.lab._mgmt("DELETE", path + "/" + key) as response:
            response.read()

    @classmethod
    def _restart(cls):
        cls.lab.restart()
        cls.wait_kv_ready(timeout=300)

    @classmethod
    def _cleanup(cls):
        try:
            cls._docker_write(SERVER_CONF, cls.original_server)
            cls._docker_write(SERVER_CERT, cls.original_cert)
            cls._docker_write(SERVER_CA, cls.original_ca)
            for path, content in cls.original_local.items():
                cls._docker_write(path, content)
            cls._restart()
        finally:
            cls.tempdir.cleanup()

    def _session_key(self) -> str:
        with self.lab._mgmt(
            "POST",
            "/services/auth/login",
            {"username": "admin", "password": self.password},
        ) as response:
            root = ET.fromstring(response.read())
        value = root.findtext("./sessionKey")
        self.assertTrue(value)
        return value

    def _run_entrypoint(
        self, session_key: str, target="ADM - Identity builder"
    ) -> subprocess.CompletedProcess:
        payload = {
            "app": "splunk_adm",
            "session_key": session_key,
            "result": {"name": target},
        }
        return subprocess.run(
            [
                "docker",
                "exec",
                "-u",
                "splunk",
                "-i",
                CONTAINER,
                "/opt/splunk/bin/splunk",
                "cmd",
                "python3",
                "/opt/splunk/etc/apps/splunk_adm/bin/adm_recovery.py",
            ],
            input=json.dumps(payload).encode(),
            capture_output=True,
            timeout=300,
            check=False,
        )

    def _noop_audits(self) -> int:
        rows = self.lab.search(
            '| inputlookup adm_recovery_audit | search event="noop" | stats count AS n'
        )
        return int(rows[0].get("n", 0)) if rows else 0

    def test_packaged_entrypoint_uses_verified_localhost_tls_and_returns_noop(self):
        result = self._run_entrypoint(self._session_key())
        self.assertEqual(
            result.returncode,
            0,
            result.stdout.decode(errors="replace")
            + result.stderr.decode(errors="replace"),
        )
        output = json.loads(result.stdout)
        self.assertEqual(output["status"], "noop", output)
        self.assertEqual(output["name"], "ADM - Identity builder")

    def test_packaged_entrypoint_refuses_when_local_action_is_disabled(self):
        disabled = self._set_stanza(
            "",
            "recovery",
            {
                "enabled": "0",
                "management_uri": MGMT,
                "ca_file": SERVER_CA,
            },
        )
        self._docker_write(LOCAL_FILES[0], disabled.encode())
        try:
            result = self._run_entrypoint(self._session_key())
            self.assertEqual(result.returncode, 1)
            self.assertEqual(json.loads(result.stdout)["status"], "refused")
        finally:
            enabled = self._set_stanza(
                "",
                "recovery",
                {
                    "enabled": "1",
                    "management_uri": MGMT,
                    "ca_file": SERVER_CA,
                },
            )
            self._docker_write(LOCAL_FILES[0], enabled.encode())

    def test_sendalert_invokes_the_packaged_action_with_owner_session(self):
        before = self._noop_audits()
        self.lab.search(
            '| makeresults | eval name="ADM - Identity builder" '
            "| sendalert adm_recovery"
        )
        deadline = time.time() + 120
        while time.time() < deadline:
            if self._noop_audits() > before:
                return
            time.sleep(2)
        self.fail("sendalert did not produce a recovery audit record")

    def test_unrecoverable_v2_detector_rows_do_not_block_v1_fallback(self):
        macro_path = (
            "/servicesNS/nobody/splunk_adm/configs/conf-macros/adm_health_missed_slots"
        )
        original = self.lab._json("GET", macro_path)["entry"][0]["content"][
            "definition"
        ]
        now = int(time.time())
        definition = (
            'makeresults count=3 | streamstats count AS n | eval reason="missed_slot", '
            'name=case(n==1, "ADM - Conversation rollup v2", '
            'n==2, "ADM - Application catalog v2", n==3, "ADM - Identity builder"), '
            f"scheduled_time=if(n==3, {now - 600}, {now - 3600}) "
            "| fields name scheduled_time reason"
        )
        try:
            self.lab._json("POST", macro_path, {"definition": definition})
            self.lab._json("GET", "/servicesNS/nobody/splunk_adm/admin/macros/_reload")
            result = self._run_entrypoint(
                self._session_key(), "ADM - Conversation rollup v2"
            )
            output = json.loads(result.stdout)
            self.assertNotEqual(output.get("reason"), "unknown target", output)
            self.assertEqual(output.get("name"), "ADM - Identity builder", output)
            self.assertIn(output["status"], ("noop", "recovered"), output)
        finally:
            self.lab._json("POST", macro_path, {"definition": original})
            self.lab._json("GET", "/servicesNS/nobody/splunk_adm/admin/macros/_reload")

    def test_packaged_entrypoint_recovers_one_builder_slot(self):
        target = "ADM - Service binding"
        now = int(time.time())
        if (now - 120) % 300 > 270:
            time.sleep(31)
            now = int(time.time())
        last = now - 1 - ((now - 1 - 120) % 300)
        slots = (last - 900, last - 300, last)
        definition = (
            'makeresults | eval savedsearch_name="'
            + target
            + '", status="success", sid="scheduler__synthetic", '
            'scheduled_time=split("'
            + ";".join(str(slot) for slot in slots)
            + '", ";") | mvexpand scheduled_time | eval scheduled_time=tonumber(scheduled_time) | fields '
            "savedsearch_name scheduled_time status sid"
        )
        macro_path = "/servicesNS/nobody/splunk_adm/configs/conf-macros/adm_recovery_scheduler_history"
        target_path = "/servicesNS/nobody/splunk_adm/saved/searches/" + target.replace(
            " ", "%20"
        )
        original_macro = self.lab._json("GET", macro_path)["entry"][0]["content"][
            "definition"
        ]
        original_target = self.lab._json("GET", target_path)["entry"][0]["content"]
        originals = {
            key: str(int(original_target[key] in (True, 1, "1")))
            for key in ("disabled", "is_scheduled")
        }
        before = {
            path: {
                row["_key"]
                for row in self._collection_records(path)
                if row.get("name") == target
            }
            for path in (STATE_PATH, AUDIT_PATH)
        }
        try:
            self.lab._json("POST", macro_path, {"definition": definition})
            self.lab._json("GET", "/servicesNS/nobody/splunk_adm/admin/macros/_reload")
            self.lab._json("POST", target_path, {"disabled": "0", "is_scheduled": "1"})
            result = self._run_entrypoint(self._session_key(), target)
            self.assertEqual(
                result.returncode, 0, result.stdout.decode() + result.stderr.decode()
            )
            output = json.loads(result.stdout)
            self.assertEqual(output["status"], "recovered", output)
            self.assertEqual(output["name"], target)
            self.assertEqual(output["slots"], [last - 600], output)
            slot_rows = [
                row
                for row in self._collection_records(STATE_PATH)
                if row.get("name") == target and row["_key"] not in before[STATE_PATH]
            ]
            self.assertEqual(len(slot_rows), 1, slot_rows)
            self.assertEqual(slot_rows[0].get("state"), "recovered")
        finally:
            self.lab._json("POST", target_path, originals)
            for path, keys in before.items():
                for row in self._collection_records(path):
                    if row.get("name") == target and row["_key"] not in keys:
                        self._delete_record(path, row["_key"])
            self.lab._json("POST", macro_path, {"definition": original_macro})
            self.lab._json("GET", "/servicesNS/nobody/splunk_adm/admin/macros/_reload")


if __name__ == "__main__":
    unittest.main()
