#!/usr/bin/env python3
"""Rehearse cold case/ledger recovery using only exact new disposable labs.

This is an installed synthetic rehearsal, not a production backup command.
It creates three fixed task namespaces, runs one heavy container at a time,
and removes only verified owned resources, including on failure.
"""

from __future__ import annotations

import argparse
from contextlib import ExitStack, closing
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import ssl
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "tests/splunk"), str(ROOT / "tools")]
from lab_lock import LabLock  # noqa: E402
from case_recovery_snapshot import (  # noqa: E402
    SnapshotError,
    create_snapshot,
    prepare_restore,
    schema_descriptor,
    validate_snapshot,
)
from check_release import check_release  # noqa: E402
from case_recovery_lab import TASKS  # noqa: E402

IMAGE = "splunk/splunk@sha256:9280f9ce267b212e5596aa1832cdfd3f9be886c378da35ebc87499323ee447a4"
LIFETIME = 2700
VOLUME_BUDGET = 8 * 1024**3
MIN_HOST_FREE = 12 * 1024**3
PORTS = {
    "source": (30900, 30989, 30988),
    "occupied": (31900, 31989, 31988),
    "target": (32900, 32989, 32988),
}
SOURCES = (
    "tools/rehearse_case_recovery.py",
    "tools/case_recovery_snapshot.py",
    "tools/lab_lock.py",
    "tools/stage_lab_package.py",
    "tools/check_release.py",
    "tests/splunk/lab.py",
    "tests/splunk/lab.sh",
    "tests/splunk/lab_tls.py",
    "tests/splunk/web_session.py",
    "tests/splunk/test_cases_endpoint.py",
    "tests/splunk/case_recovery_lab.py",
    "tests/splunk/case_recovery_native.py",
    "tests/splunk/case_recovery_fixture.py",
)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def canonical(data):
    return json.dumps(
        data, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()


def private_directory(path):
    path = Path(path)
    info = path.lstat()
    if (
        not path.is_absolute()
        or path.is_symlink()
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o700
        or any((p / ".git").exists() for p in (path, *path.parents))
    ):
        raise RuntimeError("protected external task directory required")
    return path


class Rehearsal:
    def __init__(self, args):
        self.args = args
        self.runtime = private_directory(args.runtime)
        if any(self.runtime.iterdir()):
            raise RuntimeError("a new empty runtime directory is required")
        self.out = self.runtime / "outputs"
        self.out.mkdir(mode=0o700)
        self.started, self.cancelled = time.monotonic(), False
        self.envs, self.created, self.samples = {}, set(), {}
        self.purge_attempts = {}
        self.hashes = {p: sha(ROOT / p) for p in SOURCES}
        self.receipt = {
            "schema": 1,
            "status": "preflight",
            "native_resource_qualification": False,
            "scope": "Synthetic installed same-build cold cases+ledger recovery only; no source capture, baseline/KV/platform backup, live-writer backup or job reconciliation",
            "image": IMAGE,
            "package_sha256": args.package_sha256,
            "lifetime_seconds": LIFETIME,
            "aggregate_named_volume_budget_bytes": VOLUME_BUDGET,
            "disk_enforcement": "cooperative running-volume phase samples and host free-space checks; not a filesystem quota; excludes image cache, writable layers and logs",
            "source_hashes": self.hashes,
            "phases": {},
            "labs": {},
            "cleanup": {},
        }
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(sig, self._cancel)

    def _cancel(self, _sig, _frame):
        self.cancelled = True

    def persist(self):
        target = self.out / "recovery-receipt.json"
        temp = target.with_suffix(".tmp")
        fd = os.open(temp, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump(self.receipt, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        temp.replace(target)
        fd = os.open(self.out, os.O_RDONLY)
        os.fsync(fd)
        os.close(fd)

    def check_time(self):
        if self.cancelled or time.monotonic() - self.started >= LIFETIME:
            raise RuntimeError("recovery rehearsal cancelled or lifetime exhausted")

    def reporting_failure(self, exc):
        self.receipt["status"] = "failed_or_uncertain"
        self.receipt.setdefault("reporting_errors", []).append(type(exc).__name__)

    def persist_cleanup(self):
        # Evidence storage failure cannot prevent an owned-resource cleanup.
        try:
            self.persist()
        except Exception as exc:
            self.reporting_failure(exc)

    def run(self, phase, kind, argv, timeout=300, *, cleanup=False):
        if not cleanup:
            self.check_time()
        self.receipt["phases"][phase] = {"state": "started"}
        (self.persist_cleanup if cleanup else self.persist)()
        try:
            fd = os.open(
                self.out / (phase + ".log"), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600
            )
        except OSError as exc:
            if not cleanup:
                raise
            self.reporting_failure(exc)
            fd = os.open(os.devnull, os.O_WRONLY)
        with os.fdopen(fd, "wb") as log:
            child = subprocess.Popen(
                argv,
                cwd=ROOT,
                env=self.envs[kind],
                stdout=log,
                stderr=log,
                start_new_session=True,
            )
            deadline = time.monotonic() + timeout
            if not cleanup:
                deadline = min(deadline, self.started + LIFETIME)
            while child.poll() is None:
                if time.monotonic() >= deadline or (self.cancelled and not cleanup):
                    try:
                        os.killpg(child.pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass
                    try:
                        child.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        pass
                    try:
                        os.killpg(child.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    child.wait()
                    self.receipt["phases"][phase] = {
                        "state": "uncertain_timeout_or_cancel",
                        "returncode": child.returncode,
                    }
                    (self.persist_cleanup if cleanup else self.persist)()
                    raise RuntimeError("rehearsal phase cancelled or timed out")
                time.sleep(0.2)
            # A completed leader does not prove its descendants have stopped.
            try:
                os.killpg(child.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            time.sleep(0.05)
            try:
                os.killpg(child.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        self.receipt["phases"][phase] = {
            "state": "completed",
            "returncode": child.returncode,
        }
        (self.persist_cleanup if cleanup else self.persist)()
        if child.returncode:
            raise RuntimeError("rehearsal phase failed: " + phase)

    def docker(self, *args):
        return json.loads(
            subprocess.check_output(
                ["docker", *args], env=self.envs["source"], timeout=30
            )
        )

    def helper(self, phase, kind, action, *args, timeout=300):
        self.run(
            phase,
            kind,
            [
                sys.executable,
                str(ROOT / "tests/splunk/case_recovery_lab.py"),
                action,
                *map(str, args),
            ],
            timeout,
        )

    def preflight(self):
        endpoint = subprocess.check_output(
            ["docker", "context", "inspect", "--format", "{{.Endpoints.docker.Host}}"],
            text=True,
            timeout=30,
        ).strip()
        if endpoint != self.args.socket or not endpoint.startswith("unix:///"):
            raise RuntimeError("verified local Docker context/socket mismatch")
        socket_info = os.stat(endpoint[len("unix://") :])
        if not stat.S_ISSOCK(socket_info.st_mode) or socket_info.st_uid != os.getuid():
            raise RuntimeError("Docker socket is not owned by this user")
        if sha(self.args.package) != self.args.package_sha256:
            raise RuntimeError("frozen package checksum differs")
        # Verify the exact retained artifact, never a source-tree installation.
        check_release(Path(self.args.package).parent, ROOT / "package.json")
        retained = self.out / "frozen-package"
        retained.mkdir(mode=0o700)
        archive = retained / Path(self.args.package).name
        shutil.copyfile(self.args.package, archive)
        archive.chmod(0o600)
        if sha(archive) != self.args.package_sha256:
            raise RuntimeError("package changed while making private retained copy")
        checksum = Path(str(archive) + ".sha256")
        checksum.write_text(f"{self.args.package_sha256}  {archive.name}\n")
        checksum.chmod(0o600)
        check_release(retained, ROOT / "package.json")
        for env in self.envs.values():
            env["ADM_LAB_PACKAGE"] = str(archive)
        self.receipt["retained_archive"] = str(archive)
        info = self.docker("info", "--format", "{{json .}}")
        if (
            info["OSType"] != "linux"
            or info["NCPU"] < 4
            or info["MemTotal"] < 12 * 1024**3
        ):
            raise RuntimeError("insufficient configured engine resources")
        self.receipt["engine"] = {
            k: info[k]
            for k in (
                "Name",
                "OSType",
                "Architecture",
                "NCPU",
                "MemTotal",
                "ServerVersion",
            )
        }
        self.receipt["host_python"] = sys.version.split()[0]
        self.receipt["socket"] = endpoint
        image = self.docker("image", "inspect", IMAGE)[0]
        if (
            IMAGE not in image.get("RepoDigests", [])
            or image.get("Os") != "linux"
            or image.get("Architecture") != "amd64"
        ):
            raise RuntimeError("reviewed Linux/amd64 image must already be cached")
        self.receipt["cached_image"] = {
            key: image[key] for key in ("Id", "Os", "Architecture", "RepoDigests")
        }
        self.receipt["host_disk_free_before"] = shutil.disk_usage(self.runtime).free
        if self.receipt["host_disk_free_before"] < MIN_HOST_FREE:
            raise RuntimeError("insufficient host disk reserve")
        for kind in TASKS:
            task, name = TASKS[kind]
            for resource, names in (
                ("container", [name]),
                ("network", [name + "-net"]),
                ("volume", [name + "-etc", name + "-var"]),
            ):
                inventory = subprocess.check_output(
                    [
                        "docker",
                        resource,
                        "ls",
                        *(
                            ["-a", "--format", "{{.Names}}"]
                            if resource == "container"
                            else ["--format", "{{.Name}}"]
                        ),
                    ],
                    env=self.envs[kind],
                    text=True,
                    timeout=30,
                ).splitlines()
                if set(names) & set(inventory):
                    raise RuntimeError(
                        "refusing to adopt an existing recovery namespace"
                    )
            for port in PORTS[kind]:
                with socket.socket() as probe:
                    probe.bind(("127.0.0.1", port))
        self.persist()

    def memory_and_single_active(self):
        # Read only resource summaries; never inspect or alter peer configuration.
        rows = subprocess.check_output(
            ["docker", "stats", "--no-stream", "--format", "{{.MemUsage}}"],
            env=self.envs["source"],
            text=True,
            timeout=30,
        ).splitlines()
        used = 0
        units = {"B": 1, "KiB": 1024, "MiB": 1024**2, "GiB": 1024**3}
        for row in rows:
            match = re.fullmatch(r"([0-9.]+)(B|KiB|MiB|GiB) / .+", row)
            if not match:
                raise RuntimeError("cannot establish current memory use")
            used += int(float(match[1]) * units[match[2]])
        if used + 10 * 1024**3 > self.receipt["engine"]["MemTotal"]:
            raise RuntimeError("queue heavy lab: insufficient available engine memory")
        self.receipt.setdefault("memory_samples_bytes", []).append(used)
        for kind in self.created:
            ident = self.receipt["labs"].get(kind, {}).get("id")
            if ident and self.docker("inspect", ident)[0]["State"]["Running"]:
                raise RuntimeError(
                    "only one recovery Splunk container may run at a time"
                )
        if shutil.disk_usage(self.runtime).free < MIN_HOST_FREE:
            raise RuntimeError("host disk reserve exhausted")

    def up(self, kind):
        self.memory_and_single_active()
        if sha(self.envs[kind]["ADM_LAB_PACKAGE"]) != self.args.package_sha256:
            raise RuntimeError("private retained package checksum differs")
        self.created.add(kind)
        self.run(kind + "-up", kind, ["bash", "tests/splunk/lab.sh", "up"], 1200)
        target = self.docker("inspect", TASKS[kind][1])[0]
        self.receipt["labs"][kind] = {
            "id": target["Id"],
            "image": target["Image"],
            "configured_image": target["Config"]["Image"],
            "labels": {
                k: v
                for k, v in target["Config"]["Labels"].items()
                if k.startswith("org.splunk-adm.")
            },
            "mounts": [
                {k: m[k] for k in ("Type", "Name", "Destination")}
                for m in target["Mounts"]
            ],
            "ports": target["HostConfig"]["PortBindings"],
            "limits": {
                k: target["HostConfig"][k]
                for k in ("NanoCpus", "Memory", "MemorySwap", "PidsLimit", "LogConfig")
            },
        }
        self.persist()
        self.helper(kind + "-web-before", kind, "ready")
        self.tls(kind, "before_install")
        self.sample(kind)
        if sha(self.envs[kind]["ADM_LAB_PACKAGE"]) != self.args.package_sha256:
            raise RuntimeError("private retained package changed before installation")
        self.run(
            kind + "-install", kind, ["bash", "tests/splunk/lab.sh", "install"], 900
        )
        self.helper(kind + "-web-after", kind, "ready")
        self.tls(kind, "after_install")
        self.sample(kind)

    def tls(self, kind, phase):
        self.check_time()
        self.run(
            kind + "-tls-guard-before-" + phase,
            kind,
            [sys.executable, "tests/splunk/lab.py", "verify-target"],
            30,
        )
        env = self.envs[kind]
        public_ca = Path(env["ADM_LAB_SECRETS"] + ".tls/ca.pem")
        good, wrong = (
            ssl.create_default_context(cafile=str(public_ca)),
            ssl.create_default_context(),
        )
        outcome = {}
        for name, port in zip(("web", "management", "hec"), PORTS[kind]):
            for label, context, host in (
                ("trusted", good, "127.0.0.1"),
                ("wrong_ca", wrong, "127.0.0.1"),
                ("wrong_hostname", good, "wrong.example"),
            ):
                try:
                    with socket.create_connection(
                        ("127.0.0.1", port), timeout=5
                    ) as raw:
                        with context.wrap_socket(raw, server_hostname=host):
                            pass
                except ssl.SSLCertVerificationError:
                    if label == "trusted":
                        raise
                else:
                    if label != "trusted":
                        raise RuntimeError("negative TLS accepted")
            outcome[name] = {
                "trusted": True,
                "wrong_ca_rejected": True,
                "wrong_hostname_rejected": True,
            }
        self.receipt["labs"][kind].setdefault("tls", {})[phase] = outcome
        self.run(
            kind + "-tls-guard-after-" + phase,
            kind,
            [sys.executable, "tests/splunk/lab.py", "verify-target"],
            30,
        )
        self.persist()

    def sample(self, kind):
        ident = self.receipt["labs"][kind]["id"]
        data = subprocess.check_output(
            [
                "docker",
                "exec",
                "--user",
                "root",
                ident,
                "du",
                "-sk",
                "/opt/splunk/etc",
                "/opt/splunk/var",
            ],
            env=self.envs[kind],
            text=True,
            timeout=30,
        )
        self.samples[kind] = (
            sum(int(row.split()[0]) for row in data.splitlines()) * 1024
        )
        self.receipt.setdefault("volume_samples", []).append(
            {
                "kind": kind,
                "bytes": self.samples[kind],
                "aggregate_live_volumes_bytes": sum(self.samples.values()),
            }
        )
        self.persist()
        if sum(self.samples.values()) > VOLUME_BUDGET:
            raise RuntimeError("aggregate named-volume budget exhausted")

    def purge(self, kind):
        attempt = self.purge_attempts.get(kind, 0) + 1
        self.purge_attempts[kind] = attempt
        history = self.receipt.setdefault("cleanup_attempts", {}).setdefault(kind, [])
        history.append({"attempt": attempt, "state": "started"})
        self.persist_cleanup()
        self.run(
            f"{kind}-purge-{attempt}",
            kind,
            ["bash", "tests/splunk/lab.sh", "purge"],
            180,
            cleanup=True,
        )
        name = TASKS[kind][1]
        outcome = {}
        for resource, names in (
            ("container", [name]),
            ("network", [name + "-net"]),
            ("volume", [name + "-etc", name + "-var"]),
        ):
            inventory = subprocess.check_output(
                [
                    "docker",
                    resource,
                    "ls",
                    *(
                        ["-a", "--format", "{{.Names}}"]
                        if resource == "container"
                        else ["--format", "{{.Name}}"]
                    ),
                ],
                env=self.envs[kind],
                text=True,
                timeout=30,
            ).splitlines()
            outcome[resource + "_absent"] = not bool(set(names) & set(inventory))
        secret = Path(self.envs[kind]["ADM_LAB_SECRETS"])
        outcome.update(
            credentials_absent=not secret.exists(),
            tls_absent=not Path(str(secret) + ".tls").exists(),
        )
        deadline = time.monotonic() + 90
        while True:
            try:
                for port in PORTS[kind]:
                    with socket.socket() as probe:
                        probe.bind(("127.0.0.1", port))
                outcome["ports_released"] = True
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(1)
        self.receipt["cleanup"][kind] = outcome
        history[-1].update(state="verified" if all(outcome.values()) else "incomplete")
        self.persist_cleanup()
        if not all(outcome.values()):
            raise RuntimeError("owned resource cleanup incomplete")
        self.created.discard(kind)
        self.samples.pop(kind, None)

    def negative_bundles(self, schemas, provenance, digest):
        import sqlite3

        for label in ("corrupt", "future"):
            path = self.out / (label + "-bundle")
            shutil.copytree(self.out / "snapshot", path)
            database = path / "cases.sqlite"
            candidate_digest = digest
            if label == "corrupt":
                data = database.read_bytes()
                database.write_bytes(b"X" + data[1:])
            else:
                with closing(sqlite3.connect(database)) as db:
                    db.execute("PRAGMA user_version=999")
                    db.commit()
                manifest = json.loads((path / "manifest.json").read_text())
                manifest["files"]["cases.sqlite"].update(
                    sha256=sha(database),
                    size=database.stat().st_size,
                    schema=schema_descriptor(database),
                )
                data = canonical(manifest)
                (path / "manifest.json").write_bytes(data)
                candidate_digest = hashlib.sha256(data).hexdigest()
            destination = self.out / (label + "-must-not-be-created")
            try:
                prepare_restore(
                    path,
                    destination,
                    expected_manifest_sha256=candidate_digest,
                    expected_schemas=schemas,
                    expected_provenance=provenance,
                )
            except SnapshotError as exc:
                reason = str(exc)
            else:
                raise RuntimeError("invalid backup was accepted")
            if destination.exists():
                raise RuntimeError("invalid restore created destination")
            self.receipt.setdefault("negative_backups", {})[label] = {
                "refused": True,
                "destination_absent": True,
                "reason": reason,
            }
            self.persist()

    def exercise(self):
        helper = ROOT / "tests/splunk/case_recovery_fixture.py"
        source_meta = self.out / "source.json"
        self.up("source")
        self.run(
            "source-restart-notes",
            "source",
            [sys.executable, str(helper), "source"],
            900,
        )
        metadata = json.loads(source_meta.read_text())
        self.sample("source")
        self.helper(
            "source-live-refusal",
            "source",
            "live-refusal",
            "--output",
            self.out / "source-live-refusal.json",
        )
        self.helper("source-stop", "source", "stop")
        self.helper(
            "source-cold-export",
            "source",
            "export",
            "--metadata",
            source_meta,
            "--directory",
            self.out / "cold-source",
            "--output",
            self.out / "cold-source-hashes.json",
        )
        schemas = metadata["native"]["schemas"]
        provenance = {
            "application_sha256": self.args.package_sha256,
            "image": IMAGE,
            "source_container_id": self.receipt["labs"]["source"]["id"],
            "source_task": TASKS["source"][0],
            "fixed_path": "/opt/splunk/var/lib/splunk/splunk_adm_investigations",
        }
        digest = create_snapshot(
            self.out / "cold-source",
            self.out / "snapshot",
            expected_schemas=schemas,
            provenance=provenance,
        )
        self.receipt["snapshot_manifest_sha256"] = digest
        self.receipt["snapshot_provenance"] = provenance
        self.receipt["trusted_schemas"] = schemas
        self.persist()
        summary = prepare_restore(
            self.out / "snapshot",
            self.out / "prepared",
            expected_manifest_sha256=digest,
            expected_schemas=schemas,
            expected_provenance=provenance,
        )
        for name, value in summary["files"].items():
            if value["tables"] != metadata["native"]["databases"][name]["tables"]:
                raise RuntimeError("cold snapshot differs from installed logical rows")
        self.write_state("summary.json", summary)
        self.up("occupied")
        self.helper(
            "occupied-marker",
            "occupied",
            "occupied",
            "--output",
            self.out / "occupied-native.json",
        )
        self.helper("occupied-stop", "occupied", "stop")
        self.helper(
            "occupied-refusal",
            "occupied",
            "occupied-refusal",
            "--metadata",
            self.out / "occupied-native.json",
            "--summary",
            self.out / "summary.json",
            "--directory",
            self.out / "prepared",
            "--output",
            self.out / "occupied-refusal.json",
        )
        self.purge("occupied")
        self.up("target")
        self.helper(
            "target-identity",
            "target",
            "identity",
            "--output",
            self.out / "target-identity.json",
        )
        identity = json.loads((self.out / "target-identity.json").read_text())
        if identity["schemas"] != schemas or (identity["uid"], identity["gid"]) != (
            metadata["native"]["uid"],
            metadata["native"]["gid"],
        ):
            raise RuntimeError("fresh target schema or service identity differs")
        self.helper("target-stop", "target", "stop")
        self.helper(
            "target-absent-before",
            "target",
            "absent",
            "--output",
            self.out / "target-absent-before.json",
        )
        self.negative_bundles(schemas, provenance, digest)
        self.helper(
            "target-absent-after",
            "target",
            "absent",
            "--output",
            self.out / "target-absent-after.json",
        )
        self.helper(
            "target-restore",
            "target",
            "restore",
            "--metadata",
            self.out / "target-identity.json",
            "--summary",
            self.out / "summary.json",
            "--directory",
            self.out / "prepared",
            "--output",
            self.out / "target-restored.json",
        )
        self.helper(
            "target-cold-check",
            "target",
            "export",
            "--metadata",
            self.out / "target-identity.json",
            "--directory",
            self.out / "cold-target",
            "--output",
            self.out / "cold-target-hashes.json",
        )
        for name, value in summary["files"].items():
            if sha(self.out / "cold-target" / name) != value["sha256"]:
                raise RuntimeError("restored native filesystem bytes differ")
        self.run(
            "target-start-restored",
            "target",
            [sys.executable, "tests/splunk/lab.py", "start-container"],
            300,
        )
        self.run(
            "target-management-ready",
            "target",
            [sys.executable, "tests/splunk/lab.py", "wait"],
            900,
        )
        self.helper("target-web-restored", "target", "ready")
        self.tls("target", "after_restore_restart")
        self.run(
            "target-restored-notes",
            "target",
            [sys.executable, str(helper), "target"],
            600,
        )
        self.sample("target")
        for kind in ("source", "target"):
            journal = json.loads(
                Path(self.envs[kind]["ADM_LAB_WEB_RECEIPT"]).read_text()
            )
            if any(r["state"] != "response_received" for r in journal["requests"]):
                raise RuntimeError("a case mutation outcome remains unresolved")
            if journal["fixture"].get("cleanup_verified") is not True:
                raise RuntimeError("fixture cleanup was not verified")
            self.receipt["labs"][kind]["fixture"] = {
                "cleanup_verified": True,
                "requests_with_responses": len(journal["requests"]),
                "journal_sha256": sha(Path(self.envs[kind]["ADM_LAB_WEB_RECEIPT"])),
            }
        if {p: sha(ROOT / p) for p in SOURCES} != self.hashes:
            raise RuntimeError("rehearsal source changed during execution")
        if sha(self.envs["source"]["ADM_LAB_PACKAGE"]) != self.args.package_sha256:
            raise RuntimeError("private retained package changed during rehearsal")
        validate_snapshot(
            self.out / "snapshot",
            expected_manifest_sha256=digest,
            expected_schemas=schemas,
            expected_provenance=provenance,
        )
        self.receipt["status"] = "tests_passed"
        self.persist()

    def write_state(self, name, value):
        path = self.out / name
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w") as stream:
            json.dump(value, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        fd = os.open(self.out, os.O_RDONLY)
        os.fsync(fd)
        os.close(fd)

    def execute(self):
        base_env = {
            k: v
            for k, v in os.environ.items()
            if not k.startswith("ADM_LAB_") and k != "DOCKER_CONTEXT"
        }
        previous = os.environ.copy()
        try:
            with ExitStack() as locks:
                for kind in sorted(TASKS):
                    task, name = TASKS[kind]
                    web, management, hec = PORTS[kind]
                    directory = self.runtime / kind
                    directory.mkdir(mode=0o700)
                    cfg = {
                        **base_env,
                        "ADM_LAB": "1",
                        "ADM_LAB_CASE_RECOVERY": "1",
                        "ADM_LAB_WEB_TLS": "1",
                        "ADM_LAB_TASK": task,
                        "ADM_LAB_NAME": name,
                        "ADM_LAB_WEB_PORT": str(web),
                        "ADM_LAB_MGMT_PORT": str(management),
                        "ADM_LAB_HEC_PORT": str(hec),
                        "ADM_LAB_SECRETS": str(directory / "credentials"),
                        "ADM_LAB_EXTRACTED": str(Path(self.args.extracted).resolve()),
                        "ADM_LAB_PACKAGE": str(Path(self.args.package).resolve()),
                        "ADM_LAB_WEB_RECEIPT": str(directory / "web-journal.json"),
                        "ADM_RECOVERY_METADATA": str(self.out / "source.json"),
                        "DOCKER_HOST": self.args.socket,
                        "PATH": str(Path(sys.executable).parent)
                        + os.pathsep
                        + os.environ["PATH"],
                    }
                    # Preserve earlier locks, but pass each child its own lock token.
                    for key, value in cfg.items():
                        os.environ[key] = value
                    os.environ.pop("DOCKER_CONTEXT", None)
                    locks.enter_context(LabLock(ROOT))
                    self.envs[kind] = {
                        **cfg,
                        **{
                            k: os.environ[k]
                            for k in (
                                "SPLUNK_ADM_LAB_LOCK_TOKEN",
                                "SPLUNK_ADM_LAB_LOCK_PATH",
                                "SPLUNK_ADM_LAB_LOCK_PID",
                            )
                        },
                    }
                self.preflight()
                try:
                    self.exercise()
                except BaseException as exc:
                    self.receipt["status"] = "failed_or_uncertain"
                    self.receipt["error_type"] = type(exc).__name__
                    self.receipt["error"] = str(exc)[:500]
                    self.persist_cleanup()
                finally:
                    for kind in sorted(tuple(self.created)):
                        try:
                            self.purge(kind)
                        except BaseException as exc:
                            self.receipt["cleanup_attempts"][kind][-1].update(
                                state="uncertain", error_type=type(exc).__name__
                            )
                            self.receipt["cleanup"][kind] = {
                                "error_type": type(exc).__name__
                            }
                            self.persist_cleanup()
                    self.receipt["elapsed_seconds"] = round(
                        time.monotonic() - self.started, 2
                    )
                    self.persist_cleanup()
                if self.receipt["status"] != "tests_passed" or self.created:
                    raise RuntimeError(
                        "rehearsal failed or cleanup remains uncertain; retain receipts"
                    )
        finally:
            os.environ.clear()
            os.environ.update(previous)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", required=True)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--package-sha256", required=True)
    parser.add_argument("--extracted", type=Path, required=True)
    parser.add_argument("--socket", required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{64}", args.package_sha256):
        parser.error("invalid package SHA-256")
    Rehearsal(args).execute()


if __name__ == "__main__":
    main()
