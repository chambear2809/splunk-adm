#!/usr/bin/env python3
"""Exact disposable local lab for synthetic current case source capture qualification."""

import argparse
import configparser
import json
import os
import re
from pathlib import Path
import shutil
import signal
import socket
import ssl
import stat
import subprocess
import sys
import tarfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "tools"), str(ROOT / "tests/splunk")]

from lab_lock import LabLock  # noqa: E402
from check_release import check_release  # noqa: E402
from rehearse_case_recovery import (  # noqa: E402
    IMAGE,
    LIFETIME,
    MIN_HOST_FREE,
    Rehearsal,
    private_directory,
    sha,
)

TASK = "cases-source-20261118"
NAME = "adm-" + TASK
PORTS = (35000, 35089, 35088)
DISK_BUDGET = 4 * 1024**3
FILES = (
    "tools/rehearse_case_source_capture.py",
    "tools/rehearse_case_recovery.py",
    "tests/splunk/case_source_capture.py",
    "tests/splunk/case_source_faults.py",
    "tests/splunk/case_source_native.py",
    "tests/splunk/case_request_lab.py",
    "tests/splunk/case_request_native.py",
    "tests/splunk/case_request_fault_hook.py",
    "tests/test_case_request_supervisor.py",
    "tests/splunk/test_qualified_summaries.py",
    "tests/splunk/test_cases_endpoint.py",
    "tests/test_qualified_rollup.py",
    "tests/splunk/lab.py",
    "tests/splunk/lab.sh",
    "tests/splunk/lab_tls.py",
    "tools/lab_lock.py",
    "tools/check_release.py",
    "tools/stage_lab_package.py",
)


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def memory_reserve(rows, engine_total):
    units = {"B": 1, "KiB": 1024, "MiB": 1024**2, "GiB": 1024**3}
    used = 0
    for row in rows:
        match = re.fullmatch(r"([0-9.]+)(B|KiB|MiB|GiB) / .+", row)
        if not match:
            raise RuntimeError("unknown peer memory use")
        used += int(float(match[1]) * units[match[2]])
    if used + 10 * 1024**3 > engine_total:
        raise RuntimeError("queue heavy lab: peer memory reserve unavailable")
    return used


def wait_tls_ready(port, context, check_time):
    """Allow startup EOF/refusal, but never retry a certificate rejection."""
    deadline = time.monotonic() + 60
    retries = 0
    while True:
        check_time()
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
                with context.wrap_socket(raw, server_hostname="127.0.0.1"):
                    return retries
        except ssl.SSLCertVerificationError:
            raise
        except OSError:
            if time.monotonic() >= deadline:
                raise
            retries += 1
            time.sleep(0.5)


class SourceRehearsal:
    # Reuse the already reviewed parent phase runner, including process-group
    # retirement and cleanup even when log/receipt storage is unavailable.
    run = Rehearsal.run
    persist_cleanup = Rehearsal.persist_cleanup
    reporting_failure = Rehearsal.reporting_failure
    check_time = Rehearsal.check_time
    _cancel = Rehearsal._cancel

    def persist(self):
        target = self.out / "source-receipt.json"
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

    def __init__(self, args):
        self.args = args
        self.runtime = private_directory(args.runtime)
        if any(self.runtime.iterdir()):
            raise RuntimeError("new empty private runtime required")
        self.out = self.runtime / "outputs"
        self.out.mkdir(mode=0o700)
        # Persist the evidence-directory entry and the caller-created runtime
        # before any external mutation or durable request journal is possible.
        sync_directory(self.runtime)
        sync_directory(self.runtime.parent)
        self.started, self.cancelled, self.created = time.monotonic(), False, False
        self.envs = {}
        self.receipt = {
            "schema": 1,
            "status": "preflight",
            "task": TASK,
            "lab": NAME,
            "scope": "Installed synthetic source capture attempt only; no native AMD64 resources, real sources, Cloud/SHC or production qualification",
            "image": IMAGE,
            "package_sha256": args.package_sha256,
            "lifetime_seconds": LIFETIME,
            "named_volume_budget_bytes": DISK_BUDGET,
            "disk_enforcement": "cooperative phase du samples; not a filesystem quota; excludes cached image, writable layer and logs",
            "source_hashes": {p: sha(ROOT / p) for p in FILES},
            "phases": {},
            "cleanup": {},
        }
        if args.expect_unsupported_helper:
            self.receipt["scope"] = (
                "Installed unsupported-helper fail-closed notes behavior only; "
                "no positive source capture or failure-reconciliation qualification"
            )
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(sig, self._cancel)

    def docker(self, *args):
        return subprocess.check_output(
            ["docker", *args], env=self.envs["source"], timeout=30, text=True
        )

    def preflight(self):
        endpoint = self.docker(
            "context", "inspect", "--format", "{{.Endpoints.docker.Host}}"
        ).strip()
        if endpoint != self.args.socket or not endpoint.startswith("unix:///"):
            raise RuntimeError("verified local Docker context/socket required")
        info = os.stat(endpoint[len("unix://") :])
        if not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid():
            raise RuntimeError("user-owned local Docker socket required")
        engine = json.loads(self.docker("info", "--format", "{{json .}}"))
        if (
            engine["OSType"] != "linux"
            or engine["NCPU"] < 4
            or engine["MemTotal"] < 12 * 1024**3
        ):
            raise RuntimeError("insufficient configured engine resources")
        self.receipt["engine"] = {
            k: engine[k]
            for k in (
                "Name",
                "OSType",
                "Architecture",
                "NCPU",
                "MemTotal",
                "ServerVersion",
            )
        }
        image = json.loads(self.docker("image", "inspect", IMAGE))[0]
        if (
            IMAGE not in image.get("RepoDigests", [])
            or image["Architecture"] != "amd64"
            or image["Os"] != "linux"
        ):
            raise RuntimeError(
                "reviewed pinned Linux/amd64 image must already be cached"
            )
        for resource, names in (
            ("container", [NAME]),
            ("network", [NAME + "-net"]),
            ("volume", [NAME + "-etc", NAME + "-var"]),
        ):
            flags = (
                ["-a", "--format", "{{.Names}}"]
                if resource == "container"
                else ["--format", "{{.Name}}"]
            )
            if set(names) & set(self.docker(resource, "ls", *flags).splitlines()):
                raise RuntimeError("refusing existing task namespace")
        for port in PORTS:
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", port))
        if shutil.disk_usage(self.runtime).free < MIN_HOST_FREE:
            raise RuntimeError("insufficient host disk reserve")
        # Conservative reserve above the framework's fixed 8GiB container cap.
        rows = self.docker(
            "stats", "--no-stream", "--format", "{{.MemUsage}}"
        ).splitlines()
        used = memory_reserve(rows, engine["MemTotal"])
        self.receipt["peer_memory_bytes"] = used
        if sha(self.args.package) != self.args.package_sha256:
            raise RuntimeError("candidate package changed")
        retained = self.out / "frozen-package"
        retained.mkdir(mode=0o700)
        archive = retained / Path(self.args.package).name
        shutil.copyfile(self.args.package, archive)
        archive.chmod(0o600)
        if sha(archive) != self.args.package_sha256:
            raise RuntimeError("candidate changed during copy")
        checksum = Path(str(archive) + ".sha256")
        checksum.write_text(f"{self.args.package_sha256}  {archive.name}\n")
        checksum.chmod(0o600)
        check_release(retained, ROOT / "package.json")
        with tarfile.open(archive, "r:gz") as package:
            config = configparser.ConfigParser(interpolation=None)
            config.read_string(
                package.extractfile("splunk_adm/default/app.conf").read().decode()
            )
            self.receipt["expected_version"] = config.get("launcher", "version")
            self.receipt["expected_build"] = config.get("install", "build")
            self.expected_runtime = {
                m.name[len("splunk_adm/") :]: __import__("hashlib")
                .sha256(package.extractfile(m).read())
                .hexdigest()
                for m in package
                if m.isfile()
                and m.name.startswith("splunk_adm/bin/")
                and m.name.endswith(".py")
            }
        self.envs["source"]["ADM_LAB_PACKAGE"] = str(archive)
        self.persist()

    def tls(self, label):
        self.run(
            label + "-guard-before",
            "source",
            [sys.executable, "tests/splunk/lab.py", "verify-target"],
            30,
        )
        ca = Path(self.envs["source"]["ADM_LAB_SECRETS"] + ".tls/ca.pem")
        contexts = (
            ssl.create_default_context(cafile=str(ca)),
            ssl.create_default_context(),
        )
        retries = {}
        for port in PORTS:
            retries[str(port)] = wait_tls_ready(port, contexts[0], self.check_time)
            for kind, context, host in (
                ("trusted", contexts[0], "127.0.0.1"),
                ("wrong_ca", contexts[1], "127.0.0.1"),
                ("wrong_host", contexts[0], "wrong.example"),
            ):
                try:
                    with socket.create_connection(
                        ("127.0.0.1", port), timeout=5
                    ) as raw:
                        with context.wrap_socket(raw, server_hostname=host):
                            pass
                except ssl.SSLCertVerificationError:
                    if kind == "trusted":
                        raise
                else:
                    if kind != "trusted":
                        raise RuntimeError("negative TLS accepted")
        self.run(
            label + "-guard-after",
            "source",
            [sys.executable, "tests/splunk/lab.py", "verify-target"],
            30,
        )
        self.receipt.setdefault("tls", {})[label] = {
            "Web": "trusted/wrongCA/wrongHost passed",
            "management": "trusted/wrongCA/wrongHost passed",
            "HEC": "trusted/wrongCA/wrongHost passed",
        }
        self.receipt.setdefault("tls_readiness_retries", {})[label] = retries
        self.persist()

    def sample(self, label):
        if shutil.disk_usage(self.runtime).free < MIN_HOST_FREE:
            raise RuntimeError("host disk reserve exhausted")
        data = self.docker(
            "exec",
            "--user",
            "root",
            self.receipt["container_id"],
            "du",
            "-sk",
            "/opt/splunk/etc",
            "/opt/splunk/var",
        )
        size = sum(int(v.split()[0]) for v in data.splitlines()) * 1024
        self.receipt.setdefault("volume_samples", []).append(
            {"phase": label, "bytes": size}
        )
        self.persist()
        if size > DISK_BUDGET:
            raise RuntimeError("task volume budget exceeded")

    def exercise(self):
        self.created = True
        self.run("up", "source", ["bash", "tests/splunk/lab.sh", "up"], 1200)
        info = json.loads(self.docker("inspect", NAME))[0]
        self.receipt["container_id"] = info["Id"]
        self.receipt["resources"] = {
            "labels": {
                k: v
                for k, v in info["Config"]["Labels"].items()
                if k.startswith("org.splunk-adm.")
            },
            "mounts": [
                {k: m[k] for k in ("Type", "Name", "Destination")}
                for m in info["Mounts"]
            ],
            "ports": info["HostConfig"]["PortBindings"],
            "limits": {
                k: info["HostConfig"][k]
                for k in ("NanoCpus", "Memory", "MemorySwap", "PidsLimit", "LogConfig")
            },
        }
        self.tls("before_install")
        self.sample("before_install")
        self.run("install", "source", ["bash", "tests/splunk/lab.sh", "install"], 900)
        self.tls("after_install")
        self.sample("after_install")
        # Read only installed Python bytes; compare every installed bin Python
        # file against the retained archive before any source fixture runs.
        probe = (
            "import hashlib,json,pathlib; "
            "p=pathlib.Path('/opt/splunk/etc/apps/splunk_adm'); "
            "print(json.dumps({str(f.relative_to(p)):hashlib.sha256(f.read_bytes()).hexdigest() "
            "for f in (p/'bin').rglob('*.py') if f.is_file() and not f.is_symlink()}))"
        )
        self.run(
            "runtime-guard",
            "source",
            [sys.executable, "tests/splunk/lab.py", "verify-target"],
            30,
        )
        actual = json.loads(
            self.docker(
                "exec",
                "--user",
                "splunk",
                self.receipt["container_id"],
                "/opt/splunk/bin/splunk",
                "cmd",
                "python3.13",
                "-c",
                probe,
            )
        )
        if actual != self.expected_runtime:
            raise RuntimeError(
                "installed runtime differs from retained candidate archive"
            )
        self.receipt["runtime_sha256"] = actual
        self.persist()
        if self.args.expect_unsupported_helper:
            self.envs["source"]["ADM_LAB_EXPECT_UNSUPPORTED_CAPTURE"] = "1"
            self.run(
                "unsupported-helper",
                "source",
                [
                    sys.executable,
                    "-m",
                    "unittest",
                    "discover",
                    "-s",
                    "tests/splunk",
                    "-p",
                    "test_cases_endpoint.py",
                    "-k",
                    "unsupported_runtime_preflight",
                ],
                300,
            )
            log = (self.out / "unsupported-helper.log").read_text()
            if "Ran 1 test" not in log or "OK" not in log or "skipped" in log:
                raise RuntimeError("unsupported-helper test did not actually run")
            self.sample("unsupported-helper")
            if {p: sha(ROOT / p) for p in FILES} != self.receipt["source_hashes"]:
                raise RuntimeError("qualification source changed")
            self.receipt["unsupported_helper_verified"] = True
            self.receipt["positive_source_qualification"] = False
            self.receipt["status"] = "unsupported_helper_verified"
            self.persist()
            return
        self.run(
            "synthetic-source",
            "source",
            [sys.executable, "tests/splunk/case_source_capture.py"],
            900,
        )
        journal = self.out / "source-journal.jsonl"
        self.receipt["journal_sha256"] = sha(journal)
        self.sample("synthetic-source")
        self.envs["source"]["ADM_LAB_SOURCE_JOURNAL"] = str(
            self.out / "source-fault-journal.jsonl"
        )
        self.run(
            "synthetic-source-faults",
            "source",
            [sys.executable, "tests/splunk/case_source_faults.py"],
            900,
        )
        self.receipt["fault_journal_sha256"] = sha(
            self.out / "source-fault-journal.jsonl"
        )
        self.sample("synthetic-source-faults")
        if {p: sha(ROOT / p) for p in FILES} != self.receipt["source_hashes"]:
            raise RuntimeError("qualification source changed")
        if sha(self.envs["source"]["ADM_LAB_PACKAGE"]) != self.args.package_sha256:
            raise RuntimeError("retained archive changed")
        self.receipt["status"] = "tests_passed"
        self.persist()

    def cleanup(self):
        self.run(
            "purge",
            "source",
            ["bash", "tests/splunk/lab.sh", "purge"],
            180,
            cleanup=True,
        )
        outcome = {}
        for resource, names in (
            ("container", [NAME]),
            ("network", [NAME + "-net"]),
            ("volume", [NAME + "-etc", NAME + "-var"]),
        ):
            flags = (
                ["-a", "--format", "{{.Names}}"]
                if resource == "container"
                else ["--format", "{{.Name}}"]
            )
            outcome[resource + "_absent"] = not (
                set(names) & set(self.docker(resource, "ls", *flags).splitlines())
            )
        path = Path(self.envs["source"]["ADM_LAB_SECRETS"])
        outcome["credentials_absent"] = not path.exists()
        outcome["tls_absent"] = not Path(str(path) + ".tls").exists()
        deadline = time.monotonic() + 90
        while True:
            try:
                for port in PORTS:
                    with socket.socket() as probe:
                        probe.bind(("127.0.0.1", port))
                outcome["ports_released"] = True
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(1)
        self.receipt["cleanup"] = outcome
        self.persist_cleanup()
        if not all(outcome.values()):
            raise RuntimeError("owned cleanup incomplete")
        self.created = False

    def execute(self):
        previous = os.environ.copy()
        env = {
            k: v
            for k, v in previous.items()
            if not k.startswith("ADM_LAB_") and k != "DOCKER_CONTEXT"
        }
        env.update(
            ADM_LAB="1",
            ADM_LAB_WEB_TLS="1",
            ADM_LAB_SOURCE_CAPTURE="1",
            ADM_LAB_SOURCE_JOURNAL=str(self.out / "source-journal.jsonl"),
            ADM_LAB_TASK=TASK,
            ADM_LAB_NAME=NAME,
            ADM_LAB_WEB_PORT=str(PORTS[0]),
            ADM_LAB_MGMT_PORT=str(PORTS[1]),
            ADM_LAB_HEC_PORT=str(PORTS[2]),
            ADM_LAB_SECRETS=str(self.runtime / "credentials"),
            ADM_LAB_EXTRACTED=str(self.args.extracted.resolve()),
            ADM_LAB_PACKAGE=str(self.args.package.resolve()),
            DOCKER_HOST=self.args.socket,
        )
        env["PATH"] = str(Path(sys.executable).parent) + os.pathsep + env["PATH"]
        try:
            os.environ.clear()
            os.environ.update(env)
            with LabLock(ROOT):
                self.envs["source"] = os.environ.copy()
                self.preflight()
                try:
                    self.exercise()
                except BaseException as exc:
                    self.receipt["status"] = "failed_or_uncertain"
                    self.receipt["error_type"] = type(exc).__name__
                    self.receipt["error"] = str(exc)[:500]
                    self.persist_cleanup()
                finally:
                    if self.created:
                        try:
                            self.cleanup()
                        except BaseException as exc:
                            self.receipt["cleanup_error"] = type(exc).__name__
                            self.persist_cleanup()
                    self.receipt["elapsed_seconds"] = round(
                        time.monotonic() - self.started, 2
                    )
                    self.persist_cleanup()
                expected_status = (
                    "unsupported_helper_verified"
                    if self.args.expect_unsupported_helper
                    else "tests_passed"
                )
                if self.receipt["status"] != expected_status or self.created:
                    raise RuntimeError(
                        "source rehearsal failed or cleanup uncertain; retain receipts"
                    )
        finally:
            os.environ.clear()
            os.environ.update(previous)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run", action="store_true", required=True)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--package-sha256", required=True)
    parser.add_argument("--extracted", type=Path, required=True)
    parser.add_argument("--socket", required=True)
    parser.add_argument(
        "--expect-unsupported-helper",
        action="store_true",
        help="Verify fail-closed helper preflight, notes availability and absent job intents; does not qualify source capture",
    )
    SourceRehearsal(parser.parse_args()).execute()
