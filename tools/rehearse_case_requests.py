#!/usr/bin/env python3
"""Exact disposable local lab for case request interruption qualification."""

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

from lab_lock import LabLock
from check_release import check_release
from rehearse_case_recovery import (
    IMAGE,
    LIFETIME,
    MIN_HOST_FREE,
    Rehearsal,
    private_directory,
    sha,
)

ROOT = Path(__file__).resolve().parents[1]
TASK = "cases-requests-20261118"
NAME = "adm-" + TASK
PORTS = (34900, 34989, 34988)
DISK_BUDGET = 4 * 1024**3
FILES = (
    "tools/rehearse_case_requests.py",
    "tools/rehearse_case_recovery.py",
    "tests/splunk/case_request_lab.py",
    "tests/splunk/case_request_native.py",
    "tests/splunk/case_request_fault_hook.py",
    "tests/splunk/test_case_request_bounds.py",
    "tests/test_case_request_supervisor.py",
    "tests/splunk/lab.py",
    "tests/splunk/lab.sh",
    "tests/splunk/lab_tls.py",
    "tools/lab_lock.py",
    "tools/check_release.py",
    "tools/stage_lab_package.py",
    "tests/splunk/web_session.py",
    "tests/splunk/test_cases_endpoint.py",
)


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


class RequestRehearsal:
    # Reuse the already reviewed parent phase runner, including process-group
    # retirement and cleanup even when log/receipt storage is unavailable.
    run = Rehearsal.run
    persist_cleanup = Rehearsal.persist_cleanup
    reporting_failure = Rehearsal.reporting_failure
    check_time = Rehearsal.check_time
    _cancel = Rehearsal._cancel

    def persist(self):
        target = self.out / "request-receipt.json"
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
        self.started, self.cancelled, self.created = time.monotonic(), False, False
        self.envs = {}
        self.receipt = {
            "schema": 1,
            "status": "preflight",
            "task": TASK,
            "lab": NAME,
            "scope": "Installed synthetic notes request supervision only; no native AMD64 resources, source capture, Cloud/SHC or production qualification",
            "image": IMAGE,
            "package_sha256": args.package_sha256,
            "lifetime_seconds": LIFETIME,
            "named_volume_budget_bytes": DISK_BUDGET,
            "disk_enforcement": "cooperative phase du samples; not a filesystem quota; excludes cached image, writable layer and logs",
            "source_hashes": {p: sha(ROOT / p) for p in FILES},
            "phases": {},
            "cleanup": {},
        }
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

    def helper(self, phase, *args, timeout=180):
        self.run(
            phase,
            "source",
            [sys.executable, "tests/splunk/case_request_lab.py", *map(str, args)],
            timeout,
        )

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
        for port in PORTS:
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
        self.helper("web-before", "ready")
        self.tls("before_install")
        self.sample("before_install")
        self.run("install", "source", ["bash", "tests/splunk/lab.sh", "install"], 900)
        self.helper("web-after", "ready")
        self.tls("after_install")
        self.sample("after_install")
        self.helper("stage-public-fixtures", "stage")
        self.helper(
            "native-probe",
            "native",
            "probe",
            "--output",
            self.out / "native-probe.json",
        )
        probe = json.loads((self.out / "native-probe.json").read_text())
        if (
            probe["installed_version"] != self.receipt["expected_version"]
            or probe["installed_build"] != self.receipt["expected_build"]
            or probe["runtime_sha256"] != self.expected_runtime
        ):
            raise RuntimeError(
                "installed runtime differs from retained candidate archive"
            )
        self.helper("linux-process-tests", "unit-tests", timeout=180)
        for phase in ("before", "faults", "after"):
            self.envs["source"]["ADM_LAB_WEB_RECEIPT"] = str(
                self.out / (phase + "-journal.json")
            )
            self.run(
                phase + "-web",
                "source",
                [sys.executable, "tests/splunk/test_case_request_bounds.py", phase],
                900,
            )
            journal = json.loads(
                Path(self.envs["source"]["ADM_LAB_WEB_RECEIPT"]).read_text()
            )
            if not journal["fixture"].get("checks_passed") or not journal[
                "fixture"
            ].get("cleanup_verified"):
                raise RuntimeError("installed fixture checks/cleanup not verified")
            for record in journal["requests"]:
                if (
                    record["state"] != "response_received"
                    or record.get("status", 0) >= 500
                ):
                    if record.get("reconciled_by_exact_retry") is not True:
                        raise RuntimeError("a mutation outcome remains unresolved")
            self.receipt.setdefault("fixtures", {})[phase] = {
                "journal_sha256": sha(Path(self.envs["source"]["ADM_LAB_WEB_RECEIPT"])),
                "checks": journal["fixture"]["checks"],
                "cleanup_verified": True,
            }
            self.sample(phase)
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
            ADM_LAB_REQUEST_BOUNDS="1",
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
                if self.receipt["status"] != "tests_passed" or self.created:
                    raise RuntimeError(
                        "request rehearsal failed or cleanup uncertain; retain receipts"
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
    RequestRehearsal(parser.parse_args()).execute()
