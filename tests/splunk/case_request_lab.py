"""Exact identity, staging and native fixture entrypoints for request tests."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path[:0] = [str(HERE), str(ROOT / "tools")]
import lab  # noqa: E402
from lab_lock import LabLock  # noqa: E402

TASK = "cases-requests-20261118"
NAME = "adm-" + TASK
DIRECTORY = "/tmp/" + TASK + "-fixtures"
FILES = {
    "case_request_native.py": HERE / "case_request_native.py",
    "case_request_fault_hook.py": HERE / "case_request_fault_hook.py",
    "qualify/tests/test_case_request_supervisor.py": ROOT
    / "tests/test_case_request_supervisor.py",
}


def guard():
    if (
        os.environ.get("ADM_LAB_REQUEST_BOUNDS") != "1"
        or os.environ.get("ADM_LAB_WEB_TLS") != "1"
        or lab.task_identity() != (TASK, NAME)
        or not LabLock(ROOT).check_owned()
    ):
        raise RuntimeError("exact request lab and inherited live lock required")
    lab.verify_target()
    ident = lab.lab_tls.read_container(lab.SECRETS, (TASK, NAME))
    info = json.loads(
        subprocess.check_output(["docker", "inspect", ident], timeout=30)
    )[0]
    if (
        not info["State"]["Running"]
        or sorted((m["Type"], m.get("Name"), m["Destination"]) for m in info["Mounts"])
        != sorted(
            ("volume", NAME + "-" + suffix, "/opt/splunk/" + suffix)
            for suffix in ("etc", "var")
        )
        or set(info["HostConfig"]["PortBindings"])
        != {"8000/tcp", "8089/tcp", "8088/tcp"}
    ):
        raise RuntimeError("running exact-volume lab required")
    return ident


def stage():
    ident = guard()
    for suffix in ("", "/qualify", "/qualify/tests"):
        subprocess.run(
            [
                "docker",
                "exec",
                "--user",
                "splunk",
                ident,
                "mkdir",
                "-p",
                "-m",
                "700",
                DIRECTORY + suffix,
            ],
            check=True,
            timeout=30,
            stdout=subprocess.DEVNULL,
        )
    for name, path in FILES.items():
        destination = DIRECTORY + "/" + name
        subprocess.run(
            ["docker", "cp", str(path), ident + ":" + destination],
            check=True,
            timeout=30,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        for command in (
            ["chown", "splunk:splunk", destination],
            ["chmod", "600", destination],
        ):
            subprocess.run(
                ["docker", "exec", "--user", "root", ident, *command],
                check=True,
                timeout=30,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
        actual = subprocess.check_output(
            ["docker", "exec", "--user", "splunk", ident, "sha256sum", destination],
            timeout=30,
            text=True,
        ).split()[0]
        if actual != hashlib.sha256(path.read_bytes()).hexdigest():
            raise RuntimeError("staged public fixture differs")
    guard()


def native(action, payload=None):
    ident = guard()
    data = {"action": action, **(payload or {})}
    if action in ("hook_install", "hook_remove"):
        data["expected_sha256"] = hashlib.sha256(
            FILES["case_request_fault_hook.py"].read_bytes()
        ).hexdigest()
    result = subprocess.run(
        [
            "docker",
            "exec",
            "--user",
            "root" if action in ("hook_install", "hook_remove") else "splunk",
            "-i",
            "--env",
            "ADM_CASE_REQUEST_NATIVE_TASK=" + TASK,
            ident,
            "/opt/splunk/bin/splunk",
            "cmd",
            "python3.13",
            DIRECTORY + "/case_request_native.py",
        ],
        input=json.dumps(data).encode(),
        capture_output=True,
        timeout=180 if action == "seed_large" else 60,
    )
    guard()
    if result.returncode:
        # Only code locations and exception class, never exception text or data.
        try:
            error = json.loads(result.stdout)
            diagnostic = {k: error[k] for k in ("error_type", "location") if k in error}
        except (ValueError, TypeError):
            diagnostic = {}
        raise RuntimeError("native request fixture failed: " + json.dumps(diagnostic))
    return json.loads(result.stdout)


def ready():
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        guard()
        try:
            with lab.urlopen(
                urllib.request.Request(lab.WEB + "/en-US/account/login"), timeout=10
            ) as response:
                if response.status == 200:
                    return
                raise RuntimeError("unexpected Web readiness status")
        except urllib.error.HTTPError as exc:
            if exc.code != 503:
                raise
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, ssl.SSLCertVerificationError):
                raise
        time.sleep(1)
    raise RuntimeError("verified Web readiness timed out")


def write(path, value):
    path = Path(path)
    if (
        not path.is_absolute()
        or path.parent.is_symlink()
        or not path.parent.is_dir()
        or path.parent.stat().st_uid != os.getuid()
        or path.parent.stat().st_mode & 0o077
        or any((p / ".git").exists() for p in (path.parent, *path.parents))
    ):
        raise RuntimeError("private external evidence path required")
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(value, stream, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    fd = os.open(path.parent, os.O_RDONLY)
    os.fsync(fd)
    os.close(fd)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("ready", "stage", "native", "unit-tests"))
    parser.add_argument("native_action", nargs="?")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.action == "ready":
        ready()
    elif args.action == "stage":
        stage()
    elif args.action == "native":
        write(args.output, native(args.native_action))
    else:
        result = native("unit_setup")
        ident = guard()
        subprocess.run(
            [
                "docker",
                "exec",
                "--user",
                "splunk",
                ident,
                "/opt/splunk/bin/splunk",
                "cmd",
                "python3.13",
                result["unit_path"],
            ],
            check=True,
            timeout=120,
        )
        guard()
