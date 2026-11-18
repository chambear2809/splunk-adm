"""Fixed-path cold recovery operations for three exact disposable task labs.

No production target, live filesystem copy, or arbitrary archive extraction is
supported. The parent must own each lab's direct cross-worktree lock.
"""

from __future__ import annotations

import base64
import argparse
import hashlib
import http.client
import io
import json
import os
from pathlib import Path
import socket
import ssl
import stat
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.request
from urllib.parse import urlencode, urlsplit

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path[:0] = [str(HERE), str(ROOT / "tools")]
import lab  # noqa: E402
from lab_lock import LabLock  # noqa: E402
from case_recovery_snapshot import ALLOWLIST, MAX_TOTAL_BYTES  # noqa: E402

TASKS = {
    "source": ("cases-recovery-source-20261117", "adm-cases-recovery-source-20261117"),
    "occupied": (
        "cases-recovery-occupied-20261117",
        "adm-cases-recovery-occupied-20261117",
    ),
    "target": ("cases-recovery-target-20261117", "adm-cases-recovery-target-20261117"),
}
DB_PARENT = "/opt/splunk/var/lib/splunk"
DIRECTORY = "splunk_adm_investigations"
DB_DIRECTORY = DB_PARENT + "/" + DIRECTORY
MARKER = "refuse-overwrite-marker"
MARKER_DATA = b"owned negative recovery target\n"
MAX_TAR_BYTES = MAX_TOTAL_BYTES + 1024 * 1024
SIDECARS = {name + suffix for name in ALLOWLIST for suffix in ("-wal", "-shm")}


class RecoveryLabError(RuntimeError):
    pass


def target(*, stopped=None):
    identity = lab.task_identity()
    if os.environ.get("ADM_LAB_CASE_RECOVERY") != "1" or identity not in TASKS.values():
        raise RecoveryLabError("requires exact case-recovery lab opt-in")
    if not LabLock(ROOT).check_owned():
        raise RecoveryLabError("parent must hold this lab's direct lock")
    lab.verify_target()
    ident = lab.lab_tls.read_container(lab.SECRETS, identity)
    info = json.loads(
        subprocess.check_output(["docker", "inspect", ident], timeout=30)
    )[0]
    mounts = info.get("Mounts", [])
    expected_mounts = {
        "/opt/splunk/etc": identity[1] + "-etc",
        "/opt/splunk/var": identity[1] + "-var",
    }
    if len(mounts) != 2 or {
        item.get("Destination"): (item.get("Type"), item.get("Name")) for item in mounts
    } != {path: ("volume", name) for path, name in expected_mounts.items()}:
        raise RecoveryLabError("recovery requires exactly its two owned volume mounts")
    if set(info.get("HostConfig", {}).get("PortBindings", {})) != {
        "8000/tcp",
        "8089/tcp",
        "8088/tcp",
    }:
        raise RecoveryLabError("recovery refuses extra or missing port bindings")
    state = info["State"]
    if stopped is True and (
        state.get("Running") is not False
        or state.get("Status") != "exited"
        or state.get("Pid") != 0
        or state.get("Restarting")
        or state.get("Dead")
    ):
        raise RecoveryLabError("cold operation requires the complete container stopped")
    if stopped is False and (not state.get("Running") or state.get("Paused")):
        raise RecoveryLabError("operation requires the owned running container")
    if stopped is True:
        # No peer may hold the same named volumes, even if that peer is stopped.
        peers = subprocess.check_output(
            ["docker", "ps", "-aq"], text=True, timeout=30
        ).splitlines()
        volumes = {identity[1] + "-etc", identity[1] + "-var"}
        for peer in peers:
            mounts = json.loads(
                subprocess.check_output(
                    ["docker", "inspect", "--format", "{{json .Mounts}}", peer],
                    timeout=30,
                )
            )
            if (
                peer != ident
                and not ident.startswith(peer)
                and any(item.get("Name") in volumes for item in mounts)
            ):
                raise RecoveryLabError("task volumes have another container consumer")
    return ident, info


class _UnixHTTP(http.client.HTTPConnection):
    def __init__(self, endpoint):
        parsed = urlsplit(endpoint)
        if (
            parsed.scheme != "unix"
            or parsed.netloc
            or not parsed.path.startswith("/")
            or parsed.query
            or parsed.fragment
        ):
            raise RecoveryLabError("only the framework's local Unix socket is accepted")
        super().__init__("localhost", timeout=30)
        self.socket_path = parsed.path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.socket_path)


def _archive(method):
    if method not in ("HEAD", "GET"):
        raise RecoveryLabError("read-only archive method required")
    ident, _ = target(stopped=True)
    connection = _UnixHTTP(lab.local_docker_endpoint())
    try:
        connection.request(
            method,
            f"/v1.48/containers/{ident}/archive?" + urlencode({"path": DB_DIRECTORY}),
        )
        response = connection.getresponse()
        status = response.status
        header = response.getheader("X-Docker-Container-Path-Stat")
        body = response.read(MAX_TAR_BYTES + 1)
        if len(body) > MAX_TAR_BYTES:
            raise RecoveryLabError("cold archive exceeds bound")
    finally:
        connection.close()
    after, _ = target(stopped=True)
    if after != ident:
        raise RecoveryLabError("container changed during archive read")
    if status == 404:
        # The exact container still exists and is stopped, so this is path absence.
        return None, b""
    if status != 200 or not header or len(header) > 8192:
        raise RecoveryLabError("Docker cold-path metadata unavailable")
    try:
        metadata = json.loads(base64.b64decode(header, validate=True))
    except (ValueError, TypeError) as exc:
        raise RecoveryLabError("invalid Docker path metadata") from exc
    if (
        not isinstance(metadata, dict)
        or metadata.get("name") != DIRECTORY
        or metadata.get("linkTarget")
        or type(metadata.get("mode")) is not int
        or metadata["mode"] != (1 << 31) | 0o700
    ):
        raise RecoveryLabError("unsafe cold database directory")
    return metadata, body


def path_present():
    metadata, _ = _archive("HEAD")
    return metadata is not None


def stop():
    ident, _ = target(stopped=False)
    subprocess.run(
        ["docker", "stop", "--time", "45", ident],
        check=True,
        stdout=subprocess.DEVNULL,
        timeout=75,
    )
    target(stopped=True)


def restart():
    ident, before = target(stopped=False)
    subprocess.run(
        ["docker", "restart", "--time", "45", ident],
        check=True,
        stdout=subprocess.DEVNULL,
        timeout=90,
    )
    lab.wait_bootstrap()
    lab.wait_ready()
    wait_web()
    after_id, after = target(stopped=False)
    if after_id != ident or before["State"]["StartedAt"] == after["State"]["StartedAt"]:
        raise RecoveryLabError("restart identity or start time not established")
    return {"id": ident, "restarted": True}


def wait_web():
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        target(stopped=False)
        try:
            with lab.urlopen(
                urllib.request.Request(lab.WEB + "/en-US/account/login"), timeout=10
            ) as response:
                if response.status == 200:
                    return
                raise RecoveryLabError("unexpected Web readiness response")
        except urllib.error.HTTPError as exc:
            if exc.code != 503:
                raise
        except urllib.error.URLError as exc:
            if isinstance(exc.reason, ssl.SSLCertVerificationError):
                raise
        time.sleep(1)
    raise RecoveryLabError("verified Web readiness timed out")


def _read_tar(payload, allowed, uid, gid):
    if len(payload) > MAX_TAR_BYTES:
        raise RecoveryLabError("cold archive exceeds bound")
    contents, seen, total = {}, set(), 0
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:") as archive:
        for member in archive:
            name = member.name.rstrip("/")
            if name in seen:
                raise RecoveryLabError("duplicate archive entry")
            seen.add(name)
            if member.uid != uid or member.gid != gid:
                raise RecoveryLabError("database archive is not service-owned")
            if name == DIRECTORY and member.isdir() and member.mode == 0o700:
                continue
            if (
                not name.startswith(DIRECTORY + "/")
                or name[len(DIRECTORY) + 1 :] not in allowed
                or not member.isfile()
                or member.mode != 0o600
                or member.size < 0
            ):
                raise RecoveryLabError("unlisted or unsafe archive entry")
            total += member.size
            if total > MAX_TOTAL_BYTES:
                raise RecoveryLabError("database files exceed bound")
            stream = archive.extractfile(member)
            data = stream.read(member.size + 1)
            if len(data) != member.size:
                raise RecoveryLabError("truncated archive entry")
            contents[name[len(DIRECTORY) + 1 :]] = data
    if DIRECTORY not in seen:
        raise RecoveryLabError("database directory entry missing")
    return contents


def cold_export(destination, *, uid, gid):
    metadata, payload = _archive("GET")
    if metadata is None:
        raise RecoveryLabError("source database directory absent")
    contents = _read_tar(payload, set(ALLOWLIST) | SIDECARS, uid, gid)
    if "cases.sqlite" not in contents:
        raise RecoveryLabError("case database absent")
    destination = Path(destination)
    destination.mkdir(mode=0o700)
    for name, data in contents.items():
        fd = os.open(destination / name, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    return {name: hashlib.sha256(data).hexdigest() for name, data in contents.items()}


def restore_prepared(directory, summary, *, uid, gid):
    if lab.task_identity() not in (TASKS["occupied"], TASKS["target"]):
        raise RecoveryLabError("restore requires an exact restore-target task")
    ident, _ = target(stopped=True)
    directory = Path(directory)
    info = directory.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o700
        or not {"cases.sqlite"} <= set(summary["files"]) <= set(ALLOWLIST)
        or {p.name for p in directory.iterdir()} != set(summary["files"])
    ):
        raise RecoveryLabError("unsafe prepared restore directory")
    data = {}
    for name, expected in summary["files"].items():
        fd = os.open(directory / name, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_nlink != 1
                or info.st_size != expected["size"]
                or info.st_size > MAX_TOTAL_BYTES
            ):
                raise RecoveryLabError("unsafe prepared database")
            data[name] = stream.read(MAX_TOTAL_BYTES + 1)
        if hashlib.sha256(data[name]).hexdigest() != expected["sha256"]:
            raise RecoveryLabError("prepared database changed")
    if sum(map(len, data.values())) > MAX_TOTAL_BYTES:
        raise RecoveryLabError("prepared restore exceeds bound")
    if path_present():
        raise RecoveryLabError("restore refuses any existing database directory")
    payload = io.BytesIO()
    with tarfile.open(
        fileobj=payload, mode="w", format=tarfile.USTAR_FORMAT
    ) as archive:
        item = tarfile.TarInfo(DIRECTORY)
        item.type, item.mode, item.uid, item.gid = tarfile.DIRTYPE, 0o700, uid, gid
        archive.addfile(item)
        for name, content in data.items():
            item = tarfile.TarInfo(DIRECTORY + "/" + name)
            item.mode, item.uid, item.gid, item.size = 0o600, uid, gid, len(content)
            archive.addfile(item, io.BytesIO(content))
    target(stopped=True)
    # Constructed allowlisted tar only, never an uploaded/unvalidated archive.
    # Do not add -a: copyUIDGID=true overrides tar IDs with Config.User on
    # this Engine. Our tar already carries the verified service UID/GID.
    # The mandatory cold readback independently checks the resulting ownership.
    result = subprocess.run(
        ["docker", "cp", "-", ident + ":" + DB_PARENT],
        input=payload.getvalue(),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=90,
    )
    if result.returncode:
        raise RecoveryLabError("restore copy outcome uncertain; retain target")
    target(stopped=True)
    if not path_present():
        raise RecoveryLabError("restore outcome uncertain; database directory absent")


def occupied_marker(*, uid, gid):
    if lab.task_identity() != TASKS["occupied"]:
        raise RecoveryLabError("marker read requires its exact negative fixture")
    _, payload = _archive("GET")
    files = _read_tar(payload, {MARKER}, uid, gid)
    if files != {MARKER: MARKER_DATA}:
        raise RecoveryLabError("occupied target marker changed")
    return hashlib.sha256(files[MARKER]).hexdigest()


def native(action, payload=None):
    """Run public fixture code as the pinned image's ordinary Splunk identity."""
    ident, _ = target(stopped=False)
    task, _ = lab.task_identity()
    directory = "/tmp/" + task + "-inspection"
    # This fixed code path contains no credentials or caller-supplied shell.
    subprocess.run(
        [
            "docker",
            "exec",
            "--user",
            "splunk",
            ident,
            "mkdir",
            "-m",
            "700",
            "-p",
            directory,
        ],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=30,
    )
    for source in (
        HERE / "case_recovery_native.py",
        ROOT / "tools/case_recovery_snapshot.py",
    ):
        subprocess.run(
            ["docker", "cp", str(source), ident + ":" + directory + "/" + source.name],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=30,
        )
        for command in (
            ["chown", "splunk:splunk", directory + "/" + source.name],
            ["chmod", "600", directory + "/" + source.name],
        ):
            subprocess.run(
                ["docker", "exec", "--user", "root", ident, *command],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=30,
            )
        actual = subprocess.check_output(
            [
                "docker",
                "exec",
                "--user",
                "splunk",
                ident,
                "sha256sum",
                directory + "/" + source.name,
            ],
            timeout=30,
            text=True,
        ).split()[0]
        if actual != hashlib.sha256(source.read_bytes()).hexdigest():
            raise RecoveryLabError("native inspection code changed during staging")
    result = subprocess.run(
        [
            "docker",
            "exec",
            "--user",
            "splunk",
            "-i",
            "--env",
            "ADM_RECOVERY_NATIVE_TASK=" + task,
            ident,
            "/opt/splunk/bin/splunk",
            "cmd",
            "python3.13",
            directory + "/case_recovery_native.py",
        ],
        input=json.dumps({**(payload or {}), "action": action}).encode(),
        capture_output=True,
        timeout=60,
    )
    if result.returncode:
        raise RecoveryLabError(
            "native recovery fixture failed; no credential output forwarded"
        )
    target(stopped=False)
    return json.loads(result.stdout)


def private_json(path):
    path = Path(path)
    parent = path.parent.lstat()
    if (
        not path.is_absolute()
        or not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != os.getuid()
        or stat.S_IMODE(parent.st_mode) != 0o700
        or any((p / ".git").exists() for p in (path.parent, *path.parents))
    ):
        raise RecoveryLabError("private external state path required")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
            or info.st_size > 2 * 1024 * 1024
        ):
            raise RecoveryLabError("unsafe private state file")
        return json.loads(stream.read(2 * 1024 * 1024 + 1))


def write_json(path, data):
    path = Path(path)
    info = path.parent.lstat()
    if (
        not path.is_absolute()
        or not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o700
        or any((p / ".git").exists() for p in (path.parent, *path.parents))
    ):
        raise RecoveryLabError("private external state path required")
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(data, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    descriptor = os.open(path.parent, os.O_RDONLY)
    os.fsync(descriptor)
    os.close(descriptor)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "action",
        choices=(
            "stop",
            "ready",
            "live-refusal",
            "export",
            "identity",
            "occupied",
            "occupied-refusal",
            "restore",
            "absent",
        ),
    )
    parser.add_argument("--metadata")
    parser.add_argument("--summary")
    parser.add_argument("--directory")
    parser.add_argument("--output")
    args = parser.parse_args()
    if args.action == "stop":
        stop()
        return
    if args.action == "ready":
        wait_web()
        return
    if args.action == "live-refusal":
        target(stopped=False)
        try:
            path_present()
        except RecoveryLabError as exc:
            if "complete container stopped" not in str(exc):
                raise
        else:
            raise RecoveryLabError("live path operation was accepted")
        result = {"live_copy_refused": True}
    elif args.action in ("identity", "occupied"):
        result = native(args.action)
    elif args.action == "absent":
        if path_present():
            raise RecoveryLabError("target database directory already exists")
        result = {"target_directory_absent": True}
    else:
        metadata = private_json(args.metadata)
        identity = metadata.get("native", metadata)
        if args.action == "export":
            result = cold_export(
                args.directory, uid=identity["uid"], gid=identity["gid"]
            )
        elif args.action == "occupied-refusal":
            before = occupied_marker(uid=identity["uid"], gid=identity["gid"])
            try:
                restore_prepared(
                    args.directory,
                    private_json(args.summary),
                    uid=identity["uid"],
                    gid=identity["gid"],
                )
            except RecoveryLabError as exc:
                if "existing database directory" not in str(exc):
                    raise
            else:
                raise RecoveryLabError("occupied restore was accepted")
            if occupied_marker(uid=identity["uid"], gid=identity["gid"]) != before:
                raise RecoveryLabError("occupied target was modified")
            result = {"occupied_target_refused": True, "marker_unchanged": True}
        else:
            restore_prepared(
                args.directory,
                private_json(args.summary),
                uid=identity["uid"],
                gid=identity["gid"],
            )
            result = {"restore_copy_completed": True}
    write_json(args.output, result)


if __name__ == "__main__":
    main()
