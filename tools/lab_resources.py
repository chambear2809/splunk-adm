"""Host-wide reservations and capacity leases for disposable Splunk labs.

The registry coordinates cooperating local commands.  It does not replace the
per-lab lock in :mod:`tools.lab_lock`, reserve ports in the operating system, or
manage Docker resources.  OS/Docker bind failures remain authoritative.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import fcntl
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Sequence
from urllib.parse import urlsplit

try:
    from tools.lab_lock import LabLockError, run_locked
except ImportError:  # pragma: no cover - direct script execution fallback
    from lab_lock import LabLockError, run_locked


ENV_CAPACITY = "ADM_LAB_RESOURCE_CAPACITY"
ENV_LEASE_ID = "SPLUNK_ADM_RESOURCE_LEASE_ID"
ENV_LEASE_TOKEN = "SPLUNK_ADM_RESOURCE_LEASE_TOKEN"
ENV_LEASE_PID = "SPLUNK_ADM_RESOURCE_LEASE_PID"
ENV_LEASE_START = "SPLUNK_ADM_RESOURCE_LEASE_START"
ENV_REGISTRY = "SPLUNK_ADM_RESOURCE_REGISTRY"
MAX_REGISTRY_BYTES = 1_048_576
MAX_CAPACITY = 128
REGISTRY_LOCK_TIMEOUT_SECONDS = 10.0
REGISTRY_LOCK_RETRY_SECONDS = 0.025
PORT_FIELDS = {
    "web_port": "web",
    "management_port": "management",
    "hec_port": "hec",
    "preview_port": "preview",
    "browser_harness_port": "browser_harness",
}
MANIFEST_FIELDS = {
    "program_id",
    "workstream_id",
    "agent_id",
    "model",
    "reasoning_effort",
    "base_commit",
    "branch",
    "absolute_worktree_path",
    "allowed_write_paths",
    "lab_task",
    "lab_name",
    "docker_endpoint",
    *PORT_FIELDS,
    "runtime_directory",
    "credentials_path",
    "network_name",
    "volume_names",
    "container_id",
    "image_digest",
    "package_sha256",
    "fixture_manifest_sha256",
    "evidence_directory",
    "resource_lease",
}
HASH_RE = re.compile(r"^(?:[0-9a-f]{40}|[0-9a-f]{64})$", re.IGNORECASE)
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$", re.IGNORECASE)
SAFE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
SAFE_LAB_NAME_RE = re.compile(r"^adm-[a-z0-9][a-z0-9-]{0,59}$")
SAFE_LEASE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
SAFE_BRANCH_RE = re.compile(r"^codex/[A-Za-z0-9._/-]+$")
SAFE_AGENT_RE = re.compile(r"^/?[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")
EFFORTS = {"none", "minimal", "low", "medium", "high", "xhigh", "max", "ultra"}


class LabResourceError(RuntimeError):
    """Raised when a resource allocation or capacity lease is unsafe."""


def default_registry_path() -> Path:
    """Return this user's shared host registry path."""

    return Path("/tmp") / f"splunk-adm-resource-registry-{os.getuid()}.json"


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _safe_text(value, field: str, pattern: re.Pattern | None = None) -> str:
    if not isinstance(value, str) or not value or len(value) > 512:
        raise LabResourceError(f"invalid {field}")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise LabResourceError(f"invalid {field}")
    if pattern is not None and not pattern.fullmatch(value):
        raise LabResourceError(f"invalid {field}")
    return value


def _absolute_path(value, field: str) -> Path:
    if not isinstance(value, str) or not value or "\0" in value:
        raise LabResourceError(f"invalid {field}")
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise LabResourceError(f"{field} must be an absolute normalized path")
    try:
        return path.resolve(strict=False)
    except (OSError, RuntimeError) as exc:
        raise LabResourceError(f"unable to resolve {field}") from exc


def _path_overlaps(first: Path, second: Path) -> bool:
    return first == second or first in second.parents or second in first.parents


def _path_is_within(path: Path, parent: Path) -> bool:
    return path == parent or parent in path.parents


def _read_manifest(path: Path) -> dict:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
            info = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_nlink != 1
                or info.st_size > MAX_REGISTRY_BYTES
            ):
                raise LabResourceError("unsafe allocation manifest")
            value = json.load(stream, object_pairs_hook=_unique_object)
    except LabResourceError:
        raise
    except (OSError, ValueError, TypeError) as exc:
        raise LabResourceError("unable to read allocation manifest") from exc
    if not isinstance(value, dict):
        raise LabResourceError("allocation manifest must be a JSON object")
    return value


@dataclass(frozen=True)
class Allocation:
    """Validated task allocation with canonical paths and immutable identity."""

    values: dict
    manifest_path: Path
    worktree: Path
    runtime_directory: Path
    evidence_directory: Path
    credentials_path: Path

    @property
    def lease_id(self) -> str:
        return self.values["resource_lease"]

    @property
    def lab_name(self) -> str:
        return self.values["lab_name"]

    @property
    def ports(self) -> dict[str, int]:
        return {key: self.values[key] for key in PORT_FIELDS}

    def reservation(self) -> dict:
        return {
            "resource_lease": self.lease_id,
            "program_id": self.values["program_id"],
            "workstream_id": self.values["workstream_id"],
            "lab_task": self.values["lab_task"],
            "lab_name": self.lab_name,
            "docker_endpoint": self.values["docker_endpoint"],
            "ports": {PORT_FIELDS[key]: value for key, value in self.ports.items()},
            "runtime_directory": str(self.runtime_directory),
            "evidence_directory": str(self.evidence_directory),
            "credentials_path": str(self.credentials_path),
        }


def validate_allocation(manifest_path: str | os.PathLike[str]) -> Allocation:
    """Read and validate an allocation manifest without reserving resources."""

    source = Path(manifest_path)
    if not source.is_absolute():
        source = Path.cwd() / source
    values = _read_manifest(source)
    missing = MANIFEST_FIELDS - values.keys()
    unknown = values.keys() - MANIFEST_FIELDS
    if missing:
        raise LabResourceError("allocation manifest is missing required fields")
    if unknown:
        raise LabResourceError("allocation manifest has unknown fields")

    for field in ("program_id", "workstream_id", "lab_task"):
        _safe_text(values[field], field, SAFE_ID_RE)
    _safe_text(values["agent_id"], "agent_id", SAFE_AGENT_RE)
    if ".." in values["agent_id"].split("/"):
        raise LabResourceError("invalid agent_id")
    _safe_text(values["model"], "model", re.compile(r"^[a-z0-9][a-z0-9.-]{0,63}$"))
    if (
        not isinstance(values["reasoning_effort"], str)
        or values["reasoning_effort"] not in EFFORTS
    ):
        raise LabResourceError("invalid reasoning_effort")
    if not isinstance(values["base_commit"], str) or not HASH_RE.fullmatch(
        values["base_commit"]
    ):
        raise LabResourceError("invalid base_commit")
    branch = _safe_text(values["branch"], "branch", SAFE_BRANCH_RE)
    if any(
        part in {"", ".", ".."} for part in branch.removeprefix("codex/").split("/")
    ):
        raise LabResourceError("invalid branch")
    _safe_text(values["resource_lease"], "resource_lease", SAFE_LEASE_RE)

    write_paths = values["allowed_write_paths"]
    if not isinstance(write_paths, list):
        raise LabResourceError("allowed_write_paths must be an array")
    seen_write_paths = set()
    for item in write_paths:
        if not isinstance(item, str) or not item or Path(item).is_absolute():
            raise LabResourceError("allowed_write_paths must be relative paths")
        parts = Path(item).parts
        if ".." in parts or item in seen_write_paths:
            raise LabResourceError("invalid or duplicate allowed_write_paths entry")
        seen_write_paths.add(item)

    _safe_text(values["lab_name"], "lab_name", SAFE_LAB_NAME_RE)
    if values["lab_name"] == "adm-splunk-lab":
        raise LabResourceError("task allocation cannot use the default lab name")
    docker_endpoint = _safe_text(values["docker_endpoint"], "docker_endpoint")
    endpoint = urlsplit(docker_endpoint)
    if (
        endpoint.scheme != "unix"
        or endpoint.netloc
        or not endpoint.path.startswith("/")
    ):
        raise LabResourceError("docker_endpoint must name a local Unix socket")

    port_values = []
    for field in PORT_FIELDS:
        value = values[field]
        if (
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 1024 <= value <= 65535
        ):
            raise LabResourceError(f"invalid {field}")
        port_values.append(value)
    if len(set(port_values)) != len(port_values):
        raise LabResourceError("all five allocated ports must be unique")

    if values["network_name"] != f"{values['lab_name']}-net":
        raise LabResourceError("network_name does not match lab_name")
    volume_names = values["volume_names"]
    expected_volumes = [f"{values['lab_name']}-etc", f"{values['lab_name']}-var"]
    if volume_names != expected_volumes:
        raise LabResourceError("volume_names must match the task lab namespace")

    worktree = _absolute_path(
        values["absolute_worktree_path"], "absolute_worktree_path"
    )
    if not worktree.is_dir() or Path(values["absolute_worktree_path"]).is_symlink():
        raise LabResourceError(
            "absolute_worktree_path must be an existing real directory"
        )
    runtime = _absolute_path(values["runtime_directory"], "runtime_directory")
    evidence = _absolute_path(values["evidence_directory"], "evidence_directory")
    credentials = _absolute_path(values["credentials_path"], "credentials_path")
    if any(
        Path(values[field]).is_symlink()
        for field in ("runtime_directory", "evidence_directory", "credentials_path")
    ):
        raise LabResourceError("allocation private paths cannot be symlinks")
    if _path_overlaps(runtime, evidence):
        raise LabResourceError(
            "runtime_directory and evidence_directory must be separate"
        )
    for directory, field in (
        (runtime, "runtime_directory"),
        (evidence, "evidence_directory"),
    ):
        if _path_overlaps(directory, worktree):
            raise LabResourceError(f"{field} must be outside the worktree")
        if directory == Path(directory.anchor):
            raise LabResourceError(f"invalid {field}")
        if directory.exists():
            info = directory.lstat()
            if (
                not stat.S_ISDIR(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_mode & 0o077
            ):
                raise LabResourceError(
                    f"{field} must be a private user-owned directory"
                )
    if not _path_is_within(credentials, runtime) or credentials == runtime:
        raise LabResourceError("credentials_path must be inside runtime_directory")
    if credentials.exists() or credentials.is_symlink():
        try:
            info = credentials.lstat()
        except OSError as exc:
            raise LabResourceError("unsafe credentials_path") from exc
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or info.st_mode & 0o077
        ):
            raise LabResourceError("credentials_path must be a private regular file")

    container_id = values["container_id"]
    if container_id is not None and (
        not isinstance(container_id, str)
        or not re.fullmatch(r"[0-9a-f]{12,64}", container_id, re.IGNORECASE)
    ):
        raise LabResourceError("invalid container_id")
    image_digest = values["image_digest"]
    if image_digest is not None and (
        not isinstance(image_digest, str) or not SHA256_RE.fullmatch(image_digest)
    ):
        raise LabResourceError("invalid image_digest")
    for field in ("package_sha256", "fixture_manifest_sha256"):
        value = values[field]
        if value is not None and (
            not isinstance(value, str) or not HASH_RE.fullmatch(value)
        ):
            raise LabResourceError(f"invalid {field}")

    return Allocation(
        values=values,
        manifest_path=source.resolve(strict=False),
        worktree=worktree,
        runtime_directory=runtime,
        evidence_directory=evidence,
        credentials_path=credentials,
    )


def _ensure_private_directory(path: Path, field: str) -> None:
    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = path.lstat()
    except OSError as exc:
        raise LabResourceError(f"unable to prepare private {field}") from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_mode & 0o077
    ):
        raise LabResourceError(f"{field} must be a private user-owned directory")


def _process_start_time(pid: int) -> str | None:
    """Return a stable OS start marker, or ``None`` when it cannot be read."""

    try:
        result = subprocess.run(
            ["ps", "-p", str(pid), "-o", "lstart="],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    value = result.stdout.strip()
    return value or None


def _pid_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _process_matches(pid: int, start_time: str) -> bool | None:
    """Return False only when the old process is provably gone or reused."""

    if not _pid_exists(pid):
        return False
    observed = _process_start_time(pid)
    if observed is None:
        return None
    return observed == start_time


class _RegistryFile:
    def __init__(self, path: str | os.PathLike[str], *, initial_capacity: int = 1):
        self.path = Path(path)
        self.lock_path = self.path.with_name(self.path.name + ".lock")
        self.initial_capacity = initial_capacity
        self.file = None
        self.last_write_committed = False

    def __enter__(self) -> "_RegistryFile":
        self.path.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.lock_path, flags, 0o600)
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_nlink != 1
            ):
                os.close(descriptor)
                raise LabResourceError(
                    f"unsafe resource registry lock: {self.lock_path}"
                )
            os.fchmod(descriptor, 0o600)
            self.file = os.fdopen(descriptor, "r+b")
            deadline = time.monotonic() + REGISTRY_LOCK_TIMEOUT_SECONDS
            try:
                while True:
                    try:
                        fcntl.flock(self.file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                        break
                    except BlockingIOError:
                        if time.monotonic() >= deadline:
                            raise LabResourceError(
                                f"resource registry is busy: {self.path}"
                            )
                        time.sleep(REGISTRY_LOCK_RETRY_SECONDS)
            except BaseException:
                self.file.close()
                self.file = None
                raise
        except LabResourceError:
            raise
        except OSError as exc:
            raise LabResourceError(
                f"unsafe resource registry lock: {self.lock_path}"
            ) from exc
        return self

    def __exit__(self, *_args) -> None:
        if self.file is not None:
            try:
                fcntl.flock(self.file.fileno(), fcntl.LOCK_UN)
            finally:
                self.file.close()
                self.file = None

    def read(self) -> dict:
        assert self.file is not None
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.path, flags)
        except FileNotFoundError:
            return {
                "version": 1,
                "capacity": self.initial_capacity,
                "allocations": [],
            }
        except OSError as exc:
            raise LabResourceError(f"unsafe resource registry: {self.path}") from exc
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_nlink != 1
            ):
                raise LabResourceError(f"unsafe resource registry: {self.path}")
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "rb") as stream:
                descriptor = -1
                raw = stream.read(MAX_REGISTRY_BYTES + 1)
        except LabResourceError:
            raise
        except OSError as exc:
            raise LabResourceError(
                f"unable to read resource registry: {self.path}"
            ) from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        if len(raw) > MAX_REGISTRY_BYTES:
            raise LabResourceError("resource registry is oversized")
        if not raw:
            raise LabResourceError(
                "resource registry is empty or interrupted; preserve it for inspection"
            )
        try:
            registry = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
        except (UnicodeDecodeError, ValueError, TypeError) as exc:
            raise LabResourceError(
                "resource registry is corrupt; preserve it for inspection"
            ) from exc
        if (
            not isinstance(registry, dict)
            or registry.get("version") != 1
            or isinstance(registry.get("capacity"), bool)
            or not isinstance(registry.get("capacity"), int)
            or not 1 <= registry["capacity"] <= MAX_CAPACITY
            or not isinstance(registry.get("allocations"), list)
        ):
            raise LabResourceError("resource registry has an unsupported schema")
        return registry

    def write(self, registry: dict) -> None:
        assert self.file is not None
        data = json.dumps(registry, sort_keys=True, separators=(",", ":"))
        encoded = data.encode("utf-8")
        if len(encoded) > MAX_REGISTRY_BYTES:
            raise LabResourceError("resource registry is oversized")
        self.last_write_committed = False
        temporary = self.path.with_name(
            f".{self.path.name}.tmp-{os.getpid()}-{uuid.uuid4().hex}"
        )
        descriptor = -1
        temporary_identity = None
        try:
            # Validate any existing destination before replacing it. A missing
            # path is the only valid uninitialized state; an existing empty or
            # unsafe file is rejected by read() before callers reach write().
            self._validate_destination()
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(temporary, flags, 0o600)
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_nlink != 1
            ):
                raise LabResourceError(
                    f"unsafe temporary resource registry: {temporary}"
                )
            temporary_identity = (info.st_dev, info.st_ino)
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                descriptor = -1
                stream.write(encoded)
                stream.flush()
                os.fsync(stream.fileno())
            self._validate_destination()
            os.replace(temporary, self.path)
            self.last_write_committed = True
            directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            directory_fd = os.open(self.path.parent, directory_flags)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except LabResourceError:
            raise
        except OSError as exc:
            raise LabResourceError(
                f"unable to atomically write resource registry: {self.path}"
            ) from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if temporary_identity is not None:
                try:
                    info = temporary.lstat()
                    if (
                        stat.S_ISREG(info.st_mode)
                        and info.st_uid == os.getuid()
                        and info.st_nlink == 1
                        and (info.st_dev, info.st_ino) == temporary_identity
                    ):
                        temporary.unlink()
                except FileNotFoundError:
                    pass

    def _validate_destination(self) -> None:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.path, flags)
        except FileNotFoundError:
            return
        except OSError as exc:
            raise LabResourceError(f"unsafe resource registry: {self.path}") from exc
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_nlink != 1
                or info.st_size == 0
            ):
                raise LabResourceError(f"unsafe resource registry: {self.path}")
        finally:
            os.close(descriptor)


def _active_entry(entry: dict) -> dict | None:
    active = entry.get("active")
    if active is None:
        return None
    if (
        not isinstance(active, dict)
        or isinstance(active.get("pid"), bool)
        or not isinstance(active.get("pid"), int)
        or active.get("pid", 0) <= 0
        or not isinstance(active.get("start_time"), str)
        or not active["start_time"]
        or not isinstance(active.get("token"), str)
        or not re.fullmatch(r"[0-9a-f]{32}", active["token"])
        or not isinstance(active.get("capacity"), int)
        or isinstance(active.get("capacity"), bool)
        or not 1 <= active["capacity"] <= MAX_CAPACITY
    ):
        raise LabResourceError("resource registry contains invalid lease metadata")
    return active


def _active_lock_path(registry_path: Path, lease_id: str) -> Path:
    digest = hashlib.sha256(lease_id.encode("utf-8")).hexdigest()
    return registry_path.with_name(f"{registry_path.name}.lease-{digest}.lock")


# If registry cleanup cannot be committed, retain the OS lock until this
# process exits. Releasing it while the registry still says the same live PID
# owns the lease would make stale recovery fail closed against a false orphan.
_QUARANTINED_ACTIVE_LOCKS: dict[str, "_ProcessLeaseLock"] = {}


class _ProcessLeaseLock:
    """Per-allocation OS lock retained for the complete active command."""

    def __init__(self, path: Path):
        self.path = path
        self.file = None

    def acquire(self, *, blocking: bool = False) -> bool:
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.path, flags, 0o600)
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_nlink != 1
            ):
                os.close(descriptor)
                raise LabResourceError(f"unsafe active lease metadata: {self.path}")
            os.fchmod(descriptor, 0o600)
            self.file = os.fdopen(descriptor, "r+", encoding="utf-8")
            flags = fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB)
            try:
                fcntl.flock(self.file.fileno(), flags)
            except BlockingIOError:
                self.file.close()
                self.file = None
                return False
            return True
        except LabResourceError:
            raise
        except OSError as exc:
            raise LabResourceError(
                f"unsafe active lease metadata: {self.path}"
            ) from exc

    def read(self) -> dict:
        if self.file is None:
            raise LabResourceError("active lease metadata is not locked")
        self.file.seek(0)
        raw = self.file.read(4097)
        if len(raw) > 4096:
            raise LabResourceError("active lease metadata is oversized")
        if not raw:
            return {}
        try:
            value = json.loads(raw, object_pairs_hook=_unique_object)
        except (ValueError, TypeError) as exc:
            raise LabResourceError("active lease metadata is corrupt") from exc
        if not isinstance(value, dict):
            raise LabResourceError("active lease metadata is corrupt")
        return value

    def write(self, metadata: dict) -> None:
        if self.file is None:
            raise LabResourceError("active lease metadata is not locked")
        raw = json.dumps(metadata, sort_keys=True, separators=(",", ":"))
        self.file.seek(0)
        self.file.truncate()
        self.file.write(raw)
        self.file.flush()
        os.fsync(self.file.fileno())

    def release(self) -> None:
        if self.file is not None:
            file = self.file
            self.file = None
            try:
                fcntl.flock(file.fileno(), fcntl.LOCK_UN)
            finally:
                file.close()


def _reap_stale_active(registry: dict, registry_path: Path) -> bool:
    """Clear dead/reused process leases while retaining their reservations."""

    changed = False
    for entry in registry["allocations"]:
        active = _active_entry(entry)
        if active is None:
            continue
        lease_id = entry["reservation"]["resource_lease"]
        probe = _ProcessLeaseLock(_active_lock_path(registry_path, lease_id))
        locked = probe.acquire()
        if not locked:
            continue
        try:
            metadata = probe.read()
            if metadata != {
                "pid": active["pid"],
                "start_time": active["start_time"],
                "token": active["token"],
            }:
                raise LabResourceError(
                    "active lease token/start metadata does not match registry"
                )
            if _process_matches(active["pid"], active["start_time"]) is True:
                raise LabResourceError(
                    "lease process identity is still live but its OS lease lock is free"
                )
            # The lease lock is held for the complete runtime. Its availability
            # proves the old holder is gone; matching the stored token and
            # process start marker prevents clearing a replaced registry record.
            entry["active"] = None
            changed = True
        finally:
            probe.release()
    return changed


def _validate_registry_entries(registry: dict) -> None:
    seen_ids = set()
    seen_names = set()
    seen_tasks = set()
    seen_ports: dict[int, str] = {}
    seen_paths: list[tuple[Path, str]] = []
    for entry in registry["allocations"]:
        if not isinstance(entry, dict) or not isinstance(
            entry.get("reservation"), dict
        ):
            raise LabResourceError("resource registry contains an invalid reservation")
        reservation = entry["reservation"]
        expected_keys = {
            "resource_lease",
            "program_id",
            "workstream_id",
            "lab_task",
            "lab_name",
            "docker_endpoint",
            "ports",
            "runtime_directory",
            "evidence_directory",
            "credentials_path",
        }
        if set(reservation) != expected_keys:
            raise LabResourceError(
                "resource registry contains an invalid reservation schema"
            )
        lease_id = reservation.get("resource_lease")
        lab_name = reservation.get("lab_name")
        lab_task = reservation.get("lab_task")
        if not isinstance(lease_id, str) or not SAFE_LEASE_RE.fullmatch(lease_id):
            raise LabResourceError(
                "resource registry contains an invalid allocation id"
            )
        if (
            not isinstance(lab_name, str)
            or not SAFE_LAB_NAME_RE.fullmatch(lab_name)
            or not isinstance(lab_task, str)
            or not SAFE_ID_RE.fullmatch(lab_task)
        ):
            raise LabResourceError("resource registry contains an invalid lab identity")
        for field in ("program_id", "workstream_id"):
            if not isinstance(reservation[field], str) or not SAFE_ID_RE.fullmatch(
                reservation[field]
            ):
                raise LabResourceError(
                    "resource registry contains an invalid allocation identity"
                )
        if lease_id in seen_ids or lab_name in seen_names or lab_task in seen_tasks:
            raise LabResourceError(
                "resource registry contains duplicate allocation identities"
            )
        seen_ids.add(lease_id)
        seen_names.add(lab_name)
        seen_tasks.add(lab_task)
        ports = reservation.get("ports")
        if not isinstance(ports, dict) or set(ports) != set(PORT_FIELDS.values()):
            raise LabResourceError(
                "resource registry contains invalid port reservations"
            )
        for port in ports.values():
            if (
                isinstance(port, bool)
                or not isinstance(port, int)
                or not 1024 <= port <= 65535
            ):
                raise LabResourceError("resource registry contains an invalid port")
            if port in seen_ports:
                raise LabResourceError(f"port {port} is reserved by another allocation")
            seen_ports[port] = lease_id
        for field in ("runtime_directory", "evidence_directory"):
            path = _absolute_path(reservation.get(field), field)
            for existing, existing_id in seen_paths:
                if _path_overlaps(existing, path):
                    raise LabResourceError(
                        "private runtime/evidence path collision in resource registry"
                    )
            seen_paths.append((path, lease_id))
        if _path_overlaps(
            Path(reservation["runtime_directory"]),
            Path(reservation["evidence_directory"]),
        ):
            raise LabResourceError(
                "resource registry contains overlapping private paths"
            )
        credentials = _absolute_path(
            reservation["credentials_path"], "credentials_path"
        )
        if not _path_is_within(credentials, Path(reservation["runtime_directory"])):
            raise LabResourceError(
                "resource registry contains an invalid credentials path"
            )
        _active_entry(entry)


def _ensure_capacity(registry: dict, requested: int | None) -> int:
    active_count = sum(
        _active_entry(entry) is not None for entry in registry["allocations"]
    )
    current = registry["capacity"]
    if requested is None:
        return current
    if (
        isinstance(requested, bool)
        or not isinstance(requested, int)
        or not 1 <= requested <= MAX_CAPACITY
    ):
        raise LabResourceError(f"capacity must be an integer from 1 to {MAX_CAPACITY}")
    if requested != current and active_count:
        raise LabResourceError(
            f"cannot change host capacity from {current} while {active_count} lease(s) are active"
        )
    registry["capacity"] = requested
    return requested


def _requested_capacity(capacity: int | None) -> int | None:
    if capacity is not None:
        return capacity
    value = os.environ.get(ENV_CAPACITY)
    if value is None or value == "":
        return None
    try:
        return int(value)
    except ValueError as exc:
        raise LabResourceError(f"{ENV_CAPACITY} must be an integer") from exc


def _check_reservation_conflicts(registry: dict, candidate: dict) -> None:
    for entry in registry["allocations"]:
        existing = entry["reservation"]
        if existing["resource_lease"] == candidate["resource_lease"]:
            if existing != candidate:
                raise LabResourceError(
                    "resource_lease already belongs to a different allocation"
                )
            continue
        if existing["lab_name"] == candidate["lab_name"]:
            raise LabResourceError("lab name is already reserved")
        if existing["lab_task"] == candidate["lab_task"]:
            raise LabResourceError("lab task is already reserved")
        for port in candidate["ports"].values():
            if port in existing["ports"].values():
                raise LabResourceError(f"port {port} is already reserved")
        for path_field in ("runtime_directory", "evidence_directory"):
            candidate_path = Path(candidate[path_field])
            for existing_field in ("runtime_directory", "evidence_directory"):
                if _path_overlaps(candidate_path, Path(existing[existing_field])):
                    raise LabResourceError(f"{path_field} is already reserved")


class ResourceRegistry:
    """Cross-process reservation registry and bounded active-lab capacity."""

    def __init__(
        self,
        path: str | os.PathLike[str] | None = None,
        *,
        capacity: int | None = None,
    ):
        self.path = Path(path) if path is not None else default_registry_path()
        self.requested_capacity = _requested_capacity(capacity)

    def _locked(self, *, initial_capacity: int = 1):
        return _RegistryFile(self.path, initial_capacity=initial_capacity)

    def reserve(self, allocation: Allocation) -> int:
        candidate = allocation.reservation()
        with self._locked(initial_capacity=self.requested_capacity or 1) as file:
            registry = file.read()
            _reap_stale_active(registry, self.path)
            capacity = _ensure_capacity(registry, self.requested_capacity)
            _validate_registry_entries(registry)
            _check_reservation_conflicts(registry, candidate)
            existing = next(
                (
                    entry
                    for entry in registry["allocations"]
                    if entry["reservation"]["resource_lease"] == allocation.lease_id
                ),
                None,
            )
            _ensure_private_directory(allocation.runtime_directory, "runtime_directory")
            _ensure_private_directory(
                allocation.evidence_directory, "evidence_directory"
            )
            if existing is None:
                registry["allocations"].append(
                    {"reservation": candidate, "active": None}
                )
            file.write(registry)
            return capacity

    def release(self, allocation: Allocation) -> None:
        with self._locked(initial_capacity=self.requested_capacity or 1) as file:
            registry = file.read()
            changed = _reap_stale_active(registry, self.path)
            _validate_registry_entries(registry)
            entry = next(
                (
                    item
                    for item in registry["allocations"]
                    if item["reservation"]["resource_lease"] == allocation.lease_id
                ),
                None,
            )
            if entry is None:
                if changed:
                    file.write(registry)
                return
            if entry["reservation"] != allocation.reservation():
                raise LabResourceError(
                    "allocation manifest does not match its reservation"
                )
            if _active_entry(entry) is not None:
                raise LabResourceError(
                    "cannot release an allocation with an active lease"
                )
            registry["allocations"].remove(entry)
            file.write(registry)

    @contextlib.contextmanager
    def active(self, allocation: Allocation) -> Iterator[dict]:
        candidate = allocation.reservation()
        previous_env = {
            key: os.environ.get(key)
            for key in (
                ENV_LEASE_ID,
                ENV_LEASE_TOKEN,
                ENV_LEASE_PID,
                ENV_LEASE_START,
                ENV_REGISTRY,
            )
        }
        process_lock = None
        inherited = False
        lease_token = None
        try:
            with self._locked(initial_capacity=self.requested_capacity or 1) as file:
                registry = file.read()
                _reap_stale_active(registry, self.path)
                capacity = _ensure_capacity(registry, self.requested_capacity)
                _validate_registry_entries(registry)
                _check_reservation_conflicts(registry, candidate)
                entry = next(
                    (
                        item
                        for item in registry["allocations"]
                        if item["reservation"]["resource_lease"] == allocation.lease_id
                    ),
                    None,
                )
                if entry is None:
                    entry = {"reservation": candidate, "active": None}
                    registry["allocations"].append(entry)
                _ensure_private_directory(
                    allocation.runtime_directory, "runtime_directory"
                )
                _ensure_private_directory(
                    allocation.evidence_directory, "evidence_directory"
                )
                current_token = os.environ.get(ENV_LEASE_TOKEN)
                current_id = os.environ.get(ENV_LEASE_ID)
                try:
                    inherited_pid = int(os.environ.get(ENV_LEASE_PID, ""))
                except ValueError:
                    inherited_pid = -1
                inherited_start = os.environ.get(ENV_LEASE_START)
                inherited_registry = os.environ.get(ENV_REGISTRY)
                active = _active_entry(entry)
                if (
                    active is not None
                    and current_token
                    and current_token == active["token"]
                    and current_id == allocation.lease_id
                    and inherited_pid == active["pid"]
                    and inherited_start == active["start_time"]
                    and inherited_registry == str(self.path.resolve(strict=False))
                    and _process_matches(inherited_pid, inherited_start) is True
                ):
                    inherited = True
                    lease = dict(
                        active, resource_lease=allocation.lease_id, capacity=capacity
                    )
                else:
                    if active is not None:
                        raise LabResourceError(
                            "allocation already has an active resource lease"
                        )
                    active_count = sum(
                        _active_entry(item) is not None
                        for item in registry["allocations"]
                    )
                    if active_count >= capacity:
                        raise LabResourceError(
                            f"host resource capacity is full ({active_count}/{capacity} active leases)"
                        )
                    start_time = _process_start_time(os.getpid())
                    if start_time is None:
                        raise LabResourceError(
                            "unable to verify current process start time"
                        )
                    token = uuid.uuid4().hex
                    lease_token = token
                    active = {
                        "pid": os.getpid(),
                        "start_time": start_time,
                        "token": token,
                        "capacity": capacity,
                        "started_at": dt.datetime.now(dt.timezone.utc).isoformat(),
                    }
                    process_lock = _ProcessLeaseLock(
                        _active_lock_path(self.path, allocation.lease_id)
                    )
                    if not process_lock.acquire():
                        process_lock = None
                        raise LabResourceError("active lease lock is already held")
                    process_lock.write(
                        {"pid": os.getpid(), "start_time": start_time, "token": token}
                    )
                    entry["active"] = active
                    file.write(registry)
                    lease = dict(
                        active, resource_lease=allocation.lease_id, capacity=capacity
                    )
                    os.environ.update(
                        {
                            ENV_LEASE_ID: allocation.lease_id,
                            ENV_LEASE_TOKEN: token,
                            ENV_LEASE_PID: str(os.getpid()),
                            ENV_LEASE_START: start_time,
                            ENV_REGISTRY: str(self.path.resolve(strict=False)),
                        }
                    )
            yield lease
        finally:
            body_exception = sys.exc_info()[0] is not None
            cleanup_error = None
            cleared = False
            try:
                if process_lock is not None and not inherited:
                    with self._locked(initial_capacity=capacity) as file:
                        registry = file.read()
                        _reap_stale_active(registry, self.path)
                        entry = next(
                            (
                                item
                                for item in registry["allocations"]
                                if item["reservation"]["resource_lease"]
                                == allocation.lease_id
                            ),
                            None,
                        )
                        if entry is None:
                            cleared = True
                        else:
                            active = _active_entry(entry)
                            if active is None:
                                cleared = True
                            elif (
                                lease_token is not None
                                and active["token"] == lease_token
                            ):
                                entry["active"] = None
                                try:
                                    file.write(registry)
                                finally:
                                    # A directory-fsync error can occur after
                                    # replace. The visible registry is then
                                    # already safe to unlock.
                                    cleared = file.last_write_committed
                            else:
                                raise LabResourceError(
                                    "active lease metadata changed before cleanup"
                                )
            except BaseException as exc:
                cleanup_error = exc
            finally:
                try:
                    if process_lock is not None and not inherited:
                        if cleared:
                            try:
                                process_lock.release()
                            except BaseException as exc:
                                if cleanup_error is None:
                                    cleanup_error = exc
                        else:
                            # Keep the OS lock alive while the registry still
                            # names this process as owner. It will be released
                            # by the kernel when this process exits, allowing
                            # safe stale recovery afterward.
                            _QUARANTINED_ACTIVE_LOCKS[allocation.lease_id] = (
                                process_lock
                            )
                            process_lock = None
                            if cleanup_error is None:
                                cleanup_error = LabResourceError(
                                    "could not clear active resource lease safely"
                                )
                finally:
                    # Restore inherited state even if bounded cleanup retries
                    # time out or registry I/O fails. Nested leases do not
                    # modify it.
                    if not inherited and lease_token is not None:
                        for key, value in previous_env.items():
                            if value is None:
                                os.environ.pop(key, None)
                            else:
                                os.environ[key] = value

            # Preserve the enclosed command's own failure and exit status. A
            # cleanup failure is surfaced only when it is the primary error.
            if cleanup_error is not None and not isinstance(cleanup_error, Exception):
                # KeyboardInterrupt/SystemExit must survive cleanup intact,
                # even when an enclosed command was already failing.
                raise cleanup_error
            if cleanup_error is not None and not body_exception:
                if isinstance(cleanup_error, LabResourceError):
                    raise cleanup_error
                raise LabResourceError(
                    "unable to clean up active resource lease"
                ) from cleanup_error

    def verify_active_environment(
        self, env: dict[str, str] | os._Environ[str] | None = None
    ) -> dict:
        """Verify that an inherited active lease matches the current lab env."""

        source = os.environ if env is None else env
        lease_id = source.get(ENV_LEASE_ID, "")
        lease_token = source.get(ENV_LEASE_TOKEN, "")
        lease_pid_raw = source.get(ENV_LEASE_PID, "")
        lease_start = source.get(ENV_LEASE_START, "")
        lease_registry = source.get(ENV_REGISTRY, "")
        if not all((lease_id, lease_token, lease_pid_raw, lease_start, lease_registry)):
            raise LabResourceError("incomplete active resource lease environment")
        try:
            lease_pid = int(lease_pid_raw)
        except ValueError as exc:
            raise LabResourceError("invalid active resource lease PID") from exc
        if lease_pid <= 0:
            raise LabResourceError("invalid active resource lease PID")
        if lease_registry != str(self.path.resolve(strict=False)):
            raise LabResourceError("active resource lease registry mismatch")
        if _process_matches(lease_pid, lease_start) is not True:
            raise LabResourceError("active resource lease owner is not running")

        with self._locked() as file:
            registry = file.read()
            if _reap_stale_active(registry, self.path):
                file.write(registry)
            entry = next(
                (
                    item
                    for item in registry["allocations"]
                    if item["reservation"]["resource_lease"] == lease_id
                ),
                None,
            )
            if entry is None:
                raise LabResourceError("active resource allocation is not registered")
            active = _active_entry(entry)
            if (
                active is None
                or active["token"] != lease_token
                or active["pid"] != lease_pid
                or active["start_time"] != lease_start
            ):
                raise LabResourceError("active resource lease does not match registry")
            probe = _ProcessLeaseLock(_active_lock_path(self.path, lease_id))
            if probe.acquire():
                probe.release()
                raise LabResourceError("active resource lease lock is not held")
            reservation = entry["reservation"]
            ports = reservation["ports"]
            expected = {
                "ADM_LAB_TASK": reservation["lab_task"],
                "ADM_LAB_NAME": reservation["lab_name"],
                "ADM_LAB_WEB_PORT": str(ports["web"]),
                "ADM_LAB_MGMT_PORT": str(ports["management"]),
                "ADM_LAB_HEC_PORT": str(ports["hec"]),
            }
            for key, want in expected.items():
                if source.get(key) != want:
                    raise LabResourceError(
                        f"lab environment {key} does not match active allocation"
                    )
            secrets = source.get("ADM_LAB_SECRETS", "")
            if not secrets or Path(secrets).resolve(strict=False) != Path(
                reservation["credentials_path"]
            ).resolve(strict=False):
                raise LabResourceError(
                    "lab environment ADM_LAB_SECRETS does not match active allocation"
                )
            return dict(
                active,
                resource_lease=lease_id,
                lab_name=reservation["lab_name"],
                lab_task=reservation["lab_task"],
            )


def verify_active_lease(
    *,
    registry_path: str | os.PathLike[str] | None = None,
    env: dict[str, str] | os._Environ[str] | None = None,
) -> dict:
    """Verify the active host resource lease named in the environment."""

    source = os.environ if env is None else env
    resolved_registry = registry_path or source.get(ENV_REGISTRY)
    if not resolved_registry:
        raise LabResourceError("active resource lease registry is missing")
    return ResourceRegistry(resolved_registry).verify_active_environment(source)


def _command_environment(allocation: Allocation, capacity: int) -> None:
    values = allocation.values
    os.environ.update(
        {
            "ADM_LAB_TASK": values["lab_task"],
            "ADM_LAB_NAME": values["lab_name"],
            "ADM_LAB_WEB_PORT": str(values["web_port"]),
            "ADM_LAB_MGMT_PORT": str(values["management_port"]),
            "ADM_LAB_HEC_PORT": str(values["hec_port"]),
            "ADM_LAB_SECRETS": str(allocation.credentials_path),
            "ADM_LAB_RUNTIME_DIRECTORY": str(allocation.runtime_directory),
            "ADM_LAB_EVIDENCE_DIRECTORY": str(allocation.evidence_directory),
            "ADM_LAB_RESOURCE_CAPACITY": str(capacity),
            "DOCKER_HOST": values["docker_endpoint"],
        }
    )
    os.environ.pop("DOCKER_CONTEXT", None)


def reserve_allocation(
    allocation: Allocation,
    *,
    registry_path: str | os.PathLike[str] | None = None,
    capacity: int | None = None,
) -> int:
    return ResourceRegistry(registry_path, capacity=capacity).reserve(allocation)


def release_allocation(
    allocation: Allocation,
    *,
    registry_path: str | os.PathLike[str] | None = None,
    capacity: int | None = None,
) -> None:
    ResourceRegistry(registry_path, capacity=capacity).release(allocation)


@contextlib.contextmanager
def resource_lease(
    allocation: Allocation,
    *,
    registry_path: str | os.PathLike[str] | None = None,
    capacity: int | None = None,
) -> Iterator[dict]:
    """Hold one host-capacity slot for the complete enclosed runtime."""

    with ResourceRegistry(registry_path, capacity=capacity).active(allocation) as lease:
        yield lease


def run_allocated(
    allocation: Allocation,
    command: Sequence[str],
    *,
    registry_path: str | os.PathLike[str] | None = None,
    capacity: int | None = None,
) -> int:
    """Run a workflow under both the capacity lease and named lab lock."""

    if not command:
        raise LabResourceError("a command is required after --")
    registry = ResourceRegistry(registry_path, capacity=capacity)
    with registry.active(allocation) as lease:
        environment_keys = (
            "ADM_LAB_TASK",
            "ADM_LAB_NAME",
            "ADM_LAB_WEB_PORT",
            "ADM_LAB_MGMT_PORT",
            "ADM_LAB_HEC_PORT",
            "ADM_LAB_SECRETS",
            "ADM_LAB_RUNTIME_DIRECTORY",
            "ADM_LAB_EVIDENCE_DIRECTORY",
            "ADM_LAB_RESOURCE_CAPACITY",
            "DOCKER_HOST",
            "DOCKER_CONTEXT",
        )
        previous_environment = {key: os.environ.get(key) for key in environment_keys}
        try:
            _command_environment(allocation, lease["capacity"])
            print(
                f"resource lease active: {allocation.lease_id} "
                f"(capacity {lease['capacity']})",
                file=sys.stderr,
            )
            previous_cwd = Path.cwd()
            os.chdir(allocation.worktree)
            try:
                return run_locked(command, root=allocation.worktree)
            finally:
                os.chdir(previous_cwd)
        except LabLockError as exc:
            raise LabResourceError(str(exc)) from exc
        finally:
            for key, value in previous_environment.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value


def _add_registry_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--registry", help="shared registry path (tests/host setup only)"
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)

    validate_parser = subparsers.add_parser(
        "validate", help="validate without reserving"
    )
    validate_parser.add_argument("manifest")

    reserve_parser = subparsers.add_parser(
        "reserve", help="reserve names, paths and ports"
    )
    reserve_parser.add_argument("manifest")
    reserve_parser.add_argument("--capacity", type=int)
    _add_registry_argument(reserve_parser)

    release_parser = subparsers.add_parser(
        "release", help="release registry reservation only"
    )
    release_parser.add_argument("manifest")
    release_parser.add_argument("--capacity", type=int)
    _add_registry_argument(release_parser)

    verify_parser = subparsers.add_parser(
        "verify-active",
        help="verify inherited active resource lease matches lab environment",
    )
    _add_registry_argument(verify_parser)

    run_parser = subparsers.add_parser(
        "run", help="run under resource and named-lab leases"
    )
    run_parser.add_argument("manifest")
    run_parser.add_argument("--capacity", type=int)
    _add_registry_argument(run_parser)
    command: list[str] = []
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    if raw_argv[:1] == ["run"]:
        if "--" not in raw_argv:
            parser.error("run requires -- followed by a command")
        separator = raw_argv.index("--")
        command = raw_argv[separator + 1 :]
        raw_argv = raw_argv[:separator]
    args = parser.parse_args(raw_argv)
    try:
        if args.action == "verify-active":
            verified = verify_active_lease(
                registry_path=getattr(args, "registry", None)
            )
            print(
                f"verified active resource lease {verified['resource_lease']} "
                f"for {verified['lab_name']}"
            )
            return 0
        allocation = validate_allocation(args.manifest)
        if args.action == "validate":
            print(
                f"valid allocation {allocation.lease_id} for {allocation.lab_name}; "
                "ports and private paths validated"
            )
            return 0
        registry_path = getattr(args, "registry", None)
        capacity = getattr(args, "capacity", None)
        if args.action == "reserve":
            effective = reserve_allocation(
                allocation, registry_path=registry_path, capacity=capacity
            )
            print(
                f"reserved allocation {allocation.lease_id} for {allocation.lab_name}; "
                f"host capacity {effective}"
            )
            return 0
        if args.action == "release":
            release_allocation(
                allocation, registry_path=registry_path, capacity=capacity
            )
            print(f"released registry reservation {allocation.lease_id}")
            return 0
        return run_allocated(
            allocation,
            command,
            registry_path=registry_path,
            capacity=capacity,
        )
    except LabResourceError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 75


if __name__ == "__main__":
    raise SystemExit(main())
