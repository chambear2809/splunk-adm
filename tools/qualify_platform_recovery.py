#!/usr/bin/env python3
"""Validate an offline platform recovery evidence inventory, not perform a restore.

The CLI reads an offline inventory; imported helpers may write fresh private
staging and SQLite snapshot artifacts. It does not execute Splunk, Docker,
process control, or live platform restoration. Its digest is a corruption check
whose expected value must be retained separately.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
from contextlib import closing

if __package__:
    from . import case_recovery_snapshot as case_snapshot
else:
    import case_recovery_snapshot as case_snapshot

COMPONENTS = (
    "package",
    "app_config",
    "platform_config",
    "identity",
    "kv_collections",
    "raw_indexes",
    "summary_indexes",
    "baselines",
    "watch_runs",
    "cases",
    "case_ledger",
)
MAX_ARTIFACT_BYTES = 256 * 1024 * 1024
MAX_MANIFEST_BYTES = 128 * 1024


class InventoryError(ValueError):
    """Evidence is incomplete, unsafe, inconsistent, or cannot be verified."""


def _require(condition, reason):
    if not condition:
        raise InventoryError(reason)


def _canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()


def _sha(value):
    return hashlib.sha256(value).hexdigest()


def _directory(path):
    path = Path(path)
    _require(
        path.is_absolute() and ".." not in path.parts,
        "inventory path must be absolute and unaliased",
    )
    # Each path component is inspected without following symbolic links.
    for part in (path, *path.parents):
        info = part.lstat()
        _require(stat.S_ISDIR(info.st_mode), "inventory path contains a link")
    info = path.lstat()
    _require(
        info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
        "inventory directory must be private",
    )
    return path


def _read(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        entry = path.lstat()
        _require(
            stat.S_ISREG(before.st_mode)
            and before.st_uid == os.getuid()
            and before.st_nlink == 1
            and stat.S_IMODE(before.st_mode) == 0o600,
            "unsafe evidence file",
        )
        _require(
            (before.st_dev, before.st_ino) == (entry.st_dev, entry.st_ino)
            and before.st_size <= limit,
            "evidence changed or too large",
        )
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(limit + 1)
        after = os.fstat(fd)
        entry_after = path.lstat()
        _require(
            len(data) == before.st_size
            and (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
            == (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
            and (entry_after.st_dev, entry_after.st_ino)
            == (before.st_dev, before.st_ino),
            "evidence changed during read",
        )
        return data
    finally:
        os.close(fd)


def build_inventory(directory, *, source_id, package_sha256, unresolved_operations):
    """Compute fixed-component digests from already captured offline artifacts.

    This does not prove a snapshot was correctly made, quiesced, or complete.
    Unresolved operations means unsettled dispatches, not retained and known
    uncertain ledger records, which must remain intact in future restore work.
    The caller must retain the returned digest in an independent trusted channel.
    """
    root = _directory(directory)
    _require(
        isinstance(source_id, str)
        and re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", source_id),
        "invalid source identity",
    )
    _require(
        isinstance(package_sha256, str)
        and re.fullmatch(r"[0-9a-f]{64}", package_sha256),
        "invalid package digest",
    )
    _require(
        type(unresolved_operations) is int and unresolved_operations == 0,
        "unresolved operations require reconciliation",
    )
    artifacts = {}
    for name in COMPONENTS:
        data = _read(root / (name + ".snapshot"), MAX_ARTIFACT_BYTES)
        _require(bool(data), "empty evidence artifact")
        artifacts[name] = {"sha256": _sha(data), "size": len(data)}
    _require(artifacts["package"]["sha256"] == package_sha256, "package digest differs")
    manifest = {
        "schema": 1,
        "source_id": source_id,
        "package_sha256": package_sha256,
        "unresolved_operations": 0,
        "artifacts": artifacts,
    }
    return manifest, _sha(_canonical(manifest))


def verify_inventory(directory, manifest, trusted_digest):
    """Verify a sealed inventory with an independently supplied manifest digest."""
    _require(
        isinstance(trusted_digest, str)
        and re.fullmatch(r"[0-9a-f]{64}", trusted_digest),
        "trusted digest required",
    )
    _require(
        isinstance(manifest, dict)
        and set(manifest)
        == {
            "schema",
            "source_id",
            "package_sha256",
            "unresolved_operations",
            "artifacts",
        },
        "invalid manifest shape",
    )
    _require(
        manifest["schema"] == 1 and type(manifest["schema"]) is int,
        "unsupported schema",
    )
    _require(_sha(_canonical(manifest)) == trusted_digest, "manifest digest mismatch")
    _require(
        isinstance(manifest["artifacts"], dict)
        and set(manifest["artifacts"]) == set(COMPONENTS),
        "incomplete component inventory",
    )
    actual, _ = build_inventory(
        directory,
        source_id=manifest["source_id"],
        package_sha256=manifest["package_sha256"],
        unresolved_operations=manifest["unresolved_operations"],
    )
    _require(actual == manifest, "artifact inventory differs")
    return {
        "status": "inventory_verified",
        "components": len(COMPONENTS),
        "manifest_sha256": trusted_digest,
        "operational_restore_qualified": False,
    }


def _fresh_target(source, target):
    target = Path(target)
    _require(target.is_absolute() and ".." not in target.parts, "invalid target")
    parent = _directory(target.parent)
    _require(
        target != source and source not in target.parents,
        "source cannot contain target",
    )
    return target, parent


def _write_all(fd, data):
    view = memoryview(data)
    while view:
        count = os.write(fd, view)
        _require(count > 0, "journal write failed")
        view = view[count:]


def stage_fresh_inventory(source, manifest, trusted_digest, target):
    """Copy a verified evidence bundle to a new private directory, not a platform.

    A failure leaves the exclusive target and journal for inspection; never retry
    into a partial target or delete it automatically. Neither this staging nor a
    successful verification proves any component can be restored operationally.
    """
    source = _directory(source)
    verify_inventory(source, manifest, trusted_digest)
    target, parent = _fresh_target(source, target)
    target.mkdir(mode=0o700)
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
    root = _directory(target)
    journal = root / "staging.jsonl"
    journal_fd = os.open(
        journal, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
    )
    try:
        expected_records = []
        for name in COMPONENTS:
            data = _read(source / (name + ".snapshot"), MAX_ARTIFACT_BYTES)
            expected = manifest["artifacts"][name]
            _require(
                len(data) == expected["size"] and _sha(data) == expected["sha256"],
                "source changed during staging",
            )
            record = {"state": "copy_intent", "component": name}
            expected_records.append(record)
            _write_all(journal_fd, _canonical(record) + b"\n")
            os.fsync(journal_fd)
            fd = os.open(
                root / (name + ".snapshot"),
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
            )
            try:
                with os.fdopen(fd, "wb", closefd=False) as stream:
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
            finally:
                os.close(fd)
            record = {
                "state": "copy_ack",
                "component": name,
                "sha256": expected["sha256"],
            }
            expected_records.append(record)
            _write_all(journal_fd, _canonical(record) + b"\n")
            os.fsync(journal_fd)
        verify_inventory(root, manifest, trusted_digest)
        record = {"state": "staging_verified", "manifest_sha256": trusted_digest}
        expected_records.append(record)
        _write_all(journal_fd, _canonical(record) + b"\n")
        os.fsync(journal_fd)
        actual = _read(journal, MAX_MANIFEST_BYTES)
        expected_journal = b"".join(
            _canonical(item) + b"\n" for item in expected_records
        )
        _require(actual == expected_journal, "journal verification failed")
        root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(root_fd)
        finally:
            os.close(root_fd)
    finally:
        os.close(journal_fd)
    return {"status": "staged_and_verified", "operational_restore_qualified": False}


COLD_DATABASES = {
    "baselines.sqlite": "baselines",
    "watch_runs.sqlite": "baselines",
    "cases.sqlite": "investigations",
    "capture_jobs.sqlite": "investigations",
}


def snapshot_cold_databases(source, target, expected_schemas):
    """Back up four cold fixture SQLite exports into a new private directory.

    Callers must independently establish writer/process quiescence and trusted
    installed schema descriptors. This intentionally does not stop Splunk, open
    a live platform path, or recover a server.
    """
    source = _directory(source)
    _require(set(expected_schemas) == set(COLD_DATABASES), "four schemas required")
    target, parent = _fresh_target(source, target)
    # Fixed nested export layout; the caller must establish that it is cold.
    for folder in ("baselines", "investigations"):
        _directory(source / folder)
        allowed = {name for name, parent in COLD_DATABASES.items() if parent == folder}
        _require(
            {item.name for item in (source / folder).iterdir()} == allowed,
            "unexpected database or sidecar",
        )
    for name, folder in COLD_DATABASES.items():
        path = source / folder / name
        _read(path, MAX_ARTIFACT_BYTES)
        case_snapshot.inspect_database(path, expected_schemas[name])
    target.mkdir(mode=0o700)
    parent_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(parent_fd)
    finally:
        os.close(parent_fd)
    results = {}
    for name, folder in COLD_DATABASES.items():
        src = source / folder / name
        dst = target / name
        fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        with (
            closing(sqlite3.connect(src.as_uri() + "?mode=ro", uri=True)) as source_db,
            closing(sqlite3.connect(dst)) as dest_db,
        ):
            source_db.backup(dest_db)
            dest_db.execute("PRAGMA journal_mode=DELETE")
        fd = os.open(dst, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        _require(
            not any(
                os.path.lexists(str(dst) + suffix)
                for suffix in ("-wal", "-shm", "-journal")
            ),
            "unsealed target database",
        )
        evidence = case_snapshot.inspect_database(dst, expected_schemas[name])
        _require(
            evidence == case_snapshot.inspect_database(src, expected_schemas[name]),
            "database logical contents changed",
        )
        data = _read(dst, MAX_ARTIFACT_BYTES)
        results[name] = {"sha256": _sha(data), "size": len(data), "logical": evidence}
    fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
    return results


# Launch rendering is deliberately separate from execution. No credentials in
# properties, environment, arguments, or the reviewed driver digest.
NATIVE_STAGE = Path("/var/lib/atlas-platform-recovery-inputs-20261118")
INPUT_OWNER_UID = 0
NATIVE_MANIFEST_SHA256 = (
    "e2804612e699f12f07c04bc0c876d17c583f3dd0a9ebfe6555e71c6ab2e9c429"
)
NATIVE_UNIT = "atlas-platform-recovery-20261118.service"
NATIVE_PACKAGE_SHA256 = (
    "a84961c31c4bb9dad35f1fb10fb4eb3a9e924bb54774450ee1c13b640b4dbc94"
)
NATIVE_APP_SHA256 = "0a87171ca77fbeedc778844fb326e523f7c427920ea36dcd4fc4cd54cb62bc7e"


def _stream_digest(path, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        entry = path.lstat()
        _require(
            stat.S_ISREG(before.st_mode)
            and before.st_uid == INPUT_OWNER_UID
            and before.st_nlink == 1
            and stat.S_IMODE(before.st_mode) == 0o444,
            "unsafe native artifact",
        )
        _require(
            (before.st_dev, before.st_ino) == (entry.st_dev, entry.st_ino)
            and 0 < before.st_size <= limit,
            "invalid native artifact",
        )
        digest = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            chunk = os.read(fd, min(remaining, 1024 * 1024))
            _require(bool(chunk), "artifact truncated")
            digest.update(chunk)
            remaining -= len(chunk)
        after = os.fstat(fd)
        final_entry = path.lstat()
        _require(
            not os.read(fd, 1)
            and (
                before.st_dev,
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
                before.st_ctime_ns,
            )
            == (
                after.st_dev,
                after.st_ino,
                after.st_size,
                after.st_mtime_ns,
                after.st_ctime_ns,
            )
            and (after.st_dev, after.st_ino)
            == (final_entry.st_dev, final_entry.st_ino),
            "artifact changed",
        )
        return digest.hexdigest()
    finally:
        os.close(fd)


def render_native_launch(driver_sha256, *, runtime_minutes=45):
    """Return a fixed, non-secret systemd launch argv after artifact checks.

    Rendering does not authorize or execute the launch. It does not attest that
    the reviewed driver implements recovery or that systemd can enforce the
    declared properties. Those are independent prelaunch requirements.
    """
    _require(
        isinstance(driver_sha256, str) and re.fullmatch(r"[0-9a-f]{64}", driver_sha256),
        "reviewed driver digest required",
    )
    _require(
        type(runtime_minutes) is int and 1 <= runtime_minutes <= 45,
        "invalid runtime budget",
    )
    root = NATIVE_STAGE
    info = root.lstat()
    _require(
        stat.S_ISDIR(info.st_mode)
        and info.st_uid == INPUT_OWNER_UID
        and stat.S_IMODE(info.st_mode) == 0o700
        and ".." not in root.parts
        and root.is_absolute(),
        "unsafe native input directory",
    )
    _require(
        _stream_digest(root / "splunk.tgz", 2 * 1024 * 1024 * 1024)
        == NATIVE_PACKAGE_SHA256,
        "native package mismatch",
    )
    _require(
        _stream_digest(root / "atlas.tgz", 256 * 1024 * 1024) == NATIVE_APP_SHA256,
        "app package mismatch",
    )
    _require(
        _stream_digest(root / "driver.py", 8 * 1024 * 1024) == driver_sha256,
        "driver mismatch",
    )
    _require(
        _stream_digest(root / "package-manifest.json", 1024 * 1024)
        == NATIVE_MANIFEST_SHA256,
        "manifest mismatch",
    )
    properties = (
        "DynamicUser=yes",
        "StateDirectory=atlas-platform-recovery-20261118",
        "StateDirectoryMode=0700",
        "RuntimeDirectory=atlas-platform-recovery-inputs-20261118",
        "RuntimeDirectoryMode=0700",
        "PrivateNetwork=yes",
        "PrivateTmp=yes",
        "NoNewPrivileges=yes",
        "ProtectSystem=strict",
        "ProtectProc=invisible",
        "ProcSubset=pid",
        "PrivateDevices=yes",
        "CapabilityBoundingSet=",
        "AmbientCapabilities=",
        "ProtectKernelTunables=yes",
        "ProtectControlGroups=yes",
        "InaccessiblePaths=/opt/splunk -/run/dbus/system_bus_socket -/run/docker.sock -/run/containerd",
        "MemoryMax=8G",
        "MemorySwapMax=0",
        "CPUQuota=400%",
        "TasksMax=1024",
        f"RuntimeMaxSec={60 * runtime_minutes}",
        "KillMode=control-group",
        "TimeoutStopSec=15s",
        "SendSIGKILL=yes",
        "OOMPolicy=kill",
    )
    argv = [
        "/usr/bin/sudo",
        "-n",
        "/usr/bin/systemd-run",
        "--unit=" + NATIVE_UNIT,
        "--wait",
    ]
    argv.extend("--property=" + item for item in properties)
    mounts = [
        str(root / name) + ":/run/atlas-platform-recovery-inputs-20261118/" + name
        for name in (
            "splunk.tgz",
            "atlas.tgz",
            "driver.py",
            "package-manifest.json",
            "approval.json",
        )
    ]
    argv.append("--property=BindReadOnlyPaths=" + " ".join(mounts))
    argv.extend(
        [
            "/usr/bin/python3",
            "-I",
            "/run/atlas-platform-recovery-inputs-20261118/driver.py",
        ]
    )
    return {
        "argv": argv,
        "driver_sha256": driver_sha256,
        "execution_authorized": False,
        "operational_restore_qualified": False,
    }


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        _require(key not in result, "duplicate manifest key")
        result[key] = value
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument(
        "trusted_digest", help="independently retained SHA-256 of canonical manifest"
    )
    args = parser.parse_args()
    try:
        root = _directory(args.directory)
        manifest = json.loads(
            _read(root / "manifest.json", MAX_MANIFEST_BYTES),
            object_pairs_hook=_unique_object,
        )
        print(
            json.dumps(
                verify_inventory(root, manifest, args.trusted_digest), sort_keys=True
            )
        )
    except (OSError, ValueError, TypeError, RecursionError):
        print(json.dumps({"status": "refused", "operational_restore_qualified": False}))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
