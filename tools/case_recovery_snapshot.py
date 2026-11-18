"""Small, fail-closed SQLite snapshot helper for the case-recovery rehearsal.

This consumes a cold export from the exact stopped app container. It is not a
live Splunk backup tool and deliberately supports only two fixed database names.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import stat
from contextlib import closing

ALLOWLIST = ("cases.sqlite", "capture_jobs.sqlite")
MAX_TOTAL_BYTES = 64 * 1024 * 1024
MANIFEST = "manifest.json"


class SnapshotError(ValueError):
    """Input or snapshot failed a recovery safety check."""


def _canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode()


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _json_value(value):
    if isinstance(value, bytes):
        return {"blob_sha256": _sha(value), "blob_size": len(value)}
    if isinstance(value, tuple):
        return [_json_value(item) for item in value]
    return value


def _safe_dir(path, *, create=False):
    path = Path(path)
    if not path.is_absolute():
        raise SnapshotError("directory must be absolute")
    if create:
        try:
            path.mkdir(mode=0o700)
        except FileExistsError as exc:
            raise SnapshotError("destination already exists") from exc
    try:
        info = path.lstat()
    except OSError as exc:
        raise SnapshotError("directory unavailable") from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise SnapshotError("unsafe directory")
    return path


def _safe_file(path, *, create=False):
    flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        if create:
            fd = os.open(path, flags | os.O_CREAT | os.O_EXCL, 0o600)
        else:
            fd = os.open(path, flags)
        info = os.fstat(fd)
        entry = Path(path).lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
            or (info.st_dev, info.st_ino) != (entry.st_dev, entry.st_ino)
        ):
            os.close(fd)
            raise SnapshotError("unsafe file")
        return fd, info.st_size
    except OSError as exc:
        raise SnapshotError("file unavailable or linked") from exc


def _sidecars(directory, name):
    sizes = {}
    for suffix in ("-journal", "-wal", "-shm"):
        path = directory / (name + suffix)
        if not path.exists() and not path.is_symlink():
            continue
        fd, size = _safe_file(path)
        os.close(fd)
        sizes[suffix] = size
        if suffix == "-journal":
            raise SnapshotError("hot rollback journal is not accepted")
    return sizes


def schema_identity(path):
    """Return the read-only SQLite schema fingerprint and user_version."""
    with closing(sqlite3.connect(Path(path).as_uri() + "?mode=ro", uri=True)) as db:
        rows = db.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_master "
            "WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name"
        ).fetchall()
        version = db.execute("PRAGMA user_version").fetchone()[0]
    return {"user_version": version, "schema_sha256": _sha(_canonical(rows))}


def schema_descriptor(path):
    """Trusted descriptor callers can derive from an independently built DB."""
    return schema_identity(path)


def _inspect(path, expected):
    identity = schema_identity(path)
    if identity != expected:
        raise SnapshotError("database schema differs from trusted installed schema")
    with closing(sqlite3.connect(Path(path).as_uri() + "?mode=ro", uri=True)) as db:
        if db.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
            raise SnapshotError("SQLite integrity check failed")
        if db.execute("PRAGMA foreign_key_check").fetchall():
            raise SnapshotError("SQLite foreign key check failed")
        tables = [
            r[0]
            for r in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name NOT LIKE 'sqlite_%' ORDER BY name"
            )
        ]
        table_rows = []
        for table in tables:
            # Names come from sqlite_master, not external input.
            quoted = '"' + table.replace('"', '""') + '"'
            columns = [r[1] for r in db.execute(f"PRAGMA table_info({quoted})")]
            order_by = ", ".join('"' + c.replace('"', '""') + '"' for c in columns)
            digest = hashlib.sha256()
            digest.update(_canonical(columns) + b"\n")
            count = 0
            for row in db.execute(f"SELECT * FROM {quoted} ORDER BY {order_by}"):
                digest.update(_canonical(_json_value(row)) + b"\n")
                count += 1
            table_rows.append(
                {"name": table, "rows": count, "sha256": digest.hexdigest()}
            )
    return {"schema": identity, "tables": table_rows}


def inspect_database(path, expected_schema):
    """Read-only schema, integrity, FK and logical-row summary for one DB."""
    return _inspect(path, expected_schema)


def _check_names(directory, expected_names, *, allow_sidecars=True):
    allowed = set(expected_names)
    if allow_sidecars:
        for name in ALLOWLIST:
            allowed.update(name + suffix for suffix in ("-journal", "-wal", "-shm"))
    extras = {p.name for p in directory.iterdir()} - allowed
    if extras:
        raise SnapshotError("unexpected file in database directory")


def _valid_inputs(source_dir, expected_schemas):
    source = _safe_dir(source_dir)
    if set(expected_schemas) not in ({"cases.sqlite"}, set(ALLOWLIST)):
        raise SnapshotError("schema expectations must cover cases and optional ledger")
    _check_names(source, set(expected_schemas))
    for name in set(ALLOWLIST) - set(expected_schemas):
        if any(
            (source / (name + suffix)).exists()
            or (source / (name + suffix)).is_symlink()
            for suffix in ("-journal", "-wal", "-shm")
        ):
            raise SnapshotError("absent database has an unexpected sidecar")
    records = {}
    for name in expected_schemas:
        sidecar_sizes = _sidecars(source, name)
        path = source / name
        fd, size = _safe_file(path)
        os.close(fd)
        records[name] = (path, size, sidecar_sizes)
    physical_size = sum(
        size + sum(sidecars.values()) for _, size, sidecars in records.values()
    )
    if physical_size > MAX_TOTAL_BYTES:
        raise SnapshotError("database bundle exceeds size limit")
    for name, (path, _, _) in records.items():
        _inspect(path, expected_schemas[name])
    return source, records


def _file_digest(path):
    fd, size = _safe_file(path)
    digest = hashlib.sha256()
    try:
        remaining = size
        while remaining:
            chunk = os.read(fd, min(remaining, 1024 * 1024))
            if not chunk:
                raise SnapshotError("file changed while reading")
            digest.update(chunk)
            remaining -= len(chunk)
        if os.read(fd, 1):
            raise SnapshotError("file changed while reading")
    finally:
        os.close(fd)
    return digest.hexdigest()


def _fsync_path(path, *, directory=False):
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if directory:
        flags |= getattr(os, "O_DIRECTORY", 0)
    fd = os.open(path, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _read_checked(fd, size, limit):
    if size > limit:
        raise SnapshotError("manifest exceeds size limit")
    chunks = []
    remaining = size
    while remaining:
        chunk = os.read(fd, min(remaining, 1024 * 1024))
        if not chunk:
            raise SnapshotError("manifest changed while reading")
        chunks.append(chunk)
        remaining -= len(chunk)
    if os.read(fd, 1):
        raise SnapshotError("manifest changed while reading")
    return b"".join(chunks)


def create_snapshot(source_dir, bundle_dir, *, expected_schemas, provenance):
    """Copy verified cold DBs to a new private bundle; return manifest digest."""
    source, inputs = _valid_inputs(source_dir, expected_schemas)
    if not isinstance(provenance, dict) or not provenance:
        raise SnapshotError("provenance must be a nonempty object")
    bundle = _safe_dir(bundle_dir, create=True)
    try:
        files = {}
        for name, (src, _, _) in inputs.items():
            target = bundle / name
            fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
            with (
                closing(
                    sqlite3.connect(src.as_uri() + "?mode=ro", uri=True)
                ) as source_db,
                closing(sqlite3.connect(target)) as target_db,
            ):
                source_db.backup(target_db)
                target_db.execute("PRAGMA journal_mode=DELETE")
            os.chmod(target, 0o600)
            _fsync_path(target)
            if any(
                Path(str(target) + suffix).exists()
                for suffix in ("-journal", "-wal", "-shm")
            ):
                raise SnapshotError("snapshot database is not sealed")
            check_fd, _ = _safe_file(target)
            os.close(check_fd)
            info = _inspect(target, expected_schemas[name])
            files[name] = {
                "size": target.stat().st_size,
                "sha256": _file_digest(target),
                **info,
            }
        absent = [name for name in ALLOWLIST if name not in files]
        manifest = {
            "format": 1,
            "provenance": provenance,
            "files": files,
            "absent": absent,
        }
        data = _canonical(manifest)
        if len(data) + sum(v["size"] for v in files.values()) > MAX_TOTAL_BYTES:
            raise SnapshotError("database bundle exceeds size limit")
        path = bundle / MANIFEST
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        _fsync_path(bundle, directory=True)
        _fsync_path(bundle.parent, directory=True)
        return _sha(data)
    except Exception:
        shutil.rmtree(bundle)
        raise


def validate_snapshot(
    bundle_dir, *, expected_manifest_sha256, expected_schemas, expected_provenance
):
    bundle = _safe_dir(bundle_dir)
    _check_names(bundle, set(expected_schemas) | {MANIFEST}, allow_sidecars=False)
    manifest_path = bundle / MANIFEST
    fd, manifest_size = _safe_file(manifest_path)
    try:
        data = _read_checked(fd, manifest_size, MAX_TOTAL_BYTES)
    finally:
        os.close(fd)
    if _sha(data) != expected_manifest_sha256:
        raise SnapshotError("manifest digest mismatch")
    try:
        manifest = json.loads(data)
    except (ValueError, UnicodeDecodeError) as exc:
        raise SnapshotError("invalid manifest") from exc
    if (
        manifest.get("format") != 1
        or manifest.get("provenance") != expected_provenance
        or set(manifest.get("files", {})) != set(expected_schemas)
        or manifest.get("absent") != [n for n in ALLOWLIST if n not in expected_schemas]
    ):
        raise SnapshotError("manifest does not match expected provenance or file set")
    total = len(data)
    for name, expected in expected_schemas.items():
        path = bundle / name
        fd, size = _safe_file(path)
        os.close(fd)
        total += size
        if total > MAX_TOTAL_BYTES:
            raise SnapshotError("database bundle exceeds size limit")
        record = manifest["files"][name]
        if record.get("size") != size or record.get("sha256") != _file_digest(path):
            raise SnapshotError("database bytes differ from manifest")
        if {k: record.get(k) for k in ("schema", "tables")} != _inspect(path, expected):
            raise SnapshotError("database contents differ from manifest or schema")
    return {
        "manifest_sha256": expected_manifest_sha256,
        "provenance": manifest["provenance"],
        "files": {
            n: {
                "size": manifest["files"][n]["size"],
                "sha256": manifest["files"][n]["sha256"],
                "tables": manifest["files"][n]["tables"],
            }
            for n in expected_schemas
        },
        "absent": manifest["absent"],
    }


def prepare_restore(
    bundle_dir,
    destination_dir,
    *,
    expected_manifest_sha256,
    expected_schemas,
    expected_provenance,
):
    """Validate the complete bundle before creating an exclusive restore dir."""
    summary = validate_snapshot(
        bundle_dir,
        expected_manifest_sha256=expected_manifest_sha256,
        expected_schemas=expected_schemas,
        expected_provenance=expected_provenance,
    )
    bundle = Path(bundle_dir)
    destination = _safe_dir(destination_dir, create=True)
    try:
        for name in expected_schemas:
            source = bundle / name
            target = destination / name
            fd = os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, "wb") as out, open(source, "rb") as inp:
                shutil.copyfileobj(inp, out)
                out.flush()
                os.fsync(out.fileno())
            if _file_digest(target) != summary["files"][name]["sha256"]:
                raise SnapshotError("restored file digest mismatch")
        _fsync_path(destination, directory=True)
        _fsync_path(destination.parent, directory=True)
        return summary
    except Exception:
        shutil.rmtree(destination)
        raise
